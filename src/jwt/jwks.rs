#[cfg(feature = "async-validate")]
use crate::error::read_body_with_limit_async;
use crate::error::{read_body_with_limit, Error, MAX_ERROR_BODY_BYTES};
use jsonwebtoken::jwk::JwkSet;
use log::warn;
use reqwest::blocking::Client as HttpClient;
#[cfg(feature = "async-validate")]
use reqwest::Client as AsyncHttpClient;
use serde_json::Value;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
#[cfg(feature = "async-validate")]
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use url::Url;

use super::constants::SUPPORTED_JWK_ALGS;
use super::types::{JwksSanitizeReport, RemovedAlg, RemovedAlgReason};

const DEFAULT_JWKS_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct JwksProvider {
    jwks_uri: Url,
    http: HttpClient,
    timeout: Option<Duration>,
    cache_ttl: Duration,
    cache: RwLock<Option<CachedJwks>>,
    fetch_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: JwkSet,
    expires_at: Instant,
    fetched_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FetchSource {
    Cache,
    Remote,
}

#[cfg(feature = "async-validate")]
#[derive(Debug)]
pub struct JwksProviderAsync {
    jwks_uri: Url,
    http: AsyncHttpClient,
    timeout: Option<Duration>,
    cache_ttl: Duration,
    cache: AsyncRwLock<Option<CachedJwks>>,
    fetch_lock: AsyncMutex<()>,
}

#[cfg(feature = "async-validate")]
impl JwksProviderAsync {
    pub fn new(jwks_uri: impl AsRef<str>) -> Result<Self, Error> {
        let jwks_uri = Url::parse(jwks_uri.as_ref())?;
        let http = AsyncHttpClient::builder().build()?;
        Ok(Self {
            jwks_uri,
            http,
            timeout: Some(DEFAULT_JWKS_TIMEOUT),
            cache_ttl: Duration::from_secs(300),
            cache: AsyncRwLock::new(None),
            fetch_lock: AsyncMutex::new(()),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_http_client(mut self, http: AsyncHttpClient) -> Self {
        self.http = http;
        self
    }

    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        let cache = self.cache.into_inner();
        self.cache = AsyncRwLock::new(cache.map(|mut cached| {
            let now = Instant::now();
            cached.expires_at = now + self.cache_ttl;
            cached.fetched_at = now;
            cached
        }));
        self
    }

    pub fn with_preloaded(self, jwks: JwkSet) -> Self {
        let now = Instant::now();
        let cached = CachedJwks {
            jwks,
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        let mut this = self;
        this.cache = AsyncRwLock::new(Some(cached));
        this
    }

    pub async fn fetch(&self) -> Result<JwkSet, Error> {
        let (jwks, _source) = self.fetch_with_source().await?;
        Ok(jwks)
    }

    pub(crate) async fn fetch_with_source(&self) -> Result<(JwkSet, FetchSource), Error> {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok((cached.jwks.clone(), FetchSource::Cache));
                }
            }
        }

        let _guard = self.fetch_lock.lock().await;
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok((cached.jwks.clone(), FetchSource::Cache));
                }
            }
        }
        let jwks = self.fetch_remote().await?;
        Ok((jwks, FetchSource::Remote))
    }

    pub async fn fetch_fresh(&self) -> Result<JwkSet, Error> {
        let now = Instant::now();
        if let Some(cached) = self.cache.read().await.as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        let _guard = self.fetch_lock.lock().await;
        if let Some(cached) = self.cache.read().await.as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        self.fetch_remote().await
    }

    async fn fetch_remote(&self) -> Result<JwkSet, Error> {
        let mut req = self.http.get(self.jwks_uri.clone());
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
        }
        let mut resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_body_with_limit_async(&mut resp, MAX_ERROR_BODY_BYTES).await?;
            let body_preview = sanitize_error_body(&body);
            let redacted = redact_jwks_uri(&self.jwks_uri);
            return Err(Error::Crypto(if body_preview.is_empty() {
                format!(
                    "jwks fetch failed: uri {} status {} body_read_len {}",
                    redacted,
                    status,
                    body.len()
                )
            } else {
                format!(
                    "jwks fetch failed: uri {} status {} body_read_len {} body_preview {}",
                    redacted,
                    status,
                    body.len(),
                    body_preview
                )
            }));
        }
        let body = resp.bytes().await?;
        let jwks = jwks_from_slice(&body)?;
        let now = Instant::now();
        let cached = CachedJwks {
            jwks: jwks.clone(),
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        *self.cache.write().await = Some(cached);
        Ok(jwks)
    }
}

impl JwksProvider {
    pub fn new(jwks_uri: impl AsRef<str>) -> Result<Self, Error> {
        let jwks_uri = Url::parse(jwks_uri.as_ref())?;
        let http = HttpClient::builder().build()?;
        Ok(Self {
            jwks_uri,
            http,
            timeout: Some(DEFAULT_JWKS_TIMEOUT),
            cache_ttl: Duration::from_secs(300),
            cache: RwLock::new(None),
            fetch_lock: Mutex::new(()),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_http_client(mut self, http: HttpClient) -> Self {
        self.http = http;
        self
    }

    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        if let Some(cached) = self.cache.write().unwrap().as_mut() {
            let now = Instant::now();
            cached.expires_at = now + self.cache_ttl;
            cached.fetched_at = now;
        }
        self
    }

    pub fn with_preloaded(self, jwks: JwkSet) -> Self {
        let now = Instant::now();
        let cached = CachedJwks {
            jwks,
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        *self.cache.write().unwrap() = Some(cached);
        self
    }

    pub fn fetch(&self) -> Result<JwkSet, Error> {
        let (jwks, _source) = self.fetch_with_source()?;
        Ok(jwks)
    }

    pub(crate) fn fetch_with_source(&self) -> Result<(JwkSet, FetchSource), Error> {
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.expires_at > Instant::now() {
                return Ok((cached.jwks.clone(), FetchSource::Cache));
            }
        }

        let _guard = self.fetch_lock.lock().unwrap();
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.expires_at > Instant::now() {
                return Ok((cached.jwks.clone(), FetchSource::Cache));
            }
        }

        let jwks = self.fetch_remote()?;
        Ok((jwks, FetchSource::Remote))
    }

    pub fn fetch_fresh(&self) -> Result<JwkSet, Error> {
        let now = Instant::now();
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        let _guard = self.fetch_lock.lock().unwrap();
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        self.fetch_remote()
    }

    fn fetch_remote(&self) -> Result<JwkSet, Error> {
        let mut req = self.http.get(self.jwks_uri.clone());
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
        }
        let mut resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_body_with_limit(&mut resp, MAX_ERROR_BODY_BYTES)?;
            let body_preview = sanitize_error_body(&body);
            let redacted = redact_jwks_uri(&self.jwks_uri);
            return Err(Error::Crypto(if body_preview.is_empty() {
                format!(
                    "jwks fetch failed: uri {} status {} body_read_len {}",
                    redacted,
                    status,
                    body.len()
                )
            } else {
                format!(
                    "jwks fetch failed: uri {} status {} body_read_len {} body_preview {}",
                    redacted,
                    status,
                    body.len(),
                    body_preview
                )
            }));
        }
        let body = resp.bytes()?;
        let jwks = jwks_from_slice(&body)?;
        let now = Instant::now();
        let cached = CachedJwks {
            jwks: jwks.clone(),
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        *self.cache.write().unwrap() = Some(cached);
        Ok(jwks)
    }
}

fn sanitize_error_body(body: &[u8]) -> String {
    let mut sanitized = String::new();
    for &byte in body.iter().take(128) {
        let ch = match byte {
            b'\n' => '\\',
            b'\r' => '\\',
            b'\t' => '\\',
            _ if byte.is_ascii_graphic() || byte == b' ' => byte as char,
            _ => '.',
        };
        if ch == '\\' {
            sanitized.push('\\');
            sanitized.push(match byte {
                b'\n' => 'n',
                b'\r' => 'r',
                b'\t' => 't',
                _ => '\\',
            });
        } else {
            sanitized.push(ch);
        }
    }
    if body.len() > 128 {
        sanitized.push_str("...");
    }
    sanitized
}

fn redact_jwks_uri(uri: &Url) -> String {
    let mut redacted = uri.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

pub fn jwks_from_slice(body: &[u8]) -> Result<JwkSet, Error> {
    let report = jwks_from_slice_with_report(body)?;
    Ok(report.jwks)
}

pub fn jwks_from_slice_with_report(body: &[u8]) -> Result<JwksSanitizeReport, Error> {
    let mut value: Value = serde_json::from_slice(body)?;
    let removed_algs = sanitize_jwks(&mut value);
    let jwks = serde_json::from_value(value).map_err(Error::from)?;
    Ok(JwksSanitizeReport { jwks, removed_algs })
}

fn sanitize_jwks(value: &mut Value) -> Vec<RemovedAlg> {
    let Some(keys) = value.get_mut("keys").and_then(Value::as_array_mut) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for key in keys {
        let Some(object) = key.as_object_mut() else {
            continue;
        };
        let Some(alg_value) = object.get("alg").cloned() else {
            continue;
        };
        let kid = object
            .get("kid")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let alg = match alg_value.as_str() {
            Some(alg) => alg,
            None => {
                warn!(
                    "jwks key alg is not a string; kid={}",
                    kid.as_deref().unwrap_or("<none>")
                );
                object.remove("alg");
                removed.push(RemovedAlg {
                    kid,
                    alg: None,
                    reason: RemovedAlgReason::NotString,
                });
                continue;
            }
        };
        if !SUPPORTED_JWK_ALGS.contains(&alg) {
            warn!(
                "jwks key alg unsupported; kid={}, alg={}",
                kid.as_deref().unwrap_or("<none>"),
                alg
            );
            object.remove("alg");
            removed.push(RemovedAlg {
                kid,
                alg: Some(alg.to_string()),
                reason: RemovedAlgReason::Unsupported,
            });
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::constants::{
        ES512_DISABLED_MESSAGE, MAX_KIDLESS_JWKS_KEYS, NO_COMPATIBLE_JWK_MESSAGE,
    };
    #[cfg(feature = "async-validate")]
    use crate::jwt::{JwksProviderAsync, JwtValidatorAsync};
    use crate::jwt::{JwtValidationOptions, JwtValidator};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p521::ecdsa::{
        Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
    };
    use rand::thread_rng;
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::{json, Value};
    use signature::Signer;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, OnceLock};
    use std::thread;
    use std::time::Duration;

    fn build_es512_token() -> (String, JwkSet) {
        build_es512_token_with_typ_value(Some(json!("JWT")))
    }

    fn build_es512_token_with_typ(typ: Option<&str>) -> (String, JwkSet) {
        build_es512_token_with_typ_value(typ.map(|value| json!(value)))
    }

    fn build_es512_token_with_typ_value(typ: Option<Value>) -> (String, JwkSet) {
        let mut rng = thread_rng();
        let signing_key = P521SigningKey::random(&mut rng);
        let verifying_key = P521VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("x coord");
        let y = encoded_point.y().expect("y coord");

        let kid = "test-key";
        let jwks_json = json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-521",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "use": "sig",
                "kid": kid,
                "alg": "ES512",
            }]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");

        let mut header = json!({
            "alg": "ES512",
            "kid": kid,
        });
        if let Some(typ) = typ {
            header["typ"] = typ;
        }
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let payload = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{}.{}", signing_input, signature_b64);

        (token, jwks)
    }

    fn build_es512_token_without_kid() -> (String, JwkSet) {
        let mut rng = thread_rng();
        let signing_key = P521SigningKey::random(&mut rng);
        let verifying_key = P521VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("x coord");
        let y = encoded_point.y().expect("y coord");

        let bad_signing_key = P521SigningKey::random(&mut rng);
        let bad_verifying_key = P521VerifyingKey::from(&bad_signing_key);
        let bad_point = bad_verifying_key.to_encoded_point(false);
        let bad_x = bad_point.x().expect("x coord");
        let bad_y = bad_point.y().expect("y coord");

        let jwks_json = json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": URL_SAFE_NO_PAD.encode(bad_x),
                    "y": URL_SAFE_NO_PAD.encode(bad_y),
                    "use": "sig",
                    "kid": "bad-key",
                    "alg": "ES512",
                },
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": URL_SAFE_NO_PAD.encode(x),
                    "y": URL_SAFE_NO_PAD.encode(y),
                    "use": "sig",
                    "kid": "good-key",
                    "alg": "ES512",
                }
            ]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");

        let header = json!({
            "alg": "ES512",
            "typ": "JWT",
        });
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let payload = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{}.{}", signing_input, signature_b64);

        (token, jwks)
    }

    fn rsa_private_key_pem() -> &'static str {
        static PEM: OnceLock<String> = OnceLock::new();
        PEM.get_or_init(|| {
            let mut rng = thread_rng();
            let key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
            key.to_pkcs1_pem(LineEnding::LF)
                .expect("private key pem")
                .to_string()
        })
        .as_str()
    }

    fn rs256_public_components() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let pem = rsa_private_key_pem();
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem).expect("private key");
        let public_key = RsaPublicKey::from(&private_key);
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        let mut bad_n = n.clone();
        if let Some(last) = bad_n.last_mut() {
            *last ^= 0x01;
        }
        (n, e, bad_n)
    }

    fn build_rs256_token_with_kid_and_claims(kid: &str, claims: Value) -> (String, JwkSet) {
        let pem = rsa_private_key_pem();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key"),
        )
        .expect("token");

        let (n, e, _) = rs256_public_components();
        let jwks_json = json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(&n),
                "e": URL_SAFE_NO_PAD.encode(&e),
            }]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");
        (token, jwks)
    }

    fn build_rs256_token_with_kid(kid: &str) -> (String, JwkSet) {
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let claims = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });
        build_rs256_token_with_kid_and_claims(kid, claims)
    }

    fn serve_jwks_sequence(
        bodies: Vec<String>,
    ) -> (String, Arc<AtomicUsize>, Sender<()>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let count = Arc::new(AtomicUsize::new(0));
        let count_thread = Arc::clone(&count);
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            while count_thread.load(Ordering::SeqCst) < bodies.len() {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let idx = count_thread.fetch_add(1, Ordering::SeqCst);
                        let body = bodies
                            .get(idx)
                            .unwrap_or_else(|| bodies.last().expect("body"));
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.as_bytes().len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://{}", addr), count, shutdown_tx, handle)
    }

    fn rs256_token_without_kid() -> String {
        let pem = rsa_private_key_pem();
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let claims = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = None;
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key"),
        )
        .expect("token")
    }

    fn build_rs256_token_without_kid() -> (String, JwkSet) {
        let (n, e, bad_n) = rs256_public_components();

        let jwks_json = json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "bad-key",
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&bad_n),
                    "e": URL_SAFE_NO_PAD.encode(&e),
                },
                {
                    "kty": "RSA",
                    "kid": "good-key",
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&n),
                    "e": URL_SAFE_NO_PAD.encode(&e),
                }
            ]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");

        (rs256_token_without_kid(), jwks)
    }

    fn jwks_provider_with_seeded_cache(jwks: JwkSet) -> JwksProvider {
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });
        jwks_provider
    }

    #[test]
    fn jwks_sanitize_report_removes_unsupported_alg() {
        let jwks_json = json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "key-1",
                    "alg": "RS256",
                    "n": "sXchbWFrZV9tb2R1bHVz",
                    "e": "AQAB"
                },
                {
                    "kty": "RSA",
                    "kid": "key-2",
                    "alg": "none",
                    "n": "sXchbWFrZV9tb2R1bHVz",
                    "e": "AQAB"
                }
            ]
        });
        let body = serde_json::to_vec(&jwks_json).expect("jwks json");
        let report = jwks_from_slice_with_report(&body).expect("report");
        assert_eq!(report.removed_algs.len(), 1);
        assert_eq!(report.removed_algs[0].kid.as_deref(), Some("key-2"));
        assert_eq!(report.removed_algs[0].reason, RemovedAlgReason::Unsupported);

        let key = report
            .jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some("key-2"))
            .expect("key-2");
        assert!(key.common.key_algorithm.is_none());
    }

    #[test]
    fn jwt_es512_validate_success() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::athenz_default().with_es512();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["iss"], "athenz");
        assert_eq!(data.claims["aud"], "client");
        assert_eq!(data.header.alg, "ES512");
    }

    #[test]
    fn jwt_es512_allows_aud_when_audience_empty() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = jwks_provider_with_seeded_cache(jwks);

        let mut options = JwtValidationOptions::athenz_default().with_es512();
        options.issuer = Some("athenz".to_string());

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["aud"], "client");
        assert_eq!(data.header.alg, "ES512");
    }

    #[test]
    fn jwt_es512_validates_without_kid_using_all_keys() {
        let (token, jwks) = build_es512_token_without_kid();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::athenz_default().with_es512();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["sub"], "principal");
        assert_eq!(data.header.alg, "ES512");
    }

    #[test]
    fn jwt_es512_rejected_when_rsa_only() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::UnsupportedAlg(alg) => assert_eq!(alg, ES512_DISABLED_MESSAGE),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_es512_rejected_by_default() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::athenz_default();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::UnsupportedAlg(alg) => assert_eq!(alg, ES512_DISABLED_MESSAGE),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_es512_rejected_without_ec_allowlist() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.allow_es512 = true;
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::UnsupportedAlg(alg) => assert_eq!(alg, ES512_DISABLED_MESSAGE),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rs256_rejects_future_nbf() {
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": now + 3600,
            "nbf": now + 60,
        });
        let (token, jwks) = build_rs256_token_with_kid_and_claims("good-key", claims);
        let jwks_provider = jwks_provider_with_seeded_cache(jwks);

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &ErrorKind::ImmatureSignature),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rs256_validates_without_kid_using_all_keys() {
        let (token, jwks) = build_rs256_token_without_kid();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["sub"], "principal");
    }

    #[test]
    fn jwt_rs256_allows_aud_when_audience_empty() {
        let (token, jwks) = build_rs256_token_without_kid();
        let jwks_provider = jwks_provider_with_seeded_cache(jwks);

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["aud"], "client");
        assert_eq!(data.claims["sub"], "principal");
    }

    #[test]
    fn jwt_rs256_kidless_fails_when_key_beyond_cap() {
        let token = rs256_token_without_kid();
        let (n, e, bad_n) = rs256_public_components();
        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let bad_n_b64 = URL_SAFE_NO_PAD.encode(&bad_n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        let mut keys = Vec::new();
        for idx in 0..MAX_KIDLESS_JWKS_KEYS {
            keys.push(json!({
                "kty": "RSA",
                "kid": format!("bad-{}", idx),
                "alg": "RS256",
                "n": bad_n_b64.clone(),
                "e": e_b64.clone(),
            }));
        }
        keys.push(json!({
            "kty": "RSA",
            "kid": "good-key",
            "alg": "RS256",
            "n": n_b64,
            "e": e_b64,
        }));

        let jwks = jwks_from_value(json!({ "keys": keys })).expect("jwks");
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &ErrorKind::InvalidSignature),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rs256_kidless_no_compatible_key() {
        let token = rs256_token_without_kid();
        let (_es_token, jwks) = build_es512_token_without_kid();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        let expected = format!("{NO_COMPATIBLE_JWK_MESSAGE} RS256 (kid missing)");
        match err {
            Error::Crypto(message) => assert_eq!(message, expected),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rs256_refetches_when_kid_missing() {
        let (token, jwks) = build_rs256_token_with_kid("good-key");
        let (n, e, _) = rs256_public_components();
        let missing_jwks = jwks_from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": "other-key",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(&n),
                "e": URL_SAFE_NO_PAD.encode(&e),
            }]
        }))
        .expect("jwks");
        let bodies = vec![serde_json::to_string(&jwks).expect("jwks")];
        let (base_url, count, shutdown, handle) = serve_jwks_sequence(bodies);
        let jwks_provider = JwksProvider::new(format!("{}/jwks", base_url))
            .expect("provider")
            .with_preloaded(missing_jwks);
        if let Some(cached) = jwks_provider.cache.write().unwrap().as_mut() {
            cached.fetched_at = Instant::now() - MIN_REFRESH_INTERVAL - Duration::from_millis(1);
        }

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.header.kid.as_deref(), Some("good-key"));
        let _ = shutdown.send(());
        handle.join().expect("server");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "async-validate")]
    #[tokio::test]
    async fn jwt_rs256_refetches_when_kid_missing_async() {
        let (token, jwks) = build_rs256_token_with_kid("good-key");
        let (n, e, _) = rs256_public_components();
        let missing_jwks = jwks_from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": "other-key",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(&n),
                "e": URL_SAFE_NO_PAD.encode(&e),
            }]
        }))
        .expect("jwks");
        let bodies = vec![serde_json::to_string(&jwks).expect("jwks")];
        let (base_url, count, shutdown, handle) = serve_jwks_sequence(bodies);
        let jwks_provider = JwksProviderAsync::new(format!("{}/jwks", base_url))
            .expect("provider")
            .with_preloaded(missing_jwks);
        if let Some(cached) = jwks_provider.cache.write().await.as_mut() {
            cached.fetched_at = Instant::now() - MIN_REFRESH_INTERVAL - Duration::from_millis(1);
        }

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidatorAsync::new(jwks_provider).with_options(options);
        let data = validator
            .validate_access_token(&token)
            .await
            .expect("validate");
        assert_eq!(data.header.kid.as_deref(), Some("good-key"));
        let _ = shutdown.send(());
        handle.join().expect("server");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn jwt_es512_kidless_fails_when_key_beyond_cap() {
        let mut rng = thread_rng();
        let signing_key = P521SigningKey::random(&mut rng);
        let verifying_key = P521VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("x coord");
        let y = encoded_point.y().expect("y coord");

        let mut keys = Vec::new();
        for idx in 0..MAX_KIDLESS_JWKS_KEYS {
            let bad_signing_key = P521SigningKey::random(&mut rng);
            let bad_verifying_key = P521VerifyingKey::from(&bad_signing_key);
            let bad_point = bad_verifying_key.to_encoded_point(false);
            let bad_x = bad_point.x().expect("x coord");
            let bad_y = bad_point.y().expect("y coord");
            keys.push(json!({
                "kty": "EC",
                "crv": "P-521",
                "x": URL_SAFE_NO_PAD.encode(bad_x),
                "y": URL_SAFE_NO_PAD.encode(bad_y),
                "use": "sig",
                "kid": format!("bad-{}", idx),
                "alg": "ES512",
            }));
        }
        keys.push(json!({
            "kty": "EC",
            "crv": "P-521",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "kid": "good-key",
            "alg": "ES512",
        }));

        let jwks = jwks_from_value(json!({ "keys": keys })).expect("jwks");
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let payload = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });
        let header = json!({
            "alg": "ES512",
            "typ": "JWT",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{}.{}", signing_input, signature_b64);

        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::athenz_default().with_es512();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &ErrorKind::InvalidSignature),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rejects_invalid_typ() {
        let (token, jwks) = build_es512_token_with_typ(Some("JAG"));
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::athenz_default().with_es512();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(err) => assert_eq!(err.kind(), &ErrorKind::InvalidToken),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rejects_non_string_typ() {
        let (token, jwks) = build_es512_token_with_typ_value(Some(json!(123)));
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
            fetched_at: Instant::now(),
        });

        let mut options = JwtValidationOptions::athenz_default().with_es512();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(err) => assert_eq!(err.kind(), &ErrorKind::InvalidToken),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    fn jwks_from_value(value: Value) -> Result<JwkSet, Error> {
        let mut value = value;
        sanitize_jwks(&mut value);
        serde_json::from_value(value).map_err(Error::from)
    }
}
