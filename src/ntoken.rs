use crate::error::Error;
use crate::models::PublicKeyEntry;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use pem::parse_many;
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use rand::RngCore;
use reqwest::blocking::Client as HttpClient;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer as SignatureSigner, Verifier as SignatureVerifier};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_VERSION: &str = "S1";
const DEFAULT_EXPIRATION: Duration = Duration::from_secs(60 * 60);
const EXPIRATION_DRIFT: Duration = Duration::from_secs(10 * 60);

const TAG_VERSION: &str = "v";
const TAG_DOMAIN: &str = "d";
const TAG_NAME: &str = "n";
const TAG_KEY_VERSION: &str = "k";
const TAG_KEY_SERVICE: &str = "z";
const TAG_HOSTNAME: &str = "h";
const TAG_IP: &str = "i";
const TAG_GENERATION_TIME: &str = "t";
const TAG_EXPIRE_TIME: &str = "e";
const TAG_SALT: &str = "a";
const TAG_SIGNATURE: &str = "s";

#[derive(Debug, Clone)]
pub struct NToken {
    pub version: String,
    pub domain: String,
    pub name: String,
    pub key_version: String,
    pub key_service: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub generation_time: i64,
    pub expiry_time: i64,
}

pub type NTokenClaims = NToken;

impl NToken {
    pub fn principal_name(&self) -> String {
        format!("{}.{}", self.domain, self.name)
    }

    pub fn is_expired(&self) -> bool {
        let now = unix_time_now();
        self.expiry_time <= now
    }
}

#[derive(Debug, Clone)]
pub struct NTokenBuilder {
    domain: String,
    name: String,
    key_version: String,
    version: String,
    key_service: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    expiration: Duration,
}

impl NTokenBuilder {
    pub fn new(
        domain: impl Into<String>,
        name: impl Into<String>,
        key_version: impl Into<String>,
    ) -> Self {
        let mut domain = domain.into();
        domain.make_ascii_lowercase();
        let mut name = name.into();
        name.make_ascii_lowercase();
        let mut key_version = key_version.into();
        key_version.make_ascii_lowercase();
        Self {
            domain,
            name,
            key_version,
            version: DEFAULT_VERSION.to_string(),
            key_service: None,
            hostname: None,
            ip: None,
            expiration: DEFAULT_EXPIRATION,
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_key_service(mut self, key_service: impl Into<String>) -> Self {
        let mut key_service = key_service.into();
        key_service.make_ascii_lowercase();
        self.key_service = Some(key_service);
        self
    }

    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    pub fn with_expiration(mut self, expiration: Duration) -> Self {
        self.expiration = expiration;
        self
    }

    pub fn set_version(&mut self, version: impl Into<String>) -> &mut Self {
        self.version = version.into();
        self
    }

    pub fn set_key_service(&mut self, key_service: impl Into<String>) -> &mut Self {
        let mut key_service = key_service.into();
        key_service.make_ascii_lowercase();
        self.key_service = Some(key_service);
        self
    }

    pub fn set_hostname(&mut self, hostname: impl Into<String>) -> &mut Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn set_ip(&mut self, ip: impl Into<String>) -> &mut Self {
        self.ip = Some(ip.into());
        self
    }

    pub fn set_expiration(&mut self, expiration: Duration) -> &mut Self {
        self.expiration = expiration;
        self
    }

    pub fn sign(&self, private_key_pem: &[u8]) -> Result<String, Error> {
        let key = load_private_key(private_key_pem)?;
        let (token, _) = sign_with_key(self, &key)?;
        Ok(token)
    }

    fn unsigned_token(&self, now: i64, expiry: i64, salt: &str) -> String {
        let mut parts = Vec::new();
        parts.push(format!("{TAG_VERSION}={}", self.version));
        parts.push(format!("{TAG_DOMAIN}={}", self.domain));
        parts.push(format!("{TAG_NAME}={}", self.name));
        parts.push(format!("{TAG_KEY_VERSION}={}", self.key_version));
        if let Some(ref key_service) = self.key_service {
            parts.push(format!("{TAG_KEY_SERVICE}={key_service}"));
        }
        if let Some(ref hostname) = self.hostname {
            parts.push(format!("{TAG_HOSTNAME}={hostname}"));
        }
        if let Some(ref ip) = self.ip {
            parts.push(format!("{TAG_IP}={ip}"));
        }
        parts.push(format!("{TAG_SALT}={salt}"));
        parts.push(format!("{TAG_GENERATION_TIME}={now}"));
        parts.push(format!("{TAG_EXPIRE_TIME}={expiry}"));
        parts.join(";")
    }
}

#[derive(Clone)]
enum PrivateKey {
    Rsa(RsaPrivateKey),
    P256(P256SigningKey),
    P384(P384SigningKey),
    P521(P521SigningKey),
}

#[derive(Clone)]
enum PublicKey {
    Rsa(RsaPublicKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
    P521(P521VerifyingKey),
}

pub struct NTokenSigner {
    builder: NTokenBuilder,
    key: PrivateKey,
    cached: RwLock<Option<CachedToken>>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expiry_time: i64,
}

impl NTokenSigner {
    pub fn new(
        domain: impl Into<String>,
        name: impl Into<String>,
        key_version: impl Into<String>,
        private_key_pem: &[u8],
    ) -> Result<Self, Error> {
        let key = load_private_key(private_key_pem)?;
        Ok(Self {
            builder: NTokenBuilder::new(domain, name, key_version),
            key,
            cached: RwLock::new(None),
        })
    }

    pub fn builder_mut(&mut self) -> &mut NTokenBuilder {
        &mut self.builder
    }

    pub fn token(&self) -> Result<String, Error> {
        if let Some(cached) = self.cached.read().unwrap().as_ref() {
            let now = unix_time_now();
            if now + EXPIRATION_DRIFT.as_secs() as i64 <= cached.expiry_time {
                return Ok(cached.token.clone());
            }
        }

        let token = self.sign_once()?;
        Ok(token)
    }

    pub fn sign_once(&self) -> Result<String, Error> {
        let (token, expiry) = sign_with_key(&self.builder, &self.key)?;
        let cached = CachedToken {
            token: token.clone(),
            expiry_time: expiry,
        };
        *self.cached.write().unwrap() = Some(cached);
        Ok(token)
    }
}

fn sign_with_key(builder: &NTokenBuilder, key: &PrivateKey) -> Result<(String, i64), Error> {
    let now = unix_time_now();
    let expiry = now + builder.expiration.as_secs() as i64;
    let salt = random_salt()?;
    let unsigned = builder.unsigned_token(now, expiry, &salt);

    let signature = match key {
        PrivateKey::Rsa(rsa_key) => {
            let signing_key = RsaSigningKey::<Sha256>::new(rsa_key.clone());
            let sig = signing_key.sign(unsigned.as_bytes());
            sig.to_vec()
        }
        PrivateKey::P256(signing_key) => {
            let sig: P256Signature = signing_key.sign(unsigned.as_bytes());
            sig.to_vec()
        }
        PrivateKey::P384(signing_key) => {
            let sig: P384Signature = signing_key.sign(unsigned.as_bytes());
            sig.to_vec()
        }
        PrivateKey::P521(signing_key) => {
            let sig: P521Signature = signing_key.sign(unsigned.as_bytes());
            sig.to_vec()
        }
    };
    let signature = ybase64_encode(&signature);

    Ok((format!("{unsigned};{TAG_SIGNATURE}={signature}"), expiry))
}

#[derive(Clone)]
pub struct NTokenVerifier {
    key: PublicKey,
}

impl NTokenVerifier {
    pub fn from_public_key_pem(public_key_pem: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            key: load_public_key(public_key_pem)?,
        })
    }

    pub fn verify(&self, unsigned: &str, signature: &str) -> Result<(), Error> {
        let sig_bytes = ybase64_decode(signature)?;
        match &self.key {
            PublicKey::Rsa(rsa_key) => {
                let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key.clone());
                let sig = RsaSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| Error::Crypto(format!("rsa signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("rsa signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P256(verifying_key) => {
                let sig = P256Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p256 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p256 signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P384(verifying_key) => {
                let sig = P384Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p384 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p384 signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P521(verifying_key) => {
                let sig = P521Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p521 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p521 signature verify error: {e}")))?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NTokenValidatorConfig {
    pub zts_base_url: String,
    pub public_key_fetch_timeout: Duration,
    pub cache_ttl: Duration,
    pub sys_auth_domain: String,
    pub zms_service: String,
    pub zts_service: String,
}

impl Default for NTokenValidatorConfig {
    fn default() -> Self {
        Self {
            zts_base_url: "https://localhost:4443/zts/v1".to_string(),
            public_key_fetch_timeout: Duration::from_secs(5),
            cache_ttl: Duration::from_secs(600),
            sys_auth_domain: "sys.auth".to_string(),
            zms_service: "zms".to_string(),
            zts_service: "zts".to_string(),
        }
    }
}

#[allow(private_interfaces)]
pub enum NTokenValidator {
    Static(NTokenVerifier),
    Zts {
        config: NTokenValidatorConfig,
        cache: RwLock<HashMap<KeySource, CachedKey>>,
        http: HttpClient,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KeySource {
    domain: String,
    name: String,
    key_version: String,
}

#[derive(Clone)]
struct CachedKey {
    verifier: NTokenVerifier,
    expires_at: Instant,
}

impl NTokenValidator {
    pub fn new_with_public_key(public_key_pem: &[u8]) -> Result<Self, Error> {
        Ok(NTokenValidator::Static(
            NTokenVerifier::from_public_key_pem(public_key_pem)?,
        ))
    }

    pub fn new_with_zts(config: NTokenValidatorConfig) -> Result<Self, Error> {
        let http = HttpClient::builder()
            .timeout(config.public_key_fetch_timeout)
            .build()?;
        Ok(NTokenValidator::Zts {
            config,
            cache: RwLock::new(HashMap::new()),
            http,
        })
    }

    pub fn validate(&self, token: &str) -> Result<NToken, Error> {
        let (claims, unsigned, signature) = parse_unverified(token)?;
        match self {
            NTokenValidator::Static(verifier) => {
                verifier.verify(&unsigned, &signature)?;
                if claims.is_expired() {
                    return Err(Error::Crypto("ntoken expired".to_string()));
                }
                Ok(claims)
            }
            NTokenValidator::Zts {
                config,
                cache,
                http,
            } => {
                let src = key_source_from_claims(&claims, config);
                let verifier = get_cached_verifier(cache, http, config, &src)?;
                verifier.verify(&unsigned, &signature)?;
                if claims.is_expired() {
                    return Err(Error::Crypto("ntoken expired".to_string()));
                }
                Ok(claims)
            }
        }
    }
}

fn load_private_key(pem_bytes: &[u8]) -> Result<PrivateKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {e}")))?;
    for block in blocks {
        match block.tag() {
            "RSA PRIVATE KEY" => {
                if let Ok(key) = parse_rsa_private_pkcs1(block.contents()) {
                    return Ok(key);
                }
            }
            "PRIVATE KEY" => {
                if let Ok(key) = parse_rsa_private_pkcs8(block.contents()) {
                    return Ok(key);
                }
                if let Ok(key) = parse_ec_private_pkcs8(block.contents()) {
                    return Ok(key);
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported private key format".to_string()))
}

fn load_public_key(pem_bytes: &[u8]) -> Result<PublicKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {e}")))?;
    for block in blocks {
        match block.tag() {
            "RSA PUBLIC KEY" => {
                if let Ok(key) = parse_rsa_public_pkcs1(block.contents()) {
                    return Ok(key);
                }
            }
            "PUBLIC KEY" => {
                if let Ok(key) = parse_rsa_public_pkcs8(block.contents()) {
                    return Ok(key);
                }
                if let Ok(key) = parse_ec_public_pkcs8(block.contents()) {
                    return Ok(key);
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported public key format".to_string()))
}

fn parse_rsa_private_pkcs1(der: &[u8]) -> Result<PrivateKey, Error> {
    let key = RsaPrivateKey::from_pkcs1_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs1 private key error: {e}")))?;
    Ok(PrivateKey::Rsa(key))
}

fn parse_rsa_private_pkcs8(der: &[u8]) -> Result<PrivateKey, Error> {
    let key = RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs8 private key error: {e}")))?;
    Ok(PrivateKey::Rsa(key))
}

fn parse_ec_private_pkcs8(der: &[u8]) -> Result<PrivateKey, Error> {
    if let Ok(secret) = p256::SecretKey::from_pkcs8_der(der) {
        let key = P256SigningKey::from_bytes(&secret.to_bytes())
            .map_err(|e| Error::Crypto(format!("p256 signing key error: {e}")))?;
        return Ok(PrivateKey::P256(key));
    }
    if let Ok(secret) = p384::SecretKey::from_pkcs8_der(der) {
        let key = P384SigningKey::from_bytes(&secret.to_bytes())
            .map_err(|e| Error::Crypto(format!("p384 signing key error: {e}")))?;
        return Ok(PrivateKey::P384(key));
    }
    if let Ok(secret) = p521::SecretKey::from_pkcs8_der(der) {
        let key = P521SigningKey::from_bytes(&secret.to_bytes())
            .map_err(|e| Error::Crypto(format!("p521 signing key error: {e}")))?;
        return Ok(PrivateKey::P521(key));
    }
    Err(Error::Crypto(
        "unsupported ec pkcs8 private key".to_string(),
    ))
}

fn parse_rsa_public_pkcs1(der: &[u8]) -> Result<PublicKey, Error> {
    let key = RsaPublicKey::from_pkcs1_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs1 public key error: {e}")))?;
    Ok(PublicKey::Rsa(key))
}

fn parse_rsa_public_pkcs8(der: &[u8]) -> Result<PublicKey, Error> {
    let key = RsaPublicKey::from_public_key_der(der)
        .map_err(|e| Error::Crypto(format!("rsa pkcs8 public key error: {e}")))?;
    Ok(PublicKey::Rsa(key))
}

fn parse_ec_public_pkcs8(der: &[u8]) -> Result<PublicKey, Error> {
    if let Ok(public_key) = p256::PublicKey::from_public_key_der(der) {
        let encoded = public_key.to_encoded_point(false);
        let key = P256VerifyingKey::from_encoded_point(&encoded)
            .map_err(|e| Error::Crypto(format!("p256 public key error: {e}")))?;
        return Ok(PublicKey::P256(key));
    }
    if let Ok(public_key) = p384::PublicKey::from_public_key_der(der) {
        let encoded = public_key.to_encoded_point(false);
        let key = P384VerifyingKey::from_encoded_point(&encoded)
            .map_err(|e| Error::Crypto(format!("p384 public key error: {e}")))?;
        return Ok(PublicKey::P384(key));
    }
    if let Ok(public_key) = p521::PublicKey::from_public_key_der(der) {
        let encoded = public_key.to_encoded_point(false);
        let key = P521VerifyingKey::from_encoded_point(&encoded)
            .map_err(|e| Error::Crypto(format!("p521 public key error: {e}")))?;
        return Ok(PublicKey::P521(key));
    }
    Err(Error::Crypto("unsupported ec public key".to_string()))
}

fn get_cached_verifier(
    cache: &RwLock<HashMap<KeySource, CachedKey>>,
    http: &HttpClient,
    config: &NTokenValidatorConfig,
    src: &KeySource,
) -> Result<NTokenVerifier, Error> {
    if let Some(entry) = cache.read().unwrap().get(src) {
        if entry.expires_at > Instant::now() {
            return Ok(entry.verifier.clone());
        }
    }

    let url = format!(
        "{}/domain/{}/service/{}/publickey/{}",
        config.zts_base_url.trim_end_matches('/'),
        src.domain,
        src.name,
        src.key_version
    );
    let resp = http.get(url).send()?;
    if !resp.status().is_success() {
        return Err(Error::Crypto(format!(
            "unable to fetch public key: status {}",
            resp.status()
        )));
    }
    let entry: PublicKeyEntry = resp.json()?;
    let pem_bytes = ybase64_decode(&entry.key)?;
    let verifier = NTokenVerifier::from_public_key_pem(&pem_bytes)?;

    let cached = CachedKey {
        verifier: verifier.clone(),
        expires_at: Instant::now() + config.cache_ttl,
    };
    cache.write().unwrap().insert(src.clone(), cached);
    Ok(verifier)
}

fn key_source_from_claims(claims: &NToken, config: &NTokenValidatorConfig) -> KeySource {
    if let Some(ref key_service) = claims.key_service {
        if key_service == &config.zms_service {
            return KeySource {
                domain: config.sys_auth_domain.clone(),
                name: config.zms_service.clone(),
                key_version: claims.key_version.clone(),
            };
        }
        if key_service == &config.zts_service {
            return KeySource {
                domain: config.sys_auth_domain.clone(),
                name: config.zts_service.clone(),
                key_version: claims.key_version.clone(),
            };
        }
    }

    if claims.version.starts_with('U') {
        return KeySource {
            domain: config.sys_auth_domain.clone(),
            name: config.zms_service.clone(),
            key_version: claims.key_version.clone(),
        };
    }

    KeySource {
        domain: claims.domain.clone(),
        name: claims.name.clone(),
        key_version: claims.key_version.clone(),
    }
}

fn parse_unverified(token: &str) -> Result<(NToken, String, String), Error> {
    let (unsigned, signature) = split_token(token)?;
    let claims = parse_claims(&unsigned)?;
    Ok((claims, unsigned, signature))
}

fn split_token(token: &str) -> Result<(String, String), Error> {
    let delim = format!(";{TAG_SIGNATURE}=");
    let mut parts = token.splitn(2, &delim);
    let unsigned = parts
        .next()
        .ok_or_else(|| Error::Crypto("invalid ntoken".to_string()))?;
    let signature = parts
        .next()
        .ok_or_else(|| Error::Crypto("ntoken missing signature".to_string()))?;
    Ok((unsigned.to_string(), signature.to_string()))
}

fn parse_claims(unsigned: &str) -> Result<NToken, Error> {
    let mut claims = NToken {
        version: String::new(),
        domain: String::new(),
        name: String::new(),
        key_version: String::new(),
        key_service: None,
        hostname: None,
        ip: None,
        generation_time: 0,
        expiry_time: 0,
    };

    for part in unsigned.split(';') {
        let mut kv = part.splitn(2, '=');
        let key = kv
            .next()
            .ok_or_else(|| Error::Crypto("invalid ntoken field".to_string()))?;
        let value = kv
            .next()
            .ok_or_else(|| Error::Crypto("invalid ntoken field".to_string()))?;
        match key {
            TAG_VERSION => claims.version = value.to_string(),
            TAG_DOMAIN => claims.domain = value.to_string(),
            TAG_NAME => claims.name = value.to_string(),
            TAG_KEY_VERSION => claims.key_version = value.to_string(),
            TAG_KEY_SERVICE => claims.key_service = Some(value.to_string()),
            TAG_HOSTNAME => claims.hostname = Some(value.to_string()),
            TAG_IP => claims.ip = Some(value.to_string()),
            TAG_GENERATION_TIME => claims.generation_time = parse_unix(value)?,
            TAG_EXPIRE_TIME => claims.expiry_time = parse_unix(value)?,
            TAG_SALT | TAG_SIGNATURE => {}
            _ => {}
        }
    }

    if claims.version.is_empty()
        || claims.domain.is_empty()
        || claims.name.is_empty()
        || claims.key_version.is_empty()
        || claims.generation_time == 0
        || claims.expiry_time == 0
    {
        return Err(Error::Crypto("invalid ntoken claims".to_string()));
    }

    Ok(claims)
}

fn parse_unix(value: &str) -> Result<i64, Error> {
    value
        .parse::<i64>()
        .map_err(|_| Error::Crypto(format!("invalid unix time: {value}")))
}

fn unix_time_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_salt() -> Result<String, Error> {
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    Ok(hex::encode(buf))
}

fn ybase64_encode(data: &[u8]) -> String {
    let encoded = BASE64_STD.encode(data);
    encoded
        .replace('+', ".")
        .replace('/', "_")
        .replace('=', "-")
}

fn ybase64_decode(data: &str) -> Result<Vec<u8>, Error> {
    let normalized = data.replace('.', "+").replace('_', "/").replace('-', "=");
    BASE64_STD
        .decode(normalized.as_bytes())
        .map_err(|e| Error::Crypto(format!("ybase64 decode error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454
BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURxVCa0JTzAPJw6/JIoyOZnHZCoarcg
QQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI+gpaQZa7rSytU5RFSG
OnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/v+YrUFtjxBKsG1UrWbnHbgciiN5U
2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG
99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1etawIDAQABAoIBAD67C7/N56WdJodt
soNkvcnXPEfrG+W9+Hc/RQvwljnxCKoxfUuMfYrbj2pLLnrfDfo/hYukyeKcCYwx
xN9VcMK1BaPMLpX0bdtY+m+T73KyPbqT3ycqBbXVImFM/L67VLxcrqUgVOuNcn67
IWWLQF6pWpErJaVk87/Ys/4DmpJXebLDyta8+ce6r0ppSG5+AifGo1byQT7kSJkF
lyQsyKWoVN+02s7gLsln5JXXZ672y2Xtp/S3wK0vfzy/HcGSxzn1yE0M5UJtDm/Y
qECnV1LQ0FB1l1a+/itHR8ipp5rScD4ZpzOPLKthglEvNPe4Lt5rieH9TR97siEe
SrC8uyECgYEA5Q/elOJAddpE+cO22gTFt973DcPGjM+FYwgdrora+RfEXJsMDoKW
AGSm5da7eFo8u/bJEvHSJdytc4CRQYnWNryIaUw2o/1LYXRvoEt1rEEgQ4pDkErR
PsVcVuc3UDeeGtYJwJLV6pjxO11nodFv4IgaVj64SqvCOApTTJgWXF0CgYEA3gzN
d3l376mSMuKc4Ep++TxybzA5mtF2qoXucZOon8EDJKr+vGQ9Z6X4YSdkSMNXqK1j
ILmFH7V3dyMOKRBA84YeawFacPLBJq+42t5Q1OYdcKZbaArlBT8ImGT7tQODs3JN
4w7DH+V1v/VCTl2zQaZRksb0lUsQbFiEfj+SVGcCgYAYIlDoTOJPyHyF+En2tJQE
aHiNObhcs6yxH3TJJBYoMonc2/UsPjQBvJkdFD/SUWeewkSzO0lR9etMhRpI1nX8
dGbG+WG0a4aasQLl162BRadZlmLB/DAJtg+hlGDukb2VxEFoyc/CFPUttQyrLv7j
oFNuDNOsAmbHMsdOBaQtfQKBgQCb/NRuRNebdj0tIALikZLHVc5yC6e7+b/qJPIP
uZIwv++MV89h2u1EHdTxszGA6DFxXnSPraQ2VU2aVPcCo9ds+9/sfePiCrbjjXhH
0PtpxEoUM9lsqpKeb9yC6hXk4JYpfnf2tQ0gIBrrAclVsf9WdBdEDB4Prs7Xvgs9
gT0zqwKBgQCzZubFO0oTYO9e2r8wxPPPsE3ZCjbP/y7lIoBbSzxDGUubXmbvD0GO
MC8dM80plsTym96UxpKkQMAglKKLPtG2n8xB8v5H/uIB4oIegMSEx3F7MRWWIQmR
Gea7bQ16YCzM/l2yygGhAW61bg2Z2GoVF6X5z/qhKGyo97V87qTbmg==
-----END RSA PRIVATE KEY-----
"#;

    const RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxq83nCd8AqH5n40dEBME
lbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURx
VCa0JTzAPJw6/JIoyOZnHZCoarcgQQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLg
GqVN4BoEEI+gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/
v+YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8m
LAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1et
awIDAQAB
-----END PUBLIC KEY-----
"#;

    #[test]
    fn ntoken_sign_and_verify_rsa() {
        let signer =
            NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
        let token = signer.sign_once().expect("token");
        let validator =
            NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
        let claims = validator.validate(&token).expect("validate");
        assert_eq!(claims.domain, "sports");
        assert_eq!(claims.name, "api");
    }

    #[test]
    fn ntoken_builder_lowercases_fields() {
        let builder = NTokenBuilder::new("Sports", "API", "V1").with_key_service("ZTS");
        let token = builder.sign(RSA_PRIVATE_KEY.as_bytes()).expect("token");
        let validator =
            NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
        let claims = validator.validate(&token).expect("validate");
        assert_eq!(claims.domain, "sports");
        assert_eq!(claims.name, "api");
        assert_eq!(claims.key_version, "v1");
        assert_eq!(claims.key_service.as_deref(), Some("zts"));
    }

    #[test]
    fn ntoken_signer_builder_mut_updates_fields() {
        let mut signer =
            NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
        signer
            .builder_mut()
            .set_hostname("host.example")
            .set_ip("127.0.0.1")
            .set_key_service("ZTS")
            .set_version("S2")
            .set_expiration(Duration::from_secs(90));
        let token = signer.sign_once().expect("token");
        let validator =
            NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
        let claims = validator.validate(&token).expect("validate");
        assert_eq!(claims.hostname.as_deref(), Some("host.example"));
        assert_eq!(claims.ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(claims.key_service.as_deref(), Some("zts"));
        assert_eq!(claims.version, "S2");
        assert_eq!(claims.expiry_time - claims.generation_time, 90);
    }
}
