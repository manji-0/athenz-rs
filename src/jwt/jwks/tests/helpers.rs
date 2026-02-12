use super::super::provider::CachedJwks;
use super::super::sanitize::sanitize_jwks;
use super::super::JwksProvider;
use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
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
use std::time::{Duration, Instant};

pub(super) fn build_es512_token() -> (String, JwkSet) {
    build_es512_token_with_typ_value(Some(json!("JWT")))
}

pub(super) fn build_es512_token_with_typ(typ: Option<&str>) -> (String, JwkSet) {
    build_es512_token_with_typ_value(typ.map(|value| json!(value)))
}

pub(super) fn build_es512_token_with_typ_value(typ: Option<Value>) -> (String, JwkSet) {
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
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let token = format!("{}.{}", signing_input, signature_b64);

    (token, jwks)
}

pub(super) fn build_es512_token_without_kid() -> (String, JwkSet) {
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
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let token = format!("{}.{}", signing_input, signature_b64);

    (token, jwks)
}

pub(super) fn rsa_private_key_pem() -> &'static str {
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

pub(super) fn rs256_public_components() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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

pub(super) fn build_rs256_token_with_kid_and_claims(kid: &str, claims: Value) -> (String, JwkSet) {
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

pub(super) fn build_rs256_token_with_kid(kid: &str) -> (String, JwkSet) {
    let exp = jsonwebtoken::get_current_timestamp() + 3600;
    let claims = json!({
        "iss": "athenz",
        "aud": "client",
        "sub": "principal",
        "exp": exp,
    });
    build_rs256_token_with_kid_and_claims(kid, claims)
}

pub(super) fn serve_jwks_sequence(
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

pub(super) fn rs256_token_without_kid() -> String {
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

pub(super) fn build_rs256_token_without_kid() -> (String, JwkSet) {
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

pub(super) fn jwks_provider_with_seeded_cache(jwks: JwkSet) -> JwksProvider {
    let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
    *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
        jwks,
        expires_at: Instant::now() + Duration::from_secs(60),
        fetched_at: Instant::now(),
    });
    jwks_provider
}

pub(super) fn jwks_from_value(value: Value) -> Result<JwkSet, Error> {
    let mut value = value;
    sanitize_jwks(&mut value);
    serde_json::from_value(value).map_err(Error::from)
}
