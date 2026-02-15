#![cfg(feature = "async-validate")]

use athenz_rs::{
    DomainSignedPolicyData, Error, JWSPolicyData, JwksProviderAsync, JwtValidationOptions,
    JwtValidatorAsync, NTokenSigner, NTokenValidatorAsync, NTokenValidatorConfig,
    PolicyClientAsync, PolicyData, SignedPolicyData, ZtsAsyncClient,
};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rand::thread_rng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use serde_json::json;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

mod common;
use common::serve_once;

#[tokio::test]
async fn jwks_provider_fetches_keys() {
    let body = r#"{"keys":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let provider =
        JwksProviderAsync::new(format!("{}/zts/v1/oauth2/keys", base_url)).expect("provider");
    let jwks = provider.fetch().await.expect("fetch");
    assert!(jwks.keys.is_empty());

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/oauth2/keys");
}

#[tokio::test]
async fn jwks_provider_uses_cache() {
    let body = r#"{"keys":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let provider =
        JwksProviderAsync::new(format!("{}/zts/v1/oauth2/keys", base_url)).expect("provider");
    let first = provider.fetch().await.expect("first fetch");
    assert!(first.keys.is_empty());
    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/oauth2/keys");

    let second = provider.fetch().await.expect("second fetch");
    assert!(second.keys.is_empty());
}

#[tokio::test]
async fn jwks_provider_reports_non_success() {
    let body = "boom";
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, _rx) = serve_once(response).await;

    let provider =
        JwksProviderAsync::new(format!("{}/zts/v1/oauth2/keys", base_url)).expect("provider");
    let err = provider.fetch().await.expect_err("should error");
    let message = format!("{}", err);
    assert!(message.contains("status 500"));
}

#[tokio::test]
async fn jwt_es512_async_validate_success() {
    let (token, jwks) = build_es512_token();
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default().with_es512();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let data = validator
        .validate_access_token(&token)
        .await
        .expect("validate");
    assert_eq!(data.claims["iss"], "athenz");
    assert_eq!(data.claims["aud"], "client");
    assert_eq!(data.header.alg, "ES512");
}

#[tokio::test]
async fn jwt_rs256_async_validate_success() {
    let token = build_rs256_token(Some("good-key"));
    let (n, e, _) = rs256_public_components();
    let jwks = build_rs256_jwks(&n, &e, "good-key");
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let data = validator
        .validate_access_token(&token)
        .await
        .expect("validate");
    assert_eq!(data.header.alg, "RS256");
}

#[tokio::test]
async fn jwt_rs256_async_rejects_invalid_typ() {
    let header = json!({
        "alg": "RS256",
        "kid": "good-key",
        "typ": "JAG",
    });
    let token = build_rs256_token_with_header(header);
    let (n, e, _) = rs256_public_components();
    let jwks = build_rs256_jwks(&n, &e, "good-key");
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let err = validator
        .validate_access_token(&token)
        .await
        .expect_err("should reject");
    match err {
        Error::Jwt(err) => assert_eq!(err.kind(), &ErrorKind::InvalidToken),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn jwt_rs256_async_rejects_non_string_typ() {
    let header = json!({
        "alg": "RS256",
        "kid": "good-key",
        "typ": 123,
    });
    let token = build_rs256_token_with_header(header);
    let (n, e, _) = rs256_public_components();
    let jwks = build_rs256_jwks(&n, &e, "good-key");
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let err = validator
        .validate_access_token(&token)
        .await
        .expect_err("should reject");
    match err {
        Error::Jwt(err) => assert_eq!(err.kind(), &ErrorKind::InvalidToken),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn jwt_rs256_async_kidless_falls_back_to_matching_key() {
    let token = build_rs256_token(None);
    let (n, e, bad_n) = rs256_public_components();
    let jwks = build_rs256_jwks_pair(&bad_n, &n, &e);
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let data = validator
        .validate_access_token(&token)
        .await
        .expect("validate");
    assert_eq!(data.header.alg, "RS256");
}

#[tokio::test]
async fn jwt_rs256_async_rejects_unknown_kid() {
    let token = build_rs256_token(Some("missing"));
    let (n, e, _) = rs256_public_components();
    let jwks = build_rs256_jwks(&n, &e, "good-key");
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let err = validator
        .validate_access_token(&token)
        .await
        .expect_err("should fail");
    let message = format!("{}", err);
    assert!(message.contains("missing jwk"));
}

#[tokio::test]
async fn jwt_rs256_async_reports_jwks_fetch_failure() {
    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, _rx) = serve_once(response).await;
    let provider = JwksProviderAsync::new(format!("{}/jwks", base_url)).expect("provider");

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let token = build_rs256_token(Some("good-key"));
    let err = validator
        .validate_access_token(&token)
        .await
        .expect_err("should fail");
    let message = format!("{}", err);
    assert!(message.contains("jwks fetch failed"));
}

#[tokio::test]
async fn ntoken_validator_async_uses_cache() {
    let signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    let token = signer.sign_once().expect("token");

    let body = format!(
        r#"{{"key":"{}","id":"v1"}}"#,
        ybase64_encode(RSA_PUBLIC_KEY.as_bytes())
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let mut config = NTokenValidatorConfig::default();
    config.zts_base_url = format!("{}/zts/v1", base_url);
    let validator = NTokenValidatorAsync::new_with_zts(config).expect("validator");

    validator.validate(&token).await.expect("first validate");
    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/domain/sports/service/api/publickey/v1");

    validator.validate(&token).await.expect("second validate");
}

#[tokio::test]
async fn ntoken_validator_async_sends_auth_header_when_fetching_zts_public_key() {
    let signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    let token = signer.sign_once().expect("token");

    let body = format!(
        r#"{{"key":"{}","id":"v1"}}"#,
        ybase64_encode(RSA_PUBLIC_KEY.as_bytes())
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let mut config = NTokenValidatorConfig::default();
    config.zts_base_url = format!("{}/zts/v1", base_url);
    config.public_key_fetch_auth_header = Some((
        "Athenz-Principal-Auth".to_string(),
        "NToken dummy".to_string(),
    ));
    let validator = NTokenValidatorAsync::new_with_zts(config).expect("validator");

    validator.validate(&token).await.expect("validate");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/domain/sports/service/api/publickey/v1");
    assert_eq!(
        req.header_value("Athenz-Principal-Auth"),
        Some("NToken dummy")
    );
}

#[tokio::test]
async fn ntoken_validator_async_limits_zts_key_cache_entries() {
    let response = zts_public_key_response();
    let (base_url, request_count, handle) =
        spawn_zts_key_server(response, 3, Duration::from_secs(2)).await;

    let mut config = NTokenValidatorConfig::default();
    config.zts_base_url = format!("{}/zts/v1", base_url);
    config.max_cache_entries = 1;
    let validator = NTokenValidatorAsync::new_with_zts(config).expect("validator");

    let token_v1 = NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes())
        .expect("signer")
        .sign_once()
        .expect("v1 token");
    let token_v2 = NTokenSigner::new("sports", "api", "v2", RSA_PRIVATE_KEY.as_bytes())
        .expect("signer")
        .sign_once()
        .expect("v2 token");

    validator
        .validate(&token_v1)
        .await
        .expect("v1 first validate");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);

    validator
        .validate(&token_v1)
        .await
        .expect("v1 cached validate");
    assert_eq!(request_count.load(Ordering::SeqCst), 1);

    validator.validate(&token_v2).await.expect("v2 validate");
    assert_eq!(request_count.load(Ordering::SeqCst), 2);

    validator
        .validate(&token_v1)
        .await
        .expect("v1 after eviction validate");
    assert_eq!(request_count.load(Ordering::SeqCst), 3);

    handle.await.expect("mock zts key server task should exit");
}

#[tokio::test]
async fn policy_client_async_validates_jws_policy_data() {
    let now = OffsetDateTime::now_utc();
    let expires = (now + time::Duration::seconds(300))
        .format(&Rfc3339)
        .expect("expires");
    let modified = now.format(&Rfc3339).expect("modified");

    let signed_policy = SignedPolicyData {
        policy_data: PolicyData {
            domain: "sports".to_string(),
            policies: Vec::new(),
        },
        zms_signature: None,
        zms_key_id: None,
        modified,
        expires,
    };

    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RS256",
            "kid": "v1",
        }))
        .expect("header"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed_policy).expect("payload"));
    let signing_input = format!("{}.{}", protected, payload);

    let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let jws = JWSPolicyData {
        payload,
        protected_header: protected,
        header: None,
        signature: signature_b64,
    };

    let body = format!(
        r#"{{"key":"{}","id":"v1"}}"#,
        ybase64_encode(RSA_PUBLIC_KEY.as_bytes())
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let zts = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");
    let client = PolicyClientAsync::new(zts);
    let policy = client
        .validate_jws_policy_data(&jws)
        .await
        .expect("validate");
    assert_eq!(policy.domain, "sports");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/domain/sys.auth/service/zts/publickey/v1");
    assert!(req.header_value("Host").is_some());
    assert!(req.query_value("missing").is_none());
}

#[tokio::test]
async fn policy_client_async_rejects_expired_jws_policy_data() {
    let now = OffsetDateTime::now_utc();
    let expires = (now - time::Duration::seconds(5))
        .format(&Rfc3339)
        .expect("expires");
    let modified = now.format(&Rfc3339).expect("modified");
    let signed_policy = SignedPolicyData {
        policy_data: PolicyData {
            domain: "sports".to_string(),
            policies: Vec::new(),
        },
        zms_signature: None,
        zms_key_id: None,
        modified,
        expires,
    };
    let jws = build_jws_policy_data(&signed_policy);

    let response = zts_public_key_response();
    let (base_url, rx) = serve_once(response).await;
    let zts = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");
    let client = PolicyClientAsync::new(zts);

    let err = client
        .validate_jws_policy_data(&jws)
        .await
        .expect_err("should fail");
    let message = format!("{}", err);
    assert!(message.contains("policy data is expired"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/domain/sys.auth/service/zts/publickey/v1");
}

#[tokio::test]
async fn policy_client_async_rejects_missing_zms_signature_for_jws_policy_data() {
    let now = OffsetDateTime::now_utc();
    let expires = (now + time::Duration::seconds(300))
        .format(&Rfc3339)
        .expect("expires");
    let modified = now.format(&Rfc3339).expect("modified");
    let signed_policy = SignedPolicyData {
        policy_data: PolicyData {
            domain: "sports".to_string(),
            policies: Vec::new(),
        },
        zms_signature: None,
        zms_key_id: None,
        modified,
        expires,
    };
    let jws = build_jws_policy_data(&signed_policy);

    let response = zts_public_key_response();
    let (base_url, rx) = serve_once(response).await;
    let zts = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");
    let mut client = PolicyClientAsync::new(zts);
    client.config_mut().check_zms_signature = true;

    let err = client
        .validate_jws_policy_data(&jws)
        .await
        .expect_err("should fail");
    let message = format!("{}", err);
    assert!(message.contains("missing zms signature"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/domain/sys.auth/service/zts/publickey/v1");
}

#[tokio::test]
async fn policy_client_async_rejects_missing_zms_signature_for_signed_policy_data() {
    let now = OffsetDateTime::now_utc();
    let expires = (now + time::Duration::seconds(300))
        .format(&Rfc3339)
        .expect("expires");
    let modified = now.format(&Rfc3339).expect("modified");
    let signed_policy = SignedPolicyData {
        policy_data: PolicyData {
            domain: "sports".to_string(),
            policies: Vec::new(),
        },
        zms_signature: None,
        zms_key_id: None,
        modified,
        expires,
    };
    let signed = build_domain_signed_policy_data(&signed_policy);

    let response = zts_public_key_response();
    let (base_url, rx) = serve_once(response).await;
    let zts = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");
    let mut client = PolicyClientAsync::new(zts);
    client.config_mut().check_zms_signature = true;

    let err = client
        .validate_signed_policy_data(&signed)
        .await
        .expect_err("should fail");
    let message = format!("{}", err);
    assert!(message.contains("missing zms signature"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/domain/sys.auth/service/zts/publickey/v1");
}

fn rs256_public_components() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
    let public_key = RsaPublicKey::from(&private_key);
    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();
    let mut bad_n = n.clone();
    if let Some(last) = bad_n.last_mut() {
        *last ^= 0x01;
    }
    (n, e, bad_n)
}

fn build_rs256_token(kid: Option<&str>) -> String {
    let exp = jsonwebtoken::get_current_timestamp() + 3600;
    let claims = json!({
        "iss": "athenz",
        "aud": "client",
        "sub": "principal",
        "exp": exp,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(|value| value.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes()).expect("encoding key"),
    )
    .expect("token")
}

fn build_rs256_token_with_header(header: serde_json::Value) -> String {
    let exp = jsonwebtoken::get_current_timestamp() + 3600;
    let claims = json!({
        "iss": "athenz",
        "aud": "client",
        "sub": "principal",
        "exp": exp,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("payload json"));
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    format!("{}.{}", signing_input, signature_b64)
}

fn build_rs256_jwks(n: &[u8], e: &[u8], kid: &str) -> JwkSet {
    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(n),
            "e": URL_SAFE_NO_PAD.encode(e),
        }]
    });
    serde_json::from_value(jwks_json).expect("jwks")
}

fn build_rs256_jwks_pair(bad_n: &[u8], good_n: &[u8], e: &[u8]) -> JwkSet {
    let jwks_json = json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "bad-key",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(bad_n),
                "e": URL_SAFE_NO_PAD.encode(e),
            },
            {
                "kty": "RSA",
                "kid": "good-key",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(good_n),
                "e": URL_SAFE_NO_PAD.encode(e),
            }
        ]
    });
    serde_json::from_value(jwks_json).expect("jwks")
}

fn build_es512_token() -> (String, JwkSet) {
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
            "kid": kid
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("jwks");

    let header = json!({
        "alg": "ES512",
        "kid": kid,
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

fn ybase64_encode(data: &[u8]) -> String {
    BASE64_STD
        .encode(data)
        .replace('+', ".")
        .replace('/', "_")
        .replace('=', "-")
}

fn zts_public_key_response() -> String {
    let body = format!(
        r#"{{"key":"{}","id":"v1"}}"#,
        ybase64_encode(RSA_PUBLIC_KEY.as_bytes())
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

async fn spawn_zts_key_server(
    response: String,
    expected_requests: usize,
    timeout_duration: Duration,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_for_task = request_count.clone();
    let handle = tokio::spawn(async move {
        let mut served = 0usize;
        let deadline = tokio::time::Instant::now() + timeout_duration;
        while served < expected_requests {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining.min(Duration::from_millis(10)), listener.accept()).await {
                Ok(Ok((mut stream, _))) => {
                    let _ = consume_http_request_async(&mut stream).await;
                    let _ = stream.write_all(response.as_bytes()).await;
                    request_count_for_task.fetch_add(1, Ordering::SeqCst);
                    served += 1;
                }
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
    });

    (base_url, request_count, handle)
}

async fn consume_http_request_async(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(())
}

fn build_jws_policy_data(signed_policy: &SignedPolicyData) -> JWSPolicyData {
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RS256",
            "kid": "v1",
        }))
        .expect("header"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(signed_policy).expect("payload"));
    let signing_input = format!("{}.{}", protected, payload);
    let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    JWSPolicyData {
        payload,
        protected_header: protected,
        header: None,
        signature: signature_b64,
    }
}

fn build_domain_signed_policy_data(signed_policy: &SignedPolicyData) -> DomainSignedPolicyData {
    let signed_json = canonical_json(&serde_json::to_value(signed_policy).expect("signed policy"));
    let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signed_json.as_bytes());
    let signature_b64 = ybase64_encode(signature.to_bytes().as_ref());
    DomainSignedPolicyData {
        signed_policy_data: signed_policy.clone(),
        signature: signature_b64,
        key_id: "v1".to_string(),
    }
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for key in keys {
                let key_json = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""));
                let val = canonical_json(&map[key]);
                parts.push(format!("{key_json}:{val}"));
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(list) => {
            let mut parts = Vec::new();
            for item in list {
                parts.push(canonical_json(item));
            }
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::String(val) => {
            serde_json::to_string(val).unwrap_or_else(|_| format!("\"{val}\""))
        }
        serde_json::Value::Number(val) => val.to_string(),
        serde_json::Value::Bool(val) => val.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

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
-----END RSA PRIVATE KEY-----"#;

const RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxq83nCd8AqH5n40dEBME
lbaJd2gFWu6bjhNzyp9562dpf454BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURx
VCa0JTzAPJw6/JIoyOZnHZCoarcgQQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLg
GqVN4BoEEI+gpaQZa7rSytU5RFSGOnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/
v+YrUFtjxBKsG1UrWbnHbgciiN5U2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8m
LAsEhjV1sP8GItjfdfwXpXT7q2QG99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1et
awIDAQAB
-----END PUBLIC KEY-----"#;
