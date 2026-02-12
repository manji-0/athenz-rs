use super::super::provider::CachedJwks;
use super::super::JwksProvider;
use super::helpers::{
    build_es512_token, build_es512_token_without_kid, jwks_from_value,
    jwks_provider_with_seeded_cache,
};
use crate::error::Error;
use crate::jwt::constants::{ES512_DISABLED_MESSAGE, MAX_KIDLESS_JWKS_KEYS};
use crate::jwt::{JwtValidationOptions, JwtValidator};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rand::thread_rng;
use serde_json::json;
use signature::Signer;
use std::time::{Duration, Instant};

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
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
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
