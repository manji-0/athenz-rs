use super::super::provider::CachedJwks;
use super::super::JwksProvider;
use super::helpers::{
    build_rs256_token_with_kid, build_rs256_token_with_kid_and_claims,
    build_rs256_token_without_kid, jwks_from_value, jwks_provider_with_seeded_cache,
    rs256_public_components, rs256_token_without_kid,
};
use crate::error::Error;
use crate::jwt::constants::{MAX_KIDLESS_JWKS_KEYS, NO_COMPATIBLE_JWK_MESSAGE};
use crate::jwt::{JwtValidationOptions, JwtValidator};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use serde_json::json;
use std::time::{Duration, Instant};

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
fn jwt_rs256_rejects_jwk_use_enc() {
    let (token, _jwks) = build_rs256_token_with_kid("good-key");
    let (n, e, _) = rs256_public_components();
    let jwks = jwks_from_value(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "good-key",
            "alg": "RS256",
            "use": "enc",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e),
        }]
    }))
    .expect("jwks");
    let jwks_provider = jwks_provider_with_seeded_cache(jwks);

    let mut options = JwtValidationOptions::rsa_only();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidator::new(jwks_provider).with_options(options);
    let err = validator
        .validate_access_token(&token)
        .expect_err("should reject");
    match err {
        Error::MissingJwk(kid) => assert_eq!(kid, "good-key"),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn jwt_rs256_rejects_jwk_alg_mismatch() {
    let (token, _jwks) = build_rs256_token_with_kid("good-key");
    let (n, e, _) = rs256_public_components();
    let jwks = jwks_from_value(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "good-key",
            "alg": "RS512",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e),
        }]
    }))
    .expect("jwks");
    let jwks_provider = jwks_provider_with_seeded_cache(jwks);

    let mut options = JwtValidationOptions::rsa_only();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidator::new(jwks_provider).with_options(options);
    let err = validator
        .validate_access_token(&token)
        .expect_err("should reject");
    match err {
        Error::MissingJwk(kid) => assert_eq!(kid, "good-key"),
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
    let (_es_token, jwks) = super::helpers::build_es512_token_without_kid();
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
