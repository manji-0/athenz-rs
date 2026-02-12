use super::super::provider::CachedJwks;
use super::super::JwksProvider;
use super::helpers::{build_es512_token_with_typ, build_es512_token_with_typ_value};
use crate::error::Error;
use crate::jwt::{JwtValidationOptions, JwtValidator};
use jsonwebtoken::errors::ErrorKind;
use serde_json::json;
use std::time::{Duration, Instant};

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
