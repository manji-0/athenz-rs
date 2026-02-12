use super::super::provider::MIN_REFRESH_INTERVAL;
use super::super::JwksProvider;
#[cfg(feature = "async-validate")]
use super::super::JwksProviderAsync;
use super::helpers::{build_rs256_token_with_kid, rs256_public_components, serve_jwks_sequence};
use crate::jwt::JwtValidationOptions;
use crate::jwt::JwtValidator;
#[cfg(feature = "async-validate")]
use crate::jwt::JwtValidatorAsync;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[test]
fn jwt_rs256_refetches_when_kid_missing() {
    let (token, jwks) = build_rs256_token_with_kid("good-key");
    let (n, e, _) = rs256_public_components();
    let missing_jwks = super::helpers::jwks_from_value(json!({
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
    let missing_jwks = super::helpers::jwks_from_value(json!({
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
