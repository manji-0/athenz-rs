use super::{RSA_PRIVATE_KEY, RSA_PUBLIC_KEY};
use crate::ntoken::keys::load_private_key;
use crate::ntoken::token::sign_with_key_at;
use crate::ntoken::{NTokenBuilder, NTokenSigner, NTokenValidationOptions, NTokenValidator};
use std::time::Duration;

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
fn ntoken_parse_claims_lowercases_domain_and_service() {
    let unsigned = "v=S1;d=Sports;n=API;k=v1;z=ZTS;a=abc;t=1;e=2";
    let claims = super::super::helpers::parse_claims(unsigned).expect("claims");
    assert_eq!(claims.domain, "sports");
    assert_eq!(claims.name, "api");
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

#[test]
fn ntoken_signer_builder_mut_invalidates_cached_token() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    let token = signer.token().expect("token");
    signer.builder_mut().set_hostname("host.example");
    let token_after = signer.token().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let claims = validator.validate(&token_after).expect("validate");
    assert_eq!(claims.hostname.as_deref(), Some("host.example"));
    assert_ne!(token, token_after);
}

#[test]
fn ntoken_validate_rejects_future_generation_time() {
    let builder = NTokenBuilder::new("sports", "api", "v1");
    let key = load_private_key(RSA_PRIVATE_KEY.as_bytes()).expect("private key");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default();
    let now = crate::ntoken::token::unix_time_now();
    let offset = i64::try_from(options.allowed_offset().as_secs()).unwrap();
    let generation_time = now + offset + 60;
    let expiry_time = generation_time + 60;
    let token = sign_with_key_at(&builder, &key, generation_time, expiry_time).expect("token");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("future generation time");
    assert!(err.to_string().contains("future timestamp"));
}
