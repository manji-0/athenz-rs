use super::{RSA_PRIVATE_KEY, RSA_PUBLIC_KEY};
use crate::ntoken::keys::load_private_key;
use crate::ntoken::token::{sign_with_key_at, unix_time_now};
use crate::ntoken::validator::checks::validate_authorized_service_claims;
use crate::ntoken::NToken;
use crate::ntoken::{NTokenBuilder, NTokenSigner, NTokenValidationOptions, NTokenValidator};

#[test]
fn ntoken_validate_user_version_requires_user_domain() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_version("U1");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let err = validator.validate(&token).expect_err("domain mismatch");
    assert!(err
        .to_string()
        .contains("user version requires domain 'user'"));
}

#[test]
fn ntoken_validate_user_domain_requires_user_version() {
    let signer =
        NTokenSigner::new("user", "alice", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let err = validator.validate(&token).expect_err("version mismatch");
    assert!(err
        .to_string()
        .contains("domain 'user' requires user version"));
}

#[test]
fn ntoken_validate_user_version_and_domain_ok() {
    let mut signer =
        NTokenSigner::new("user", "alice", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_version("U1");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let claims = validator.validate(&token).expect("validate");
    assert_eq!(claims.version, "U1");
    assert_eq!(claims.domain, "user");
}

#[test]
fn ntoken_validate_user_version_case_insensitive() {
    let mut signer =
        NTokenSigner::new("user", "alice", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_version("u1");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let claims = validator.validate(&token).expect("validate");
    assert_eq!(claims.version, "u1");
    assert_eq!(claims.domain, "user");
}

#[test]
fn ntoken_validate_with_ip_hostname_options() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer
        .builder_mut()
        .set_hostname("host.example")
        .set_ip("127.0.0.1");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default()
        .with_hostname("host.example")
        .with_ip("127.0.0.1");
    let claims = validator
        .validate_with_options(&token, &options)
        .expect("validate");
    assert_eq!(claims.hostname.as_deref(), Some("host.example"));
    assert_eq!(claims.ip.as_deref(), Some("127.0.0.1"));
}

#[test]
fn ntoken_validate_with_hostname_missing() {
    let signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default().with_hostname("host.example");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("missing hostname");
    assert!(err.to_string().contains("missing hostname"));
}

#[test]
fn ntoken_validate_with_ip_mismatch() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_ip("127.0.0.1");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default().with_ip("127.0.0.2");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("ip mismatch");
    assert!(err.to_string().contains("ip mismatch"));
}

#[test]
fn ntoken_validate_with_hostname_mismatch() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_hostname("host.example");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default().with_hostname("other.example");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("hostname mismatch");
    assert!(err.to_string().contains("hostname mismatch"));
}

#[test]
fn ntoken_validate_with_ip_missing() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_hostname("host.example");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default().with_ip("127.0.0.1");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("missing ip");
    assert!(err.to_string().contains("missing ip"));
}

#[test]
fn ntoken_validate_with_hostname_normalization() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_hostname("Host.Example.");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default().with_hostname("host.example");
    let claims = validator
        .validate_with_options(&token, &options)
        .expect("validate");
    assert_eq!(claims.hostname.as_deref(), Some("Host.Example."));
}

#[test]
fn ntoken_validate_with_ip_normalization() {
    let mut signer =
        NTokenSigner::new("sports", "api", "v1", RSA_PRIVATE_KEY.as_bytes()).expect("signer");
    signer.builder_mut().set_ip("2001:0db8:0:0:0:0:0:1");
    let token = signer.sign_once().expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default().with_ip("2001:db8::1");
    let claims = validator
        .validate_with_options(&token, &options)
        .expect("validate");
    assert_eq!(claims.ip.as_deref(), Some("2001:0db8:0:0:0:0:0:1"));
}

#[test]
fn ntoken_validate_with_authorized_service_option() {
    let claims = NToken {
        version: "S1".to_string(),
        domain: "sports".to_string(),
        name: "api".to_string(),
        key_version: "v1".to_string(),
        key_service: None,
        hostname: None,
        ip: None,
        authorized_services: Some(vec!["tenant".to_string(), "analytics".to_string()]),
        authorized_service_key_id: None,
        authorized_service_name: None,
        authorized_service_signature: None,
        generation_time: 1,
        expiry_time: 2,
    };
    let options = NTokenValidationOptions::default().with_authorized_service("tenant");
    validate_authorized_service_claims(&claims, &options).expect("authorized service");
}

#[test]
fn ntoken_validate_with_authorized_service_option_not_authorized() {
    let claims = NToken {
        version: "S1".to_string(),
        domain: "sports".to_string(),
        name: "api".to_string(),
        key_version: "v1".to_string(),
        key_service: None,
        hostname: None,
        ip: None,
        authorized_services: Some(vec!["tenant".to_string(), "analytics".to_string()]),
        authorized_service_key_id: None,
        authorized_service_name: None,
        authorized_service_signature: None,
        generation_time: 1,
        expiry_time: 2,
    };
    let options = NTokenValidationOptions::default().with_authorized_service("other");
    let err =
        validate_authorized_service_claims(&claims, &options).expect_err("not authorized service");
    assert!(err.to_string().contains("not authorized for service"));
}

#[test]
fn ntoken_validate_with_authorized_service_option_no_claims() {
    let claims = NToken {
        version: "S1".to_string(),
        domain: "sports".to_string(),
        name: "api".to_string(),
        key_version: "v1".to_string(),
        key_service: None,
        hostname: None,
        ip: None,
        authorized_services: None,
        authorized_service_key_id: None,
        authorized_service_name: None,
        authorized_service_signature: None,
        generation_time: 1,
        expiry_time: 2,
    };
    let options = NTokenValidationOptions::default().with_authorized_service("tenant");
    let err = validate_authorized_service_claims(&claims, &options)
        .expect_err("missing authorized_services should fail for authorized service option");
    assert!(err.to_string().contains("not authorized for service"));
}

#[test]
fn ntoken_validate_with_partial_authorized_service_signature_fields() {
    let claims = NToken {
        version: "S1".to_string(),
        domain: "sports".to_string(),
        name: "api".to_string(),
        key_version: "v1".to_string(),
        key_service: None,
        hostname: None,
        ip: None,
        authorized_services: Some(vec!["tenant".to_string(), "analytics".to_string()]),
        authorized_service_key_id: Some("1".to_string()),
        authorized_service_name: Some("sys.auth.zts".to_string()),
        authorized_service_signature: None,
        generation_time: 1,
        expiry_time: 2,
    };
    let options = NTokenValidationOptions::default();
    let err = validate_authorized_service_claims(&claims, &options)
        .expect_err("partial re-signature fields");
    assert!(err
        .to_string()
        .contains("incomplete authorized-service re-signature fields"));
}

#[test]
fn ntoken_validate_with_signature_without_authorized_services_list() {
    let claims = NToken {
        version: "S1".to_string(),
        domain: "sports".to_string(),
        name: "api".to_string(),
        key_version: "v1".to_string(),
        key_service: None,
        hostname: None,
        ip: None,
        authorized_services: None,
        authorized_service_key_id: Some("1".to_string()),
        authorized_service_name: Some("sys.auth.zts".to_string()),
        authorized_service_signature: Some("signature".to_string()),
        generation_time: 1,
        expiry_time: 2,
    };
    let options = NTokenValidationOptions::default();
    let err = validate_authorized_service_claims(&claims, &options)
        .expect_err("re-signed authorized services without service list");
    assert!(err
        .to_string()
        .contains("re-signed authorized services without service list"));
}

#[test]
fn ntoken_validate_rejects_expiry_too_far_in_future() {
    let options = NTokenValidationOptions::default();
    let builder = NTokenBuilder::new("sports", "api", "v1");
    let key = load_private_key(RSA_PRIVATE_KEY.as_bytes()).expect("private key");
    let now = unix_time_now();
    let max = i64::try_from(options.max_expiry().as_secs()).unwrap();
    let offset = i64::try_from(options.allowed_offset().as_secs()).unwrap();
    let generation_time = now;
    let expiry_time = now + max + offset + 60;
    let token = sign_with_key_at(&builder, &key, generation_time, expiry_time).expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("expiry too far");
    assert!(err.to_string().contains("expires too far"));
}

#[test]
fn ntoken_validate_allows_generation_time_at_allowed_offset() {
    let options = NTokenValidationOptions::default();
    let builder = NTokenBuilder::new("sports", "api", "v1");
    let key = load_private_key(RSA_PRIVATE_KEY.as_bytes()).expect("private key");
    let now = unix_time_now();
    let offset = i64::try_from(options.allowed_offset().as_secs()).unwrap();
    let generation_time = now + offset;
    let expiry_time = generation_time + 60;
    let token = sign_with_key_at(&builder, &key, generation_time, expiry_time).expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    validator
        .validate_with_options(&token, &options)
        .expect("generation time within offset");
}

#[test]
fn ntoken_validate_allows_expiry_at_max_bound() {
    let options = NTokenValidationOptions::default();
    let builder = NTokenBuilder::new("sports", "api", "v1");
    let key = load_private_key(RSA_PRIVATE_KEY.as_bytes()).expect("private key");
    let now = unix_time_now();
    let max = i64::try_from(options.max_expiry().as_secs()).unwrap();
    let offset = i64::try_from(options.allowed_offset().as_secs()).unwrap();
    let generation_time = now;
    let expiry_time = now + max + offset;
    let token = sign_with_key_at(&builder, &key, generation_time, expiry_time).expect("token");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    validator
        .validate_with_options(&token, &options)
        .expect("expiry at max bound");
}
