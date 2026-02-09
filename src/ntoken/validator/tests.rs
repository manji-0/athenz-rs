use super::NTokenValidator;
use crate::ntoken::keys::load_private_key;
use crate::ntoken::token::{sign_with_key_at, unix_time_now};
use crate::ntoken::{NTokenBuilder, NTokenSigner, NTokenValidationOptions};
use std::time::Duration;

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
fn ntoken_validate_rejects_future_generation_time() {
    let builder = NTokenBuilder::new("sports", "api", "v1");
    let key = load_private_key(RSA_PRIVATE_KEY.as_bytes()).expect("private key");
    let validator =
        NTokenValidator::new_with_public_key(RSA_PUBLIC_KEY.as_bytes()).expect("validator");
    let options = NTokenValidationOptions::default();
    let now = unix_time_now();
    let offset = i64::try_from(options.allowed_offset().as_secs()).unwrap();
    let generation_time = now + offset + 60;
    let expiry_time = generation_time + 60;
    let token = sign_with_key_at(&builder, &key, generation_time, expiry_time).expect("token");
    let err = validator
        .validate_with_options(&token, &options)
        .expect_err("future generation time");
    assert!(err.to_string().contains("future timestamp"));
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
