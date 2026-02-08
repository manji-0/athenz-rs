use super::helpers::{canonical_json, ensure_not_expired, verify_jws_signature};
use super::PolicyValidatorConfig;
use crate::models::SignedPolicyData;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use signature::SignatureEncoding;
use signature::Signer;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[test]
fn canonical_signed_policy_data_matches_go() {
    let input = r#"{"policyData":{"domain":"test","policies":[{"name":"policy1","modified":"2017-06-02T06:11:12.125Z","assertions":[{"role":"sys.auth:role.admin","resource":"*","action":"*","effect":"ALLOW"},{"role":"sys.auth:role.non-admin","resource":"*","action":"*","effect":"DENY"}]}]},"zmsSignature":"zms_signature","zmsKeyId":"0","modified":"2017-06-02T06:11:12.125Z","expires":"2017-06-09T06:11:12.125Z"}"#;
    let signed: SignedPolicyData = serde_json::from_str(input).unwrap();
    let canon = canonical_json(&serde_json::to_value(&signed).unwrap());
    assert_eq!(canon, "{\"expires\":\"2017-06-09T06:11:12.125Z\",\"modified\":\"2017-06-02T06:11:12.125Z\",\"policyData\":{\"domain\":\"test\",\"policies\":[{\"assertions\":[{\"action\":\"*\",\"effect\":\"ALLOW\",\"resource\":\"*\",\"role\":\"sys.auth:role.admin\"},{\"action\":\"*\",\"effect\":\"DENY\",\"resource\":\"*\",\"role\":\"sys.auth:role.non-admin\"}],\"modified\":\"2017-06-02T06:11:12.125Z\",\"name\":\"policy1\"}]},\"zmsKeyId\":\"0\",\"zmsSignature\":\"zms_signature\"}");
}

#[test]
fn canonical_json_escapes_strings() {
    let value = serde_json::json!({
        "key": "value\"quoted\"",
        "path": "a\\b",
    });
    let canon = canonical_json(&value);
    assert_eq!(
        canon,
        "{\"key\":\"value\\\"quoted\\\"\",\"path\":\"a\\\\b\"}"
    );
}

#[test]
fn verify_jws_signature_rs256() {
    let header = serde_json::json!({
        "alg": "RS256",
        "kid": "v1",
    });
    let payload = serde_json::json!({
        "domain": "sports",
        "policies": [],
    });
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
    let signing_input = format!("{protected}.{payload_b64}");

    let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    verify_jws_signature(
        "RS256",
        &protected,
        &payload_b64,
        &signature_b64,
        RSA_PUBLIC_KEY.as_bytes(),
    )
    .expect("verify");
}

#[test]
fn ensure_not_expired_respects_offset() {
    let mut config = PolicyValidatorConfig::default();
    let future = OffsetDateTime::now_utc() + time::Duration::seconds(60);
    let future_str = future.format(&Rfc3339).expect("format");
    ensure_not_expired(&future_str, &config).expect("future ok");

    let past = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let past_str = past.format(&Rfc3339).expect("format");
    assert!(ensure_not_expired(&past_str, &config).is_err());

    config.expiry_offset = Duration::from_secs(60);
    let near_future = OffsetDateTime::now_utc() + time::Duration::seconds(30);
    let near_future_str = near_future.format(&Rfc3339).expect("format");
    assert!(ensure_not_expired(&near_future_str, &config).is_err());
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
