#![cfg(feature = "async-validate")]

use athenz_rs::{
    JWSPolicyData, JwksProviderAsync, JwtValidationOptions, JwtValidatorAsync, NTokenSigner,
    NTokenValidatorAsync, NTokenValidatorConfig, PolicyClientAsync, PolicyData, SignedPolicyData,
    ZtsAsyncClient,
};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rand::thread_rng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::RsaPrivateKey;
use serde_json::json;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
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

    let mut options = JwtValidationOptions::athenz_default();
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
