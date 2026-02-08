#![cfg(feature = "async-client")]

use athenz_rs::{DomainListOptions, NTokenSigner, ZmsAsyncClient};
use rand::thread_rng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use std::sync::OnceLock;
use tokio::time::{timeout, Duration};

mod common;
use common::{empty_response, json_response, serve_once};

#[tokio::test]
async fn get_domain_list_sets_query_and_modified_since() {
    let body = r#"{"names":["a","b"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let mut options = DomainListOptions::default();
    options.limit = Some(5);
    options.prefix = Some("core".to_string());
    options.modified_since = Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string());

    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string(), "b".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain");
    assert_eq!(
        req.header_value("If-Modified-Since"),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(req.query_value("limit"), Some("5"));
    assert_eq!(req.query_value("prefix"), Some("core"));
}

#[tokio::test]
async fn get_domain_list_returns_none_on_not_modified() {
    let response = empty_response("304 Not Modified");
    let (base_url, _rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client.get_domain_list(&options).await.expect("request");
    assert!(list.is_none());
}

#[tokio::test]
async fn get_domain_list_applies_auth_header() {
    let body = r#"{"names":["a"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.header_value("Athenz-Principal-Auth"), Some("token"));
}

#[tokio::test]
async fn get_domain_list_applies_ntoken_signer_auth() {
    let body = r#"{"names":["a"]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let signer = test_signer();
    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .ntoken_signer("Athenz-Principal-Auth", signer)
        .expect("auth")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    let header = req
        .header_value("Athenz-Principal-Auth")
        .expect("auth header");
    assert!(header.starts_with("v="));
}

#[tokio::test]
async fn get_domain_list_reports_status_on_empty_error_body() {
    let response = empty_response("500 Internal Server Error");
    let (base_url, _rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let err = client.get_domain_list(&options).await.expect_err("error");
    let message = format!("{}", err);
    assert!(message.contains("500"));
}

fn test_signer() -> NTokenSigner {
    static TEST_RSA_PRIVATE_KEY: OnceLock<String> = OnceLock::new();
    let pem = TEST_RSA_PRIVATE_KEY.get_or_init(|| {
        let mut rng = thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
        key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pem")
            .to_string()
    });
    NTokenSigner::new("sports", "api", "v1", pem.as_bytes()).expect("signer")
}
