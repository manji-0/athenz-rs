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
async fn get_info_calls_sys_info_endpoint() {
    let body = r#"{"buildJdkSpec":"17","implementationTitle":"zms"}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let info = client.get_info().await.expect("info");
    assert_eq!(info.build_jdk_spec.as_deref(), Some("17"));
    assert_eq!(info.implementation_title.as_deref(), Some("zms"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/info");
}

#[tokio::test]
async fn get_status_calls_status_endpoint() {
    let body = r#"{"code":200,"message":"ok"}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let status = client.get_status().await.expect("status");
    assert_eq!(status.code, 200);
    assert_eq!(status.message, "ok");

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/status");
}

#[tokio::test]
async fn get_schema_calls_schema_endpoint() {
    let body = r#"{"name":"zms","types":[]}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let schema = client.get_schema().await.expect("schema");
    assert_eq!(schema.0.get("name").and_then(|v| v.as_str()), Some("zms"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/schema");
}

#[tokio::test]
async fn get_user_authority_attributes_calls_endpoint() {
    let body = r#"{"attributes":{"employeeType":{"values":["full_time"]}}}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let attributes = client
        .get_user_authority_attributes()
        .await
        .expect("authority attributes");
    let employee_type = attributes
        .attributes
        .get("employeeType")
        .expect("employeeType attribute");
    assert_eq!(employee_type.values, vec!["full_time".to_string()]);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/authority/user/attribute");
}

#[tokio::test]
async fn get_domain_stats_calls_domain_stats_endpoint() {
    let body = r#"{"name":"sports","subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let stats = client
        .get_domain_stats("sports")
        .await
        .expect("domain stats");
    assert_eq!(stats.name.as_deref(), Some("sports"));
    assert_eq!(stats.subdomain, 1);
    assert_eq!(stats.group_member, 11);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain/sports/stats");
}

#[tokio::test]
async fn get_system_stats_calls_system_stats_endpoint() {
    let body = r#"{"subdomain":1,"role":2,"roleMember":3,"policy":4,"assertion":5,"entity":6,"service":7,"serviceHost":8,"publicKey":9,"group":10,"groupMember":11}"#;
    let response = json_response("200 OK", body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let stats = client.get_system_stats().await.expect("system stats");
    assert_eq!(stats.name, None);
    assert_eq!(stats.policy, 4);
    assert_eq!(stats.public_key, 9);

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/stats");
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
        .follow_redirects(false)
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
        .follow_redirects(false)
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
