use crate::models::InstanceRefreshRequest;
use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn refresh_instance_credentials_uses_expected_path() {
    let body = r#"{"name":"sports.api","certificate":"x509-cert","caCertBundle":"ca-bundle","serviceToken":"token"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let request = InstanceRefreshRequest {
        csr: Some("csr".to_string()),
        expiry_time: Some(600),
        key_id: Some("v1".to_string()),
    };
    let identity = client
        .refresh_instance_credentials("sports", "api", &request)
        .expect("identity");

    assert_eq!(identity.name.as_deref(), Some("sports.api"));
    assert_eq!(identity.certificate.as_deref(), Some("x509-cert"));
    assert_eq!(identity.ca_cert_bundle.as_deref(), Some("ca-bundle"));
    assert_eq!(identity.service_token.as_deref(), Some("token"));

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/zts/v1/instance/sports/api/refresh");

    handle.join().expect("server");
}

#[test]
fn refresh_instance_credentials_applies_auth_header() {
    let body = r#"{"name":"sports.api"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    let request = InstanceRefreshRequest {
        csr: None,
        expiry_time: None,
        key_id: None,
    };
    client
        .refresh_instance_credentials("sports", "api", &request)
        .expect("identity");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}
