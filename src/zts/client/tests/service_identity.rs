use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn get_service_identity_uses_expected_path() {
    let body = r#"{"name":"sports.api","providerEndpoint":"https://provider.example"}"#;
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

    let identity = client
        .get_service_identity("sports", "api")
        .expect("service identity");
    assert_eq!(identity.name, "sports.api");
    assert_eq!(
        identity.provider_endpoint.as_deref(),
        Some("https://provider.example")
    );

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/domain/sports/service/api");

    handle.join().expect("server");
}

#[test]
fn get_service_identity_list_applies_auth_header() {
    let body = r#"{"names":["sports.api","sports.ui"]}"#;
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

    let list = client
        .get_service_identity_list("sports")
        .expect("service identity list");
    assert_eq!(list.names, vec!["sports.api", "sports.ui"]);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/domain/sports/service");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}
