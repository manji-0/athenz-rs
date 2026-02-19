use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn get_resource_access_uses_expected_path_and_query() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access("read", "sports.resource", Some("sports"), Some("user.jane"))
        .expect("resource access");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/read/sports.resource?domain=sports&principal=user.jane"
    );

    handle.join().expect("server");
}

#[test]
fn get_resource_access_with_principal_only_sets_principal_query_param() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access("read", "sports.resource", None, Some("user.jane"))
        .expect("resource access");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/read/sports.resource?principal=user.jane"
    );

    handle.join().expect("server");
}

#[test]
fn get_resource_access_with_domain_only_sets_domain_query_param() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access("read", "sports.resource", Some("sports"), None)
        .expect("resource access");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/read/sports.resource?domain=sports"
    );

    handle.join().expect("server");
}

#[test]
fn get_resource_access_without_optional_filters_omits_query_params() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access("read", "sports.resource", None, None)
        .expect("resource access");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/access/read/sports.resource");

    handle.join().expect("server");
}

#[test]
fn get_resource_access_ext_uses_expected_path_and_query() {
    let body = r#"{"granted":false}"#;
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

    let access = client
        .get_resource_access_ext("read", "sports.resource", Some("sports"), Some("user.jane"))
        .expect("resource access ext");
    assert!(!access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/read?resource=sports.resource&domain=sports&principal=user.jane"
    );

    handle.join().expect("server");
}

#[test]
fn get_resource_access_ext_with_principal_only_sets_principal_query_param() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access_ext("read", "sports.resource", None, Some("user.jane"))
        .expect("resource access ext");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/read?resource=sports.resource&principal=user.jane"
    );

    handle.join().expect("server");
}

#[test]
fn get_resource_access_ext_with_domain_only_sets_domain_query_param() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access_ext("read", "sports.resource", Some("sports"), None)
        .expect("resource access ext");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/read?resource=sports.resource&domain=sports"
    );

    handle.join().expect("server");
}

#[test]
fn get_resource_access_ext_without_optional_filters_omits_query_params() {
    let body = r#"{"granted":true}"#;
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

    let access = client
        .get_resource_access_ext("read", "sports.resource", None, None)
        .expect("resource access ext");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/access/read?resource=sports.resource");

    handle.join().expect("server");
}

#[test]
fn get_resource_access_applies_auth_header() {
    let body = r#"{"granted":true}"#;
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

    client
        .get_resource_access("read", "sports.resource", None, None)
        .expect("resource access");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );
    assert_eq!(req.path, "/zts/v1/access/read/sports.resource");

    handle.join().expect("server");
}
