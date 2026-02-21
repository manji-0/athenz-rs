use crate::error::Error;
use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn get_role_access_uses_expected_path() {
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
        .get_role_access("sports", "reader", "user.jane")
        .expect("access");
    assert!(access.granted);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/access/domain/sports/role/reader/principal/user.jane"
    );

    handle.join().expect("server");
}

#[test]
fn get_role_access_applies_auth_header() {
    let body = r#"{"granted":false}"#;
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
        .get_role_access("sports", "reader", "user.jane")
        .expect("access");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn get_domain_role_access_uses_expected_path() {
    let body = r#"{"roles":["reader","writer"]}"#;
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
        .get_domain_role_access("sports", "user.jane")
        .expect("role access");
    assert_eq!(access.roles, vec!["reader", "writer"]);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/access/domain/sports/principal/user.jane");

    handle.join().expect("server");
}

#[test]
fn get_domain_role_access_applies_auth_header() {
    let body = r#"{"roles":[]}"#;
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
        .get_domain_role_access("sports", "user.jane")
        .expect("role access");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn get_domain_role_access_propagates_api_error() {
    let body = r#"{"code":403,"message":"forbidden"}"#;
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let err = client
        .get_domain_role_access("sports", "user.jane")
        .expect_err("expected api error");
    match err {
        Error::Api(api_err) => {
            assert_eq!(api_err.code, 403);
            assert_eq!(api_err.message, "forbidden");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/access/domain/sports/principal/user.jane");

    handle.join().expect("server");
}
