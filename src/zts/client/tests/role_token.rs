use crate::models::RoleCertificateRequest;
use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn get_role_token_uses_expected_path_and_query() {
    let body = r#"{"token":"v=Z1;d=sports;r=reader,writer","expiryTime":12345}"#;
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

    let token = client
        .get_role_token(
            "sports",
            Some("reader,writer"),
            Some(60),
            Some(120),
            Some("user.jane"),
        )
        .expect("role token");
    assert_eq!(token.token, "v=Z1;d=sports;r=reader,writer");
    assert_eq!(token.expiry_time, 12345);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/domain/sports/token?role=reader%2Cwriter&minExpiryTime=60&maxExpiryTime=120&proxyForPrincipal=user.jane"
    );

    handle.join().expect("server");
}

#[test]
fn get_role_token_applies_auth_header() {
    let body = r#"{"token":"v=Z1;d=sports;r=reader","expiryTime":900}"#;
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
        .get_role_token("sports", None, None, None, None)
        .expect("role token");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn post_role_token_uses_expected_path() {
    let body = r#"{"token":"v=Z1;d=sports;r=reader","expiryTime":1800}"#;
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

    let request = RoleCertificateRequest {
        csr: "csr".to_string(),
        proxy_for_principal: None,
        expiry_time: 1800,
        prev_cert_not_before: None,
        prev_cert_not_after: None,
        x509_cert_signer_key_id: None,
    };
    let token = client
        .post_role_token("sports", "reader", &request)
        .expect("role token");
    assert_eq!(token.token, "v=Z1;d=sports;r=reader");
    assert_eq!(token.expiry_time, 1800);

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/zts/v1/domain/sports/role/reader/token");

    handle.join().expect("server");
}

#[test]
fn get_aws_temporary_credentials_uses_expected_path_and_query() {
    let body = r#"{"accessKeyId":"AKIA_TEST","secretAccessKey":"secret","sessionToken":"session","expiration":"2026-02-19T00:00:00Z"}"#;
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

    let creds = client
        .get_aws_temporary_credentials("sports", "reader", Some(3600), Some("ext-tenant"))
        .expect("aws temporary credentials");
    assert_eq!(creds.access_key_id, "AKIA_TEST");
    assert_eq!(creds.secret_access_key, "secret");
    assert_eq!(creds.session_token, "session");
    assert_eq!(creds.expiration.as_deref(), Some("2026-02-19T00:00:00Z"));

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.path,
        "/zts/v1/domain/sports/role/reader/creds?durationSeconds=3600&externalId=ext-tenant"
    );

    handle.join().expect("server");
}

#[test]
fn get_aws_temporary_credentials_applies_auth_header() {
    let body = r#"{"accessKeyId":"AKIA_TEST","secretAccessKey":"secret","sessionToken":"session"}"#;
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
        .get_aws_temporary_credentials("sports", "reader", None, None)
        .expect("aws temporary credentials");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );
    assert_eq!(req.path, "/zts/v1/domain/sports/role/reader/creds");

    handle.join().expect("server");
}
