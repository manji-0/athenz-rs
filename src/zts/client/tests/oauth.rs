use crate::error::Error;
use crate::zts::{AccessTokenRequest, ZtsClient};

use super::helpers::serve_once;

#[test]
fn issue_access_token_rejects_response_without_any_token() {
    let body = r#"{"token_type":"Bearer"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, _rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    let request = AccessTokenRequest::builder("sports")
        .roles(["reader"])
        .build();
    let err = client
        .issue_access_token(&request)
        .expect_err("empty token response should fail");
    match err {
        Error::Api(err) => {
            assert_eq!(err.code, 200);
            assert!(err.message.contains("did not include access_token"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    handle.join().expect("server");
}

#[test]
fn issue_access_token_rejects_id_token_only_response_without_id_token_request() {
    let body = r#"{"token_type":"Bearer","id_token":"id-token","issued_token_type":"urn:ietf:params:oauth:token-type:id_token"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, _rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    let request = AccessTokenRequest::builder("sports")
        .roles(["reader"])
        .build();
    let err = client
        .issue_access_token(&request)
        .expect_err("id_token-only response should fail for access token requests");
    match err {
        Error::Api(err) => {
            assert_eq!(err.code, 200);
            assert!(err.message.contains("did not include access_token"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    handle.join().expect("server");
}

#[test]
fn issue_access_token_allows_id_token_only_response_when_requested() {
    let body = r#"{"token_type":"Bearer","id_token":"id-token","issued_token_type":"urn:ietf:params:oauth:token-type:id_token"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, _rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    let request = AccessTokenRequest::builder("sports")
        .roles(["reader"])
        .subject_token("subject-token")
        .subject_token_type("urn:ietf:params:oauth:token-type:access_token")
        .requested_token_type("urn:ietf:params:oauth:token-type:id_token")
        .build();
    let response = client
        .issue_access_token(&request)
        .expect("id token response");
    assert_eq!(response.access_token, None);
    assert_eq!(response.id_token.as_deref(), Some("id-token"));

    handle.join().expect("server");
}
