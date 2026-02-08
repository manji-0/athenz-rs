#![cfg(feature = "async-client")]

use athenz_rs::{Error, IdTokenRequest, ZtsAsyncClient};
use tokio::time::{timeout, Duration};

mod common;
use common::serve_once;

const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

#[tokio::test]
async fn issue_id_token_returns_location_on_redirect() {
    let response = "HTTP/1.1 302 Found\r\nLocation: https://example.com/cb\r\n\r\n".to_string();
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let request = IdTokenRequest::new(
        "client-id",
        "https://example.com/redirect",
        "openid",
        "nonce",
    );
    let response = client.issue_id_token(&request).await.expect("id token");
    assert!(response.response.is_none());
    assert_eq!(response.location.as_deref(), Some("https://example.com/cb"));

    let req = timeout(Duration::from_secs(1), rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/oauth2/auth");
}

#[tokio::test]
async fn get_status_truncates_large_error_body() {
    let body = "x".repeat(MAX_ERROR_BODY_BYTES + 10);
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    let (base_url, _rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let err = client.get_status().await.expect_err("should error");
    match err {
        Error::Api(err) => {
            assert_eq!(err.code, 500);
            assert_eq!(err.message.len(), MAX_ERROR_BODY_BYTES);
            assert!(err.message.chars().all(|ch| ch == 'x'));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn get_status_uses_fallback_message_on_empty_error_body() {
    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, _rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let err = client.get_status().await.expect_err("should error");
    match err {
        Error::Api(err) => {
            assert!(err.message.contains("http status 500"));
            assert!(!err.message.trim().is_empty());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
