#![cfg(feature = "async-client")]

use athenz_rs::{IdTokenRequest, ZtsAsyncClient};
use tokio::time::{timeout, Duration};

mod common;
use common::serve_once;

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
