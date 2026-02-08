#![cfg(feature = "async-client")]

use athenz_rs::{
    AccessTokenRequest, Error, IdTokenRequest, InstanceRegisterInformation, ZtsAsyncClient,
};
use tokio::time::{timeout, Duration};

mod common;
use common::{empty_response, response_with_body, serve_once};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

#[tokio::test]
async fn get_status_uses_status_path() {
    let body = r#"{"code":200,"message":"ok"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let status = client.get_status().await.expect("status");
    assert_eq!(status.code, 200);

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/status");
}

#[tokio::test]
async fn get_status_handles_trailing_slash_base_url() {
    let body = r#"{"code":200,"message":"ok"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1/", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let status = client.get_status().await.expect("status");
    assert_eq!(status.code, 200);

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/status");
}

#[tokio::test]
async fn get_domain_signed_policy_data_returns_etag_on_ok() {
    let body = r#"{"signedPolicyData":{"policyData":{"domain":"sports","policies":[{"name":"p","assertions":[]}]},"modified":"2020-01-01T00:00:00Z","expires":"2099-01-01T00:00:00Z"},"signature":"sig","keyId":"0"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: v1\r\nContent-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let response = client
        .get_domain_signed_policy_data("sports", None)
        .await
        .expect("fetch");
    assert_eq!(response.etag.as_deref(), Some("v1"));
    assert!(response.data.is_some());

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/domain/sports/signed_policy_data");
    assert!(req.header_value("If-None-Match").is_none());
}

#[tokio::test]
async fn get_domain_signed_policy_data_returns_none_on_not_modified() {
    let response = "HTTP/1.1 304 Not Modified\r\nETag: v2\r\n\r\n".to_string();
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let response = client
        .get_domain_signed_policy_data("sports", Some("v2"))
        .await
        .expect("fetch");
    assert_eq!(response.etag.as_deref(), Some("v2"));
    assert!(response.data.is_none());

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.header_value("If-None-Match"), Some("v2"));
}

#[tokio::test]
async fn issue_access_token_sends_form_body() {
    let body = r#"{"access_token":"token","token_type":"Bearer","expires_in":3600}"#;
    let response = response_with_body("200 OK", &[("Content-Type", "application/json")], body);
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .build()
        .expect("build");

    let request = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
    let response = client.issue_access_token(&request).await.expect("token");
    assert_eq!(response.access_token, "token");

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/zts/v1/oauth2/token");
    assert_eq!(
        req.header_value("Content-Type"),
        Some("application/x-www-form-urlencoded")
    );
    let body_str = String::from_utf8_lossy(&req.body);
    assert!(body_str.contains("grant_type=client_credentials"));
}

#[tokio::test]
async fn register_instance_returns_location_on_created() {
    let body = r#"{"provider":"prov","name":"sports.api","instanceId":"i-123"}"#;
    let response = format!(
        "HTTP/1.1 201 Created\r\nLocation: https://example.com/instance/i-123\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .build()
        .expect("build");

    let info = InstanceRegisterInformation {
        provider: "prov".to_string(),
        domain: "sports".to_string(),
        service: "api".to_string(),
        attestation_data: None,
        csr: None,
        ssh: None,
        ssh_cert_request: None,
        token: None,
        expiry_time: None,
        hostname: None,
        host_cnames: None,
        athenz_jwk: None,
        athenz_jwk_modified: None,
        namespace: None,
        cloud: None,
        x509_cert_signer_key_id: None,
        ssh_cert_signer_key_id: None,
        jwt_svid_instance_id: None,
        jwt_svid_audience: None,
        jwt_svid_nonce: None,
        jwt_svid_spiffe: None,
        jwt_svid_spiffe_subject: None,
        jwt_svid_key_type: None,
    };
    let response = client.register_instance(&info).await.expect("register");
    assert_eq!(
        response.location.as_deref(),
        Some("https://example.com/instance/i-123")
    );
    assert_eq!(response.identity.instance_id, "i-123");

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/zts/v1/instance");
    assert_eq!(req.header_value("Athenz-Principal-Auth"), Some("token"));
}

#[tokio::test]
async fn get_roles_require_role_cert_sends_principal() {
    let body = r#"{"roles":["sports:role.reader"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.as_bytes().len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .build()
        .expect("build");

    let access = client
        .get_roles_require_role_cert(Some("user.sports"))
        .await
        .expect("roles");
    assert_eq!(access.roles, vec!["sports:role.reader".to_string()]);

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.path, "/zts/v1/role/cert");
    assert_eq!(req.query_value("principal"), Some("user.sports"));
    assert_eq!(req.header_value("Athenz-Principal-Auth"), Some("token"));
}

#[tokio::test]
async fn delete_instance_accepts_no_content() {
    let response = empty_response("204 No Content");
    let (base_url, rx) = serve_once(response).await;

    let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth")
        .build()
        .expect("build");

    client
        .delete_instance("prov", "sports", "api", "i-123")
        .await
        .expect("delete");

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "DELETE");
    assert_eq!(req.path, "/zts/v1/instance/prov/sports/api/i-123");
    assert_eq!(req.header_value("Athenz-Principal-Auth"), Some("token"));
}

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

    let req = timeout(REQUEST_TIMEOUT, rx)
        .await
        .expect("request timeout")
        .expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/oauth2/auth");
    assert_eq!(req.query_value("response_type"), Some("id_token"));
}

#[tokio::test]
async fn issue_id_token_rejects_when_redirects_enabled() {
    let client = ZtsAsyncClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .follow_redirects(true)
        .build()
        .expect("build");

    let request = IdTokenRequest::new(
        "client-id",
        "https://example.com/redirect",
        "openid",
        "nonce",
    );
    let err = client
        .issue_id_token(&request)
        .await
        .expect_err("should reject");
    match err {
        Error::Crypto(message) => {
            assert!(message.contains("issue_id_token requires follow_redirects(false)"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn ntoken_auth_rejects_invalid_header_name() {
    let err = match ZtsAsyncClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .ntoken_auth("bad header", "token")
    {
        Ok(_) => panic!("expected invalid header error"),
        Err(err) => err,
    };
    match err {
        Error::Crypto(message) => {
            assert!(message.contains("invalid header name"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn ntoken_auth_rejects_invalid_header_value() {
    let err = match ZtsAsyncClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "bad\nvalue")
    {
        Ok(_) => panic!("expected invalid header error"),
        Err(err) => err,
    };
    match err {
        Error::Crypto(message) => {
            assert!(message.contains("invalid header value"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn builder_rejects_redirects_with_auth() {
    let builder = ZtsAsyncClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .expect("auth");
    let err = builder
        .follow_redirects(true)
        .build()
        .expect_err("should reject redirects with auth");
    match err {
        Error::Crypto(message) => assert!(message.contains("follow_redirects(true)")),
        other => panic!("unexpected error: {other:?}"),
    }
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
