use crate::error::{Error, CONFIG_ERROR_REDIRECT_WITH_AUTH};
use crate::zts::{IdTokenRequest, ZtsClient};

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn build_url_trims_trailing_slash() {
    let client = ZtsClient::builder("https://example.com/zts/v1/")
        .expect("builder")
        .build()
        .expect("build");
    let url = client.build_url(&["domain"]).expect("url");
    assert_eq!(url.path(), "/zts/v1/domain");
}

#[test]
fn id_token_query_defaults_output_to_json() {
    let req = IdTokenRequest::new(
        "sports.api",
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );
    let query = req.to_query();
    assert!(query.contains("output=json"));
}

#[test]
fn id_token_query_includes_optional_fields() {
    let mut req = IdTokenRequest::new(
        "sports.api",
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );
    req.state = Some("state-1".to_string());
    req.key_type = Some("EC".to_string());
    req.full_arn = Some(true);
    req.expiry_time = Some(3600);
    req.output = Some("json".to_string());
    req.role_in_aud_claim = Some(true);
    req.all_scope_present = Some(true);

    let query = req.to_query();
    assert!(query.contains("response_type=id_token"));
    assert!(query.contains("client_id=sports.api"));
    assert!(query.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
    assert!(query.contains("scope=openid"));
    assert!(query.contains("nonce=nonce-123"));
    assert!(query.contains("state=state-1"));
    assert!(query.contains("keyType=EC"));
    assert!(query.contains("fullArn=true"));
    assert!(query.contains("expiryTime=3600"));
    assert!(query.contains("output=json"));
    assert!(query.contains("roleInAudClaim=true"));
    assert!(query.contains("allScopePresent=true"));
}

#[test]
fn issue_id_token_accepts_redirects() {
    let response = concat!(
        "HTTP/1.1 303 See Other\r\n",
        "Location: https://example.com/callback?token=abc\r\n",
        "Content-Length: 0\r\n",
        "\r\n"
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .build()
        .expect("build");
    let req = IdTokenRequest::new(
        "sports.api",
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );

    let result = client.issue_id_token(&req).expect("request");
    assert!(result.response.is_none());
    assert_eq!(
        result.location.as_deref(),
        Some("https://example.com/callback?token=abc")
    );

    let captured = rx.recv().expect("request");
    assert_eq!(captured.method, "GET");
    assert!(
        captured.path.starts_with("/zts/v1/oauth2/auth?"),
        "unexpected path: {}",
        captured.path
    );

    handle.join().expect("server");
}

#[test]
fn auth_requires_redirects_disabled() {
    let err = match ZtsClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .disable_redirect(false)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
    {
        Ok(_) => panic!("expected error"),
        Err(err) => err,
    };
    match err {
        Error::Crypto(message) => {
            assert_eq!(message, CONFIG_ERROR_REDIRECT_WITH_AUTH);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn auth_allows_redirects_disabled() {
    ZtsClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");
}

#[test]
fn issue_id_token_ok_includes_location_header() {
    let response = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: application/json\r\n",
        "Location: https://example.com/callback?token=abc\r\n",
        "Content-Length: 89\r\n",
        "\r\n",
        "{\"version\":1,\"id_token\":\"abc\",\"token_type\":\"Bearer\",\"success\":true,\"expiration_time\":123}"
    );
    let (base_url, _rx, handle) = serve_once(response);
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .build()
        .expect("build");
    let req = IdTokenRequest::new(
        "sports.api",
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );

    let result = client.issue_id_token(&req).expect("request");
    assert!(result.response.is_some());
    assert_eq!(
        result.location.as_deref(),
        Some("https://example.com/callback?token=abc")
    );

    handle.join().expect("server");
}

#[test]
fn issue_id_token_redirect_requires_location() {
    let response = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n";
    let (base_url, _rx, handle) = serve_once(response);
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .build()
        .expect("build");
    let req = IdTokenRequest::new(
        "sports.api",
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );

    let err = client.issue_id_token(&req).expect_err("request");
    match err {
        Error::Api(resource) => {
            assert_eq!(resource.code, 302);
            assert!(resource.message.contains("missing location"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    handle.join().expect("server");
}

#[test]
fn issue_id_token_rejects_when_redirects_enabled() {
    let client = ZtsClient::builder("https://example.com/zts/v1")
        .expect("builder")
        .disable_redirect(false)
        .build()
        .expect("build");
    let req = IdTokenRequest::new(
        "sports.api",
        "https://example.com/callback",
        "openid",
        "nonce-123",
    );

    let err = client.issue_id_token(&req).expect_err("request");
    match err {
        Error::Crypto(message) => {
            assert!(message.contains("issue_id_token requires disable_redirect(true)"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn get_domain_signed_policy_data_sets_if_none_match() {
    let response = "HTTP/1.1 304 Not Modified\r\nETag: tag-1\r\nContent-Length: 0\r\n\r\n";
    let (base_url, rx, handle) = serve_once(response);
    let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let result = client
        .get_domain_signed_policy_data("sports", Some("tag-1"))
        .expect("request");
    assert!(result.data.is_none());
    assert_eq!(result.etag.as_deref(), Some("tag-1"));

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/domain/sports/signed_policy_data");
    assert_eq!(
        req.headers.get("if-none-match").map(String::as_str),
        Some("tag-1")
    );

    handle.join().expect("server");
}
