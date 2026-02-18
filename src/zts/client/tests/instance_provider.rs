use crate::error::{Error, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL};
use crate::models::InstanceConfirmation;
use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn post_instance_confirmation_uses_expected_path() {
    let body = r#"{"provider":"sports.provider","domain":"sports","service":"api","attestationData":"doc"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/instanceprovider/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let confirmation = InstanceConfirmation {
        provider: "sports.provider".to_string(),
        domain: "sports".to_string(),
        service: "api".to_string(),
        attestation_data: "doc".to_string(),
        attributes: None,
    };
    let result = client
        .post_instance_confirmation(&confirmation)
        .expect("instance confirmation");

    assert_eq!(result.provider, "sports.provider");
    assert_eq!(result.domain, "sports");
    assert_eq!(result.service, "api");
    assert_eq!(result.attestation_data, "doc");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/instanceprovider/v1/instance");

    handle.join().expect("server");
}

#[test]
fn post_refresh_confirmation_applies_auth_header() {
    let body = r#"{"provider":"sports.provider","domain":"sports","service":"api","attestationData":"doc"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(Box::leak(response.into_boxed_str()));
    let client = ZtsClient::builder(format!("{}/instanceprovider/v1", base_url))
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");

    let confirmation = InstanceConfirmation {
        provider: "sports.provider".to_string(),
        domain: "sports".to_string(),
        service: "api".to_string(),
        attestation_data: "doc".to_string(),
        attributes: None,
    };
    client
        .post_refresh_confirmation(&confirmation)
        .expect("refresh confirmation");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/instanceprovider/v1/refresh");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}

#[test]
fn confirmation_endpoints_require_instance_provider_base_path() {
    let client = ZtsClient::builder("https://zts.example.com/zts/v1")
        .expect("builder")
        .build()
        .expect("build");
    let confirmation = InstanceConfirmation {
        provider: "sports.provider".to_string(),
        domain: "sports".to_string(),
        service: "api".to_string(),
        attestation_data: "doc".to_string(),
        attributes: None,
    };

    let err = client
        .post_instance_confirmation(&confirmation)
        .expect_err("expected base path validation error");
    match err {
        Error::Crypto(message) => assert_eq!(message, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL),
        other => panic!("unexpected error: {other:?}"),
    }

    let err = client
        .post_refresh_confirmation(&confirmation)
        .expect_err("expected base path validation error");
    match err {
        Error::Crypto(message) => assert_eq!(message, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL),
        other => panic!("unexpected error: {other:?}"),
    }
}
