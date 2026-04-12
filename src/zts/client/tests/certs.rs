use crate::models::UserCertificateRequest;
use crate::zts::ZtsClient;

use super::helpers::{serve_once, CapturedRequest};

#[test]
fn post_user_certificate_uses_expected_path() {
    let body = r#"{"x509Certificate":"cert"}"#;
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

    let request = UserCertificateRequest {
        name: "user.jane".to_string(),
        csr: "csr".to_string(),
        attestation_data: "attestation".to_string(),
        expiry_time: Some(60),
        x509_cert_signer_key_id: Some("v1".to_string()),
    };
    let certificate = client
        .post_user_certificate(&request)
        .expect("user certificate");
    assert_eq!(certificate.x509_certificate, "cert");

    let req: CapturedRequest = rx.recv().expect("request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/zts/v1/usercert");
    assert_eq!(
        req.headers.get("athenz-principal-auth").map(String::as_str),
        Some("token")
    );

    handle.join().expect("server");
}
