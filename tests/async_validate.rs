#![cfg(feature = "async-validate")]

use athenz_provider_tenant::{JwksProviderAsync, JwtValidationOptions, JwtValidatorAsync};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rand::thread_rng;
use serde_json::json;
use signature::Signer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[tokio::test]
async fn jwks_provider_fetches_keys() {
    let body = r#"{"keys":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let provider =
        JwksProviderAsync::new(format!("{}/zts/v1/oauth2/keys", base_url)).expect("provider");
    let jwks = provider.fetch().await.expect("fetch");
    assert!(jwks.keys.is_empty());

    let req = rx.await.expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/oauth2/keys");
}

#[tokio::test]
async fn jwks_provider_uses_cache() {
    let body = r#"{"keys":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let provider =
        JwksProviderAsync::new(format!("{}/zts/v1/oauth2/keys", base_url)).expect("provider");
    let first = provider.fetch().await.expect("first fetch");
    assert!(first.keys.is_empty());
    let req = rx.await.expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zts/v1/oauth2/keys");

    let second = provider.fetch().await.expect("second fetch");
    assert!(second.keys.is_empty());
}

#[tokio::test]
async fn jwks_provider_reports_non_success() {
    let body = "boom";
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, _rx) = serve_once(response).await;

    let provider =
        JwksProviderAsync::new(format!("{}/zts/v1/oauth2/keys", base_url)).expect("provider");
    let err = provider.fetch().await.expect_err("should error");
    let message = format!("{}", err);
    assert!(message.contains("status 500"));
}

#[tokio::test]
async fn jwt_es512_async_validate_success() {
    let (token, jwks) = build_es512_token();
    let provider = JwksProviderAsync::new("https://example.com/jwks")
        .expect("provider")
        .with_preloaded(jwks);

    let mut options = JwtValidationOptions::athenz_default();
    options.issuer = Some("athenz".to_string());
    options.audience = vec!["client".to_string()];

    let validator = JwtValidatorAsync::new(provider).with_options(options);
    let data = validator
        .validate_access_token(&token)
        .await
        .expect("validate");
    assert_eq!(data.claims["iss"], "athenz");
    assert_eq!(data.claims["aud"], "client");
    assert_eq!(data.header.alg, "ES512");
}

fn build_es512_token() -> (String, JwkSet) {
    let mut rng = thread_rng();
    let signing_key = P521SigningKey::random(&mut rng);
    let verifying_key = P521VerifyingKey::from(&signing_key);
    let encoded_point = verifying_key.to_encoded_point(false);
    let x = encoded_point.x().expect("x coord");
    let y = encoded_point.y().expect("y coord");

    let kid = "test-key";
    let jwks_json = json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-521",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "kid": kid
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("jwks");

    let header = json!({
        "alg": "ES512",
        "kid": kid,
        "typ": "JWT",
    });
    let exp = jsonwebtoken::get_current_timestamp() + 3600;
    let payload = json!({
        "iss": "athenz",
        "aud": "client",
        "sub": "principal",
        "exp": exp,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let token = format!("{}.{}", signing_input, signature_b64);

    (token, jwks)
}

struct CapturedRequest {
    method: String,
    path: String,
}

async fn serve_once(response: String) -> (String, oneshot::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let req = read_request(&mut stream).await;
            let _ = tx.send(req);
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    (format!("http://{}", addr), rx)
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> CapturedRequest {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("failed to read from stream");
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(buf.len());
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let full_path = parts.next().unwrap_or("");

    let mut path_parts = full_path.splitn(2, '?');
    let path = path_parts.next().unwrap_or("").to_string();

    CapturedRequest { method, path }
}
