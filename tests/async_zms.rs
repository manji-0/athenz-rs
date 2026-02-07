#![cfg(feature = "async-client")]

use athenz_provider_tenant::{DomainListOptions, ZmsAsyncClient};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[tokio::test]
async fn get_domain_list_sets_query_and_modified_since() {
    let body = r#"{"names":["a","b"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let mut options = DomainListOptions::default();
    options.limit = Some(5);
    options.prefix = Some("core".to_string());
    options.modified_since = Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string());

    let list = client
        .get_domain_list(&options)
        .await
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string(), "b".to_string()]);

    let req = rx.await.expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain");
    assert_eq!(
        req.headers.get("if-modified-since").map(String::as_str),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(req.query.get("limit").map(String::as_str), Some("5"));
    assert_eq!(req.query.get("prefix").map(String::as_str), Some("core"));
}

struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
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
    let query_str = path_parts.next().unwrap_or("");
    let mut query = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(query_str.as_bytes()) {
        query.insert(k.to_string(), v.to_string());
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    CapturedRequest {
        method,
        path,
        headers,
        query,
    }
}

#[tokio::test]
async fn get_domain_list_returns_none_on_not_modified() {
    let response = "HTTP/1.1 304 Not Modified\r\n\r\n".to_string();
    let (base_url, _rx) = serve_once(response).await;

    let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client.get_domain_list(&options).await.expect("request");
    assert!(list.is_none());
}
