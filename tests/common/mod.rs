#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

const READ_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_READ_DURATION: Duration = Duration::from_secs(6);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }
}

pub async fn serve_once(
    response: impl AsRef<[u8]>,
) -> (String, oneshot::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel();
    let response = response.as_ref().to_vec();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let req = read_request(&mut stream).await;
            let _ = tx.send(req);
            let _ = stream.write_all(&response).await;
        }
    });

    (format!("http://{}", addr), rx)
}

pub fn response_with_body(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut response = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n{}", body.len(), body));
    response
}

pub fn json_response(status: &str, body: &str) -> String {
    response_with_body(status, &[("Content-Type", "application/json")], body)
}

pub fn empty_response(status: &str) -> String {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n")
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> CapturedRequest {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut header_end = None;
    let mut incomplete_reason: Option<&'static str> = None;
    let deadline = Instant::now() + MAX_READ_DURATION;
    loop {
        if buf.len() >= MAX_HEADER_BYTES {
            panic!("request headers too large");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("timed out reading request headers");
        }
        let read = match timeout(remaining.min(READ_TIMEOUT), stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            Ok(Err(e)) => panic!("read_request I/O error: {e}"),
            Err(_) => continue,
        };
        if read == 0 {
            incomplete_reason = Some("eof");
            break;
        }
        let remaining_space = MAX_HEADER_BYTES.saturating_sub(buf.len());
        let take = read.min(remaining_space);
        if take == 0 {
            panic!("request headers too large");
        }
        buf.extend_from_slice(&chunk[..take]);
        let start = buf.len().saturating_sub(take + 3);
        if let Some(pos) = find_header_end(&buf, start) {
            header_end = Some(pos);
            break;
        }
        if take < read {
            panic!("request headers too large");
        }
    }

    let header_end = match header_end {
        Some(pos) => pos,
        None => {
            let reason = incomplete_reason.unwrap_or("incomplete");
            return CapturedRequest {
                method: "<incomplete>".to_string(),
                path: format!("<{}>", reason),
                headers: Vec::new(),
                query: HashMap::new(),
                body: Vec::new(),
            };
        }
    };
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
    for (key, value) in url::form_urlencoded::parse(query_str.as_bytes()) {
        query.insert(key.to_string(), value.to_string());
    }

    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }
    if content_length > MAX_BODY_BYTES {
        panic!(
            "request body too large: {} > {} bytes",
            content_length, MAX_BODY_BYTES
        );
    }

    let body_read = buf.len().saturating_sub(header_end);
    let mut body = Vec::new();
    let initial_take = content_length.min(body_read);
    if initial_take > 0 {
        body.extend_from_slice(&buf[header_end..header_end + initial_take]);
    }
    let mut remaining = content_length.saturating_sub(initial_take);
    while remaining > 0 {
        let remaining_time = deadline.saturating_duration_since(Instant::now());
        if remaining_time.is_zero() {
            break;
        }
        let read = match timeout(remaining_time.min(READ_TIMEOUT), stream.read(&mut chunk)).await {
            Ok(Ok(read)) => read,
            Ok(Err(e)) => panic!("read_request body I/O error: {e}"),
            Err(_) => continue,
        };
        if read == 0 {
            break;
        }
        let take = remaining.min(read);
        if take > 0 {
            body.extend_from_slice(&chunk[..take]);
        }
        remaining = remaining.saturating_sub(take);
    }

    if remaining > 0 {
        panic!(
            "read_request body incomplete: expected {content_length} bytes, got {} bytes",
            content_length.saturating_sub(remaining)
        );
    }
    CapturedRequest {
        method,
        path,
        headers,
        query,
        body,
    }
}

fn find_header_end(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 3 < buf.len() {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}
