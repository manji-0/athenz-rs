use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub query: HashMap<String, String>,
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

pub async fn serve_once(response: String) -> (String, oneshot::Receiver<CapturedRequest>) {
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
    let mut header_end = None;
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("failed to read from stream");
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        let start = buf.len().saturating_sub(read + 3);
        if let Some(pos) = find_header_end(&buf, start) {
            header_end = Some(pos);
            break;
        }
    }

    let header_end = header_end.unwrap_or(buf.len());
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
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    CapturedRequest {
        method,
        path,
        headers,
        query,
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
