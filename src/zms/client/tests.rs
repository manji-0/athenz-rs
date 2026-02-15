use crate::error::{Error, CONFIG_ERROR_REDIRECT_WITH_AUTH};
use crate::zms::{DomainListOptions, ZmsClient};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

#[test]
fn get_domain_list_sets_query_and_modified_since() {
    let body = r#"{"names":["a","b"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let mut options = DomainListOptions::default();
    options.limit = Some(5);
    options.prefix = Some("core".to_string());
    options.modified_since = Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string());

    let list = client
        .get_domain_list(&options)
        .expect("request")
        .expect("list");
    assert_eq!(list.names, vec!["a".to_string(), "b".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/domain");
    assert_eq!(
        req.headers.get("if-modified-since").map(String::as_str),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    assert_eq!(req.query.get("limit").map(String::as_str), Some("5"));
    assert_eq!(req.query.get("prefix").map(String::as_str), Some("core"));

    handle.join().expect("server");
}

#[test]
fn get_domain_list_returns_none_on_not_modified() {
    let response = "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n".to_string();
    let (base_url, _rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let options = DomainListOptions::default();
    let list = client.get_domain_list(&options).expect("request");
    assert!(list.is_none());

    handle.join().expect("server");
}

#[test]
fn get_info_calls_sys_info_endpoint() {
    let body = r#"{"buildJdkSpec":"17","implementationTitle":"zms"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let info = client.get_info().expect("info");
    assert_eq!(info.build_jdk_spec.as_deref(), Some("17"));
    assert_eq!(info.implementation_title.as_deref(), Some("zms"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/sys/info");

    handle.join().expect("server");
}

#[test]
fn get_status_calls_status_endpoint() {
    let body = r#"{"code":200,"message":"ok"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let status = client.get_status().expect("status");
    assert_eq!(status.code, 200);
    assert_eq!(status.message, "ok");

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/status");

    handle.join().expect("server");
}

#[test]
fn get_schema_calls_schema_endpoint() {
    let body = r#"{"name":"zms","types":[]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let schema = client.get_schema().expect("schema");
    assert_eq!(schema.0.get("name").and_then(|v| v.as_str()), Some("zms"));

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/schema");

    handle.join().expect("server");
}

#[test]
fn get_user_authority_attributes_calls_endpoint() {
    let body = r#"{"attributes":{"employeeType":{"values":["full_time"]}}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (base_url, rx, handle) = serve_once(response);
    let client = ZmsClient::builder(format!("{}/zms/v1", base_url))
        .expect("builder")
        .build()
        .expect("build");

    let attributes = client
        .get_user_authority_attributes()
        .expect("authority attributes");
    let employee_type = attributes
        .attributes
        .get("employeeType")
        .expect("employeeType attribute");
    assert_eq!(employee_type.values, vec!["full_time".to_string()]);

    let req = rx.recv().expect("request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/zms/v1/authority/user/attribute");

    handle.join().expect("server");
}

#[test]
fn auth_requires_redirects_disabled() {
    let err = match ZmsClient::builder("https://example.com/zms/v1")
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
fn build_url_trims_trailing_slash() {
    let client = ZmsClient::builder("https://example.com/zms/v1/")
        .expect("builder")
        .build()
        .expect("build");
    let url = client.build_url(&["domain"]).expect("url");
    assert_eq!(url.path(), "/zms/v1/domain");
}

#[test]
fn auth_allows_redirects_disabled() {
    ZmsClient::builder("https://example.com/zms/v1")
        .expect("builder")
        .disable_redirect(true)
        .ntoken_auth("Athenz-Principal-Auth", "token")
        .build()
        .expect("build");
}

struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
}

fn serve_once(
    response: String,
) -> (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let req = read_request(&mut stream);
            let _ = tx.send(req);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (format!("http://{}", addr), rx, handle)
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
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
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    CapturedRequest {
        method,
        path,
        headers,
        query,
    }
}
