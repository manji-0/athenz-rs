use crate::client_defaults::DEFAULT_TIMEOUT;
use crate::error::{
    read_body_with_limit, Error, CONFIG_ERROR_REDIRECT_WITH_AUTH, MAX_ERROR_BODY_BYTES,
};
use crate::ntoken::NTokenSigner;
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::{Certificate, Identity, StatusCode};
use std::time::Duration;
use url::Url;

use super::common;

mod domain;
mod groups;
mod policies;
mod roles;
mod services;

pub struct ZmsClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<Identity>,
    ca_certs: Vec<Certificate>,
    auth: Option<common::AuthProvider>,
}

impl ZmsClientBuilder {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            base_url: Url::parse(base_url.as_ref())?,
            timeout: Some(DEFAULT_TIMEOUT),
            disable_redirect: false,
            identity: None,
            ca_certs: Vec::new(),
            auth: None,
        })
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn disable_redirect(mut self, disable: bool) -> Self {
        self.disable_redirect = disable;
        self
    }

    pub fn mtls_identity_from_pem(mut self, identity_pem: &[u8]) -> Result<Self, Error> {
        self.identity = Some(Identity::from_pem(identity_pem)?);
        Ok(self)
    }

    pub fn mtls_identity_from_parts(
        mut self,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, Error> {
        let mut combined = Vec::new();
        combined.extend_from_slice(cert_pem);
        if !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(key_pem);
        self.identity = Some(Identity::from_pem(&combined)?);
        Ok(self)
    }

    pub fn add_ca_cert_pem(mut self, ca_pem: &[u8]) -> Result<Self, Error> {
        self.ca_certs.push(Certificate::from_pem(ca_pem)?);
        Ok(self)
    }

    pub fn ntoken_auth(mut self, header: impl Into<String>, token: impl Into<String>) -> Self {
        self.auth = Some(common::AuthProvider::StaticHeader {
            header: header.into(),
            value: token.into(),
        });
        self
    }

    pub fn ntoken_signer(mut self, header: impl Into<String>, signer: NTokenSigner) -> Self {
        self.auth = Some(common::AuthProvider::NToken {
            header: header.into(),
            signer,
        });
        self
    }

    pub fn build(self) -> Result<ZmsClient, Error> {
        if self.auth.is_some() && !self.disable_redirect {
            return Err(Error::Crypto(CONFIG_ERROR_REDIRECT_WITH_AUTH.to_string()));
        }
        let mut builder = HttpClient::builder();
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if self.disable_redirect {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        if let Some(identity) = self.identity {
            builder = builder.identity(identity);
        }
        for cert in self.ca_certs {
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build()?;
        Ok(ZmsClient {
            base_url: self.base_url,
            http,
            auth: self.auth,
        })
    }
}

pub struct ZmsClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<common::AuthProvider>,
}

impl ZmsClient {
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZmsClientBuilder, Error> {
        ZmsClientBuilder::new(base_url)
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        common::build_url(
            &self.base_url,
            segments,
            common::BuildUrlOptions::SYNC_CLIENT,
        )
    }

    fn apply_auth(&self, req: RequestBuilder) -> Result<RequestBuilder, Error> {
        common::apply_auth(req, &self.auth, |req, header, value, _ctx| {
            Ok(req.header(header, value))
        })
    }

    fn expect_ok_json<T: serde::de::DeserializeOwned>(&self, resp: Response) -> Result<T, Error> {
        if resp.status() == StatusCode::OK {
            resp.json::<T>().map_err(Error::from)
        } else {
            self.parse_error(resp)
        }
    }

    fn expect_no_content(&self, resp: Response) -> Result<(), Error> {
        if resp.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            self.parse_error(resp)
        }
    }

    fn expect_no_content_or_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<Option<T>, Error> {
        match resp.status() {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => resp.json::<T>().map(Some).map_err(Error::from),
            _ => self.parse_error(resp),
        }
    }

    fn parse_error<T>(&self, mut resp: Response) -> Result<T, Error> {
        let status = resp.status();
        let body = read_body_with_limit(&mut resp, MAX_ERROR_BODY_BYTES)?;
        Err(common::parse_error_from_body(status, &body, false))
    }
}

#[cfg(test)]
mod tests {
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

        let list = client.get_domain_list(&options).expect("request");
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
}
