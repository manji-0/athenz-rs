use crate::client_defaults::DEFAULT_TIMEOUT;
use crate::error::{
    read_body_with_limit_async, Error, CONFIG_ERROR_REDIRECT_WITH_AUTH, MAX_ERROR_BODY_BYTES,
};
use crate::ntoken::NTokenSigner;
use crate::zms::common;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Certificate, Client as HttpClient, Identity, RequestBuilder, Response, StatusCode};
use std::time::Duration;
use url::Url;

mod authority;
mod domain;
mod groups;
mod meta;
mod policies;
mod principal;
mod quota;
mod roles;
mod services;
mod signed_domains;
mod stats;
mod templates;
mod tenancy;
mod token;

/// Builder for [`ZmsAsyncClient`].
///
/// Available when the `async-client` feature is enabled. The `base_url` should
/// point to the ZMS API root, for example `https://zms.example.com/zms/v1`.
pub struct ZmsAsyncClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<Identity>,
    ca_certs: Vec<Certificate>,
    auth: Option<common::AuthProvider>,
}

impl ZmsAsyncClientBuilder {
    /// Creates a builder for the provided base URL.
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

    /// Sets the request timeout for the underlying HTTP client.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Control whether HTTP redirects should be followed.
    ///
    /// If auth headers are configured, enabling redirects is rejected to avoid
    /// leaking credentials to redirected hosts.
    pub fn follow_redirects(mut self, follow_redirects: bool) -> Self {
        self.disable_redirect = !follow_redirects;
        self
    }

    /// Set to true to disable HTTP redirects.
    ///
    /// Deprecated: prefer `follow_redirects(false)` for clarity.
    #[deprecated(note = "Use follow_redirects(false) instead")]
    pub fn disable_redirect(mut self, disable: bool) -> Self {
        self.disable_redirect = disable;
        self
    }

    /// Configure mutual TLS identity from a single PEM bundle containing the
    /// certificate and private key.
    pub fn mtls_identity_from_pem(mut self, identity_pem: &[u8]) -> Result<Self, Error> {
        self.identity = Some(Identity::from_pem(identity_pem)?);
        Ok(self)
    }

    /// Configure mutual TLS identity from separate PEM-encoded certificate
    /// and private key. The inputs are concatenated with a newline if needed.
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

    /// Adds a PEM-encoded CA certificate to the trust store.
    pub fn add_ca_cert_pem(mut self, ca_pem: &[u8]) -> Result<Self, Error> {
        self.ca_certs.push(Certificate::from_pem(ca_pem)?);
        Ok(self)
    }

    /// Configures a static auth header.
    pub fn ntoken_auth(
        mut self,
        header: impl AsRef<str>,
        token: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let header = header.as_ref().to_string();
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {e}")))?;
        let value = token.as_ref().to_string();
        HeaderValue::from_str(&value)
            .map_err(|e| Error::Crypto(format!("config error: invalid header value: {e}")))?;
        self.auth = Some(common::AuthProvider::StaticHeader { header, value });
        Ok(self)
    }

    /// Configures a signer-based auth header.
    pub fn ntoken_signer(
        mut self,
        header: impl AsRef<str>,
        signer: NTokenSigner,
    ) -> Result<Self, Error> {
        let header = header.as_ref().to_string();
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {e}")))?;
        self.auth = Some(common::AuthProvider::NToken { header, signer });
        Ok(self)
    }

    /// Builds the async ZMS client from the configured options.
    pub fn build(self) -> Result<ZmsAsyncClient, Error> {
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
        Ok(ZmsAsyncClient {
            base_url: self.base_url,
            http,
            auth: self.auth,
        })
    }
}

/// Async ZMS client (requires the `async-client` feature).
///
/// Use [`ZmsAsyncClient::builder`] with a base URL like
/// `https://zms.example.com/zms/v1`.
pub struct ZmsAsyncClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<common::AuthProvider>,
}

impl ZmsAsyncClient {
    /// Returns a builder for an async ZMS client.
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZmsAsyncClientBuilder, Error> {
        ZmsAsyncClientBuilder::new(base_url)
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        common::build_url(&self.base_url, segments, common::BuildUrlOptions::REQUEST)
    }

    fn apply_auth(&self, req: RequestBuilder) -> Result<RequestBuilder, Error> {
        common::apply_auth(req, &self.auth, |req, header, value, ctx| {
            let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|e| {
                let msg = match ctx {
                    common::AuthContext::Config => {
                        format!("config error: invalid header name: {e}")
                    }
                    common::AuthContext::NToken => format!("invalid auth header name: {e}"),
                };
                Error::Crypto(msg)
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                let msg = match ctx {
                    common::AuthContext::Config => {
                        format!("config error: invalid header value: {e}")
                    }
                    common::AuthContext::NToken => {
                        format!("invalid auth header value generated by ntoken signer: {e}",)
                    }
                };
                Error::Crypto(msg)
            })?;
            Ok(req.header(header_name, header_value))
        })
    }

    async fn expect_ok_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<T, Error> {
        if resp.status() == StatusCode::OK {
            resp.json::<T>().await.map_err(Error::from)
        } else {
            self.parse_error(resp).await
        }
    }

    async fn expect_no_content(&self, resp: Response) -> Result<(), Error> {
        if resp.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            self.parse_error(resp).await
        }
    }

    async fn expect_no_content_or_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<Option<T>, Error> {
        match resp.status() {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => resp.json::<T>().await.map(Some).map_err(Error::from),
            _ => self.parse_error(resp).await,
        }
    }

    async fn expect_conditional_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<crate::zts::ConditionalResponse<T>, Error> {
        let status = resp.status();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        match status {
            StatusCode::OK => {
                let data = resp.json::<T>().await?;
                Ok(crate::zts::ConditionalResponse {
                    data: Some(data),
                    etag,
                })
            }
            StatusCode::NOT_MODIFIED => Ok(crate::zts::ConditionalResponse { data: None, etag }),
            _ => self.parse_error(resp).await,
        }
    }

    async fn parse_error<T>(&self, mut resp: Response) -> Result<T, Error> {
        let status = resp.status();
        let body = read_body_with_limit_async(&mut resp, MAX_ERROR_BODY_BYTES).await?;
        Err(common::parse_error_from_body(status, &body, true))
    }
}

#[cfg(test)]
mod tests {
    use super::ZmsAsyncClient;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    #[tokio::test]
    async fn get_status_calls_status_endpoint() {
        let body = r#"{"code":200,"message":"ok"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let status = client.get_status().await.expect("status");
        assert_eq!(status.code, 200);
        assert_eq!(status.message, "ok");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zms/v1/status");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    struct CapturedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
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
        let path = parts.next().unwrap_or("").to_string();
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
        }
    }
}
