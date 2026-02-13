use crate::client_defaults::DEFAULT_TIMEOUT;
use crate::error::{
    read_body_with_limit_async, Error, CONFIG_ERROR_REDIRECT_WITH_AUTH, MAX_ERROR_BODY_BYTES,
};
use crate::ntoken::NTokenSigner;
use crate::zts::{common, ConditionalResponse};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Certificate, Client as HttpClient, Identity, RequestBuilder, Response, StatusCode};
use std::time::Duration;
use url::Url;

mod certs;
mod instance;
mod meta;
mod oauth;
mod policy;
mod workloads;

/// Async ZTS client builder.
///
/// `base_url` should point to the ZTS v1 root (e.g., `https://zts.example/zts/v1`).
/// Trailing slashes are allowed. Redirects default to disabled
/// (`follow_redirects(false)`) to observe `Location` headers and avoid leaking
/// auth on redirects; this differs from the sync client.
pub struct ZtsAsyncClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<Identity>,
    ca_certs: Vec<Certificate>,
    auth: Option<common::AuthProvider>,
}

impl ZtsAsyncClientBuilder {
    /// Create a new async client builder.
    ///
    /// `base_url` should point to the ZTS v1 root (e.g., `https://zts.example/zts/v1`).
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            base_url: Url::parse(base_url.as_ref())?,
            timeout: Some(DEFAULT_TIMEOUT),
            disable_redirect: true,
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
    pub fn disable_redirect(mut self, disable_redirect: bool) -> Self {
        self.disable_redirect = disable_redirect;
        self
    }

    /// Configure mTLS identity from a combined PEM (cert + key).
    pub fn mtls_identity_from_pem(mut self, identity_pem: &[u8]) -> Result<Self, Error> {
        self.identity = Some(Identity::from_pem(identity_pem)?);
        Ok(self)
    }

    /// Configure mTLS identity from separate cert/key PEMs.
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

    /// Add a CA certificate PEM for TLS validation.
    pub fn add_ca_cert_pem(mut self, ca_pem: &[u8]) -> Result<Self, Error> {
        self.ca_certs.push(Certificate::from_pem(ca_pem)?);
        Ok(self)
    }

    /// Configure a static auth header.
    ///
    /// Header name/value are validated immediately.
    pub fn ntoken_auth(
        mut self,
        header: impl AsRef<str>,
        token: impl AsRef<str>,
    ) -> Result<Self, Error> {
        // Async builder validates header inputs to avoid request-time failures.
        let header = header.as_ref().to_string();
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {}", e)))?;
        let value = token.as_ref().to_string();
        HeaderValue::from_str(&value)
            .map_err(|e| Error::Crypto(format!("config error: invalid header value: {}", e)))?;
        self.auth = Some(common::AuthProvider::StaticHeader { header, value });
        Ok(self)
    }

    /// Configure a signer-based auth header.
    ///
    /// Header name is validated immediately; token generation happens per request.
    pub fn ntoken_signer(
        mut self,
        header: impl AsRef<str>,
        signer: NTokenSigner,
    ) -> Result<Self, Error> {
        // Async builder validates header inputs to avoid request-time failures.
        let header = header.as_ref().to_string();
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {}", e)))?;
        self.auth = Some(common::AuthProvider::NToken { header, signer });
        Ok(self)
    }

    /// Build the async client.
    ///
    /// Redirects are rejected when auth headers are configured.
    pub fn build(self) -> Result<ZtsAsyncClient, Error> {
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
        Ok(ZtsAsyncClient {
            base_url: self.base_url,
            http,
            auth: self.auth,
            disable_redirect: self.disable_redirect,
        })
    }
}

/// Async ZTS client. Requires the `async-client` feature.
pub struct ZtsAsyncClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<common::AuthProvider>,
    disable_redirect: bool,
}

impl ZtsAsyncClient {
    /// Returns a builder for an async ZTS client.
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZtsAsyncClientBuilder, Error> {
        ZtsAsyncClientBuilder::new(base_url)
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        common::build_url(&self.base_url, segments, common::BuildUrlOptions::REQUEST)
    }

    fn apply_auth(&self, req: RequestBuilder) -> Result<RequestBuilder, Error> {
        common::apply_auth(req, &self.auth, |req, header, value, ctx| {
            let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|e| {
                let msg = match ctx {
                    common::AuthContext::Config => {
                        format!("config error: invalid header name: {}", e)
                    }
                    common::AuthContext::NToken => format!("invalid auth header name: {}", e),
                };
                Error::Crypto(msg)
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                let msg = match ctx {
                    common::AuthContext::Config => {
                        format!("config error: invalid header value: {}", e)
                    }
                    common::AuthContext::NToken => format!(
                        "invalid auth header value generated by ntoken signer: {}",
                        e
                    ),
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

    async fn expect_conditional_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<ConditionalResponse<T>, Error> {
        let status = resp.status();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        match status {
            StatusCode::OK => {
                let data = resp.json::<T>().await?;
                Ok(ConditionalResponse {
                    data: Some(data),
                    etag,
                })
            }
            StatusCode::NOT_MODIFIED => Ok(ConditionalResponse { data: None, etag }),
            _ => self.parse_error(resp).await,
        }
    }

    async fn parse_error<T>(&self, mut resp: Response) -> Result<T, Error> {
        let status = resp.status();
        let body = read_body_with_limit_async(&mut resp, MAX_ERROR_BODY_BYTES).await?;
        Err(common::parse_error_from_body(status, &body, None, true))
    }
}
