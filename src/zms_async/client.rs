use crate::error::Error;
use crate::ntoken::NTokenSigner;
use crate::zms::common;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Certificate, Client as HttpClient, Identity, RequestBuilder, Response, StatusCode};
use std::time::Duration;
use url::Url;

mod domain;
mod groups;
mod policies;
mod roles;
mod services;

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
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            base_url: Url::parse(base_url.as_ref())?,
            timeout: None,
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

    pub fn add_ca_cert_pem(mut self, ca_pem: &[u8]) -> Result<Self, Error> {
        self.ca_certs.push(Certificate::from_pem(ca_pem)?);
        Ok(self)
    }

    pub fn ntoken_auth(
        mut self,
        header: impl AsRef<str>,
        token: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let header = header.as_ref().to_string();
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {}", e)))?;
        let value = token.as_ref().to_string();
        HeaderValue::from_str(&value)
            .map_err(|e| Error::Crypto(format!("config error: invalid header value: {}", e)))?;
        self.auth = Some(common::AuthProvider::StaticHeader { header, value });
        Ok(self)
    }

    pub fn ntoken_signer(
        mut self,
        header: impl AsRef<str>,
        signer: NTokenSigner,
    ) -> Result<Self, Error> {
        let header = header.as_ref().to_string();
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {}", e)))?;
        self.auth = Some(common::AuthProvider::NToken { header, signer });
        Ok(self)
    }

    pub fn build(self) -> Result<ZmsAsyncClient, Error> {
        if self.auth.is_some() && !self.disable_redirect {
            return Err(Error::Crypto(
                "config error: follow_redirects(true) is not allowed when auth is configured"
                    .to_string(),
            ));
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
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZmsAsyncClientBuilder, Error> {
        ZmsAsyncClientBuilder::new(base_url)
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        common::build_url(&self.base_url, segments, true, true, true)
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

    async fn parse_error<T>(&self, resp: Response) -> Result<T, Error> {
        let status = resp.status();
        let body = resp.bytes().await?;
        Err(common::parse_error_from_body(status, &body, true))
    }
}
