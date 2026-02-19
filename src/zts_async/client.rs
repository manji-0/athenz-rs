use crate::client_defaults::DEFAULT_TIMEOUT;
use crate::error::{
    read_body_with_limit_async, Error, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL,
    CONFIG_ERROR_REDIRECT_WITH_AUTH, MAX_ERROR_BODY_BYTES,
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
mod tenancy;
mod workloads;

/// Async ZTS client builder.
///
/// `base_url` should point to the API root used by this client:
/// `.../zts/v1` for standard ZTS endpoints, or
/// `.../instanceprovider/v1` for instance provider confirmation endpoints.
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
    /// `base_url` should point to `.../zts/v1` for standard ZTS APIs, or to
    /// `.../instanceprovider/v1` when calling instance provider confirmation APIs.
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
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {e}")))?;
        let value = token.as_ref().to_string();
        HeaderValue::from_str(&value)
            .map_err(|e| Error::Crypto(format!("config error: invalid header value: {e}")))?;
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
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {e}")))?;
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

    fn ensure_instance_provider_base_url(&self) -> Result<(), Error> {
        let segments = self
            .base_url
            .path_segments()
            .ok_or_else(|| Error::InvalidBaseUrl(self.base_url.to_string()))?
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if segments.ends_with(&["instanceprovider", "v1"]) {
            Ok(())
        } else {
            Err(Error::Crypto(
                CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL.to_string(),
            ))
        }
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

#[cfg(test)]
mod tests {
    use crate::error::{Error, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL};
    use crate::models::{InstanceConfirmation, InstanceRefreshRequest, RoleCertificateRequest};

    use super::ZtsAsyncClient;
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
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let status = client.get_status().await.expect("status");
        assert_eq!(status.code, 200);
        assert_eq!(status.message, "ok");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/status");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn refresh_instance_credentials_calls_refresh_endpoint() {
        let body = r#"{"name":"sports.api","certificate":"x509-cert"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let request = InstanceRefreshRequest {
            csr: Some("csr".to_string()),
            expiry_time: Some(120),
            key_id: Some("v1".to_string()),
        };
        let identity = client
            .refresh_instance_credentials("sports", "api", &request)
            .await
            .expect("refresh");

        assert_eq!(identity.name.as_deref(), Some("sports.api"));
        assert_eq!(identity.certificate.as_deref(), Some("x509-cert"));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/zts/v1/instance/sports/api/refresh");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_service_identity_calls_expected_endpoint() {
        let body = r#"{"name":"sports.api","providerEndpoint":"https://provider.example"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let identity = client
            .get_service_identity("sports", "api")
            .await
            .expect("service identity");
        assert_eq!(identity.name, "sports.api");
        assert_eq!(
            identity.provider_endpoint.as_deref(),
            Some("https://provider.example")
        );

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/domain/sports/service/api");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_service_identity_list_applies_auth_header() {
        let body = r#"{"names":["sports.api","sports.ui"]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .ntoken_auth("Athenz-Principal-Auth", "token")
            .expect("ntoken auth")
            .build()
            .expect("build");

        let list = client
            .get_service_identity_list("sports")
            .await
            .expect("service identity list");
        assert_eq!(list.names, vec!["sports.api", "sports.ui"]);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/domain/sports/service");
        assert_eq!(
            req.headers.get("athenz-principal-auth").map(String::as_str),
            Some("token")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn post_instance_confirmation_calls_expected_endpoint() {
        let body = r#"{"provider":"sports.provider","domain":"sports","service":"api","attestationData":"doc"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/instanceprovider/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let confirmation = InstanceConfirmation {
            provider: "sports.provider".to_string(),
            domain: "sports".to_string(),
            service: "api".to_string(),
            attestation_data: "doc".to_string(),
            attributes: None,
        };
        let result = client
            .post_instance_confirmation(&confirmation)
            .await
            .expect("instance confirmation");

        assert_eq!(result.provider, "sports.provider");
        assert_eq!(result.domain, "sports");
        assert_eq!(result.service, "api");
        assert_eq!(result.attestation_data, "doc");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/instanceprovider/v1/instance");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn post_refresh_confirmation_applies_auth_header() {
        let body = r#"{"provider":"sports.provider","domain":"sports","service":"api","attestationData":"doc"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/instanceprovider/v1", base_url))
            .expect("builder")
            .ntoken_auth("Athenz-Principal-Auth", "token")
            .expect("ntoken auth")
            .build()
            .expect("build");

        let confirmation = InstanceConfirmation {
            provider: "sports.provider".to_string(),
            domain: "sports".to_string(),
            service: "api".to_string(),
            attestation_data: "doc".to_string(),
            attributes: None,
        };
        client
            .post_refresh_confirmation(&confirmation)
            .await
            .expect("refresh confirmation");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/instanceprovider/v1/refresh");
        assert_eq!(
            req.headers.get("athenz-principal-auth").map(String::as_str),
            Some("token")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn confirmation_endpoints_require_instance_provider_base_path() {
        let client = ZtsAsyncClient::builder("https://zts.example.com/zts/v1")
            .expect("builder")
            .build()
            .expect("build");
        let confirmation = InstanceConfirmation {
            provider: "sports.provider".to_string(),
            domain: "sports".to_string(),
            service: "api".to_string(),
            attestation_data: "doc".to_string(),
            attributes: None,
        };

        let err = client
            .post_instance_confirmation(&confirmation)
            .await
            .expect_err("expected base path validation error");
        match err {
            Error::Crypto(message) => assert_eq!(message, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL),
            other => panic!("unexpected error: {other:?}"),
        }

        let err = client
            .post_refresh_confirmation(&confirmation)
            .await
            .expect_err("expected base path validation error");
        match err {
            Error::Crypto(message) => assert_eq!(message, CONFIG_ERROR_INSTANCE_PROVIDER_BASE_URL),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_role_access_calls_expected_endpoint() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_role_access("sports", "reader", "user.jane")
            .await
            .expect("access");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/domain/sports/role/reader/principal/user.jane"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_calls_expected_endpoint() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access("read", "sports.resource", Some("sports"), Some("user.jane"))
            .await
            .expect("resource access");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/read/sports.resource?domain=sports&principal=user.jane"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_with_principal_only_sets_principal_query_param() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access("read", "sports.resource", None, Some("user.jane"))
            .await
            .expect("resource access");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/read/sports.resource?principal=user.jane"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_with_domain_only_sets_domain_query_param() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access("read", "sports.resource", Some("sports"), None)
            .await
            .expect("resource access");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/read/sports.resource?domain=sports"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_without_optional_filters_omits_query_params() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access("read", "sports.resource", None, None)
            .await
            .expect("resource access");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/access/read/sports.resource");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_ext_calls_expected_endpoint() {
        let body = r#"{"granted":false}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access_ext("read", "sports.resource", Some("sports"), Some("user.jane"))
            .await
            .expect("resource access ext");
        assert!(!access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/read?resource=sports.resource&domain=sports&principal=user.jane"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_ext_with_principal_only_sets_principal_query_param() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access_ext("read", "sports.resource", None, Some("user.jane"))
            .await
            .expect("resource access ext");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/read?resource=sports.resource&principal=user.jane"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_ext_with_domain_only_sets_domain_query_param() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access_ext("read", "sports.resource", Some("sports"), None)
            .await
            .expect("resource access ext");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/read?resource=sports.resource&domain=sports"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_resource_access_ext_without_optional_filters_omits_query_params() {
        let body = r#"{"granted":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let access = client
            .get_resource_access_ext("read", "sports.resource", None, None)
            .await
            .expect("resource access ext");
        assert!(access.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/access/read?resource=sports.resource");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_role_token_calls_expected_endpoint() {
        let body = r#"{"token":"v=Z1;d=sports;r=reader","expiryTime":1800}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let token = client
            .get_role_token(
                "sports",
                Some("reader"),
                Some(60),
                Some(120),
                Some("user.jane"),
            )
            .await
            .expect("role token");
        assert_eq!(token.token, "v=Z1;d=sports;r=reader");
        assert_eq!(token.expiry_time, 1800);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/domain/sports/token?role=reader&minExpiryTime=60&maxExpiryTime=120&proxyForPrincipal=user.jane"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn post_role_token_calls_expected_endpoint() {
        let body = r#"{"token":"v=Z1;d=sports;r=reader","expiryTime":1800}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let request = RoleCertificateRequest {
            csr: "csr".to_string(),
            proxy_for_principal: None,
            expiry_time: 1800,
            prev_cert_not_before: None,
            prev_cert_not_after: None,
            x509_cert_signer_key_id: None,
        };
        let token = client
            .post_role_token("sports", "reader", &request)
            .await
            .expect("role token");
        assert_eq!(token.token, "v=Z1;d=sports;r=reader");
        assert_eq!(token.expiry_time, 1800);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/zts/v1/domain/sports/role/reader/token");
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_aws_temporary_credentials_calls_expected_endpoint() {
        let body = r#"{"accessKeyId":"AKIA_TEST","secretAccessKey":"secret","sessionToken":"session","expiration":"2026-02-19T00:00:00Z"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let creds = client
            .get_aws_temporary_credentials("sports", "reader", Some(3600), Some("ext-tenant"))
            .await
            .expect("aws temporary credentials");
        assert_eq!(creds.access_key_id, "AKIA_TEST");
        assert_eq!(creds.secret_access_key, "secret");
        assert_eq!(creds.session_token, "session");
        assert_eq!(creds.expiration.as_deref(), Some("2026-02-19T00:00:00Z"));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/domain/sports/role/reader/creds?durationSeconds=3600&externalId=ext-tenant"
        );
        assert!(req.headers.contains_key("host"));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_aws_temporary_credentials_applies_auth_header() {
        let body =
            r#"{"accessKeyId":"AKIA_TEST","secretAccessKey":"secret","sessionToken":"session"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsAsyncClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .ntoken_auth("Athenz-Principal-Auth", "token")
            .expect("ntoken auth")
            .build()
            .expect("build");

        client
            .get_aws_temporary_credentials("sports", "reader", None, None)
            .await
            .expect("aws temporary credentials");

        let req = rx.recv().expect("request");
        assert_eq!(
            req.headers.get("athenz-principal-auth").map(String::as_str),
            Some("token")
        );
        assert_eq!(req.path, "/zts/v1/domain/sports/role/reader/creds");

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
