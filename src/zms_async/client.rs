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

mod access;
mod authority;
mod dependency;
mod domain;
mod entities;
mod groups;
mod meta;
mod policies;
mod principal;
mod quota;
mod review;
mod roles;
mod services;
mod signed_domains;
mod stats;
mod templates;
mod tenancy;
mod token;
mod user;

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
    use crate::error::Error;
    use crate::models::{
        DependentService, DomainMeta, Entity, GroupMeta, PolicyOptions, PrincipalState,
        ProviderResourceGroupRoles, Quota, ResourceDomainOwnership, ResourceGroupOwnership,
        ResourcePolicyOwnership, ResourceServiceIdentityOwnership, ServiceIdentitySystemMeta,
        Tenancy, TenantResourceGroupRoles, TenantRoleAction,
    };
    use crate::zms::{DomainListOptions, SignedDomainsOptions};
    use serde_json::json;
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

    #[tokio::test]
    async fn get_policy_version_list_calls_expected_endpoint() {
        let body = r#"{"names":["0","v1"]}"#;
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

        let list = client
            .get_policy_version_list("sports", "readers")
            .await
            .expect("policy version list");
        assert_eq!(list.names, vec!["0", "v1"]);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/version");

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_policy_version_calls_expected_endpoint() {
        let body = r#"{"name":"sports:policy.readers","version":"v1"}"#;
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

        let policy = client
            .get_policy_version("sports", "readers", "v1")
            .await
            .expect("policy version");
        assert_eq!(policy.name, "sports:policy.readers");
        assert_eq!(policy.version.as_deref(), Some("v1"));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/version/v1");

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_policy_version_calls_create_endpoint() {
        let body = r#"{"name":"sports:policy.readers","version":"v2"}"#;
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
        let options = PolicyOptions {
            version: "v2".to_string(),
            from_version: Some("v1".to_string()),
        };

        let policy = client
            .put_policy_version(
                "sports",
                "readers",
                &options,
                Some("create version"),
                Some(true),
                Some("sports.owner"),
            )
            .await
            .expect("put policy version")
            .expect("policy");
        assert_eq!(policy.name, "sports:policy.readers");
        assert_eq!(policy.version.as_deref(), Some("v2"));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/policy/readers/version/create"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("create version")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );
        assert_eq!(
            req.headers.get("athenz-return-object").map(String::as_str),
            Some("true")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn set_active_policy_version_calls_active_endpoint() {
        let body = r#"{"name":"sports:policy.readers","version":"v2","active":true}"#;
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
        let options = PolicyOptions {
            version: "v2".to_string(),
            from_version: None,
        };

        let policy = client
            .set_active_policy_version(
                "sports",
                "readers",
                &options,
                Some("activate version"),
                Some(true),
                Some("sports.owner"),
            )
            .await
            .expect("set active policy version")
            .expect("policy");
        assert_eq!(policy.name, "sports:policy.readers");
        assert_eq!(policy.version.as_deref(), Some("v2"));
        assert_eq!(policy.active, Some(true));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/policy/readers/version/active"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("activate version")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );
        assert_eq!(
            req.headers.get("athenz-return-object").map(String::as_str),
            Some("true")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_policy_version_calls_expected_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_policy_version(
                "sports",
                "readers",
                "v2",
                Some("delete version"),
                Some("sports.owner"),
            )
            .await
            .expect("delete policy version");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/version/v2");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete version")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_service_identity_system_meta_calls_expected_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let meta = ServiceIdentitySystemMeta {
            provider_endpoint: Some("https://provider.example/callback".to_string()),
            ..Default::default()
        };

        client
            .put_service_identity_system_meta(
                "sports",
                "api",
                "provider-endpoint",
                &meta,
                Some("set service provider endpoint"),
            )
            .await
            .expect("put service identity system meta");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/service/api/meta/system/provider-endpoint"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set service provider endpoint")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_service_identity_ownership_calls_expected_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let ownership = ResourceServiceIdentityOwnership {
            public_keys_owner: Some("sports.pubkeys_owner".to_string()),
            hosts_owner: Some("sports.hosts_owner".to_string()),
            object_owner: Some("sports.object_owner".to_string()),
        };

        client
            .put_service_identity_ownership(
                "sports",
                "api",
                &ownership,
                Some("set service ownership"),
            )
            .await
            .expect("put service identity ownership");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/service/api/ownership");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set service ownership")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_domain_system_meta_calls_domain_meta_system_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let meta = DomainMeta {
            product_id: Some("prod-1".to_string()),
            ..Default::default()
        };

        client
            .put_domain_system_meta("sports", "product-id", &meta, Some("set product id"))
            .await
            .expect("put domain system meta");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/meta/system/product-id");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set product id")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("json body for put_domain_system_meta");
        assert_eq!(body_json, json!({ "productId": "prod-1" }));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_domain_ownership_calls_domain_ownership_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let ownership = ResourceDomainOwnership {
            meta_owner: Some("sports.meta_owner".to_string()),
            object_owner: Some("sports.object_owner".to_string()),
        };

        client
            .put_domain_ownership("sports", &ownership, Some("set domain ownership"))
            .await
            .expect("put domain ownership");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/ownership");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set domain ownership")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(
            body_json,
            json!({
                "metaOwner": "sports.meta_owner",
                "objectOwner": "sports.object_owner",
            })
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_quota_calls_domain_quota_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let quota = Quota {
            name: "sports".to_string(),
            subdomain: 1,
            role: 2,
            role_member: 3,
            policy: 4,
            assertion: 5,
            entity: 6,
            service: 7,
            service_host: 8,
            public_key: 9,
            group: 10,
            group_member: 11,
            modified: None,
        };

        client
            .put_quota("sports", &quota, Some("update domain quota"))
            .await
            .expect("put quota");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/quota");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("update domain quota")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_quota_calls_domain_quota_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_quota("sports", Some("delete domain quota"))
            .await
            .expect("delete quota");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/zms/v1/domain/sports/quota");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete domain quota")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_entity_calls_domain_entity_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let entity = Entity {
            name: "sports.entity.config".to_string(),
            value: json!({
                "enabled": true,
                "limit": 100
            }),
        };

        client
            .put_entity(
                "sports",
                "entity.config",
                &entity,
                Some("upsert domain entity"),
                Some("sports-admin"),
            )
            .await
            .expect("put entity");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/entity/entity.config");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("upsert domain entity")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports-admin")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(
            body_json,
            json!({
                "name": "sports.entity.config",
                "value": {
                    "enabled": true,
                    "limit": 100
                }
            })
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_entity_calls_domain_entity_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_entity(
                "sports",
                "entity.config",
                Some("delete domain entity"),
                Some("sports-admin"),
            )
            .await
            .expect("delete entity");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/zms/v1/domain/sports/entity/entity.config");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete domain entity")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports-admin")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_domain_dependency_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let detail = DependentService {
            service: "sports.storage".to_string(),
        };

        client
            .put_domain_dependency(
                "sports",
                &detail,
                Some("register dependency"),
                Some("sports.owner"),
            )
            .await
            .expect("put domain dependency");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/dependency/domain/sports");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("register dependency")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
        assert_eq!(body["service"], "sports.storage");

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_domain_dependency_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_domain_dependency(
                "sports",
                "sports.storage",
                Some("delete dependency"),
                Some("sports.owner"),
            )
            .await
            .expect("delete domain dependency");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(
            req.path,
            "/zms/v1/dependency/domain/sports/service/sports.storage"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete dependency")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_group_system_meta_calls_group_meta_system_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let meta = GroupMeta {
            self_serve: Some(true),
            ..Default::default()
        };

        client
            .put_group_system_meta(
                "sports",
                "devs",
                "self-serve",
                &meta,
                Some("set group self-serve"),
            )
            .await
            .expect("put group system meta");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/group/devs/meta/system/self-serve"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set group self-serve")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(body_json, json!({ "selfServe": true }));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_group_meta_calls_group_meta_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let meta = GroupMeta {
            self_serve: Some(true),
            review_enabled: Some(true),
            ..Default::default()
        };

        client
            .put_group_meta("sports", "devs", &meta, Some("update group meta"))
            .await
            .expect("put group meta");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/group/devs/meta");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("update group meta")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(
            body_json,
            json!({ "selfServe": true, "reviewEnabled": true })
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_group_review_calls_group_review_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .put_group_review("sports", "devs", Some("mark group reviewed"))
            .await
            .expect("put group review");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/group/devs/review");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("mark group reviewed")
        );
        assert!(req.body.is_empty());

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_group_ownership_calls_group_ownership_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let ownership = ResourceGroupOwnership {
            meta_owner: Some("sports.meta_owner".to_string()),
            members_owner: Some("sports.members_owner".to_string()),
            object_owner: Some("sports.object_owner".to_string()),
        };

        client
            .put_group_ownership("sports", "devs", &ownership, Some("set group ownership"))
            .await
            .expect("put group ownership");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/group/devs/ownership");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set group ownership")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(
            body_json,
            json!({
                "metaOwner": "sports.meta_owner",
                "membersOwner": "sports.members_owner",
                "objectOwner": "sports.object_owner",
            })
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_policy_ownership_calls_expected_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let ownership = ResourcePolicyOwnership {
            assertions_owner: Some("sports.assertions_owner".to_string()),
            object_owner: Some("sports.object_owner".to_string()),
        };

        client
            .put_policy_ownership(
                "sports",
                "readers",
                &ownership,
                Some("set policy ownership"),
            )
            .await
            .expect("put policy ownership");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/policy/readers/ownership");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("set policy ownership")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(
            body_json,
            json!({
                "assertionsOwner": "sports.assertions_owner",
                "objectOwner": "sports.object_owner",
            })
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_principal_state_calls_principal_state_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let principal_state = PrincipalState { suspended: true };

        client
            .put_principal_state(
                "sports.api",
                &principal_state,
                Some("disable compromised principal"),
            )
            .await
            .expect("put principal state");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/principal/sports.api/state");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("disable compromised principal")
        );
        let body_json: serde_json::Value =
            serde_json::from_slice(&req.body).expect("request body should be valid JSON");
        assert_eq!(body_json, json!({ "suspended": true }));

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_user_calls_endpoint_with_audit_headers() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_user("jane", Some("cleanup user"), Some("sports.owner"))
            .await
            .expect("delete user");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/zms/v1/user/jane");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("cleanup user")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_domain_member_calls_endpoint_with_audit_headers() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_domain_member(
                "sports",
                "user.jane",
                Some("remove user memberships"),
                Some("sports.owner"),
            )
            .await
            .expect("delete domain member");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/zms/v1/domain/sports/member/user.jane");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("remove user memberships")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_tenancy_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let detail = Tenancy {
            domain: "sports".to_string(),
            service: "storage".to_string(),
            resource_groups: Some(vec!["core".to_string()]),
            create_admin_role: Some(true),
        };

        client
            .put_tenancy(
                "sports",
                "storage",
                &detail,
                Some("register tenant service"),
                Some("sports.owner"),
            )
            .await
            .expect("put tenancy");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(req.path, "/zms/v1/domain/sports/tenancy/storage");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("register tenant service")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_tenancy_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_tenancy(
                "sports",
                "storage",
                Some("delete tenant service"),
                Some("sports.owner"),
            )
            .await
            .expect("delete tenancy");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/zms/v1/domain/sports/tenancy/storage");
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete tenant service")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_tenant_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let detail = Tenancy {
            domain: "sports.tenant".to_string(),
            service: "storage".to_string(),
            resource_groups: Some(vec!["core".to_string()]),
            create_admin_role: Some(true),
        };

        client
            .put_tenant(
                "sports",
                "storage",
                "sports.tenant",
                &detail,
                Some("register tenant domain"),
                Some("sports.owner"),
            )
            .await
            .expect("put tenant");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/service/storage/tenant/sports.tenant"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("register tenant domain")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_tenant_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_tenant(
                "sports",
                "storage",
                "sports.tenant",
                Some("delete tenant domain"),
                Some("sports.owner"),
            )
            .await
            .expect("delete tenant");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/service/storage/tenant/sports.tenant"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete tenant domain")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_tenant_resource_group_roles_calls_endpoint() {
        let body = r#"{"domain":"sports","service":"storage","tenant":"sports.tenant","roles":[{"role":"reader","action":"read"}],"resourceGroup":"core"}"#;
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
        let detail = TenantResourceGroupRoles {
            domain: "sports".to_string(),
            service: "storage".to_string(),
            tenant: "sports.tenant".to_string(),
            roles: vec![TenantRoleAction {
                role: "reader".to_string(),
                action: "read".to_string(),
            }],
            resource_group: "core".to_string(),
        };

        let result = client
            .put_tenant_resource_group_roles(
                "sports",
                "storage",
                "sports.tenant",
                "core",
                &detail,
                Some("upsert tenant roles"),
                Some("sports.owner"),
            )
            .await
            .expect("put tenant resource group roles");
        assert_eq!(result.domain, "sports");
        assert_eq!(result.service, "storage");
        assert_eq!(result.tenant, "sports.tenant");
        assert_eq!(result.roles.len(), 1);
        assert_eq!(result.roles[0].role, "reader");
        assert_eq!(result.roles[0].action, "read");
        assert_eq!(result.resource_group, "core");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/service/storage/tenant/sports.tenant/resourceGroup/core"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("upsert tenant roles")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_tenant_resource_group_roles_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_tenant_resource_group_roles(
                "sports",
                "storage",
                "sports.tenant",
                "core",
                Some("delete tenant roles"),
                Some("sports.owner"),
            )
            .await
            .expect("delete tenant resource group roles");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports/service/storage/tenant/sports.tenant/resourceGroup/core"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete tenant roles")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn put_provider_resource_group_roles_calls_endpoint() {
        let body = r#"{"domain":"sports","service":"storage","tenant":"sports.tenant","roles":[{"role":"reader","action":"read"}],"resourceGroup":"core","createAdminRole":true,"skipPrincipalMember":false}"#;
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
        let detail = ProviderResourceGroupRoles {
            domain: "sports".to_string(),
            service: "storage".to_string(),
            tenant: "sports.tenant".to_string(),
            roles: vec![TenantRoleAction {
                role: "reader".to_string(),
                action: "read".to_string(),
            }],
            resource_group: "core".to_string(),
            create_admin_role: Some(true),
            skip_principal_member: Some(false),
        };

        let result = client
            .put_provider_resource_group_roles(
                "sports.tenant",
                "sports",
                "storage",
                "core",
                &detail,
                Some("upsert provider roles"),
                Some("sports.owner"),
            )
            .await
            .expect("put provider resource group roles");
        assert_eq!(result.domain, "sports");
        assert_eq!(result.service, "storage");
        assert_eq!(result.tenant, "sports.tenant");
        assert_eq!(result.roles.len(), 1);
        assert_eq!(result.roles[0].role, "reader");
        assert_eq!(result.roles[0].action, "read");
        assert_eq!(result.resource_group, "core");
        assert_eq!(result.create_admin_role, Some(true));
        assert_eq!(result.skip_principal_member, Some(false));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports.tenant/provDomain/sports/provService/storage/resourceGroup/core"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("upsert provider roles")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn delete_provider_resource_group_roles_calls_endpoint() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .delete_provider_resource_group_roles(
                "sports.tenant",
                "sports",
                "storage",
                "core",
                Some("delete provider roles"),
                Some("sports.owner"),
            )
            .await
            .expect("delete provider resource group roles");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "DELETE");
        assert_eq!(
            req.path,
            "/zms/v1/domain/sports.tenant/provDomain/sports/provService/storage/resourceGroup/core"
        );
        assert_eq!(
            req.headers.get("y-audit-ref").map(String::as_str),
            Some("delete provider roles")
        );
        assert_eq!(
            req.headers.get("athenz-resource-owner").map(String::as_str),
            Some("sports.owner")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn options_user_token_calls_user_token_options_endpoint() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .options_user_token("jane", Some("sports.api"))
            .await
            .expect("options user token");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.path, "/zms/v1/user/jane/token");
        assert_eq!(
            req.query.get("services").map(String::as_str),
            Some("sports.api")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn options_user_token_accepts_no_content_response() {
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        client
            .options_user_token("jane", Some("sports.api"))
            .await
            .expect("options user token");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.path, "/zms/v1/user/jane/token");
        assert_eq!(
            req.query.get("services").map(String::as_str),
            Some("sports.api")
        );

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn options_user_token_applies_auth_header() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .follow_redirects(false)
            .ntoken_auth("Athenz-Principal-Auth", "token")
            .expect("ntoken auth")
            .build()
            .expect("build");

        client
            .options_user_token("jane", Some("sports.api"))
            .await
            .expect("options user token");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.path, "/zms/v1/user/jane/token");
        assert_eq!(
            req.query.get("services").map(String::as_str),
            Some("sports.api")
        );
        assert_eq!(
            req.headers.get("athenz-principal-auth").map(String::as_str),
            Some("token")
        );

        handle.join().expect("server");
    }

    async fn assert_error_request<F, Fut>(
        expected_method: &str,
        expected_path: &str,
        expected_query: &[(&str, &str)],
        call: F,
    ) where
        F: FnOnce(ZmsAsyncClient) -> Fut,
        Fut: std::future::Future<Output = Result<(), Error>>,
    {
        let response =
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZmsAsyncClient::builder(format!("{}/zms/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = call(client).await;
        assert!(result.is_err(), "request should fail with 500 response");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, expected_method);
        assert_eq!(req.path, expected_path);
        for (key, value) in expected_query {
            assert_eq!(req.query.get(*key).map(String::as_str), Some(*value));
        }
        if expected_query.is_empty() {
            assert!(
                req.query.is_empty(),
                "unexpected query params: {:?}",
                req.query
            );
        }

        handle.join().expect("server");
    }

    #[tokio::test]
    async fn get_endpoints_cover_async_client_surface() {
        assert_error_request(
            "GET",
            "/zms/v1/access/read/sports.resource",
            &[("domain", "sports"), ("principal", "user.jane")],
            |client| async move {
                client
                    .get_access("read", "sports.resource", Some("sports"), Some("user.jane"))
                    .await
                    .map(|_| ())
            },
        )
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/access/read",
            &[
                ("resource", "sports.resource"),
                ("domain", "sports"),
                ("principal", "user.jane"),
            ],
            |client| async move {
                client
                    .get_access_ext("read", "sports.resource", Some("sports"), Some("user.jane"))
                    .await
                    .map(|_| ())
            },
        )
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/dependency/service/sports.storage",
            &[],
            |client| async move {
                client
                    .get_dependent_domain_list("sports.storage")
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/dependency/domain/sports",
            &[],
            |client| async move {
                client
                    .get_dependent_service_list("sports")
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/dependency/domain/sports/resourceGroup",
            &[],
            |client| async move {
                client
                    .get_dependent_service_resource_group_list("sports")
                    .await
                    .map(|_| ())
            },
        )
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/check",
            &[],
            |client| async move { client.get_domain_data_check("sports").await.map(|_| ()) },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/group/member",
            &[],
            |client| async move { client.get_domain_group_members("sports").await.map(|_| ()) },
        )
        .await;
        assert_error_request("GET", "/zms/v1/domain", &[], |client| async move {
            client
                .get_domain_list(&DomainListOptions::default())
                .await
                .map(|_| ())
        })
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/metastore",
            &[("attribute", "product-id"), ("user", "user.jane")],
            |client| async move {
                client
                    .get_domain_meta_store("product-id", Some("user.jane"))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/member",
            &[],
            |client| async move { client.get_domain_role_members("sports").await.map(|_| ()) },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/stats",
            &[],
            |client| async move { client.get_domain_stats("sports").await.map(|_| ()) },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/templatedetails",
            &[],
            |client| async move {
                client
                    .get_domain_template_details("sports")
                    .await
                    .map(|_| ())
            },
        )
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/entity/entity.config",
            &[],
            |client| async move {
                client
                    .get_entity("sports", "entity.config")
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/entity",
            &[],
            |client| async move { client.get_entity_list("sports").await.map(|_| ()) },
        )
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/review/group",
            &[("principal", "user.jane")],
            |client| async move {
                client
                    .get_groups_for_review(Some("user.jane"))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request("GET", "/zms/v1/sys/info", &[], |client| async move {
            client.get_info().await.map(|_| ())
        })
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/sys/modified_domains",
            &[],
            |client| async move {
                client
                    .get_modified_domains(&SignedDomainsOptions::default(), None)
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/overdue",
            &[],
            |client| async move {
                client
                    .get_overdue_domain_role_members("sports")
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/pending_group_members",
            &[("principal", "user.jane"), ("domain", "sports")],
            |client| async move {
                client
                    .get_pending_group_members(Some("user.jane"), Some("sports"))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/pending_members",
            &[("principal", "user.jane"), ("domain", "sports")],
            |client| async move {
                client
                    .get_pending_members(Some("user.jane"), Some("sports"))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/group",
            &[("principal", "user.jane"), ("domain", "sports")],
            |client| async move {
                client
                    .get_principal_groups(Some("user.jane"), Some("sports"))
                    .await
                    .map(|_| ())
            },
        )
        .await;

        assert_error_request(
            "GET",
            "/zms/v1/domain/sports.tenant/provDomain/sports/provService/storage/resourceGroup/core",
            &[],
            |client| async move {
                client
                    .get_provider_resource_group_roles("sports.tenant", "sports", "storage", "core")
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/quota",
            &[],
            |client| async move { client.get_quota("sports").await.map(|_| ()) },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/resource",
            &[
                ("principal", "user.jane"),
                ("action", "read"),
                ("filter", "sports."),
            ],
            |client| async move {
                client
                    .get_resource_access_list("user.jane", Some("read"), Some("sports."))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/review/role",
            &[("principal", "user.jane")],
            |client| async move {
                client
                    .get_roles_for_review(Some("user.jane"))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request("GET", "/zms/v1/schema", &[], |client| async move {
            client.get_schema().await.map(|_| ())
        })
        .await;
        assert_error_request("GET", "/zms/v1/templatedetails", &[], |client| async move {
            client.get_server_template_details_list().await.map(|_| ())
        })
        .await;
        assert_error_request("GET", "/zms/v1/template", &[], |client| async move {
            client.get_server_template_list().await.map(|_| ())
        })
        .await;
        assert_error_request("GET", "/zms/v1/principal", &[], |client| async move {
            client.get_service_principal().await.map(|_| ())
        })
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/signed",
            &[("signaturep1363format", "true")],
            |client| async move {
                client
                    .get_signed_domain("sports", Some(true), Some("etag-2"))
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request("GET", "/zms/v1/sys/stats", &[], |client| async move {
            client.get_system_stats().await.map(|_| ())
        })
        .await;
        assert_error_request("GET", "/zms/v1/template/base", &[], |client| async move {
            client.get_template("base").await.map(|_| ())
        })
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/domain/sports/service/storage/tenant/sports.tenant/resourceGroup/core",
            &[],
            |client| async move {
                client
                    .get_tenant_resource_group_roles("sports", "storage", "sports.tenant", "core")
                    .await
                    .map(|_| ())
            },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/authority/user/attribute",
            &[],
            |client| async move { client.get_user_authority_attributes().await.map(|_| ()) },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/user",
            &[("domain", "user")],
            |client| async move { client.get_user_list(Some("user")).await.map(|_| ()) },
        )
        .await;
        assert_error_request(
            "GET",
            "/zms/v1/user/jane/token",
            &[("services", "sports.api,media.api"), ("header", "true")],
            |client| async move {
                client
                    .get_user_token("jane", Some("sports.api,media.api"), Some(true))
                    .await
                    .map(|_| ())
            },
        )
        .await;
    }

    struct CapturedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        query: HashMap<String, String>,
        body: Vec<u8>,
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

        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buf[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        if body.len() > content_length {
            body.truncate(content_length);
        }

        CapturedRequest {
            method,
            path,
            headers,
            query,
            body,
        }
    }
}
