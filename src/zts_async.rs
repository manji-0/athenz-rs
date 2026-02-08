use crate::error::{Error, ResourceError, MAX_ERROR_BODY_BYTES};
use crate::models::{
    AccessTokenResponse, CertificateAuthorityBundle, DomainSignedPolicyData,
    ExternalCredentialsRequest, ExternalCredentialsResponse, Info, InstanceIdentity,
    InstanceRefreshInformation, InstanceRegisterInformation, InstanceRegisterResponse,
    InstanceRegisterToken, IntrospectResponse, JWSPolicyData, JwkList, OAuthConfig, OidcResponse,
    OpenIdConfig, PublicKeyEntry, RdlSchema, RoleAccess, RoleCertificate, RoleCertificateRequest,
    SSHCertRequest, SSHCertificates, SignedPolicyRequest, Status, TransportRules, Workloads,
};
use crate::ntoken::NTokenSigner;
use crate::zts::{AccessTokenRequest, ConditionalResponse, IdTokenRequest, IdTokenResponse};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Certificate, Client as HttpClient, Identity, RequestBuilder, Response, StatusCode};
use std::time::Duration;
use url::Url;

/// Async ZTS client builder.
///
/// `base_url` should point to the ZTS v1 root (e.g., `https://zts.example/zts/v1`).
/// Trailing slashes are allowed.
pub struct ZtsAsyncClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<Identity>,
    ca_certs: Vec<Certificate>,
    auth: Option<AuthProvider>,
}

impl ZtsAsyncClientBuilder {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            base_url: Url::parse(base_url.as_ref())?,
            timeout: None,
            disable_redirect: true,
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
    pub fn follow_redirects(mut self, follow_redirects: bool) -> Self {
        self.disable_redirect = !follow_redirects;
        self
    }

    /// Set to true to disable HTTP redirects. Prefer `follow_redirects(false)` for clarity.
    pub fn disable_redirect(mut self, disable_redirect: bool) -> Self {
        self.disable_redirect = disable_redirect;
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

    pub fn ntoken_auth(
        mut self,
        header: impl AsRef<str>,
        token: impl AsRef<str>,
    ) -> Result<Self, Error> {
        // Async builder validates header inputs to avoid request-time failures.
        let header = HeaderName::from_bytes(header.as_ref().as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {}", e)))?;
        let value = HeaderValue::from_str(token.as_ref())
            .map_err(|e| Error::Crypto(format!("config error: invalid header value: {}", e)))?;
        self.auth = Some(AuthProvider::StaticHeader { header, value });
        Ok(self)
    }

    pub fn ntoken_signer(
        mut self,
        header: impl AsRef<str>,
        signer: NTokenSigner,
    ) -> Result<Self, Error> {
        // Async builder validates header inputs to avoid request-time failures.
        let header = HeaderName::from_bytes(header.as_ref().as_bytes())
            .map_err(|e| Error::Crypto(format!("config error: invalid header name: {}", e)))?;
        self.auth = Some(AuthProvider::NToken { header, signer });
        Ok(self)
    }

    pub fn build(self) -> Result<ZtsAsyncClient, Error> {
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

#[allow(clippy::large_enum_variant)]
enum AuthProvider {
    StaticHeader {
        header: HeaderName,
        value: HeaderValue,
    },
    NToken {
        header: HeaderName,
        signer: NTokenSigner,
    },
}

/// Async ZTS client. Requires the `async-client` feature.
pub struct ZtsAsyncClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<AuthProvider>,
    disable_redirect: bool,
}

impl ZtsAsyncClient {
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZtsAsyncClientBuilder, Error> {
        ZtsAsyncClientBuilder::new(base_url)
    }

    pub async fn issue_access_token(
        &self,
        request: &AccessTokenRequest,
    ) -> Result<AccessTokenResponse, Error> {
        let url = self.build_url(&["oauth2", "token"])?;
        let body = request.to_form();
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn issue_id_token(&self, request: &IdTokenRequest) -> Result<IdTokenResponse, Error> {
        if !self.disable_redirect {
            return Err(Error::Crypto(
                "config error: issue_id_token requires follow_redirects(false) to observe Location header"
                    .to_string(),
            ));
        }
        let mut url = self.build_url(&["oauth2", "auth"])?;
        let query = request.to_query();
        url.set_query(Some(&query));
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        let status = resp.status();
        match status {
            StatusCode::OK => {
                let response = resp.json::<OidcResponse>().await?;
                Ok(IdTokenResponse {
                    response: Some(response),
                    location: None,
                })
            }
            _ if status.is_redirection() => {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string());
                Ok(IdTokenResponse {
                    response: None,
                    location,
                })
            }
            _ => self.parse_error(resp).await,
        }
    }

    pub async fn introspect_access_token(&self, token: &str) -> Result<IntrospectResponse, Error> {
        let url = self.build_url(&["oauth2", "introspect"])?;
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("token", token);
        let body = params.finish();
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_oauth_config(&self) -> Result<OAuthConfig, Error> {
        let url = self.build_url(&[".well-known", "oauth-authorization-server"])?;
        // Well-known discovery endpoints are typically public; omit auth to match sync client.
        let resp = self.http.get(url).send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_openid_config(&self) -> Result<OpenIdConfig, Error> {
        let url = self.build_url(&[".well-known", "openid-configuration"])?;
        // Well-known discovery endpoints are typically public; omit auth to match sync client.
        let resp = self.http.get(url).send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
    ) -> Result<PublicKeyEntry, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_jwk_list(
        &self,
        rfc: Option<bool>,
        service: Option<&str>,
    ) -> Result<JwkList, Error> {
        let url = self.build_url(&["oauth2", "keys"])?;
        let mut req = self.http.get(url);
        if let Some(rfc) = rfc {
            req = req.query(&[("rfc", rfc.to_string())]);
        }
        if let Some(service) = service {
            req = req.query(&[("service", service)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn register_instance(
        &self,
        info: &InstanceRegisterInformation,
    ) -> Result<InstanceRegisterResponse, Error> {
        let url = self.build_url(&["instance"])?;
        let mut req = self.http.post(url).json(info);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::CREATED => {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string());
                let identity = resp.json::<InstanceIdentity>().await?;
                Ok(InstanceRegisterResponse { identity, location })
            }
            _ => self.parse_error(resp).await,
        }
    }

    pub async fn refresh_instance(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
        info: &InstanceRefreshInformation,
    ) -> Result<InstanceIdentity, Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id])?;
        let mut req = self.http.post(url).json(info);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_instance_register_token(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
    ) -> Result<InstanceRegisterToken, Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id, "token"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn delete_instance(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
    ) -> Result<(), Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_ca_cert_bundle(
        &self,
        name: &str,
    ) -> Result<CertificateAuthorityBundle, Error> {
        let url = self.build_url(&["cacerts", name])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn post_ssh_cert(&self, request: &SSHCertRequest) -> Result<SSHCertificates, Error> {
        let url = self.build_url(&["sshcert"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::CREATED => resp.json::<SSHCertificates>().await.map_err(Error::from),
            _ => self.parse_error(resp).await,
        }
    }

    pub async fn get_workloads_by_service(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<Workloads, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "workloads"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_workloads_by_ip(&self, ip: &str) -> Result<Workloads, Error> {
        let url = self.build_url(&["workloads", ip])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_transport_rules(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<TransportRules, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "transportRules"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn post_external_credentials(
        &self,
        provider: &str,
        domain: &str,
        request: &ExternalCredentialsRequest,
    ) -> Result<ExternalCredentialsResponse, Error> {
        let url = self.build_url(&["external", provider, "domain", domain, "creds"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_status(&self) -> Result<Status, Error> {
        let url = self.build_url(&["status"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_info(&self) -> Result<Info, Error> {
        let url = self.build_url(&["sys", "info"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_schema(&self) -> Result<RdlSchema, Error> {
        let url = self.build_url(&["schema"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn post_role_certificate(
        &self,
        request: &RoleCertificateRequest,
    ) -> Result<RoleCertificate, Error> {
        let url = self.build_url(&["rolecert"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_roles_require_role_cert(
        &self,
        principal: Option<&str>,
    ) -> Result<RoleAccess, Error> {
        let url = self.build_url(&["role", "cert"])?;
        let mut req = self.http.get(url);
        if let Some(principal) = principal {
            req = req.query(&[("principal", principal)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_domain_signed_policy_data(
        &self,
        domain: &str,
        matching_tag: Option<&str>,
    ) -> Result<ConditionalResponse<DomainSignedPolicyData>, Error> {
        let url = self.build_url(&["domain", domain, "signed_policy_data"])?;
        let mut req = self.http.get(url);
        if let Some(tag) = matching_tag {
            req = req.header("If-None-Match", tag);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_conditional_json(resp).await
    }

    pub async fn post_domain_signed_policy_data_jws(
        &self,
        domain: &str,
        request: &SignedPolicyRequest,
        matching_tag: Option<&str>,
    ) -> Result<ConditionalResponse<JWSPolicyData>, Error> {
        let url = self.build_url(&["domain", domain, "policy", "signed"])?;
        let mut req = self.http.post(url).json(request);
        if let Some(tag) = matching_tag {
            req = req.header("If-None-Match", tag);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_conditional_json(resp).await
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        let mut url = self.base_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut path_segments = url
                .path_segments_mut()
                .map_err(|_| Error::InvalidBaseUrl(self.base_url.to_string()))?;
            path_segments.pop_if_empty();
            for segment in segments {
                path_segments.push(segment);
            }
        }
        Ok(url)
    }

    fn apply_auth(&self, mut req: RequestBuilder) -> Result<RequestBuilder, Error> {
        if let Some(ref auth) = self.auth {
            match auth {
                AuthProvider::StaticHeader { header, value } => {
                    req = req.header(header.clone(), value.clone());
                }
                AuthProvider::NToken { header, signer } => {
                    let token = signer.token()?;
                    let value = HeaderValue::from_str(&token)
                        .map_err(|e| Error::Crypto(format!("invalid header value: {}", e)))?;
                    req = req.header(header.clone(), value);
                }
            }
        }
        Ok(req)
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
        let mut body = Vec::new();
        let mut remaining = MAX_ERROR_BODY_BYTES;
        while let Some(chunk) = resp.chunk().await? {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(chunk.len());
            body.extend_from_slice(&chunk[..take]);
            remaining -= take;
        }
        let body_text = String::from_utf8_lossy(&body).to_string();
        let fallback_message = if body_text.trim().is_empty() {
            let reason = status.canonical_reason().unwrap_or("");
            if reason.is_empty() {
                format!("http status {}", status.as_u16())
            } else {
                format!("http status {} {}", status.as_u16(), reason)
            }
        } else {
            body_text.clone()
        };
        let mut err =
            serde_json::from_slice::<ResourceError>(&body).unwrap_or_else(|_| ResourceError {
                code: status.as_u16() as i32,
                message: fallback_message.clone(),
                description: None,
                error: None,
                request_id: None,
            });
        if err.code == 0 {
            err.code = status.as_u16() as i32;
        }
        if err.message.trim().is_empty() {
            err.message = fallback_message;
        }
        Err(Error::Api(err))
    }
}
