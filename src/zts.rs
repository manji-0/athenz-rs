use crate::error::{Error, ResourceError};
use crate::models::{
    Access, AccessTokenResponse, AWSTemporaryCredentials, CertificateAuthorityBundle,
    DomainSignedPolicyData, ExternalCredentialsRequest, ExternalCredentialsResponse, Identity as ZtsIdentity,
    Info, InstanceIdentity, InstanceRefreshInformation, InstanceRefreshRequest, InstanceRegisterInformation,
    InstanceRegisterResponse, InstanceRegisterToken, IntrospectResponse, JwkList, JWSPolicyData,
    OAuthConfig, OidcResponse, OpenIdConfig, PublicKeyEntry, RdlSchema, ResourceAccess, RoleAccess,
    RoleCertificate, RoleCertificateRequest, RoleToken, SignedPolicyRequest, SSHCertRequest,
    SSHCertificates, Status, TenantDomains, TransportRules, Workloads,
};
use crate::ntoken::NTokenSigner;
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::{Certificate, Identity as TlsIdentity, StatusCode};
use std::time::Duration;
use url::Url;

/// Request parameters for AccessToken issuance.
/// Use `new()`/`builder()` for forward-compatible construction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AccessTokenRequest {
    pub domain: String,
    pub roles: Vec<String>,
    pub id_token_service: Option<String>,
    /// If set, this value is used as-is and overrides role/id_token_service scope composition.
    pub raw_scope: Option<String>,
    pub expires_in: Option<i32>,
    pub proxy_principal_spiffe_uris: Option<String>,
    pub proxy_for_principal: Option<String>,
    pub authorization_details: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub assertion: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub actor: Option<String>,
    pub openid_issuer: Option<bool>,
}

impl AccessTokenRequest {
    pub fn new(domain: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            domain: domain.into(),
            roles,
            id_token_service: None,
            raw_scope: None,
            expires_in: None,
            proxy_principal_spiffe_uris: None,
            proxy_for_principal: None,
            authorization_details: None,
            client_assertion_type: None,
            client_assertion: None,
            requested_token_type: None,
            audience: None,
            resource: None,
            subject_token: None,
            subject_token_type: None,
            assertion: None,
            actor_token: None,
            actor_token_type: None,
            actor: None,
            openid_issuer: None,
        }
    }

    pub fn builder(domain: impl Into<String>) -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder::new(domain)
    }

    pub fn to_form(&self) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("grant_type", "client_credentials");
        if let Some(expires_in) = self.expires_in {
            params.append_pair("expires_in", &expires_in.to_string());
        }
        if let Some(ref proxy) = self.proxy_principal_spiffe_uris {
            params.append_pair("proxy_principal_spiffe_uris", proxy);
        }
        if let Some(ref proxy_for_principal) = self.proxy_for_principal {
            params.append_pair("proxy_for_principal", proxy_for_principal);
        }
        if let Some(ref authorization_details) = self.authorization_details {
            params.append_pair("authorization_details", authorization_details);
        }
        if let Some(ref client_assertion_type) = self.client_assertion_type {
            params.append_pair("client_assertion_type", client_assertion_type);
        }
        if let Some(ref client_assertion) = self.client_assertion {
            params.append_pair("client_assertion", client_assertion);
        }
        if let Some(ref requested_token_type) = self.requested_token_type {
            params.append_pair("requested_token_type", requested_token_type);
        }
        if let Some(ref audience) = self.audience {
            params.append_pair("audience", audience);
        }
        if let Some(ref resource) = self.resource {
            params.append_pair("resource", resource);
        }
        if let Some(ref subject_token) = self.subject_token {
            params.append_pair("subject_token", subject_token);
        }
        if let Some(ref subject_token_type) = self.subject_token_type {
            params.append_pair("subject_token_type", subject_token_type);
        }
        if let Some(ref assertion) = self.assertion {
            params.append_pair("assertion", assertion);
        }
        if let Some(ref actor_token) = self.actor_token {
            params.append_pair("actor_token", actor_token);
        }
        if let Some(ref actor_token_type) = self.actor_token_type {
            params.append_pair("actor_token_type", actor_token_type);
        }
        if let Some(ref actor) = self.actor {
            params.append_pair("actor", actor);
        }
        if let Some(openid_issuer) = self.openid_issuer {
            params.append_pair("openid_issuer", &openid_issuer.to_string());
        }
        params.append_pair("scope", &self.scope());
        params.finish()
    }

    fn scope(&self) -> String {
        if let Some(ref raw_scope) = self.raw_scope {
            return raw_scope.clone();
        }
        let mut scopes = Vec::new();
        if self.roles.is_empty() || self.roles.iter().any(|r| r == "*") {
            scopes.push(format!("{}:domain", self.domain));
        } else {
            scopes.extend(
                self.roles
                    .iter()
                    .map(|role| format!("{}:role.{}", self.domain, role)),
            );
        }
        if let Some(ref service) = self.id_token_service {
            scopes.push("openid".to_string());
            scopes.push(format!("{}:service.{}", self.domain, service));
        }
        scopes.join(" ")
    }
}

#[derive(Debug, Clone)]
/// Builder for constructing [`AccessTokenRequest`] values.
///
/// This is the preferred, forward-compatible way to create access token requests.
/// It composes the OAuth/OIDC `scope` parameter from `domain`, `roles`, and
/// `id_token_service`. If [`raw_scope`](AccessTokenRequestBuilder::raw_scope)
/// is set, that value is used as-is and overrides the composed scopes.
///
/// The underlying [`AccessTokenRequest`] struct remains public, so you can still
/// mutate its fields directly if needed, but using this builder is recommended
/// to remain compatible with future extensions.
pub struct AccessTokenRequestBuilder {
    request: AccessTokenRequest,
}

impl AccessTokenRequestBuilder {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            request: AccessTokenRequest::new(domain, Vec::new()),
        }
    }

    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.request.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    pub fn id_token_service(mut self, service: impl Into<String>) -> Self {
        self.request.id_token_service = Some(service.into());
        self
    }

    /// Overrides composed scopes from roles/id_token_service.
    pub fn raw_scope(mut self, scope: impl Into<String>) -> Self {
        self.request.raw_scope = Some(scope.into());
        self
    }

    pub fn expires_in(mut self, value: i32) -> Self {
        self.request.expires_in = Some(value);
        self
    }

    pub fn proxy_principal_spiffe_uris(mut self, value: impl Into<String>) -> Self {
        self.request.proxy_principal_spiffe_uris = Some(value.into());
        self
    }

    pub fn proxy_for_principal(mut self, value: impl Into<String>) -> Self {
        self.request.proxy_for_principal = Some(value.into());
        self
    }

    pub fn authorization_details(mut self, value: impl Into<String>) -> Self {
        self.request.authorization_details = Some(value.into());
        self
    }

    pub fn client_assertion_type(mut self, value: impl Into<String>) -> Self {
        self.request.client_assertion_type = Some(value.into());
        self
    }

    pub fn client_assertion(mut self, value: impl Into<String>) -> Self {
        self.request.client_assertion = Some(value.into());
        self
    }

    pub fn requested_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.requested_token_type = Some(value.into());
        self
    }

    pub fn audience(mut self, value: impl Into<String>) -> Self {
        self.request.audience = Some(value.into());
        self
    }

    pub fn resource(mut self, value: impl Into<String>) -> Self {
        self.request.resource = Some(value.into());
        self
    }

    pub fn subject_token(mut self, value: impl Into<String>) -> Self {
        self.request.subject_token = Some(value.into());
        self
    }

    pub fn subject_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.subject_token_type = Some(value.into());
        self
    }

    pub fn assertion(mut self, value: impl Into<String>) -> Self {
        self.request.assertion = Some(value.into());
        self
    }

    pub fn actor_token(mut self, value: impl Into<String>) -> Self {
        self.request.actor_token = Some(value.into());
        self
    }

    pub fn actor_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.actor_token_type = Some(value.into());
        self
    }

    pub fn actor(mut self, value: impl Into<String>) -> Self {
        self.request.actor = Some(value.into());
        self
    }

    pub fn openid_issuer(mut self, value: bool) -> Self {
        self.request.openid_issuer = Some(value);
        self
    }

    pub fn build(self) -> AccessTokenRequest {
        self.request
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: String,
    pub state: Option<String>,
    pub key_type: Option<String>,
    pub full_arn: Option<bool>,
    pub expiry_time: Option<i32>,
    pub output: Option<String>,
    pub role_in_aud_claim: Option<bool>,
    pub all_scope_present: Option<bool>,
}

impl IdTokenRequest {
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            nonce: nonce.into(),
            state: None,
            key_type: None,
            full_arn: None,
            expiry_time: None,
            output: None,
            role_in_aud_claim: None,
            all_scope_present: None,
        }
    }

    pub fn to_query(&self) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("response_type", "id_token");
        params.append_pair("client_id", &self.client_id);
        params.append_pair("redirect_uri", &self.redirect_uri);
        params.append_pair("scope", &self.scope);
        params.append_pair("nonce", &self.nonce);
        if let Some(ref state) = self.state {
            params.append_pair("state", state);
        }
        if let Some(ref key_type) = self.key_type {
            params.append_pair("keyType", key_type);
        }
        if let Some(full_arn) = self.full_arn {
            params.append_pair("fullArn", &full_arn.to_string());
        }
        if let Some(expiry_time) = self.expiry_time {
            params.append_pair("expiryTime", &expiry_time.to_string());
        }
        if let Some(ref output) = self.output {
            params.append_pair("output", output);
        }
        if let Some(role_in_aud) = self.role_in_aud_claim {
            params.append_pair("roleInAudClaim", &role_in_aud.to_string());
        }
        if let Some(all_scope) = self.all_scope_present {
            params.append_pair("allScopePresent", &all_scope.to_string());
        }
        params.finish()
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenResponse {
    pub response: Option<OidcResponse>,
    pub location: Option<String>,
}

pub struct ZtsClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<TlsIdentity>,
    ca_certs: Vec<Certificate>,
    auth: Option<AuthProvider>,
}

impl ZtsClientBuilder {
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

    pub fn disable_redirect(mut self, disable: bool) -> Self {
        self.disable_redirect = disable;
        self
    }

    pub fn mtls_identity_from_pem(mut self, identity_pem: &[u8]) -> Result<Self, Error> {
        self.identity = Some(TlsIdentity::from_pem(identity_pem)?);
        Ok(self)
    }

    pub fn mtls_identity_from_parts(mut self, cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        let mut combined = Vec::new();
        combined.extend_from_slice(cert_pem);
        if !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(key_pem);
        self.identity = Some(TlsIdentity::from_pem(&combined)?);
        Ok(self)
    }

    pub fn add_ca_cert_pem(mut self, ca_pem: &[u8]) -> Result<Self, Error> {
        self.ca_certs.push(Certificate::from_pem(ca_pem)?);
        Ok(self)
    }

    pub fn ntoken_auth(mut self, header: impl Into<String>, token: impl Into<String>) -> Self {
        self.auth = Some(AuthProvider::StaticHeader {
            header: header.into(),
            value: token.into(),
        });
        self
    }

    pub fn ntoken_signer(mut self, header: impl Into<String>, signer: NTokenSigner) -> Self {
        self.auth = Some(AuthProvider::NToken {
            header: header.into(),
            signer,
        });
        self
    }

    pub fn build(self) -> Result<ZtsClient, Error> {
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
        Ok(ZtsClient {
            base_url: self.base_url,
            http,
            auth: self.auth,
        })
    }
}

enum AuthProvider {
    StaticHeader { header: String, value: String },
    NToken { header: String, signer: NTokenSigner },
}

pub struct ZtsClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<AuthProvider>,
}

#[derive(Debug, Clone)]
pub struct ConditionalResponse<T> {
    pub data: Option<T>,
    pub etag: Option<String>,
}

impl ZtsClient {
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZtsClientBuilder, Error> {
        ZtsClientBuilder::new(base_url)
    }

    pub fn issue_access_token(&self, request: &AccessTokenRequest) -> Result<AccessTokenResponse, Error> {
        let url = self.build_url(&["oauth2", "token"])?;
        let body = request.to_form();
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn issue_id_token(&self, request: &IdTokenRequest) -> Result<IdTokenResponse, Error> {
        let mut url = self.build_url(&["oauth2", "auth"])?;
        let query = request.to_query();
        url.set_query(Some(&query));
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        match resp.status() {
            StatusCode::OK => {
                let response = resp.json::<OidcResponse>()?;
                Ok(IdTokenResponse {
                    response: Some(response),
                    location: None,
                })
            }
            StatusCode::FOUND => {
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
            _ => self.parse_error(resp),
        }
    }

    pub fn introspect_access_token(&self, token: &str) -> Result<IntrospectResponse, Error> {
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
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_oauth_config(&self) -> Result<OAuthConfig, Error> {
        let url = self.build_url(&[".well-known", "oauth-authorization-server"])?;
        let resp = self.http.get(url).send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_openid_config(&self) -> Result<OpenIdConfig, Error> {
        let url = self.build_url(&[".well-known", "openid-configuration"])?;
        let resp = self.http.get(url).send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
    ) -> Result<PublicKeyEntry, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_jwk_list(&self, rfc: Option<bool>, service: Option<&str>) -> Result<JwkList, Error> {
        let url = self.build_url(&["oauth2", "keys"])?;
        let mut req = self.http.get(url);
        if let Some(rfc) = rfc {
            req = req.query(&[("rfc", rfc.to_string())]);
        }
        if let Some(service) = service {
            req = req.query(&[("service", service)]);
        }
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_resource_access(
        &self,
        action: &str,
        resource: &str,
        domain: Option<&str>,
        principal: Option<&str>,
    ) -> Result<ResourceAccess, Error> {
        let url = self.build_url(&["access", action, resource])?;
        let mut req = self.http.get(url);
        if let Some(domain) = domain {
            req = req.query(&[("domain", domain)]);
        }
        if let Some(principal) = principal {
            req = req.query(&[("principal", principal)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_resource_access_ext(
        &self,
        action: &str,
        resource: Option<&str>,
        domain: Option<&str>,
        principal: Option<&str>,
    ) -> Result<ResourceAccess, Error> {
        let url = self.build_url(&["access", action])?;
        let mut req = self.http.get(url);
        if let Some(resource) = resource {
            req = req.query(&[("resource", resource)]);
        }
        if let Some(domain) = domain {
            req = req.query(&[("domain", domain)]);
        }
        if let Some(principal) = principal {
            req = req.query(&[("principal", principal)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_role_token(
        &self,
        domain: &str,
        role: Option<&str>,
        min_expiry_time: Option<i32>,
        max_expiry_time: Option<i32>,
        proxy_for_principal: Option<&str>,
    ) -> Result<RoleToken, Error> {
        let url = self.build_url(&["domain", domain, "token"])?;
        let mut req = self.http.get(url);
        if let Some(role) = role {
            req = req.query(&[("role", role)]);
        }
        if let Some(min_expiry_time) = min_expiry_time {
            req = req.query(&[("minExpiryTime", min_expiry_time.to_string())]);
        }
        if let Some(max_expiry_time) = max_expiry_time {
            req = req.query(&[("maxExpiryTime", max_expiry_time.to_string())]);
        }
        if let Some(proxy_for_principal) = proxy_for_principal {
            req = req.query(&[("proxyForPrincipal", proxy_for_principal)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_role_certificate_request(
        &self,
        domain: &str,
        role: &str,
        request: &RoleCertificateRequest,
    ) -> Result<RoleToken, Error> {
        let url = self.build_url(&["domain", domain, "role", role, "token"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_access(
        &self,
        domain: &str,
        role: &str,
        principal: &str,
    ) -> Result<Access, Error> {
        let url = self.build_url(&["access", "domain", domain, "role", role, "principal", principal])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_role_access(&self, domain: &str, principal: &str) -> Result<RoleAccess, Error> {
        let url = self.build_url(&["access", "domain", domain, "principal", principal])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_tenant_domains(
        &self,
        provider_domain: &str,
        user: &str,
        role_name: Option<&str>,
        service_name: Option<&str>,
    ) -> Result<TenantDomains, Error> {
        let url = self.build_url(&["providerdomain", provider_domain, "user", user])?;
        let mut req = self.http.get(url);
        if let Some(role_name) = role_name {
            req = req.query(&[("roleName", role_name)]);
        }
        if let Some(service_name) = service_name {
            req = req.query(&[("serviceName", service_name)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_instance_refresh_request(
        &self,
        domain: &str,
        service: &str,
        request: &InstanceRefreshRequest,
    ) -> Result<ZtsIdentity, Error> {
        let url = self.build_url(&["instance", domain, service, "refresh"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_aws_temporary_credentials(
        &self,
        domain: &str,
        role: &str,
        duration_seconds: Option<i32>,
        external_id: Option<&str>,
    ) -> Result<AWSTemporaryCredentials, Error> {
        let url = self.build_url(&["domain", domain, "role", role, "creds"])?;
        let mut req = self.http.get(url);
        if let Some(duration_seconds) = duration_seconds {
            req = req.query(&[("durationSeconds", duration_seconds.to_string())]);
        }
        if let Some(external_id) = external_id {
            req = req.query(&[("externalId", external_id)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn register_instance(
        &self,
        info: &InstanceRegisterInformation,
    ) -> Result<InstanceRegisterResponse, Error> {
        let url = self.build_url(&["instance"])?;
        let mut req = self.http.post(url).json(info);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        match resp.status() {
            StatusCode::CREATED => {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string());
                let identity = resp.json::<InstanceIdentity>()?;
                Ok(InstanceRegisterResponse { identity, location })
            }
            _ => self.parse_error(resp),
        }
    }

    pub fn refresh_instance(
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
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_instance_register_token(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
    ) -> Result<InstanceRegisterToken, Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id, "token"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn delete_instance(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
    ) -> Result<(), Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_ca_cert_bundle(&self, name: &str) -> Result<CertificateAuthorityBundle, Error> {
        let url = self.build_url(&["cacerts", name])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_ssh_cert(&self, request: &SSHCertRequest) -> Result<SSHCertificates, Error> {
        let url = self.build_url(&["sshcert"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        match resp.status() {
            StatusCode::CREATED => resp.json::<SSHCertificates>().map_err(Error::from),
            _ => self.parse_error(resp),
        }
    }

    pub fn get_workloads_by_service(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<Workloads, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "workloads"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_workloads_by_ip(&self, ip: &str) -> Result<Workloads, Error> {
        let url = self.build_url(&["workloads", ip])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_transport_rules(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<TransportRules, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "transportRules"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_external_credentials(
        &self,
        provider: &str,
        domain: &str,
        request: &ExternalCredentialsRequest,
    ) -> Result<ExternalCredentialsResponse, Error> {
        let url = self.build_url(&["external", provider, "domain", domain, "creds"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_status(&self) -> Result<Status, Error> {
        let url = self.build_url(&["status"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_info(&self) -> Result<Info, Error> {
        let url = self.build_url(&["sys", "info"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_schema(&self) -> Result<RdlSchema, Error> {
        let url = self.build_url(&["schema"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_role_certificate(
        &self,
        request: &RoleCertificateRequest,
    ) -> Result<RoleCertificate, Error> {
        let url = self.build_url(&["rolecert"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_roles_require_role_cert(
        &self,
        principal: Option<&str>,
    ) -> Result<RoleAccess, Error> {
        let url = self.build_url(&["role", "cert"])?;
        let mut req = self.http.get(url);
        if let Some(principal) = principal {
            req = req.query(&[("principal", principal)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_domain_signed_policy_data(
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
        let resp = req.send()?;
        self.expect_conditional_json(resp)
    }

    pub fn post_domain_signed_policy_data_jws(
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
        let resp = req.send()?;
        self.expect_conditional_json(resp)
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        let mut url = self.base_url.clone();
        {
            let mut path_segments = url
                .path_segments_mut()
                .map_err(|_| Error::InvalidBaseUrl(self.base_url.to_string()))?;
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
                    req = req.header(header, value);
                }
                AuthProvider::NToken { header, signer } => {
                    let token = signer.token()?;
                    req = req.header(header, token);
                }
            }
        }
        Ok(req)
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

    fn expect_conditional_json<T: serde::de::DeserializeOwned>(
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
                let data = resp.json::<T>()?;
                Ok(ConditionalResponse {
                    data: Some(data),
                    etag,
                })
            }
            StatusCode::NOT_MODIFIED => Ok(ConditionalResponse { data: None, etag }),
            _ => self.parse_error(resp),
        }
    }

    fn parse_error<T>(&self, resp: Response) -> Result<T, Error> {
        let status = resp.status();
        let body = resp.bytes()?;
        let mut err = serde_json::from_slice::<ResourceError>(&body).unwrap_or_else(|_| {
            ResourceError {
                code: status.as_u16() as i32,
                message: String::from_utf8_lossy(&body).to_string(),
                description: None,
                error: None,
                request_id: None,
            }
        });
        if err.code == 0 {
            err.code = status.as_u16() as i32;
        }
        if err.message.is_empty() {
            err.message = String::from_utf8_lossy(&body).to_string();
        }
        Err(Error::Api(err))
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessTokenRequest, IdTokenRequest, ZtsClient};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn access_token_scope_domain_only() {
        let req = AccessTokenRequest::new("sports", vec!["*".to_string()]);
        let form = req.to_form();
        assert!(form.contains("scope=sports%3Adomain"));
    }

    #[test]
    fn access_token_scope_roles() {
        let req = AccessTokenRequest::new(
            "sports",
            vec!["reader".to_string(), "writer".to_string()],
        );
        let scope = req.scope();
        assert_eq!(scope, "sports:role.reader sports:role.writer");
    }

    #[test]
    fn access_token_form_includes_optional_fields() {
        let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
        req.proxy_for_principal = Some("user.test".to_string());
        req.authorization_details = Some("{\"type\":\"test\"}".to_string());
        req.openid_issuer = Some(true);
        let form = req.to_form();
        assert!(form.contains("proxy_for_principal=user.test"));
        assert!(form.contains("authorization_details=%7B%22type%22%3A%22test%22%7D"));
        assert!(form.contains("openid_issuer=true"));
    }

    #[test]
    fn access_token_scope_includes_id_token_service() {
        let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
        req.id_token_service = Some("api".to_string());
        let scope = req.scope();
        assert_eq!(scope, "sports:role.reader openid sports:service.api");
        let form = req.to_form();
        assert!(form.contains("scope=sports%3Arole.reader+openid+sports%3Aservice.api"));
    }

    #[test]
    fn access_token_raw_scope_overrides_composed_scope() {
        let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
        req.id_token_service = Some("api".to_string());
        req.raw_scope = Some("custom:scope".to_string());
        let scope = req.scope();
        assert_eq!(scope, "custom:scope");
        let form = req.to_form();
        assert!(form.contains("scope=custom%3Ascope"));
    }

    #[test]
    fn access_token_builder_sets_raw_scope() {
        let req = AccessTokenRequest::builder("sports")
            .roles(vec!["reader".to_string()])
            .id_token_service("api")
            .raw_scope("custom:scope")
            .build();
        let scope = req.scope();
        assert_eq!(scope, "custom:scope");
    }

    #[test]
    fn id_token_query_includes_optional_fields() {
        let mut req = IdTokenRequest::new(
            "sports.api",
            "https://example.com/callback",
            "openid",
            "nonce-123",
        );
        req.state = Some("state-1".to_string());
        req.key_type = Some("EC".to_string());
        req.full_arn = Some(true);
        req.expiry_time = Some(3600);
        req.output = Some("json".to_string());
        req.role_in_aud_claim = Some(true);
        req.all_scope_present = Some(true);

        let query = req.to_query();
        assert!(query.contains("response_type=id_token"));
        assert!(query.contains("client_id=sports.api"));
        assert!(query.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(query.contains("scope=openid"));
        assert!(query.contains("nonce=nonce-123"));
        assert!(query.contains("state=state-1"));
        assert!(query.contains("keyType=EC"));
        assert!(query.contains("fullArn=true"));
        assert!(query.contains("expiryTime=3600"));
        assert!(query.contains("output=json"));
        assert!(query.contains("roleInAudClaim=true"));
        assert!(query.contains("allScopePresent=true"));
    }

    #[test]
    fn get_domain_signed_policy_data_sets_if_none_match() {
        let response = "HTTP/1.1 304 Not Modified\r\nETag: tag-1\r\nContent-Length: 0\r\n\r\n".to_string();
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_domain_signed_policy_data("sports", Some("tag-1"))
            .expect("request");
        assert!(result.data.is_none());
        assert_eq!(result.etag.as_deref(), Some("tag-1"));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/domain/sports/signed_policy_data");
        assert_eq!(req.headers.get("if-none-match").map(String::as_str), Some("tag-1"));

        handle.join().expect("server");
    }

    #[test]
    fn get_resource_access_sets_query() {
        let response = ok_json_response("{\"granted\":true}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_resource_access("update", "resource1", Some("core"), Some("user.jane"))
            .expect("request");
        assert!(result.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/update/resource1?domain=core&principal=user.jane"
        );

        handle.join().expect("server");
    }

    #[test]
    fn get_resource_access_ext_sets_query() {
        let response = ok_json_response("{\"granted\":false}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_resource_access_ext(
                "update",
                Some("resource1"),
                Some("core"),
                Some("user.jane"),
            )
            .expect("request");
        assert!(!result.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/update?resource=resource1&domain=core&principal=user.jane"
        );

        handle.join().expect("server");
    }

    #[test]
    fn get_role_token_sets_query() {
        let response = ok_json_response("{\"token\":\"t\",\"expiryTime\":123}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_role_token(
                "sports",
                Some("admin"),
                Some(300),
                Some(600),
                Some("user.jane"),
            )
            .expect("request");
        assert_eq!(result.token, "t");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/domain/sports/token?role=admin&minExpiryTime=300&maxExpiryTime=600&proxyForPrincipal=user.jane"
        );

        handle.join().expect("server");
    }

    #[test]
    fn post_role_certificate_request_uses_path() {
        let response = ok_json_response("{\"token\":\"t\",\"expiryTime\":123}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let request = crate::models::RoleCertificateRequest {
            csr: "csr".to_string(),
            proxy_for_principal: None,
            expiry_time: 0,
            prev_cert_not_before: None,
            prev_cert_not_after: None,
            x509_cert_signer_key_id: None,
        };

        let result = client
            .post_role_certificate_request("sports", "reader", &request)
            .expect("request");
        assert_eq!(result.token, "t");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/zts/v1/domain/sports/role/reader/token");

        handle.join().expect("server");
    }

    #[test]
    fn get_access_and_role_access_paths() {
        let response = ok_json_response("{\"granted\":true}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_access("sports", "reader", "user.jane")
            .expect("request");
        assert!(result.granted);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/access/domain/sports/role/reader/principal/user.jane"
        );

        handle.join().expect("server");
    }

    #[test]
    fn get_role_access_path() {
        let response = ok_json_response("{\"roles\":[\"a\",\"b\"]}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_role_access("sports", "user.jane")
            .expect("request");
        assert_eq!(result.roles, vec!["a".to_string(), "b".to_string()]);

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/access/domain/sports/principal/user.jane");

        handle.join().expect("server");
    }

    #[test]
    fn get_tenant_domains_sets_query() {
        let response = ok_json_response("{\"tenantDomainNames\":[\"a\",\"b\"]}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_tenant_domains("athenz.provider", "alice", Some("tenant"), Some("svc"))
            .expect("request");
        assert_eq!(
            result.tenant_domain_names,
            vec!["a".to_string(), "b".to_string()]
        );

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/providerdomain/athenz.provider/user/alice?roleName=tenant&serviceName=svc"
        );

        handle.join().expect("server");
    }

    #[test]
    fn post_instance_refresh_request_uses_path() {
        let response = ok_json_response("{\"name\":\"svc\"}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let request = crate::models::InstanceRefreshRequest {
            csr: "csr".to_string(),
            expiry_time: None,
            key_id: None,
            namespace: None,
            cloud: None,
            x509_cert_signer_key_id: None,
        };

        let result = client
            .post_instance_refresh_request("sports", "api", &request)
            .expect("request");
        assert_eq!(result.name, "svc");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/zts/v1/instance/sports/api/refresh");

        handle.join().expect("server");
    }

    #[test]
    fn get_aws_temporary_credentials_sets_query() {
        let response = ok_json_response("{\"accessKeyId\":\"a\",\"secretAccessKey\":\"b\",\"sessionToken\":\"c\",\"expiration\":\"d\"}");
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_aws_temporary_credentials("sports", "admin", Some(900), Some("ext"))
            .expect("request");
        assert_eq!(result.access_key_id, "a");

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.path,
            "/zts/v1/domain/sports/role/admin/creds?durationSeconds=900&externalId=ext"
        );

        handle.join().expect("server");
    }

    struct CapturedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
    }

    fn ok_json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn serve_once(response: String) -> (String, mpsc::Receiver<CapturedRequest>, thread::JoinHandle<()>) {
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

        CapturedRequest { method, path, headers }
    }
}
