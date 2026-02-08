use crate::error::{Error, ResourceError};
use crate::models::{
    Assertion, Domain, DomainList, DomainMeta, Group, GroupMembership, Groups, Membership,
    Policies, Policy, PolicyList, PublicKeyEntry, Role, RoleList, Roles, ServiceIdentities,
    ServiceIdentity, ServiceIdentityList, SubDomain, TopLevelDomain, UserDomain,
};
use crate::ntoken::NTokenSigner;
use crate::zms::{
    DomainListOptions, GroupGetOptions, GroupsQueryOptions, PoliciesQueryOptions,
    PolicyListOptions, RoleGetOptions, RoleListOptions, RolesQueryOptions,
    ServiceIdentitiesQueryOptions, ServiceListOptions,
};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Certificate, Client as HttpClient, Identity, RequestBuilder, Response, StatusCode};
use std::time::Duration;
use url::Url;

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
    auth: Option<AuthProvider>,
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
        let header = HeaderName::from_bytes(header.as_ref().as_bytes())
            .map_err(|e| Error::Crypto(format!("invalid header name (config): {}", e)))?;
        let value = HeaderValue::from_str(token.as_ref())
            .map_err(|e| Error::Crypto(format!("invalid header value (config): {}", e)))?;
        self.auth = Some(AuthProvider::StaticHeader { header, value });
        Ok(self)
    }

    pub fn ntoken_signer(
        mut self,
        header: impl AsRef<str>,
        signer: NTokenSigner,
    ) -> Result<Self, Error> {
        let header = HeaderName::from_bytes(header.as_ref().as_bytes())
            .map_err(|e| Error::Crypto(format!("invalid header name (config): {}", e)))?;
        self.auth = Some(AuthProvider::NToken { header, signer });
        Ok(self)
    }

    pub fn build(self) -> Result<ZmsAsyncClient, Error> {
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

/// Async ZMS client (requires the `async-client` feature).
///
/// Use [`ZmsAsyncClient::builder`] with a base URL like
/// `https://zms.example.com/zms/v1`.
pub struct ZmsAsyncClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<AuthProvider>,
}

impl ZmsAsyncClient {
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZmsAsyncClientBuilder, Error> {
        ZmsAsyncClientBuilder::new(base_url)
    }

    pub async fn get_domain(&self, domain: &str) -> Result<Domain, Error> {
        let url = self.build_url(&["domain", domain])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_domain_list(
        &self,
        options: &DomainListOptions,
    ) -> Result<Option<DomainList>, Error> {
        let url = self.build_url(&["domain"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        if let Some(ref modified_since) = options.modified_since {
            req = req.header("If-Modified-Since", modified_since);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json::<DomainList>().await.map_err(Error::from)?)),
            StatusCode::NOT_MODIFIED => Ok(None),
            _ => self.parse_error(resp).await,
        }
    }

    pub async fn post_top_level_domain(
        &self,
        detail: &TopLevelDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["domain"])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn post_sub_domain(
        &self,
        parent: &str,
        detail: &SubDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["subdomain", parent])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn post_user_domain(
        &self,
        name: &str,
        detail: &UserDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["userdomain", name])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn delete_top_level_domain(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn delete_sub_domain(
        &self,
        parent: &str,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["subdomain", parent, name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn delete_user_domain(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["userdomain", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn put_domain_meta(
        &self,
        name: &str,
        meta: &DomainMeta,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "meta"])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_role_list(
        &self,
        domain: &str,
        options: &RoleListOptions,
    ) -> Result<RoleList, Error> {
        let url = self.build_url(&["domain", domain, "role"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_roles(
        &self,
        domain: &str,
        options: &RolesQueryOptions,
    ) -> Result<Roles, Error> {
        let url = self.build_url(&["domain", domain, "roles"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_role(
        &self,
        domain: &str,
        role: &str,
        options: &RoleGetOptions,
    ) -> Result<Role, Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn put_role(
        &self,
        domain: &str,
        role: &str,
        role_obj: &Role,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<Role>, Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.put(url).json(role_obj);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    pub async fn delete_role(
        &self,
        domain: &str,
        role: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_role_membership(
        &self,
        domain: &str,
        role: &str,
        member: &str,
        expiration: Option<&str>,
    ) -> Result<Membership, Error> {
        let url = self.build_url(&["domain", domain, "role", role, "member", member])?;
        let mut req = self.http.get(url);
        if let Some(expiration) = expiration {
            req = req.query(&[("expiration", expiration)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_role_membership(
        &self,
        domain: &str,
        role: &str,
        member: &str,
        membership: &Membership,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<Membership>, Error> {
        let url = self.build_url(&["domain", domain, "role", role, "member", member])?;
        let mut req = self.http.put(url).json(membership);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    pub async fn delete_role_membership(
        &self,
        domain: &str,
        role: &str,
        member: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role, "member", member])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_policy_list(
        &self,
        domain: &str,
        options: &PolicyListOptions,
    ) -> Result<PolicyList, Error> {
        let url = self.build_url(&["domain", domain, "policy"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_policies(
        &self,
        domain: &str,
        options: &PoliciesQueryOptions,
    ) -> Result<Policies, Error> {
        let url = self.build_url(&["domain", domain, "policies"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_policy(&self, domain: &str, policy: &str) -> Result<Policy, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn put_policy(
        &self,
        domain: &str,
        policy: &str,
        policy_obj: &Policy,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<Policy>, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.put(url).json(policy_obj);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    pub async fn delete_policy(
        &self,
        domain: &str,
        policy: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_assertion(
        &self,
        domain: &str,
        policy: &str,
        assertion_id: i64,
    ) -> Result<Assertion, Error> {
        let id = assertion_id.to_string();
        let url = self.build_url(&["domain", domain, "policy", policy, "assertion", &id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn put_assertion(
        &self,
        domain: &str,
        policy: &str,
        assertion: &Assertion,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Assertion, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy, "assertion"])?;
        let mut req = self.http.put(url).json(assertion);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn delete_assertion(
        &self,
        domain: &str,
        policy: &str,
        assertion_id: i64,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let id = assertion_id.to_string();
        let url = self.build_url(&["domain", domain, "policy", policy, "assertion", &id])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_service_identity(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<ServiceIdentity, Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn put_service_identity(
        &self,
        domain: &str,
        service: &str,
        detail: &ServiceIdentity,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<ServiceIdentity>, Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, None);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    pub async fn delete_service_identity(
        &self,
        domain: &str,
        service: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_service_identities(
        &self,
        domain: &str,
        options: &ServiceIdentitiesQueryOptions,
    ) -> Result<ServiceIdentities, Error> {
        let url = self.build_url(&["domain", domain, "services"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_service_identity_list(
        &self,
        domain: &str,
        options: &ServiceListOptions,
    ) -> Result<ServiceIdentityList, Error> {
        let url = self.build_url(&["domain", domain, "service"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
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

    pub async fn put_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
        entry: &PublicKeyEntry,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.put(url).json(entry);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn delete_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_groups(
        &self,
        domain: &str,
        options: &GroupsQueryOptions,
    ) -> Result<Groups, Error> {
        let url = self.build_url(&["domain", domain, "groups"])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_group(
        &self,
        domain: &str,
        group: &str,
        options: &GroupGetOptions,
    ) -> Result<Group, Error> {
        let url = self.build_url(&["domain", domain, "group", group])?;
        let mut req = self.http.get(url);
        req = self.apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn put_group(
        &self,
        domain: &str,
        group: &str,
        detail: &Group,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<Group>, Error> {
        let url = self.build_url(&["domain", domain, "group", group])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, None);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    pub async fn delete_group(
        &self,
        domain: &str,
        group: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    pub async fn get_group_membership(
        &self,
        domain: &str,
        group: &str,
        member: &str,
        expiration: Option<&str>,
    ) -> Result<GroupMembership, Error> {
        let url = self.build_url(&["domain", domain, "group", group, "member", member])?;
        let mut req = self.http.get(url);
        if let Some(expiration) = expiration {
            req = req.query(&[("expiration", expiration)]);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_group_membership(
        &self,
        domain: &str,
        group: &str,
        member: &str,
        membership: &GroupMembership,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<GroupMembership>, Error> {
        let url = self.build_url(&["domain", domain, "group", group, "member", member])?;
        let mut req = self.http.put(url).json(membership);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, None);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    pub async fn delete_group_membership(
        &self,
        domain: &str,
        group: &str,
        member: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group, "member", member])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = self.apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
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

    fn apply_audit_headers(
        &self,
        mut req: RequestBuilder,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> RequestBuilder {
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        req
    }

    fn apply_query_params(
        &self,
        mut req: RequestBuilder,
        params: Vec<(&'static str, String)>,
    ) -> RequestBuilder {
        if !params.is_empty() {
            req = req.query(&params);
        }
        req
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
        let mut err =
            serde_json::from_slice::<ResourceError>(&body).unwrap_or_else(|_| ResourceError {
                code: status.as_u16() as i32,
                message: String::from_utf8_lossy(&body).to_string(),
                description: None,
                error: None,
                request_id: None,
            });
        if err.code == 0 {
            err.code = status.as_u16() as i32;
        }
        if err.message.is_empty() {
            if body.is_empty() {
                err.message = status.to_string();
            } else {
                err.message = String::from_utf8_lossy(&body).to_string();
            }
        }
        Err(Error::Api(err))
    }
}
