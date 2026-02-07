use crate::error::{Error, ResourceError};
use crate::models::{
    Assertion, Domain, DomainList, DomainMeta, Group, GroupMembership, Groups, Membership, Policy,
    PolicyList, Policies, PublicKeyEntry, Role, RoleList, Roles, ServiceIdentities,
    ServiceIdentity, ServiceIdentityList, SubDomain, TopLevelDomain, UserDomain,
};
use crate::ntoken::NTokenSigner;
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::{Certificate, Identity, StatusCode};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct DomainListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
    pub prefix: Option<String>,
    pub depth: Option<i32>,
    pub account: Option<String>,
    pub product_number: Option<i32>,
    pub role_member: Option<String>,
    pub role_name: Option<String>,
    pub subscription: Option<String>,
    pub project: Option<String>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
    pub business_service: Option<String>,
    pub product_id: Option<String>,
    pub modified_since: Option<String>,
}

impl DomainListOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        if let Some(ref prefix) = self.prefix {
            pairs.push(("prefix", prefix.clone()));
        }
        if let Some(depth) = self.depth {
            pairs.push(("depth", depth.to_string()));
        }
        if let Some(ref account) = self.account {
            pairs.push(("account", account.clone()));
        }
        if let Some(product_number) = self.product_number {
            pairs.push(("ypmid", product_number.to_string()));
        }
        if let Some(ref role_member) = self.role_member {
            pairs.push(("member", role_member.clone()));
        }
        if let Some(ref role_name) = self.role_name {
            pairs.push(("role", role_name.clone()));
        }
        if let Some(ref subscription) = self.subscription {
            pairs.push(("azure", subscription.clone()));
        }
        if let Some(ref project) = self.project {
            pairs.push(("gcp", project.clone()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        if let Some(ref business_service) = self.business_service {
            pairs.push(("businessService", business_service.clone()));
        }
        if let Some(ref product_id) = self.product_id {
            pairs.push(("productId", product_id.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct RoleListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
}

impl RoleListOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct RolesQueryOptions {
    pub members: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl RolesQueryOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(members) = self.members {
            pairs.push(("members", members.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct RoleGetOptions {
    pub audit_log: Option<bool>,
    pub expand: Option<bool>,
    pub pending: Option<bool>,
}

impl RoleGetOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(audit_log) = self.audit_log {
            pairs.push(("auditLog", audit_log.to_string()));
        }
        if let Some(expand) = self.expand {
            pairs.push(("expand", expand.to_string()));
        }
        if let Some(pending) = self.pending {
            pairs.push(("pending", pending.to_string()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
}

impl PolicyListOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct PoliciesQueryOptions {
    pub assertions: Option<bool>,
    pub include_non_active: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl PoliciesQueryOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(assertions) = self.assertions {
            pairs.push(("assertions", assertions.to_string()));
        }
        if let Some(include_non_active) = self.include_non_active {
            pairs.push(("includeNonActive", include_non_active.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServiceListOptions {
    pub limit: Option<i32>,
    pub skip: Option<String>,
}

impl ServiceListOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(limit) = self.limit {
            pairs.push(("limit", limit.to_string()));
        }
        if let Some(ref skip) = self.skip {
            pairs.push(("skip", skip.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServiceIdentitiesQueryOptions {
    pub public_keys: Option<bool>,
    pub hosts: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl ServiceIdentitiesQueryOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(public_keys) = self.public_keys {
            pairs.push(("publickeys", public_keys.to_string()));
        }
        if let Some(hosts) = self.hosts {
            pairs.push(("hosts", hosts.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct GroupsQueryOptions {
    pub members: Option<bool>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
}

impl GroupsQueryOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(members) = self.members {
            pairs.push(("members", members.to_string()));
        }
        if let Some(ref tag_key) = self.tag_key {
            pairs.push(("tagKey", tag_key.clone()));
        }
        if let Some(ref tag_value) = self.tag_value {
            pairs.push(("tagValue", tag_value.clone()));
        }
        pairs
    }
}

#[derive(Debug, Clone, Default)]
pub struct GroupGetOptions {
    pub audit_log: Option<bool>,
    pub pending: Option<bool>,
}

impl GroupGetOptions {
    fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(audit_log) = self.audit_log {
            pairs.push(("auditLog", audit_log.to_string()));
        }
        if let Some(pending) = self.pending {
            pairs.push(("pending", pending.to_string()));
        }
        pairs
    }
}

pub struct ZmsClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<Identity>,
    ca_certs: Vec<Certificate>,
    auth: Option<AuthProvider>,
}

impl ZmsClientBuilder {
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
        self.identity = Some(Identity::from_pem(identity_pem)?);
        Ok(self)
    }

    pub fn mtls_identity_from_parts(mut self, cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
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

    pub fn build(self) -> Result<ZmsClient, Error> {
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

enum AuthProvider {
    StaticHeader { header: String, value: String },
    NToken { header: String, signer: NTokenSigner },
}

pub struct ZmsClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<AuthProvider>,
}

impl ZmsClient {
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZmsClientBuilder, Error> {
        ZmsClientBuilder::new(base_url)
    }

    pub fn get_domain(&self, domain: &str) -> Result<Domain, Error> {
        let url = self.build_url(&["domain", domain])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_domain_list(&self, options: &DomainListOptions) -> Result<DomainList, Error> {
        let url = self.build_url(&["domain"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        if let Some(ref modified_since) = options.modified_since {
            req = req.header("If-Modified-Since", modified_since);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_top_level_domain(
        &self,
        detail: &TopLevelDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["domain"])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_sub_domain(
        &self,
        parent: &str,
        detail: &SubDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["subdomain", parent])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn post_user_domain(
        &self,
        name: &str,
        detail: &UserDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["userdomain", name])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn delete_top_level_domain(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn delete_sub_domain(
        &self,
        parent: &str,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["subdomain", parent, name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn delete_user_domain(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["userdomain", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn put_domain_meta(
        &self,
        name: &str,
        meta: &DomainMeta,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "meta"])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_role_list(&self, domain: &str, options: &RoleListOptions) -> Result<RoleList, Error> {
        let url = self.build_url(&["domain", domain, "role"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_roles(&self, domain: &str, options: &RolesQueryOptions) -> Result<Roles, Error> {
        let url = self.build_url(&["domain", domain, "roles"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_role(
        &self,
        domain: &str,
        role: &str,
        options: &RoleGetOptions,
    ) -> Result<Role, Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_role(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_role(
        &self,
        domain: &str,
        role: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_role_membership(
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
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_role_membership(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_role_membership(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_policy_list(
        &self,
        domain: &str,
        options: &PolicyListOptions,
    ) -> Result<PolicyList, Error> {
        let url = self.build_url(&["domain", domain, "policy"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_policies(
        &self,
        domain: &str,
        options: &PoliciesQueryOptions,
    ) -> Result<Policies, Error> {
        let url = self.build_url(&["domain", domain, "policies"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_policy(&self, domain: &str, policy: &str) -> Result<Policy, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_policy(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_policy(
        &self,
        domain: &str,
        policy: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_assertion(
        &self,
        domain: &str,
        policy: &str,
        assertion_id: i64,
    ) -> Result<Assertion, Error> {
        let id = assertion_id.to_string();
        let url = self.build_url(&["domain", domain, "policy", policy, "assertion", &id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_assertion(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn delete_assertion(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_service_identity(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<ServiceIdentity, Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_service_identity(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_service_identity(
        &self,
        domain: &str,
        service: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_service_identities(
        &self,
        domain: &str,
        options: &ServiceIdentitiesQueryOptions,
    ) -> Result<ServiceIdentities, Error> {
        let url = self.build_url(&["domain", domain, "services"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_service_identity_list(
        &self,
        domain: &str,
        options: &ServiceListOptions,
    ) -> Result<ServiceIdentityList, Error> {
        let url = self.build_url(&["domain", domain, "service"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
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

    pub fn put_public_key_entry(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn delete_public_key_entry(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_groups(&self, domain: &str, options: &GroupsQueryOptions) -> Result<Groups, Error> {
        let url = self.build_url(&["domain", domain, "groups"])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_group(
        &self,
        domain: &str,
        group: &str,
        options: &GroupGetOptions,
    ) -> Result<Group, Error> {
        let url = self.build_url(&["domain", domain, "group", group])?;
        let mut req = self.http.get(url);
        let params = options.to_query_pairs();
        if !params.is_empty() {
            req = req.query(&params);
        }
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_group(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_group(
        &self,
        domain: &str,
        group: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_group_membership(
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
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_group_membership(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_group_membership(
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
        if let Some(audit_ref) = audit_ref {
            req = req.header("Y-Audit-Ref", audit_ref);
        }
        if let Some(resource_owner) = resource_owner {
            req = req.header("Athenz-Resource-Owner", resource_owner);
        }
        let resp = req.send()?;
        self.expect_no_content(resp)
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
    use super::{DomainListOptions, ZmsClient};
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

    struct CapturedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        query: HashMap<String, String>,
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
