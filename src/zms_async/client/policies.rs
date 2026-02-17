use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{Assertion, Policies, Policy, PolicyList, PolicyOptions};
use crate::zms::common;
use crate::zms::{PoliciesQueryOptions, PolicyListOptions};

impl ZmsAsyncClient {
    /// Lists policy names within a domain.
    pub async fn get_policy_list(
        &self,
        domain: &str,
        options: &PolicyListOptions,
    ) -> Result<PolicyList, Error> {
        let url = self.build_url(&["domain", domain, "policy"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists policy objects within a domain.
    pub async fn get_policies(
        &self,
        domain: &str,
        options: &PoliciesQueryOptions,
    ) -> Result<Policies, Error> {
        let url = self.build_url(&["domain", domain, "policies"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves a specific policy.
    pub async fn get_policy(&self, domain: &str, policy: &str) -> Result<Policy, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists versions of a specific policy.
    pub async fn get_policy_version_list(
        &self,
        domain: &str,
        policy: &str,
    ) -> Result<PolicyList, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy, "version"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves a specific policy version.
    pub async fn get_policy_version(
        &self,
        domain: &str,
        policy: &str,
        version: &str,
    ) -> Result<Policy, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy, "version", version])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Creates a new policy version.
    pub async fn put_policy_version(
        &self,
        domain: &str,
        policy: &str,
        options: &PolicyOptions,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<Policy>, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy, "version", "create"])?;
        let mut req = self.http.put(url).json(options);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Marks a policy version as active.
    pub async fn set_active_policy_version(
        &self,
        domain: &str,
        policy: &str,
        options: &PolicyOptions,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<Policy>, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy, "version", "active"])?;
        let mut req = self.http.put(url).json(options);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Deletes a specific policy version.
    pub async fn delete_policy_version(
        &self,
        domain: &str,
        policy: &str,
        version: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "policy", policy, "version", version])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Creates or updates a policy.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Deletes a policy.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Retrieves a specific assertion by ID.
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

    /// Creates a new assertion in a policy.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Deletes a policy assertion.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
