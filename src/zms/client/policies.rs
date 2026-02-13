use super::ZmsClient;
use crate::error::Error;
use crate::models::{Assertion, Policies, Policy, PolicyList};
use crate::zms::common;
use crate::zms::{PoliciesQueryOptions, PolicyListOptions};

impl ZmsClient {
    /// Lists policy names within a domain.
    pub fn get_policy_list(
        &self,
        domain: &str,
        options: &PolicyListOptions,
    ) -> Result<PolicyList, Error> {
        let url = self.build_url(&["domain", domain, "policy"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Lists policy objects within a domain.
    pub fn get_policies(
        &self,
        domain: &str,
        options: &PoliciesQueryOptions,
    ) -> Result<Policies, Error> {
        let url = self.build_url(&["domain", domain, "policies"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves a specific policy.
    pub fn get_policy(&self, domain: &str, policy: &str) -> Result<Policy, Error> {
        let url = self.build_url(&["domain", domain, "policy", policy])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Creates or updates a policy.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    /// Deletes a policy.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Retrieves a specific assertion by ID.
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

    /// Creates a new assertion in a policy.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Deletes a policy assertion.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
