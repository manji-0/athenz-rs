use super::{ConditionalResponse, ZtsClient};
use crate::error::Error;
use crate::models::{
    Access, DomainSignedPolicyData, JWSPolicyData, ResourceAccess, SignedPolicyRequest,
};
use crate::zts::common;

impl ZtsClient {
    /// Checks whether the principal has access to the specified role.
    pub fn get_role_access(
        &self,
        domain: &str,
        role: &str,
        principal: &str,
    ) -> Result<Access, Error> {
        let url = self.build_url(&[
            "access",
            "domain",
            domain,
            "role",
            role,
            "principal",
            principal,
        ])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Checks whether the specified action is allowed on the given resource.
    pub fn get_resource_access(
        &self,
        action: &str,
        resource: &str,
        domain: Option<&str>,
        principal: Option<&str>,
    ) -> Result<ResourceAccess, Error> {
        let url = self.build_url(&["access", action, resource])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(domain) = domain {
            params.push(("domain", domain.to_string()));
        }
        if let Some(principal) = principal {
            params.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Checks resource access using the extended endpoint with query resource.
    pub fn get_resource_access_ext(
        &self,
        action: &str,
        resource: &str,
        domain: Option<&str>,
        principal: Option<&str>,
    ) -> Result<ResourceAccess, Error> {
        let url = self.build_url(&["access", action])?;
        let mut req = self.http.get(url);
        let mut params = vec![("resource", resource.to_string())];
        if let Some(domain) = domain {
            params.push(("domain", domain.to_string()));
        }
        if let Some(principal) = principal {
            params.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Fetches signed policy data for a domain.
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

    /// Fetches JWS policy data for a domain.
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
}
