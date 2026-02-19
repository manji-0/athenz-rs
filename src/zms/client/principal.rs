use super::ZmsClient;
use crate::error::Error;
use crate::models::{DomainGroupMembership, DomainRoleMembership, PrincipalState};
use crate::zms::common;

impl ZmsClient {
    /// Updates a principal state entry.
    pub fn put_principal_state(
        &self,
        principal_name: &str,
        principal_state: &PrincipalState,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["principal", principal_name, "state"])?;
        let mut req = self.http.put(url).json(principal_state);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Lists pending role memberships for a principal.
    pub fn get_pending_members(
        &self,
        principal: Option<&str>,
        domain: Option<&str>,
    ) -> Result<DomainRoleMembership, Error> {
        let url = self.build_url(&["pending_members"])?;
        let mut req = self.http.get(url);
        let mut query = Vec::new();
        if let Some(principal) = principal {
            query.push(("principal", principal.to_string()));
        }
        if let Some(domain) = domain {
            query.push(("domain", domain.to_string()));
        }
        req = common::apply_query_params(req, query);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Lists pending group memberships for a principal.
    pub fn get_pending_group_members(
        &self,
        principal: Option<&str>,
        domain: Option<&str>,
    ) -> Result<DomainGroupMembership, Error> {
        let url = self.build_url(&["pending_group_members"])?;
        let mut req = self.http.get(url);
        let mut query = Vec::new();
        if let Some(principal) = principal {
            query.push(("principal", principal.to_string()));
        }
        if let Some(domain) = domain {
            query.push(("domain", domain.to_string()));
        }
        req = common::apply_query_params(req, query);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
