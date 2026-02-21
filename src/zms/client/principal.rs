use super::ZmsClient;
use crate::error::Error;
use crate::models::{DomainGroupMembership, DomainRoleMembership, PrincipalState};
use crate::zms::common;
use crate::zms::PendingMembershipOptions;

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
        let options = PendingMembershipOptions {
            principal: principal.map(str::to_owned),
            domain: domain.map(str::to_owned),
        };
        self.get_pending_members_with_options(&options)
    }

    /// Lists pending role memberships using query options.
    pub fn get_pending_members_with_options(
        &self,
        options: &PendingMembershipOptions,
    ) -> Result<DomainRoleMembership, Error> {
        let url = self.build_url(&["pending_members"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
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
        let options = PendingMembershipOptions {
            principal: principal.map(str::to_owned),
            domain: domain.map(str::to_owned),
        };
        self.get_pending_group_members_with_options(&options)
    }

    /// Lists pending group memberships using query options.
    pub fn get_pending_group_members_with_options(
        &self,
        options: &PendingMembershipOptions,
    ) -> Result<DomainGroupMembership, Error> {
        let url = self.build_url(&["pending_group_members"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
