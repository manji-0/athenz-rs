use super::ZmsClient;
use crate::error::Error;
use crate::models::UserList;
use crate::zms::common;

impl ZmsClient {
    /// Lists users registered as principals in the system.
    pub fn get_user_list(&self, domain_name: Option<&str>) -> Result<UserList, Error> {
        let url = self.build_url(&["user"])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(domain_name) = domain_name {
            params.push(("domain", domain_name.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Deletes a user and related domains/memberships.
    pub fn delete_user(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["user", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Removes a member from all roles in the specified domain.
    pub fn delete_domain_member(
        &self,
        domain_name: &str,
        member_name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain_name, "member", member_name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
