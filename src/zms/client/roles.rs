use super::ZmsClient;
use crate::error::Error;
use crate::models::{Membership, Role, RoleList, Roles};
use crate::zms::common;
use crate::zms::{RoleGetOptions, RoleListOptions, RolesQueryOptions};

impl ZmsClient {
    /// Lists role names within a domain.
    pub fn get_role_list(
        &self,
        domain: &str,
        options: &RoleListOptions,
    ) -> Result<RoleList, Error> {
        let url = self.build_url(&["domain", domain, "role"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Lists role objects within a domain.
    pub fn get_roles(&self, domain: &str, options: &RolesQueryOptions) -> Result<Roles, Error> {
        let url = self.build_url(&["domain", domain, "roles"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves a specific role.
    pub fn get_role(
        &self,
        domain: &str,
        role: &str,
        options: &RoleGetOptions,
    ) -> Result<Role, Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Creates or updates a role.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    /// Deletes a role.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Retrieves role membership details for a member.
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

    #[allow(clippy::too_many_arguments)]
    /// Creates or updates a role membership.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    /// Deletes a role membership.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
