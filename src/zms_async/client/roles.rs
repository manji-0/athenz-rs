use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{
    DomainRoleMember, DomainRoleMembers, Membership, ResourceRoleOwnership, Role, RoleList,
    RoleMeta, Roles,
};
use crate::zms::common;
use crate::zms::{PrincipalRolesOptions, RoleGetOptions, RoleListOptions, RolesQueryOptions};

impl ZmsAsyncClient {
    /// Lists role names within a domain.
    pub async fn get_role_list(
        &self,
        domain: &str,
        options: &RoleListOptions,
    ) -> Result<RoleList, Error> {
        let url = self.build_url(&["domain", domain, "role"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists role objects within a domain.
    pub async fn get_roles(
        &self,
        domain: &str,
        options: &RolesQueryOptions,
    ) -> Result<Roles, Error> {
        let url = self.build_url(&["domain", domain, "roles"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves a specific role.
    pub async fn get_role(
        &self,
        domain: &str,
        role: &str,
        options: &RoleGetOptions,
    ) -> Result<Role, Error> {
        let url = self.build_url(&["domain", domain, "role", role])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Creates or updates a role.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Updates role system metadata for a specific attribute.
    pub async fn put_role_system_meta(
        &self,
        domain: &str,
        role: &str,
        attribute: &str,
        meta: &RoleMeta,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role, "meta", "system", attribute])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Updates role metadata.
    pub async fn put_role_meta(
        &self,
        domain: &str,
        role: &str,
        meta: &RoleMeta,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role, "meta"])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Marks a role as reviewed.
    pub async fn put_role_review(
        &self,
        domain: &str,
        role: &str,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role, "review"])?;
        let mut req = self.http.put(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Sets resource ownership for a role.
    pub async fn put_role_ownership(
        &self,
        domain: &str,
        role: &str,
        ownership: &ResourceRoleOwnership,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "role", role, "ownership"])?;
        let mut req = self.http.put(url).json(ownership);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes a role.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Retrieves role membership details for a member.
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

    /// Lists roles for a principal across domains, optionally scoped to one domain.
    pub async fn get_principal_roles(
        &self,
        principal: Option<&str>,
        domain: Option<&str>,
        expand: Option<bool>,
    ) -> Result<DomainRoleMember, Error> {
        let options = PrincipalRolesOptions {
            principal: principal.map(str::to_owned),
            domain: domain.map(str::to_owned),
            expand,
        };
        self.get_principal_roles_with_options(&options).await
    }

    /// Lists roles for a principal across domains using query options.
    pub async fn get_principal_roles_with_options(
        &self,
        options: &PrincipalRolesOptions,
    ) -> Result<DomainRoleMember, Error> {
        let url = self.build_url(&["role"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists members with overdue review in a domain.
    pub async fn get_overdue_domain_role_members(
        &self,
        domain: &str,
    ) -> Result<DomainRoleMembers, Error> {
        let url = self.build_url(&["domain", domain, "overdue"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists role memberships by member in a domain.
    pub async fn get_domain_role_members(&self, domain: &str) -> Result<DomainRoleMembers, Error> {
        let url = self.build_url(&["domain", domain, "member"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates or updates a role membership.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Deletes a role membership.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
