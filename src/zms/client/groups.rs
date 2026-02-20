use super::ZmsClient;
use crate::error::Error;
use crate::models::{
    DomainGroupMember, DomainGroupMembers, Group, GroupMembership, GroupMeta, Groups,
    ResourceGroupOwnership,
};
use crate::zms::common;
use crate::zms::{GroupGetOptions, GroupsQueryOptions};

impl ZmsClient {
    /// Lists groups within a domain.
    pub fn get_groups(&self, domain: &str, options: &GroupsQueryOptions) -> Result<Groups, Error> {
        let url = self.build_url(&["domain", domain, "groups"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves a specific group.
    pub fn get_group(
        &self,
        domain: &str,
        group: &str,
        options: &GroupGetOptions,
    ) -> Result<Group, Error> {
        let url = self.build_url(&["domain", domain, "group", group])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Creates or updates a group.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    /// Updates group system metadata for a specific attribute.
    pub fn put_group_system_meta(
        &self,
        domain: &str,
        group: &str,
        attribute: &str,
        meta: &GroupMeta,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain", domain, "group", group, "meta", "system", attribute,
        ])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Updates group metadata.
    pub fn put_group_meta(
        &self,
        domain: &str,
        group: &str,
        meta: &GroupMeta,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group, "meta"])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Marks a group as reviewed.
    pub fn put_group_review(
        &self,
        domain: &str,
        group: &str,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group, "review"])?;
        let mut req = self.http.put(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Sets resource ownership for a group.
    pub fn put_group_ownership(
        &self,
        domain: &str,
        group: &str,
        ownership: &ResourceGroupOwnership,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group, "ownership"])?;
        let mut req = self.http.put(url).json(ownership);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes a group.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Retrieves group membership details for a member.
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

    /// Lists groups for a principal across domains, optionally scoped to one domain.
    pub fn get_principal_groups(
        &self,
        principal: Option<&str>,
        domain: Option<&str>,
    ) -> Result<DomainGroupMember, Error> {
        let url = self.build_url(&["group"])?;
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

    /// Lists group memberships by member in a domain.
    pub fn get_domain_group_members(&self, domain: &str) -> Result<DomainGroupMembers, Error> {
        let url = self.build_url(&["domain", domain, "group", "member"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates or updates a group membership.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    /// Approves or rejects a pending group membership request.
    pub fn put_group_membership_decision(
        &self,
        domain: &str,
        group: &str,
        member: &str,
        membership: &GroupMembership,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain", domain, "group", group, "member", member, "decision",
        ])?;
        let mut req = self.http.put(url).json(membership);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes a group membership.
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
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes a pending group membership request.
    pub fn delete_pending_group_membership(
        &self,
        domain: &str,
        group: &str,
        member: &str,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "group", group, "pendingmember", member])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
