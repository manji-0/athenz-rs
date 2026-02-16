use super::ZmsClient;
use crate::error::Error;
use crate::models::{ProviderResourceGroupRoles, Tenancy, TenantResourceGroupRoles};
use crate::zms::common;

impl ZmsClient {
    /// Registers the provider service in the tenant domain.
    pub fn put_tenancy(
        &self,
        domain: &str,
        service: &str,
        detail: &Tenancy,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "tenancy", service])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes provider service tenancy from the tenant domain.
    pub fn delete_tenancy(
        &self,
        domain: &str,
        service: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "tenancy", service])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Registers a tenant domain for a provider service.
    pub fn put_tenant(
        &self,
        domain: &str,
        service: &str,
        tenant_domain: &str,
        detail: &Tenancy,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain",
            domain,
            "service",
            service,
            "tenant",
            tenant_domain,
        ])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes a tenant domain from a provider service.
    pub fn delete_tenant(
        &self,
        domain: &str,
        service: &str,
        tenant_domain: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain",
            domain,
            "service",
            service,
            "tenant",
            tenant_domain,
        ])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Creates or updates tenant roles for a provider service resource group.
    #[allow(clippy::too_many_arguments)]
    pub fn put_tenant_resource_group_roles(
        &self,
        domain: &str,
        service: &str,
        tenant_domain: &str,
        resource_group: &str,
        detail: &TenantResourceGroupRoles,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<TenantResourceGroupRoles, Error> {
        let url = self.build_url(&[
            "domain",
            domain,
            "service",
            service,
            "tenant",
            tenant_domain,
            "resourceGroup",
            resource_group,
        ])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves tenant roles for a provider service resource group.
    pub fn get_tenant_resource_group_roles(
        &self,
        domain: &str,
        service: &str,
        tenant_domain: &str,
        resource_group: &str,
    ) -> Result<TenantResourceGroupRoles, Error> {
        let url = self.build_url(&[
            "domain",
            domain,
            "service",
            service,
            "tenant",
            tenant_domain,
            "resourceGroup",
            resource_group,
        ])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Deletes tenant roles for a provider service resource group.
    pub fn delete_tenant_resource_group_roles(
        &self,
        domain: &str,
        service: &str,
        tenant_domain: &str,
        resource_group: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain",
            domain,
            "service",
            service,
            "tenant",
            tenant_domain,
            "resourceGroup",
            resource_group,
        ])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Creates or updates provider roles for a tenant resource group.
    #[allow(clippy::too_many_arguments)]
    pub fn put_provider_resource_group_roles(
        &self,
        tenant_domain: &str,
        prov_domain: &str,
        prov_service: &str,
        resource_group: &str,
        detail: &ProviderResourceGroupRoles,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<ProviderResourceGroupRoles, Error> {
        let url = self.build_url(&[
            "domain",
            tenant_domain,
            "provDomain",
            prov_domain,
            "provService",
            prov_service,
            "resourceGroup",
            resource_group,
        ])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves provider roles for a tenant resource group.
    pub fn get_provider_resource_group_roles(
        &self,
        tenant_domain: &str,
        prov_domain: &str,
        prov_service: &str,
        resource_group: &str,
    ) -> Result<ProviderResourceGroupRoles, Error> {
        let url = self.build_url(&[
            "domain",
            tenant_domain,
            "provDomain",
            prov_domain,
            "provService",
            prov_service,
            "resourceGroup",
            resource_group,
        ])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Deletes provider roles for a tenant resource group.
    pub fn delete_provider_resource_group_roles(
        &self,
        tenant_domain: &str,
        prov_domain: &str,
        prov_service: &str,
        resource_group: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain",
            tenant_domain,
            "provDomain",
            prov_domain,
            "provService",
            prov_service,
            "resourceGroup",
            resource_group,
        ])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
