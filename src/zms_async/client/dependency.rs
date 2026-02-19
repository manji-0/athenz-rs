use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{
    DependentService, DependentServiceResourceGroupList, DomainList, ServiceIdentityList,
};
use crate::zms::common;

impl ZmsAsyncClient {
    /// Registers a dependency from domain to provider service.
    pub async fn put_domain_dependency(
        &self,
        domain_name: &str,
        service: &DependentService,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["dependency", "domain", domain_name])?;
        let mut req = self.http.put(url).json(service);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes a dependency from domain to provider service.
    pub async fn delete_domain_dependency(
        &self,
        domain_name: &str,
        service: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["dependency", "domain", domain_name, "service", service])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Lists services a domain depends on.
    pub async fn get_dependent_service_list(
        &self,
        domain_name: &str,
    ) -> Result<ServiceIdentityList, Error> {
        let url = self.build_url(&["dependency", "domain", domain_name])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists dependent services and resource groups for a domain.
    pub async fn get_dependent_service_resource_group_list(
        &self,
        domain_name: &str,
    ) -> Result<DependentServiceResourceGroupList, Error> {
        let url = self.build_url(&["dependency", "domain", domain_name, "resourceGroup"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists domains that depend on a service.
    pub async fn get_dependent_domain_list(&self, service: &str) -> Result<DomainList, Error> {
        let url = self.build_url(&["dependency", "service", service])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
