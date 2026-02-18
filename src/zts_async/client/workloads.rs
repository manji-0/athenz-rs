use super::ZtsAsyncClient;
use crate::error::Error;
use crate::models::{
    ExternalCredentialsRequest, ExternalCredentialsResponse, HostServices, ServiceIdentity,
    ServiceIdentityList, TransportRules, Workloads,
};

impl ZtsAsyncClient {
    /// Retrieves a service identity.
    pub async fn get_service_identity(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<ServiceIdentity, Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists service identity names within a domain.
    pub async fn get_service_identity_list(
        &self,
        domain: &str,
    ) -> Result<ServiceIdentityList, Error> {
        let url = self.build_url(&["domain", domain, "service"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves services provisioned on a host.
    pub async fn get_host_services(&self, host: &str) -> Result<HostServices, Error> {
        let url = self.build_url(&["host", host, "services"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves workloads for a service.
    pub async fn get_workloads_by_service(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<Workloads, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "workloads"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves workloads by IP address.
    pub async fn get_workloads_by_ip(&self, ip: &str) -> Result<Workloads, Error> {
        let url = self.build_url(&["workloads", ip])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves transport rules for a service.
    pub async fn get_transport_rules(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<TransportRules, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "transportRules"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Requests external credentials for a provider and domain.
    pub async fn post_external_credentials(
        &self,
        provider: &str,
        domain: &str,
        request: &ExternalCredentialsRequest,
    ) -> Result<ExternalCredentialsResponse, Error> {
        let url = self.build_url(&["external", provider, "domain", domain, "creds"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
