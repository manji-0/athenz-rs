use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{
    CredsEntry, PublicKeyEntry, ResourceServiceIdentityOwnership, ServiceIdentities,
    ServiceIdentity, ServiceIdentityList, ServiceIdentitySystemMeta,
};
use crate::zms::common;
use crate::zms::{ServiceIdentitiesQueryOptions, ServiceListOptions, ServiceSearchOptions};

impl ZmsAsyncClient {
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

    /// Creates or updates a service identity.
    pub async fn put_service_identity(
        &self,
        domain: &str,
        service: &str,
        detail: &ServiceIdentity,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
        resource_owner: Option<&str>,
    ) -> Result<Option<ServiceIdentity>, Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Updates service identity system metadata for a specific attribute.
    pub async fn put_service_identity_system_meta(
        &self,
        domain: &str,
        service: &str,
        attribute: &str,
        meta: &ServiceIdentitySystemMeta,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&[
            "domain", domain, "service", service, "meta", "system", attribute,
        ])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Sets resource ownership for a service identity.
    pub async fn put_service_identity_ownership(
        &self,
        domain: &str,
        service: &str,
        ownership: &ResourceServiceIdentityOwnership,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service, "ownership"])?;
        let mut req = self.http.put(url).json(ownership);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes a service identity.
    pub async fn delete_service_identity(
        &self,
        domain: &str,
        service: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Lists service identities within a domain.
    pub async fn get_service_identities(
        &self,
        domain: &str,
        options: &ServiceIdentitiesQueryOptions,
    ) -> Result<ServiceIdentities, Error> {
        let url = self.build_url(&["domain", domain, "services"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists service identity names within a domain.
    pub async fn get_service_identity_list(
        &self,
        domain: &str,
        options: &ServiceListOptions,
    ) -> Result<ServiceIdentityList, Error> {
        let url = self.build_url(&["domain", domain, "service"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Searches services across domains by service name.
    pub async fn search_service_identities(
        &self,
        service_name: &str,
        options: &ServiceSearchOptions,
    ) -> Result<ServiceIdentities, Error> {
        let url = self.build_url(&["service", service_name])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves a public key entry for a service.
    pub async fn get_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
    ) -> Result<PublicKeyEntry, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Creates or updates a public key entry for a service.
    pub async fn put_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
        entry: &PublicKeyEntry,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.put(url).json(entry);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes a public key entry for a service.
    pub async fn delete_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Creates or updates credentials for a service.
    pub async fn put_service_creds_entry(
        &self,
        domain: &str,
        service: &str,
        cred_entry: &CredsEntry,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "service", service, "creds"])?;
        let mut req = self.http.put(url).json(cred_entry);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
