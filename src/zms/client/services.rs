use super::ZmsClient;
use crate::error::Error;
use crate::models::{PublicKeyEntry, ServiceIdentities, ServiceIdentity, ServiceIdentityList};
use crate::zms::common;
use crate::zms::{ServiceIdentitiesQueryOptions, ServiceListOptions};

impl ZmsClient {
    pub fn get_service_identity(
        &self,
        domain: &str,
        service: &str,
    ) -> Result<ServiceIdentity, Error> {
        let url = self.build_url(&["domain", domain, "service", service])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_service_identity(
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
        let resp = req.send()?;
        self.expect_no_content_or_json(resp)
    }

    pub fn delete_service_identity(
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
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn get_service_identities(
        &self,
        domain: &str,
        options: &ServiceIdentitiesQueryOptions,
    ) -> Result<ServiceIdentities, Error> {
        let url = self.build_url(&["domain", domain, "services"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_service_identity_list(
        &self,
        domain: &str,
        options: &ServiceListOptions,
    ) -> Result<ServiceIdentityList, Error> {
        let url = self.build_url(&["domain", domain, "service"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
    ) -> Result<PublicKeyEntry, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn put_public_key_entry(
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
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    pub fn delete_public_key_entry(
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
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
