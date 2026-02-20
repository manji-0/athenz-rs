use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{
    AuthHistoryDependencies, Domain, DomainDataCheck, DomainList, DomainMeta,
    DomainMetaStoreValidValuesList, ExpiredMembers, ResourceDomainOwnership, SubDomain,
    TopLevelDomain, UserDomain,
};
use crate::zms::common;
use crate::zms::DomainListOptions;
use reqwest::StatusCode;

impl ZmsAsyncClient {
    /// Retrieves a domain by name.
    pub async fn get_domain(&self, domain: &str) -> Result<Domain, Error> {
        let url = self.build_url(&["domain", domain])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves domain data check results by domain name.
    pub async fn get_domain_data_check(&self, domain: &str) -> Result<DomainDataCheck, Error> {
        let url = self.build_url(&["domain", domain, "check"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists domains using the provided query options.
    pub async fn get_domain_list(
        &self,
        options: &DomainListOptions,
    ) -> Result<Option<DomainList>, Error> {
        let url = self.build_url(&["domain"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        if let Some(ref modified_since) = options.modified_since {
            req = req.header("If-Modified-Since", modified_since);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json::<DomainList>().await.map_err(Error::from)?)),
            StatusCode::NOT_MODIFIED => Ok(None),
            _ => self.parse_error(resp).await,
        }
    }

    /// Creates a top-level domain.
    pub async fn post_top_level_domain(
        &self,
        detail: &TopLevelDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["domain"])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Creates a sub-domain under the given parent.
    pub async fn post_sub_domain(
        &self,
        parent: &str,
        detail: &SubDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["subdomain", parent])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Creates a user domain for the provided name.
    pub async fn post_user_domain(
        &self,
        name: &str,
        detail: &UserDomain,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<Domain, Error> {
        let url = self.build_url(&["userdomain", name])?;
        let mut req = self.http.post(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Deletes a top-level domain.
    pub async fn delete_top_level_domain(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes a sub-domain under the given parent.
    pub async fn delete_sub_domain(
        &self,
        parent: &str,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["subdomain", parent, name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes a user domain.
    pub async fn delete_user_domain(
        &self,
        name: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["userdomain", name])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Updates domain metadata.
    pub async fn put_domain_meta(
        &self,
        name: &str,
        meta: &DomainMeta,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "meta"])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Updates domain system metadata for a specific attribute.
    pub async fn put_domain_system_meta(
        &self,
        name: &str,
        attribute: &str,
        meta: &DomainMeta,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "meta", "system", attribute])?;
        let mut req = self.http.put(url).json(meta);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Lists valid values for a domain meta-store attribute.
    pub async fn get_domain_meta_store(
        &self,
        attribute_name: &str,
        user_name: Option<&str>,
    ) -> Result<DomainMetaStoreValidValuesList, Error> {
        let url = self.build_url(&["domain", "metastore"])?;
        let mut req = self.http.get(url);
        let mut query = vec![("attribute", attribute_name.to_string())];
        if let Some(user_name) = user_name {
            query.push(("user", user_name.to_string()));
        }
        req = common::apply_query_params(req, query);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves authorization/token dependency history for a domain.
    pub async fn get_domain_auth_history(
        &self,
        domain_name: &str,
    ) -> Result<AuthHistoryDependencies, Error> {
        let url = self.build_url(&["domain", domain_name, "history", "auth"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Deletes expired members and optionally returns deleted entries.
    pub async fn delete_expired_members(
        &self,
        purge_resources: Option<i32>,
        audit_ref: Option<&str>,
        return_obj: Option<bool>,
    ) -> Result<Option<ExpiredMembers>, Error> {
        let url = self.build_url(&["expired-members"])?;
        let mut req = self.http.delete(url);
        let mut query = Vec::new();
        if let Some(purge_resources) = purge_resources {
            query.push(("purgeResources", purge_resources.to_string()));
        }
        req = common::apply_query_params(req, query);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        if let Some(return_obj) = return_obj {
            req = req.header("Athenz-Return-Object", return_obj.to_string());
        }
        let resp = req.send().await?;
        self.expect_no_content_or_json(resp).await
    }

    /// Sets resource ownership for a domain.
    pub async fn put_domain_ownership(
        &self,
        name: &str,
        ownership: &ResourceDomainOwnership,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "ownership"])?;
        let mut req = self.http.put(url).json(ownership);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
