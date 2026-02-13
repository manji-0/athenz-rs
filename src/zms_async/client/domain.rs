use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{Domain, DomainList, DomainMeta, SubDomain, TopLevelDomain, UserDomain};
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
}
