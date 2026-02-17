use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{Entity, EntityList};
use crate::zms::common;

impl ZmsAsyncClient {
    /// Retrieves an entity from a domain.
    pub async fn get_entity(&self, domain: &str, entity: &str) -> Result<Entity, Error> {
        let url = self.build_url(&["domain", domain, "entity", entity])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Creates or updates an entity in a domain.
    pub async fn put_entity(
        &self,
        domain: &str,
        entity: &str,
        detail: &Entity,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "entity", entity])?;
        let mut req = self.http.put(url).json(detail);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes an entity from a domain.
    pub async fn delete_entity(
        &self,
        domain: &str,
        entity: &str,
        audit_ref: Option<&str>,
        resource_owner: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "entity", entity])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, resource_owner);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Lists entity names within a domain.
    pub async fn get_entity_list(&self, domain: &str) -> Result<EntityList, Error> {
        let url = self.build_url(&["domain", domain, "entity"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
