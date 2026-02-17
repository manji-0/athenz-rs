use super::ZmsClient;
use crate::error::Error;
use crate::models::{Entity, EntityList};
use crate::zms::common;

impl ZmsClient {
    /// Retrieves an entity from a domain.
    pub fn get_entity(&self, domain: &str, entity: &str) -> Result<Entity, Error> {
        let url = self.build_url(&["domain", domain, "entity", entity])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Creates or updates an entity in a domain.
    pub fn put_entity(
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
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes an entity from a domain.
    pub fn delete_entity(
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
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Lists entity names within a domain.
    pub fn get_entity_list(&self, domain: &str) -> Result<EntityList, Error> {
        let url = self.build_url(&["domain", domain, "entity"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
