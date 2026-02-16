use super::ZmsClient;
use crate::error::Error;
use crate::models::Quota;
use crate::zms::common;

impl ZmsClient {
    /// Retrieves the quota configured for the specified domain.
    pub fn get_quota(&self, name: &str) -> Result<Quota, Error> {
        let url = self.build_url(&["domain", name, "quota"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Updates the quota configured for the specified domain.
    pub fn put_quota(
        &self,
        name: &str,
        quota: &Quota,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "quota"])?;
        let mut req = self.http.put(url).json(quota);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Deletes the quota configured for the specified domain.
    pub fn delete_quota(&self, name: &str, audit_ref: Option<&str>) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "quota"])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }
}
