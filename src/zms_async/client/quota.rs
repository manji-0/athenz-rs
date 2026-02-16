use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::Quota;
use crate::zms::common;

impl ZmsAsyncClient {
    /// Retrieves the quota configured for the specified domain.
    pub async fn get_quota(&self, name: &str) -> Result<Quota, Error> {
        let url = self.build_url(&["domain", name, "quota"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Updates the quota configured for the specified domain.
    pub async fn put_quota(
        &self,
        name: &str,
        quota: &Quota,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "quota"])?;
        let mut req = self.http.put(url).json(quota);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Deletes the quota configured for the specified domain.
    pub async fn delete_quota(&self, name: &str, audit_ref: Option<&str>) -> Result<(), Error> {
        let url = self.build_url(&["domain", name, "quota"])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
