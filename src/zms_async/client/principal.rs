use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::PrincipalState;
use crate::zms::common;

impl ZmsAsyncClient {
    /// Updates a principal state entry.
    pub async fn put_principal_state(
        &self,
        principal_name: &str,
        principal_state: &PrincipalState,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["principal", principal_name, "state"])?;
        let mut req = self.http.put(url).json(principal_state);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
