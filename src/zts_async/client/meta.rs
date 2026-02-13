use super::ZtsAsyncClient;
use crate::error::Error;
use crate::models::{Info, RdlSchema, Status};

impl ZtsAsyncClient {
    /// Retrieves the service status.
    pub async fn get_status(&self) -> Result<Status, Error> {
        let url = self.build_url(&["status"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves service info.
    pub async fn get_info(&self) -> Result<Info, Error> {
        let url = self.build_url(&["sys", "info"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves the service RDL schema.
    pub async fn get_schema(&self) -> Result<RdlSchema, Error> {
        let url = self.build_url(&["schema"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
