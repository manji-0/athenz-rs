use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::Stats;

impl ZmsAsyncClient {
    /// Retrieves statistics for the specified domain.
    pub async fn get_domain_stats(&self, name: &str) -> Result<Stats, Error> {
        let url = self.build_url(&["domain", name, "stats"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves system-wide statistics.
    pub async fn get_system_stats(&self) -> Result<Stats, Error> {
        let url = self.build_url(&["sys", "stats"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
