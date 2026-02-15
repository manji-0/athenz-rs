use super::ZmsClient;
use crate::error::Error;
use crate::models::Stats;

impl ZmsClient {
    /// Retrieves statistics for the specified domain.
    pub fn get_domain_stats(&self, name: &str) -> Result<Stats, Error> {
        let url = self.build_url(&["domain", name, "stats"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves system-wide statistics.
    pub fn get_system_stats(&self) -> Result<Stats, Error> {
        let url = self.build_url(&["sys", "stats"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
