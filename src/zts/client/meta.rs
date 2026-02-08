use super::ZtsClient;
use crate::error::Error;
use crate::models::{Info, RdlSchema, Status};

impl ZtsClient {
    pub fn get_status(&self) -> Result<Status, Error> {
        let url = self.build_url(&["status"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_info(&self) -> Result<Info, Error> {
        let url = self.build_url(&["sys", "info"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    pub fn get_schema(&self) -> Result<RdlSchema, Error> {
        let url = self.build_url(&["schema"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
