use super::ZtsAsyncClient;
use crate::error::Error;
use crate::models::{
    InstanceIdentity, InstanceRefreshInformation, InstanceRegisterInformation,
    InstanceRegisterResponse, InstanceRegisterToken,
};
use reqwest::StatusCode;

impl ZtsAsyncClient {
    pub async fn register_instance(
        &self,
        info: &InstanceRegisterInformation,
    ) -> Result<InstanceRegisterResponse, Error> {
        let url = self.build_url(&["instance"])?;
        let mut req = self.http.post(url).json(info);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::CREATED => {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string());
                let identity = resp.json::<InstanceIdentity>().await?;
                Ok(InstanceRegisterResponse { identity, location })
            }
            _ => self.parse_error(resp).await,
        }
    }

    pub async fn refresh_instance(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
        info: &InstanceRefreshInformation,
    ) -> Result<InstanceIdentity, Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id])?;
        let mut req = self.http.post(url).json(info);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn get_instance_register_token(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
    ) -> Result<InstanceRegisterToken, Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id, "token"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    pub async fn delete_instance(
        &self,
        provider: &str,
        domain: &str,
        service: &str,
        instance_id: &str,
    ) -> Result<(), Error> {
        let url = self.build_url(&["instance", provider, domain, service, instance_id])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }
}
