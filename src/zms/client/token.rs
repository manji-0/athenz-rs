use super::ZmsClient;
use crate::error::Error;
use crate::models::{ServicePrincipal, UserToken};
use crate::zms::common;
use reqwest::StatusCode;

impl ZmsClient {
    /// Retrieves a user token for the specified user.
    pub fn get_user_token(
        &self,
        user_name: &str,
        service_names: Option<&str>,
        header: Option<bool>,
    ) -> Result<UserToken, Error> {
        let url = self.build_url(&["user", user_name, "token"])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(service_names) = service_names {
            params.push(("services", service_names.to_string()));
        }
        if let Some(header) = header {
            params.push(("header", header.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Handles CORS preflight requests for the user token endpoint.
    pub fn options_user_token(
        &self,
        user_name: &str,
        service_names: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["user", user_name, "token"])?;
        let mut req = self.http.request(reqwest::Method::OPTIONS, url);
        let mut params = Vec::new();
        if let Some(service_names) = service_names {
            params.push(("services", service_names.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        match resp.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(()),
            _ => self.parse_error(resp),
        }
    }

    /// Returns the calling service principal details.
    pub fn get_service_principal(&self) -> Result<ServicePrincipal, Error> {
        let url = self.build_url(&["principal"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
