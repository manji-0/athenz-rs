use super::ZmsClient;
use crate::error::Error;
use crate::models::{ZmsAccess, ZmsResourceAccessList};
use crate::zms::common;

impl ZmsClient {
    /// Checks whether the specified action is allowed on the given resource.
    pub fn get_access(
        &self,
        action: &str,
        resource: &str,
        domain: Option<&str>,
        principal: Option<&str>,
    ) -> Result<ZmsAccess, Error> {
        let url = self.build_url(&["access", action, resource])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(domain) = domain {
            params.push(("domain", domain.to_string()));
        }
        if let Some(principal) = principal {
            params.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Checks access using the extended endpoint with `resource` in query.
    pub fn get_access_ext(
        &self,
        action: &str,
        resource: &str,
        domain: Option<&str>,
        principal: Option<&str>,
    ) -> Result<ZmsAccess, Error> {
        let url = self.build_url(&["access", action])?;
        let mut req = self.http.get(url);
        let mut params = vec![("resource", resource.to_string())];
        if let Some(domain) = domain {
            params.push(("domain", domain.to_string()));
        }
        if let Some(principal) = principal {
            params.push(("principal", principal.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Lists accessible resources for a principal.
    pub fn get_resource_access_list(
        &self,
        principal: &str,
        action: Option<&str>,
        filter: Option<&str>,
    ) -> Result<ZmsResourceAccessList, Error> {
        let url = self.build_url(&["resource"])?;
        let mut req = self.http.get(url);
        let mut params = vec![("principal", principal.to_string())];
        if let Some(action) = action {
            params.push(("action", action.to_string()));
        }
        if let Some(filter) = filter {
            params.push(("filter", filter.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
