use super::ZtsClient;
use crate::error::Error;
use crate::models::TenantDomains;
use crate::zts::common;

impl ZtsClient {
    /// Lists tenant domains a user can access for the given provider domain.
    pub fn get_tenant_domains(
        &self,
        provider_domain_name: &str,
        user_name: &str,
        role_name: Option<&str>,
        service_name: Option<&str>,
    ) -> Result<TenantDomains, Error> {
        let url = self.build_url(&["providerdomain", provider_domain_name, "user", user_name])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(role_name) = role_name {
            params.push(("roleName", role_name.to_string()));
        }
        if let Some(service_name) = service_name {
            params.push(("serviceName", service_name.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
