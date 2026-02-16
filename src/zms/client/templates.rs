use super::ZmsClient;
use crate::error::Error;
use crate::models::{DomainTemplateDetailsList, ServerTemplateList, Template};

impl ZmsClient {
    /// Lists solution templates defined in ZMS.
    pub fn get_server_template_list(&self) -> Result<ServerTemplateList, Error> {
        let url = self.build_url(&["template"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Retrieves a solution template definition.
    pub fn get_template(&self, template: &str) -> Result<Template, Error> {
        let url = self.build_url(&["template", template])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Lists template metadata details for a domain.
    pub fn get_domain_template_details(
        &self,
        domain: &str,
    ) -> Result<DomainTemplateDetailsList, Error> {
        let url = self.build_url(&["domain", domain, "templatedetails"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Lists template metadata details available in ZMS.
    pub fn get_server_template_details_list(&self) -> Result<DomainTemplateDetailsList, Error> {
        let url = self.build_url(&["templatedetails"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }
}
