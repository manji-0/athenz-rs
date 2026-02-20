use super::ZmsClient;
use crate::error::Error;
use crate::models::{
    DomainTemplate, DomainTemplateDetailsList, DomainTemplateList, ServerTemplateList, Template,
};
use crate::zms::common;

impl ZmsClient {
    /// Applies one or more solution templates to a domain.
    pub fn put_domain_template(
        &self,
        domain: &str,
        domain_template: &DomainTemplate,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "template"])?;
        let mut req = self.http.put(url).json(domain_template);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Applies a specific solution template to a domain.
    pub fn put_domain_template_ext(
        &self,
        domain: &str,
        template: &str,
        domain_template: &DomainTemplate,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "template", template])?;
        let mut req = self.http.put(url).json(domain_template);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

    /// Lists solution templates applied to a domain.
    pub fn get_domain_template_list(&self, domain: &str) -> Result<DomainTemplateList, Error> {
        let url = self.build_url(&["domain", domain, "template"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send()?;
        self.expect_ok_json(resp)
    }

    /// Removes a specific solution template from a domain.
    pub fn delete_domain_template(
        &self,
        domain: &str,
        template: &str,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "template", template])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send()?;
        self.expect_no_content(resp)
    }

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
