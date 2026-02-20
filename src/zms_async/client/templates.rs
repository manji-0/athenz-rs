use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{
    DomainTemplate, DomainTemplateDetailsList, DomainTemplateList, ServerTemplateList, Template,
};
use crate::zms::common;

impl ZmsAsyncClient {
    /// Applies one or more solution templates to a domain.
    pub async fn put_domain_template(
        &self,
        domain: &str,
        domain_template: &DomainTemplate,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "template"])?;
        let mut req = self.http.put(url).json(domain_template);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Applies a specific solution template to a domain.
    pub async fn put_domain_template_ext(
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
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Lists solution templates applied to a domain.
    pub async fn get_domain_template_list(
        &self,
        domain: &str,
    ) -> Result<DomainTemplateList, Error> {
        let url = self.build_url(&["domain", domain, "template"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Removes a specific solution template from a domain.
    pub async fn delete_domain_template(
        &self,
        domain: &str,
        template: &str,
        audit_ref: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.build_url(&["domain", domain, "template", template])?;
        let mut req = self.http.delete(url);
        req = self.apply_auth(req)?;
        req = common::apply_audit_headers(req, audit_ref, None);
        let resp = req.send().await?;
        self.expect_no_content(resp).await
    }

    /// Lists solution templates defined in ZMS.
    pub async fn get_server_template_list(&self) -> Result<ServerTemplateList, Error> {
        let url = self.build_url(&["template"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves a solution template definition.
    pub async fn get_template(&self, template: &str) -> Result<Template, Error> {
        let url = self.build_url(&["template", template])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists template metadata details for a domain.
    pub async fn get_domain_template_details(
        &self,
        domain: &str,
    ) -> Result<DomainTemplateDetailsList, Error> {
        let url = self.build_url(&["domain", domain, "templatedetails"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Lists template metadata details available in ZMS.
    pub async fn get_server_template_details_list(
        &self,
    ) -> Result<DomainTemplateDetailsList, Error> {
        let url = self.build_url(&["templatedetails"])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
