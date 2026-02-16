use super::ZmsAsyncClient;
use crate::error::Error;
use crate::models::{JWSDomain, SignedDomains};
use crate::zms::common;
use crate::zms::SignedDomainsOptions;

impl ZmsAsyncClient {
    /// Retrieves the list of modified domains, optionally using conditional ETag matching.
    pub async fn get_modified_domains(
        &self,
        options: &SignedDomainsOptions,
        matching_tag: Option<&str>,
    ) -> Result<crate::zts::ConditionalResponse<SignedDomains>, Error> {
        let url = self.build_url(&["sys", "modified_domains"])?;
        let mut req = self.http.get(url);
        req = common::apply_query_params(req, options.to_query_pairs());
        if let Some(tag) = matching_tag {
            req = req.header("If-None-Match", tag);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_conditional_json(resp).await
    }

    /// Retrieves a signed domain payload using JWS JSON serialization.
    pub async fn get_signed_domain(
        &self,
        name: &str,
        signature_p1363_format: Option<bool>,
        matching_tag: Option<&str>,
    ) -> Result<crate::zts::ConditionalResponse<JWSDomain>, Error> {
        let url = self.build_url(&["domain", name, "signed"])?;
        let mut req = self.http.get(url);
        if let Some(signature_p1363_format) = signature_p1363_format {
            req = req.query(&[("signaturep1363format", signature_p1363_format.to_string())]);
        }
        if let Some(tag) = matching_tag {
            req = req.header("If-None-Match", tag);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_conditional_json(resp).await
    }
}
