use super::{ConditionalResponse, ZtsAsyncClient};
use crate::error::Error;
use crate::models::{DomainSignedPolicyData, JWSPolicyData, SignedPolicyRequest};

impl ZtsAsyncClient {
    pub async fn get_domain_signed_policy_data(
        &self,
        domain: &str,
        matching_tag: Option<&str>,
    ) -> Result<ConditionalResponse<DomainSignedPolicyData>, Error> {
        let url = self.build_url(&["domain", domain, "signed_policy_data"])?;
        let mut req = self.http.get(url);
        if let Some(tag) = matching_tag {
            req = req.header("If-None-Match", tag);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_conditional_json(resp).await
    }

    pub async fn post_domain_signed_policy_data_jws(
        &self,
        domain: &str,
        request: &SignedPolicyRequest,
        matching_tag: Option<&str>,
    ) -> Result<ConditionalResponse<JWSPolicyData>, Error> {
        let url = self.build_url(&["domain", domain, "policy", "signed"])?;
        let mut req = self.http.post(url).json(request);
        if let Some(tag) = matching_tag {
            req = req.header("If-None-Match", tag);
        }
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_conditional_json(resp).await
    }
}
