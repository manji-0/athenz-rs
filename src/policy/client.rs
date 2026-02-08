use crate::error::Error;
use crate::models::{DomainSignedPolicyData, JWSPolicyData, PolicyData, SignedPolicyRequest};
use crate::zts::ZtsClient;
#[cfg(feature = "async-validate")]
use crate::zts_async::ZtsAsyncClient;
use std::time::Duration;

use super::validator::{validate_jws_policy_data, validate_signed_policy_data};
#[cfg(feature = "async-validate")]
use super::validator::{validate_jws_policy_data_async, validate_signed_policy_data_async};

#[derive(Debug, Clone)]
pub struct PolicyFetchResponse<T> {
    pub data: Option<T>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyValidatorConfig {
    pub sys_auth_domain: String,
    pub zts_service: String,
    pub zms_service: String,
    pub check_zms_signature: bool,
    pub expiry_offset: Duration,
}

impl Default for PolicyValidatorConfig {
    fn default() -> Self {
        Self {
            sys_auth_domain: "sys.auth".to_string(),
            zts_service: "zts".to_string(),
            zms_service: "zms".to_string(),
            check_zms_signature: false,
            expiry_offset: Duration::from_secs(0),
        }
    }
}

pub struct PolicyClient {
    zts: ZtsClient,
    config: PolicyValidatorConfig,
}

impl PolicyClient {
    pub fn new(zts: ZtsClient) -> Self {
        Self {
            zts,
            config: PolicyValidatorConfig::default(),
        }
    }

    pub fn config_mut(&mut self) -> &mut PolicyValidatorConfig {
        &mut self.config
    }

    pub fn fetch_signed_policy_data(
        &self,
        domain: &str,
        etag: Option<&str>,
    ) -> Result<PolicyFetchResponse<DomainSignedPolicyData>, Error> {
        let response = self.zts.get_domain_signed_policy_data(domain, etag)?;
        Ok(PolicyFetchResponse {
            data: response.data,
            etag: response.etag,
        })
    }

    pub fn fetch_jws_policy_data(
        &self,
        domain: &str,
        request: &SignedPolicyRequest,
        etag: Option<&str>,
    ) -> Result<PolicyFetchResponse<JWSPolicyData>, Error> {
        let response = self
            .zts
            .post_domain_signed_policy_data_jws(domain, request, etag)?;
        Ok(PolicyFetchResponse {
            data: response.data,
            etag: response.etag,
        })
    }

    pub fn validate_signed_policy_data(
        &self,
        data: &DomainSignedPolicyData,
    ) -> Result<PolicyData, Error> {
        validate_signed_policy_data(data, &self.zts, &self.config)
    }

    pub fn validate_jws_policy_data(&self, data: &JWSPolicyData) -> Result<PolicyData, Error> {
        validate_jws_policy_data(data, &self.zts, &self.config)
    }
}

#[cfg(feature = "async-validate")]
pub struct PolicyClientAsync {
    zts: ZtsAsyncClient,
    config: PolicyValidatorConfig,
}

#[cfg(feature = "async-validate")]
impl PolicyClientAsync {
    pub fn new(zts: ZtsAsyncClient) -> Self {
        Self {
            zts,
            config: PolicyValidatorConfig::default(),
        }
    }

    pub fn config_mut(&mut self) -> &mut PolicyValidatorConfig {
        &mut self.config
    }

    pub async fn fetch_signed_policy_data(
        &self,
        domain: &str,
        etag: Option<&str>,
    ) -> Result<PolicyFetchResponse<DomainSignedPolicyData>, Error> {
        let response = self.zts.get_domain_signed_policy_data(domain, etag).await?;
        Ok(PolicyFetchResponse {
            data: response.data,
            etag: response.etag,
        })
    }

    pub async fn fetch_jws_policy_data(
        &self,
        domain: &str,
        request: &SignedPolicyRequest,
        etag: Option<&str>,
    ) -> Result<PolicyFetchResponse<JWSPolicyData>, Error> {
        let response = self
            .zts
            .post_domain_signed_policy_data_jws(domain, request, etag)
            .await?;
        Ok(PolicyFetchResponse {
            data: response.data,
            etag: response.etag,
        })
    }

    pub async fn validate_signed_policy_data(
        &self,
        data: &DomainSignedPolicyData,
    ) -> Result<PolicyData, Error> {
        validate_signed_policy_data_async(data, &self.zts, &self.config).await
    }

    pub async fn validate_jws_policy_data(
        &self,
        data: &JWSPolicyData,
    ) -> Result<PolicyData, Error> {
        validate_jws_policy_data_async(data, &self.zts, &self.config).await
    }
}
