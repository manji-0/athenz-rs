use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainMetricType {
    AccessAllowed,
    AccessAllowedDeny,
    AccessAllowedDenyNoMatch,
    AccessAllowedAllow,
    AccessAllowedError,
    AccessAllowedTokenInvalid,
    #[serde(rename = "ACCESS_Allowed_TOKEN_EXPIRED")]
    AccessAllowedTokenExpired,
    AccessAllowedDomainNotFound,
    AccessAllowedDomainMismatch,
    AccessAllowedDomainExpired,
    AccessAllowedDomainEmpty,
    AccessAllowedTokenCacheFailure,
    AccessAllowedTokenCacheNotFound,
    AccessAllowedTokenCacheSuccess,
    AccessAllowedTokenValidate,
    LoadFileFail,
    LoadFileGood,
    LoadDomainGood,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetric {
    pub metric_type: DomainMetricType,
    pub metric_val: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetrics {
    pub domain_name: String,
    pub metric_list: Vec<DomainMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDomainOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DomainMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ypm_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_dns_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_cert_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_cert_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_subscription: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_project_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_purge_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceDomainOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_call: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_delete_tenant_assume_role_assertions: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopLevelDomain {
    pub name: String,
    pub admin_users: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubDomain {
    pub parent: String,
    #[serde(default, flatten)]
    pub domain: TopLevelDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDomain {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}
