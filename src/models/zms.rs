use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::common::PublicKeyEntry;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAuditLog {
    pub member: String,
    pub admin: String,
    pub created: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleMember {
    pub member_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reminder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRoleOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RoleMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_serve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_review_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_review_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_review_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_protection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reviewed_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_members: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceRoleOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_domain_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_members: Option<Vec<RoleMember>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<Vec<RoleAuditLog>>,
    #[serde(default, flatten)]
    pub meta: RoleMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Roles {
    pub list: Vec<Role>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub member_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_member: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reminder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssertionEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssertionConditionOperator {
    Equals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionConditionData {
    pub operator: AssertionConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
    pub conditions_map: HashMap<String, AssertionConditionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionConditions {
    pub conditions_list: Vec<AssertionCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    pub role: String,
    pub resource: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<AssertionEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<AssertionConditions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourcePolicyOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourcePolicyOwnership>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policies {
    pub list: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceServiceIdentityOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_keys_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentity {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKeyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceServiceIdentityOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creds: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentities {
    pub list: Vec<ServiceIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_match_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentityList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAuditLog {
    pub member: String,
    pub admin: String,
    pub created: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembership {
    pub member_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_member: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGroupOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_serve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_protection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reviewed_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_members: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceGroupOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_domain_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<GroupMember>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<Vec<GroupAuditLog>>,
    #[serde(default, flatten)]
    pub meta: GroupMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Groups {
    pub list: Vec<Group>,
}
