use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
#[serde(rename_all = "camelCase")]
pub struct MemberRole {
    pub role_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reminder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_role_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoleMember {
    pub member_name: String,
    pub member_roles: Vec<MemberRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoleMembers {
    pub domain_name: String,
    pub members: Vec<DomainRoleMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoleMembership {
    pub domain_role_members_list: Vec<DomainRoleMembers>,
}
