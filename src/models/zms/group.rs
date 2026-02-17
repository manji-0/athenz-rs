use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainGroupMember {
    pub member_name: String,
    pub member_groups: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainGroupMembers {
    pub domain_name: String,
    pub members: Vec<DomainGroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainGroupMembership {
    pub domain_group_members_list: Vec<DomainGroupMembers>,
}
