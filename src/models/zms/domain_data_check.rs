use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DanglingPolicy {
    pub policy_name: String,
    pub role_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainDataCheck {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling_roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling_policies: Option<Vec<DanglingPolicy>>,
    pub policy_count: i32,
    pub assertion_count: i32,
    pub role_wild_card_count: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers_without_trust: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenants_without_assume_role: Option<Vec<String>>,
}
