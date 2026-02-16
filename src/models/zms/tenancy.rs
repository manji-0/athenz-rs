use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenancy {
    pub domain: String,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_admin_role: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRoleAction {
    pub role: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantResourceGroupRoles {
    pub domain: String,
    pub service: String,
    pub tenant: String,
    pub roles: Vec<TenantRoleAction>,
    pub resource_group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResourceGroupRoles {
    pub domain: String,
    pub service: String,
    pub tenant: String,
    pub roles: Vec<TenantRoleAction>,
    pub resource_group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_admin_role: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_principal_member: Option<bool>,
}
