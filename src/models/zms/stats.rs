use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub subdomain: i32,
    pub role: i32,
    pub role_member: i32,
    pub policy: i32,
    pub assertion: i32,
    pub entity: i32,
    pub service: i32,
    pub service_host: i32,
    pub public_key: i32,
    pub group: i32,
    pub group_member: i32,
}
