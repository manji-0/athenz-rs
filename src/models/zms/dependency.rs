use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependentService {
    pub service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependentServiceResourceGroup {
    pub service: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependentServiceResourceGroupList {
    pub service_and_resource_groups: Vec<DependentServiceResourceGroup>,
}
