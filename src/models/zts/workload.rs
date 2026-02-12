use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<Vec<String>>,
    pub hostname: String,
    pub provider: String,
    pub update_time: String,
    pub cert_expiry_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workloads {
    pub workload_list: Vec<Workload>,
}
