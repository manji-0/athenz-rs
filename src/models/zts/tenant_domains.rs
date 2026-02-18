use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantDomains {
    #[serde(default)]
    pub tenant_domain_names: Vec<String>,
}
