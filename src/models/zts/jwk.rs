use serde::{Deserialize, Serialize};

use super::super::common::JwkList;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AthenzJwkConfig {
    pub zms: JwkList,
    pub zts: JwkList,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}
