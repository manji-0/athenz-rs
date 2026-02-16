use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostServices {
    pub host: String,
    #[serde(default)]
    pub names: Vec<String>,
}
