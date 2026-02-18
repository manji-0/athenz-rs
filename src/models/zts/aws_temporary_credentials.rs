use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AWSTemporaryCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}
