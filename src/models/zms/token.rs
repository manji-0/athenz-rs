use serde::{Deserialize, Serialize};

/// A user token generated from the user's authenticated credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserToken {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

/// A service principal object identifying a service and its token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipal {
    pub domain: String,
    pub service: String,
    pub token: String,
}
