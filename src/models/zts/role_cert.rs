use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RoleCertificate {
    pub x509_certificate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleCertificateRequest {
    pub csr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_for_principal: Option<String>,
    pub expiry_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cert_not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cert_not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RoleAccess {
    pub roles: Vec<String>,
}
