use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHCertRequestData {
    pub principals: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touch_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pub_key_algo: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHCertRequestMeta {
    pub requestor: String,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_client_version: Option<String>,
    pub cert_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id_principals: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub athenz_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cert_valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_cert_valid_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trans_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHCertRequest {
    pub cert_request_data: SSHCertRequestData,
    pub cert_request_meta: SSHCertRequestMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHCertificate {
    pub certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSHCertificates {
    pub certificates: Vec<SSHCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_signer: Option<String>,
}
