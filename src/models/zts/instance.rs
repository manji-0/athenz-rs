use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::jwk::AthenzJwkConfig;
use super::ssh::SSHCertRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRegisterInformation {
    pub provider: String,
    pub domain: String,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_request: Option<SSHCertRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_cnames: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub athenz_jwk: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub athenz_jwk_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_spiffe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_spiffe_subject: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_key_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRefreshInformation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_request: Option<SSHCertRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_cnames: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub athenz_jwk: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub athenz_jwk_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRefreshRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRefreshIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_bundle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_certificate_signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRegisterToken {
    pub provider: String,
    pub domain: String,
    pub service: String,
    pub attestation_data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceConfirmation {
    pub provider: String,
    pub domain: String,
    pub service: String,
    pub attestation_data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceIdentity {
    pub provider: String,
    pub name: String,
    pub instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_certificate_signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_certificate_signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub athenz_jwk: Option<AthenzJwkConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRegisterResponse {
    pub identity: InstanceIdentity,
    pub location: Option<String>,
}
