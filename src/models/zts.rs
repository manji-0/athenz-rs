use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::common::JwkList;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OidcResponse {
    pub version: i32,
    pub id_token: String,
    pub token_type: String,
    pub success: bool,
    pub expiration_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IntrospectResponse {
    pub active: bool,
    pub ver: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub introspection_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OpenIdConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
}

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
pub struct AthenzJwkConfig {
    pub zms: JwkList,
    pub zts: JwkList,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthorityBundle {
    pub name: String,
    pub certs: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportRule {
    pub end_point: String,
    pub source_port_range: String,
    pub port: i32,
    pub protocol: String,
    pub direction: TransportDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportRules {
    pub ingress_rules: Vec<TransportRule>,
    pub egress_rules: Vec<TransportRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalCredentialsRequest {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalCredentialsResponse {
    pub attributes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}
