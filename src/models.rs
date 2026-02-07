use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
pub struct PublicKeyEntry {
    pub key: String,
    pub id: String,
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
pub struct Access {
    pub granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAccess {
    pub granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleToken {
    pub token: String,
    pub expiry_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantDomains {
    pub tenant_domain_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AWSTemporaryCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceRefreshRequest {
    pub csr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub name: String,
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
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwkList {
    pub keys: Vec<Jwk>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainMetricType {
    AccessAllowed,
    AccessAllowedDeny,
    AccessAllowedDenyNoMatch,
    AccessAllowedAllow,
    AccessAllowedError,
    AccessAllowedTokenInvalid,
    #[serde(rename = "ACCESS_Allowed_TOKEN_EXPIRED")]
    AccessAllowedTokenExpired,
    AccessAllowedDomainNotFound,
    AccessAllowedDomainMismatch,
    AccessAllowedDomainExpired,
    AccessAllowedDomainEmpty,
    AccessAllowedTokenCacheFailure,
    AccessAllowedTokenCacheNotFound,
    AccessAllowedTokenCacheSuccess,
    AccessAllowedTokenValidate,
    LoadFileFail,
    LoadFileGood,
    LoadDomainGood,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetric {
    pub metric_type: DomainMetricType,
    pub metric_val: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetrics {
    pub domain_name: String,
    pub metric_list: Vec<DomainMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_jdk_spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdlSchema(pub serde_json::Value);

// --- ZMS (management) models ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDomainOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DomainMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ypm_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_dns_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_cert_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_cert_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_subscription: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_project_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_purge_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceDomainOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_call: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_delete_tenant_assume_role_assertions: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopLevelDomain {
    pub name: String,
    pub admin_users: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubDomain {
    pub parent: String,
    #[serde(default, flatten)]
    pub domain: TopLevelDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDomain {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateMetaData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords_to_replace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Template {
    pub roles: Vec<Role>,
    pub policies: Vec<Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Group>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceIdentity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TemplateMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateList {
    pub template_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainTemplate {
    pub template_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<TemplateParam>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainTemplateList {
    pub template_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerTemplateList {
    pub template_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainTemplateDetailsList {
    pub meta_data: Vec<TemplateMetaData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainMetaStoreValidValuesList {
    pub valid_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entity {
    pub name: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityList {
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAuditLog {
    pub member: String,
    pub admin: String,
    pub created: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleMember {
    pub member_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reminder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRoleOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RoleMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_serve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_expiry_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_review_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_review_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_review_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_protection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reviewed_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_members: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceRoleOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_domain_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RoleSystemMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_members: Option<Vec<RoleMember>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<Vec<RoleAuditLog>>,
    #[serde(default, flatten)]
    pub meta: RoleMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Roles {
    pub list: Vec<Role>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub member_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_member: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reminder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRole {
    pub role_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reminder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_role_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoleMember {
    pub member_name: String,
    pub member_roles: Vec<MemberRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoleMembers {
    pub domain_name: String,
    pub members: Vec<DomainRoleMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRoleMembership {
    pub domain_role_members_list: Vec<DomainRoleMembers>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssertionEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssertionConditionOperator {
    Equals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionConditionData {
    pub operator: AssertionConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
    pub conditions_map: HashMap<String, AssertionConditionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionConditions {
    pub conditions_list: Vec<AssertionCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    pub role: String,
    pub resource: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<AssertionEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<AssertionConditions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourcePolicyOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourcePolicyOwnership>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policies {
    pub list: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyData {
    pub domain: String,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPolicyData {
    pub policy_data: PolicyData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zms_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zms_key_id: Option<String>,
    pub modified: String,
    pub expires: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainSignedPolicyData {
    pub signed_policy_data: SignedPolicyData,
    pub signature: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWSPolicyData {
    pub payload: String,
    #[serde(rename = "protected")]
    pub protected_header: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<HashMap<String, String>>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPolicyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_versions: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_p1363_format: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceServiceIdentityOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_keys_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentity {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKeyEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceServiceIdentityOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creds: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentities {
    pub list: Vec<ServiceIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_match_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentityList {
    pub names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServiceIdentitySystemMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_cert_signer_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAuditLog {
    pub member: String,
    pub admin: String,
    pub created: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_last_notified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembership {
    pub member_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_member: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disabled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGroupOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_serve: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_roles: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authority_expiration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_expiry_days: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_protection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reviewed_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_renew_mins: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_members: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ownership: Option<ResourceGroupOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_domain_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GroupSystemMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<GroupMember>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<Vec<GroupAuditLog>>,
    #[serde(default, flatten)]
    pub meta: GroupMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Groups {
    pub list: Vec<Group>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainGroupMember {
    pub member_name: String,
    pub member_groups: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainGroupMembers {
    pub domain_name: String,
    pub members: Vec<DomainGroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainGroupMembership {
    pub domain_group_members_list: Vec<DomainGroupMembers>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewObject {
    pub domain_name: String,
    pub name: String,
    pub member_expiry_days: i32,
    pub member_review_days: i32,
    pub service_expiry_days: i32,
    pub service_review_days: i32,
    pub group_expiry_days: i32,
    pub group_review_days: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reviewed_date: Option<String>,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewObjects {
    pub list: Vec<ReviewObject>,
}
