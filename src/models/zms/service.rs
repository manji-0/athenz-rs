use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::super::common::PublicKeyEntry;

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
