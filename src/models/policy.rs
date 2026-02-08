use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::zms::Policy;

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
