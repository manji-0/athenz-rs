use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::{DomainMeta, Group, Policy, Role, ServiceIdentity};

/// Policies plus owning domain name used for signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainPolicies {
    pub domain: String,
    pub policies: Vec<Policy>,
}

/// Signed policy bundle for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPolicies {
    pub contents: DomainPolicies,
    pub signature: String,
    pub key_id: String,
}

/// Domain payload returned by signed domain APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainData {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<SignedPolicies>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceIdentity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Group>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, flatten)]
    pub meta: DomainMeta,
}

/// Signed domain object. Signature fields can be omitted for meta-only reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedDomain {
    pub domain: DomainData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// List of signed domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedDomains {
    pub domains: Vec<SignedDomain>,
}

/// SignedDomain using flattened JWS JSON serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWSDomain {
    pub payload: String,
    #[serde(rename = "protected")]
    pub protected_header: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<HashMap<String, String>>,
    pub signature: String,
}
