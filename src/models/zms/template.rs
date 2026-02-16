use serde::{Deserialize, Serialize};

use super::{Group, Policy, Role, ServiceIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateMeta {
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "metadata",
        alias = "meta"
    )]
    pub meta: Option<TemplateMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerTemplateList {
    pub template_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainTemplateDetailsList {
    pub meta_data: Vec<TemplateMeta>,
}
