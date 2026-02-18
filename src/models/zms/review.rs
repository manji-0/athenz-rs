use serde::{Deserialize, Serialize};

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
