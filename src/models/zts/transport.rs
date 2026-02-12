use serde::{Deserialize, Serialize};

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
