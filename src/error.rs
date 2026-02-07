use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct ResourceError {
    pub code: i32,
    pub message: String,
    pub description: Option<String>,
    pub error: Option<String>,
    pub request_id: Option<String>,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "code={}", self.code)
        } else {
            write!(f, "code={}, message={}", self.code, self.message)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid base url: {0}")]
    InvalidBaseUrl(String),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("missing jwk for kid: {0}")]
    MissingJwk(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("athenz api error: {0}")]
    Api(ResourceError),
}
