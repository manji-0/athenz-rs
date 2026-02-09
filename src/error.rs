use reqwest::blocking::Response as BlockingResponse;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;

pub(crate) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

pub(crate) fn fallback_message(status: StatusCode, body: &[u8]) -> String {
    let body_text = String::from_utf8_lossy(body);
    if body_text.trim().is_empty() {
        let reason = status.canonical_reason().unwrap_or("");
        if reason.is_empty() {
            format!("http status {}", status.as_u16())
        } else {
            format!("http status {} {}", status.as_u16(), reason)
        }
    } else {
        body_text.to_string()
    }
}

pub(crate) fn read_body_with_limit(
    resp: &mut BlockingResponse,
    limit: usize,
) -> Result<Vec<u8>, reqwest::Error> {
    struct BodyCapture {
        buf: Vec<u8>,
        remaining: usize,
    }

    impl BodyCapture {
        fn new(limit: usize) -> Self {
            Self {
                buf: Vec::new(),
                remaining: limit,
            }
        }
    }

    impl io::Write for BodyCapture {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.remaining > 0 {
                let take = self.remaining.min(data.len());
                self.buf.extend_from_slice(&data[..take]);
                self.remaining -= take;
            }
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut capture = BodyCapture::new(limit);
    resp.copy_to(&mut capture)?;
    Ok(capture.buf)
}

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
