use std::time::Duration;

const DEFAULT_ALLOWED_OFFSET: Duration = Duration::from_secs(300);
const DEFAULT_MAX_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Options controlling additional validation checks when validating an
/// [`NToken`](crate::ntoken::token::NToken).
///
/// Hostname comparison is case-insensitive (ASCII) and ignores any trailing dot(s).
/// IP comparison parses both values as `IpAddr` when possible and compares the
/// parsed addresses; if parsing fails, it falls back to string equality.
/// The default allowed offset is 300 seconds, and the default max expiry is 30 days
/// from the current time.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NTokenValidationOptions {
    hostname: Option<String>,
    ip: Option<String>,
    authorized_service: Option<String>,
    allowed_offset: Duration,
    max_expiry: Duration,
}

impl NTokenValidationOptions {
    /// Returns the configured hostname, if any.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Returns the configured IP address, if any.
    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }

    /// Returns the expected authorized service, if any.
    pub fn authorized_service(&self) -> Option<&str> {
        self.authorized_service.as_deref()
    }

    /// Returns the allowed clock offset when validating token timestamps.
    pub fn allowed_offset(&self) -> Duration {
        self.allowed_offset
    }

    /// Returns the maximum allowed expiry window for a token.
    pub fn max_expiry(&self) -> Duration {
        self.max_expiry
    }

    /// Set the expected hostname to be matched against the token.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Set the expected IP address to be matched against the token.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Set the expected authorized service name.
    pub fn with_authorized_service(mut self, authorized_service: impl Into<String>) -> Self {
        self.authorized_service = Some(authorized_service.into().to_ascii_lowercase());
        self
    }

    /// Set the allowed clock offset when validating token timestamps.
    pub fn with_allowed_offset(mut self, allowed_offset: Duration) -> Self {
        self.allowed_offset = allowed_offset;
        self
    }

    /// Set the maximum allowed expiry window for a token.
    pub fn with_max_expiry(mut self, max_expiry: Duration) -> Self {
        self.max_expiry = max_expiry;
        self
    }
}

impl Default for NTokenValidationOptions {
    fn default() -> Self {
        Self {
            hostname: None,
            ip: None,
            authorized_service: None,
            allowed_offset: DEFAULT_ALLOWED_OFFSET,
            max_expiry: DEFAULT_MAX_EXPIRY,
        }
    }
}
