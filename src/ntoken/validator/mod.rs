use crate::error::Error;
use p256::ecdsa::Signature as P256Signature;
use p384::ecdsa::Signature as P384Signature;
use p521::ecdsa::Signature as P521Signature;
use reqwest::blocking::Client as HttpClient;
#[cfg(feature = "async-validate")]
use reqwest::Client as AsyncHttpClient;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use sha2::Sha256;
use signature::Verifier as SignatureVerifier;
use std::collections::HashMap;
#[cfg(feature = "async-validate")]
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
#[cfg(feature = "async-validate")]
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

use super::keys::{load_public_key, PublicKey};
use super::token::{unix_time_now, NToken};

mod helpers;
#[cfg(test)]
mod tests;

#[cfg(feature = "async-validate")]
use helpers::get_cached_verifier_async;
use helpers::{get_cached_verifier, key_source_from_claims, parse_unverified, ybase64_decode};

#[derive(Clone)]
pub struct NTokenVerifier {
    key: PublicKey,
}

impl NTokenVerifier {
    pub fn from_public_key_pem(public_key_pem: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            key: load_public_key(public_key_pem)?,
        })
    }

    pub fn verify(&self, unsigned: &str, signature: &str) -> Result<(), Error> {
        let sig_bytes = ybase64_decode(signature)?;
        match &self.key {
            PublicKey::Rsa(rsa_key) => {
                let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key.clone());
                let sig = RsaSignature::try_from(sig_bytes.as_slice())
                    .map_err(|e| Error::Crypto(format!("rsa signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("rsa signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P256(verifying_key) => {
                let sig = P256Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p256 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p256 signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P384(verifying_key) => {
                let sig = P384Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p384 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p384 signature verify error: {e}")))?;
                Ok(())
            }
            PublicKey::P521(verifying_key) => {
                let sig = P521Signature::from_der(&sig_bytes)
                    .map_err(|e| Error::Crypto(format!("p521 signature parse error: {e}")))?;
                verifying_key
                    .verify(unsigned.as_bytes(), &sig)
                    .map_err(|e| Error::Crypto(format!("p521 signature verify error: {e}")))?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NTokenValidatorConfig {
    pub zts_base_url: String,
    pub public_key_fetch_timeout: Duration,
    pub cache_ttl: Duration,
    pub sys_auth_domain: String,
    pub zms_service: String,
    pub zts_service: String,
}

const DEFAULT_ALLOWED_OFFSET: Duration = Duration::from_secs(300);
const DEFAULT_MAX_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Options controlling additional validation checks when validating an [`NToken`].
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
            allowed_offset: DEFAULT_ALLOWED_OFFSET,
            max_expiry: DEFAULT_MAX_EXPIRY,
        }
    }
}

impl Default for NTokenValidatorConfig {
    fn default() -> Self {
        Self {
            zts_base_url: "https://localhost:4443/zts/v1".to_string(),
            public_key_fetch_timeout: Duration::from_secs(5),
            cache_ttl: Duration::from_secs(600),
            sys_auth_domain: "sys.auth".to_string(),
            zms_service: "zms".to_string(),
            zts_service: "zts".to_string(),
        }
    }
}

#[allow(private_interfaces)]
pub enum NTokenValidator {
    Static(NTokenVerifier),
    Zts {
        config: NTokenValidatorConfig,
        cache: RwLock<HashMap<KeySource, CachedKey>>,
        http: HttpClient,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct KeySource {
    domain: String,
    name: String,
    key_version: String,
}

#[derive(Clone)]
struct CachedKey {
    verifier: NTokenVerifier,
    expires_at: Instant,
}

impl NTokenValidator {
    pub fn new_with_public_key(public_key_pem: &[u8]) -> Result<Self, Error> {
        Ok(NTokenValidator::Static(
            NTokenVerifier::from_public_key_pem(public_key_pem)?,
        ))
    }

    pub fn new_with_zts(config: NTokenValidatorConfig) -> Result<Self, Error> {
        let http = HttpClient::builder()
            .timeout(config.public_key_fetch_timeout)
            .build()?;
        Ok(NTokenValidator::Zts {
            config,
            cache: RwLock::new(HashMap::new()),
            http,
        })
    }

    pub fn validate(&self, token: &str) -> Result<NToken, Error> {
        let options = NTokenValidationOptions::default();
        self.validate_with_options(token, &options)
    }

    /// Validate an NToken using additional validation options.
    ///
    /// When `options.hostname` is set, the token must contain a hostname and it
    /// must match the configured value (case-insensitive ASCII, ignoring trailing
    /// dot(s)). When `options.ip` is set, the token must contain an IP and it must
    /// match the configured value (parsed `IpAddr` equality when possible,
    /// otherwise string equality). If an expected value is set but the token is
    /// missing the corresponding claim, validation fails.
    ///
    /// Timestamps are also validated: the generation time cannot be in the
    /// future beyond the allowed offset, and the expiry time cannot exceed the
    /// configured maximum window. The allowed offset is not applied to the
    /// expiration check itself (`expiry_time < now`).
    pub fn validate_with_options(
        &self,
        token: &str,
        options: &NTokenValidationOptions,
    ) -> Result<NToken, Error> {
        let (claims, unsigned, signature) = parse_unverified(token)?;
        match self {
            NTokenValidator::Static(verifier) => {
                verifier.verify(&unsigned, &signature)?;
                validate_version_domain(&claims)?;
                validate_time_bounds(&claims, options)?;
                if claims.is_expired() {
                    return Err(Error::Crypto("ntoken expired".to_string()));
                }
                validate_ip_hostname(&claims, options)?;
                Ok(claims)
            }
            NTokenValidator::Zts {
                config,
                cache,
                http,
            } => {
                let src = key_source_from_claims(&claims, config);
                let verifier = get_cached_verifier(cache, http, config, &src)?;
                verifier.verify(&unsigned, &signature)?;
                validate_version_domain(&claims)?;
                validate_time_bounds(&claims, options)?;
                if claims.is_expired() {
                    return Err(Error::Crypto("ntoken expired".to_string()));
                }
                validate_ip_hostname(&claims, options)?;
                Ok(claims)
            }
        }
    }
}

#[cfg(feature = "async-validate")]
#[allow(private_interfaces)]
pub enum NTokenValidatorAsync {
    Static(NTokenVerifier),
    Zts {
        config: NTokenValidatorConfig,
        cache: AsyncRwLock<HashMap<KeySource, CachedKey>>,
        http: AsyncHttpClient,
        fetch_locks: AsyncMutex<HashMap<KeySource, Arc<AsyncMutex<()>>>>,
    },
}

#[cfg(feature = "async-validate")]
impl NTokenValidatorAsync {
    pub fn new_with_public_key(public_key_pem: &[u8]) -> Result<Self, Error> {
        Ok(NTokenValidatorAsync::Static(
            NTokenVerifier::from_public_key_pem(public_key_pem)?,
        ))
    }

    pub fn new_with_zts(config: NTokenValidatorConfig) -> Result<Self, Error> {
        let http = AsyncHttpClient::builder()
            .timeout(config.public_key_fetch_timeout)
            .build()?;
        Ok(NTokenValidatorAsync::Zts {
            config,
            cache: AsyncRwLock::new(HashMap::new()),
            http,
            fetch_locks: AsyncMutex::new(HashMap::new()),
        })
    }

    pub async fn validate(&self, token: &str) -> Result<NToken, Error> {
        let options = NTokenValidationOptions::default();
        self.validate_with_options(token, &options).await
    }

    /// Validate an NToken using additional validation options.
    ///
    /// When `options.hostname` is set, the token must contain a hostname and it
    /// must match the configured value (case-insensitive ASCII, ignoring trailing
    /// dot(s)). When `options.ip` is set, the token must contain an IP and it must
    /// match the configured value (parsed `IpAddr` equality when possible,
    /// otherwise string equality). If an expected value is set but the token is
    /// missing the corresponding claim, validation fails.
    ///
    /// Timestamps are also validated: the generation time cannot be in the
    /// future beyond the allowed offset, and the expiry time cannot exceed the
    /// configured maximum window. The allowed offset is not applied to the
    /// expiration check itself (`expiry_time < now`).
    pub async fn validate_with_options(
        &self,
        token: &str,
        options: &NTokenValidationOptions,
    ) -> Result<NToken, Error> {
        let (claims, unsigned, signature) = parse_unverified(token)?;
        match self {
            NTokenValidatorAsync::Static(verifier) => {
                verifier.verify(&unsigned, &signature)?;
                validate_version_domain(&claims)?;
                validate_time_bounds(&claims, options)?;
                if claims.is_expired() {
                    return Err(Error::Crypto("ntoken expired".to_string()));
                }
                validate_ip_hostname(&claims, options)?;
                Ok(claims)
            }
            NTokenValidatorAsync::Zts {
                config,
                cache,
                http,
                fetch_locks,
            } => {
                let src = key_source_from_claims(&claims, config);
                let verifier =
                    get_cached_verifier_async(cache, fetch_locks, http, config, &src).await?;
                verifier.verify(&unsigned, &signature)?;
                validate_version_domain(&claims)?;
                validate_time_bounds(&claims, options)?;
                if claims.is_expired() {
                    return Err(Error::Crypto("ntoken expired".to_string()));
                }
                validate_ip_hostname(&claims, options)?;
                Ok(claims)
            }
        }
    }
}

fn validate_ip_hostname(claims: &NToken, options: &NTokenValidationOptions) -> Result<(), Error> {
    if let Some(expected) = options.hostname() {
        match claims.hostname.as_deref() {
            Some(actual) if hostname_matches(expected, actual) => {}
            Some(actual) => {
                return Err(Error::Crypto(format!(
                    "ntoken hostname mismatch: expected {expected}, got {actual}"
                )));
            }
            None => return Err(Error::Crypto("ntoken missing hostname".to_string())),
        }
    }

    if let Some(expected) = options.ip() {
        match claims.ip.as_deref() {
            Some(actual) if ip_matches(expected, actual) => {}
            Some(actual) => {
                return Err(Error::Crypto(format!(
                    "ntoken ip mismatch: expected {expected}, got {actual}"
                )));
            }
            None => return Err(Error::Crypto("ntoken missing ip".to_string())),
        }
    }

    Ok(())
}

fn validate_version_domain(claims: &NToken) -> Result<(), Error> {
    let is_user_version = claims
        .version
        .chars()
        .next()
        .map(|c| c.eq_ignore_ascii_case(&'U'))
        .unwrap_or(false);
    let is_user_domain = claims.domain == "user";

    if is_user_version && !is_user_domain {
        return Err(Error::Crypto(format!(
            "ntoken user version requires domain 'user' (domain={}, version={})",
            claims.domain, claims.version
        )));
    }

    if is_user_domain && !is_user_version {
        return Err(Error::Crypto(format!(
            "ntoken domain 'user' requires user version (domain={}, version={})",
            claims.domain, claims.version
        )));
    }

    Ok(())
}

fn validate_time_bounds(claims: &NToken, options: &NTokenValidationOptions) -> Result<(), Error> {
    let now = unix_time_now();
    let allowed_offset = duration_to_i64(options.allowed_offset);

    // generation_time is required by parsing, but keep a defensive guard for
    // manually constructed claims.
    if claims.generation_time != 0 && claims.generation_time.saturating_sub(allowed_offset) > now {
        return Err(Error::Crypto(format!(
            "ntoken has future timestamp: generation_time={} now={} allowed_offset={}",
            claims.generation_time, now, allowed_offset
        )));
    }

    let max_expiry = duration_to_i64(options.max_expiry);
    let latest_expiry = now
        .saturating_add(max_expiry)
        .saturating_add(allowed_offset);
    if claims.expiry_time > latest_expiry {
        return Err(Error::Crypto(format!(
            "ntoken expires too far in the future: expiry_time={} now={} max_expiry={} allowed_offset={}",
            claims.expiry_time, now, max_expiry, allowed_offset
        )));
    }

    Ok(())
}

fn duration_to_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn hostname_matches(expected: &str, actual: &str) -> bool {
    let expected = expected.trim_end_matches('.');
    let actual = actual.trim_end_matches('.');
    expected.eq_ignore_ascii_case(actual)
}

fn ip_matches(expected: &str, actual: &str) -> bool {
    use std::net::IpAddr;

    match (expected.parse::<IpAddr>(), actual.parse::<IpAddr>()) {
        (Ok(expected), Ok(actual)) => expected == actual,
        _ => expected == actual,
    }
}
