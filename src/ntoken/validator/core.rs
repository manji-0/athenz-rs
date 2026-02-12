use crate::error::Error;
use reqwest::blocking::Client as HttpClient;
#[cfg(feature = "async-validate")]
use reqwest::Client as AsyncHttpClient;
use std::collections::HashMap;
#[cfg(feature = "async-validate")]
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
#[cfg(feature = "async-validate")]
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

use super::super::token::NToken;
use super::checks::{validate_ip_hostname, validate_time_bounds, validate_version_domain};
use super::config::NTokenValidatorConfig;
#[cfg(feature = "async-validate")]
use super::helpers::get_cached_verifier_async;
use super::helpers::{get_cached_verifier, key_source_from_claims, parse_unverified};
use super::options::NTokenValidationOptions;
use super::verifier::NTokenVerifier;

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
pub(super) struct KeySource {
    pub(super) domain: String,
    pub(super) name: String,
    pub(super) key_version: String,
}

#[derive(Clone)]
pub(super) struct CachedKey {
    pub(super) verifier: NTokenVerifier,
    pub(super) expires_at: Instant,
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
