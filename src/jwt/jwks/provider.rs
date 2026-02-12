use crate::error::{read_body_with_limit, Error, MAX_ERROR_BODY_BYTES};
use jsonwebtoken::jwk::JwkSet;
use reqwest::blocking::Client as HttpClient;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use url::Url;

use super::sanitize::{jwks_from_slice, redact_jwks_uri, sanitize_error_body};

pub(super) const DEFAULT_JWKS_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct JwksProvider {
    jwks_uri: Url,
    http: HttpClient,
    timeout: Option<Duration>,
    cache_ttl: Duration,
    pub(super) cache: RwLock<Option<CachedJwks>>,
    fetch_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
pub(super) struct CachedJwks {
    pub(super) jwks: JwkSet,
    pub(super) expires_at: Instant,
    pub(super) fetched_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FetchSource {
    Cache,
    Remote,
}

impl JwksProvider {
    pub fn new(jwks_uri: impl AsRef<str>) -> Result<Self, Error> {
        let jwks_uri = Url::parse(jwks_uri.as_ref())?;
        let http = HttpClient::builder().build()?;
        Ok(Self {
            jwks_uri,
            http,
            timeout: Some(DEFAULT_JWKS_TIMEOUT),
            cache_ttl: Duration::from_secs(300),
            cache: RwLock::new(None),
            fetch_lock: Mutex::new(()),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_http_client(mut self, http: HttpClient) -> Self {
        self.http = http;
        self
    }

    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        if let Some(cached) = self.cache.write().unwrap().as_mut() {
            let now = Instant::now();
            cached.expires_at = now + self.cache_ttl;
            cached.fetched_at = now;
        }
        self
    }

    pub fn with_preloaded(self, jwks: JwkSet) -> Self {
        let now = Instant::now();
        let cached = CachedJwks {
            jwks,
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        *self.cache.write().unwrap() = Some(cached);
        self
    }

    pub fn fetch(&self) -> Result<JwkSet, Error> {
        let (jwks, _source) = self.fetch_with_source()?;
        Ok(jwks)
    }

    pub(crate) fn fetch_with_source(&self) -> Result<(JwkSet, FetchSource), Error> {
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.expires_at > Instant::now() {
                return Ok((cached.jwks.clone(), FetchSource::Cache));
            }
        }

        let _guard = self.fetch_lock.lock().unwrap();
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.expires_at > Instant::now() {
                return Ok((cached.jwks.clone(), FetchSource::Cache));
            }
        }

        let jwks = self.fetch_remote()?;
        Ok((jwks, FetchSource::Remote))
    }

    pub fn fetch_fresh(&self) -> Result<JwkSet, Error> {
        let now = Instant::now();
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        let _guard = self.fetch_lock.lock().unwrap();
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        self.fetch_remote()
    }

    fn fetch_remote(&self) -> Result<JwkSet, Error> {
        let mut req = self.http.get(self.jwks_uri.clone());
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
        }
        let mut resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_body_with_limit(&mut resp, MAX_ERROR_BODY_BYTES)?;
            let body_preview = sanitize_error_body(&body);
            let redacted = redact_jwks_uri(&self.jwks_uri);
            return Err(Error::Crypto(if body_preview.is_empty() {
                format!(
                    "jwks fetch failed: uri {} status {} body_read_len {}",
                    redacted,
                    status,
                    body.len()
                )
            } else {
                format!(
                    "jwks fetch failed: uri {} status {} body_read_len {} body_preview {}",
                    redacted,
                    status,
                    body.len(),
                    body_preview
                )
            }));
        }
        let body = resp.bytes()?;
        let jwks = jwks_from_slice(&body)?;
        let now = Instant::now();
        let cached = CachedJwks {
            jwks: jwks.clone(),
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        *self.cache.write().unwrap() = Some(cached);
        Ok(jwks)
    }
}
