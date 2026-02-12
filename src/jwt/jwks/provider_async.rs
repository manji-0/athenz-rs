use crate::error::{read_body_with_limit_async, Error, MAX_ERROR_BODY_BYTES};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client as AsyncHttpClient;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use url::Url;

use super::provider::{CachedJwks, FetchSource, DEFAULT_JWKS_TIMEOUT, MIN_REFRESH_INTERVAL};
use super::sanitize::{jwks_from_slice, redact_jwks_uri, sanitize_error_body};

#[derive(Debug)]
pub struct JwksProviderAsync {
    jwks_uri: Url,
    http: AsyncHttpClient,
    timeout: Option<Duration>,
    cache_ttl: Duration,
    cache: AsyncRwLock<Option<CachedJwks>>,
    fetch_lock: AsyncMutex<()>,
}

impl JwksProviderAsync {
    pub fn new(jwks_uri: impl AsRef<str>) -> Result<Self, Error> {
        let jwks_uri = Url::parse(jwks_uri.as_ref())?;
        let http = AsyncHttpClient::builder().build()?;
        Ok(Self {
            jwks_uri,
            http,
            timeout: Some(DEFAULT_JWKS_TIMEOUT),
            cache_ttl: Duration::from_secs(300),
            cache: AsyncRwLock::new(None),
            fetch_lock: AsyncMutex::new(()),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_http_client(mut self, http: AsyncHttpClient) -> Self {
        self.http = http;
        self
    }

    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        let cache = self.cache.into_inner();
        self.cache = AsyncRwLock::new(cache.map(|mut cached| {
            let now = Instant::now();
            cached.expires_at = now + self.cache_ttl;
            cached.fetched_at = now;
            cached
        }));
        self
    }

    pub fn with_preloaded(self, jwks: JwkSet) -> Self {
        let now = Instant::now();
        let cached = CachedJwks {
            jwks,
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        let mut this = self;
        this.cache = AsyncRwLock::new(Some(cached));
        this
    }

    pub async fn fetch(&self) -> Result<JwkSet, Error> {
        let (jwks, _source) = self.fetch_with_source().await?;
        Ok(jwks)
    }

    pub(crate) async fn fetch_with_source(&self) -> Result<(JwkSet, FetchSource), Error> {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok((cached.jwks.clone(), FetchSource::Cache));
                }
            }
        }

        let _guard = self.fetch_lock.lock().await;
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok((cached.jwks.clone(), FetchSource::Cache));
                }
            }
        }
        let jwks = self.fetch_remote().await?;
        Ok((jwks, FetchSource::Remote))
    }

    pub async fn fetch_fresh(&self) -> Result<JwkSet, Error> {
        let now = Instant::now();
        if let Some(cached) = self.cache.read().await.as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        let _guard = self.fetch_lock.lock().await;
        if let Some(cached) = self.cache.read().await.as_ref() {
            if cached.fetched_at + MIN_REFRESH_INTERVAL > now {
                return Ok(cached.jwks.clone());
            }
        }
        self.fetch_remote().await
    }

    async fn fetch_remote(&self) -> Result<JwkSet, Error> {
        let mut req = self.http.get(self.jwks_uri.clone());
        if let Some(timeout) = self.timeout {
            req = req.timeout(timeout);
        }
        let mut resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_body_with_limit_async(&mut resp, MAX_ERROR_BODY_BYTES).await?;
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
        let body = resp.bytes().await?;
        let jwks = jwks_from_slice(&body)?;
        let now = Instant::now();
        let cached = CachedJwks {
            jwks: jwks.clone(),
            expires_at: now + self.cache_ttl,
            fetched_at: now,
        };
        *self.cache.write().await = Some(cached);
        Ok(jwks)
    }
}
