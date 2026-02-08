use crate::error::Error;
use crate::models::PublicKeyEntry;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
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
use url::Url;

use super::super::token::{
    NToken, TAG_DOMAIN, TAG_EXPIRE_TIME, TAG_GENERATION_TIME, TAG_HOSTNAME, TAG_IP,
    TAG_KEY_SERVICE, TAG_KEY_VERSION, TAG_NAME, TAG_SALT, TAG_SIGNATURE, TAG_VERSION,
};
use super::{CachedKey, KeySource, NTokenValidatorConfig, NTokenVerifier};

pub(super) fn build_zts_public_key_url(
    config: &NTokenValidatorConfig,
    src: &KeySource,
) -> Result<Url, Error> {
    let mut url = Url::parse(&config.zts_base_url)?;
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| Error::InvalidBaseUrl(config.zts_base_url.clone()))?;
        segments.pop_if_empty();
        segments.push("domain");
        segments.push(&src.domain);
        segments.push("service");
        segments.push(&src.name);
        segments.push("publickey");
        segments.push(&src.key_version);
    }
    Ok(url)
}

pub(super) fn get_cached_verifier(
    cache: &RwLock<HashMap<KeySource, CachedKey>>,
    http: &HttpClient,
    config: &NTokenValidatorConfig,
    src: &KeySource,
) -> Result<NTokenVerifier, Error> {
    if let Some(entry) = cache.read().unwrap().get(src) {
        if entry.expires_at > Instant::now() {
            return Ok(entry.verifier.clone());
        }
    }

    let url = build_zts_public_key_url(config, src)?;
    let resp = http.get(url).send()?;
    if !resp.status().is_success() {
        return Err(Error::Crypto(format!(
            "unable to fetch public key: status {}",
            resp.status()
        )));
    }
    let entry: PublicKeyEntry = resp.json()?;
    let pem_bytes = ybase64_decode(&entry.key)?;
    let verifier = NTokenVerifier::from_public_key_pem(&pem_bytes)?;

    let cached = CachedKey {
        verifier: verifier.clone(),
        expires_at: Instant::now() + config.cache_ttl,
    };
    cache.write().unwrap().insert(src.clone(), cached);
    Ok(verifier)
}

#[cfg(feature = "async-validate")]
pub(super) async fn get_cached_verifier_async(
    cache: &AsyncRwLock<HashMap<KeySource, CachedKey>>,
    fetch_locks: &AsyncMutex<HashMap<KeySource, Arc<AsyncMutex<()>>>>,
    http: &AsyncHttpClient,
    config: &NTokenValidatorConfig,
    src: &KeySource,
) -> Result<NTokenVerifier, Error> {
    {
        let cache = cache.read().await;
        if let Some(entry) = cache.get(src) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.verifier.clone());
            }
        }
    }

    let fetch_lock = {
        let mut locks = fetch_locks.lock().await;
        locks
            .entry(src.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    };
    let _guard = fetch_lock.lock().await;
    let result = async {
        {
            let cache = cache.read().await;
            if let Some(entry) = cache.get(src) {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.verifier.clone());
                }
            }
        }

        let url = build_zts_public_key_url(config, src)?;
        let resp = http.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(Error::Crypto(format!(
                "unable to fetch public key: status {}",
                resp.status()
            )));
        }
        let entry: PublicKeyEntry = resp.json().await?;
        let pem_bytes = ybase64_decode(&entry.key)?;
        let verifier = NTokenVerifier::from_public_key_pem(&pem_bytes)?;

        let cached = CachedKey {
            verifier: verifier.clone(),
            expires_at: Instant::now() + config.cache_ttl,
        };
        let mut cache = cache.write().await;
        cache.insert(src.clone(), cached);
        Ok(verifier)
    }
    .await;

    let mut locks = fetch_locks.lock().await;
    if let Some(existing) = locks.get(src) {
        if Arc::ptr_eq(existing, &fetch_lock) && Arc::strong_count(existing) == 2 {
            locks.remove(src);
        }
    }
    result
}

pub(super) fn key_source_from_claims(claims: &NToken, config: &NTokenValidatorConfig) -> KeySource {
    if let Some(ref key_service) = claims.key_service {
        if key_service == &config.zms_service {
            return KeySource {
                domain: config.sys_auth_domain.clone(),
                name: config.zms_service.clone(),
                key_version: claims.key_version.clone(),
            };
        }
        if key_service == &config.zts_service {
            return KeySource {
                domain: config.sys_auth_domain.clone(),
                name: config.zts_service.clone(),
                key_version: claims.key_version.clone(),
            };
        }
    }

    if claims.version.starts_with('U') {
        return KeySource {
            domain: config.sys_auth_domain.clone(),
            name: config.zms_service.clone(),
            key_version: claims.key_version.clone(),
        };
    }

    KeySource {
        domain: claims.domain.clone(),
        name: claims.name.clone(),
        key_version: claims.key_version.clone(),
    }
}

pub(super) fn parse_unverified(token: &str) -> Result<(NToken, String, String), Error> {
    let (unsigned, signature) = split_token(token)?;
    let claims = parse_claims(&unsigned)?;
    Ok((claims, unsigned, signature))
}

pub(super) fn split_token(token: &str) -> Result<(String, String), Error> {
    let delim = format!(";{TAG_SIGNATURE}=");
    let mut parts = token.splitn(2, &delim);
    let unsigned = parts
        .next()
        .ok_or_else(|| Error::Crypto("invalid ntoken".to_string()))?;
    let signature = parts
        .next()
        .ok_or_else(|| Error::Crypto("ntoken missing signature".to_string()))?;
    Ok((unsigned.to_string(), signature.to_string()))
}

pub(super) fn parse_claims(unsigned: &str) -> Result<NToken, Error> {
    let mut claims = NToken {
        version: String::new(),
        domain: String::new(),
        name: String::new(),
        key_version: String::new(),
        key_service: None,
        hostname: None,
        ip: None,
        generation_time: 0,
        expiry_time: 0,
    };

    for part in unsigned.split(';') {
        let mut kv = part.splitn(2, '=');
        let key = kv
            .next()
            .ok_or_else(|| Error::Crypto("invalid ntoken field".to_string()))?;
        let value = kv
            .next()
            .ok_or_else(|| Error::Crypto("invalid ntoken field".to_string()))?;
        match key {
            TAG_VERSION => claims.version = value.to_string(),
            TAG_DOMAIN => claims.domain = value.to_string(),
            TAG_NAME => claims.name = value.to_string(),
            TAG_KEY_VERSION => claims.key_version = value.to_string(),
            TAG_KEY_SERVICE => claims.key_service = Some(value.to_string()),
            TAG_HOSTNAME => claims.hostname = Some(value.to_string()),
            TAG_IP => claims.ip = Some(value.to_string()),
            TAG_GENERATION_TIME => claims.generation_time = parse_unix(value)?,
            TAG_EXPIRE_TIME => claims.expiry_time = parse_unix(value)?,
            TAG_SALT | TAG_SIGNATURE => {}
            _ => {}
        }
    }

    if claims.version.is_empty()
        || claims.domain.is_empty()
        || claims.name.is_empty()
        || claims.key_version.is_empty()
        || claims.generation_time == 0
        || claims.expiry_time == 0
    {
        return Err(Error::Crypto("invalid ntoken claims".to_string()));
    }

    Ok(claims)
}

pub(super) fn parse_unix(value: &str) -> Result<i64, Error> {
    value
        .parse::<i64>()
        .map_err(|_| Error::Crypto(format!("invalid unix time: {value}")))
}

pub(super) fn ybase64_decode(data: &str) -> Result<Vec<u8>, Error> {
    let normalized = data.replace('.', "+").replace('_', "/").replace('-', "=");
    BASE64_STD
        .decode(normalized.as_bytes())
        .map_err(|e| Error::Crypto(format!("ybase64 decode error: {e}")))
}
