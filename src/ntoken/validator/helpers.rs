use crate::error::Error;
use crate::models::PublicKeyEntry;
use crate::ybase64::decode as ybase64_decode_impl;
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
    NToken, TAG_AUTHORIZED_SERVICES, TAG_AUTHORIZED_SERVICE_KEY_ID, TAG_AUTHORIZED_SERVICE_NAME,
    TAG_AUTHORIZED_SERVICE_SIGNATURE, TAG_DOMAIN, TAG_EXPIRE_TIME, TAG_GENERATION_TIME,
    TAG_HOSTNAME, TAG_IP, TAG_KEY_SERVICE, TAG_KEY_VERSION, TAG_NAME, TAG_ORIGINAL_REQUESTOR,
    TAG_SALT, TAG_SIGNATURE, TAG_VERSION,
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
    let now = Instant::now();
    if let Some(entry) = cache.read().unwrap().get(src) {
        if entry.expires_at > now {
            return Ok(entry.verifier.clone());
        }
    }

    let url = build_zts_public_key_url(config, src)?;
    let mut req = http.get(url);
    if let Some((header, value)) = &config.public_key_fetch_auth_header {
        req = req.header(header.as_str(), value.as_str());
    }
    let resp = req.send()?;
    if !resp.status().is_success() {
        return Err(Error::Crypto(format!(
            "unable to fetch public key: status {}",
            resp.status()
        )));
    }
    let entry: PublicKeyEntry = resp.json()?;
    let pem_bytes = ybase64_decode(&entry.key)?;
    let verifier = NTokenVerifier::from_public_key_pem(&pem_bytes)?;
    let now = Instant::now();

    let cached = CachedKey {
        verifier: verifier.clone(),
        expires_at: now + config.cache_ttl,
        created_at: now,
    };
    let mut cache = cache.write().unwrap();
    cache.insert(src.clone(), cached);
    enforce_cache_limit(&mut cache, config.max_cache_entries);
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
    let now = Instant::now();
    {
        let cache = cache.read().await;
        if let Some(entry) = cache.get(src) {
            if entry.expires_at > now {
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
        let mut req = http.get(url);
        if let Some((header, value)) = &config.public_key_fetch_auth_header {
            req = req.header(header.as_str(), value.as_str());
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(Error::Crypto(format!(
                "unable to fetch public key: status {}",
                resp.status()
            )));
        }
        let entry: PublicKeyEntry = resp.json().await?;
        let pem_bytes = ybase64_decode(&entry.key)?;
        let verifier = NTokenVerifier::from_public_key_pem(&pem_bytes)?;
        let now = Instant::now();

        let cached = CachedKey {
            verifier: verifier.clone(),
            expires_at: now + config.cache_ttl,
            created_at: now,
        };
        let mut cache = cache.write().await;
        cache.insert(src.clone(), cached);
        enforce_cache_limit(&mut cache, config.max_cache_entries);
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

fn enforce_cache_limit(cache: &mut HashMap<KeySource, CachedKey>, max_cache_entries: usize) {
    if max_cache_entries == 0 {
        cache.clear();
        return;
    }
    while cache.len() > max_cache_entries {
        if let Some((oldest_key, _)) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, value)| (key.clone(), value.created_at))
        {
            cache.remove(&oldest_key);
        } else {
            break;
        }
    }
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
        original_requestor: None,
        authorized_services: None,
        authorized_service_key_id: None,
        authorized_service_name: None,
        authorized_service_signature: None,
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
            TAG_ORIGINAL_REQUESTOR => {
                claims.original_requestor =
                    Some(validate_non_empty_value(TAG_ORIGINAL_REQUESTOR, value)?)
            }
            TAG_AUTHORIZED_SERVICES => {
                claims.authorized_services = Some(parse_authorized_services(value)?)
            }
            TAG_AUTHORIZED_SERVICE_KEY_ID => {
                claims.authorized_service_key_id = Some(validate_non_empty_value(
                    TAG_AUTHORIZED_SERVICE_KEY_ID,
                    value,
                )?);
            }
            TAG_AUTHORIZED_SERVICE_NAME => {
                claims.authorized_service_name = Some(validate_non_empty_value(
                    TAG_AUTHORIZED_SERVICE_NAME,
                    value,
                )?);
            }
            TAG_AUTHORIZED_SERVICE_SIGNATURE => {
                claims.authorized_service_signature = Some(validate_non_empty_value(
                    TAG_AUTHORIZED_SERVICE_SIGNATURE,
                    value,
                )?);
            }
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

    claims.domain.make_ascii_lowercase();
    claims.name.make_ascii_lowercase();
    if let Some(ref mut services) = claims.authorized_services {
        for service in services.iter_mut() {
            service.make_ascii_lowercase();
        }
    }
    if let Some(ref mut authorized_service_name) = claims.authorized_service_name {
        authorized_service_name.make_ascii_lowercase();
    }
    if let Some(ref mut key_service) = claims.key_service {
        key_service.make_ascii_lowercase();
    }
    if let Some(ref mut original_requestor) = claims.original_requestor {
        original_requestor.make_ascii_lowercase();
    }

    Ok(claims)
}

pub(super) fn parse_unix(value: &str) -> Result<i64, Error> {
    value
        .parse::<i64>()
        .map_err(|_| Error::Crypto(format!("invalid unix time: {value}")))
}

fn parse_authorized_services(value: &str) -> Result<Vec<String>, Error> {
    let services: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if services.is_empty() {
        return Err(Error::Crypto(
            "invalid ntoken authorized service list".to_string(),
        ));
    }
    Ok(services
        .into_iter()
        .map(|s| s.to_ascii_lowercase())
        .collect())
}

fn validate_non_empty_value(tag: &str, value: &str) -> Result<String, Error> {
    if value.is_empty() {
        return Err(Error::Crypto(format!("invalid ntoken field: {tag}")));
    }
    Ok(value.to_string())
}

pub(super) fn ybase64_decode(data: &str) -> Result<Vec<u8>, Error> {
    ybase64_decode_impl(data)
}
