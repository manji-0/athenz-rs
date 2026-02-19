use crate::error::Error;
use crate::models::PublicKeyEntry;
use crate::policy::validator::{
    CachedPolicyPublicKey, PolicyPublicKeyCache, PolicyPublicKeyFetchLocks, PolicyPublicKeySource,
};
#[cfg(feature = "async-validate")]
use crate::policy::validator::{PolicyPublicKeyCacheAsync, PolicyPublicKeyFetchLocksAsync};
use crate::ybase64::decode as ybase64_decode;
use crate::zts::ZtsClient;
#[cfg(feature = "async-validate")]
use crate::zts_async::ZtsAsyncClient;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
#[cfg(feature = "async-validate")]
use tokio::sync::Mutex as AsyncMutex;

const POLICY_PUBLIC_KEY_CACHE_TTL: Duration = Duration::from_secs(600);
const POLICY_PUBLIC_KEY_CACHE_MAX_ENTRIES: usize = 1024;

fn lock_poison_error(lock: &str) -> Error {
    Error::Crypto(format!("{lock} lock poisoned"))
}

fn enforce_cache_limit(
    cache: &mut HashMap<PolicyPublicKeySource, CachedPolicyPublicKey>,
    max_cache_entries: usize,
) {
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

pub(in crate::policy::validator) fn get_public_key_pem(
    zts: &ZtsClient,
    domain: &str,
    service: &str,
    key_id: &str,
    key_cache: &PolicyPublicKeyCache,
    fetch_locks: &PolicyPublicKeyFetchLocks,
) -> Result<Vec<u8>, Error> {
    let source = PolicyPublicKeySource {
        domain: domain.to_string(),
        service: service.to_string(),
        key_id: key_id.to_string(),
    };

    {
        let cache = key_cache
            .read()
            .map_err(|_| lock_poison_error("policy public key cache"))?;
        if let Some(entry) = cache.get(&source) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.pem.clone());
            }
        }
    }

    let fetch_lock = {
        let mut locks = fetch_locks
            .lock()
            .map_err(|_| lock_poison_error("policy fetch lock map"))?;
        locks
            .entry(source.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let result = {
        let _guard = fetch_lock
            .lock()
            .map_err(|_| lock_poison_error("policy fetch lock"))?;
        (|| -> Result<Vec<u8>, Error> {
            {
                let cache = key_cache
                    .read()
                    .map_err(|_| lock_poison_error("policy public key cache"))?;
                if let Some(entry) = cache.get(&source) {
                    if entry.expires_at > Instant::now() {
                        return Ok(entry.pem.clone());
                    }
                }
            }

            let entry: PublicKeyEntry =
                zts.get_public_key_entry(&source.domain, &source.service, &source.key_id)?;
            let pem = ybase64_decode(&entry.key)?;
            let now = Instant::now();
            let cached = CachedPolicyPublicKey {
                pem: pem.clone(),
                created_at: now,
                expires_at: now + POLICY_PUBLIC_KEY_CACHE_TTL,
            };
            let mut cache = key_cache
                .write()
                .map_err(|_| lock_poison_error("policy public key cache"))?;
            cache.insert(source.clone(), cached);
            enforce_cache_limit(&mut cache, POLICY_PUBLIC_KEY_CACHE_MAX_ENTRIES);
            Ok(pem)
        })()
    };

    let mut locks = fetch_locks
        .lock()
        .map_err(|_| lock_poison_error("policy fetch lock map"))?;
    if let Some(existing) = locks.get(&source) {
        if Arc::ptr_eq(existing, &fetch_lock) && Arc::strong_count(existing) == 2 {
            locks.remove(&source);
        }
    }
    result
}

#[cfg(feature = "async-validate")]
pub(in crate::policy::validator) async fn get_public_key_pem_async(
    zts: &ZtsAsyncClient,
    domain: &str,
    service: &str,
    key_id: &str,
    key_cache: &PolicyPublicKeyCacheAsync,
    fetch_locks: &PolicyPublicKeyFetchLocksAsync,
) -> Result<Vec<u8>, Error> {
    let source = PolicyPublicKeySource {
        domain: domain.to_string(),
        service: service.to_string(),
        key_id: key_id.to_string(),
    };
    {
        let cache = key_cache.read().await;
        if let Some(entry) = cache.get(&source) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.pem.clone());
            }
        }
    }

    let fetch_lock = {
        let mut locks = fetch_locks.lock().await;
        locks
            .entry(source.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    };
    let result = {
        let _guard = fetch_lock.lock().await;
        async {
            {
                let cache = key_cache.read().await;
                if let Some(entry) = cache.get(&source) {
                    if entry.expires_at > Instant::now() {
                        return Ok(entry.pem.clone());
                    }
                }
            }

            let entry: PublicKeyEntry = zts
                .get_public_key_entry(&source.domain, &source.service, &source.key_id)
                .await?;
            let pem = ybase64_decode(&entry.key)?;
            let now = Instant::now();
            let cached = CachedPolicyPublicKey {
                pem: pem.clone(),
                created_at: now,
                expires_at: now + POLICY_PUBLIC_KEY_CACHE_TTL,
            };
            let mut cache = key_cache.write().await;
            cache.insert(source.clone(), cached);
            enforce_cache_limit(&mut cache, POLICY_PUBLIC_KEY_CACHE_MAX_ENTRIES);
            Ok(pem)
        }
        .await
    };

    let mut locks = fetch_locks.lock().await;
    if let Some(existing) = locks.get(&source) {
        if Arc::ptr_eq(existing, &fetch_lock) && Arc::strong_count(existing) == 2 {
            locks.remove(&source);
        }
    }
    result
}
