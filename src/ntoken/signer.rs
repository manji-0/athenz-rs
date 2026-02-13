use crate::error::Error;
use std::sync::RwLock;

use super::keys::load_private_key;
use super::keys::PrivateKey;
use super::token::{sign_with_key, unix_time_now, NTokenBuilder, EXPIRATION_DRIFT};

pub struct NTokenSigner {
    builder: NTokenBuilder,
    key: PrivateKey,
    cached: RwLock<Option<CachedToken>>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expiry_time: i64,
}

impl NTokenSigner {
    /// Creates a signer for the given principal and private key.
    pub fn new(
        domain: impl Into<String>,
        name: impl Into<String>,
        key_version: impl Into<String>,
        private_key_pem: &[u8],
    ) -> Result<Self, Error> {
        let key = load_private_key(private_key_pem)?;
        Ok(Self {
            builder: NTokenBuilder::new(domain, name, key_version),
            key,
            cached: RwLock::new(None),
        })
    }

    /// Returns a mutable reference to the underlying `NTokenBuilder`.
    ///
    /// Calling this method will invalidate any cached token by clearing the
    /// internal cache, even if the returned builder is not subsequently mutated.
    /// Any later call to [`Self::token`] will recompute and recache a new token.
    pub fn builder_mut(&mut self) -> &mut NTokenBuilder {
        *self
            .cached
            .write()
            .expect("ntoken signer cache lock poisoned") = None;
        &mut self.builder
    }

    /// Returns a cached token when valid, otherwise signs a new token.
    pub fn token(&self) -> Result<String, Error> {
        if let Some(cached) = self.cached.read().unwrap().as_ref() {
            let now = unix_time_now();
            if now + EXPIRATION_DRIFT.as_secs() as i64 <= cached.expiry_time {
                return Ok(cached.token.clone());
            }
        }

        let token = self.sign_once()?;
        Ok(token)
    }

    /// Signs a fresh token and updates the cache.
    pub fn sign_once(&self) -> Result<String, Error> {
        let (token, expiry) = sign_with_key(&self.builder, &self.key)?;
        let cached = CachedToken {
            token: token.clone(),
            expiry_time: expiry,
        };
        *self.cached.write().unwrap() = Some(cached);
        Ok(token)
    }
}
