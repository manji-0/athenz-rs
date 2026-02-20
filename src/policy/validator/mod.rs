mod helpers;
#[cfg(test)]
mod tests;

use crate::error::Error;
use crate::models::{DomainSignedPolicyData, JWSPolicyData, PolicyData};
use crate::zts::ZtsClient;
#[cfg(feature = "async-validate")]
use crate::zts_async::ZtsAsyncClient;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
#[cfg(feature = "async-validate")]
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

use super::PolicyValidatorConfig;
#[cfg(feature = "async-validate")]
use helpers::get_public_key_pem_async;
use helpers::{
    decode_jws_payload, ensure_not_expired, get_public_key_pem, parse_jws_protected_header,
    verify_jws_signature, verify_ybase64_signature_sha256, zms_signature_inputs,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PolicyPublicKeySource {
    pub(super) domain: String,
    pub(super) service: String,
    pub(super) key_id: String,
}

#[derive(Clone)]
pub(super) struct CachedPolicyPublicKey {
    pub(super) pem: Vec<u8>,
    pub(super) created_at: Instant,
    pub(super) expires_at: Instant,
}

pub(super) type PolicyPublicKeyCache =
    RwLock<HashMap<PolicyPublicKeySource, CachedPolicyPublicKey>>;
pub(super) type PolicyPublicKeyFetchLocks = Mutex<HashMap<PolicyPublicKeySource, Arc<Mutex<()>>>>;

#[cfg(feature = "async-validate")]
pub(super) type PolicyPublicKeyCacheAsync =
    AsyncRwLock<HashMap<PolicyPublicKeySource, CachedPolicyPublicKey>>;
#[cfg(feature = "async-validate")]
pub(super) type PolicyPublicKeyFetchLocksAsync =
    AsyncMutex<HashMap<PolicyPublicKeySource, Arc<AsyncMutex<()>>>>;

pub(super) fn validate_signed_policy_data(
    data: &DomainSignedPolicyData,
    zts: &ZtsClient,
    config: &PolicyValidatorConfig,
    key_cache: &PolicyPublicKeyCache,
    fetch_locks: &PolicyPublicKeyFetchLocks,
) -> Result<PolicyData, Error> {
    let signed_policy = &data.signed_policy_data;

    ensure_not_expired(&signed_policy.expires, config)?;

    let zts_key_pem = get_public_key_pem(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &data.key_id,
        key_cache,
        fetch_locks,
    )?;
    let signed_json = helpers::canonical_json(&serde_json::to_value(signed_policy)?);
    verify_ybase64_signature_sha256(&signed_json, &data.signature, &zts_key_pem)?;

    if let Some(inputs) = zms_signature_inputs(signed_policy, config)? {
        let zms_key_pem = get_public_key_pem(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            &inputs.key_id,
            key_cache,
            fetch_locks,
        )?;
        verify_ybase64_signature_sha256(&inputs.policy_json, &inputs.signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data.clone())
}

pub(super) fn validate_jws_policy_data(
    data: &JWSPolicyData,
    zts: &ZtsClient,
    config: &PolicyValidatorConfig,
    key_cache: &PolicyPublicKeyCache,
    fetch_locks: &PolicyPublicKeyFetchLocks,
) -> Result<PolicyData, Error> {
    let header = parse_jws_protected_header(&data.protected_header)?;
    let zts_key_pem = get_public_key_pem(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &header.kid,
        key_cache,
        fetch_locks,
    )?;

    verify_jws_signature(
        &header.alg,
        &data.protected_header,
        &data.payload,
        &data.signature,
        &zts_key_pem,
    )?;

    let signed_policy = decode_jws_payload(&data.payload)?;
    ensure_not_expired(&signed_policy.expires, config)?;

    if let Some(inputs) = zms_signature_inputs(&signed_policy, config)? {
        let zms_key_pem = get_public_key_pem(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            &inputs.key_id,
            key_cache,
            fetch_locks,
        )?;
        verify_ybase64_signature_sha256(&inputs.policy_json, &inputs.signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data)
}

#[cfg(feature = "async-validate")]
pub(super) async fn validate_signed_policy_data_async(
    data: &DomainSignedPolicyData,
    zts: &ZtsAsyncClient,
    config: &PolicyValidatorConfig,
    key_cache: &PolicyPublicKeyCacheAsync,
    fetch_locks: &PolicyPublicKeyFetchLocksAsync,
) -> Result<PolicyData, Error> {
    let signed_policy = &data.signed_policy_data;

    ensure_not_expired(&signed_policy.expires, config)?;

    let zts_key_pem = get_public_key_pem_async(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &data.key_id,
        key_cache,
        fetch_locks,
    )
    .await?;
    let signed_json = helpers::canonical_json(&serde_json::to_value(signed_policy)?);
    verify_ybase64_signature_sha256(&signed_json, &data.signature, &zts_key_pem)?;

    if let Some(inputs) = zms_signature_inputs(signed_policy, config)? {
        let zms_key_pem = get_public_key_pem_async(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            &inputs.key_id,
            key_cache,
            fetch_locks,
        )
        .await?;
        verify_ybase64_signature_sha256(&inputs.policy_json, &inputs.signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data.clone())
}

#[cfg(feature = "async-validate")]
pub(super) async fn validate_jws_policy_data_async(
    data: &JWSPolicyData,
    zts: &ZtsAsyncClient,
    config: &PolicyValidatorConfig,
    key_cache: &PolicyPublicKeyCacheAsync,
    fetch_locks: &PolicyPublicKeyFetchLocksAsync,
) -> Result<PolicyData, Error> {
    let header = parse_jws_protected_header(&data.protected_header)?;
    let zts_key_pem = get_public_key_pem_async(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &header.kid,
        key_cache,
        fetch_locks,
    )
    .await?;

    verify_jws_signature(
        &header.alg,
        &data.protected_header,
        &data.payload,
        &data.signature,
        &zts_key_pem,
    )?;

    let signed_policy = decode_jws_payload(&data.payload)?;
    ensure_not_expired(&signed_policy.expires, config)?;

    if let Some(inputs) = zms_signature_inputs(&signed_policy, config)? {
        let zms_key_pem = get_public_key_pem_async(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            &inputs.key_id,
            key_cache,
            fetch_locks,
        )
        .await?;
        verify_ybase64_signature_sha256(&inputs.policy_json, &inputs.signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data)
}
