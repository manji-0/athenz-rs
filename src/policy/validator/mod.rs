mod helpers;
#[cfg(test)]
mod tests;

use crate::error::Error;
use crate::models::{DomainSignedPolicyData, JWSPolicyData, PolicyData};
use crate::zts::ZtsClient;
#[cfg(feature = "async-validate")]
use crate::zts_async::ZtsAsyncClient;

use super::PolicyValidatorConfig;
#[cfg(feature = "async-validate")]
use helpers::get_public_key_pem_async;
use helpers::{
    decode_jws_payload, ensure_not_expired, get_public_key_pem, parse_jws_protected_header,
    verify_jws_signature, verify_ybase64_signature_sha256, zms_signature_inputs,
};

pub(super) fn validate_signed_policy_data(
    data: &DomainSignedPolicyData,
    zts: &ZtsClient,
    config: &PolicyValidatorConfig,
) -> Result<PolicyData, Error> {
    let signed_policy = &data.signed_policy_data;

    ensure_not_expired(&signed_policy.expires, config)?;

    let zts_key_pem = get_public_key_pem(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &data.key_id,
    )?;
    let signed_json = helpers::canonical_json(&serde_json::to_value(signed_policy)?);
    verify_ybase64_signature_sha256(&signed_json, &data.signature, &zts_key_pem)?;

    if let Some(inputs) = zms_signature_inputs(signed_policy, config)? {
        let zms_key_pem = get_public_key_pem(
            zts,
            &config.sys_auth_domain,
            &config.zms_service,
            &inputs.key_id,
        )?;
        verify_ybase64_signature_sha256(&inputs.policy_json, &inputs.signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data.clone())
}

pub(super) fn validate_jws_policy_data(
    data: &JWSPolicyData,
    zts: &ZtsClient,
    config: &PolicyValidatorConfig,
) -> Result<PolicyData, Error> {
    let header = parse_jws_protected_header(&data.protected_header)?;
    let zts_key_pem = get_public_key_pem(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &header.kid,
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
) -> Result<PolicyData, Error> {
    let signed_policy = &data.signed_policy_data;

    ensure_not_expired(&signed_policy.expires, config)?;

    let zts_key_pem = get_public_key_pem_async(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &data.key_id,
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
) -> Result<PolicyData, Error> {
    let header = parse_jws_protected_header(&data.protected_header)?;
    let zts_key_pem = get_public_key_pem_async(
        zts,
        &config.sys_auth_domain,
        &config.zts_service,
        &header.kid,
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
        )
        .await?;
        verify_ybase64_signature_sha256(&inputs.policy_json, &inputs.signature, &zms_key_pem)?;
    }

    Ok(signed_policy.policy_data)
}
