use crate::error::Error;
use crate::models::SignedPolicyData;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::super::PolicyValidatorConfig;
use super::canonical::canonical_json;

pub(in crate::policy::validator) struct ZmsSignatureInputs {
    pub(in crate::policy::validator) key_id: String,
    pub(in crate::policy::validator) signature: String,
    pub(in crate::policy::validator) policy_json: String,
}

pub(in crate::policy::validator) fn zms_signature_inputs(
    signed_policy: &SignedPolicyData,
    config: &PolicyValidatorConfig,
) -> Result<Option<ZmsSignatureInputs>, Error> {
    if !config.check_zms_signature {
        return Ok(None);
    }
    let zms_signature = signed_policy.zms_signature.as_deref().unwrap_or("");
    let zms_key_id = signed_policy.zms_key_id.as_deref().unwrap_or("");
    if zms_signature.is_empty() || zms_key_id.is_empty() {
        return Err(Error::Crypto("missing zms signature or key id".to_string()));
    }
    let policy_json = canonical_json(&serde_json::to_value(&signed_policy.policy_data)?);
    Ok(Some(ZmsSignatureInputs {
        key_id: zms_key_id.to_string(),
        signature: zms_signature.to_string(),
        policy_json,
    }))
}

pub(in crate::policy::validator) fn ensure_not_expired(
    expires: &str,
    config: &PolicyValidatorConfig,
) -> Result<(), Error> {
    let expires_at = OffsetDateTime::parse(expires, &Rfc3339)
        .map_err(|e| Error::Crypto(format!("invalid expires timestamp: {e}")))?;
    let now = OffsetDateTime::now_utc();
    let expiry_offset_secs = config.expiry_offset.as_secs();
    let offset_seconds = expiry_offset_secs.min(i64::MAX as u64) as i64;
    let offset = time::Duration::seconds(offset_seconds);
    if now > expires_at - offset {
        return Err(Error::Crypto(format!(
            "policy data is expired on {expires}"
        )));
    }
    Ok(())
}
