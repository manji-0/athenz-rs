use crate::error::Error;
use crate::models::SignedPolicyData;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

#[derive(Debug, serde::Deserialize)]
pub(in crate::policy::validator) struct JwsProtectedHeader {
    pub(in crate::policy::validator) kid: String,
    pub(in crate::policy::validator) alg: String,
}

pub(in crate::policy::validator) fn parse_jws_protected_header(
    header: &str,
) -> Result<JwsProtectedHeader, Error> {
    let decoded = URL_SAFE_NO_PAD
        .decode(header.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws header decode error: {e}")))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&decoded)?;
    Ok(header)
}

pub(in crate::policy::validator) fn decode_jws_payload(
    payload: &str,
) -> Result<SignedPolicyData, Error> {
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws payload decode error: {e}")))?;
    let signed_policy: SignedPolicyData = serde_json::from_slice(&decoded)?;
    Ok(signed_policy)
}
