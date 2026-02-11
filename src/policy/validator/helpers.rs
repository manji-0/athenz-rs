use crate::error::Error;
use crate::models::{PublicKeyEntry, SignedPolicyData};
use crate::ybase64::decode as ybase64_decode;
use crate::zts::ZtsClient;
#[cfg(feature = "async-validate")]
use crate::zts_async::ZtsAsyncClient;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pem::parse_many;
use pkcs8::DecodePublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier as SignatureVerifier;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::PolicyValidatorConfig;

pub(super) struct ZmsSignatureInputs {
    pub(super) key_id: String,
    pub(super) signature: String,
    pub(super) policy_json: String,
}

pub(super) fn zms_signature_inputs(
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

pub(super) fn ensure_not_expired(
    expires: &str,
    config: &PolicyValidatorConfig,
) -> Result<(), Error> {
    let expires_at = OffsetDateTime::parse(expires, &Rfc3339)
        .map_err(|e| Error::Crypto(format!("invalid expires timestamp: {e}")))?;
    let now = OffsetDateTime::now_utc();
    let offset = time::Duration::seconds(config.expiry_offset.as_secs() as i64);
    if now > expires_at - offset {
        return Err(Error::Crypto(format!(
            "policy data is expired on {expires}"
        )));
    }
    Ok(())
}

pub(super) fn parse_jws_protected_header(header: &str) -> Result<JwsProtectedHeader, Error> {
    let decoded = URL_SAFE_NO_PAD
        .decode(header.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws header decode error: {e}")))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&decoded)?;
    Ok(header)
}

pub(super) fn decode_jws_payload(payload: &str) -> Result<SignedPolicyData, Error> {
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws payload decode error: {e}")))?;
    let signed_policy: SignedPolicyData = serde_json::from_slice(&decoded)?;
    Ok(signed_policy)
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct JwsProtectedHeader {
    pub(super) kid: String,
    pub(super) alg: String,
}

pub(super) fn get_public_key_pem(
    zts: &ZtsClient,
    domain: &str,
    service: &str,
    key_id: &str,
) -> Result<Vec<u8>, Error> {
    let entry: PublicKeyEntry = zts.get_public_key_entry(domain, service, key_id)?;
    ybase64_decode(&entry.key)
}

#[cfg(feature = "async-validate")]
pub(super) async fn get_public_key_pem_async(
    zts: &ZtsAsyncClient,
    domain: &str,
    service: &str,
    key_id: &str,
) -> Result<Vec<u8>, Error> {
    let entry: PublicKeyEntry = zts.get_public_key_entry(domain, service, key_id).await?;
    ybase64_decode(&entry.key)
}

pub(super) fn verify_ybase64_signature_sha256(
    message: &str,
    signature: &str,
    public_key_pem: &[u8],
) -> Result<(), Error> {
    let sig_bytes = ybase64_decode(signature)?;
    verify_signature_sha256(message.as_bytes(), &sig_bytes, public_key_pem)
}

pub(super) fn verify_jws_signature(
    alg: &str,
    protected: &str,
    payload: &str,
    signature: &str,
    public_key_pem: &[u8],
) -> Result<(), Error> {
    let signing_input = format!("{protected}.{payload}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature.as_bytes())
        .map_err(|e| Error::Crypto(format!("jws signature decode error: {e}")))?;

    match alg {
        "RS256" => verify_rsa(&signing_input, &sig_bytes, public_key_pem, RsaHash::Sha256),
        "RS384" => verify_rsa(&signing_input, &sig_bytes, public_key_pem, RsaHash::Sha384),
        "RS512" => verify_rsa(&signing_input, &sig_bytes, public_key_pem, RsaHash::Sha512),
        "ES256" => verify_ecdsa(&signing_input, &sig_bytes, public_key_pem, EcdsaCurve::P256),
        "ES384" => verify_ecdsa(&signing_input, &sig_bytes, public_key_pem, EcdsaCurve::P384),
        "ES512" => verify_ecdsa(&signing_input, &sig_bytes, public_key_pem, EcdsaCurve::P521),
        _ => Err(Error::UnsupportedAlg(alg.to_string())),
    }
}

fn verify_signature_sha256(
    message: &[u8],
    signature: &[u8],
    public_key_pem: &[u8],
) -> Result<(), Error> {
    match load_public_key(public_key_pem)? {
        PublicKey::Rsa(key) => {
            let verifier = RsaVerifyingKey::<Sha256>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {e}")))?;
            verifier
                .verify(message, &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {e}")))
        }
        PublicKey::P256(key) => verify_ecdsa_raw(message, signature, EcdsaCurve::P256, key),
        PublicKey::P384(key) => verify_ecdsa_raw(message, signature, EcdsaCurve::P384, key),
        PublicKey::P521(key) => verify_ecdsa_raw(message, signature, EcdsaCurve::P521, key),
    }
}

fn verify_rsa(
    message: &str,
    signature: &[u8],
    public_key_pem: &[u8],
    hash: RsaHash,
) -> Result<(), Error> {
    let key = match load_public_key(public_key_pem)? {
        PublicKey::Rsa(key) => key,
        _ => return Err(Error::Crypto("public key is not RSA".to_string())),
    };
    match hash {
        RsaHash::Sha256 => {
            let verifier = RsaVerifyingKey::<Sha256>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {e}")))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {e}")))
        }
        RsaHash::Sha384 => {
            let verifier = RsaVerifyingKey::<Sha384>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {e}")))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {e}")))
        }
        RsaHash::Sha512 => {
            let verifier = RsaVerifyingKey::<Sha512>::new(key);
            let sig = RsaSignature::try_from(signature)
                .map_err(|e| Error::Crypto(format!("rsa signature error: {e}")))?;
            verifier
                .verify(message.as_bytes(), &sig)
                .map_err(|e| Error::Crypto(format!("rsa verify error: {e}")))
        }
    }
}

fn verify_ecdsa(
    message: &str,
    signature: &[u8],
    public_key_pem: &[u8],
    curve: EcdsaCurve,
) -> Result<(), Error> {
    let key = load_public_key(public_key_pem)?;
    match (curve, key) {
        (EcdsaCurve::P256, PublicKey::P256(key)) => {
            verify_ecdsa_raw(message.as_bytes(), signature, curve, key)
        }
        (EcdsaCurve::P384, PublicKey::P384(key)) => {
            verify_ecdsa_raw(message.as_bytes(), signature, curve, key)
        }
        (EcdsaCurve::P521, PublicKey::P521(key)) => {
            verify_ecdsa_raw(message.as_bytes(), signature, curve, key)
        }
        _ => Err(Error::Crypto("public key curve mismatch".to_string())),
    }
}

fn verify_ecdsa_raw(
    message: &[u8],
    signature: &[u8],
    curve: EcdsaCurve,
    key: impl EcdsaVerifier,
) -> Result<(), Error> {
    let raw = normalize_ecdsa_signature(signature, curve)?;
    key.verify(message, &raw)
}

#[derive(Clone, Copy)]
enum RsaHash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy)]
enum EcdsaCurve {
    P256,
    P384,
    P521,
}

fn normalize_ecdsa_signature(signature: &[u8], curve: EcdsaCurve) -> Result<Vec<u8>, Error> {
    let size = match curve {
        EcdsaCurve::P256 => 32,
        EcdsaCurve::P384 => 48,
        EcdsaCurve::P521 => 66,
    };
    if signature.len() == size * 2 {
        return Ok(signature.to_vec());
    }
    der_to_p1363(signature, size)
}

fn der_to_p1363(signature: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    if signature.len() < 8 || signature[0] != 0x30 {
        return Err(Error::Crypto("invalid der signature".to_string()));
    }
    let (seq_len, mut idx) = read_der_length(signature, 1)?;
    if idx + seq_len > signature.len() {
        return Err(Error::Crypto("invalid der length".to_string()));
    }
    if signature[idx] != 0x02 {
        return Err(Error::Crypto("invalid der signature (r)".to_string()));
    }
    let (r_len, next) = read_der_length(signature, idx + 1)?;
    idx = next;
    if idx + r_len > signature.len() {
        return Err(Error::Crypto(
            "invalid der signature (r length)".to_string(),
        ));
    }
    let r_bytes = &signature[idx..idx + r_len];
    idx += r_len;

    if idx >= signature.len() {
        return Err(Error::Crypto("invalid der signature (s)".to_string()));
    }
    if signature[idx] != 0x02 {
        return Err(Error::Crypto("invalid der signature (s)".to_string()));
    }
    let (s_len, next) = read_der_length(signature, idx + 1)?;
    idx = next;
    if idx + s_len > signature.len() {
        return Err(Error::Crypto(
            "invalid der signature (s length)".to_string(),
        ));
    }
    let s_bytes = &signature[idx..idx + s_len];

    let r = trim_leading_zero(r_bytes);
    let s = trim_leading_zero(s_bytes);
    if r.len() > size || s.len() > size {
        return Err(Error::Crypto("invalid der integer size".to_string()));
    }

    let mut out = vec![0u8; size * 2];
    out[size - r.len()..size].copy_from_slice(r);
    out[size * 2 - s.len()..size * 2].copy_from_slice(s);
    Ok(out)
}

fn read_der_length(data: &[u8], offset: usize) -> Result<(usize, usize), Error> {
    if offset >= data.len() {
        return Err(Error::Crypto("invalid der length".to_string()));
    }
    let first = data[offset];
    if first & 0x80 == 0 {
        return Ok((first as usize, offset + 1));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || offset + 1 + num_bytes > data.len() {
        return Err(Error::Crypto("invalid der length".to_string()));
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | data[offset + 1 + i] as usize;
    }
    Ok((len, offset + 1 + num_bytes))
}

fn trim_leading_zero(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    &bytes[start..]
}

trait EcdsaVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

impl EcdsaVerifier for p256::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p256::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p256 signature error: {e}")))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p256 verify error: {e}")))
    }
}

impl EcdsaVerifier for p384::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p384::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p384 signature error: {e}")))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p384 verify error: {e}")))
    }
}

impl EcdsaVerifier for p521::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("p521 signature error: {e}")))?;
        signature::Verifier::verify(self, message, &sig)
            .map_err(|e| Error::Crypto(format!("p521 verify error: {e}")))
    }
}

#[derive(Clone)]
enum PublicKey {
    Rsa(RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

fn load_public_key(pem_bytes: &[u8]) -> Result<PublicKey, Error> {
    let blocks =
        parse_many(pem_bytes).map_err(|e| Error::Crypto(format!("pem parse error: {e}")))?;
    for block in blocks {
        match block.tag() {
            "RSA PUBLIC KEY" => {
                if let Ok(key) = RsaPublicKey::from_pkcs1_der(block.contents()) {
                    return Ok(PublicKey::Rsa(key));
                }
            }
            "PUBLIC KEY" => {
                if let Ok(key) = RsaPublicKey::from_public_key_der(block.contents()) {
                    return Ok(PublicKey::Rsa(key));
                }
                if let Ok(key) = p256::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p256 public key error: {e}")))?;
                    return Ok(PublicKey::P256(key));
                }
                if let Ok(key) = p384::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p384::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p384 public key error: {e}")))?;
                    return Ok(PublicKey::P384(key));
                }
                if let Ok(key) = p521::PublicKey::from_public_key_der(block.contents()) {
                    let encoded = key.to_encoded_point(false);
                    let key = p521::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .map_err(|e| Error::Crypto(format!("p521 public key error: {e}")))?;
                    return Ok(PublicKey::P521(key));
                }
            }
            _ => {}
        }
    }
    Err(Error::Crypto("unsupported public key format".to_string()))
}

pub(super) fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::new();
            for key in keys {
                let key_json = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\""));
                let val = canonical_json(&map[key]);
                parts.push(format!("{key_json}:{val}"));
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(list) => {
            let mut parts = Vec::new();
            for item in list {
                parts.push(canonical_json(item));
            }
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::String(val) => {
            serde_json::to_string(val).unwrap_or_else(|_| format!("\"{val}\""))
        }
        serde_json::Value::Number(val) => val.to_string(),
        serde_json::Value::Bool(val) => val.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}
