use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier as SignatureVerifier;

use super::pem::{load_public_key, EcdsaVerifier, PublicKey};

pub(in crate::policy::validator) fn verify_ybase64_signature_sha256(
    message: &str,
    signature: &str,
    public_key_pem: &[u8],
) -> Result<(), Error> {
    let sig_bytes = crate::ybase64::decode(signature)?;
    verify_signature_sha256(message.as_bytes(), &sig_bytes, public_key_pem)
}

pub(in crate::policy::validator) fn verify_jws_signature(
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
