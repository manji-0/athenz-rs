use crate::error::Error;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet, PublicKeyUse};
use p521::ecdsa::VerifyingKey as P521VerifyingKey;
use serde_json::Value;

use super::errors::jwt_error;
use super::parts::base64_url_decode;
use crate::jwt::constants::{MAX_KIDLESS_JWKS_KEYS, NO_COMPATIBLE_JWK_MESSAGE};
use crate::jwt::types::JwtTokenData;

pub(in crate::jwt::validator) fn p521_verifying_key_from_jwk(
    jwk: &jsonwebtoken::jwk::Jwk,
) -> Result<P521VerifyingKey, Error> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => {
            if params.curve != EllipticCurve::P521 {
                return Err(Error::UnsupportedAlg(
                    "ES512 requires P-521 key".to_string(),
                ));
            }
            let x = decode_p521_coord(&params.x)?;
            let y = decode_p521_coord(&params.y)?;
            let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            P521VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| jwt_error(ErrorKind::InvalidEcdsaKey))
        }
        _ => Err(Error::UnsupportedAlg("ES512 requires EC key".to_string())),
    }
}

pub(in crate::jwt::validator) fn is_es512_key_error(err: &Error) -> bool {
    match err {
        Error::UnsupportedAlg(_) => true,
        Error::Jwt(jwt_err) => matches!(jwt_err.kind(), ErrorKind::InvalidEcdsaKey),
        _ => false,
    }
}

pub(in crate::jwt::validator) fn is_rs_key_error(err: &Error) -> bool {
    match err {
        Error::Jwt(jwt_err) => matches!(
            jwt_err.kind(),
            ErrorKind::InvalidKeyFormat
                | ErrorKind::InvalidAlgorithm
                | ErrorKind::InvalidAlgorithmName
                | ErrorKind::InvalidRsaKey(_)
        ),
        _ => false,
    }
}

pub(in crate::jwt::validator) fn is_signature_error(err: &Error) -> bool {
    match err {
        Error::Jwt(jwt_err) => matches!(jwt_err.kind(), ErrorKind::InvalidSignature),
        _ => false,
    }
}

pub(in crate::jwt::validator) fn kidless_no_compatible_jwk(alg: &str) -> Error {
    Error::Crypto(format!("{NO_COMPATIBLE_JWK_MESSAGE} {alg} (kid missing)"))
}

pub(in crate::jwt::validator) fn validate_kidless_jwks<'a, I, F, K>(
    keys: I,
    alg: &str,
    mut try_key: F,
    is_key_error: K,
) -> Result<JwtTokenData<Value>, Error>
where
    I: Iterator<Item = &'a jsonwebtoken::jwk::Jwk>,
    F: FnMut(&'a jsonwebtoken::jwk::Jwk) -> Result<JwtTokenData<Value>, Error>,
    K: Fn(&Error) -> bool,
{
    let mut signature_err = None;
    let mut key_err = None;
    let mut candidates = 0usize;
    for jwk in keys.take(MAX_KIDLESS_JWKS_KEYS) {
        candidates += 1;
        match try_key(jwk) {
            Ok(data) => return Ok(data),
            Err(err) => {
                if is_key_error(&err) {
                    if key_err.is_none() {
                        key_err = Some(err);
                    }
                } else if is_signature_error(&err) {
                    if signature_err.is_none() {
                        signature_err = Some(err);
                    }
                } else {
                    return Err(err);
                }
            }
        }
    }
    if candidates == 0 {
        return Err(kidless_no_compatible_jwk(alg));
    }
    Err(signature_err
        .or(key_err)
        .unwrap_or_else(|| kidless_no_compatible_jwk(alg)))
}

pub(in crate::jwt::validator) fn is_rs_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
}

pub(in crate::jwt::validator) fn is_es512_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    matches!(
        jwk.algorithm,
        AlgorithmParameters::EllipticCurve(ref params) if params.curve == EllipticCurve::P521
    )
}

fn jwk_allows_use(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    match jwk.common.public_key_use.as_ref() {
        None => true,
        Some(PublicKeyUse::Signature) => true,
        Some(_) => false,
    }
}

fn jwk_allows_alg(jwk: &jsonwebtoken::jwk::Jwk, alg: &str) -> bool {
    match jwk.common.key_algorithm.as_ref() {
        None => true,
        Some(key_alg) => key_alg.to_string() == alg,
    }
}

pub(in crate::jwt::validator) fn jwk_matches_constraints(
    jwk: &jsonwebtoken::jwk::Jwk,
    alg: &str,
) -> bool {
    jwk_allows_use(jwk) && jwk_allows_alg(jwk, alg)
}

pub(in crate::jwt::validator) fn decode_p521_coord(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = base64_url_decode(value).map_err(|_| jwt_error(ErrorKind::InvalidEcdsaKey))?;
    const P521_COORD_SIZE: usize = 66;
    if bytes.len() > P521_COORD_SIZE {
        return Err(jwt_error(ErrorKind::InvalidEcdsaKey));
    }
    if bytes.len() == P521_COORD_SIZE {
        return Ok(bytes);
    }
    let mut padded = vec![0u8; P521_COORD_SIZE - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

pub(in crate::jwt::validator) fn select_jwk<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
    alg: &str,
) -> Result<&'a jsonwebtoken::jwk::Jwk, Error> {
    if let Some(kid) = kid {
        if let Some(jwk) = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid) && jwk_matches_constraints(k, alg))
        {
            return Ok(jwk);
        }
        return Err(Error::MissingJwk(kid.to_string()));
    }

    if jwks.keys.len() == 1 {
        if jwk_matches_constraints(&jwks.keys[0], alg) {
            return Ok(&jwks.keys[0]);
        }
        return Err(kidless_no_compatible_jwk(alg));
    }

    Err(Error::MissingJwk("kid required".to_string()))
}
