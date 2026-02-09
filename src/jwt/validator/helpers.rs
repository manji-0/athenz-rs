use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use jsonwebtoken::{Algorithm, Validation};
use p521::ecdsa::VerifyingKey as P521VerifyingKey;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use super::super::constants::{
    ATHENZ_ALLOWED_ALGS, ATHENZ_ALLOWED_JWT_TYPES, ATHENZ_EC_ALGS, MAX_KIDLESS_JWKS_KEYS,
    NO_COMPATIBLE_JWK_MESSAGE,
};
use super::super::types::{JwtHeader, JwtTokenData, JwtValidationOptions};

pub(super) fn resolve_allowed_algs(options: &JwtValidationOptions) -> Result<&[Algorithm], Error> {
    if options.allowed_algs.is_empty() {
        return Err(Error::UnsupportedAlg(
            "no allowed algorithms configured".to_string(),
        ));
    }
    for alg in &options.allowed_algs {
        if !ATHENZ_ALLOWED_ALGS.contains(alg) {
            return Err(Error::UnsupportedAlg(format!("{alg:?}")));
        }
    }
    Ok(&options.allowed_algs)
}

pub(super) fn apply_validation_options(
    validation: &mut Validation,
    options: &JwtValidationOptions,
) {
    validation.leeway = options.leeway;
    validation.validate_exp = options.validate_exp;
    if let Some(ref issuer) = options.issuer {
        validation.set_issuer(&[issuer.as_str()]);
    }
    if !options.audience.is_empty() {
        validation.set_audience(&options.audience);
    }
    validation.validate_aud = !options.audience.is_empty();
}

pub(super) fn allows_es512(options: &JwtValidationOptions) -> bool {
    if !options.allow_es512 {
        return false;
    }
    ATHENZ_EC_ALGS
        .iter()
        .all(|alg| options.allowed_algs.contains(alg))
}

pub(super) struct JwtParts<'a> {
    pub(super) header: &'a str,
    pub(super) payload: &'a str,
    pub(super) signature: &'a str,
}

pub(super) fn split_jwt(token: &str) -> Result<JwtParts<'_>, Error> {
    let mut iter = token.split('.');
    let header = iter
        .next()
        .ok_or_else(|| jwt_error(ErrorKind::InvalidToken))?;
    let payload = iter
        .next()
        .ok_or_else(|| jwt_error(ErrorKind::InvalidToken))?;
    let signature = iter
        .next()
        .ok_or_else(|| jwt_error(ErrorKind::InvalidToken))?;
    if iter.next().is_some() {
        return Err(jwt_error(ErrorKind::InvalidToken));
    }
    Ok(JwtParts {
        header,
        payload,
        signature,
    })
}

pub(super) fn decode_jwt_header(encoded: &str) -> Result<JwtHeader, Error> {
    let header_bytes = base64_url_decode(encoded)?;
    let raw: Value = serde_json::from_slice(&header_bytes).map_err(jwt_json_error)?;
    let alg = raw
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| jwt_error(ErrorKind::InvalidToken))?;
    let kid = raw
        .get("kid")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let typ = match raw.get("typ") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.to_string()),
        Some(_) => return Err(jwt_error(ErrorKind::InvalidToken)),
    };
    Ok(JwtHeader {
        alg: alg.to_string(),
        kid,
        typ,
        raw,
    })
}

pub(super) fn validate_jwt_typ(typ: Option<&str>) -> Result<(), Error> {
    let Some(typ) = typ else {
        return Ok(());
    };
    if ATHENZ_ALLOWED_JWT_TYPES
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(typ))
    {
        return Ok(());
    }
    Err(jwt_error(ErrorKind::InvalidToken))
}

pub(super) fn base64_url_decode(data: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|err| Error::Crypto(format!("base64url decode error: {err}")))
}

pub(super) fn p521_verifying_key_from_jwk(
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

pub(super) fn is_es512_key_error(err: &Error) -> bool {
    match err {
        Error::UnsupportedAlg(_) => true,
        Error::Jwt(jwt_err) => matches!(jwt_err.kind(), ErrorKind::InvalidEcdsaKey),
        _ => false,
    }
}

pub(super) fn is_rs_key_error(err: &Error) -> bool {
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

pub(super) fn is_signature_error(err: &Error) -> bool {
    match err {
        Error::Jwt(jwt_err) => matches!(jwt_err.kind(), ErrorKind::InvalidSignature),
        _ => false,
    }
}

pub(super) fn kidless_no_compatible_jwk(alg: &str) -> Error {
    Error::Crypto(format!("{NO_COMPATIBLE_JWK_MESSAGE} {alg} (kid missing)"))
}

pub(super) fn validate_kidless_jwks<'a, I, F, K>(
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

pub(super) fn is_rs_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
}

pub(super) fn is_es512_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    matches!(
        jwk.algorithm,
        AlgorithmParameters::EllipticCurve(ref params) if params.curve == EllipticCurve::P521
    )
}

pub(super) fn decode_p521_coord(value: &str) -> Result<Vec<u8>, Error> {
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

pub(super) fn jwt_error(kind: ErrorKind) -> Error {
    Error::Jwt(kind.into())
}

pub(super) fn jwt_json_error(err: serde_json::Error) -> Error {
    Error::Jwt(ErrorKind::Json(Arc::new(err)).into())
}

#[derive(serde::Deserialize)]
pub(super) struct ClaimsForValidation {
    #[serde(deserialize_with = "numeric_type", default)]
    exp: TryParse<u64>,
    #[serde(deserialize_with = "numeric_type", default)]
    nbf: TryParse<u64>,
    sub: TryParse<String>,
    iss: TryParse<Issuer>,
    aud: TryParse<Audience>,
}

#[derive(Debug, Default)]
pub(super) enum TryParse<T> {
    Parsed(T),
    FailedToParse,
    #[default]
    NotPresent,
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for TryParse<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(deserializer) {
            Ok(Some(value)) => TryParse::Parsed(value),
            Ok(None) => TryParse::NotPresent,
            Err(_) => TryParse::FailedToParse,
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum Audience {
    Single(String),
    Multiple(HashSet<String>),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum Issuer {
    Single(String),
    Multiple(HashSet<String>),
}

pub(super) fn validate_claims(claims: &Value, options: &Validation) -> Result<(), Error> {
    let claims: ClaimsForValidation =
        serde::Deserialize::deserialize(claims).map_err(jwt_json_error)?;

    for required_claim in &options.required_spec_claims {
        let present = match required_claim.as_str() {
            "exp" => matches!(claims.exp, TryParse::Parsed(_)),
            "sub" => matches!(claims.sub, TryParse::Parsed(_)),
            "iss" => matches!(claims.iss, TryParse::Parsed(_)),
            "aud" => matches!(claims.aud, TryParse::Parsed(_)),
            "nbf" => matches!(claims.nbf, TryParse::Parsed(_)),
            _ => continue,
        };

        if !present {
            return Err(jwt_error(ErrorKind::MissingRequiredClaim(
                required_claim.clone(),
            )));
        }
    }

    if options.validate_exp || options.validate_nbf {
        let now = jsonwebtoken::get_current_timestamp();
        if matches!(claims.exp, TryParse::Parsed(exp) if options.validate_exp
            && exp.saturating_sub(options.reject_tokens_expiring_in_less_than) < now.saturating_sub(options.leeway))
        {
            return Err(jwt_error(ErrorKind::ExpiredSignature));
        }

        if matches!(claims.nbf, TryParse::Parsed(nbf) if options.validate_nbf && nbf > now + options.leeway)
        {
            return Err(jwt_error(ErrorKind::ImmatureSignature));
        }
    }

    if let (TryParse::Parsed(sub), Some(correct_sub)) = (claims.sub, options.sub.as_deref()) {
        if sub != correct_sub {
            return Err(jwt_error(ErrorKind::InvalidSubject));
        }
    }

    match (claims.iss, options.iss.as_ref()) {
        (TryParse::Parsed(Issuer::Single(iss)), Some(correct_iss)) => {
            if !correct_iss.contains(&iss) {
                return Err(jwt_error(ErrorKind::InvalidIssuer));
            }
        }
        (TryParse::Parsed(Issuer::Multiple(iss)), Some(correct_iss)) => {
            if !is_subset(correct_iss, &iss) {
                return Err(jwt_error(ErrorKind::InvalidIssuer));
            }
        }
        _ => {}
    }

    if !options.validate_aud {
        return Ok(());
    }
    match (claims.aud, options.aud.as_ref()) {
        (TryParse::Parsed(_), None) => {
            return Err(jwt_error(ErrorKind::InvalidAudience));
        }
        (TryParse::Parsed(Audience::Single(aud)), Some(correct_aud)) => {
            if !correct_aud.contains(&aud) {
                return Err(jwt_error(ErrorKind::InvalidAudience));
            }
        }
        (TryParse::Parsed(Audience::Multiple(aud)), Some(correct_aud)) => {
            if !is_subset(correct_aud, &aud) {
                return Err(jwt_error(ErrorKind::InvalidAudience));
            }
        }
        _ => {}
    }

    Ok(())
}

pub(super) fn is_subset(reference: &HashSet<String>, given: &HashSet<String>) -> bool {
    if reference.len() < given.len() {
        reference.iter().any(|a| given.contains(a))
    } else {
        given.iter().any(|a| reference.contains(a))
    }
}

pub(super) fn numeric_type<'de, D>(deserializer: D) -> Result<TryParse<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NumericType;

    impl<'de> serde::de::Visitor<'de> for NumericType {
        type Value = TryParse<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a numeric value representable as u64")
        }

        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.is_finite() && value >= 0.0 && value < (u64::MAX as f64) {
                Ok(TryParse::Parsed(value.round() as u64))
            } else {
                Err(serde::de::Error::custom(
                    "numeric value must be representable as u64",
                ))
            }
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(TryParse::Parsed(value))
        }
    }

    match deserializer.deserialize_any(NumericType) {
        Ok(ok) => Ok(ok),
        Err(_) => Ok(TryParse::FailedToParse),
    }
}

pub(super) fn select_jwk<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
) -> Result<&'a jsonwebtoken::jwk::Jwk, Error> {
    if let Some(kid) = kid {
        if let Some(jwk) = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
        {
            return Ok(jwk);
        }
        return Err(Error::MissingJwk(kid.to_string()));
    }

    if jwks.keys.len() == 1 {
        return Ok(&jwks.keys[0]);
    }

    Err(Error::MissingJwk("kid required".to_string()))
}
