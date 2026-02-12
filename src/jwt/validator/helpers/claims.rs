use crate::error::Error;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::Validation;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

use super::errors::{jwt_error, jwt_json_error};

#[derive(serde::Deserialize)]
pub(in crate::jwt::validator) struct ClaimsForValidation {
    #[serde(deserialize_with = "numeric_type", default)]
    exp: TryParse<u64>,
    #[serde(deserialize_with = "numeric_type", default)]
    nbf: TryParse<u64>,
    sub: TryParse<String>,
    iss: TryParse<Issuer>,
    aud: TryParse<Audience>,
}

#[derive(Debug, Default)]
pub(in crate::jwt::validator) enum TryParse<T> {
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
pub(in crate::jwt::validator) enum Audience {
    Single(String),
    Multiple(HashSet<String>),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(in crate::jwt::validator) enum Issuer {
    Single(String),
    Multiple(HashSet<String>),
}

pub(in crate::jwt::validator) fn validate_claims(
    claims: &Value,
    options: &Validation,
) -> Result<(), Error> {
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
            if !has_overlap(correct_iss, &iss) {
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
            if !has_overlap(correct_aud, &aud) {
                return Err(jwt_error(ErrorKind::InvalidAudience));
            }
        }
        _ => {}
    }

    Ok(())
}

pub(in crate::jwt::validator) fn has_overlap(
    reference: &HashSet<String>,
    given: &HashSet<String>,
) -> bool {
    if reference.len() < given.len() {
        reference.iter().any(|a| given.contains(a))
    } else {
        given.iter().any(|a| reference.contains(a))
    }
}

pub(in crate::jwt::validator) fn numeric_type<'de, D>(
    deserializer: D,
) -> Result<TryParse<u64>, D::Error>
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
