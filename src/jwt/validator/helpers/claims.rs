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

pub(in crate::jwt::validator) fn is_subset(
    reference: &HashSet<String>,
    given: &HashSet<String>,
) -> bool {
    !given.is_empty() && given.iter().all(|value| reference.contains(value))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::validate_claims;
    use crate::error::Error;
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{Algorithm, Validation};
    use serde_json::json;

    fn assert_invalid_claim(err: Error, kind: ErrorKind) {
        match err {
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &kind),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    fn base_validation() -> Validation {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation
    }

    #[test]
    fn issuer_list_must_be_subset_of_allowed_issuers() {
        let mut validation = base_validation();
        validation.set_issuer(&["trusted"]);
        let claims = json!({
            "iss": ["trusted", "evil"],
            "sub": "principal",
        });

        let err = validate_claims(&claims, &validation).expect_err("issuer must be rejected");
        assert_invalid_claim(err, ErrorKind::InvalidIssuer);
    }

    #[test]
    fn issuer_list_subset_is_allowed() {
        let mut validation = base_validation();
        validation.set_issuer(&["trusted", "backup"]);
        let claims = json!({
            "iss": ["trusted"],
            "sub": "principal",
        });

        validate_claims(&claims, &validation).expect("issuer subset should be allowed");
    }

    #[test]
    fn issuer_list_empty_is_rejected() {
        let mut validation = base_validation();
        validation.set_issuer(&["trusted"]);
        let claims = json!({
            "iss": [],
            "sub": "principal",
        });

        let err = validate_claims(&claims, &validation).expect_err("empty issuer list rejected");
        assert_invalid_claim(err, ErrorKind::InvalidIssuer);
    }

    #[test]
    fn audience_list_must_be_subset_of_allowed_audience() {
        let mut validation = base_validation();
        validation.set_audience(&["client"]);
        validation.validate_aud = true;
        let claims = json!({
            "aud": ["client", "evil"],
            "sub": "principal",
        });

        let err = validate_claims(&claims, &validation).expect_err("audience must be rejected");
        assert_invalid_claim(err, ErrorKind::InvalidAudience);
    }

    #[test]
    fn audience_list_subset_is_allowed() {
        let mut validation = base_validation();
        validation.set_audience(&["client", "backup"]);
        validation.validate_aud = true;
        let claims = json!({
            "aud": ["client"],
            "sub": "principal",
        });

        validate_claims(&claims, &validation).expect("audience subset should be allowed");
    }

    #[test]
    fn audience_list_empty_is_rejected() {
        let mut validation = base_validation();
        validation.set_audience(&["client"]);
        validation.validate_aud = true;
        let claims = json!({
            "aud": [],
            "sub": "principal",
        });

        let err = validate_claims(&claims, &validation).expect_err("empty audience list rejected");
        assert_invalid_claim(err, ErrorKind::InvalidAudience);
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
