use crate::error::Error;
use jsonwebtoken::{Algorithm, Validation};

use crate::jwt::constants::{ATHENZ_ALLOWED_ALGS, ATHENZ_EC_ALGS};
use crate::jwt::types::JwtValidationOptions;

pub(in crate::jwt::validator) fn resolve_allowed_algs(
    options: &JwtValidationOptions,
) -> Result<&[Algorithm], Error> {
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

pub(in crate::jwt::validator) fn apply_validation_options(
    validation: &mut Validation,
    options: &JwtValidationOptions,
) {
    validation.leeway = options.leeway;
    validation.validate_exp = options.validate_exp;
    validation.validate_nbf = options.validate_nbf;
    validation.required_spec_claims = options.required_spec_claims.iter().cloned().collect();
    if let Some(ref issuer) = options.issuer {
        validation.set_issuer(&[issuer.as_str()]);
    }
    if !options.audience.is_empty() {
        validation.set_audience(&options.audience);
    }
    validation.validate_aud = !options.audience.is_empty();
}

pub(in crate::jwt::validator) fn allows_es512(options: &JwtValidationOptions) -> bool {
    if !options.allow_es512 {
        return false;
    }
    ATHENZ_EC_ALGS
        .iter()
        .all(|alg| options.allowed_algs.contains(alg))
}

#[cfg(test)]
mod tests {
    use super::apply_validation_options;
    use crate::jwt::types::JwtValidationOptions;
    use jsonwebtoken::{Algorithm, Validation};
    use std::collections::HashSet;

    #[test]
    fn apply_validation_options_overrides_required_spec_claims() {
        let mut validation = Validation::new(Algorithm::RS256);
        let options = JwtValidationOptions::athenz_default()
            .with_required_spec_claims(["nbf".to_string(), "aud".to_string()]);

        apply_validation_options(&mut validation, &options);

        let expected: HashSet<String> =
            ["nbf".to_string(), "aud".to_string()].into_iter().collect();
        assert_eq!(validation.required_spec_claims, expected);
    }
}
