use crate::error::Error;
use std::time::Duration;

use super::super::token::{unix_time_now, NToken};
use super::options::NTokenValidationOptions;

pub(super) fn validate_ip_hostname(
    claims: &NToken,
    options: &NTokenValidationOptions,
) -> Result<(), Error> {
    if let Some(expected) = options.hostname() {
        match claims.hostname.as_deref() {
            Some(actual) if hostname_matches(expected, actual) => {}
            Some(actual) => {
                return Err(Error::Crypto(format!(
                    "ntoken hostname mismatch: expected {expected}, got {actual}"
                )));
            }
            None => return Err(Error::Crypto("ntoken missing hostname".to_string())),
        }
    }

    if let Some(expected) = options.ip() {
        match claims.ip.as_deref() {
            Some(actual) if ip_matches(expected, actual) => {}
            Some(actual) => {
                return Err(Error::Crypto(format!(
                    "ntoken ip mismatch: expected {expected}, got {actual}"
                )));
            }
            None => return Err(Error::Crypto("ntoken missing ip".to_string())),
        }
    }

    Ok(())
}

pub(super) fn validate_version_domain(claims: &NToken) -> Result<(), Error> {
    let is_user_version = claims
        .version
        .chars()
        .next()
        .map(|c| c.eq_ignore_ascii_case(&'U'))
        .unwrap_or(false);
    let is_user_domain = claims.domain == "user";

    if is_user_version && !is_user_domain {
        return Err(Error::Crypto(format!(
            "ntoken user version requires domain 'user' (domain={}, version={})",
            claims.domain, claims.version
        )));
    }

    if is_user_domain && !is_user_version {
        return Err(Error::Crypto(format!(
            "ntoken domain 'user' requires user version (domain={}, version={})",
            claims.domain, claims.version
        )));
    }

    Ok(())
}

pub(super) fn validate_time_bounds(
    claims: &NToken,
    options: &NTokenValidationOptions,
) -> Result<(), Error> {
    let now = unix_time_now();
    let allowed_offset = duration_to_i64(options.allowed_offset());

    // generation_time is required by parsing, but keep a defensive guard for
    // manually constructed claims.
    if claims.generation_time != 0 && claims.generation_time.saturating_sub(allowed_offset) > now {
        return Err(Error::Crypto(format!(
            "ntoken has future timestamp: generation_time={} now={} allowed_offset={}",
            claims.generation_time, now, allowed_offset
        )));
    }

    let max_expiry = duration_to_i64(options.max_expiry());
    let latest_expiry = now
        .saturating_add(max_expiry)
        .saturating_add(allowed_offset);
    if claims.expiry_time > latest_expiry {
        return Err(Error::Crypto(format!(
            "ntoken expires too far in the future: expiry_time={} now={} max_expiry={} allowed_offset={}",
            claims.expiry_time, now, max_expiry, allowed_offset
        )));
    }

    Ok(())
}

pub(super) fn validate_authorized_service_claims(
    claims: &NToken,
    options: &NTokenValidationOptions,
) -> Result<(), Error> {
    if let Some(expected_service) = options.authorized_service() {
        let authorized = claims
            .authorized_services
            .as_deref()
            .is_some_and(|services| services.iter().any(|service| service == expected_service));
        if !authorized {
            return Err(Error::Crypto(format!(
                "ntoken not authorized for service: {expected_service}"
            )));
        }
    }

    let has_authorized_services = claims.authorized_services.is_some();
    let has_re_signature = claims.authorized_service_signature.is_some()
        || claims.authorized_service_key_id.is_some()
        || claims.authorized_service_name.is_some();
    let has_full_re_signature = claims.authorized_service_signature.is_some()
        && claims.authorized_service_key_id.is_some()
        && claims.authorized_service_name.is_some();
    if has_re_signature && !has_full_re_signature {
        return Err(Error::Crypto(
            "ntoken has incomplete authorized-service re-signature fields".to_string(),
        ));
    }
    if claims.authorized_service_signature.is_some() && !has_authorized_services {
        return Err(Error::Crypto(
            "ntoken has re-signed authorized services without service list".to_string(),
        ));
    }

    Ok(())
}

fn duration_to_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn hostname_matches(expected: &str, actual: &str) -> bool {
    let expected = expected.trim_end_matches('.');
    let actual = actual.trim_end_matches('.');
    expected.eq_ignore_ascii_case(actual)
}

fn ip_matches(expected: &str, actual: &str) -> bool {
    use std::net::IpAddr;

    match (expected.parse::<IpAddr>(), actual.parse::<IpAddr>()) {
        (Ok(expected), Ok(actual)) => expected == actual,
        _ => expected == actual,
    }
}
