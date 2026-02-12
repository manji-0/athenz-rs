use crate::error::Error;
use jsonwebtoken::jwk::JwkSet;
use log::warn;
use serde_json::Value;
use url::Url;

use super::super::constants::SUPPORTED_JWK_ALGS;
use super::super::types::{JwksSanitizeReport, RemovedAlg, RemovedAlgReason};

pub(super) fn sanitize_error_body(body: &[u8]) -> String {
    let mut sanitized = String::new();
    for &byte in body.iter().take(128) {
        let ch = match byte {
            b'\n' => '\\',
            b'\r' => '\\',
            b'\t' => '\\',
            _ if byte.is_ascii_graphic() || byte == b' ' => byte as char,
            _ => '.',
        };
        if ch == '\\' {
            sanitized.push('\\');
            sanitized.push(match byte {
                b'\n' => 'n',
                b'\r' => 'r',
                b'\t' => 't',
                _ => '\\',
            });
        } else {
            sanitized.push(ch);
        }
    }
    if body.len() > 128 {
        sanitized.push_str("...");
    }
    sanitized
}

pub(super) fn redact_jwks_uri(uri: &Url) -> String {
    let mut redacted = uri.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

pub fn jwks_from_slice(body: &[u8]) -> Result<JwkSet, Error> {
    let report = jwks_from_slice_with_report(body)?;
    Ok(report.jwks)
}

pub fn jwks_from_slice_with_report(body: &[u8]) -> Result<JwksSanitizeReport, Error> {
    let mut value: Value = serde_json::from_slice(body)?;
    let removed_algs = sanitize_jwks(&mut value);
    let jwks: JwkSet = serde_json::from_value(value).map_err(Error::from)?;
    Ok(JwksSanitizeReport { jwks, removed_algs })
}

pub(super) fn sanitize_jwks(value: &mut Value) -> Vec<RemovedAlg> {
    let Some(keys) = value.get_mut("keys").and_then(Value::as_array_mut) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for key in keys {
        let Some(object) = key.as_object_mut() else {
            continue;
        };
        let Some(alg_value) = object.get("alg").cloned() else {
            continue;
        };
        let kid = object
            .get("kid")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let alg = match alg_value.as_str() {
            Some(alg) => alg,
            None => {
                warn!(
                    "jwks key alg is not a string; kid={}",
                    kid.as_deref().unwrap_or("<none>")
                );
                object.remove("alg");
                removed.push(RemovedAlg {
                    kid,
                    alg: None,
                    reason: RemovedAlgReason::NotString,
                });
                continue;
            }
        };
        if !SUPPORTED_JWK_ALGS.contains(&alg) {
            warn!(
                "jwks key alg unsupported; kid={}, alg={}",
                kid.as_deref().unwrap_or("<none>"),
                alg
            );
            object.remove("alg");
            removed.push(RemovedAlg {
                kid,
                alg: Some(alg.to_string()),
                reason: RemovedAlgReason::Unsupported,
            });
        }
    }
    removed
}
