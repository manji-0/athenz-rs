use super::super::jwks_from_slice_with_report;
use crate::jwt::types::RemovedAlgReason;
use serde_json::json;

#[test]
fn jwks_sanitize_report_removes_unsupported_alg() {
    let jwks_json = json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "key-1",
                "alg": "RS256",
                "n": "sXchbWFrZV9tb2R1bHVz",
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "kid": "key-2",
                "alg": "none",
                "n": "sXchbWFrZV9tb2R1bHVz",
                "e": "AQAB"
            }
        ]
    });
    let body = serde_json::to_vec(&jwks_json).expect("jwks json");
    let report = jwks_from_slice_with_report(&body).expect("report");
    assert_eq!(report.removed_algs.len(), 1);
    assert_eq!(report.removed_algs[0].kid.as_deref(), Some("key-2"));
    assert_eq!(report.removed_algs[0].reason, RemovedAlgReason::Unsupported);

    let key = report
        .jwks
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some("key-2"))
        .expect("key-2");
    assert!(key.common.key_algorithm.is_none());
}
