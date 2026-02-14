use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use serde_json::Value;

use super::errors::{jwt_error, jwt_json_error};
use crate::jwt::constants::ATHENZ_ALLOWED_JWT_TYPES;
use crate::jwt::types::JwtHeader;

pub(in crate::jwt::validator) struct JwtParts<'a> {
    pub(in crate::jwt::validator) header: &'a str,
    pub(in crate::jwt::validator) payload: &'a str,
    pub(in crate::jwt::validator) signature: &'a str,
}

pub(in crate::jwt::validator) fn split_jwt(token: &str) -> Result<JwtParts<'_>, Error> {
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

pub(in crate::jwt::validator) fn decode_jwt_header(encoded: &str) -> Result<JwtHeader, Error> {
    let header_bytes = base64_url_decode(encoded)?;
    let raw: Value = serde_json::from_slice(&header_bytes).map_err(jwt_json_error)?;
    validate_unsupported_jose_headers(&raw)?;
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

fn validate_unsupported_jose_headers(raw: &Value) -> Result<(), Error> {
    if raw.get("crit").is_some() || raw.get("b64").is_some() {
        return Err(jwt_error(ErrorKind::InvalidToken));
    }
    Ok(())
}

pub(in crate::jwt::validator) fn validate_jwt_typ(typ: Option<&str>) -> Result<(), Error> {
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

pub(in crate::jwt::validator) fn base64_url_decode(data: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|err| Error::Crypto(format!("base64url decode error: {err}")))
}

#[cfg(test)]
mod tests {
    use super::decode_jwt_header;
    use crate::error::Error;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use jsonwebtoken::errors::ErrorKind;
    use serde_json::{json, Value};

    fn encoded_header(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("header json"))
    }

    fn assert_invalid_token(err: Error) {
        match err {
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &ErrorKind::InvalidToken),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn decode_jwt_header_rejects_crit_header() {
        let encoded = encoded_header(json!({
            "alg": "RS256",
            "crit": ["exp"],
        }));

        let err = decode_jwt_header(&encoded).expect_err("crit must be rejected");
        assert_invalid_token(err);
    }

    #[test]
    fn decode_jwt_header_rejects_b64_false_header() {
        let encoded = encoded_header(json!({
            "alg": "RS256",
            "b64": false,
        }));

        let err = decode_jwt_header(&encoded).expect_err("b64 must be rejected");
        assert_invalid_token(err);
    }

    #[test]
    fn decode_jwt_header_rejects_b64_true_header() {
        let encoded = encoded_header(json!({
            "alg": "RS256",
            "b64": true,
        }));

        let err = decode_jwt_header(&encoded).expect_err("b64 must be rejected");
        assert_invalid_token(err);
    }
}
