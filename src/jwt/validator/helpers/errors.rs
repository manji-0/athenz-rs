use crate::error::Error;
use jsonwebtoken::errors::ErrorKind;
use std::sync::Arc;

pub(in crate::jwt::validator) fn jwt_error(kind: ErrorKind) -> Error {
    Error::Jwt(kind.into())
}

pub(in crate::jwt::validator) fn jwt_json_error(err: serde_json::Error) -> Error {
    Error::Jwt(ErrorKind::Json(Arc::new(err)).into())
}
