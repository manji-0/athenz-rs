use crate::error::Error;
use jsonwebtoken::jwk::JwkSet;

use super::helpers::{jwk_matches_constraints, select_jwk};

pub(super) fn select_jwk_with_refresh<'a, F>(
    jwks: &'a mut JwkSet,
    kid: Option<&str>,
    alg: &str,
    refresh: F,
) -> Result<&'a jsonwebtoken::jwk::Jwk, Error>
where
    F: FnOnce() -> Result<JwkSet, Error>,
{
    if let Some(kid) = kid {
        if jwks.keys.iter().any(|key| {
            key.common.key_id.as_deref() == Some(kid) && jwk_matches_constraints(key, alg)
        }) {
            return select_jwk(jwks, Some(kid), alg);
        }
        *jwks = refresh()?;
        return select_jwk(jwks, Some(kid), alg);
    }
    select_jwk(jwks, None, alg)
}

#[cfg(feature = "async-validate")]
pub(super) async fn select_jwk_with_refresh_async<'a, F, Fut>(
    jwks: &'a mut JwkSet,
    kid: Option<&str>,
    alg: &str,
    refresh: F,
) -> Result<&'a jsonwebtoken::jwk::Jwk, Error>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<JwkSet, Error>>,
{
    if let Some(kid) = kid {
        if jwks.keys.iter().any(|key| {
            key.common.key_id.as_deref() == Some(kid) && jwk_matches_constraints(key, alg)
        }) {
            return select_jwk(jwks, Some(kid), alg);
        }
        *jwks = refresh().await?;
        return select_jwk(jwks, Some(kid), alg);
    }
    select_jwk(jwks, None, alg)
}
