use crate::error::Error;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use p521::ecdsa::Signature as P521Signature;
use serde_json::Value;
use signature::Verifier as _;
use std::str::FromStr;

use super::constants::{ATHENZ_ALLOWED_ALG_NAMES, ATHENZ_RSA_ALGS, ES512_DISABLED_MESSAGE};
#[cfg(feature = "async-validate")]
use super::jwks::JwksProviderAsync;
use super::jwks::{FetchSource, JwksProvider};
use super::types::{JwtHeader, JwtTokenData, JwtValidationOptions};

mod helpers;
use helpers::{
    allows_es512, apply_validation_options, base64_url_decode, decode_jwt_header, is_es512_jwk,
    is_es512_key_error, is_rs_jwk, is_rs_key_error, jwk_matches_constraints, jwt_error,
    jwt_json_error, p521_verifying_key_from_jwk, resolve_allowed_algs, select_jwk, split_jwt,
    validate_claims, validate_jwt_typ, validate_kidless_jwks, JwtParts,
};
use jsonwebtoken::jwk::JwkSet;
#[cfg(feature = "async-validate")]
use std::future::Future;

fn select_jwk_with_refresh<'a, F>(
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
async fn select_jwk_with_refresh_async<'a, F, Fut>(
    jwks: &'a mut JwkSet,
    kid: Option<&str>,
    alg: &str,
    refresh: F,
) -> Result<&'a jsonwebtoken::jwk::Jwk, Error>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<JwkSet, Error>>,
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

pub struct JwtValidator {
    jwks: JwksProvider,
    options: JwtValidationOptions,
}

impl JwtValidator {
    pub fn new(jwks: JwksProvider) -> Self {
        Self {
            jwks,
            options: JwtValidationOptions::default(),
        }
    }

    pub fn with_options(mut self, options: JwtValidationOptions) -> Self {
        self.options = options;
        self
    }

    pub fn validate(&self, token: &str) -> Result<JwtTokenData<Value>, Error> {
        let parts = split_jwt(token)?;
        let header = decode_jwt_header(parts.header)?;
        validate_jwt_typ(header.typ.as_deref())?;
        let alg = header.alg.as_str();
        if !ATHENZ_ALLOWED_ALG_NAMES.contains(&alg) {
            return Err(Error::UnsupportedAlg(header.alg.clone()));
        }

        if alg == "ES512" {
            return self.validate_es512(&parts, &header);
        }

        let alg =
            Algorithm::from_str(alg).map_err(|_| Error::UnsupportedAlg(header.alg.clone()))?;
        let allowed_algs = resolve_allowed_algs(&self.options)?;
        if !allowed_algs.contains(&alg) {
            return Err(Error::UnsupportedAlg(format!("{alg:?}")));
        }

        let mut validation = Validation::new(alg);
        apply_validation_options(&mut validation, &self.options);

        let (mut jwks, source) = self.jwks.fetch_with_source()?;
        if header.kid.is_none() && jwks.keys.len() > 1 && ATHENZ_RSA_ALGS.contains(&alg) {
            let keys = jwks
                .keys
                .iter()
                .filter(|jwk| is_rs_jwk(jwk) && jwk_matches_constraints(jwk, &header.alg));
            let result = validate_kidless_jwks(
                keys,
                &header.alg,
                |jwk| {
                    let decoding_key = DecodingKey::from_jwk(jwk).map_err(Error::from)?;
                    let token_data =
                        decode::<Value>(token, &decoding_key, &validation).map_err(Error::from)?;
                    Ok(JwtTokenData {
                        header: header.clone(),
                        claims: token_data.claims,
                    })
                },
                is_rs_key_error,
            );
            return result;
        }

        let key = if source == FetchSource::Cache {
            select_jwk_with_refresh(&mut jwks, header.kid.as_deref(), &header.alg, || {
                self.jwks.fetch_fresh()
            })?
        } else {
            select_jwk(&jwks, header.kid.as_deref(), &header.alg)?
        };
        let decoding_key = DecodingKey::from_jwk(key)?;
        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(Error::from)?;
        Ok(JwtTokenData {
            header,
            claims: token_data.claims,
        })
    }

    pub fn validate_access_token(&self, token: &str) -> Result<JwtTokenData<Value>, Error> {
        self.validate(token)
    }

    pub fn validate_id_token(&self, token: &str) -> Result<JwtTokenData<Value>, Error> {
        self.validate(token)
    }

    fn validate_es512(
        &self,
        parts: &JwtParts<'_>,
        header: &JwtHeader,
    ) -> Result<JwtTokenData<Value>, Error> {
        resolve_allowed_algs(&self.options)?;
        if !allows_es512(&self.options) {
            return Err(Error::UnsupportedAlg(ES512_DISABLED_MESSAGE.to_string()));
        }

        let (mut jwks, source) = self.jwks.fetch_with_source()?;
        if header.kid.is_none() && jwks.keys.len() > 1 {
            let keys = jwks
                .keys
                .iter()
                .filter(|jwk| is_es512_jwk(jwk) && jwk_matches_constraints(jwk, &header.alg));
            return validate_kidless_jwks(
                keys,
                &header.alg,
                |jwk| self.validate_es512_with_key(parts, header, jwk),
                is_es512_key_error,
            );
        }

        let key = if source == FetchSource::Cache {
            select_jwk_with_refresh(&mut jwks, header.kid.as_deref(), &header.alg, || {
                self.jwks.fetch_fresh()
            })?
        } else {
            select_jwk(&jwks, header.kid.as_deref(), &header.alg)?
        };
        self.validate_es512_with_key(parts, header, key)
    }

    fn validate_es512_with_key(
        &self,
        parts: &JwtParts<'_>,
        header: &JwtHeader,
        key: &jsonwebtoken::jwk::Jwk,
    ) -> Result<JwtTokenData<Value>, Error> {
        let verifying_key = p521_verifying_key_from_jwk(key)?;
        let signature_bytes = base64_url_decode(parts.signature)?;
        let signature = P521Signature::from_slice(&signature_bytes)
            .map_err(|_| jwt_error(ErrorKind::InvalidSignature))?;
        let signing_input = format!("{}.{}", parts.header, parts.payload);
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| jwt_error(ErrorKind::InvalidSignature))?;

        let claims_bytes = base64_url_decode(parts.payload)?;
        let claims: Value = serde_json::from_slice(&claims_bytes).map_err(jwt_json_error)?;

        // jsonwebtoken::Algorithm does not include ES512; Validation is used only for claims.
        let mut validation = Validation::new(Algorithm::RS256);
        apply_validation_options(&mut validation, &self.options);
        validate_claims(&claims, &validation)?;

        Ok(JwtTokenData {
            header: header.clone(),
            claims,
        })
    }
}

#[cfg(feature = "async-validate")]
#[derive(Debug)]
pub struct JwtValidatorAsync {
    jwks: JwksProviderAsync,
    options: JwtValidationOptions,
}

#[cfg(feature = "async-validate")]
impl JwtValidatorAsync {
    pub fn new(jwks: JwksProviderAsync) -> Self {
        Self {
            jwks,
            options: JwtValidationOptions::default(),
        }
    }

    pub fn with_options(mut self, options: JwtValidationOptions) -> Self {
        self.options = options;
        self
    }

    pub async fn validate(&self, token: &str) -> Result<JwtTokenData<Value>, Error> {
        let parts = split_jwt(token)?;
        let header = decode_jwt_header(parts.header)?;
        validate_jwt_typ(header.typ.as_deref())?;
        let alg = header.alg.as_str();
        if !ATHENZ_ALLOWED_ALG_NAMES.contains(&alg) {
            return Err(Error::UnsupportedAlg(header.alg.clone()));
        }

        if alg == "ES512" {
            return self.validate_es512(&parts, &header).await;
        }

        let alg =
            Algorithm::from_str(alg).map_err(|_| Error::UnsupportedAlg(header.alg.clone()))?;
        let allowed_algs = resolve_allowed_algs(&self.options)?;
        if !allowed_algs.contains(&alg) {
            return Err(Error::UnsupportedAlg(header.alg.clone()));
        }

        let mut validation = Validation::new(alg);
        validation.leeway = self.options.leeway;
        validation.validate_exp = self.options.validate_exp;
        validation.validate_nbf = self.options.validate_nbf;
        if let Some(ref issuer) = self.options.issuer {
            validation.set_issuer(&[issuer.as_str()]);
        }
        if !self.options.audience.is_empty() {
            validation.set_audience(&self.options.audience);
        }
        validation.validate_aud = !self.options.audience.is_empty();

        let (mut jwks, source) = self.jwks.fetch_with_source().await?;
        if header.kid.is_none() && jwks.keys.len() > 1 && ATHENZ_RSA_ALGS.contains(&alg) {
            let keys = jwks
                .keys
                .iter()
                .filter(|jwk| is_rs_jwk(jwk) && jwk_matches_constraints(jwk, &header.alg));
            let result = validate_kidless_jwks(
                keys,
                &header.alg,
                |jwk| {
                    let decoding_key = DecodingKey::from_jwk(jwk).map_err(Error::from)?;
                    let token_data =
                        decode::<Value>(token, &decoding_key, &validation).map_err(Error::from)?;
                    Ok(JwtTokenData {
                        header: header.clone(),
                        claims: token_data.claims,
                    })
                },
                is_rs_key_error,
            );
            return result;
        }

        let key = if source == FetchSource::Cache {
            select_jwk_with_refresh_async(&mut jwks, header.kid.as_deref(), &header.alg, || {
                self.jwks.fetch_fresh()
            })
            .await?
        } else {
            select_jwk(&jwks, header.kid.as_deref(), &header.alg)?
        };
        let decoding_key = DecodingKey::from_jwk(key)?;
        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(Error::from)?;
        Ok(JwtTokenData {
            header,
            claims: token_data.claims,
        })
    }

    pub async fn validate_access_token(&self, token: &str) -> Result<JwtTokenData<Value>, Error> {
        self.validate(token).await
    }

    pub async fn validate_id_token(&self, token: &str) -> Result<JwtTokenData<Value>, Error> {
        self.validate(token).await
    }

    async fn validate_es512(
        &self,
        parts: &JwtParts<'_>,
        header: &JwtHeader,
    ) -> Result<JwtTokenData<Value>, Error> {
        resolve_allowed_algs(&self.options)?;
        if !allows_es512(&self.options) {
            return Err(Error::UnsupportedAlg(ES512_DISABLED_MESSAGE.to_string()));
        }

        let (mut jwks, source) = self.jwks.fetch_with_source().await?;
        if header.kid.is_none() && jwks.keys.len() > 1 {
            let keys = jwks
                .keys
                .iter()
                .filter(|jwk| is_es512_jwk(jwk) && jwk_matches_constraints(jwk, &header.alg));
            return validate_kidless_jwks(
                keys,
                &header.alg,
                |jwk| self.validate_es512_with_key(parts, header, jwk),
                is_es512_key_error,
            );
        }

        let key = if source == FetchSource::Cache {
            select_jwk_with_refresh_async(&mut jwks, header.kid.as_deref(), &header.alg, || {
                self.jwks.fetch_fresh()
            })
            .await?
        } else {
            select_jwk(&jwks, header.kid.as_deref(), &header.alg)?
        };
        self.validate_es512_with_key(parts, header, key)
    }

    fn validate_es512_with_key(
        &self,
        parts: &JwtParts<'_>,
        header: &JwtHeader,
        key: &jsonwebtoken::jwk::Jwk,
    ) -> Result<JwtTokenData<Value>, Error> {
        let verifying_key = p521_verifying_key_from_jwk(key)?;
        let signature_bytes = base64_url_decode(parts.signature)?;
        let signature = P521Signature::from_slice(&signature_bytes)
            .map_err(|_| jwt_error(ErrorKind::InvalidSignature))?;
        let signing_input = format!("{}.{}", parts.header, parts.payload);
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| jwt_error(ErrorKind::InvalidSignature))?;

        let claims_bytes = base64_url_decode(parts.payload)?;
        let claims: Value = serde_json::from_slice(&claims_bytes).map_err(jwt_json_error)?;

        // jsonwebtoken::Algorithm does not include ES512; Validation is used only for claims.
        let mut validation = Validation::new(Algorithm::RS256);
        apply_validation_options(&mut validation, &self.options);
        validate_claims(&claims, &validation)?;

        Ok(JwtTokenData {
            header: header.clone(),
            claims,
        })
    }
}
