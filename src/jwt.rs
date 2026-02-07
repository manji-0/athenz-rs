use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::warn;
use p521::ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
use reqwest::blocking::Client as HttpClient;
use serde_json::Value;
use signature::Verifier as _;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::{fmt, str::FromStr};
use url::Url;

/// Fixed allowlist for Athenz JWT validation (jsonwebtoken-supported subset).
pub const ATHENZ_ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];
const ATHENZ_RSA_ALGS: &[Algorithm] = &[Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];
const ATHENZ_EC_ALGS: &[Algorithm] = &[Algorithm::ES256, Algorithm::ES384];
const ATHENZ_ALLOWED_ALG_NAMES: &[&str] = &["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"];
const SUPPORTED_JWK_ALGS: &[&str] = &[
    "HS256",
    "HS384",
    "HS512",
    "ES256",
    "ES384",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
];

#[derive(Debug, Clone)]
pub struct JwtHeader {
    pub alg: String,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub raw: Value,
}

#[derive(Debug, Clone)]
pub struct JwtTokenData<T> {
    pub header: JwtHeader,
    pub claims: T,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JwksSanitizeReport {
    pub jwks: JwkSet,
    pub removed_algs: Vec<RemovedAlg>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RemovedAlg {
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub reason: RemovedAlgReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RemovedAlgReason {
    NotString,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct JwtValidationOptions {
    pub issuer: Option<String>,
    pub audience: Vec<String>,
    pub leeway: u64,
    pub validate_exp: bool,
    pub allowed_algs: Vec<Algorithm>,
}

impl JwtValidationOptions {
    pub fn athenz_default() -> Self {
        Self {
            issuer: None,
            audience: Vec::new(),
            leeway: 0,
            validate_exp: true,
            allowed_algs: ATHENZ_ALLOWED_ALGS.to_vec(),
        }
    }

    pub fn rsa_only() -> Self {
        let mut options = Self::athenz_default();
        options.allowed_algs = ATHENZ_RSA_ALGS.to_vec();
        options
    }

    pub fn ec_only() -> Self {
        let mut options = Self::athenz_default();
        options.allowed_algs = ATHENZ_EC_ALGS.to_vec();
        options
    }
}

impl Default for JwtValidationOptions {
    fn default() -> Self {
        Self::athenz_default()
    }
}

#[derive(Debug)]
pub struct JwksProvider {
    jwks_uri: Url,
    http: HttpClient,
    cache_ttl: Duration,
    cache: RwLock<Option<CachedJwks>>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: JwkSet,
    expires_at: Instant,
}

impl JwksProvider {
    pub fn new(jwks_uri: impl AsRef<str>) -> Result<Self, Error> {
        let jwks_uri = Url::parse(jwks_uri.as_ref())?;
        Ok(Self {
            jwks_uri,
            http: HttpClient::new(),
            cache_ttl: Duration::from_secs(300),
            cache: RwLock::new(None),
        })
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    pub fn with_preloaded(self, jwks: JwkSet) -> Self {
        let cached = CachedJwks {
            jwks,
            expires_at: Instant::now() + self.cache_ttl,
        };
        *self.cache.write().unwrap() = Some(cached);
        self
    }

    pub fn fetch(&self) -> Result<JwkSet, Error> {
        if let Some(cached) = self.cache.read().unwrap().as_ref() {
            if cached.expires_at > Instant::now() {
                return Ok(cached.jwks.clone());
            }
        }

        let body = self.http.get(self.jwks_uri.clone()).send()?.bytes()?;
        let jwks = jwks_from_slice(&body)?;
        let cached = CachedJwks {
            jwks: jwks.clone(),
            expires_at: Instant::now() + self.cache_ttl,
        };
        *self.cache.write().unwrap() = Some(cached);
        Ok(jwks)
    }
}

#[derive(Debug)]
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
        validation.leeway = self.options.leeway;
        validation.validate_exp = self.options.validate_exp;
        if let Some(ref issuer) = self.options.issuer {
            validation.set_issuer(&[issuer.as_str()]);
        }
        if !self.options.audience.is_empty() {
            validation.set_audience(&self.options.audience);
        }

        let jwks = self.jwks.fetch()?;
        if header.kid.is_none() && jwks.keys.len() > 1 {
            let mut last_err = None;
            for jwk in &jwks.keys {
                let decoding_key = match DecodingKey::from_jwk(jwk) {
                    Ok(key) => key,
                    Err(err) => {
                        last_err = Some(Error::from(err));
                        continue;
                    }
                };
                match decode::<Value>(token, &decoding_key, &validation) {
                    Ok(token_data) => {
                        return Ok(JwtTokenData {
                            header: header.clone(),
                            claims: token_data.claims,
                        });
                    }
                    Err(err) => last_err = Some(Error::from(err)),
                }
            }
            return Err(last_err.unwrap_or_else(|| Error::MissingJwk("kid required".to_string())));
        }

        let key = select_jwk(&jwks, header.kid.as_deref())?;
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
            return Err(Error::UnsupportedAlg("ES512".to_string()));
        }

        let jwks = self.jwks.fetch()?;
        if header.kid.is_none() && jwks.keys.len() > 1 {
            let mut last_err = None;
            for jwk in &jwks.keys {
                match self.validate_es512_with_key(parts, header, jwk) {
                    Ok(data) => return Ok(data),
                    Err(err) => last_err = Some(err),
                }
            }
            return Err(last_err.unwrap_or_else(|| jwt_error(ErrorKind::InvalidSignature)));
        }

        let key = select_jwk(&jwks, header.kid.as_deref())?;
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

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = self.options.leeway;
        validation.validate_exp = self.options.validate_exp;
        if let Some(ref issuer) = self.options.issuer {
            validation.set_issuer(&[issuer.as_str()]);
        }
        if !self.options.audience.is_empty() {
            validation.set_audience(&self.options.audience);
        }
        validate_claims(&claims, &validation)?;

        Ok(JwtTokenData {
            header: header.clone(),
            claims,
        })
    }
}

fn resolve_allowed_algs(options: &JwtValidationOptions) -> Result<&[Algorithm], Error> {
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

fn allows_es512(options: &JwtValidationOptions) -> bool {
    ATHENZ_ALLOWED_ALGS
        .iter()
        .all(|alg| options.allowed_algs.contains(alg))
}

struct JwtParts<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

fn split_jwt(token: &str) -> Result<JwtParts<'_>, Error> {
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

fn decode_jwt_header(encoded: &str) -> Result<JwtHeader, Error> {
    let header_bytes = base64_url_decode(encoded)?;
    let raw: Value = serde_json::from_slice(&header_bytes).map_err(jwt_json_error)?;
    let alg = raw
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| jwt_error(ErrorKind::InvalidToken))?;
    let kid = raw
        .get("kid")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let typ = raw
        .get("typ")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    Ok(JwtHeader {
        alg: alg.to_string(),
        kid,
        typ,
        raw,
    })
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|err| Error::Crypto(format!("base64url decode error: {err}")))
}

fn p521_verifying_key_from_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Result<P521VerifyingKey, Error> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) => {
            if params.curve != EllipticCurve::P521 {
                return Err(Error::UnsupportedAlg(
                    "ES512 requires P-521 key".to_string(),
                ));
            }
            let x = decode_p521_coord(&params.x)?;
            let y = decode_p521_coord(&params.y)?;
            let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            P521VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| jwt_error(ErrorKind::InvalidEcdsaKey))
        }
        _ => Err(Error::UnsupportedAlg("ES512 requires EC key".to_string())),
    }
}

fn decode_p521_coord(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = base64_url_decode(value)?;
    const P521_COORD_SIZE: usize = 66;
    if bytes.len() > P521_COORD_SIZE {
        return Err(jwt_error(ErrorKind::InvalidEcdsaKey));
    }
    if bytes.len() == P521_COORD_SIZE {
        return Ok(bytes);
    }
    let mut padded = vec![0u8; P521_COORD_SIZE - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

fn jwt_error(kind: ErrorKind) -> Error {
    Error::Jwt(kind.into())
}

fn jwt_json_error(err: serde_json::Error) -> Error {
    Error::Jwt(ErrorKind::Json(Arc::new(err)).into())
}

#[derive(serde::Deserialize)]
struct ClaimsForValidation {
    #[serde(deserialize_with = "numeric_type", default)]
    exp: TryParse<u64>,
    #[serde(deserialize_with = "numeric_type", default)]
    nbf: TryParse<u64>,
    sub: TryParse<String>,
    iss: TryParse<Issuer>,
    aud: TryParse<Audience>,
}

#[derive(Debug, Default)]
enum TryParse<T> {
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
enum Audience {
    Single(String),
    Multiple(HashSet<String>),
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Issuer {
    Single(String),
    Multiple(HashSet<String>),
}

fn validate_claims(claims: &Value, options: &Validation) -> Result<(), Error> {
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

fn is_subset(reference: &HashSet<String>, given: &HashSet<String>) -> bool {
    if reference.len() < given.len() {
        reference.iter().any(|a| given.contains(a))
    } else {
        given.iter().any(|a| reference.contains(a))
    }
}

fn numeric_type<'de, D>(deserializer: D) -> Result<TryParse<u64>, D::Error>
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

fn select_jwk<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
) -> Result<&'a jsonwebtoken::jwk::Jwk, Error> {
    if let Some(kid) = kid {
        if let Some(jwk) = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
        {
            return Ok(jwk);
        }
        return Err(Error::MissingJwk(kid.to_string()));
    }

    if jwks.keys.len() == 1 {
        return Ok(&jwks.keys[0]);
    }

    Err(Error::MissingJwk("kid required".to_string()))
}

pub fn jwks_from_slice(body: &[u8]) -> Result<JwkSet, Error> {
    let report = jwks_from_slice_with_report(body)?;
    Ok(report.jwks)
}

pub fn jwks_from_slice_with_report(body: &[u8]) -> Result<JwksSanitizeReport, Error> {
    let mut value: Value = serde_json::from_slice(body)?;
    let removed_algs = sanitize_jwks(&mut value);
    let jwks = serde_json::from_value(value).map_err(Error::from)?;
    Ok(JwksSanitizeReport { jwks, removed_algs })
}

fn sanitize_jwks(value: &mut Value) -> Vec<RemovedAlg> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p521::ecdsa::SigningKey as P521SigningKey;
    use rand::thread_rng;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use signature::Signer;

    fn build_es512_token() -> (String, JwkSet) {
        let mut rng = thread_rng();
        let signing_key = P521SigningKey::random(&mut rng);
        let verifying_key = P521VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("x coord");
        let y = encoded_point.y().expect("y coord");

        let kid = "test-key";
        let jwks_json = json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-521",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "use": "sig",
                "kid": kid,
                "alg": "ES512",
            }]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");

        let header = json!({
            "alg": "ES512",
            "kid": kid,
            "typ": "JWT",
        });
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let payload = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{}.{}", signing_input, signature_b64);

        (token, jwks)
    }

    const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxq83nCd8AqH5n40dEBMElbaJd2gFWu6bjhNzyp9562dpf454
BUSN0uF+g3i1yzcwdvADTiuExKN1u/IoGURxVCa0JTzAPJw6/JIoyOZnHZCoarcg
QQqZ56/udkSQ2NssrwGSQjOwxMrgIdH6XeLgGqVN4BoEEI+gpaQZa7rSytU5RFSG
OnZWO2Vwgs1OBxiOiYg1gzA1spJXQhxcBWw/v+YrUFtjxBKsG1UrWbnHbgciiN5U
2v51Yztjo8A1T+o9eIG90jVo3EhS2qhbzd8mLAsEhjV1sP8GItjfdfwXpXT7q2QG
99W3PM75+HdwGLvJIrkED7YRj4CpMkz6F1etawIDAQABAoIBAD67C7/N56WdJodt
soNkvcnXPEfrG+W9+Hc/RQvwljnxCKoxfUuMfYrbj2pLLnrfDfo/hYukyeKcCYwx
xN9VcMK1BaPMLpX0bdtY+m+T73KyPbqT3ycqBbXVImFM/L67VLxcrqUgVOuNcn67
IWWLQF6pWpErJaVk87/Ys/4DmpJXebLDyta8+ce6r0ppSG5+AifGo1byQT7kSJkF
lyQsyKWoVN+02s7gLsln5JXXZ672y2Xtp/S3wK0vfzy/HcGSxzn1yE0M5UJtDm/Y
qECnV1LQ0FB1l1a+/itHR8ipp5rScD4ZpzOPLKthglEvNPe4Lt5rieH9TR97siEe
SrC8uyECgYEA5Q/elOJAddpE+cO22gTFt973DcPGjM+FYwgdrora+RfEXJsMDoKW
AGSm5da7eFo8u/bJEvHSJdytc4CRQYnWNryIaUw2o/1LYXRvoEt1rEEgQ4pDkErR
PsVcVuc3UDeeGtYJwJLV6pjxO11nodFv4IgaVj64SqvCOApTTJgWXF0CgYEA3gzN
d3l376mSMuKc4Ep++TxybzA5mtF2qoXucZOon8EDJKr+vGQ9Z6X4YSdkSMNXqK1j
ILmFH7V3dyMOKRBA84YeawFacPLBJq+42t5Q1OYdcKZbaArlBT8ImGT7tQODs3JN
4w7DH+V1v/VCTl2zQaZRksb0lUsQbFiEfj+SVGcCgYAYIlDoTOJPyHyF+En2tJQE
aHiNObhcs6yxH3TJJBYoMonc2/UsPjQBvJkdFD/SUWeewkSzO0lR9etMhRpI1nX8
dGbG+WG0a4aasQLl162BRadZlmLB/DAJtg+hlGDukb2VxEFoyc/CFPUttQyrLv7j
oFNuDNOsAmbHMsdOBaQtfQKBgQCb/NRuRNebdj0tIALikZLHVc5yC6e7+b/qJPIP
uZIwv++MV89h2u1EHdTxszGA6DFxXnSPraQ2VU2aVPcCo9ds+9/sfePiCrbjjXhH
0PtpxEoUM9lsqpKeb9yC6hXk4JYpfnf2tQ0gIBrrAclVsf9WdBdEDB4Prs7Xvgs9
gT0zqwKBgQCzZubFO0oTYO9e2r8wxPPPsE3ZCjbP/y7lIoBbSzxDGUubXmbvD0GO
MC8dM80plsTym96UxpKkQMAglKKLPtG2n8xB8v5H/uIB4oIegMSEx3F7MRWWIQmR
Gea7bQ16YCzM/l2yygGhAW61bg2Z2GoVF6X5z/qhKGyo97V87qTbmg==
-----END RSA PRIVATE KEY-----
"#;

    fn build_rs256_token_without_kid() -> (String, JwkSet) {
        let private_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).expect("private key");
        let public_key = RsaPublicKey::from(&private_key);
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        let mut bad_n = n.clone();
        if let Some(first) = bad_n.first_mut() {
            *first ^= 0x01;
        }

        let jwks_json = json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "bad-key",
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&bad_n),
                    "e": URL_SAFE_NO_PAD.encode(&e),
                },
                {
                    "kty": "RSA",
                    "kid": "good-key",
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&n),
                    "e": URL_SAFE_NO_PAD.encode(&e),
                }
            ]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");

        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let claims = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = None;
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes()).expect("encoding key"),
        )
        .expect("token");

        (token, jwks)
    }

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

    #[test]
    fn jwt_es512_validate_success() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let mut options = JwtValidationOptions::athenz_default();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["iss"], "athenz");
        assert_eq!(data.claims["aud"], "client");
        assert_eq!(data.header.alg, "ES512");
    }

    #[test]
    fn jwt_es512_rejected_when_rsa_only() {
        let (token, jwks) = build_es512_token();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::UnsupportedAlg(alg) => assert_eq!(alg, "ES512"),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rs256_validates_without_kid_using_all_keys() {
        let (token, jwks) = build_rs256_token_without_kid();
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let mut options = JwtValidationOptions::rsa_only();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let data = validator.validate_access_token(&token).expect("validate");
        assert_eq!(data.claims["sub"], "principal");
    }

    fn jwks_from_value(value: Value) -> Result<JwkSet, Error> {
        let mut value = value;
        sanitize_jwks(&mut value);
        serde_json::from_value(value).map_err(Error::from)
    }
}
