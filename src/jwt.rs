use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::warn;
use p521::ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
use reqwest::blocking::Client as HttpClient;
#[cfg(feature = "async-validate")]
use reqwest::Client as AsyncHttpClient;
use serde_json::Value;
use signature::Verifier as _;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::{fmt, str::FromStr};
#[cfg(feature = "async-validate")]
use tokio::sync::Mutex as AsyncMutex;
#[cfg(feature = "async-validate")]
use tokio::sync::RwLock as AsyncRwLock;
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
const ATHENZ_ALLOWED_JWT_TYPES: &[&str] = &["at+jwt", "jwt"];
// Safety bound on how many kid-less JWKS keys we try when no `kid` is present in the JWT.
// `10` was chosen to cover typical deployments where JWKS sets are small (O(1–10) active keys)
// while preventing unbounded work on misconfigured or very large JWKS endpoints.
const MAX_KIDLESS_JWKS_KEYS: usize = 10;
const NO_COMPATIBLE_JWK_MESSAGE: &str = "no compatible jwks key for alg";
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

#[cfg(feature = "async-validate")]
#[derive(Debug)]
pub struct JwksProviderAsync {
    jwks_uri: Url,
    http: AsyncHttpClient,
    cache_ttl: Duration,
    cache: AsyncRwLock<Option<CachedJwks>>,
    fetch_lock: AsyncMutex<()>,
}

#[cfg(feature = "async-validate")]
impl JwksProviderAsync {
    pub fn new(jwks_uri: impl AsRef<str>) -> Result<Self, Error> {
        let jwks_uri = Url::parse(jwks_uri.as_ref())?;
        let http = AsyncHttpClient::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            jwks_uri,
            http,
            cache_ttl: Duration::from_secs(300),
            cache: AsyncRwLock::new(None),
            fetch_lock: AsyncMutex::new(()),
        })
    }

    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        let cache = self.cache.into_inner();
        self.cache = AsyncRwLock::new(cache.map(|mut cached| {
            cached.expires_at = Instant::now() + self.cache_ttl;
            cached
        }));
        self
    }

    pub fn with_preloaded(self, jwks: JwkSet) -> Self {
        let cached = CachedJwks {
            jwks,
            expires_at: Instant::now() + self.cache_ttl,
        };
        let mut this = self;
        this.cache = AsyncRwLock::new(Some(cached));
        this
    }

    pub async fn fetch(&self) -> Result<JwkSet, Error> {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        let _guard = self.fetch_lock.lock().await;
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        let resp = self.http.get(self.jwks_uri.clone()).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            let body_preview = sanitize_error_body(&body);
            return Err(Error::Crypto(if body_preview.is_empty() {
                format!(
                    "jwks fetch failed: status {} body_len {}",
                    status,
                    body.len()
                )
            } else {
                format!(
                    "jwks fetch failed: status {} body_len {} body_preview {}",
                    status,
                    body.len(),
                    body_preview
                )
            }));
        }
        let jwks = jwks_from_slice(&body)?;
        let cached = CachedJwks {
            jwks: jwks.clone(),
            expires_at: Instant::now() + self.cache_ttl,
        };
        *self.cache.write().await = Some(cached);
        Ok(jwks)
    }
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
        if let Some(cached) = self.cache.write().unwrap().as_mut() {
            cached.expires_at = Instant::now() + self.cache_ttl;
        }
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
        validation.leeway = self.options.leeway;
        validation.validate_exp = self.options.validate_exp;
        if let Some(ref issuer) = self.options.issuer {
            validation.set_issuer(&[issuer.as_str()]);
        }
        if !self.options.audience.is_empty() {
            validation.set_audience(&self.options.audience);
        }

        let jwks = self.jwks.fetch()?;
        if header.kid.is_none() && jwks.keys.len() > 1 && ATHENZ_RSA_ALGS.contains(&alg) {
            let keys = jwks.keys.iter().filter(|jwk| is_rs_jwk(jwk));
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
            let keys = jwks.keys.iter().filter(|jwk| is_es512_jwk(jwk));
            return validate_kidless_jwks(
                keys,
                &header.alg,
                |jwk| self.validate_es512_with_key(parts, header, jwk),
                is_es512_key_error,
            );
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

        // jsonwebtoken::Algorithm does not include ES512; Validation is used only for claims.
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

        let jwks = self.jwks.fetch().await?;
        let key = select_jwk(&jwks, header.kid.as_deref())?;
        let decoding_key = DecodingKey::from_jwk(key)?;

        let mut validation = Validation::new(alg);
        validation.leeway = self.options.leeway;
        validation.validate_exp = self.options.validate_exp;
        if let Some(ref issuer) = self.options.issuer {
            validation.set_issuer(&[issuer.as_str()]);
        }
        if !self.options.audience.is_empty() {
            validation.set_audience(&self.options.audience);
        }

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
            return Err(Error::UnsupportedAlg("ES512".to_string()));
        }

        let jwks = self.jwks.fetch().await?;
        let key = select_jwk(&jwks, header.kid.as_deref())?;
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
    // ES512 isn't representable in jsonwebtoken::Algorithm; treat full EC allowlist as opt-in.
    ATHENZ_EC_ALGS
        .iter()
        .all(|alg| options.allowed_algs.contains(alg))
}

#[cfg(feature = "async-validate")]
fn sanitize_error_body(body: &[u8]) -> String {
    let mut sanitized = String::from_utf8_lossy(body)
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    if sanitized.len() > 256 {
        sanitized.truncate(256);
        sanitized.push_str("...");
    }
    sanitized
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

fn validate_jwt_typ(typ: Option<&str>) -> Result<(), Error> {
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

fn is_es512_key_error(err: &Error) -> bool {
    match err {
        Error::UnsupportedAlg(_) => true,
        Error::Jwt(jwt_err) => matches!(jwt_err.kind(), ErrorKind::InvalidEcdsaKey),
        _ => false,
    }
}

fn is_rs_key_error(err: &Error) -> bool {
    match err {
        Error::Jwt(jwt_err) => matches!(
            jwt_err.kind(),
            ErrorKind::InvalidKeyFormat
                | ErrorKind::InvalidAlgorithm
                | ErrorKind::InvalidAlgorithmName
                | ErrorKind::InvalidRsaKey(_)
        ),
        _ => false,
    }
}

fn is_signature_error(err: &Error) -> bool {
    match err {
        Error::Jwt(jwt_err) => matches!(jwt_err.kind(), ErrorKind::InvalidSignature),
        _ => false,
    }
}

fn kidless_no_compatible_jwk(alg: &str) -> Error {
    Error::Crypto(format!("{NO_COMPATIBLE_JWK_MESSAGE} {alg} (kid missing)"))
}

fn validate_kidless_jwks<'a, I, F, K>(
    keys: I,
    alg: &str,
    mut try_key: F,
    is_key_error: K,
) -> Result<JwtTokenData<Value>, Error>
where
    I: Iterator<Item = &'a jsonwebtoken::jwk::Jwk>,
    F: FnMut(&'a jsonwebtoken::jwk::Jwk) -> Result<JwtTokenData<Value>, Error>,
    K: Fn(&Error) -> bool,
{
    let mut signature_err = None;
    let mut key_err = None;
    let mut candidates = 0usize;
    for jwk in keys.take(MAX_KIDLESS_JWKS_KEYS) {
        candidates += 1;
        match try_key(jwk) {
            Ok(data) => return Ok(data),
            Err(err) => {
                if is_key_error(&err) {
                    if key_err.is_none() {
                        key_err = Some(err);
                    }
                } else if is_signature_error(&err) {
                    if signature_err.is_none() {
                        signature_err = Some(err);
                    }
                } else {
                    return Err(err);
                }
            }
        }
    }
    if candidates == 0 {
        return Err(kidless_no_compatible_jwk(alg));
    }
    Err(signature_err
        .or(key_err)
        .unwrap_or_else(|| kidless_no_compatible_jwk(alg)))
}

fn is_rs_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
}

fn is_es512_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> bool {
    matches!(
        jwk.algorithm,
        AlgorithmParameters::EllipticCurve(ref params) if params.curve == EllipticCurve::P521
    )
}

fn decode_p521_coord(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = base64_url_decode(value).map_err(|_| jwt_error(ErrorKind::InvalidEcdsaKey))?;
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
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use signature::Signer;
    use std::sync::OnceLock;

    fn build_es512_token() -> (String, JwkSet) {
        build_es512_token_with_typ_value(Some(json!("JWT")))
    }

    fn build_es512_token_with_typ(typ: Option<&str>) -> (String, JwkSet) {
        build_es512_token_with_typ_value(typ.map(|value| json!(value)))
    }

    fn build_es512_token_with_typ_value(typ: Option<Value>) -> (String, JwkSet) {
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

        let mut header = json!({
            "alg": "ES512",
            "kid": kid,
        });
        if let Some(typ) = typ {
            header["typ"] = typ;
        }
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

    fn build_es512_token_without_kid() -> (String, JwkSet) {
        let mut rng = thread_rng();
        let signing_key = P521SigningKey::random(&mut rng);
        let verifying_key = P521VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("x coord");
        let y = encoded_point.y().expect("y coord");

        let bad_signing_key = P521SigningKey::random(&mut rng);
        let bad_verifying_key = P521VerifyingKey::from(&bad_signing_key);
        let bad_point = bad_verifying_key.to_encoded_point(false);
        let bad_x = bad_point.x().expect("x coord");
        let bad_y = bad_point.y().expect("y coord");

        let jwks_json = json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": URL_SAFE_NO_PAD.encode(bad_x),
                    "y": URL_SAFE_NO_PAD.encode(bad_y),
                    "use": "sig",
                    "kid": "bad-key",
                    "alg": "ES512",
                },
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": URL_SAFE_NO_PAD.encode(x),
                    "y": URL_SAFE_NO_PAD.encode(y),
                    "use": "sig",
                    "kid": "good-key",
                    "alg": "ES512",
                }
            ]
        });
        let jwks = jwks_from_value(jwks_json).expect("jwks");

        let header = json!({
            "alg": "ES512",
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

    fn rsa_private_key_pem() -> &'static str {
        static PEM: OnceLock<String> = OnceLock::new();
        PEM.get_or_init(|| {
            let mut rng = thread_rng();
            let key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
            key.to_pkcs1_pem(LineEnding::LF)
                .expect("private key pem")
                .to_string()
        })
        .as_str()
    }

    fn rs256_public_components() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let pem = rsa_private_key_pem();
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem).expect("private key");
        let public_key = RsaPublicKey::from(&private_key);
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        let mut bad_n = n.clone();
        if let Some(last) = bad_n.last_mut() {
            *last ^= 0x01;
        }
        (n, e, bad_n)
    }

    fn rs256_token_without_kid() -> String {
        let pem = rsa_private_key_pem();
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let claims = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = None;
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key"),
        )
        .expect("token")
    }

    fn build_rs256_token_without_kid() -> (String, JwkSet) {
        let (n, e, bad_n) = rs256_public_components();

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

        (rs256_token_without_kid(), jwks)
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
    fn jwt_es512_validates_without_kid_using_all_keys() {
        let (token, jwks) = build_es512_token_without_kid();
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
        assert_eq!(data.claims["sub"], "principal");
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

    #[test]
    fn jwt_rs256_kidless_fails_when_key_beyond_cap() {
        let token = rs256_token_without_kid();
        let (n, e, bad_n) = rs256_public_components();
        let n_b64 = URL_SAFE_NO_PAD.encode(&n);
        let bad_n_b64 = URL_SAFE_NO_PAD.encode(&bad_n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e);

        let mut keys = Vec::new();
        for idx in 0..MAX_KIDLESS_JWKS_KEYS {
            keys.push(json!({
                "kty": "RSA",
                "kid": format!("bad-{}", idx),
                "alg": "RS256",
                "n": bad_n_b64.clone(),
                "e": e_b64.clone(),
            }));
        }
        keys.push(json!({
            "kty": "RSA",
            "kid": "good-key",
            "alg": "RS256",
            "n": n_b64,
            "e": e_b64,
        }));

        let jwks = jwks_from_value(json!({ "keys": keys })).expect("jwks");
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
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &ErrorKind::InvalidSignature),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rs256_kidless_no_compatible_key() {
        let token = rs256_token_without_kid();
        let (_es_token, jwks) = build_es512_token_without_kid();
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
        let expected = format!("{NO_COMPATIBLE_JWK_MESSAGE} RS256 (kid missing)");
        match err {
            Error::Crypto(message) => assert_eq!(message, expected),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_es512_kidless_fails_when_key_beyond_cap() {
        let mut rng = thread_rng();
        let signing_key = P521SigningKey::random(&mut rng);
        let verifying_key = P521VerifyingKey::from(&signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);
        let x = encoded_point.x().expect("x coord");
        let y = encoded_point.y().expect("y coord");

        let mut keys = Vec::new();
        for idx in 0..MAX_KIDLESS_JWKS_KEYS {
            let bad_signing_key = P521SigningKey::random(&mut rng);
            let bad_verifying_key = P521VerifyingKey::from(&bad_signing_key);
            let bad_point = bad_verifying_key.to_encoded_point(false);
            let bad_x = bad_point.x().expect("x coord");
            let bad_y = bad_point.y().expect("y coord");
            keys.push(json!({
                "kty": "EC",
                "crv": "P-521",
                "x": URL_SAFE_NO_PAD.encode(bad_x),
                "y": URL_SAFE_NO_PAD.encode(bad_y),
                "use": "sig",
                "kid": format!("bad-{}", idx),
                "alg": "ES512",
            }));
        }
        keys.push(json!({
            "kty": "EC",
            "crv": "P-521",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "kid": "good-key",
            "alg": "ES512",
        }));

        let jwks = jwks_from_value(json!({ "keys": keys })).expect("jwks");
        let exp = jsonwebtoken::get_current_timestamp() + 3600;
        let payload = json!({
            "iss": "athenz",
            "aud": "client",
            "sub": "principal",
            "exp": exp,
        });
        let header = json!({
            "alg": "ES512",
            "typ": "JWT",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: P521Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{}.{}", signing_input, signature_b64);

        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let mut options = JwtValidationOptions::athenz_default();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(jwt_err) => assert_eq!(jwt_err.kind(), &ErrorKind::InvalidSignature),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rejects_invalid_typ() {
        let (token, jwks) = build_es512_token_with_typ(Some("JAG"));
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let mut options = JwtValidationOptions::athenz_default();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(err) => assert_eq!(err.kind(), &ErrorKind::InvalidToken),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn jwt_rejects_non_string_typ() {
        let (token, jwks) = build_es512_token_with_typ_value(Some(json!(123)));
        let jwks_provider = JwksProvider::new("https://example.com/jwks").expect("provider");
        *jwks_provider.cache.write().unwrap() = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let mut options = JwtValidationOptions::athenz_default();
        options.issuer = Some("athenz".to_string());
        options.audience = vec!["client".to_string()];

        let validator = JwtValidator::new(jwks_provider).with_options(options);
        let err = validator
            .validate_access_token(&token)
            .expect_err("should reject");
        match err {
            Error::Jwt(err) => assert_eq!(err.kind(), &ErrorKind::InvalidToken),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    fn jwks_from_value(value: Value) -> Result<JwkSet, Error> {
        let mut value = value;
        sanitize_jwks(&mut value);
        serde_json::from_value(value).map_err(Error::from)
    }
}
