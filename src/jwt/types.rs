use jsonwebtoken::Algorithm;
use serde_json::Value;

use super::constants::{ATHENZ_ALLOWED_ALGS, ATHENZ_EC_ALGS, ATHENZ_RSA_ALGS};

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
    pub jwks: jsonwebtoken::jwk::JwkSet,
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
