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
    pub validate_nbf: bool,
    pub allowed_algs: Vec<Algorithm>,
    /// When true, ES512 validation is permitted (requires EC algorithms in `allowed_algs`).
    pub allow_es512: bool,
}

impl JwtValidationOptions {
    pub fn athenz_default() -> Self {
        Self {
            issuer: None,
            audience: Vec::new(),
            leeway: 0,
            validate_exp: true,
            validate_nbf: true,
            allowed_algs: ATHENZ_ALLOWED_ALGS.to_vec(),
            allow_es512: false,
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

    pub fn with_es512(mut self) -> Self {
        // ES512 verification relies on EC allowlist checks for ES256/ES384.
        self.allow_es512 = true;
        for alg in ATHENZ_EC_ALGS {
            if !self.allowed_algs.contains(alg) {
                self.allowed_algs.push(*alg);
            }
        }
        self
    }
}

impl Default for JwtValidationOptions {
    fn default() -> Self {
        Self::athenz_default()
    }
}
