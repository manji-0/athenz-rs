use jsonwebtoken::Algorithm;

/// Fixed allowlist for Athenz JWT validation (jsonwebtoken-supported subset).
pub const ATHENZ_ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];
pub(super) const ATHENZ_RSA_ALGS: &[Algorithm] =
    &[Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];
pub(super) const ATHENZ_EC_ALGS: &[Algorithm] = &[Algorithm::ES256, Algorithm::ES384];
pub(super) const ATHENZ_ALLOWED_ALG_NAMES: &[&str] =
    &["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"];
pub(super) const ATHENZ_ALLOWED_JWT_TYPES: &[&str] = &["at+jwt", "jwt"];
pub(super) const ES512_DISABLED_MESSAGE: &str =
    "ES512 is not enabled; set JwtValidationOptions.allow_es512 = true and include ES256/ES384 in allowed_algs, or use JwtValidationOptions::with_es512()";
// Safety bound on how many kid-less JWKS keys we try when no `kid` is present in the JWT.
// `10` was chosen to cover typical deployments where JWKS sets are small (O(1–10) active keys)
// while preventing unbounded work on misconfigured or very large JWKS endpoints.
pub(super) const MAX_KIDLESS_JWKS_KEYS: usize = 10;
pub(super) const NO_COMPATIBLE_JWK_MESSAGE: &str = "no compatible jwks key for alg";
pub(super) const SUPPORTED_JWK_ALGS: &[&str] = &[
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
