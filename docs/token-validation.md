# Token Validation

This guide focuses on validating Access/ID Tokens (JWT) using JWKS.

## Basic validation (fetch JWKS)

```rust
use athenz_rs::{JwksProvider, JwtValidator};

# fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let jwks = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?;
let validator = JwtValidator::new(jwks);
let data = validator.validate_access_token(token)?;
println!("claims: {}", data.claims);
# Ok(())
# }
```

`JwksProvider` caches JWKS for 5 minutes by default. Use `with_cache_ttl` to override.

Note: audience validation is enforced when a token includes an `aud` claim. If you do not
set `JwtValidationOptions.audience`, tokens with `aud` will fail with `InvalidAudience`.
Configure the expected audiences when your tokens include `aud`.

## Validation options

You can customize issuer, audience, leeway, and allowed algorithms.

```rust
use athenz_rs::{JwksProvider, JwtValidator, JwtValidationOptions};

# fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let jwks = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?;
let options = JwtValidationOptions {
    issuer: Some("https://zts.example.com/".to_string()),
    audience: vec!["my-audience".to_string()],
    leeway: 30,
    validate_exp: true,
    ..JwtValidationOptions::athenz_default()
};
let validator = JwtValidator::new(jwks).with_options(options);
let _ = validator.validate_id_token(token)?;
# Ok(())
# }
```

The default algorithm allowlist is RS256/RS384/RS512/ES256/ES384/ES512.
ES512 (P-521) is verified internally (not via jsonwebtoken).

## JWKS sanitize report

If you want to remove unsupported `alg` values and inspect what was removed:

```rust
use athenz_rs::{jwks_from_slice_with_report, JwksProvider, JwtValidator};

# fn example(token: &str, jwks_body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let report = jwks_from_slice_with_report(jwks_body)?;
for removed in &report.removed_algs {
    println!("removed alg: kid={:?} alg={:?} reason={:?}", removed.kid, removed.alg, removed.reason);
}

let provider = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?
    .with_preloaded(report.jwks);
let validator = JwtValidator::new(provider);
let _ = validator.validate_access_token(token)?;
# Ok(())
# }
```
