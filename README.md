# athenz-rs

Rust client for Athenz token issuance (tenant side) and token validation (provider side).
Crate name: `athenz-provider-tenant`.

RoleToken is intentionally not included (deprecated).

## Features

- Issue **AccessToken** via `POST /oauth2/token`
- Issue **ID Token** via `GET /oauth2/auth`
- Validate **Access/ID Tokens** using JWKS (offline)
- **Introspect** AccessToken via `POST /oauth2/introspect`
- Validate **NToken** (service token) using local public key or ZTS public key endpoint
- Auth with **mTLS (x509)** or **Athenz-Principal-Auth** (NToken signed with private key)

## Requirements

- Rust edition 2021
- Minimum supported Rust version (MSRV): 1.88 (declared in `Cargo.toml`)

## Install

```toml
[dependencies]
athenz-provider-tenant = "0.1"
```

## Quickstart

### Issue AccessToken with mTLS

```rust
use athenz_provider_tenant::{AccessTokenRequest, ZtsClient};

# fn example(cert: &[u8], key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .mtls_identity_from_parts(cert, key)?
    .build()?;

let req = AccessTokenRequest::builder("sports")
    .roles(["reader"])
    .build();
let token = client.issue_access_token(&req)?;
println!("{}", token.access_token);
# Ok(())
# }
```

### Validate Access/ID Token (JWKS)

```rust
use athenz_provider_tenant::{JwksProvider, JwtValidator};

# fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let jwks = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?;
let validator = JwtValidator::new(jwks);
let data = validator.validate_access_token(token)?;
println!("claims: {}", data.claims);
# Ok(())
# }
```

## Documentation

- `docs/README.md` (overview and index)
- `docs/getting-started.md` (install + minimal flow)
- `docs/authentication.md` (mTLS/NToken)
- `docs/token-validation.md` (JWKS, validation options, sanitize report)
- `docs/policy.md` (policy validation and evaluation)
- `docs/design-doc-athenz-rust-client-scope-policy.md` (scope/policy design)

## Notes and Behavior

- ZTS base URL should include the `/zts/v1` path.
- JWT validation allowlist is RS256/RS384/RS512/ES256/ES384/ES512; ES512 (P-521) is verified internally.
- EC private keys must be in PKCS#8 (`PRIVATE KEY`) format; SEC1 (`EC PRIVATE KEY`) is not supported.
- `PolicyStore` lowercases action/resource and ignores `case_sensitive`/`conditions` (ZPE behavior).

## License

Apache-2.0. See `LICENSE`.
