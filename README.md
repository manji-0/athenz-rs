# athenz-rs

Rust client for Athenz token issuance (tenant side) and token validation (provider side).
Crate name: `athenz-rs`.

## Features

- Issue **AccessToken** via `POST /oauth2/token`
- Issue **ID Token** via `GET /oauth2/auth`
- Get **RoleToken** via `GET /domain/{domain}/token` (plus deprecated `POST /domain/{domain}/role/{role}/token`)
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
athenz-rs = "0.1"
```

## Feature Flags

Choose one dependency entry based on your use case:

Enable async ZTS/ZMS clients:
```toml
[dependencies]
athenz-rs = { version = "0.1", features = ["async-client"] }
```

Enable async NToken/JWT validation (includes `async-client`):
```toml
[dependencies]
athenz-rs = { version = "0.1", features = ["async-validate"] }
```

## Quickstart

### Issue AccessToken with mTLS

```rust
use athenz_rs::{AccessTokenRequest, ZtsClient};

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
use athenz_rs::{JwksProvider, JwtValidator};

# fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let jwks = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?;
let validator = JwtValidator::new(jwks);
let data = validator.validate_access_token(token)?;
println!("claims: {}", data.claims);
# Ok(())
# }
```

### Issue AccessToken with async ZTS client (`async-client`)

```rust
use athenz_rs::{AccessTokenRequest, ZtsAsyncClient};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsAsyncClient::builder("https://zts.example.com/zts/v1")?
    .build()?;

let req = AccessTokenRequest::builder("sports")
    .roles(["reader"])
    .build();
let token = client.issue_access_token(&req).await?;
println!("{}", token.access_token);
# Ok(())
# }
```

### Call ZMS metadata with async client (`async-client`)

```rust
use athenz_rs::ZmsAsyncClient;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = ZmsAsyncClient::builder("https://zms.example.com/zms/v1")?
    .build()?;
let status = client.get_status().await?;
println!("status={} {}", status.code, status.message);
# Ok(())
# }
```

### Validate NToken with async validator (`async-validate`)

```rust
use athenz_rs::{NTokenValidatorAsync, NTokenValidatorConfig};

# async fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let mut config = NTokenValidatorConfig::default();
config.zts_base_url = "https://zts.example.com/zts/v1".to_string();

let validator = NTokenValidatorAsync::new_with_zts(config)?;
let claims = validator.validate(token).await?;
println!("service={}.{}", claims.domain, claims.name);
# Ok(())
# }
```

## Documentation

- `docs/README.md` (overview and index)
- `docs/getting-started.md` (install + minimal flow)
- `docs/authentication.md` (mTLS/NToken)
- `docs/token-validation.md` (JWKS, validation options, sanitize report)
- `docs/policy.md` (policy validation and evaluation)
- `docs/examples.md` (runnable examples)
- `docs/architecture.md` (module overview and data flow)
- `docs/faq.md` (frequently asked questions)
- `docs/clients.md` (client configuration)
- `docs/onboarding.md` (onboarding guide for new maintainers)
- `docs/operations-handover.md` (operations handover checklist/template)
- `docs/api-coverage.md` (implemented ZTS/ZMS endpoints)
- `docs/design-doc-athenz-rust-client-scope-policy.md` (scope/policy design)
- `CODE_OF_CONDUCT.md` (community guidelines)
- `SUPPORT.md` (support and issue reporting)
- `MAINTAINERS.md` (maintainer list)
- `SECURITY.md` (vulnerability reporting)
- `CHANGELOG.md` (release notes)

## Notes and Behavior

- ZTS base URL should include the `/zts/v1` path.
- `async-client` requires running inside an async runtime (for example Tokio).
- `async-validate` enables async JWT/NToken validation and implies `async-client`.
- JWT validation allowlist defaults to RS256/RS384/RS512/ES256/ES384. ES512 (P-521) is verified internally and must be explicitly enabled via `JwtValidationOptions.allow_es512` with EC algorithms in `allowed_algs` (or use `.with_es512()`).
- EC private keys must be in PKCS#8 (`PRIVATE KEY`) format; SEC1 (`EC PRIVATE KEY`) is not supported.
- `PolicyStore` lowercases action/resource and ignores `case_sensitive`/`conditions` (ZPE behavior).

## License

Apache-2.0. See `LICENSE`.
