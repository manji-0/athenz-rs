# Getting Started

This guide shows the minimum steps to issue an AccessToken.

## 1. Add the dependency

```toml
[dependencies]
athenz-rs = "0.1"
```

## 2. Choose your ZTS base URL

ZTS base URL should include the `/zts/v1` path, for example:

- `https://zts.example.com/zts/v1`

## 3. Build a client and issue an AccessToken

Below is the smallest working flow using mTLS.

```rust
use athenz_rs::{AccessTokenRequest, ZtsClient};

# fn example(cert: &[u8], key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .mtls_identity_from_parts(cert, key)?
    .build()?;

let request = AccessTokenRequest::builder("sports")
    .roles(["reader"])
    .build();

let token = client.issue_access_token(&request)?;
let access_token = token.access_token.as_deref().expect("access token");
println!("{access_token}");
# Ok(())
# }
```

`issue_access_token` is strict for ordinary access-token requests. If ZTS omits
`access_token`, the call returns an error. The only supported token-only
exception is token exchange with `requested_token_type` set to the ID-token URN,
in which case `AccessTokenResponse.id_token` carries the result.

## Next steps

- If you authenticate with NToken instead of mTLS, see `authentication.md`.
- For token validation (JWKS), see `token-validation.md`.
- For policy evaluation, see `policy.md`.
