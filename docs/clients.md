# Clients

This guide explains how to configure ZTS and ZMS clients.

By default, `ZtsClient`/`ZmsClient` use blocking `reqwest`.
Enable the `async-client` feature to use async variants:

- `ZtsAsyncClient` / `ZtsAsyncClientBuilder`
- `ZmsAsyncClient` / `ZmsAsyncClientBuilder`

## ZTS client

```rust
use std::time::Duration;
use athenz_rs::{NTokenSigner, ZtsClient};

# fn example(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8], ntoken_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let signer = NTokenSigner::new("sports", "api", "v1", ntoken_key)?;

let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .timeout(Duration::from_secs(10))
    .disable_redirect(true)
    .mtls_identity_from_parts(cert_pem, key_pem)?
    .add_ca_cert_pem(ca_pem)?
    .ntoken_signer("Athenz-Principal-Auth", signer)
    .build()?;
# let _ = client;
# Ok(())
# }
```

Notes:

- If you do not call `timeout`, the client uses a 30s default request timeout.
- `disable_redirect(true)` is useful if you need the `Location` header from `/oauth2/auth`.
- If you already have a combined PEM (cert + key), use `mtls_identity_from_pem`.
- Use `ntoken_auth` if you already have a signed NToken string.

## ZMS client

`ZmsClient` has the same builder options as `ZtsClient`.

```rust
use std::time::Duration;
use athenz_rs::ZmsClient;

# fn example(cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let client = ZmsClient::builder("https://zms.example.com/zms/v1")?
    .timeout(Duration::from_secs(10))
    .mtls_identity_from_parts(cert_pem, key_pem)?
    .build()?;
# let _ = client;
# Ok(())
# }
```

Notes:

- If you do not call `timeout`, the client uses a 30s default request timeout.
