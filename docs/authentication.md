# Authentication

`athenz-rs` supports two authentication styles for ZTS calls:

- mTLS using x.509 certificates
- NToken using the `Athenz-Principal-Auth` header

## mTLS (x.509)

Provide a client certificate and private key in PEM format.

```rust
use athenz_rs::ZtsClient;

# fn example(cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .mtls_identity_from_parts(cert_pem, key_pem)?
    .build()?;
# let _ = client;
# Ok(())
# }
```

If you already have a combined PEM (cert + key), use `mtls_identity_from_pem`.
You can also add custom CA certificates via `add_ca_cert_pem`.

## NToken (Athenz-Principal-Auth)

There are two options:

- Precompute an NToken and pass it as a header value (`ntoken_auth`)
- Use `NTokenSigner` to sign and refresh automatically (`ntoken_signer`)

```rust
use athenz_rs::{NTokenSigner, ZtsClient};

# fn example(private_key_pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let signer = NTokenSigner::new("sports", "api", "v1", private_key_pem)?;
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .ntoken_signer("Athenz-Principal-Auth", signer)
    .build()?;
# let _ = client;
# Ok(())
# }
```

## Key formats

- RSA private keys: PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`)
- EC private keys: PKCS#8 only (`PRIVATE KEY`)
- EC keys in SEC1 (`EC PRIVATE KEY`) are not supported

Public key validation supports RSA/EC keys in PKCS#1 or PKCS#8 public key PEM.
