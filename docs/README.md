# Documentation

This folder contains user and developer documentation for `athenz-provider-tenant`.
If you are new, start with `getting-started.md` and then move to the topic guides.

## Quick example

```rust
use athenz_provider_tenant::ZtsClient;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .build()?;
# let _ = client;
# Ok(())
# }
```

## Index

- `getting-started.md` - install and first AccessToken issuance
- `authentication.md` - mTLS/NToken authentication and key formats
- `token-validation.md` - JWKS fetch, validation options, sanitize report
- `policy.md` - policy validation and evaluation (ZPU/ZPE)
- `architecture.md` - module overview and data flow
- `faq.md` - frequently asked questions
- `clients.md` - ZTS/ZMS client configuration
- `api-coverage.md` - implemented ZTS/ZMS endpoints
- `design-doc-athenz-rust-client-scope-policy.md` - scope/policy design doc

## Other repository docs

- `../CONTRIBUTING.md`
- `../SECURITY.md`
- `../CHANGELOG.md`
