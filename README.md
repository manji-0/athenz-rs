# athenz-provider-tenant

Rust client for Athenz **token issuance** (tenant side) and **token validation** (provider side).
RoleToken is intentionally not included (deprecated).

## Features

- Issue **AccessToken** via `POST /oauth2/token`
- Issue **ID Token** via `GET /oauth2/auth`
- Validate **Access/ID Tokens** using JWKS (offline)
- **Introspect** AccessToken via `POST /oauth2/introspect`
- Validate **NToken** (service token) using local public key or ZTS public key endpoint
- Auth with **mTLS (x509)** or **Athenz-Principal-Auth** (NToken signed with private key)

## Usage

### Issue AccessToken with mTLS (optionally include ID Token)

```rust
use athenz_provider_tenant::{AccessTokenRequest, ZtsClient};

# fn example(cert: &[u8], key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .mtls_identity_from_parts(cert, key)?
    .build()?;

let req = AccessTokenRequest::builder("sports")
    // override auto-composed scope if needed
    .raw_scope("custom:scope")
    .build();
let token = client.issue_access_token(&req)?;
println!("{}", token.access_token);
# Ok(())
# }
```

### Issue ID Token with private key (NToken auth)

```rust
use athenz_provider_tenant::{IdTokenRequest, NTokenSigner, ZtsClient};

# fn example(private_key_pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let signer = NTokenSigner::new("sports", "api", "v1", private_key_pem)?;
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .ntoken_signer("Athenz-Principal-Auth", signer)
    .build()?;

let mut req = IdTokenRequest::new(
    "sports.api",
    "https://example.com/callback",
    "openid sports:role.reader",
    "nonce-123",
);
req.output = Some("json".to_string());

let response = client.issue_id_token(&req)?;
if let Some(body) = response.response {
    println!("{}", body.id_token);
}
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

### Validate Token with Preloaded JWKS JSON

```rust
use athenz_provider_tenant::{jwks_from_slice, JwtValidator, JwksProvider};

# fn example(token: &str, jwks_body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let jwks = jwks_from_slice(jwks_body)?;
let provider = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?
    .with_preloaded(jwks);
let validator = JwtValidator::new(provider);
let data = validator.validate_access_token(token)?;
println!("claims: {}", data.claims);
# Ok(())
# }
```

### Validate Token with JWKS Sanitize Report

```rust
use athenz_provider_tenant::{jwks_from_slice_with_report, JwksProvider, JwtValidator};

# fn example(token: &str, jwks_body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let report = jwks_from_slice_with_report(jwks_body)?;
for removed in &report.removed_algs {
    println!("removed alg: kid={:?} alg={:?} reason={:?}", removed.kid, removed.alg, removed.reason);
}
let removed_json = serde_json::to_string_pretty(&report.removed_algs)?;
println!("removed json: {}", removed_json);
let report_json = serde_json::to_string_pretty(&report)?;
println!("report json: {}", report_json);
let provider = JwksProvider::new("https://zts.example.com/zts/v1/oauth2/keys")?
    .with_preloaded(report.jwks);
let validator = JwtValidator::new(provider);
let data = validator.validate_access_token(token)?;
println!("claims: {}", data.claims);
# Ok(())
# }
```

### Introspect AccessToken

```rust
use athenz_provider_tenant::{ZtsClient};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .build()?;
let result = client.introspect_access_token("access-token")?;
println!("active: {}", result.active);
# Ok(())
# }
```

### Validate NToken via ZTS public key

```rust
use athenz_provider_tenant::{NTokenValidator, NTokenValidatorConfig};

# fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
let validator = NTokenValidator::new_with_zts(NTokenValidatorConfig::default())?;
let claims = validator.validate(token)?;
println!("principal: {}", claims.principal_name());
# Ok(())
# }
```

### Validate Signed Policy Data and Evaluate Access (ZPU/ZPE)

```rust
use athenz_provider_tenant::{
    PolicyClient, PolicyStore, PolicyDecision, SignedPolicyRequest, ZtsClient,
};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let zts = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .build()?;
let client = PolicyClient::new(zts);

// fetch latest policy data
let response = client.fetch_signed_policy_data("sports", None)?;
if let Some(signed) = response.data {
    let policy_data = client.validate_signed_policy_data(&signed)?;
    let mut store = PolicyStore::new();
    store.insert(policy_data);

    let roles = vec!["sports:role.reader".to_string()];
    let result = store.allow_action("sports", &roles, "read", "sports:resource.read");
    if result.decision == PolicyDecision::Allow {
        println!("allowed");
    }
}
# Ok(())
# }
```

### Fetch JWS Policy Data

```rust
use athenz_provider_tenant::{PolicyClient, SignedPolicyRequest, ZtsClient};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let zts = ZtsClient::builder("https://zts.example.com/zts/v1")?
    .build()?;
let client = PolicyClient::new(zts);

let request = SignedPolicyRequest {
    policy_versions: None,
    signature_p1363_format: Some(true),
};
let response = client.fetch_jws_policy_data("sports", &request, None)?;
if let Some(jws) = response.data {
    let policy_data = client.validate_jws_policy_data(&jws)?;
    println!("domain: {}", policy_data.domain);
}
# Ok(())
# }
```

## Notes

- For mTLS, provide cert+key PEM via `mtls_identity_from_parts` or a combined PEM via `mtls_identity_from_pem`.
- For NToken auth, set the header name (usually `Athenz-Principal-Auth`).
- ZTS base URL should include the `/zts/v1` path.
- If you need the `Location` header from `/oauth2/auth`, disable redirects via `disable_redirect(true)`.
- JWT validation allowlist is RS256/RS384/RS512/ES256/ES384/ES512. ES512 (P-521) is verified internally (not via jsonwebtoken).
- EC private keys must be in PKCS#8 (`PRIVATE KEY`) format; SEC1 (`EC PRIVATE KEY`) is not currently supported.
- `PolicyStore` lowercases action/resource and ignores `case_sensitive`/`conditions` (ZPE behavior).
