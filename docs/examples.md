# Examples

This project includes runnable examples under `examples/`.

Run an example with:

```sh
cargo run --example issue_access_token
```

Most examples require environment variables for credentials or tokens. If a required
variable is missing, the example prints a hint and exits successfully.

## Environment variables

Common variables used by the examples:

- `ATHENZ_ZTS_URL` (default: `https://zts.example.com/zts/v1`)
- `ATHENZ_CLIENT_CERT_PEM` (path to client certificate PEM)
- `ATHENZ_CLIENT_KEY_PEM` (path to client private key PEM)
- `ATHENZ_NTOKEN_PRIVATE_KEY_PEM` (path to NToken private key PEM)
- `ATHENZ_NTOKEN_PUBLIC_KEY_PEM` (path to NToken public key PEM)
- `ATHENZ_NTOKEN` (raw NToken string)
- `ATHENZ_JWKS_URL` (default: `https://zts.example.com/zts/v1/oauth2/keys`)
- `ATHENZ_JWT` (raw Access/ID token)
- `ATHENZ_POLICY_DOMAIN` (policy domain name)

## Examples list

- `issue_access_token` - issue AccessToken via mTLS
- `issue_id_token` - issue ID Token via NToken auth
- `validate_jwt` - validate Access/ID token using JWKS
- `validate_ntoken` - validate NToken with a public key
- `policy_eval` - fetch policy data and evaluate access
