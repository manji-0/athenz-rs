# FAQ

## What base URL should I use?

Include the version path:

- ZTS: `https://<host>/zts/v1`
- ZMS: `https://<host>/zms/v1`

## Does this crate support async clients?

Not currently. The clients are synchronous and use `reqwest::blocking`.

## Which JWT algorithms are allowed?

The default allowlist is RS256/RS384/RS512/ES256/ES384.
ES512 (P-521) is verified internally (not via `jsonwebtoken`) and is disabled by default.
Enable it via `JwtValidationOptions.allow_es512` with EC algorithms in `allowed_algs` (or use `.with_es512()`).

## What key formats are supported?

- RSA private keys: PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`)
- EC private keys: PKCS#8 only (`PRIVATE KEY`)
- SEC1 EC keys (`EC PRIVATE KEY`) are not supported

## How do I get the `Location` header for `/oauth2/auth`?

Call `disable_redirect(true)` on the client builder to prevent following
redirects.

## How do I add custom CAs for mTLS?

Use `add_ca_cert_pem` on the client builder and pass a CA certificate PEM.

## Why does `PolicyStore` ignore `case_sensitive` and `conditions`?

It matches ZPE behavior by normalizing action/resource to lowercase and
ignoring conditions.
