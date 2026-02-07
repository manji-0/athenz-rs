# Architecture

This document provides a high-level overview of the crate's structure and data flow.

## Module map

- `zts` / `zms`: HTTP clients for ZTS/ZMS APIs (blocking `reqwest`)
- `jwt`: JWKS parsing and JWT validation
- `ntoken`: NToken signing and validation (RSA/ECDSA)
- `policy`: Signed policy validation and local policy evaluation
- `models`: RDL-based data models (serde)
- `error`: shared error types

## Data flow

### ZTS/ZMS API calls

```
client -> build request -> HTTP -> JSON -> model structs
```

Clients are synchronous and use `reqwest::blocking` with optional mTLS or
NToken auth headers.

### JWT validation

```
JWKS (HTTP or preloaded) -> sanitize -> select JWK -> validate token
```

- `JwksProvider` caches JWKS in memory (default 5 minutes).
- ES512 (P-521) is validated internally since `jsonwebtoken` does not support it.

### NToken validation

```
NToken -> parse -> verify signature (public key or ZTS) -> claims
```

- Can validate using a static public key or fetch keys via ZTS.
- Keys are cached for a configurable TTL.

### Policy evaluation

```
Signed policy data -> signature verification -> PolicyStore -> allow/deny
```

`PolicyStore` normalizes action/resource to lowercase and evaluates deny rules
before allow rules, matching ZPE behavior.

## Design choices

- **No OpenSSL dependency**: uses `rustls` and pure Rust crypto crates.
- **Blocking clients**: simple, deterministic behavior for server-side usage.
- **Explicit allowlist**: JWT algorithms are validated against a fixed allowlist.
