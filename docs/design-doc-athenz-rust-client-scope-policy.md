# Athenz Rust Client Scope & Policy

## Summary
- Define the functional scope, OpenSSL-independent policy, and testing strategy for the Athenz Rust client for developers.
- Following existing implementations (reqwest + rustls, etc.), document practical and maintainable development and verification rules.

## Goals
- Clearly state the policy to support all APIs provided by Athenz Service.
- Establish the policy to implement the following at production level:
  - Issuance of signed JWTs using private keys/certificates
  - Validation of client-signed JWTs
  - Issuance/renewal of server/client x.509 certificates for mTLS
- Clarify the policy of not depending on OpenSSL.
- Document the testing strategy (mock policy and scope/non-scope of e2e).

## Non-Goals
- Providing a compatibility layer to absorb behavioral differences in Athenz server implementations
- Application to authentication/authorization platforms other than Athenz
- Prioritizing implementation of configurations that allow OpenSSL dependencies (such as FIPS compliance) at this time

## Background / Context
- athenz-rs is a Rust client implementation for Athenz, requiring expanded API coverage and stable validation.
- Existing implementations adopt reqwest + rustls, avoiding dependency on OpenSSL.

## Requirements
### Functional
- Gradually expand ZTS/ZMS API coverage to full coverage.
- Provide stable implementations for JWT/NToken/Policy issuance, validation, and evaluation.
- Provide mTLS authentication and certificate-related APIs at production quality.

### Non-Functional
- Avoid dependency on OpenSSL (rustls/tls as standard).
- Prioritize portability and reproducibility in testing, minimizing external dependencies.
- Maintain a structure that easily follows specification changes (keeping API addition costs low).

## Proposed Design
### Architecture Overview
- Maintain existing module structure (zts / zms / jwt / ntoken / policy).
- API wrappers are based on reqwest blocking, with async considered as needed.

### Components
- ZTS client: OAuth/JWKS/instance/certificate/policy retrieval, etc.
- ZMS client: domain/role/policy/service/group, etc.
- JWT/Policy/NToken: utilities for signing, validation, and evaluation

### Data Model
- Model definitions compliant with Athenz RDL (using serde)

### APIs / Interfaces
- ZTS/ZMS provided as REST API wrappers
- JWT/Policy designed primarily for offline validation

### Data Flow
- Online: API → JSON → model
- Offline: JWKS/signing keys → JWT/Policy/NToken validation

## Operational Plan
### Deployment / Environments
- Available with Rust's standard toolchain
- TLS uses rustls as standard, avoiding OpenSSL dependency

### Observability
- Currently limited to log/error returns, with additional metrics being optional

### Reliability / Failure Modes
- API errors return ResourceError
- JWT/signature validation errors propagate with explicit error types

### Security / Privacy
- OpenSSL-independent (rustls)
- Signature validation maintains an allowlist of permitted algorithms

## Rollout / Migration Plan
- API additions/changes are made gradually, maintaining compatibility with existing methods

## Alternatives Considered
- OpenSSL dependency: Not adopted due to large platform differences and dependency costs
- External ZTS/ZMS integration testing: Minimized from reproducibility and stability perspectives

## Risks and Mitigations
- **Specification difference risk**: Differences from RDL may occur → Cover with schema references and additional tests
- **Missing API additions**: Manage expansion plans for unimplemented APIs as Linear issues
- **Cryptographic compatibility**: Specification differences in signature validation → Explicitly verify with allowlist and tests

## Open Questions
- Whether to officially support async clients
- Whether to support FIPS-required environments

## Appendix
### Testing Strategy (Mock Policy and E2E Scope)
- **Mock Policy**
  - HTTP communication reproduced with local TCP server/mocks (paths/headers/queries/responses)
  - JWKS / JWT / NToken / Policy signature validation verified with locally generated keys
  - ZTS/ZMS dependent parts replaced with minimal request/response patterns

- **E2E scope achievable with mocks**
  - Client URL/parameter generation, response parsing
  - Offline validation of JWT/NToken/Policy
  - Normal/abnormal patterns of signature validation

- **Scope not achievable with mocks**
  - Behavior dependent on actual server environment (permission settings, DB integration, actual signing key updates)
  - Integration behavior with actual ZTS/ZMS (dependent on production-equivalent configuration)
