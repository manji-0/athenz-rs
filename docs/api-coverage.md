# API Coverage

This document summarizes the currently implemented ZTS and ZMS APIs.
It is based on the public client methods in `src/zts.rs` and `src/zms.rs`.

If you add new endpoints, update this list.

## ZTS (tenant/provider)

- OAuth/OIDC: issue AccessToken, issue ID Token, introspect token
- OpenID/OAuth config: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`
- JWKS / public keys: get JWK list, get public key entry
- Instance identity: register, refresh, delete instance, get register token
- Certificate authority: fetch CA bundle
- SSH certificates: post SSH certificate request
- Workloads / host mapping: query by service or IP, enumerate host services
- Transport rules: fetch transport rules
- External credentials: post external credentials
- Status / info / schema: ZTS health and RDL schema
- Role access: check role access, list roles requiring certs
- Role tokens: get role token, post deprecated role token endpoint
- Role certificates: request role certificates
- Resource access: check resource access, check resource access ext
- Policy data: fetch signed policy data, fetch JWS policy data

## ZMS (management)

- Domain:
  - Get domain, list domains
  - Get modified signed domains (`/sys/modified_domains`)
  - Get signed domain JWS (`/domain/{name}/signed`)
  - Get/update/delete domain quota (`/domain/{name}/quota`)
  - Create top-level, sub-, and user domains
  - Delete top-level, sub-, and user domains
  - Update domain metadata
- Roles:
  - List roles / role list, get role
  - Create/update role, delete role
  - Role membership get/put/delete
- Policies:
  - List policies / policy list, get policy
  - Create/update policy, delete policy
  - Policy version management: list/get/create/activate/delete version
  - Assertion get/put/delete
- Service identities:
  - Get service identity, list service identities
  - Create/update service identity, delete service identity
  - Public key entry get/put/delete
- Entities:
  - Get entity, list entities
  - Create/update entity, delete entity
- Groups:
  - Get groups, list groups
  - Get principal groups (`/group?principal=&domain=`)
  - Create/update group, delete group
  - Group membership get/put/delete

## Gaps / to be tracked

- This list does not claim full parity with all Athenz ZTS/ZMS endpoints.
- Add missing APIs as they are implemented and update this document.
