# API Coverage

This document summarizes the currently implemented ZTS and ZMS APIs.
It is based on the public client methods in `src/zts.rs` and `src/zms.rs`.

If you add new endpoints, update this list.

## ZTS (tenant/provider)

- OAuth/OIDC: issue AccessToken, issue ID Token, introspect token
- OpenID/OAuth config: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`
- JWKS / public keys: get JWK list, get public key entry
- Service identities: get service identity, list service identities
- Instance identity: register, refresh, delete instance, get register token
- Instance provider confirmation: post instance confirmation, post refresh confirmation
- Certificate authority: fetch CA bundle
- SSH certificates: post SSH certificate request
- Workloads / host mapping: query by service or IP, enumerate host services
- Tenancy lookup: list tenant domains for provider/user
- Transport rules: fetch transport rules
- External credentials: post external credentials
- Status / info / schema: ZTS health and RDL schema
- Role access: check role access, list roles requiring certs
- Role tokens: get role token, get AWS temporary credentials, post deprecated role token endpoint
- Role certificates: request role certificates
- Resource access: check resource access, check resource access ext
- Policy data: fetch signed policy data, fetch JWS policy data

## ZMS (management)

- Domain:
  - Get domain, list domains
  - Get modified signed domains (`/sys/modified_domains`)
  - Get signed domain JWS (`/domain/{name}/signed`)
  - Get/update/delete domain quota (`/domain/{name}/quota`)
  - Update domain system meta (`/domain/{name}/meta/system/{attribute}`)
  - Get domain metastore valid values (`/domain/metastore?attribute=&user=`)
  - Set domain ownership (`/domain/{name}/ownership`)
  - Create top-level, sub-, and user domains
  - Delete top-level, sub-, and user domains
  - Update domain metadata
- Roles:
  - List roles / role list, get role
  - List role members by domain (`/domain/{name}/member`) and overdue members (`/domain/{name}/overdue`)
  - Create/update role, delete role
  - Role membership get/put/delete
- Policies:
  - List policies / policy list, get policy
  - Set policy ownership (`/domain/{name}/policy/{policy}/ownership`)
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
  - Get groups for review (`/review/group?principal=`)
  - List group members by domain (`/domain/{name}/group/member`)
  - Update group meta/system meta, review state, and ownership
  - Create/update group, delete group
  - Group membership get/put/delete
- Review:
  - Get roles for review (`/review/role?principal=`)
- Dependency:
  - Register/unregister dependency (`/dependency/domain/{domainName}`)
  - List dependent services, service resource groups, and domains
- Access:
  - Check access (`/access/{action}/{resource}` and `/access/{action}?resource=`)
  - List principal resource access (`/resource?principal=&action=&filter=`)
- User:
  - List users (`/user?domain=`)
  - Delete user and delete domain member (`/user/{name}`, `/domain/{domainName}/member/{memberName}`)

## Gaps / to be tracked

- This list does not claim full parity with all Athenz ZTS/ZMS endpoints.
- Add missing APIs as they are implemented and update this document.
