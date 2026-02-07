#![forbid(unsafe_code)]

mod error;
mod jwt;
mod models;
mod ntoken;
mod policy;
mod zms;
mod zts;

pub use error::{Error, ResourceError};

pub use jwt::{
    jwks_from_slice, jwks_from_slice_with_report, JwtHeader, JwtTokenData, JwtValidationOptions,
    JwtValidator, JwksProvider, JwksSanitizeReport, RemovedAlg, RemovedAlgReason,
};

pub use models::{
    Access, AccessTokenResponse, AthenzJwkConfig, AWSTemporaryCredentials, CertificateAuthorityBundle,
    DomainMetaStoreValidValuesList, DomainTemplate, DomainTemplateDetailsList, DomainTemplateList,
    Entity, EntityList, ExternalCredentialsRequest, ExternalCredentialsResponse, Identity, Info,
    InstanceIdentity, InstanceRefreshInformation, InstanceRefreshRequest, InstanceRegisterInformation,
    InstanceRegisterResponse, InstanceRegisterToken, IntrospectResponse, Jwk, JwkList, OAuthConfig,
    OidcResponse, OpenIdConfig, PublicKeyEntry, RdlSchema, ResourceAccess, RoleAccess,
    RoleCertificate, RoleCertificateRequest, RoleSystemMeta, RoleToken, SSHCertRequest,
    SSHCertRequestData, SSHCertRequestMeta, SSHCertificate, SSHCertificates, ServerTemplateList,
    ServiceIdentitySystemMeta, Status, Template, TemplateList, TemplateMetaData, TemplateParam,
    TenantDomains, TransportDirection, TransportRule, TransportRules, Workload, Workloads,
    DomainMetric, DomainMetricType, DomainMetrics,
    Assertion, AssertionCondition, AssertionConditionData, AssertionConditionOperator,
    AssertionConditions, AssertionEffect, Domain, DomainList, DomainMeta, Group, GroupAuditLog,
    GroupMember, GroupMembership, GroupMeta, GroupSystemMeta, Groups, Membership, MemberRole,
    Policies, Policy, PolicyList, ResourceDomainOwnership, ResourceGroupOwnership,
    ResourcePolicyOwnership, ResourceRoleOwnership, ResourceServiceIdentityOwnership, Role,
    RoleAuditLog, RoleList, RoleMember, RoleMeta, Roles, ServiceIdentities, ServiceIdentity,
    ServiceIdentityList, SubDomain, TopLevelDomain, UserDomain, PolicyData, SignedPolicyData,
    DomainSignedPolicyData, JWSPolicyData, SignedPolicyRequest, DomainRoleMember, DomainRoleMembers,
    DomainRoleMembership, DomainGroupMember, DomainGroupMembers, DomainGroupMembership, ReviewObject,
    ReviewObjects,
};

pub use ntoken::{
    NToken, NTokenBuilder, NTokenClaims, NTokenSigner, NTokenValidator, NTokenValidatorConfig,
};

pub use zts::{
    AccessTokenRequest, AccessTokenRequestBuilder, IdTokenRequest, IdTokenResponse, ZtsClient,
    ZtsClientBuilder, ConditionalResponse,
};

pub use policy::{
    PolicyClient, PolicyDecision, PolicyFetchResponse, PolicyMatch, PolicyStore, PolicyValidatorConfig,
};

pub use zms::{
    DomainListOptions, GroupGetOptions, GroupsQueryOptions, PoliciesQueryOptions, PolicyListOptions,
    RoleGetOptions, RoleListOptions, RolesQueryOptions, ServiceIdentitiesQueryOptions,
    ServiceListOptions, ZmsClient, ZmsClientBuilder,
};
