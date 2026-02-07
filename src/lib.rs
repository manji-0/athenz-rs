#![forbid(unsafe_code)]

mod error;
mod jwt;
mod models;
mod ntoken;
mod policy;
mod zms;
mod zts;
#[cfg(feature = "async-client")]
mod zms_async;

pub use error::{Error, ResourceError};

pub use jwt::{
    jwks_from_slice, jwks_from_slice_with_report, JwksProvider, JwksSanitizeReport, JwtHeader,
    JwtTokenData, JwtValidationOptions, JwtValidator, RemovedAlg, RemovedAlgReason,
};

pub use models::{
    AccessTokenResponse, Assertion, AssertionCondition, AssertionConditionData,
    AssertionConditionOperator, AssertionConditions, AssertionEffect, AthenzJwkConfig,
    CertificateAuthorityBundle, Domain, DomainList, DomainMeta, DomainMetric, DomainMetricType,
    DomainMetrics, DomainSignedPolicyData, ExternalCredentialsRequest, ExternalCredentialsResponse,
    Group, GroupAuditLog, GroupMember, GroupMembership, GroupMeta, Groups, Info, InstanceIdentity,
    InstanceRefreshInformation, InstanceRegisterInformation, InstanceRegisterResponse,
    InstanceRegisterToken, IntrospectResponse, JWSPolicyData, Jwk, JwkList, Membership,
    OAuthConfig, OidcResponse, OpenIdConfig, Policies, Policy, PolicyData, PolicyList,
    PublicKeyEntry, RdlSchema, ResourceDomainOwnership, ResourceGroupOwnership,
    ResourcePolicyOwnership, ResourceRoleOwnership, ResourceServiceIdentityOwnership, Role,
    RoleAccess, RoleAuditLog, RoleCertificate, RoleCertificateRequest, RoleList, RoleMember,
    RoleMeta, Roles, SSHCertRequest, SSHCertRequestData, SSHCertRequestMeta, SSHCertificate,
    SSHCertificates, ServiceIdentities, ServiceIdentity, ServiceIdentityList, SignedPolicyData,
    SignedPolicyRequest, Status, SubDomain, TopLevelDomain, TransportDirection, TransportRule,
    TransportRules, UserDomain, Workload, Workloads,
};

pub use ntoken::{
    NToken, NTokenBuilder, NTokenClaims, NTokenSigner, NTokenValidator, NTokenValidatorConfig,
};

pub use zts::{
    AccessTokenRequest, AccessTokenRequestBuilder, ConditionalResponse, IdTokenRequest,
    IdTokenResponse, ZtsClient, ZtsClientBuilder,
};

pub use policy::{
    PolicyClient, PolicyDecision, PolicyFetchResponse, PolicyMatch, PolicyStore,
    PolicyValidatorConfig,
};

pub use zms::{
    DomainListOptions, GroupGetOptions, GroupsQueryOptions, PoliciesQueryOptions,
    PolicyListOptions, RoleGetOptions, RoleListOptions, RolesQueryOptions,
    ServiceIdentitiesQueryOptions, ServiceListOptions, ZmsClient, ZmsClientBuilder,
};
#[cfg(feature = "async-client")]
pub use zms_async::{ZmsAsyncClient, ZmsAsyncClientBuilder};
