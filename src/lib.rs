#![forbid(unsafe_code)]

mod build_url;
mod client_defaults;
mod error;
mod jwt;
#[path = "models/mod.rs"]
mod models;
mod ntoken;
mod policy;
mod ybase64;
#[path = "zms/mod.rs"]
mod zms;
#[cfg(feature = "async-client")]
mod zms_async;
#[path = "zts/mod.rs"]
mod zts;
#[cfg(feature = "async-client")]
mod zts_async;

pub use error::{Error, ResourceError};

pub use jwt::{
    jwks_from_slice, jwks_from_slice_with_report, JwksProvider, JwksSanitizeReport, JwtHeader,
    JwtTokenData, JwtValidationOptions, JwtValidator, RemovedAlg, RemovedAlgReason,
};
#[cfg(feature = "async-validate")]
pub use jwt::{JwksProviderAsync, JwtValidatorAsync};

pub use models::{
    AWSTemporaryCredentials, Access, AccessTokenResponse, Assertion, AssertionCondition,
    AssertionConditionData, AssertionConditionOperator, AssertionConditions, AssertionEffect,
    AthenzJwkConfig, CertificateAuthorityBundle, DanglingPolicy, Domain, DomainData,
    DomainDataCheck, DomainGroupMember, DomainGroupMembers, DomainGroupMembership, DomainList,
    DomainMeta, DomainMetaStoreValidValuesList, DomainMetric, DomainMetricType, DomainMetrics,
    DomainPolicies, DomainRoleMember, DomainRoleMembers, DomainSignedPolicyData,
    DomainTemplateDetailsList, Entity, EntityList, ExternalCredentialsRequest,
    ExternalCredentialsResponse, Group, GroupAuditLog, GroupMember, GroupMembership, GroupMeta,
    Groups, HostServices, Info, InstanceConfirmation, InstanceIdentity, InstanceRefreshIdentity,
    InstanceRefreshInformation, InstanceRefreshRequest, InstanceRegisterInformation,
    InstanceRegisterResponse, InstanceRegisterToken, IntrospectResponse, JWSDomain, JWSPolicyData,
    Jwk, JwkList, MemberRole, Membership, OAuthConfig, OidcResponse, OpenIdConfig, Policies,
    Policy, PolicyData, PolicyList, PolicyOptions, PrincipalMember, PrincipalState,
    ProviderResourceGroupRoles, PublicKeyEntry, Quota, RdlSchema, ResourceAccess,
    ResourceDomainOwnership, ResourceGroupOwnership, ResourcePolicyOwnership,
    ResourceRoleOwnership, ResourceServiceIdentityOwnership, ReviewObject, ReviewObjects, Role,
    RoleAccess, RoleAuditLog, RoleCertificate, RoleCertificateRequest, RoleList, RoleMember,
    RoleMeta, RoleToken, Roles, SSHCertRequest, SSHCertRequestData, SSHCertRequestMeta,
    SSHCertificate, SSHCertificates, ServerTemplateList, ServiceIdentities, ServiceIdentity,
    ServiceIdentityList, ServicePrincipal, SignedDomain, SignedDomains, SignedPolicies,
    SignedPolicyData, SignedPolicyRequest, Stats, Status, SubDomain, Template, TemplateMeta,
    Tenancy, TenantDomains, TenantResourceGroupRoles, TenantRoleAction, TopLevelDomain,
    TransportDirection, TransportRule, TransportRules, UserAuthorityAttributeMap,
    UserAuthorityAttributes, UserDomain, UserToken, Workload, Workloads,
};

#[cfg(feature = "async-validate")]
pub use ntoken::NTokenValidatorAsync;
pub use ntoken::{
    NToken, NTokenBuilder, NTokenClaims, NTokenSigner, NTokenValidationOptions, NTokenValidator,
    NTokenValidatorConfig,
};

pub use zts::{
    AccessTokenRequest, AccessTokenRequestBuilder, ConditionalResponse, IdTokenRequest,
    IdTokenResponse, ZtsClient, ZtsClientBuilder,
};
#[cfg(feature = "async-client")]
pub use zts_async::{ZtsAsyncClient, ZtsAsyncClientBuilder};

#[cfg(feature = "async-validate")]
pub use policy::PolicyClientAsync;
pub use policy::{
    PolicyClient, PolicyDecision, PolicyFetchResponse, PolicyMatch, PolicyStore,
    PolicyValidatorConfig,
};

pub use zms::{
    DomainListOptions, GroupGetOptions, GroupsQueryOptions, PoliciesQueryOptions,
    PolicyListOptions, RoleGetOptions, RoleListOptions, RolesQueryOptions,
    ServiceIdentitiesQueryOptions, ServiceListOptions, SignedDomainsOptions, ZmsClient,
    ZmsClientBuilder,
};
#[cfg(feature = "async-client")]
pub use zms_async::{ZmsAsyncClient, ZmsAsyncClientBuilder};
