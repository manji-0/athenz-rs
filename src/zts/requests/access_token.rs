/// Request parameters for AccessToken issuance.
/// Use `new()`/`builder()` for forward-compatible construction.
const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AccessTokenRequest {
    pub domain: String,
    pub roles: Vec<String>,
    pub id_token_service: Option<String>,
    /// If set, this value is used as-is and overrides role/id_token_service scope composition.
    pub raw_scope: Option<String>,
    /// OAuth `grant_type`.
    ///
    /// When unset, this is inferred from request fields:
    /// - if token exchange fields are present -> `urn:ietf:params:oauth:grant-type:token-exchange`
    /// - else, if `assertion` is present -> `urn:ietf:params:oauth:grant-type:jwt-bearer`
    /// - else -> `client_credentials`
    pub grant_type: Option<String>,
    pub expires_in: Option<i32>,
    pub proxy_principal_spiffe_uris: Option<String>,
    pub proxy_for_principal: Option<String>,
    pub authorization_details: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub assertion: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub actor: Option<String>,
    pub openid_issuer: Option<bool>,
}

impl AccessTokenRequest {
    /// Creates an access token request with the provided domain and roles.
    pub fn new(domain: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            domain: domain.into(),
            roles,
            id_token_service: None,
            raw_scope: None,
            grant_type: None,
            expires_in: None,
            proxy_principal_spiffe_uris: None,
            proxy_for_principal: None,
            authorization_details: None,
            client_assertion_type: None,
            client_assertion: None,
            requested_token_type: None,
            audience: None,
            resource: None,
            subject_token: None,
            subject_token_type: None,
            assertion: None,
            actor_token: None,
            actor_token_type: None,
            actor: None,
            openid_issuer: None,
        }
    }

    /// Returns a builder for access token requests.
    pub fn builder(domain: impl Into<String>) -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder::new(domain)
    }

    /// Serializes the request into an application/x-www-form-urlencoded body.
    pub fn to_form(&self) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("grant_type", self.resolved_grant_type());
        if let Some(expires_in) = self.expires_in {
            params.append_pair("expires_in", &expires_in.to_string());
        }
        if let Some(ref proxy) = self.proxy_principal_spiffe_uris {
            params.append_pair("proxy_principal_spiffe_uris", proxy);
        }
        if let Some(ref proxy_for_principal) = self.proxy_for_principal {
            params.append_pair("proxy_for_principal", proxy_for_principal);
        }
        if let Some(ref authorization_details) = self.authorization_details {
            params.append_pair("authorization_details", authorization_details);
        }
        if let Some(ref client_assertion_type) = self.client_assertion_type {
            params.append_pair("client_assertion_type", client_assertion_type);
        }
        if let Some(ref client_assertion) = self.client_assertion {
            params.append_pair("client_assertion", client_assertion);
        }
        if let Some(ref requested_token_type) = self.requested_token_type {
            params.append_pair("requested_token_type", requested_token_type);
        }
        if let Some(ref audience) = self.audience {
            params.append_pair("audience", audience);
        }
        if let Some(ref resource) = self.resource {
            params.append_pair("resource", resource);
        }
        if let Some(ref subject_token) = self.subject_token {
            params.append_pair("subject_token", subject_token);
        }
        if let Some(ref subject_token_type) = self.subject_token_type {
            params.append_pair("subject_token_type", subject_token_type);
        }
        if let Some(ref assertion) = self.assertion {
            params.append_pair("assertion", assertion);
        }
        if let Some(ref actor_token) = self.actor_token {
            params.append_pair("actor_token", actor_token);
        }
        if let Some(ref actor_token_type) = self.actor_token_type {
            params.append_pair("actor_token_type", actor_token_type);
        }
        if let Some(ref actor) = self.actor {
            params.append_pair("actor", actor);
        }
        if let Some(openid_issuer) = self.openid_issuer {
            params.append_pair("openid_issuer", &openid_issuer.to_string());
        }
        params.append_pair("scope", &self.scope());
        params.finish()
    }

    fn resolved_grant_type(&self) -> &str {
        if let Some(ref grant_type) = self.grant_type {
            return grant_type.as_str();
        }
        if self.uses_token_exchange_fields() {
            return GRANT_TYPE_TOKEN_EXCHANGE;
        }
        if self.assertion.is_some() {
            return GRANT_TYPE_JWT_BEARER;
        }
        GRANT_TYPE_CLIENT_CREDENTIALS
    }

    fn uses_token_exchange_fields(&self) -> bool {
        self.subject_token.is_some()
            || self.subject_token_type.is_some()
            || self.requested_token_type.is_some()
            || self.actor_token.is_some()
            || self.actor_token_type.is_some()
            || self.actor.is_some()
    }

    fn scope(&self) -> String {
        if let Some(ref raw_scope) = self.raw_scope {
            return raw_scope.clone();
        }
        let mut scopes = Vec::new();
        if self.roles.is_empty() {
            scopes.push(format!("{}:domain", self.domain));
        } else {
            scopes.extend(
                self.roles
                    .iter()
                    .map(|role| format!("{}:role.{}", self.domain, role)),
            );
        }
        if let Some(ref service) = self.id_token_service {
            scopes.push("openid".to_string());
            scopes.push(format!("{}:service.{}", self.domain, service));
        }
        scopes.join(" ")
    }
}

#[derive(Debug, Clone)]
/// Builder for constructing [`AccessTokenRequest`] values.
///
/// This is the preferred, forward-compatible way to create access token requests.
/// It composes the OAuth/OIDC `scope` parameter from `domain`, `roles`, and
/// `id_token_service`. If [`raw_scope`](AccessTokenRequestBuilder::raw_scope)
/// is set, that value is used as-is and overrides the composed scopes.
///
/// The underlying [`AccessTokenRequest`] struct remains public, so you can still
/// mutate its fields directly if needed, but using this builder is recommended
/// to remain compatible with future extensions.
pub struct AccessTokenRequestBuilder {
    request: AccessTokenRequest,
}

impl AccessTokenRequestBuilder {
    /// Creates a builder with the provided domain.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            request: AccessTokenRequest::new(domain, Vec::new()),
        }
    }

    /// Sets the roles to include in the scope.
    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.request.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the service name for ID token scope.
    pub fn id_token_service(mut self, service: impl Into<String>) -> Self {
        self.request.id_token_service = Some(service.into());
        self
    }

    /// Overrides composed scopes from roles/id_token_service.
    pub fn raw_scope(mut self, scope: impl Into<String>) -> Self {
        self.request.raw_scope = Some(scope.into());
        self
    }

    /// Sets OAuth `grant_type` explicitly, overriding inferred defaults.
    pub fn grant_type(mut self, grant_type: impl Into<String>) -> Self {
        self.request.grant_type = Some(grant_type.into());
        self
    }

    /// Sets the requested token expiration in seconds.
    pub fn expires_in(mut self, value: i32) -> Self {
        self.request.expires_in = Some(value);
        self
    }

    /// Sets the proxy principal SPIFFE URIs.
    pub fn proxy_principal_spiffe_uris(mut self, value: impl Into<String>) -> Self {
        self.request.proxy_principal_spiffe_uris = Some(value.into());
        self
    }

    /// Sets the proxy-for principal.
    pub fn proxy_for_principal(mut self, value: impl Into<String>) -> Self {
        self.request.proxy_for_principal = Some(value.into());
        self
    }

    /// Sets authorization details.
    pub fn authorization_details(mut self, value: impl Into<String>) -> Self {
        self.request.authorization_details = Some(value.into());
        self
    }

    /// Sets the client assertion type.
    pub fn client_assertion_type(mut self, value: impl Into<String>) -> Self {
        self.request.client_assertion_type = Some(value.into());
        self
    }

    /// Sets the client assertion.
    pub fn client_assertion(mut self, value: impl Into<String>) -> Self {
        self.request.client_assertion = Some(value.into());
        self
    }

    /// Sets the requested token type.
    pub fn requested_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.requested_token_type = Some(value.into());
        self
    }

    /// Sets the audience parameter.
    pub fn audience(mut self, value: impl Into<String>) -> Self {
        self.request.audience = Some(value.into());
        self
    }

    /// Sets the resource parameter.
    pub fn resource(mut self, value: impl Into<String>) -> Self {
        self.request.resource = Some(value.into());
        self
    }

    /// Sets the subject token.
    pub fn subject_token(mut self, value: impl Into<String>) -> Self {
        self.request.subject_token = Some(value.into());
        self
    }

    /// Sets the subject token type.
    pub fn subject_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.subject_token_type = Some(value.into());
        self
    }

    /// Sets the assertion parameter.
    pub fn assertion(mut self, value: impl Into<String>) -> Self {
        self.request.assertion = Some(value.into());
        self
    }

    /// Sets the actor token.
    pub fn actor_token(mut self, value: impl Into<String>) -> Self {
        self.request.actor_token = Some(value.into());
        self
    }

    /// Sets the actor token type.
    pub fn actor_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.actor_token_type = Some(value.into());
        self
    }

    /// Sets the actor parameter.
    pub fn actor(mut self, value: impl Into<String>) -> Self {
        self.request.actor = Some(value.into());
        self
    }

    /// Sets the OpenID issuer flag.
    pub fn openid_issuer(mut self, value: bool) -> Self {
        self.request.openid_issuer = Some(value);
        self
    }

    /// Finalizes and returns the access token request.
    pub fn build(self) -> AccessTokenRequest {
        self.request
    }
}
