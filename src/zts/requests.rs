use crate::models::OidcResponse;

/// Request parameters for AccessToken issuance.
/// Use `new()`/`builder()` for forward-compatible construction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AccessTokenRequest {
    pub domain: String,
    pub roles: Vec<String>,
    pub id_token_service: Option<String>,
    /// If set, this value is used as-is and overrides role/id_token_service scope composition.
    pub raw_scope: Option<String>,
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
    pub fn new(domain: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            domain: domain.into(),
            roles,
            id_token_service: None,
            raw_scope: None,
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

    pub fn builder(domain: impl Into<String>) -> AccessTokenRequestBuilder {
        AccessTokenRequestBuilder::new(domain)
    }

    pub fn to_form(&self) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("grant_type", "client_credentials");
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
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            request: AccessTokenRequest::new(domain, Vec::new()),
        }
    }

    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.request.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    pub fn id_token_service(mut self, service: impl Into<String>) -> Self {
        self.request.id_token_service = Some(service.into());
        self
    }

    /// Overrides composed scopes from roles/id_token_service.
    pub fn raw_scope(mut self, scope: impl Into<String>) -> Self {
        self.request.raw_scope = Some(scope.into());
        self
    }

    pub fn expires_in(mut self, value: i32) -> Self {
        self.request.expires_in = Some(value);
        self
    }

    pub fn proxy_principal_spiffe_uris(mut self, value: impl Into<String>) -> Self {
        self.request.proxy_principal_spiffe_uris = Some(value.into());
        self
    }

    pub fn proxy_for_principal(mut self, value: impl Into<String>) -> Self {
        self.request.proxy_for_principal = Some(value.into());
        self
    }

    pub fn authorization_details(mut self, value: impl Into<String>) -> Self {
        self.request.authorization_details = Some(value.into());
        self
    }

    pub fn client_assertion_type(mut self, value: impl Into<String>) -> Self {
        self.request.client_assertion_type = Some(value.into());
        self
    }

    pub fn client_assertion(mut self, value: impl Into<String>) -> Self {
        self.request.client_assertion = Some(value.into());
        self
    }

    pub fn requested_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.requested_token_type = Some(value.into());
        self
    }

    pub fn audience(mut self, value: impl Into<String>) -> Self {
        self.request.audience = Some(value.into());
        self
    }

    pub fn resource(mut self, value: impl Into<String>) -> Self {
        self.request.resource = Some(value.into());
        self
    }

    pub fn subject_token(mut self, value: impl Into<String>) -> Self {
        self.request.subject_token = Some(value.into());
        self
    }

    pub fn subject_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.subject_token_type = Some(value.into());
        self
    }

    pub fn assertion(mut self, value: impl Into<String>) -> Self {
        self.request.assertion = Some(value.into());
        self
    }

    pub fn actor_token(mut self, value: impl Into<String>) -> Self {
        self.request.actor_token = Some(value.into());
        self
    }

    pub fn actor_token_type(mut self, value: impl Into<String>) -> Self {
        self.request.actor_token_type = Some(value.into());
        self
    }

    pub fn actor(mut self, value: impl Into<String>) -> Self {
        self.request.actor = Some(value.into());
        self
    }

    pub fn openid_issuer(mut self, value: bool) -> Self {
        self.request.openid_issuer = Some(value);
        self
    }

    pub fn build(self) -> AccessTokenRequest {
        self.request
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: String,
    pub state: Option<String>,
    pub key_type: Option<String>,
    pub full_arn: Option<bool>,
    pub expiry_time: Option<i32>,
    pub output: Option<String>,
    pub role_in_aud_claim: Option<bool>,
    pub all_scope_present: Option<bool>,
}

impl IdTokenRequest {
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            nonce: nonce.into(),
            state: None,
            key_type: None,
            full_arn: None,
            expiry_time: None,
            output: Some("json".into()),
            role_in_aud_claim: None,
            all_scope_present: None,
        }
    }

    pub fn to_query(&self) -> String {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("response_type", "id_token");
        params.append_pair("client_id", &self.client_id);
        params.append_pair("redirect_uri", &self.redirect_uri);
        params.append_pair("scope", &self.scope);
        params.append_pair("nonce", &self.nonce);
        if let Some(ref state) = self.state {
            params.append_pair("state", state);
        }
        if let Some(ref key_type) = self.key_type {
            params.append_pair("keyType", key_type);
        }
        if let Some(full_arn) = self.full_arn {
            params.append_pair("fullArn", &full_arn.to_string());
        }
        if let Some(expiry_time) = self.expiry_time {
            params.append_pair("expiryTime", &expiry_time.to_string());
        }
        if let Some(ref output) = self.output {
            params.append_pair("output", output);
        }
        if let Some(role_in_aud) = self.role_in_aud_claim {
            params.append_pair("roleInAudClaim", &role_in_aud.to_string());
        }
        if let Some(all_scope) = self.all_scope_present {
            params.append_pair("allScopePresent", &all_scope.to_string());
        }
        params.finish()
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenResponse {
    pub response: Option<OidcResponse>,
    pub location: Option<String>,
}
