use crate::models::OidcResponse;

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
    /// Creates an ID token request with required parameters.
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

    /// Returns a builder for ID token requests.
    pub fn builder(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        nonce: impl Into<String>,
    ) -> IdTokenRequestBuilder {
        IdTokenRequestBuilder::new(client_id, redirect_uri, scope, nonce)
    }

    /// Serializes the request into a URL query string.
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
/// Builder for constructing [`IdTokenRequest`] values.
pub struct IdTokenRequestBuilder {
    request: IdTokenRequest,
}

impl IdTokenRequestBuilder {
    /// Creates a builder with required ID token request fields.
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            request: IdTokenRequest::new(client_id, redirect_uri, scope, nonce),
        }
    }

    /// Sets the optional OAuth state.
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.request.state = Some(state.into());
        self
    }

    /// Sets the key type for token signing.
    pub fn key_type(mut self, key_type: impl Into<String>) -> Self {
        self.request.key_type = Some(key_type.into());
        self
    }

    /// Sets whether full ARN should be included.
    pub fn full_arn(mut self, full_arn: bool) -> Self {
        self.request.full_arn = Some(full_arn);
        self
    }

    /// Sets token expiry time in seconds.
    pub fn expiry_time(mut self, expiry_time: i32) -> Self {
        self.request.expiry_time = Some(expiry_time);
        self
    }

    /// Sets output mode.
    pub fn output(mut self, output: impl Into<String>) -> Self {
        self.request.output = Some(output.into());
        self
    }

    /// Sets whether role should be included in audience claim.
    pub fn role_in_aud_claim(mut self, role_in_aud_claim: bool) -> Self {
        self.request.role_in_aud_claim = Some(role_in_aud_claim);
        self
    }

    /// Sets all-scope-present behavior.
    pub fn all_scope_present(mut self, all_scope_present: bool) -> Self {
        self.request.all_scope_present = Some(all_scope_present);
        self
    }

    /// Finalizes and returns the ID token request.
    pub fn build(self) -> IdTokenRequest {
        self.request
    }
}

#[derive(Debug, Clone)]
pub struct IdTokenResponse {
    pub response: Option<OidcResponse>,
    pub location: Option<String>,
}
