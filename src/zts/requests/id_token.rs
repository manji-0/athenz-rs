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
pub struct IdTokenResponse {
    pub response: Option<OidcResponse>,
    pub location: Option<String>,
}
