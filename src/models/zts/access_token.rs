use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccessTokenResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::AccessTokenResponse;

    #[test]
    fn access_token_response_allows_missing_access_token() {
        let input = serde_json::json!({
            "token_type": "Bearer",
            "id_token": "id-token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:id_token"
        });
        let parsed: AccessTokenResponse =
            serde_json::from_value(input).expect("deserialize access token response");
        assert_eq!(parsed.access_token, None);
        assert_eq!(parsed.id_token.as_deref(), Some("id-token"));
    }
}
