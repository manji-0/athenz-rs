use super::ZtsAsyncClient;
use crate::error::{Error, ResourceError};
use crate::models::{
    AccessTokenResponse, IntrospectResponse, JwkList, OAuthConfig, OidcResponse, OpenIdConfig,
    PublicKeyEntry, RoleCertificateRequest, RoleToken,
};
use crate::zts::common;
use crate::zts::{AccessTokenRequest, IdTokenRequest, IdTokenResponse};
use reqwest::StatusCode;
impl ZtsAsyncClient {
    /// Retrieves a role token for roles in the given domain.
    pub async fn get_role_token(
        &self,
        domain: &str,
        role: Option<&str>,
        min_expiry_time: Option<i32>,
        max_expiry_time: Option<i32>,
        proxy_for_principal: Option<&str>,
    ) -> Result<RoleToken, Error> {
        let url = self.build_url(&["domain", domain, "token"])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(role) = role {
            params.push(("role", role.to_string()));
        }
        if let Some(min_expiry_time) = min_expiry_time {
            params.push(("minExpiryTime", min_expiry_time.to_string()));
        }
        if let Some(max_expiry_time) = max_expiry_time {
            params.push(("maxExpiryTime", max_expiry_time.to_string()));
        }
        if let Some(proxy_for_principal) = proxy_for_principal {
            params.push(("proxyForPrincipal", proxy_for_principal.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Requests a role token for a specific role using the deprecated endpoint.
    pub async fn post_role_token(
        &self,
        domain: &str,
        role: &str,
        request: &RoleCertificateRequest,
    ) -> Result<RoleToken, Error> {
        let url = self.build_url(&["domain", domain, "role", role, "token"])?;
        let mut req = self.http.post(url).json(request);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Issues an OAuth access token.
    pub async fn issue_access_token(
        &self,
        request: &AccessTokenRequest,
    ) -> Result<AccessTokenResponse, Error> {
        let url = self.build_url(&["oauth2", "token"])?;
        let body = request.to_form();
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Issues an ID token via the OIDC authorization endpoint.
    pub async fn issue_id_token(&self, request: &IdTokenRequest) -> Result<IdTokenResponse, Error> {
        if !self.disable_redirect {
            return Err(Error::Crypto(
                "config error: issue_id_token requires follow_redirects(false) to observe Location header"
                    .to_string(),
            ));
        }
        let mut url = self.build_url(&["oauth2", "auth"])?;
        let query = request.to_query();
        url.set_query(Some(&query));
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        let status = resp.status();
        match status {
            StatusCode::OK => {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string());
                let response = resp.json::<OidcResponse>().await?;
                Ok(IdTokenResponse {
                    response: Some(response),
                    location,
                })
            }
            _ if status.is_redirection() => {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string())
                    .ok_or_else(|| {
                        Error::Api(ResourceError {
                            code: status.as_u16() as i32,
                            message: "missing location header for redirect".to_string(),
                            description: None,
                            error: None,
                            request_id: None,
                        })
                    })?;
                Ok(IdTokenResponse {
                    response: None,
                    location: Some(location),
                })
            }
            _ => self.parse_error(resp).await,
        }
    }

    /// Introspects an access token.
    pub async fn introspect_access_token(&self, token: &str) -> Result<IntrospectResponse, Error> {
        let url = self.build_url(&["oauth2", "introspect"])?;
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("token", token);
        let body = params.finish();
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves the OAuth server configuration.
    pub async fn get_oauth_config(&self) -> Result<OAuthConfig, Error> {
        let url = self.build_url(&[".well-known", "oauth-authorization-server"])?;
        // Well-known discovery endpoints are typically public; omit auth to match sync client.
        let resp = self.http.get(url).send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves the OpenID Connect configuration.
    pub async fn get_openid_config(&self) -> Result<OpenIdConfig, Error> {
        let url = self.build_url(&[".well-known", "openid-configuration"])?;
        // Well-known discovery endpoints are typically public; omit auth to match sync client.
        let resp = self.http.get(url).send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves a public key entry for a service.
    pub async fn get_public_key_entry(
        &self,
        domain: &str,
        service: &str,
        key_id: &str,
    ) -> Result<PublicKeyEntry, Error> {
        let url = self.build_url(&["domain", domain, "service", service, "publickey", key_id])?;
        let mut req = self.http.get(url);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }

    /// Retrieves the JWK list, optionally filtered by service or RFC format.
    pub async fn get_jwk_list(
        &self,
        rfc: Option<bool>,
        service: Option<&str>,
    ) -> Result<JwkList, Error> {
        let url = self.build_url(&["oauth2", "keys"])?;
        let mut req = self.http.get(url);
        let mut params = Vec::new();
        if let Some(rfc) = rfc {
            params.push(("rfc", rfc.to_string()));
        }
        if let Some(service) = service {
            params.push(("service", service.to_string()));
        }
        req = common::apply_query_params(req, params);
        req = self.apply_auth(req)?;
        let resp = req.send().await?;
        self.expect_ok_json(resp).await
    }
}
