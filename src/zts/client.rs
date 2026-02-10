use crate::error::{
    read_body_with_limit, Error, CONFIG_ERROR_REDIRECT_WITH_AUTH, MAX_ERROR_BODY_BYTES,
};
use crate::ntoken::NTokenSigner;
use reqwest::blocking::{Client as HttpClient, RequestBuilder, Response};
use reqwest::{Certificate, Identity, StatusCode};
use std::time::Duration;
use url::Url;

use super::common;

mod certs;
mod instance;
mod meta;
mod oauth;
mod policy;
mod workloads;

pub struct ZtsClientBuilder {
    base_url: Url,
    timeout: Option<Duration>,
    disable_redirect: bool,
    identity: Option<Identity>,
    ca_certs: Vec<Certificate>,
    auth: Option<common::AuthProvider>,
}

impl ZtsClientBuilder {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            base_url: Url::parse(base_url.as_ref())?,
            timeout: None,
            disable_redirect: false,
            identity: None,
            ca_certs: Vec::new(),
            auth: None,
        })
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn disable_redirect(mut self, disable: bool) -> Self {
        self.disable_redirect = disable;
        self
    }

    pub fn mtls_identity_from_pem(mut self, identity_pem: &[u8]) -> Result<Self, Error> {
        self.identity = Some(Identity::from_pem(identity_pem)?);
        Ok(self)
    }

    pub fn mtls_identity_from_parts(
        mut self,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, Error> {
        let mut combined = Vec::new();
        combined.extend_from_slice(cert_pem);
        if !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(key_pem);
        self.identity = Some(Identity::from_pem(&combined)?);
        Ok(self)
    }

    pub fn add_ca_cert_pem(mut self, ca_pem: &[u8]) -> Result<Self, Error> {
        self.ca_certs.push(Certificate::from_pem(ca_pem)?);
        Ok(self)
    }

    pub fn ntoken_auth(mut self, header: impl Into<String>, token: impl Into<String>) -> Self {
        self.auth = Some(common::AuthProvider::StaticHeader {
            header: header.into(),
            value: token.into(),
        });
        self
    }

    pub fn ntoken_signer(mut self, header: impl Into<String>, signer: NTokenSigner) -> Self {
        self.auth = Some(common::AuthProvider::NToken {
            header: header.into(),
            signer,
        });
        self
    }

    pub fn build(self) -> Result<ZtsClient, Error> {
        if self.auth.is_some() && !self.disable_redirect {
            return Err(Error::Crypto(CONFIG_ERROR_REDIRECT_WITH_AUTH.to_string()));
        }
        let mut builder = HttpClient::builder();
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if self.disable_redirect {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        if let Some(identity) = self.identity {
            builder = builder.identity(identity);
        }
        for cert in self.ca_certs {
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build()?;
        Ok(ZtsClient {
            base_url: self.base_url,
            http,
            auth: self.auth,
        })
    }
}

pub struct ZtsClient {
    base_url: Url,
    http: HttpClient,
    auth: Option<common::AuthProvider>,
}

#[derive(Debug, Clone)]
pub struct ConditionalResponse<T> {
    pub data: Option<T>,
    pub etag: Option<String>,
}

impl ZtsClient {
    pub fn builder(base_url: impl AsRef<str>) -> Result<ZtsClientBuilder, Error> {
        ZtsClientBuilder::new(base_url)
    }

    fn build_url(&self, segments: &[&str]) -> Result<Url, Error> {
        const CLEAR_QUERY: bool = false;
        const CLEAR_FRAGMENT: bool = false;
        const POP_IF_EMPTY: bool = true;

        common::build_url(
            &self.base_url,
            segments,
            CLEAR_QUERY,
            CLEAR_FRAGMENT,
            POP_IF_EMPTY,
        )
    }

    fn apply_auth(&self, req: RequestBuilder) -> Result<RequestBuilder, Error> {
        common::apply_auth(req, &self.auth, |req, header, value, _ctx| {
            Ok(req.header(header, value))
        })
    }

    fn expect_ok_json<T: serde::de::DeserializeOwned>(&self, resp: Response) -> Result<T, Error> {
        if resp.status() == StatusCode::OK {
            resp.json::<T>().map_err(Error::from)
        } else {
            self.parse_error(resp)
        }
    }

    fn expect_no_content(&self, resp: Response) -> Result<(), Error> {
        if resp.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            self.parse_error(resp)
        }
    }

    fn expect_conditional_json<T: serde::de::DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<ConditionalResponse<T>, Error> {
        let status = resp.status();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        match status {
            StatusCode::OK => {
                let data = resp.json::<T>()?;
                Ok(ConditionalResponse {
                    data: Some(data),
                    etag,
                })
            }
            StatusCode::NOT_MODIFIED => Ok(ConditionalResponse { data: None, etag }),
            _ => self.parse_error(resp),
        }
    }

    fn parse_error<T>(&self, mut resp: Response) -> Result<T, Error> {
        let status = resp.status();
        let body = read_body_with_limit(&mut resp, MAX_ERROR_BODY_BYTES)?;
        Err(common::parse_error_from_body(status, &body, None, false))
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{Error, CONFIG_ERROR_REDIRECT_WITH_AUTH};
    use crate::zts::{AccessTokenRequest, IdTokenRequest, ZtsClient};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use url::form_urlencoded;

    fn scope_from_form(form: &str) -> String {
        form_urlencoded::parse(form.as_bytes())
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default()
    }

    #[test]
    fn access_token_scope_domain_only() {
        let req = AccessTokenRequest::new("sports", Vec::new());
        let form = req.to_form();
        assert!(form.contains("scope=sports%3Adomain"));
    }

    #[test]
    fn access_token_scope_wildcard_role() {
        let req = AccessTokenRequest::new("sports", vec!["*".to_string()]);
        let form = req.to_form();
        let scope = scope_from_form(&form);
        assert_eq!(scope, "sports:role.*");
        assert!(form.contains("scope=sports%3Arole.*") || form.contains("scope=sports%3Arole.%2A"));
    }

    #[test]
    fn access_token_scope_roles() {
        let req =
            AccessTokenRequest::new("sports", vec!["reader".to_string(), "writer".to_string()]);
        let form = req.to_form();
        let scope = scope_from_form(&form);
        assert_eq!(scope, "sports:role.reader sports:role.writer");
    }

    #[test]
    fn access_token_form_includes_optional_fields() {
        let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
        req.proxy_for_principal = Some("user.test".to_string());
        req.authorization_details = Some("{\"type\":\"test\"}".to_string());
        req.openid_issuer = Some(true);
        let form = req.to_form();
        assert!(form.contains("proxy_for_principal=user.test"));
        assert!(form.contains("authorization_details=%7B%22type%22%3A%22test%22%7D"));
        assert!(form.contains("openid_issuer=true"));
    }

    #[test]
    fn build_url_trims_trailing_slash() {
        let client = ZtsClient::builder("https://example.com/zts/v1/")
            .expect("builder")
            .build()
            .expect("build");
        let url = client.build_url(&["domain"]).expect("url");
        assert_eq!(url.path(), "/zts/v1/domain");
    }

    #[test]
    fn access_token_scope_includes_id_token_service() {
        let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
        req.id_token_service = Some("api".to_string());
        let form = req.to_form();
        let scope = scope_from_form(&form);
        assert_eq!(scope, "sports:role.reader openid sports:service.api");
        assert!(form.contains("scope=sports%3Arole.reader+openid+sports%3Aservice.api"));
    }

    #[test]
    fn access_token_raw_scope_overrides_composed_scope() {
        let mut req = AccessTokenRequest::new("sports", vec!["reader".to_string()]);
        req.id_token_service = Some("api".to_string());
        req.raw_scope = Some("custom:scope".to_string());
        let form = req.to_form();
        let scope = scope_from_form(&form);
        assert_eq!(scope, "custom:scope");
        assert!(form.contains("scope=custom%3Ascope"));
    }

    #[test]
    fn access_token_builder_sets_raw_scope() {
        let req = AccessTokenRequest::builder("sports")
            .roles(vec!["reader".to_string()])
            .id_token_service("api")
            .raw_scope("custom:scope")
            .build();
        let form = req.to_form();
        let scope = scope_from_form(&form);
        assert_eq!(scope, "custom:scope");
    }

    #[test]
    fn id_token_query_defaults_output_to_json() {
        let req = IdTokenRequest::new(
            "sports.api",
            "https://example.com/callback",
            "openid",
            "nonce-123",
        );
        let query = req.to_query();
        assert!(query.contains("output=json"));
    }

    #[test]
    fn id_token_query_includes_optional_fields() {
        let mut req = IdTokenRequest::new(
            "sports.api",
            "https://example.com/callback",
            "openid",
            "nonce-123",
        );
        req.state = Some("state-1".to_string());
        req.key_type = Some("EC".to_string());
        req.full_arn = Some(true);
        req.expiry_time = Some(3600);
        req.output = Some("json".to_string());
        req.role_in_aud_claim = Some(true);
        req.all_scope_present = Some(true);

        let query = req.to_query();
        assert!(query.contains("response_type=id_token"));
        assert!(query.contains("client_id=sports.api"));
        assert!(query.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(query.contains("scope=openid"));
        assert!(query.contains("nonce=nonce-123"));
        assert!(query.contains("state=state-1"));
        assert!(query.contains("keyType=EC"));
        assert!(query.contains("fullArn=true"));
        assert!(query.contains("expiryTime=3600"));
        assert!(query.contains("output=json"));
        assert!(query.contains("roleInAudClaim=true"));
        assert!(query.contains("allScopePresent=true"));
    }

    #[test]
    fn issue_id_token_accepts_redirects() {
        let response = concat!(
            "HTTP/1.1 303 See Other\r\n",
            "Location: https://example.com/callback?token=abc\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        );
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .disable_redirect(true)
            .build()
            .expect("build");
        let req = IdTokenRequest::new(
            "sports.api",
            "https://example.com/callback",
            "openid",
            "nonce-123",
        );

        let result = client.issue_id_token(&req).expect("request");
        assert!(result.response.is_none());
        assert_eq!(
            result.location.as_deref(),
            Some("https://example.com/callback?token=abc")
        );

        let captured = rx.recv().expect("request");
        assert_eq!(captured.method, "GET");
        assert!(
            captured.path.starts_with("/zts/v1/oauth2/auth?"),
            "unexpected path: {}",
            captured.path
        );

        handle.join().expect("server");
    }

    #[test]
    fn auth_requires_redirects_disabled() {
        let err = match ZtsClient::builder("https://example.com/zts/v1")
            .expect("builder")
            .disable_redirect(false)
            .ntoken_auth("Athenz-Principal-Auth", "token")
            .build()
        {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
        match err {
            Error::Crypto(message) => {
                assert_eq!(message, CONFIG_ERROR_REDIRECT_WITH_AUTH);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn auth_allows_redirects_disabled() {
        ZtsClient::builder("https://example.com/zts/v1")
            .expect("builder")
            .disable_redirect(true)
            .ntoken_auth("Athenz-Principal-Auth", "token")
            .build()
            .expect("build");
    }

    #[test]
    fn issue_id_token_ok_includes_location_header() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: application/json\r\n",
            "Location: https://example.com/callback?token=abc\r\n",
            "Content-Length: 89\r\n",
            "\r\n",
            "{\"version\":1,\"id_token\":\"abc\",\"token_type\":\"Bearer\",\"success\":true,\"expiration_time\":123}"
        );
        let (base_url, _rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");
        let req = IdTokenRequest::new(
            "sports.api",
            "https://example.com/callback",
            "openid",
            "nonce-123",
        );

        let result = client.issue_id_token(&req).expect("request");
        assert!(result.response.is_some());
        assert_eq!(
            result.location.as_deref(),
            Some("https://example.com/callback?token=abc")
        );

        handle.join().expect("server");
    }

    #[test]
    fn issue_id_token_redirect_requires_location() {
        let response = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n";
        let (base_url, _rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .disable_redirect(true)
            .build()
            .expect("build");
        let req = IdTokenRequest::new(
            "sports.api",
            "https://example.com/callback",
            "openid",
            "nonce-123",
        );

        let err = client.issue_id_token(&req).expect_err("request");
        match err {
            Error::Api(resource) => {
                assert_eq!(resource.code, 302);
                assert!(resource.message.contains("missing location"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        handle.join().expect("server");
    }

    #[test]
    fn get_domain_signed_policy_data_sets_if_none_match() {
        let response = "HTTP/1.1 304 Not Modified\r\nETag: tag-1\r\nContent-Length: 0\r\n\r\n";
        let (base_url, rx, handle) = serve_once(response);
        let client = ZtsClient::builder(format!("{}/zts/v1", base_url))
            .expect("builder")
            .build()
            .expect("build");

        let result = client
            .get_domain_signed_policy_data("sports", Some("tag-1"))
            .expect("request");
        assert!(result.data.is_none());
        assert_eq!(result.etag.as_deref(), Some("tag-1"));

        let req = rx.recv().expect("request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/zts/v1/domain/sports/signed_policy_data");
        assert_eq!(
            req.headers.get("if-none-match").map(String::as_str),
            Some("tag-1")
        );

        handle.join().expect("server");
    }

    struct CapturedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
    }

    fn serve_once(
        response: &'static str,
    ) -> (
        String,
        mpsc::Receiver<CapturedRequest>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let req = read_request(&mut stream);
                let _ = tx.send(req);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{}", addr), rx, handle)
    }

    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .unwrap_or(buf.len());
        let header_str = String::from_utf8_lossy(&buf[..header_end]);
        let mut lines = header_str.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        CapturedRequest {
            method,
            path,
            headers,
        }
    }
}
