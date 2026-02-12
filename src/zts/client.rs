use crate::client_defaults::DEFAULT_TIMEOUT;
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
            timeout: Some(DEFAULT_TIMEOUT),
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
        common::build_url(
            &self.base_url,
            segments,
            common::BuildUrlOptions::SYNC_CLIENT,
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
mod tests;
