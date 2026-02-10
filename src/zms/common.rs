use crate::error::{fallback_message, Error, ResourceError};
use crate::ntoken::NTokenSigner;
use reqwest::blocking::RequestBuilder as BlockingRequestBuilder;
use reqwest::RequestBuilder as AsyncRequestBuilder;
use reqwest::StatusCode;
use url::Url;

#[allow(clippy::large_enum_variant)]
pub(crate) enum AuthProvider {
    StaticHeader {
        header: String,
        value: String,
    },
    NToken {
        header: String,
        signer: NTokenSigner,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AuthContext {
    Config,
    NToken,
}

pub(crate) fn apply_auth<B, F>(
    req: B,
    auth: &Option<AuthProvider>,
    mut set_header: F,
) -> Result<B, Error>
where
    F: FnMut(B, &str, &str, AuthContext) -> Result<B, Error>,
{
    let Some(auth) = auth else {
        return Ok(req);
    };
    match auth {
        AuthProvider::StaticHeader { header, value } => {
            set_header(req, header, value, AuthContext::Config)
        }
        AuthProvider::NToken { header, signer } => {
            let token = signer.token()?;
            set_header(req, header, &token, AuthContext::NToken)
        }
    }
}

pub(crate) trait RequestBuilderExt: Sized {
    fn with_header(self, name: &str, value: &str) -> Self;
    fn with_query(self, params: &[(&'static str, String)]) -> Self;
}

impl RequestBuilderExt for BlockingRequestBuilder {
    fn with_header(self, name: &str, value: &str) -> Self {
        self.header(name, value)
    }

    fn with_query(self, params: &[(&'static str, String)]) -> Self {
        self.query(params)
    }
}

impl RequestBuilderExt for AsyncRequestBuilder {
    fn with_header(self, name: &str, value: &str) -> Self {
        self.header(name, value)
    }

    fn with_query(self, params: &[(&'static str, String)]) -> Self {
        self.query(params)
    }
}

pub(crate) use crate::build_url::BuildUrlOptions;

pub(crate) fn build_url(
    base_url: &Url,
    segments: &[&str],
    options: BuildUrlOptions,
) -> Result<Url, Error> {
    let mut url = base_url.clone();
    if options.clear_query {
        url.set_query(None);
    }
    if options.clear_fragment {
        url.set_fragment(None);
    }
    {
        let mut path_segments = url
            .path_segments_mut()
            .map_err(|_| Error::InvalidBaseUrl(base_url.to_string()))?;
        if options.pop_if_empty {
            path_segments.pop_if_empty();
        }
        for segment in segments {
            path_segments.push(segment);
        }
    }
    Ok(url)
}

pub(crate) fn apply_audit_headers<B: RequestBuilderExt>(
    mut req: B,
    audit_ref: Option<&str>,
    resource_owner: Option<&str>,
) -> B {
    if let Some(audit_ref) = audit_ref {
        req = req.with_header("Y-Audit-Ref", audit_ref);
    }
    if let Some(resource_owner) = resource_owner {
        req = req.with_header("Athenz-Resource-Owner", resource_owner);
    }
    req
}

pub(crate) fn apply_query_params<B: RequestBuilderExt>(
    req: B,
    params: Vec<(&'static str, String)>,
) -> B {
    if params.is_empty() {
        req
    } else {
        req.with_query(&params)
    }
}

pub(crate) fn parse_error_from_body(
    status: StatusCode,
    body: &[u8],
    fallback_to_status: bool,
) -> Error {
    let fallback = if fallback_to_status {
        fallback_message(status, body)
    } else {
        String::from_utf8_lossy(body).to_string()
    };
    let mut err = serde_json::from_slice::<ResourceError>(body).unwrap_or_else(|_| ResourceError {
        code: status.as_u16() as i32,
        message: fallback.clone(),
        description: None,
        error: None,
        request_id: None,
    });
    if err.code == 0 {
        err.code = status.as_u16() as i32;
    }
    if err.message.is_empty() {
        err.message = fallback;
    }
    Error::Api(err)
}
