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
    fn with_query(self, params: &[(&'static str, String)]) -> Self;
}

impl RequestBuilderExt for BlockingRequestBuilder {
    fn with_query(self, params: &[(&'static str, String)]) -> Self {
        self.query(params)
    }
}

impl RequestBuilderExt for AsyncRequestBuilder {
    fn with_query(self, params: &[(&'static str, String)]) -> Self {
        self.query(params)
    }
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

pub(crate) fn parse_error_from_body(
    status: StatusCode,
    body: &[u8],
    fallback_override: Option<String>,
    trim_empty: bool,
) -> Error {
    let fallback = match fallback_override {
        Some(value) => value,
        None => fallback_message(status, body),
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
    let is_empty = if trim_empty {
        err.message.trim().is_empty()
    } else {
        err.message.is_empty()
    };
    if is_empty {
        err.message = fallback;
    }
    Error::Api(err)
}

#[cfg(test)]
mod tests {
    use super::{build_url, BuildUrlOptions};
    use url::Url;

    #[test]
    fn build_url_clears_query_and_fragment_when_requested() {
        let base_url = Url::parse("https://example.com/zts/v1?foo=bar#frag").unwrap();
        let url = build_url(
            &base_url,
            &["status"],
            BuildUrlOptions {
                clear_query: true,
                clear_fragment: true,
                pop_if_empty: false,
            },
        )
        .expect("url");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
        assert_eq!(url.path(), "/zts/v1/status");
    }

    #[test]
    fn build_url_preserves_query_and_fragment_when_disabled() {
        let base_url = Url::parse("https://example.com/zts/v1?foo=bar#frag").unwrap();
        let url = build_url(&base_url, &["status"], BuildUrlOptions::default()).expect("url");
        assert_eq!(url.query(), Some("foo=bar"));
        assert_eq!(url.fragment(), Some("frag"));
    }
}
