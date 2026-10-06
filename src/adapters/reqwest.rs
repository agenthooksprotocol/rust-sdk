use crate::transport::{Http, Request, Response, TransportError};
use std::{future::Future, pin::Pin};
/// Redirects disabled, normal certificate verification enabled.
pub struct ReqwestHttp {
    client: reqwest::Client,
    max_response_bytes: usize,
    allow_loopback_http: bool,
}
impl ReqwestHttp {
    pub fn new() -> Result<Self, TransportError> {
        Self::with_options(1024 * 1024, false)
    }
    /// Explicit local-development HTTP opt-in and maximum buffered response size.
    /// All requests have a 30-second total timeout and never follow redirects.
    pub fn with_options(
        max_response_bytes: usize,
        allow_loopback_http: bool,
    ) -> Result<Self, TransportError> {
        Self::with_timeout(
            max_response_bytes,
            allow_loopback_http,
            std::time::Duration::from_secs(30),
        )
    }
    /// Bound pending HTTP I/O explicitly. Set this no longer than the associated
    /// subscription or upload budget; the boundary checks acceptance separately.
    pub fn with_timeout(
        max_response_bytes: usize,
        allow_loopback_http: bool,
        timeout: std::time::Duration,
    ) -> Result<Self, TransportError> {
        if timeout.is_zero() {
            return Err(TransportError("HTTP timeout must be positive".into()));
        }
        reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(|client| Self {
                client,
                max_response_bytes,
                allow_loopback_http,
            })
            .map_err(|e| TransportError(e.to_string()))
    }
}
impl Http for ReqwestHttp {
    fn send(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> {
        Box::pin(async move {
            let url =
                reqwest::Url::parse(&request.uri).map_err(|e| TransportError(e.to_string()))?;
            if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
                return Err(TransportError(
                    "URL credentials and fragments are forbidden".into(),
                ));
            }
            let loopback = url.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if url.scheme() != "https"
                && !(url.scheme() == "http" && loopback && self.allow_loopback_http)
            {
                return Err(TransportError("HTTPS required outside loopback".into()));
            }
            let method = request
                .method
                .parse::<reqwest::Method>()
                .map_err(|e| TransportError(e.to_string()))?;
            let mut builder = self.client.request(method, url).body(request.body);
            for (name, value) in request.headers {
                builder = builder.header(name, value);
            }
            let mut response = builder
                .send()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.to_string(),
                        v.to_str()
                            .map_err(|e| TransportError(e.to_string()))?
                            .to_owned(),
                    ))
                })
                .collect::<Result<_, TransportError>>()?;
            if response
                .content_length()
                .is_some_and(|n| n > self.max_response_bytes as u64)
            {
                return Err(TransportError("response body too large".into()));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| TransportError(e.to_string()))?
            {
                if chunk.len() > self.max_response_bytes.saturating_sub(body.len()) {
                    return Err(TransportError("response body too large".into()));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Response {
                status,
                headers,
                body,
            })
        })
    }
}
