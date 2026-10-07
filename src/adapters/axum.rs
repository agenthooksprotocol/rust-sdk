use crate::{
    server::{Authenticator, Handler, Server},
    transport,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
};
/// Bind in an Axum route; body collection is bounded before dispatch.
pub async fn handle<H: Handler, A: Authenticator>(
    server: &Server<H, A>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let mut headers = std::collections::BTreeMap::new();
    for (name, value) in &parts.headers {
        let Ok(value) = value.to_str() else {
            return empty(StatusCode::BAD_REQUEST);
        };
        if headers.insert(name.to_string(), value.to_owned()).is_some() {
            return empty(StatusCode::BAD_REQUEST);
        }
    }
    let body = match to_bytes(body, server.max_body_bytes).await {
        Ok(v) => v.to_vec(),
        Err(_) => return empty(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let result = server
        .handle(transport::Request {
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            headers,
            body,
        })
        .await;
    let mut response = Response::builder().status(result.status);
    for (key, value) in result.headers {
        response = response.header(key, value);
    }
    response
        .body(Body::from(result.body))
        .expect("server emits valid headers")
}
fn empty(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("valid status")
}
