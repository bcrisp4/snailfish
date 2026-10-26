//! The HTTP edge: parsing, timeouts, the body limit and the concurrency
//! limit. Each handler makes exactly one `spawn_blocking` call into the
//! synchronous core.

use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderName, HeaderValue, Request as HttpRequest, StatusCode, header};
use axum::response::Response as HttpResponse;
use snailfish_protocol::request::TIME_HEADER;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::core::{Relay, Request, Response, system_time};

/// The most requests that the relay handles at once.
pub const MAX_CONCURRENT: usize = 64;
/// The time limit of one request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn respond(r: Response) -> HttpResponse {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut out = HttpResponse::new(Body::from(r.body));
    *out.status_mut() = status;
    out.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    out.headers_mut().insert(
        HeaderName::from_static(TIME_HEADER),
        HeaderValue::from(r.time),
    );
    out
}

async fn handler(relay: Relay, req: HttpRequest<Body>) -> HttpResponse {
    let max = usize::try_from(relay.config().limits.max_request_bytes).unwrap_or(usize::MAX);
    let (parts, body) = req.into_parts();
    let too_large = || {
        respond(Response::error(
            413,
            "too_large",
            "the body is too large",
            (relay.config().clock)(),
        ))
    };
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > max) {
        return too_large();
    }
    let Ok(body) = to_bytes(body, max).await else {
        return too_large();
    };
    let headers = parts
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let request = Request {
        method: parts.method.as_str().to_owned(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or("").to_owned(),
        headers,
        body: body.to_vec(),
    };
    let core = relay.clone();
    match tokio::task::spawn_blocking(move || core.handle(&request)).await {
        Ok(r) => respond(r),
        Err(_) => respond(Response::error(
            500,
            "internal",
            "the relay failed",
            system_time(),
        )),
    }
}

/// The router of the relay.
pub fn router(relay: Relay) -> Router {
    Router::new()
        .fallback(move |req: HttpRequest<Body>| handler(relay.clone(), req))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
}
