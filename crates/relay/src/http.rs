//! The HTTP edge: parsing, timeouts, the body limit and the concurrency
//! limit. Each handler makes exactly one `spawn_blocking` call into the
//! synchronous core.

use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderName, HeaderValue, Request as HttpRequest, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response as HttpResponse;
use http_body_util::LengthLimitError;
use snailfish_protocol::request::TIME_HEADER;
use tower::limit::ConcurrencyLimitLayer;

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
    let body = match to_bytes(body, max).await {
        Ok(b) => b,
        Err(e) => {
            let now = (relay.config().clock)();
            let too_large =
                std::iter::successors(Some(&e as &dyn std::error::Error), |e| e.source())
                    .any(<dyn std::error::Error>::is::<LengthLimitError>);
            return respond(if too_large {
                Response::error(413, "too_large", "the body is too large", now)
            } else {
                Response::error(400, "bad_request", "the body could not be read", now)
            });
        }
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

/// The time limit covers the wait for a concurrency slot and the body read.
/// A core call that runs past it still finishes, and its transaction can
/// commit. The engine then sees the result at its next fetch ([DLV-8]).
async fn time_limit(relay: Relay, req: HttpRequest<Body>, next: Next) -> HttpResponse {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(r) => r,
        Err(_) => respond(Response::error(
            408,
            "timeout",
            "the request took too long",
            (relay.config().clock)(),
        )),
    }
}

/// The router of the relay.
pub fn router(relay: Relay) -> Router {
    let limit = relay.clone();
    Router::new()
        .fallback(move |req: HttpRequest<Body>| handler(relay.clone(), req))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT))
        .layer(middleware::from_fn(move |req, next| {
            time_limit(limit.clone(), req, next)
        }))
}
