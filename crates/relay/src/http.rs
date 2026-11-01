//! The HTTP edge: parsing, timeouts, the body limit and the concurrency
//! limit. Each handler makes exactly one `spawn_blocking` call into the
//! synchronous core.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
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
        HeaderValue::from_static(r.content_type),
    );
    out.headers_mut().insert(
        HeaderName::from_static(TIME_HEADER),
        HeaderValue::from(r.time),
    );
    for (n, v) in r.headers {
        if let (Ok(n), Ok(v)) = (HeaderName::try_from(n), HeaderValue::try_from(v)) {
            out.headers_mut().append(n, v);
        }
    }
    out
}

/// The token bucket of each IP address on the routes of `PROTOCOL.md`
/// 12.6: 120 requests, filled at 2 requests each second.
pub struct RateLimit {
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

/// The size of each bucket.
pub const BURST: f64 = 120.0;
/// The requests that each bucket gains in one second.
pub const RATE: f64 = 2.0;
/// The most addresses that the limiter keeps. Above it, the limiter drops
/// each full bucket, so memory stays bounded.
const MAX_BUCKETS: usize = 100_000;

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimit {
    /// Take one token for `ip` at `now`. False if the bucket is empty.
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        // A poisoned lock fails open: the limit protects availability, and
        // each limited route has its own checks.
        let Ok(mut m) = self.buckets.lock() else {
            return true;
        };
        if m.len() >= MAX_BUCKETS {
            m.retain(|_, (t, last)| {
                *t + now.saturating_duration_since(*last).as_secs_f64() * RATE < BURST
            });
        }
        let (tokens, last) = m.entry(ip).or_insert((BURST, now));
        let filled =
            (*tokens + now.saturating_duration_since(*last).as_secs_f64() * RATE).min(BURST);
        *last = now;
        if filled >= 1.0 {
            *tokens = filled - 1.0;
            true
        } else {
            *tokens = filled;
            false
        }
    }
}

/// True for a route of `PROTOCOL.md` 12.6.
fn limited(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        (
            "POST",
            "/v1/setup/token"
                | "/u/signin/start"
                | "/u/signin/finish"
                | "/u/invite/start"
                | "/u/invite/finish"
        )
    ) || (matches!(method, "GET" | "POST") && path.starts_with("/v1/e/"))
}

async fn handler(relay: Relay, limit: Arc<RateLimit>, req: HttpRequest<Body>) -> HttpResponse {
    if limited(req.method().as_str(), req.uri().path()) {
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
        if !limit.allow(ip, Instant::now()) {
            return respond(Response::error(
                429,
                "rate_limited",
                "too many requests from this address",
                (relay.config().clock)(),
            ));
        }
    }
    // The core checks the exact limit of each route. The repair routes
    // accept the allowance of PROTOCOL.md 10.9 on top of max_request_bytes.
    let max = usize::try_from(
        relay
            .config()
            .limits
            .max_request_bytes
            .saturating_add(crate::core::REPAIR_ALLOWANCE),
    )
    .unwrap_or(usize::MAX);
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
    let rate = Arc::new(RateLimit::default());
    Router::new()
        .fallback(move |req: HttpRequest<Body>| handler(relay.clone(), rate.clone(), req))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT))
        .layer(middleware::from_fn(move |req, next| {
            time_limit(limit.clone(), req, next)
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_takes_120_then_refills_at_2_each_second() {
        // PROTOCOL.md 12.6: the exact burst and refill.
        let l = RateLimit::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..120 {
            assert!(l.allow(ip, t0));
        }
        assert!(!l.allow(ip, t0));
        assert!(!l.allow(ip, t0 + Duration::from_millis(400)));
        assert!(l.allow(ip, t0 + Duration::from_millis(500)));
        assert!(!l.allow(ip, t0 + Duration::from_millis(500)));
        // Another address has its own bucket.
        assert!(l.allow("192.0.2.2".parse().unwrap(), t0));
    }

    #[test]
    fn limited_routes() {
        for (m, p) in [
            ("GET", "/v1/e/e_00"),
            ("POST", "/v1/e/e_00"),
            ("POST", "/v1/setup/token"),
            ("POST", "/u/signin/start"),
            ("POST", "/u/signin/finish"),
            ("POST", "/u/invite/start"),
            ("POST", "/u/invite/finish"),
        ] {
            assert!(limited(m, p), "{m} {p}");
        }
        for (m, p) in [
            ("GET", "/v1/info"),
            ("POST", "/u/groups"),
            ("GET", "/u/"),
            ("PUT", "/v1/e/x"),
        ] {
            assert!(!limited(m, p), "{m} {p}");
        }
    }
}
