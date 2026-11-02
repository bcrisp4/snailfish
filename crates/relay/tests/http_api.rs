//! The axum router: routes, headers and limits.

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use common::Fx;
use snailfish_protocol::request::{TIME_HEADER, parse_time};
use snailfish_protocol::wire;
use snailfish_relay::http::router;
use tower::ServiceExt as _;

async fn call(fx: &Fx, req: Request<Body>) -> (StatusCode, Option<u64>, Vec<u8>) {
    let resp = router(fx.relay.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let time = resp
        .headers()
        .get(TIME_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_time);
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, time, body)
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn health_and_info_are_unsigned_and_carry_the_time() {
    let fx = Fx::new();
    let now = fx.h["now"].as_u64().unwrap();
    let (st, time, body) = call(&fx, get("/v1/health")).await;
    assert_eq!((st, time), (StatusCode::OK, Some(now)));
    assert_eq!(body, br#"{"status":"ok"}"#);
    let (st, time, body) = call(&fx, get("/v1/info")).await;
    assert_eq!((st, time), (StatusCode::OK, Some(now)));
    let info = wire::parse_info(&body).unwrap();
    assert_eq!(info.levels, [1]);
    assert_eq!(info.limits, common::limits_of(&fx.h));
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["time"], now);
}

#[tokio::test]
async fn unknown_route_is_404_json_with_time() {
    let fx = Fx::new();
    for path in ["/", "/v2/health", "/v1/t/x", "/v1/health/extra"] {
        let (st, time, body) = call(&fx, get(path)).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
        assert!(time.is_some());
        assert_eq!(wire::parse_error(&body).as_deref(), Some("not_found"));
    }
    let post = Request::builder()
        .method("POST")
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&fx, post).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn error_response_carries_time_and_status() {
    let fx = Fx::new();
    let handle = fx.tenant();
    let path = format!("/v1/t/{handle}/s/{}/entries?after=0&limit=1", fx.log());
    let (st, time, body) = call(&fx, get(&path)).await;
    // No signature headers: the space does not exist, so 404 comes first.
    assert_eq!((st, time.is_some()), (StatusCode::NOT_FOUND, true));
    assert_eq!(wire::parse_error(&body).as_deref(), Some("unknown_space"));
}

#[tokio::test]
async fn body_over_the_limit_is_413_too_large() {
    let fx = Fx::new();
    let limit = usize::try_from(common::limits_of(&fx.h).max_request_bytes).unwrap();
    let path = format!("/v1/t/{}/s/{}/append", fx.tenant(), fx.log());
    for size in [limit + 1, limit * 4] {
        let req = Request::builder()
            .method("POST")
            .uri(&path)
            .body(Body::from(vec![b'x'; size]))
            .unwrap();
        let (st, time, body) = call(&fx, req).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(time.is_some());
        assert_eq!(wire::parse_error(&body).as_deref(), Some("too_large"));
    }
}

/// PROTOCOL.md 10.9: the edge lets a repair body use the allowance above
/// `max_request_bytes`, so a lost change of the largest size can be
/// repaired. The core still refuses a body over the allowance.
#[tokio::test]
async fn repair_body_can_use_the_allowance() {
    let fx = Fx::new();
    let limit = usize::try_from(common::limits_of(&fx.h).max_request_bytes).unwrap();
    let path = format!("/v1/t/{}/s/{}/repair", fx.tenant(), fx.log());
    for (size, too_large) in [(limit + 1024, false), (limit + 1025, true)] {
        let req = Request::builder()
            .method("POST")
            .uri(&path)
            .body(Body::from(vec![b'x'; size]))
            .unwrap();
        let (st, _, _) = call(&fx, req).await;
        assert_eq!(st == StatusCode::PAYLOAD_TOO_LARGE, too_large, "{size}");
    }
}

/// A request body that fails, or never ends, before the limit.
struct BadBody(bool);

impl axum::body::HttpBody for BadBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if self.0 {
            std::task::Poll::Ready(Some(Err(std::io::Error::other("reset"))))
        } else {
            std::task::Poll::Pending
        }
    }
}

fn post_body(fx: &Fx, body: BadBody) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/t/{}/s/{}/append", fx.tenant(), fx.log()))
        .body(Body::new(body))
        .unwrap()
}

/// A body read error that is not the size limit is `bad_request`. Without
/// this, a dropped connection reports a size fault.
#[tokio::test]
async fn body_read_error_is_400_bad_request() {
    let fx = Fx::new();
    let (st, time, body) = call(&fx, post_body(&fx, BadBody(true))).await;
    assert_eq!((st, time.is_some()), (StatusCode::BAD_REQUEST, true));
    assert_eq!(wire::parse_error(&body).as_deref(), Some("bad_request"));
}

/// `PROTOCOL.md` 8.5 and 10.3: a request past the time limit gets a JSON
/// `timeout` error with `snailfish-time`, not a bare status.
#[tokio::test(start_paused = true)]
async fn slow_request_is_408_timeout_with_time() {
    let fx = Fx::new();
    let (st, time, body) = call(&fx, post_body(&fx, BadBody(false))).await;
    assert_eq!((st, time.is_some()), (StatusCode::REQUEST_TIMEOUT, true));
    assert_eq!(wire::parse_error(&body).as_deref(), Some("timeout"));
}

/// A signed fetch through the router: the path, query and headers reach the
/// core as the client sent them.
#[tokio::test]
async fn signed_fetch_works_through_the_router() {
    let fx = Fx::new();
    let handle = fx.tenant().to_owned();
    let relay = fx.relay.clone();
    let fx = std::sync::Arc::new(fx);
    let f2 = std::sync::Arc::clone(&fx);
    tokio::task::spawn_blocking(move || f2.setup_space(&handle))
        .await
        .unwrap();
    drop(relay);
    let path = format!("/v1/t/{}/s/{}/entries", fx.tenant(), fx.log());
    let signed = fx.signed("GET", &path, "after=2&limit=500", b"", "A");
    let mut b = Request::builder().uri(format!("{path}?after=2&limit=500"));
    for (n, v) in &signed.headers {
        b = b.header(n, v);
    }
    let (st, time, body) = call(&fx, b.body(Body::empty()).unwrap()).await;
    assert_eq!((st, time.is_some()), (StatusCode::OK, true));
    let page = wire::parse_fetch(&body).unwrap();
    assert_eq!(page.entries.iter().map(|e| e.0).collect::<Vec<_>>(), [3, 4]);
}

/// PROTOCOL.md 12.6: the router lets at least 120 sign-in starts of one
/// address through to the core, then answers with `rate_limited`.
#[tokio::test]
async fn sign_in_routes_are_rate_limited() {
    let fx = Fx::new();
    let app = router(fx.relay.clone());
    let req = || {
        Request::post("/u/signin/start")
            .header("origin", "https://sync.example.net")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"nobody"}"#))
            .unwrap()
    };
    // The bucket refills at 2 requests each second while the loop runs, so
    // the first 429 comes at request 121 or a little later.
    let mut passed = 0;
    loop {
        let resp = app.clone().oneshot(req()).await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        passed += 1;
        assert!(passed < 1000, "no rate limit");
    }
    assert!(passed >= 120, "{passed}");
    // A route outside 12.6 has no limit.
    let resp = app.oneshot(get("/v1/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
