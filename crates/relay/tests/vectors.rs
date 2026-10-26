//! `vectors/http.json` through the core (`PROTOCOL.md` sections 8 and 10).
//!
//! Each case starts from a fresh relay that holds the space of `space.log`
//! and the `used_nonces` of the file. The Go generator wrote the expected
//! results from `PROTOCOL.md` alone.

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{Fx, error_code, s};
use serde_json::Value;
use snailfish_protocol::wire::{self, AppendResult};
use snailfish_relay::core::Request;

fn fresh(h: &Value, authority: &str, with_space: bool) -> Fx {
    let fx = Fx::with(authority, common::limits_of(h));
    assert_eq!(fx.h["tenant"], h["tenant"]);
    if with_space {
        fx.setup_space(fx.tenant());
        for p in h["used_nonces"].as_array().unwrap() {
            fx.seed_nonce(
                fx.tenant(),
                s(&p[0]),
                s(&p[1]),
                fx.now.load(std::sync::atomic::Ordering::SeqCst) + 300,
            );
        }
    }
    fx
}

fn request(c: &Value, method: &str) -> Request {
    Request {
        method: method.to_owned(),
        path: s(&c["path"]).to_owned(),
        query: s(&c["query"]).to_owned(),
        headers: c["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (s(&p[0]).to_owned(), s(&p[1]).to_owned()))
            .collect(),
        body: s(&c["body"]).as_bytes().to_vec(),
    }
}

#[test]
fn signed_requests_are_accepted_with_the_vector_headers() {
    let h = common::load("http.json");
    let mut seen = 0;
    for c in h["signed"].as_array().unwrap() {
        let name = s(&c["name"]);
        let create = c["method"] == "PUT";
        let fx = fresh(&h, s(&c["authority"]), !create);
        let r = fx.relay.handle(&request(c, s(&c["method"])));
        // The vector `fetch-query-several-params` carries a query that 10.7
        // refuses after the signature verifies: it tests the signed query.
        let (status, code) = match name {
            "put-create" => (201, ""),
            "fetch-query-several-params" => (400, "bad_request"),
            _ => (200, ""),
        };
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (status, code),
            "{name}"
        );
        seen += 1;
    }
    assert_eq!(seen, h["signed"].as_array().unwrap().len());
}

#[test]
fn invalid_requests_return_the_vector_error() {
    let h = common::load("http.json");
    for c in h["invalid"].as_array().unwrap() {
        let fx = fresh(&h, s(&h["authority"]), true);
        let before = fx.nonce_count(fx.tenant());
        let r = fx.relay.handle(&request(c, s(&c["method"])));
        assert_eq!(
            error_code(&r),
            s(&c["error"]),
            "{}: {}",
            s(&c["name"]),
            String::from_utf8_lossy(&r.body)
        );
        // A refused request stores no nonce, except the replay it names.
        assert_eq!(fx.nonce_count(fx.tenant()), before, "{}", s(&c["name"]));
    }
}

#[test]
fn append_cases_return_the_vector_results() {
    let h = common::load("http.json");
    for c in h["append"].as_array().unwrap() {
        let name = s(&c["name"]);
        let fx = fresh(&h, s(&h["authority"]), true);
        let path = format!("{}/append", fx.space_path(fx.tenant(), fx.log()));
        let req = fx.signed("POST", &path, "", s(&c["body"]).as_bytes(), s(&c["signer"]));
        let r = fx.relay.handle(&req);
        assert_eq!(
            r.status,
            200,
            "{name}: {}",
            String::from_utf8_lossy(&r.body)
        );
        let (got, head) = wire::parse_append_response(&r.body).unwrap();
        let want: Vec<AppendResult> = c["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                let pos = x["position"].as_u64();
                match s(&x["status"]) {
                    "stored" => AppendResult::Stored(pos.unwrap()),
                    "known" => AppendResult::Known(pos.unwrap()),
                    "conflict" => AppendResult::Conflict(pos.unwrap()),
                    _ => AppendResult::Refused(s(&x["error"]).to_owned()),
                }
            })
            .collect();
        assert_eq!(got, want, "{name}");
        assert_eq!(
            head.position,
            c["head"]["position"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(hex::encode(head.digest), s(&c["head"]["digest"]), "{name}");
        // The log holds exactly the stored entries and the head agrees.
        let page = wire::parse_fetch(&fx.fetch(fx.tenant(), 0, 500).body).unwrap();
        assert_eq!(page.head, head, "{name}");
        assert_eq!(page.entries.len() as u64, head.position, "{name}");
    }
}

#[test]
fn fetch_cases_return_the_vector_positions() {
    let h = common::load("http.json");
    let fx = fresh(&h, s(&h["authority"]), true);
    for c in h["fetch"].as_array().unwrap() {
        let name = s(&c["name"]);
        let r = fx.fetch(
            fx.tenant(),
            c["after"].as_u64().unwrap(),
            c["limit"].as_u64().unwrap(),
        );
        assert_eq!(r.status, 200, "{name}");
        let page = wire::parse_fetch(&r.body).unwrap();
        let positions: Vec<u64> = page.entries.iter().map(|e| e.0).collect();
        let want: Vec<u64> = c["positions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_u64().unwrap())
            .collect();
        assert_eq!(positions, want, "{name}");
        assert_eq!(page.head.position, c["head"].as_u64().unwrap(), "{name}");
        assert_eq!(page.has_more, c["has_more"].as_bool().unwrap(), "{name}");
        for (pos, e) in page.entries {
            let wire::FetchEntry::Envelope(e) = e else {
                panic!("stub")
            };
            let want = s(&fx.h["space"]["log"][usize::try_from(pos).unwrap() - 1]["envelope"]);
            assert_eq!(e.json, want, "{name}: stored text is served as received");
        }
    }
}
