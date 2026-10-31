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

fn run_append_cases(section: &str, hold: bool) {
    let h = common::load("http.json");
    let cases = h[section].as_array().unwrap();
    assert!(!cases.is_empty(), "{section}");
    for c in cases {
        let name = s(&c["name"]);
        let fx = fresh(&h, s(&h["authority"]), true);
        fx.set_hold(fx.tenant(), hold);
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

/// 10.6, with the base rule for security records ([LOG-7],
/// `specs/spacelog/test.qnt::concurrentGrantsTest`).
#[test]
fn append_cases_return_the_vector_results() {
    run_append_cases("append", false);
}

/// 10.6 step 3 ([LOG-14]): during a hold the relay refuses changes with
/// `on_hold` and checks security records as usual.
#[test]
fn append_hold_cases_return_the_vector_results() {
    run_append_cases("append_hold", true);
}

#[test]
fn fetch_cases_return_the_vector_positions() {
    let h = common::load("http.json");
    let fx = fresh(&h, s(&h["authority"]), true);
    for c in h["fetch"].as_array().unwrap() {
        let name = s(&c["name"]);
        let hold = c["hold"].as_bool().unwrap();
        fx.set_hold(fx.tenant(), hold);
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
        // 10.7: the relay always sends `hold`.
        let raw: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(raw["hold"].as_bool(), Some(hold), "{name}");
        for (pos, e) in page.entries {
            let wire::FetchEntry::Envelope(e) = e else {
                panic!("stub")
            };
            let want = s(&fx.h["space"]["log"][usize::try_from(pos).unwrap() - 1]["envelope"]);
            assert_eq!(e.json, want, "{name}: stored text is served as received");
        }
    }
}

/// 10.8 ([LOG-14]): the status report answers the hold state, and during a
/// hold the relay stores the report and reads its tip against the log.
#[test]
fn status_cases_return_the_vector_results() {
    let h = common::load("http.json");
    let cases = h["status"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for c in cases {
        let name = s(&c["name"]);
        let fx = fresh(&h, s(&h["authority"]), true);
        fx.set_hold(fx.tenant(), c["hold"].as_bool().unwrap());
        let r = fx.post(
            fx.tenant(),
            "status",
            s(&c["body"]).as_bytes(),
            s(&c["signer"]),
        );
        if let Some(code) = c["error"].as_str() { assert_eq!(error_code(&r), code, "{name}") } else {
            assert_eq!(
                r.status,
                200,
                "{name}: {}",
                String::from_utf8_lossy(&r.body)
            );
            assert_eq!(
                wire::parse_status_response(&r.body),
                Ok(c["response"]["hold"].as_bool().unwrap()),
                "{name}"
            );
        }
        let report = snailfish_relay::ops::hold_report(fx.dir.path(), "sam", fx.log()).unwrap();
        let (_, _, id) = fx.key(s(&c["signer"]));
        let mine = report.devices.iter().find(|d| d.device == id);
        match c["tip_in_log"].as_bool() {
            None => assert!(mine.is_none(), "{name}: no report is stored"),
            Some(want) => assert_eq!(
                mine.map(|d| d.state == snailfish_relay::ops::TipState::Reported),
                Some(want),
                "{name}"
            ),
        }
    }
}

/// 10.9 ([LOG-10] to [LOG-12], [LOG-14]): each repair case on a cut log,
/// step by step, and the relay log after the last step.
#[test]
fn repair_cases_return_the_vector_results() {
    let h = common::load("http.json");
    let cases = h["repair"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for c in cases {
        let name = s(&c["name"]);
        let fx = fresh(&h, s(&h["authority"]), true);
        fx.cut_log(fx.tenant(), c["log_prefix"].as_u64().unwrap());
        fx.set_hold(fx.tenant(), c["hold"].as_bool().unwrap());
        let mut session = String::new();
        for (i, st) in c["steps"].as_array().unwrap().iter().enumerate() {
            fx.now.store(
                st["at"].as_u64().unwrap(),
                std::sync::atomic::Ordering::SeqCst,
            );
            let route = match s(&st["route"]) {
                "start" => "repair",
                "chunk" => "repair/chunk",
                _ => "repair/finish",
            };
            let body = s(&st["body"]).replace("{{session}}", &session);
            let r = fx.post(fx.tenant(), route, body.as_bytes(), s(&st["signer"]));
            let why = format!("{name} step {i}: {}", String::from_utf8_lossy(&r.body));
            assert_eq!(u64::from(r.status), st["status"].as_u64().unwrap(), "{why}");
            match st["error"].as_str() {
                Some(code) => assert_eq!(error_code(&r), code, "{why}"),
                None if r.status == 201 => {
                    let (id, next) = wire::parse_repair_started(&r.body).unwrap();
                    session = hex::encode(id);
                    assert_eq!(Some(next), st["next"].as_u64(), "{why}");
                }
                None if st["head"].is_null() => {
                    assert_eq!(
                        wire::parse_repair_next(&r.body).ok(),
                        st["next"].as_u64(),
                        "{why}"
                    );
                }
                None => {
                    let head = wire::parse_repair_finished(&r.body).unwrap();
                    assert_eq!(
                        Some(head.position),
                        st["head"]["position"].as_u64(),
                        "{why}"
                    );
                    assert_eq!(hex::encode(head.digest), s(&st["head"]["digest"]), "{why}");
                }
            }
        }
        let want: Vec<String> = c["log"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| s(x).to_owned())
            .collect();
        assert_eq!(fx.record_hashes(fx.tenant()), want, "{name}");
    }
}
