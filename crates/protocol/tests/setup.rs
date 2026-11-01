//! The user and setup surface of `setup` against the Go vectors in
//! `vectors/http.json` (`PROTOCOL.md` 2.2, 10.11, 12.2, 12.3 and 12.5,
//! [USR-1], [USR-4], [USR-5], [USR-8]). The Go generator is a second
//! implementation of the same text, so a misreading in one of them fails
//! here.
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::setup::{self, TokenKind};

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/http.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} is not a string"))
}

fn cases<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    let c = v[k].as_array().unwrap();
    assert!(!c.is_empty(), "{k}");
    c
}

#[test]
fn tokens_and_their_hashes() {
    let h = vectors();
    for c in cases(&h, "tokens") {
        let kind = match s(c, "kind") {
            "invite" => TokenKind::Invite,
            "code" => TokenKind::Code,
            _ => TokenKind::Setup,
        };
        let got = setup::parse_token(kind, s(c, "text"));
        assert_eq!(
            got.is_ok(),
            c["valid"].as_bool().unwrap(),
            "{}",
            s(c, "name")
        );
        if let Ok(t) = got {
            assert_eq!(
                hex::encode(setup::token_hash(&t)),
                s(c, "hash"),
                "{}",
                s(c, "name")
            );
            assert_eq!(setup::token_text(kind, &t), s(c, "text"));
        }
    }
}

#[test]
fn pkce_challenges() {
    let h = vectors();
    let p = &h["pkce"];
    for c in cases(p, "valid") {
        assert!(
            setup::verifier_ok(s(c, "verifier").as_bytes()),
            "{}",
            s(c, "name")
        );
        assert_eq!(
            setup::challenge(s(c, "verifier")),
            s(c, "challenge"),
            "{}",
            s(c, "name")
        );
        assert!(setup::challenge_ok(s(c, "challenge").as_bytes()));
    }
    for c in cases(p, "invalid") {
        assert!(
            !setup::verifier_ok(s(c, "verifier").as_bytes()),
            "{}",
            s(c, "name")
        );
    }
}

#[test]
fn redirect_uris_states_and_authorize_queries() {
    let h = vectors();
    for c in cases(&h, "redirect_uris") {
        assert_eq!(
            setup::redirect_uri_ok(s(c, "text").as_bytes()),
            c["valid"].as_bool().unwrap(),
            "{}",
            s(c, "name")
        );
    }
    for c in cases(&h, "states") {
        assert_eq!(
            setup::state_ok(s(c, "text").as_bytes()),
            c["valid"].as_bool().unwrap(),
            "{}",
            s(c, "name")
        );
    }
    for c in cases(&h, "authorize") {
        assert_eq!(
            setup::parse_authorize_query(s(c, "text")).is_ok(),
            c["valid"].as_bool().unwrap(),
            "{}",
            s(c, "name")
        );
    }
}

#[test]
fn device_status_bodies() {
    let h = vectors();
    for c in cases(&h, "device_status") {
        let got = setup::parse_device_status(s(c, "body").as_bytes());
        assert_eq!(got.is_ok(), c["error"].is_null(), "{}", s(c, "name"));
    }
}

#[test]
fn token_request_bodies() {
    let h = vectors();
    for c in cases(&h, "setup_token") {
        // The relay checks the digest before it reads the body (12.3 step 1).
        if c["error"] == "bad_digest" {
            continue;
        }
        let got = setup::parse_token_request(s(c, "body").as_bytes());
        // A body error is `bad_request`. Each other case has a valid body.
        let body_error = c["error"] == "bad_request" && s(c, "name") != "cookie-header";
        assert_eq!(got.is_err(), body_error, "{}", s(c, "name"));
    }
}

#[test]
fn webhook_urls_and_messages() {
    let h = vectors();
    let w = &h["webhook"];
    let allow: Vec<&str> = w["allowlist"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for c in cases(w, "urls") {
        let ok =
            setup::parse_webhook_url(s(c, "text")).is_ok_and(|u| allow.contains(&u.host.as_str()));
        assert_eq!(ok, c["valid"].as_bool().unwrap(), "{}", s(c, "name"));
    }
    for c in cases(w, "messages") {
        assert_eq!(
            setup::webhook_body(s(c, "text")),
            s(c, "body").as_bytes(),
            "{}",
            s(c, "text")
        );
    }
}
