//! The enrollment session routes (`PROTOCOL.md` 10.10, [ENR-2]) in cases
//! that `vectors/http.json` does not hold: the exact expiry second, a
//! session of another tenant, and a session ID reuse after a restart.

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use std::sync::atomic::Ordering;

use common::{Fx, error_code};
use snailfish_protocol::mailbox;
use snailfish_relay::core::{Request, Response};

const SESSION: &str = "e_00112233445566778899aabbccddeeff";

fn open(fx: &Fx, tenant: &str, signer: &str) -> Response {
    let body = mailbox::open_body(&[
        0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    let path = format!("{}/enroll", fx.space_path(tenant, fx.log()));
    fx.relay
        .handle(&fx.signed("POST", &path, "", &body, signer))
}

fn unsigned(fx: &Fx, method: &str, body: &[u8]) -> Response {
    fx.relay.handle(&Request {
        method: method.to_owned(),
        path: format!("/v1/e/{SESSION}"),
        query: String::new(),
        headers: Vec::new(),
        body: body.to_vec(),
    })
}

fn trusted_read(fx: &Fx, tenant: &str, signer: &str) -> Response {
    let path = format!("{}/enroll/{SESSION}", fx.space_path(tenant, fx.log()));
    fx.relay.handle(&fx.signed("GET", &path, "", b"", signer))
}

/// [ENR-1] 10.10: a session exists until one second before `expires`
/// (open time + 600). At `expires` it is gone for every route, and the
/// trusted device can open the ID again.
#[test]
fn session_ends_at_the_exact_expiry_second() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let t0 = fx.now.load(Ordering::SeqCst);
    let r = open(&fx, fx.tenant(), "A");
    assert_eq!(r.status, 201);
    assert_eq!(mailbox::parse_opened(&r.body), Ok(t0 + 600));
    fx.now.store(t0 + 599, Ordering::SeqCst);
    assert_eq!(unsigned(&fx, "GET", b"").status, 200);
    assert_eq!(trusted_read(&fx, fx.tenant(), "A").status, 200);
    fx.now.store(t0 + 600, Ordering::SeqCst);
    for r in [
        unsigned(&fx, "GET", b""),
        unsigned(&fx, "POST", &mailbox::cancel_body()),
        trusted_read(&fx, fx.tenant(), "A"),
    ] {
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (404, "unknown_session")
        );
    }
    assert_eq!(open(&fx, fx.tenant(), "A").status, 201);
}

/// [ENR-2]: the open binds the session to the tenant and the space. The
/// same device in another tenant cannot open the ID again
/// (`session_exists`) or read it on its trusted route (`unknown_session`),
/// so the trusted route of one tenant never shows a session of another.
#[test]
fn session_is_bound_to_the_tenant_of_the_open() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let other = fx.relay.add_user("other").unwrap();
    fx.setup_space(&other);
    assert_eq!(open(&fx, fx.tenant(), "A").status, 201);
    let r = open(&fx, &other, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (409, "session_exists"));
    let r = trusted_read(&fx, &other, "A");
    assert_eq!(
        (r.status, error_code(&r).as_str()),
        (404, "unknown_session")
    );
    assert_eq!(trusted_read(&fx, fx.tenant(), "A").status, 200);
}

/// [ENR-1] "Each session works once": a cancelled session takes no new
/// message and cannot be opened again, also after a relay restart, because
/// the relay keeps it in `directory.db` until it expires.
#[test]
fn closed_session_survives_a_restart() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    assert_eq!(open(&fx, fx.tenant(), "A").status, 201);
    assert_eq!(unsigned(&fx, "POST", &mailbox::cancel_body()).status, 200);
    fx.restart(common::limits_of(&fx.h));
    let r = unsigned(&fx, "POST", &mailbox::nonce_body(&[1; 32]));
    assert_eq!((r.status, error_code(&r).as_str()), (409, "session_closed"));
    let r = open(&fx, fx.tenant(), "B");
    assert_eq!((r.status, error_code(&r).as_str()), (409, "session_exists"));
}
