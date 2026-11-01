//! The user and setup surface through the core (`PROTOCOL.md` 10.5, 10.11
//! and 12): invite links, passkey sign-in with a software authenticator,
//! sessions, the Origin and anti-CSRF rules, the native sign-in handoff,
//! tenant isolation, quotas and the user page.
//!
//! The sign-in cases follow `specs/signin` ([USR-1] to [USR-7]), and the
//! quota cases follow `specs/quota/test.qnt` ([QTA-1] to [QTA-5]).

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use std::sync::atomic::Ordering;

use common::passkey::SoftPasskey;
use common::{Fx, error_code, s};
use serde_json::{Value, json};
use snailfish_protocol::setup::{self, TokenKind, TokenRequest};
use snailfish_protocol::wire::{self, AppendResult};
use snailfish_relay::core::{Request, Response};

const ORIGIN: &str = "https://sync.example.net";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT: &str = "com.example.tasks:/cb";

/// A browser: a cookie, and requests with the user page origin.
struct Browser<'a> {
    fx: &'a Fx,
    cookie: Option<String>,
}

impl<'a> Browser<'a> {
    fn new(fx: &'a Fx) -> Self {
        Self { fx, cookie: None }
    }

    fn send(
        &mut self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
        extra: &[(&str, &str)],
    ) -> Response {
        let mut headers: Vec<(String, String)> = extra
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        if let Some(c) = &self.cookie {
            headers.push(("cookie".into(), format!("sf_session={c}")));
        }
        let r = self.fx.relay.handle(&Request {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers,
            body: body.to_vec(),
        });
        if let Some(v) = r.header("set-cookie") {
            let value = v
                .split(';')
                .next()
                .unwrap()
                .trim_start_matches("sf_session=");
            self.cookie = (!value.is_empty()).then(|| value.to_owned());
        }
        r
    }

    fn json(&mut self, path: &str, body: &Value) -> Response {
        let csrf = self.csrf();
        let mut extra = vec![("origin", ORIGIN), ("content-type", "application/json")];
        if let Some(c) = &csrf {
            extra.push(("snailfish-csrf", c.as_str()));
        }
        self.send("POST", path, "", body.to_string().as_bytes(), &extra)
    }

    fn form(&mut self, path: &str, fields: &[(&str, &str)]) -> Response {
        let body = form_body(fields, self.csrf().as_deref());
        self.send("POST", path, "", body.as_bytes(), &[("origin", ORIGIN)])
    }

    fn home(&mut self) -> String {
        let r = self.send("GET", "/u/", "", b"", &[]);
        assert_eq!(r.status, 200);
        String::from_utf8(r.body).unwrap()
    }

    /// The anti-CSRF token from the user page, if signed in.
    fn csrf(&mut self) -> Option<String> {
        self.cookie.as_ref()?;
        let r = self.fx.relay.handle(&Request {
            method: "GET".into(),
            path: "/u/".into(),
            query: String::new(),
            headers: vec![(
                "cookie".into(),
                format!("sf_session={}", self.cookie.as_ref()?),
            )],
            body: Vec::new(),
        });
        let page = String::from_utf8(r.body).ok()?;
        let i = page.find("name=\"csrf\" content=\"")? + 21;
        Some(page[i..i + 64].to_owned())
    }

    fn register(&mut self, invite: &str, key: &mut SoftPasskey) -> Response {
        let r = self.json("/u/invite/start", &json!({ "token": invite }));
        if r.status != 200 {
            return r;
        }
        let start: Value = serde_json::from_slice(&r.body).unwrap();
        let cred = key.create(&start);
        self.json(
            "/u/invite/finish",
            &json!({ "ceremony": start["ceremony"], "credential": cred }),
        )
    }

    fn sign_in(&mut self, name: &str, key: &mut SoftPasskey) -> Response {
        let r = self.json("/u/signin/start", &json!({ "name": name }));
        if r.status != 200 {
            return r;
        }
        let start: Value = serde_json::from_slice(&r.body).unwrap();
        let cred = key.get(&start);
        self.json(
            "/u/signin/finish",
            &json!({ "ceremony": start["ceremony"], "credential": cred }),
        )
    }

    /// Approve a native sign-in (12.2). Returns the code of the redirect.
    fn approve(&mut self, challenge: &str) -> String {
        let r = self.form(
            "/u/authorize",
            &[
                ("response_type", "code"),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("redirect_uri", REDIRECT),
                ("state", "s1"),
            ],
        );
        assert_eq!(r.status, 303, "{}", String::from_utf8_lossy(&r.body));
        let loc = r.header("location").unwrap();
        let (_, q) = loc.split_once('?').unwrap();
        let (code, state) = setup::parse_redirect_query(q).unwrap();
        assert_eq!(state, "s1");
        setup::token_text(TokenKind::Code, &code)
    }
}

fn form_body(fields: &[(&str, &str)], csrf: Option<&str>) -> String {
    let enc = |v: &str| {
        v.bytes()
            .map(|b| {
                if setup::unreserved(b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    let mut parts: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect();
    if let Some(c) = csrf {
        parts.push(format!("csrf={c}"));
    }
    parts.join("&")
}

fn invite_token(link: &str) -> &str {
    link.rsplit_once('#').unwrap().1
}

fn key() -> SoftPasskey {
    SoftPasskey::new(ORIGIN, "sync.example.net")
}

/// Sam with one passkey and a signed-in browser.
fn signed_in(fx: &Fx) -> (Browser<'_>, SoftPasskey) {
    let link = fx.relay.invite("sam").unwrap();
    let mut b = Browser::new(fx);
    let mut k = key();
    let r = b.register(invite_token(&link), &mut k);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    (b, k)
}

/// The token exchange of 12.3 for device `name` with `code`.
fn exchange(fx: &Fx, code: &str, verifier: &str, name: &str) -> Response {
    let body = setup::token_request_body(&TokenRequest {
        code: setup::parse_token(TokenKind::Code, code).unwrap(),
        verifier: verifier.into(),
        redirect_uri: REDIRECT.into(),
        device: common::keys_of(name),
    });
    fx.relay
        .handle(&fx.signed("POST", "/v1/setup/token", "", &body, name))
}

fn put(fx: &Fx, tenant: &str, token: &[u8; 32], signer: &str) -> Response {
    let g = s(&fx.h["space"]["genesis"]);
    let path = fx.space_path(tenant, fx.log());
    fx.relay
        .handle(&fx.signed("PUT", &path, "", &wire::genesis_body(g, token), signer))
}

// ------------------------------------------------------------ invites

/// [USR-1]: an invite registers a passkey once, and the passkey signs in.
#[test]
fn invite_registers_a_passkey_once_and_signs_in() {
    let fx = Fx::new();
    let link = fx.relay.invite("sam").unwrap();
    assert!(
        link.starts_with("https://sync.example.net/u/invite#it_"),
        "{link}"
    );
    let mut b = Browser::new(&fx);
    let mut k = key();
    assert_eq!(b.register(invite_token(&link), &mut k).status, 200);
    assert!(b.home().contains("Signed in as <b>sam</b>"));
    // The link works once.
    let mut other = Browser::new(&fx);
    let r = other.register(invite_token(&link), &mut key());
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_invite"));
    // Sign out, then sign in with the passkey.
    assert_eq!(b.form("/u/signout", &[]).status, 303);
    assert!(b.cookie.is_none());
    assert!(b.home().contains("Sign in with a passkey"));
    assert_eq!(b.sign_in("sam", &mut k).status, 200);
    assert!(b.home().contains("Signed in as <b>sam</b>"));
    // Another key does not sign in.
    let r = Browser::new(&fx).sign_in("sam", &mut key());
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_passkey"));
}

/// [USR-1]: a link expires 604,800 seconds after the command.
#[test]
fn invite_expires_after_7_days() {
    for (late, ok) in [(604_799, true), (604_800, false)] {
        let fx = Fx::new();
        let link = fx.relay.invite("sam").unwrap();
        fx.now.fetch_add(late, Ordering::SeqCst);
        let r = Browser::new(&fx).register(invite_token(&link), &mut key());
        assert_eq!(
            r.status == 200,
            ok,
            "{late}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
}

/// [USR-2]: a new link removes the old passkeys, the sessions, the open
/// authorization codes and the setup tokens, so a party with a stolen
/// session cannot create a space after the operator locks it out.
#[test]
fn new_invite_removes_old_passkeys_and_sessions() {
    let fx = Fx::new();
    let (mut b, mut k) = signed_in(&fx);
    let code = b.approve(&setup::challenge(VERIFIER));
    let held = b.approve(&setup::challenge(VERIFIER));
    let r = exchange(&fx, &held, VERIFIER, "A");
    let t = setup::parse_token_response(&r.body).unwrap();
    let _new = fx.relay.invite("sam").unwrap();
    let r = exchange(&fx, &code, VERIFIER, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
    let r = put(&fx, &t.tenant, &t.token, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
    assert!(
        b.home().contains("Sign in with a passkey"),
        "the old session still works"
    );
    let r = Browser::new(&fx).sign_in("sam", &mut k);
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_passkey"));
}

/// PROTOCOL.md 12.4: a flood of sign-in starts that fills the ceremony
/// store does not refuse the sign-in of the user, which starts after it.
#[test]
fn ceremony_flood_does_not_refuse_a_sign_in() {
    let fx = Fx::new();
    let (_, mut k) = signed_in(&fx);
    let mut flood = Browser::new(&fx);
    for _ in 0..snailfish_relay::core::user::MAX_CEREMONIES {
        let r = flood.json("/u/signin/start", &json!({ "name": "sam" }));
        assert_eq!(r.status, 200);
    }
    let r = Browser::new(&fx).sign_in("sam", &mut k);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

/// [USR-1], `specs/signin/plain_invite.pv`: the directory holds a hash of
/// the invite token, never the token.
#[test]
fn directory_holds_no_invite_token() {
    let fx = Fx::new();
    let link = fx.relay.invite("sam").unwrap();
    let token = setup::parse_token(TokenKind::Invite, invite_token(&link)).unwrap();
    let mut bytes = Vec::new();
    for f in ["directory.db", "directory.db-wal"] {
        bytes.extend(std::fs::read(fx.dir.path().join(f)).unwrap_or_default());
    }
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(!has(&token));
    assert!(!has(hex::encode(token).as_bytes()));
    assert!(has(&setup::token_hash(&token)));
}

// ------------------------------------------------------- write rules

/// [USR-7]: a user write needs the exact origin and the anti-CSRF token of
/// its own session.
#[test]
fn user_writes_need_origin_and_csrf() {
    let fx = Fx::new();
    let (mut b, _) = signed_in(&fx);
    let csrf = b.csrf().unwrap();
    let body = form_body(&[("name", "phone")], Some(&csrf));
    for (origin, code) in [
        (None, "bad_origin"),
        (Some("https://evil.example"), "bad_origin"),
        (Some("https://sync.example.net/"), "bad_origin"),
    ] {
        let extra: Vec<(&str, &str)> = origin.map(|o| ("origin", o)).into_iter().collect();
        let r = b.send("POST", "/u/groups", "", body.as_bytes(), &extra);
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (403, code),
            "{origin:?}"
        );
    }
    for bad in [
        form_body(&[("name", "phone")], None),
        form_body(&[("name", "phone")], Some(&"0".repeat(64))),
    ] {
        let r = b.send(
            "POST",
            "/u/groups",
            "",
            bad.as_bytes(),
            &[("origin", ORIGIN)],
        );
        assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_csrf"));
    }
    // The token of another session does not work.
    let mut other = Browser::new(&fx);
    assert_eq!(other.sign_in("sam", &mut key()).status, 403);
    let r = b.send(
        "POST",
        "/u/passkeys/start",
        "",
        b"{}",
        &[("origin", ORIGIN)],
    );
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_csrf"));
    assert!(!b.home().contains("phone"));
    assert_eq!(b.form("/u/groups", &[("name", "phone")]).status, 303);
    assert!(b.home().contains("phone"));
    // Without a session, a write is `signed_out`.
    let r = Browser::new(&fx).form("/u/groups", &[("name", "x")]);
    assert_eq!((r.status, error_code(&r).as_str()), (401, "signed_out"));
}

/// [USR-7]: device routes refuse the session cookie, and user routes refuse
/// a device signature. A cookie of a proxy, which an HTTP client with a
/// shared cookie store sends back, does not stop sync.
#[test]
fn device_routes_refuse_cookies_and_user_routes_refuse_signatures() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let mut req = fx.signed("GET", &path, "after=0&limit=5", b"", "A");
    req.headers
        .push(("cookie".into(), "__cf_bm=abc; sf_session=x".into()));
    let r = fx.relay.handle(&req);
    assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_request"));
    let mut req = fx.signed("GET", &path, "after=0&limit=5", b"", "A");
    req.headers
        .push(("cookie".into(), "__cf_bm=abc; AWSALB=x".into()));
    assert_eq!(fx.relay.handle(&req).status, 200);
    let mut req = fx.signed("POST", "/u/groups", "", b"name=x", "A");
    req.headers.push(("origin".into(), ORIGIN.into()));
    let r = fx.relay.handle(&req);
    assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_request"));
}

// ------------------------------------------------------------ handoff

/// [USR-3] to [USR-6], `specs/signin/signin.pv`: the honest run. The first
/// device gets the tenant handle from the token exchange and creates the
/// space with the setup token.
#[test]
fn handoff_creates_a_space() {
    let fx = Fx::new();
    let (mut b, _) = signed_in(&fx);
    let code = b.approve(&setup::challenge(VERIFIER));
    let r = exchange(&fx, &code, VERIFIER, "A");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let t = setup::parse_token_response(&r.body).unwrap();
    assert_eq!(t.tenant, fx.tenant());
    assert_eq!(t.expires, fx.now.load(Ordering::SeqCst) + 600);
    assert_eq!(put(&fx, &t.tenant, &t.token, "A").status, 201);
    // [USR-4]: the code works once.
    let r = exchange(&fx, &code, VERIFIER, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
}

/// `specs/signin/no_pkce.pv` ([USR-4]): a wrong verifier or another
/// redirect URI gets no token, and the code expires after 60 seconds.
#[test]
fn token_exchange_refuses_a_wrong_verifier() {
    let fx = Fx::new();
    let (mut b, _) = signed_in(&fx);
    let code = b.approve(&setup::challenge(VERIFIER));
    let other = "x".repeat(43);
    let r = exchange(&fx, &code, &other, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
    // The refusal did not use the code.
    assert_eq!(exchange(&fx, &code, VERIFIER, "A").status, 200);
    for (late, ok) in [(59, true), (60, false)] {
        let code = b.approve(&setup::challenge(VERIFIER));
        fx.now.fetch_add(late, Ordering::SeqCst);
        let r = exchange(&fx, &code, VERIFIER, "A");
        assert_eq!(r.status == 200, ok, "{late}");
        fx.now.fetch_sub(late, Ordering::SeqCst);
    }
}

/// `specs/signin/unbound_token.pv` ([USR-5], [USR-6]): a setup token works
/// only for the device that requested it.
#[test]
fn put_refuses_a_token_of_another_device() {
    let fx = Fx::new();
    let token = fx.setup_token("sam", "B");
    let r = put(&fx, fx.tenant(), &token, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
}

/// `specs/signin/no_tenant_check.pv` ([USR-3], [USR-6]): a second user gets
/// a token for its own device, and cannot create a space in the tenant of
/// the first user.
#[test]
fn put_refuses_a_token_of_another_tenant() {
    let fx = Fx::new();
    let kim = fx.relay.add_user("kim").unwrap();
    let token = fx.setup_token("kim", "A");
    let r = put(&fx, fx.tenant(), &token, "A");
    assert_eq!((r.status, error_code(&r).as_str()), (403, "bad_setup"));
    assert_eq!(put(&fx, &kim, &token, "A").status, 201);
}

/// [USR-5]: a setup token expires 600 seconds after the exchange, and an
/// exact retry needs no token.
#[test]
fn setup_token_expires_after_10_minutes() {
    for (late, status) in [(599, 201), (600, 403)] {
        let fx = Fx::new();
        let token = fx.setup_token("sam", "A");
        fx.now.fetch_add(late, Ordering::SeqCst);
        assert_eq!(put(&fx, fx.tenant(), &token, "A").status, status, "{late}");
        if status == 201 {
            fx.now.fetch_add(10, Ordering::SeqCst);
            assert_eq!(
                put(&fx, fx.tenant(), &token, "A").status,
                200,
                "exact retry"
            );
        }
    }
}

/// [USR-3]: a second user on the same relay cannot reach the first tenant
/// through the user page or the device routes.
#[test]
fn second_user_cannot_reach_the_first_tenant() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.relay.add_user("kim").unwrap();
    let link = fx.relay.invite("kim").unwrap();
    let mut kb = Browser::new(&fx);
    assert_eq!(kb.register(invite_token(&link), &mut key()).status, 200);
    let page = kb.home();
    assert!(page.contains("Signed in as <b>kim</b>"));
    assert!(!page.contains(fx.log()), "kim sees the space of sam");
    // A device of kim is not active in the space of sam.
    let kim_token = fx.setup_token("kim", "C");
    let r = put(&fx, fx.tenant(), &kim_token, "C");
    assert_eq!(r.status, 403);
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let r = fx
        .relay
        .handle(&fx.signed("GET", &path, "after=0&limit=5", b"", "C"));
    assert_eq!((r.status, error_code(&r).as_str()), (403, "unknown_device"));
}

// ------------------------------------------------------------- quotas

fn full_space(quota: u64) -> Fx {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.relay.set_quotas("sam", None, Some(quota)).unwrap();
    fx
}

/// `specs/quota/test.qnt::fullQuotaKeepsOutboxTest` and
/// `fetchAtFullQuotaTest` ([QTA-1], [QTA-2]).
#[test]
fn full_quota_refuses_changes_and_serves_fetches() {
    let fx = full_space(0);
    let before = fx.usage(fx.tenant());
    let c = fx.change("A", 4, [9; 16], 60, 1);
    let (status, results, head) = fx.append(fx.tenant(), "A", &[c]);
    assert_eq!(status, 200);
    assert_eq!(results, vec![AppendResult::Refused("quota".into())]);
    assert_eq!(fx.usage(fx.tenant()), before);
    let page = wire::parse_fetch(&fx.fetch(fx.tenant(), 0, 500).body).unwrap();
    assert_eq!(page.head, head);
    assert_eq!(page.entries.len() as u64, head.position);
    // S7: a larger quota stores the same change.
    fx.relay.set_quotas("sam", None, None).unwrap();
    let c = fx.change("A", 4, [9; 16], 60, 1);
    let (_, results, _) = fx.append(fx.tenant(), "A", std::slice::from_ref(&c));
    assert!(matches!(results[0], AppendResult::Stored(_)));
    assert_eq!(fx.usage(fx.tenant()), before + c.len() as u64);
}

/// `specs/quota/test.qnt::securityAtFullQuotaTest` ([QTA-3]).
#[test]
fn full_quota_stores_a_grant() {
    let h = common::load("http.json");
    let case = h["append_quota"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grant-at-full-quota")
        .unwrap();
    let fx = full_space(0);
    let path = format!("{}/append", fx.space_path(fx.tenant(), fx.log()));
    let r = fx.relay.handle(&fx.signed(
        "POST",
        &path,
        "",
        s(&case["body"]).as_bytes(),
        s(&case["signer"]),
    ));
    let (results, _) = wire::parse_append_response(&r.body).unwrap();
    assert!(matches!(results[0], AppendResult::Stored(_)), "{results:?}");
}

/// `specs/quota/test.qnt::knownBeforeQuotaTest` ([DLV-7], [QTA-1]).
#[test]
fn full_quota_answers_known_for_a_retry() {
    let fx = full_space(0);
    let stored = s(&fx.h["space"]["log"][1]["envelope"]).to_owned();
    let (_, results, _) = fx.append(fx.tenant(), "A", &[stored]);
    assert_eq!(results, vec![AppendResult::Known(2)]);
}

/// [QTA-5]: the space count limit.
#[test]
fn space_limit_refuses_a_new_space() {
    for (max, status) in [(0, 507), (1, 201)] {
        let fx = Fx::new();
        fx.relay.set_quotas("sam", Some(max), None).unwrap();
        let r = fx.put_genesis(fx.tenant());
        assert_eq!(r.status, status, "{max}");
        if status == 507 {
            assert_eq!(error_code(&r), "space_limit");
        }
    }
}

// ----------------------------------------------------------- user page

/// DESIGN.md "Monitoring and alerting" items 6 and 7: the device status
/// report shows on the user page, with the stalled mark.
#[test]
fn user_page_shows_device_status_and_groups() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let path = format!("{}/device-status", fx.space_path(fx.tenant(), fx.log()));
    let now = fx.now.load(Ordering::SeqCst);
    let body =
        format!(r#"{{"state":"paused: quota","outbox":1,"oldest":{now},"applied":4,"epoch":1}}"#);
    assert_eq!(
        fx.relay
            .handle(&fx.signed("POST", &path, "", body.as_bytes(), "B"))
            .status,
        200
    );
    let (mut b, mut k) = signed_in(&fx);
    let page = b.home();
    assert!(
        page.contains("paused: quota, outbox 1, applied 4"),
        "{page}"
    );
    assert!(!page.contains("stalled"));
    // An outbox entry older than one day marks the device as stalled. The
    // session ends after 12 hours, so sign in again.
    fx.now.fetch_add(86_400, Ordering::SeqCst);
    assert!(b.home().contains("Sign in with a passkey"));
    assert_eq!(b.sign_in("sam", &mut k).status, 200);
    assert!(
        b.home()
            .contains("stalled: an unsent change is older than 1 day")
    );
    // A machine group holds a device of the tenant only.
    assert_eq!(b.form("/u/groups", &[("name", "phone")]).status, 303);
    let device_b = fx.key("B").2;
    let r = b.form(
        "/u/groups/members",
        &[("group", "1"), ("device", &device_b), ("op", "add")],
    );
    assert_eq!(r.status, 303);
    let r = b.form(
        "/u/groups/members",
        &[
            ("group", "1"),
            ("device", &format!("d_{}", "0".repeat(64))),
            ("op", "add"),
        ],
    );
    assert_eq!(r.status, 400);
    // A tenant with a space cannot be deleted.
    let r = b.form("/u/tenant/delete", &[]);
    assert_eq!((r.status, error_code(&r).as_str()), (409, "not_empty"));
}

/// The user page releases a restore hold, as the operator command does.
#[test]
fn user_page_releases_a_restore_hold() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.set_hold(fx.tenant(), true);
    let (mut b, _) = signed_in(&fx);
    assert!(b.home().contains("on hold"));
    let r = b.form("/u/hold/release", &[("log", fx.log()), ("force", "yes")]);
    assert_eq!(r.status, 303, "{}", String::from_utf8_lossy(&r.body));
    let f = wire::parse_fetch(&fx.fetch(fx.tenant(), 0, 1).body).unwrap();
    assert!(!f.hold);
}

/// A tenant with no space deletes with its user. A delete waits for a
/// running backup ([STO-8]), and a setup token of the tenant creates no
/// space after the delete.
#[test]
fn empty_tenant_deletes_with_its_user() {
    let fx = Fx::new();
    let (mut b, mut k) = signed_in(&fx);
    let code = b.approve(&setup::challenge(VERIFIER));
    let t = setup::parse_token_response(&exchange(&fx, &code, VERIFIER, "A").body).unwrap();
    {
        let lock =
            std::fs::File::create(fx.dir.path().join(snailfish_relay::core::BACKUP_LOCK)).unwrap();
        lock.lock().unwrap();
        let r = b.form("/u/tenant/delete", &[]);
        assert_eq!((r.status, error_code(&r).as_str()), (503, "backup_running"));
        assert_eq!(fx.relay.tenant_ids().unwrap().len(), 1);
    }
    let r = b.form("/u/tenant/delete", &[]);
    assert_eq!(r.status, 200);
    assert_ne!(put(&fx, &t.tenant, &t.token, "A").status, 201);
    let r = Browser::new(&fx).sign_in("sam", &mut k);
    assert_eq!(r.status, 403);
    assert_eq!(fx.relay.tenant_ids().unwrap(), Vec::<String>::new());
}

/// [USR-8]: the webhook URL needs a host of the allowlist, and an address
/// that is not private unless the allowlist names that address.
#[test]
fn webhook_needs_an_allowed_host_and_address() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = snailfish_relay::core::Config::new(dir.path().join("data"), "sync.example.net");
    cfg.webhook_hosts = vec!["localhost".into()];
    let mut fx = Fx::new();
    fx.relay = snailfish_relay::core::Relay::open(cfg).unwrap();
    fx.relay.add_user("sam").unwrap();
    let link = fx.relay.invite("sam").unwrap();
    let mut b = Browser::new(&fx);
    assert_eq!(b.register(invite_token(&link), &mut key()).status, 200);
    let r = b.form("/u/webhook/test", &[]);
    assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_webhook"));
    for url in [
        "http://example.com/h",
        "http://localhost:9/h",
        "ftp://localhost/h",
    ] {
        let r = b.form("/u/webhook", &[("url", url)]);
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (400, "bad_webhook"),
            "{url}"
        );
    }
}
