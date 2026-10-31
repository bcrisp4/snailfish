//! The core through real SQLite files, without an async runtime.
//!
//! Model scenarios come from `specs/delivery/test.qnt`.

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use common::{Fx, error_code, s};
use rusqlite::Connection;
use snailfish_protocol::wire::{self, AppendResult};

const T2: &str = "t_00000000000000000000000000000002";

fn fixture_with_change() -> (Fx, String) {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let env = fx.change("B", 4, [0x11; 16], 60, 7);
    (fx, env)
}

fn entries(fx: &Fx) -> wire::Fetch {
    let r = fx.fetch(fx.tenant(), 0, 500);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    wire::parse_fetch(&r.body).unwrap()
}

/// `specs/delivery/test.qnt::retryAfterLostResponseTest` ([WIR-6] [DLV-7]).
/// The push is stored and its response is lost. The second push answers
/// `known` with the same position, and the log holds one copy.
#[test]
fn retry_after_lost_response_is_known_at_the_same_position() {
    let (fx, env) = fixture_with_change();
    let first = fx.append(fx.tenant(), "B", std::slice::from_ref(&env));
    assert_eq!(first.1, [AppendResult::Stored(5)]);
    // The response of the first push is lost. The engine sends it again.
    let second = fx.append(fx.tenant(), "B", std::slice::from_ref(&env));
    assert_eq!(second.1, [AppendResult::Known(5)]);
    assert_eq!(second.2, first.2);
    assert_eq!(second.2.position, 5);
    let log = entries(&fx);
    assert_eq!(log.entries.len(), 5);
    assert_eq!(log.head, first.2);
}

/// `specs/delivery/test.qnt::knownBeforeSizeTest` ([WIR-6] [DLV-5] [DLV-7]).
/// After a restart with a lower `max_change_bytes`, the retry of a stored
/// change is `known`, and a new change of the same size is `too_large`.
#[test]
fn known_is_answered_before_the_size_limit() {
    let (mut fx, env) = fixture_with_change();
    assert_eq!(
        fx.append(fx.tenant(), "B", std::slice::from_ref(&env)).1,
        [AppendResult::Stored(5)]
    );
    let mut limits = common::limits_of(&fx.h);
    limits.max_change_bytes = 100;
    fx.restart(limits);
    assert_eq!(
        fx.append(fx.tenant(), "B", std::slice::from_ref(&env)).1,
        [AppendResult::Known(5)]
    );
    let other = fx.change("B", 4, [0x12; 16], 60, 7);
    assert_eq!(
        fx.append(fx.tenant(), "B", &[other]).1,
        [AppendResult::Refused("too_large".into())]
    );
    assert_eq!(entries(&fx).head.position, 5);
}

/// `specs/delivery/test.qnt::badBaseTest` ([LOG-6] [DLV-9]). A base that is
/// not in the log gives `bad_base`, and the relay stores nothing.
#[test]
fn base_not_in_log_is_bad_base_and_stores_nothing() {
    let (fx, _) = fixture_with_change();
    let before = entries(&fx).head;
    let wrong_digest = fx.change_on("B", 4, &wire_b64([9; 32]), [0x21; 16], 60, 1);
    let beyond = fx.change_on("B", 9, &wire_b64([9; 32]), [0x22; 16], 60, 1);
    let r = fx.append(fx.tenant(), "B", &[wrong_digest, beyond]);
    assert_eq!(
        r.1,
        [
            AppendResult::Refused("bad_base".into()),
            AppendResult::Refused("bad_base".into())
        ]
    );
    assert_eq!(r.2, before);
    assert_eq!(entries(&fx).entries.len(), 4);
}

fn wire_b64(b: [u8; 32]) -> String {
    snailfish_protocol::encoding::encode_b64(&b)
}

/// `specs/delivery/test.qnt::pushConflictTest` ([WIR-6]) and the relay side
/// of `conflictTreatedAsStoredTest` ([DLV-6]). The same `change_id` with
/// another record hash is a `conflict` at the original position, also after a
/// lower limit, and the log keeps the original entry.
#[test]
fn same_change_id_other_hash_is_conflict_and_log_is_unchanged() {
    let (mut fx, env) = fixture_with_change();
    assert_eq!(
        fx.append(fx.tenant(), "B", std::slice::from_ref(&env)).1,
        [AppendResult::Stored(5)]
    );
    let other = fx.change("B", 4, [0x11; 16], 60, 8);
    let r = fx.append(fx.tenant(), "B", std::slice::from_ref(&other));
    assert_eq!(r.1, [AppendResult::Conflict(5)]);
    assert_eq!(r.2.position, 5);
    let mut limits = common::limits_of(&fx.h);
    limits.max_change_bytes = 100;
    fx.restart(limits);
    assert_eq!(
        fx.append(fx.tenant(), "B", &[other]).1,
        [AppendResult::Conflict(5)]
    );
    let log = entries(&fx);
    assert_eq!(log.entries.len(), 5);
    let wire::FetchEntry::Envelope(e) = &log.entries[4].1 else {
        panic!("stub")
    };
    assert_eq!(e.json, env, "the stored envelope is the original text");
}

/// 10.6 step 2 and [STO-11]: a second copy in one request is `known`, and a
/// refusal does not stop the other envelopes.
#[test]
fn one_request_mixes_stored_known_and_refused() {
    let (fx, env) = fixture_with_change();
    let bad = fx.change_on("B", 4, &wire_b64([9; 32]), [0x31; 16], 60, 1);
    let next = fx.change("B", 4, [0x32; 16], 60, 2);
    let r = fx.append(fx.tenant(), "B", &[env.clone(), env, bad, next]);
    assert_eq!(
        r.1,
        [
            AppendResult::Stored(5),
            AppendResult::Known(5),
            AppendResult::Refused("bad_base".into()),
            AppendResult::Stored(6),
        ]
    );
    assert_eq!(r.2.position, 6);
}

#[test]
fn record_by_another_device_is_not_author() {
    let (fx, _) = fixture_with_change();
    let by_b = fx.change("B", 4, [0x41; 16], 60, 1);
    assert_eq!(
        fx.append(fx.tenant(), "A", &[by_b]).1,
        [AppendResult::Refused("not_author".into())]
    );
}

#[test]
fn append_body_limits_are_bad_request() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let path = format!("{}/append", fx.space_path(fx.tenant(), fx.log()));
    for body in [&b"{\"envelopes\":[]}"[..], b"not json", b"[]"] {
        let r = fx.relay.handle(&fx.signed("POST", &path, "", body, "A"));
        assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_request"));
    }
    let env = fx.change("A", 4, [0x51; 16], 60, 1);
    let many = vec![env; 9];
    let r = fx
        .relay
        .handle(&fx.signed("POST", &path, "", &wire::append_body(&many), "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_request"));
}

#[test]
fn fetch_pages_and_strict_query() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let page = wire::parse_fetch(&fx.fetch(fx.tenant(), 1, 2).body).unwrap();
    assert_eq!(page.entries.iter().map(|e| e.0).collect::<Vec<_>>(), [2, 3]);
    assert!(page.has_more);
    assert_eq!(page.head.position, 4);
    let last = wire::parse_fetch(&fx.fetch(fx.tenant(), 3, 5).body).unwrap();
    assert_eq!(last.entries.len(), 1);
    assert!(!last.has_more);
    let beyond = wire::parse_fetch(&fx.fetch(fx.tenant(), 50, 5).body).unwrap();
    assert!(beyond.entries.is_empty() && !beyond.has_more);
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    for q in [
        "",
        "after=0",
        "limit=5",
        "limit=5&after=0",
        "after=01&limit=5",
        "after=0&limit=0",
        "after=0&limit=501",
        "after=-1&limit=5",
        "after=0&limit=5&x=1",
        "after=+1&limit=5",
        "after=0&limit=05",
        "after=&limit=5",
    ] {
        let r = fx.relay.handle(&fx.signed("GET", &path, q, b"", "A"));
        assert_eq!(
            (r.status, error_code(&r).as_str()),
            (400, "bad_request"),
            "{q}"
        );
    }
}

#[test]
fn put_is_idempotent_and_refuses_other_genesis() {
    let fx = Fx::new();
    let first = fx.put_genesis(fx.tenant());
    assert_eq!(first.status, 201);
    let again = fx.put_genesis(fx.tenant());
    assert_eq!(again.status, 200);
    assert_eq!(again.body, first.body);
    let head = wire::parse_head_body(&first.body).unwrap();
    assert_eq!(
        hex::encode(head.digest),
        s(&fx.h["space"]["genesis_digest"])
    );

    // A genesis with other bytes and a valid recovery signature.
    let p = common::load("protocol.json");
    let r1 = p["recovery"][0]["sign_seed"].as_str().unwrap();
    let rk = snailfish_protocol::sig::SecretKey::from_seed(
        &hex::decode(r1).unwrap().try_into().unwrap(),
    );
    let g = snailfish_protocol::envelope::Envelope::parse(s(&fx.h["space"]["genesis"]).as_bytes())
        .unwrap();
    let mut payload = g.payload.clone();
    payload.push(b' ');
    let other = snailfish_protocol::envelope::Envelope {
        sig: rk.sign_record(&g.payload_type, &payload),
        payload,
        payload_type: g.payload_type,
    }
    .to_json("d_x");
    let path = fx.space_path(fx.tenant(), fx.log());
    let r = fx
        .relay
        .handle(&fx.signed("PUT", &path, "", &wire::genesis_body(&other), "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (409, "space_exists"));
    assert_eq!(
        wire::parse_head_body(&fx.put_genesis(fx.tenant()).body).unwrap(),
        head
    );
}

#[test]
fn put_refuses_invalid_records_and_other_signers() {
    let fx = Fx::new();
    let path = fx.space_path(fx.tenant(), fx.log());
    let g = s(&fx.h["space"]["genesis"]);
    // Another log ID in the path.
    let other_log = fx.space_path(fx.tenant(), "l_00000000000000000000000000000000");
    let r = fx
        .relay
        .handle(&fx.signed("PUT", &other_log, "", &wire::genesis_body(g), "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (422, "invalid_record"));
    // A change record is not a genesis record.
    let change = fx.change("A", 1, [1; 16], 60, 1);
    let r = fx
        .relay
        .handle(&fx.signed("PUT", &path, "", &wire::genesis_body(&change), "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (422, "invalid_record"));
    // The signer is not the device of the genesis record.
    let r = fx
        .relay
        .handle(&fx.signed("PUT", &path, "", &wire::genesis_body(g), "B"));
    assert_eq!((r.status, error_code(&r).as_str()), (403, "unknown_device"));
    let r = fx.relay.handle(&fx.signed("PUT", &path, "", b"{}", "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (400, "bad_request"));
    // Nothing was created.
    let r = fx.fetch(fx.tenant(), 0, 5);
    assert_eq!((r.status, error_code(&r).as_str()), (404, "unknown_space"));
}

#[test]
fn unknown_tenant_and_space_are_404() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let r = fx.fetch("t_00000000000000000000000000000009", 0, 5);
    assert_eq!((r.status, error_code(&r).as_str()), (404, "unknown_tenant"));
    let path = "/v1/t/not-a-handle/s/l_00000000000000000000000000000000/entries";
    let r = fx
        .relay
        .handle(&fx.signed("GET", path, "after=0&limit=1", b"", "A"));
    assert_eq!((r.status, error_code(&r).as_str()), (404, "unknown_tenant"));
    fx.relay.add_user_with_handle("lee", T2).unwrap();
    let r = fx.fetch(T2, 0, 5);
    assert_eq!((r.status, error_code(&r).as_str()), (404, "unknown_space"));
}

/// [T11]: a device of tenant 1 cannot read the space through tenant 2.
#[test]
fn tenants_do_not_share_spaces_or_nonces() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.relay.add_user_with_handle("lee", T2).unwrap();
    fx.setup_space(T2);
    assert_eq!(fx.nonce_count(T2), 4);
    assert_ne!(fx.space_file(fx.tenant()), fx.space_file(T2));
}

// ----------------------------------------------------------------- nonces

/// 8.6 step 7: a nonce survives a restart (T5).
#[test]
fn nonce_reuse_is_refused_after_restart() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let req = fx.signed("GET", &path, "after=0&limit=1", b"", "A");
    assert_eq!(fx.relay.handle(&req).status, 200);
    let again = fx.relay.handle(&req);
    assert_eq!(
        (again.status, error_code(&again).as_str()),
        (401, "nonce_reused")
    );
    fx.restart(common::limits_of(&fx.h));
    let r = fx.relay.handle(&req);
    assert_eq!((r.status, error_code(&r).as_str()), (401, "nonce_reused"));
}

#[test]
fn nonce_is_stored_only_after_the_signature_verifies() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let before = fx.nonce_count(fx.tenant());
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let mut req = fx.signed("GET", &path, "after=0&limit=1", b"", "A");
    req.query = "after=0&limit=2".into();
    let r = fx.relay.handle(&req);
    assert_eq!((r.status, error_code(&r).as_str()), (401, "bad_signature"));
    assert_eq!(fx.nonce_count(fx.tenant()), before);
}

#[test]
fn expired_request_is_refused_and_expired_nonces_are_deleted() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let now = fx.now.load(Ordering::SeqCst);
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let old = fx.signed_with(
        "GET",
        &path,
        "after=0&limit=1",
        b"",
        "A",
        [1; 16],
        now - 301,
    );
    let r = fx.relay.handle(&old);
    assert_eq!((r.status, error_code(&r).as_str()), (401, "expired"));
    let (_, _, a) = fx.key("A");
    fx.seed_nonce(fx.tenant(), &a, "00000000000000000000000000000001", now - 1);
    let before = fx.nonce_count(fx.tenant());
    assert_eq!(fx.fetch(fx.tenant(), 0, 1).status, 200);
    // The expired row is gone and the new nonce is stored.
    assert_eq!(fx.nonce_count(fx.tenant()), before);
    // A request that stays valid after the clock moves is still checked.
    fx.now.store(now + 400, Ordering::SeqCst);
    let r = fx.fetch(fx.tenant(), 0, 1);
    assert_eq!(r.status, 200);
}

#[test]
fn wrong_authority_is_421_and_the_host_header_is_not_used() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let mut req = fx.signed("GET", &path, "after=0&limit=1", b"", "A");
    for (n, v) in &mut req.headers {
        if n == "snailfish-authority" {
            *v = "other.example.net".into();
        }
    }
    let r = fx.relay.handle(&req);
    assert_eq!(
        (r.status, error_code(&r).as_str()),
        (421, "wrong_authority")
    );
    // A Host header that names the configured authority does not repair a
    // signature made for another authority.
    let other = Fx::with("other.example.net", common::limits_of(&fx.h));
    let mut req = other.signed("GET", &path, "after=0&limit=1", b"", "A");
    req.headers.push(("host".into(), fx.authority.clone()));
    for (n, v) in &mut req.headers {
        if n == "snailfish-authority" {
            v.clone_from(&fx.authority);
        }
    }
    let r = fx.relay.handle(&req);
    assert_eq!((r.status, error_code(&r).as_str()), (401, "bad_signature"));
}

#[test]
fn startup_needs_an_authority() {
    let dir = tempfile::tempdir().unwrap();
    let e = snailfish_relay::core::Relay::open(snailfish_relay::core::Config::new(dir.path(), ""));
    assert!(e.is_err());
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_snailfish-relay"))
        .args(["serve", "--data"])
        .arg(dir.path())
        .env_remove("SNAILFISH_AUTHORITY")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("authority"));
}

// ---------------------------------------------------------------- storage

fn pragma(c: &Connection, name: &str) -> String {
    c.query_row(&format!("PRAGMA {name}"), [], |r| {
        r.get::<_, rusqlite::types::Value>(0).map(|v| match v {
            rusqlite::types::Value::Integer(i) => i.to_string(),
            rusqlite::types::Value::Text(t) => t.to_lowercase(),
            other => format!("{other:?}"),
        })
    })
    .unwrap()
}

/// [STO-1] on each file kind. `journal_mode` persists in the file. The other
/// settings are per connection, so the check opens the file as the relay
/// does, through `store::open`.
#[test]
fn every_file_kind_has_the_storage_settings() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let files = [
        (
            fx.dir.path().join("directory.db"),
            snailfish_relay::store::Kind::Directory,
        ),
        (
            fx.tenant_db(fx.tenant()),
            snailfish_relay::store::Kind::Tenant,
        ),
        (
            fx.space_file(fx.tenant()),
            snailfish_relay::store::Kind::Space,
        ),
    ];
    for (path, kind) in files {
        let c = snailfish_relay::store::open(&path, kind, false).unwrap();
        assert_eq!(pragma(&c, "journal_mode"), "wal", "{kind:?}");
        assert_eq!(pragma(&c, "synchronous"), "2", "{kind:?}");
        assert_eq!(pragma(&c, "secure_delete"), "1", "{kind:?}");
        assert_eq!(pragma(&c, "auto_vacuum"), "2", "{kind:?}");
        assert_eq!(
            pragma(&c, "user_version"),
            snailfish_relay::store::SCHEMA_VERSION.to_string(),
            "{kind:?}"
        );
    }
}

/// [STO-3]: the file name is 128 random bits in lowercase base32, and it does
/// not come from the log ID.
#[test]
fn space_file_name_is_random_base32() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.relay.add_user_with_handle("lee", T2).unwrap();
    fx.setup_space(T2);
    let a = fx.space_file(fx.tenant());
    let b = fx.space_file(T2);
    let stem = |p: &std::path::Path| p.file_stem().unwrap().to_str().unwrap().to_owned();
    for n in [stem(&a), stem(&b)] {
        assert_eq!(n.len(), 26);
        assert!(
            n.bytes()
                .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)),
            "{n}"
        );
        assert!(!n.contains(&fx.log()[2..10]));
    }
    assert_ne!(stem(&a), stem(&b), "the same log ID gets another name");
    let t = Connection::open(fx.tenant_db(fx.tenant())).unwrap();
    let (name, app): (String, String) = t
        .query_row(
            "SELECT file_name, app_id FROM spaces WHERE log_id = ?1",
            [fx.log()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(name, stem(&a));
    // [STO-7]: the space file holds its own log ID and app ID.
    let sc = Connection::open(&a).unwrap();
    let (log, app2): (Vec<u8>, String) = sc
        .query_row("SELECT log_id, app_id FROM space", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((log, app2), (fx.log_id().to_vec(), app));
}

/// [VER-15]: a file with a newer schema does not open.
#[test]
fn newer_schema_does_not_open() {
    let fx = Fx::new();
    {
        let c = Connection::open(fx.dir.path().join("directory.db")).unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
    }
    let e = Fx::open(&fx.dir, &fx.authority, common::limits_of(&fx.h), &fx.now).err();
    assert!(e.is_some_and(|e| e.to_string().contains("newer")));
}

#[test]
fn duplicate_user_name_is_refused() {
    let fx = Fx::new();
    assert!(fx.relay.add_user("sam").is_err());
    let handle = fx.relay.add_user("lee").unwrap();
    assert!(handle.starts_with("t_") && handle.len() == 34);
}

// ------------------------------------------------------------ concurrency

fn raw_write_lock(path: &std::path::Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    c
}

fn run_with_deadline<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(3)).ok()
}

/// [STO-1] [STO-3]: a write transaction that is open on the space file of
/// tenant 1 does not block a write to tenant 2.
#[test]
fn write_in_one_tenant_does_not_block_another_tenant() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.relay.add_user_with_handle("lee", T2).unwrap();
    fx.setup_space(T2);
    let lock = raw_write_lock(&fx.space_file(fx.tenant()));
    // The lock is real: a second writer of tenant 1 cannot start.
    let probe = Connection::open(fx.space_file(fx.tenant())).unwrap();
    probe.busy_timeout(Duration::ZERO).unwrap();
    assert!(probe.execute_batch("BEGIN IMMEDIATE").is_err());

    let env = fx.change("B", 4, [0x61; 16], 60, 1);
    let fx = std::sync::Arc::new(fx);
    let f2 = std::sync::Arc::clone(&fx);
    let r = run_with_deadline(move || f2.append(T2, "B", &[env])).expect("tenant 2 append blocked");
    assert_eq!(r.1, [AppendResult::Stored(5)]);
    lock.execute_batch("ROLLBACK").unwrap();
}

/// Both tenants write from separate threads at the same time. Each log ends
/// with all its changes at dense positions.
#[test]
fn concurrent_writers_in_two_tenants_all_succeed() {
    let fx = std::sync::Arc::new(Fx::new());
    fx.setup_space(fx.tenant());
    fx.relay.add_user_with_handle("lee", T2).unwrap();
    fx.setup_space(T2);
    let handles: Vec<_> = [fx.tenant().to_owned(), T2.to_owned()]
        .into_iter()
        .map(|t| {
            let fx = std::sync::Arc::clone(&fx);
            std::thread::spawn(move || {
                for i in 0..10u8 {
                    let env = fx.change("B", 4, [i + 1; 16], 100, i);
                    let r = fx.append(&t, "B", &[env]);
                    assert_eq!(r.1, [AppendResult::Stored(5 + u64::from(i))]);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        wire::parse_fetch(&fx.fetch(T2, 0, 500).body)
            .unwrap()
            .head
            .position,
        14
    );
}

/// [STO-11]: a fetch succeeds while a write transaction of the same space
/// file is open, and it does not see the uncommitted row.
#[test]
fn fetch_succeeds_during_a_write_transaction_of_the_same_space() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let lock = raw_write_lock(&fx.space_file(fx.tenant()));
    lock.execute(
        "INSERT INTO entries (position, payload_type, change_id, record_hash, digest, envelope)
         VALUES (5, 'snailfish.change.v1', NULL, x'00', x'00', '{}')",
        [],
    )
    .unwrap();
    let fx = std::sync::Arc::new(fx);
    let f2 = std::sync::Arc::clone(&fx);
    let t = fx.tenant().to_owned();
    let r = run_with_deadline(move || f2.fetch(&t, 0, 500)).expect("fetch blocked");
    assert_eq!(r.status, 200);
    let page = wire::parse_fetch(&r.body).unwrap();
    assert_eq!((page.entries.len(), page.head.position), (4, 4));
    lock.execute_batch("ROLLBACK").unwrap();
}
