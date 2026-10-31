//! The restore hold, repair sessions and the operator commands through the
//! public relay API (DESIGN.md "Space log" [LOG-10] to [LOG-15], "Relay
//! storage" [STO-7], [STO-8], [STO-10]).

#![cfg(test)]
// Test arithmetic runs on small fixed fixture values, so overflow cannot happen.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{Fx, error_code, s};
use snailfish_protocol::encoding::encode_b64;
use snailfish_protocol::wire::{self, AppendResult, Head, StatusReport};
use snailfish_relay::ops::{self, TipState};

fn head_of(fx: &Fx, n: usize) -> Head {
    Head {
        position: n as u64,
        digest: hex::decode(s(&fx.log_entry(n)["digest"]))
            .unwrap()
            .try_into()
            .unwrap(),
    }
}

fn envelope(fx: &Fx, n: usize) -> String {
    s(&fx.log_entry(n)["envelope"]).to_owned()
}

fn report(fx: &Fx, signer: &str, tip: Head, fresh: bool) -> bool {
    let r = fx.post(
        fx.tenant(),
        "status",
        &wire::status_body(&StatusReport { tip, fresh }),
        signer,
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    wire::parse_status_response(&r.body).unwrap()
}

fn start(fx: &Fx, signer: &str, base: Head, from: usize, to: usize) -> ([u8; 16], u64) {
    let entries: Vec<(u64, String)> = (from..=to).map(|n| (n as u64, envelope(fx, n))).collect();
    let body = wire::repair_start_body(&base, &entries).unwrap();
    let r = fx.post(fx.tenant(), "repair", &body, signer);
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    wire::parse_repair_started(&r.body).unwrap()
}

fn finish(fx: &Fx, signer: &str, session: [u8; 16], tip: Head) -> u16 {
    let body = wire::repair_finish_body(&wire::RepairFinish { session, tip });
    fx.post(fx.tenant(), "repair/finish", &body, signer).status
}

/// S6 at the relay, `specs/delivery/test.qnt::relayRestoreRepairTest`
/// ([LOG-10], [LOG-11], [LOG-14], [LOG-15]): after a restore to position 2,
/// the hold refuses a change, a device repairs the log with two chunks, the
/// log changes only at the finish, both devices report, and the hold stays
/// until the operator releases it. Then the change is stored.
#[test]
fn restore_hold_repair_and_release() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.cut_log(fx.tenant(), 2);
    fx.set_hold(fx.tenant(), true);
    let change = fx.change("A", 4, [0x51; 16], 40, 1);
    let r = fx.append(fx.tenant(), "A", std::slice::from_ref(&change));
    assert_eq!(r.1, [AppendResult::Refused("on_hold".into())]);

    let (sid, next) = start(&fx, "A", head_of(&fx, 2), 3, 3);
    assert_eq!(next, 4);
    let chunk = wire::repair_chunk_body(&sid, &[(4, envelope(&fx, 4))]).unwrap();
    let r = fx.post(fx.tenant(), "repair/chunk", &chunk, "A");
    assert_eq!(wire::parse_repair_next(&r.body), Ok(5));
    assert_eq!(
        fx.record_hashes(fx.tenant()).len(),
        2,
        "staged, not in the log"
    );
    assert_eq!(finish(&fx, "A", sid, head_of(&fx, 4)), 200);
    assert_eq!(fx.record_hashes(fx.tenant()).len(), 4);

    assert!(report(&fx, "A", head_of(&fx, 4), false));
    assert!(report(&fx, "B", head_of(&fx, 4), false));
    let rep = ops::hold_report(fx.dir.path(), "sam", fx.log()).unwrap();
    assert!(rep.since.is_some());
    assert!(rep.devices.iter().all(|d| d.state == TipState::Reported));
    assert_eq!(rep.repairs.len(), 1);
    assert_eq!(rep.repairs[0].finished.map(|f| f.0), Some(4));
    // The relay does not end the hold by itself.
    assert_eq!(
        fx.append(fx.tenant(), "A", std::slice::from_ref(&change)).1,
        [AppendResult::Refused("on_hold".into())]
    );
    ops::release_hold(fx.dir.path(), "sam", fx.log(), false).unwrap();
    assert!(!report(&fx, "A", head_of(&fx, 4), false));
    assert_eq!(
        fx.append(fx.tenant(), "A", &[change]).1,
        [AppendResult::Stored(5)]
    );
}

/// `specs/delivery/test.qnt::notRepairedMarkTest` ([LOG-14], [LOG-15], F3):
/// a device with a new engine state file reports `fresh`. A later report
/// without it does not clear the mark. `release-hold` refuses without
/// `--force`, and `hold-status` changes nothing.
#[test]
fn not_repaired_mark_stays_and_blocks_release_without_force() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.set_hold(fx.tenant(), true);
    assert!(report(&fx, "B", head_of(&fx, 2), true));
    assert!(report(&fx, "B", head_of(&fx, 4), false));
    let (_, _, b) = fx.key("B");
    let rep = ops::hold_report(fx.dir.path(), "sam", fx.log()).unwrap();
    assert_eq!(rep.not_repaired(), [b.as_str()]);
    assert_eq!(rep.devices[0].position, 4, "a new report replaces the tip");
    let err = ops::release_hold(fx.dir.path(), "sam", fx.log(), false).unwrap_err();
    assert!(err.to_string().contains("not repaired"), "{err}");
    assert!(
        ops::hold_report(fx.dir.path(), "sam", fx.log())
            .unwrap()
            .since
            .is_some()
    );
    ops::release_hold(fx.dir.path(), "sam", fx.log(), true).unwrap();
    assert!(
        ops::hold_report(fx.dir.path(), "sam", fx.log())
            .unwrap()
            .since
            .is_none()
    );
    assert!(
        ops::release_hold(fx.dir.path(), "sam", fx.log(), true).is_err(),
        "no hold"
    );
}

/// `specs/delivery/test.qnt::lateDeviceRepairTest` ([LOG-12]): the grant to
/// B is only in the lost range. B cannot fetch, but it repairs the log with
/// a first chunk that holds its grant.
#[test]
fn device_with_a_lost_grant_repairs_the_log() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.cut_log(fx.tenant(), 2);
    let path = format!("{}/entries", fx.space_path(fx.tenant(), fx.log()));
    let r = fx
        .relay
        .handle(&fx.signed("GET", &path, "after=0&limit=10", b"", "B"));
    assert_eq!(error_code(&r), "unknown_device");
    // C has a grant nowhere, so the same entries do not make it active.
    let entries: Vec<(u64, String)> = (3..=4).map(|n| (n as u64, envelope(&fx, n))).collect();
    let body = wire::repair_start_body(&head_of(&fx, 2), &entries).unwrap();
    assert_eq!(
        error_code(&fx.post(fx.tenant(), "repair", &body, "C")),
        "unknown_device"
    );
    let (sid, _) = start(&fx, "B", head_of(&fx, 2), 3, 4);
    assert_eq!(finish(&fx, "B", sid, head_of(&fx, 4)), 200);
    let r = fx
        .relay
        .handle(&fx.signed("GET", &path, "after=0&limit=10", b"", "B"));
    assert_eq!(r.status, 200);
}

/// [LOG-11]: a staged stub is refused, because M3 has no snapshot that
/// covers it, and nothing is staged.
#[test]
fn staged_stub_is_refused() {
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    fx.cut_log(fx.tenant(), 3);
    let base = head_of(&fx, 3);
    let body = format!(
        r#"{{"base":{{"position":3,"digest":"{}"}},"entries":[{{"position":4,"stub":{{"type":"snailfish.change.v1","change_id":"c_{}","hash":"{}"}}}}]}}"#,
        encode_b64(&base.digest),
        "00".repeat(16),
        encode_b64(&[0; 32]),
    );
    let r = fx.post(fx.tenant(), "repair", body.as_bytes(), "A");
    assert_eq!((r.status, error_code(&r).as_str()), (422, "uncovered_stub"));
    let rep = ops::hold_report(fx.dir.path(), "sam", fx.log()).unwrap();
    assert_eq!(rep.repairs, [] as [snailfish_relay::ops::RepairRecord; 0]);
}

/// [STO-7], [STO-8], [STO-10], [LOG-14]: a backup while the relay runs, then
/// more appends, then a restore. The restored relay serves the old log on
/// hold, with the same tenant handle, and a deletion marker wins over a
/// restored space file.
#[test]
fn backup_and_restore_hold_each_space() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    let out = tempfile::TempDir::new().unwrap();
    let dst = out.path().join("b1");
    let sum = ops::backup(fx.dir.path(), &dst).unwrap();
    assert_eq!((sum.tenants, sum.spaces), (1, 1));
    assert!(
        ops::backup(fx.dir.path(), &dst).is_err(),
        "the target is not empty"
    );
    let change = fx.change("A", 4, [0x52; 16], 40, 2);
    assert_eq!(
        fx.append(fx.tenant(), "A", std::slice::from_ref(&change)).1,
        [AppendResult::Stored(5)]
    );

    // A running relay holds the serve lock, so restore refuses.
    let lock = ops::serve_lock(fx.dir.path()).unwrap();
    assert!(ops::restore(fx.dir.path(), &dst, true, 1).is_err());
    drop(lock);
    assert!(
        ops::restore(fx.dir.path(), &dst, false, 1).is_err(),
        "needs --replace"
    );
    let res = ops::restore(fx.dir.path(), &dst, true, 1).unwrap();
    assert_eq!(res.held, [fx.log().to_owned()]);
    fx.restart(common::limits_of(&fx.h));
    assert_eq!(fx.record_hashes(fx.tenant()).len(), 4, "the backup log");
    assert!(report(&fx, "A", head_of(&fx, 4), false), "on hold");
    assert_eq!(
        fx.append(fx.tenant(), "A", &[change]).1,
        [AppendResult::Refused("on_hold".into())]
    );

    // A deletion marker in the tenant file wins over the space file.
    let c = rusqlite::Connection::open(
        dst.join("tenants")
            .join(
                fx.tenant_db(fx.tenant())
                    .parent()
                    .unwrap()
                    .file_name()
                    .unwrap(),
            )
            .join("tenant.db"),
    )
    .unwrap();
    c.execute(
        "INSERT INTO deletion_markers (log_id) VALUES (?1)",
        [fx.log()],
    )
    .unwrap();
    drop(c);
    let res = ops::restore(fx.dir.path(), &dst, true, 2).unwrap();
    assert_eq!(res.held, [] as [std::string::String; 0]);
    fx.restart(common::limits_of(&fx.h));
    assert_eq!(error_code(&fx.fetch(fx.tenant(), 0, 10)), "unknown_space");
}

/// [STO-8]: while a backup holds its lock, the relay refuses space creation
/// and creates no space file.
#[test]
fn space_creation_waits_for_a_backup() {
    let fx = Fx::new();
    let lock =
        std::fs::File::create(fx.dir.path().join(snailfish_relay::core::BACKUP_LOCK)).unwrap();
    lock.lock().unwrap();
    let r = fx.put_genesis(fx.tenant());
    assert_eq!((r.status, error_code(&r).as_str()), (503, "backup_running"));
    drop(lock);
    assert_eq!(fx.put_genesis(fx.tenant()).status, 201);
}

/// [VER-14]: a schema 1 file from M2 opens and gains the M3 tables.
#[test]
fn schema_one_files_migrate_forward() {
    let mut fx = Fx::new();
    fx.setup_space(fx.tenant());
    for (path, table) in [
        (fx.tenant_db(fx.tenant()), "holds"),
        (fx.space_file(fx.tenant()), "staging"),
    ] {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(&format!("DROP TABLE {table}; PRAGMA user_version = 1;"))
            .unwrap();
    }
    fx.restart(common::limits_of(&fx.h));
    // The first request opens both files and migrates them.
    assert_eq!(fx.fetch(fx.tenant(), 0, 10).status, 200);
    fx.set_hold(fx.tenant(), true);
    assert!(report(&fx, "A", head_of(&fx, 4), false));
    fx.cut_log(fx.tenant(), 3);
    let (sid, _) = start(&fx, "A", head_of(&fx, 3), 4, 4);
    assert_eq!(finish(&fx, "A", sid, head_of(&fx, 4)), 200);
}

/// [LOG-11], PROTOCOL.md 10.9: a session expires at its start + 86,400
/// seconds exactly. A chunk one second before goes in.
#[test]
fn session_expires_at_the_exact_second() {
    use std::sync::atomic::Ordering;
    for (later, ok) in [(86_399, true), (86_400, false)] {
        let fx = Fx::new();
        fx.setup_space(fx.tenant());
        fx.cut_log(fx.tenant(), 2);
        let t0 = fx.now.load(Ordering::SeqCst);
        let (sid, _) = start(&fx, "A", head_of(&fx, 2), 3, 3);
        fx.now.store(t0 + later, Ordering::SeqCst);
        let chunk = wire::repair_chunk_body(&sid, &[(4, envelope(&fx, 4))]).unwrap();
        let r = fx.post(fx.tenant(), "repair/chunk", &chunk, "A");
        assert_eq!(
            r.status == 200,
            ok,
            "{later}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
}

/// PROTOCOL.md 8.6: a repair request runs steps 1 to 4 before the body
/// parse, so an expired request with a malformed body is `expired`.
#[test]
fn repair_checks_the_request_before_the_body() {
    use std::sync::atomic::Ordering;
    let fx = Fx::new();
    fx.setup_space(fx.tenant());
    let path = format!("{}/repair", fx.space_path(fx.tenant(), fx.log()));
    let now = fx.now.load(Ordering::SeqCst);
    let req = fx.signed_with("POST", &path, "", b"{", "A", [0x77; 16], now - 1000);
    assert_eq!(error_code(&fx.relay.handle(&req)), "expired");
}
