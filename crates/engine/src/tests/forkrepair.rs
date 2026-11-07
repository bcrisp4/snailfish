//! Space deletion, export, import and fork repair through the real engine
//! and relay (`PROTOCOL.md` 10.12, 10.13 and section 15, DESIGN.md "Fork
//! repair", `specs/forkrepair/test.qnt`). Each test names its model
//! scenario and rules (`specs/conformance.md`).

use super::*;
use crate::lifecycle::Import;

/// Run an import session through the relay until it ends.
fn run_import(w: &World, imp: &mut Import) -> Result<(), EngineError> {
    while let Some(req) = imp.next_request()? {
        let (status, headers, body) = w.send(&req);
        imp.handle_response(status, &headers, &body)?;
    }
    Ok(())
}

/// Send the deletion of `e` and read the answer.
fn delete(w: &World, e: &mut Engine) -> Result<(), EngineError> {
    let req = e.delete_request()?;
    let (status, headers, body) = w.send(&req);
    e.handle_delete_response(status, &headers, &body)
}

/// The URLs of one exchange of `e`.
fn urls(w: &mut World, e: &mut Engine) -> Vec<String> {
    let mut s = e.start_sync();
    let mut out = Vec::new();
    while let Some(req) = s.next_request(e).unwrap() {
        out.push(req.url.clone());
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(e, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
    out
}

/// Apply the reset of [DLV-12] in the test app: delete the synced data and
/// apply each outbox row again. The log has no snapshot.
fn reset(w: &World, d: &mut Dev) {
    d.state = d.outbox.iter().map(|r| r.change_bytes.clone()).collect();
    d.applied = w.dev("x").applied;
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

/// The fork of `specs/forkrepair/test.qnt::forked`: B writes X and applies
/// it back, the relay loses X, and A writes Y at the same position. B's
/// next sync stops with `fork` ([FRK-1]).
fn forked() -> (World, Dev, Dev, Engine, Engine, Vec<u8>) {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    let mut eb = w.engine(&b);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    let x = b.edit(&eb, b"X");
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    assert_eq!(b.pull(&eb).unwrap(), 0);
    assert!(b.outbox.is_empty(), "X came back, so its row is gone");
    w.cut_relay(2);
    a.edit(&ea, b"Y");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    w.exchange(&mut eb);
    assert!(
        matches!(eb.status(), Status::Fork { .. }),
        "{:?}",
        eb.status()
    );
    (w, a, b, ea, eb, x)
}

/// [FRK-1] to [FRK-8] (`repairTest`, `recoverTwiceTest`): A is the source.
/// It deletes the space and imports its log. B enrolls again with new keys,
/// gets X back from its old state file with the old change ID, sends it,
/// resets and pulls. Both apps hold X and Y once.
#[test]
fn fork_repair_restores_the_own_changes_of_each_device() {
    let (mut w, mut a, mut b, mut ea, eb, x) = forked();
    // FRK-4: A deletes the space. FRK-5: A imports its log.
    delete(&w, &mut ea).unwrap();
    assert_eq!(ea.status(), Status::Deleted);
    let token = w.sign_in(&w.keys[0]).token;
    let mut imp = ea.import_space(w.space(), &token).unwrap();
    // A refused import never reports the space as made, and the Debug
    // output names the step, not the setup token.
    assert!(!imp.finished());
    let dbg = format!("{imp:?}");
    assert!(dbg.contains("Import") && dbg.contains("step"), "{dbg}");
    assert!(!dbg.contains(&token), "{dbg}");
    // The target must name this log and this app.
    let mut other_app = w.space();
    other_app.app_id = "com.example.other".into();
    assert!(matches!(
        ea.import_space(other_app, &token),
        Err(EngineError::Invalid(_))
    ));
    run_import(&w, &mut imp).unwrap();
    assert!(imp.finished());
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    // FRK-6: B enrolls again from A, with new keys and a new state file.
    drop(eb);
    let old_keys = w.keys[1].clone();
    std::fs::rename(w.root.join("b"), w.root.join("b-old")).unwrap();
    w.keys[1] = new_device_keys().unwrap();
    let (te, ne) = w.enroll_b(&mut ea, None, (true, true));
    assert_eq!((te, ne), (EnrollState::Done, EnrollState::Done));
    let mut eb2 = Engine::open(&w.root.join("b"), w.space(), &w.keys[1]).unwrap();
    // Before its first exchange, the new verified log is not the relay
    // log, so the comparison refuses to run.
    let early = Engine::open(&w.root.join("b-old"), w.space(), &old_keys).unwrap();
    assert!(matches!(
        eb2.fork_changes(&early),
        Err(EngineError::Invalid(_))
    ));
    drop(early);
    w.exchange(&mut eb2);
    assert_eq!(eb2.status(), Status::Ok);
    // FRK-7: the comparison gives X with its old change ID.
    let old = Engine::open(&w.root.join("b-old"), w.space(), &old_keys).unwrap();
    let rows = eb2.fork_changes(&old).unwrap();
    assert_eq!(
        rows,
        vec![OutboxRow {
            change_id: x.clone(),
            change_bytes: b"X".to_vec()
        }]
    );
    // A second comparison after a crash gives the same rows, and the
    // engine stores nothing twice ([DLV-5]).
    assert_eq!(eb2.fork_changes(&old).unwrap(), rows);
    // FRK-8: outbox rows, enqueue, then ResetRequired.
    b.outbox.extend(rows.clone());
    assert_eq!(b.enqueue(&mut eb2).stored, vec![x.clone()]);
    assert_eq!(
        eb2.enqueue_many(&rows).unwrap().stored,
        Vec::<Vec<u8>>::new()
    );
    w.exchange(&mut eb2);
    assert_eq!(b.pull(&eb2), Err(EngineError::ResetRequired));
    reset(&w, &mut b);
    b.pull(&eb2).unwrap();
    assert_eq!(b.outbox, vec![]);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    assert_eq!(sorted(a.state.clone()), vec![b"X".to_vec(), b"Y".to_vec()]);
    assert_eq!(sorted(b.state.clone()), vec![b"X".to_vec(), b"Y".to_vec()]);
    // `relay_change_ids` reads with the keys of B, which hold the app key
    // after its first sync.
    w.keys[1].app_key = w.keys[0].app_key;
    let ids = w.relay_change_ids();
    assert_eq!(ids.iter().filter(|i| **i == x).count(), 1);
    assert_eq!(ids.len(), 2);
}

/// [LOG-13] (`deletedThenImportedTest`): a device that sees the deletion
/// marker stops with `deleted` and sends no append or repair. After the
/// import it syncs again with its own state file.
#[test]
fn deleted_space_stops_sync_until_the_import() {
    let (mut w, _a, mut b) = World::new();
    let mut ea = w.engine(&w.dev("a"));
    let mut eb = w.engine(&b);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    delete(&w, &mut ea).unwrap();
    b.edit(&eb, b"offline");
    b.enqueue(&mut eb);
    let sent = urls(&mut w, &mut eb);
    assert_eq!(eb.status(), Status::Deleted);
    assert!(
        sent.iter()
            .all(|u| !u.ends_with("/append") && !u.contains("/repair")),
        "{sent:?}"
    );
    let token = w.sign_in(&w.keys[0]).token;
    let mut imp = ea.import_space(w.space(), &token).unwrap();
    run_import(&w, &mut imp).unwrap();
    w.exchange(&mut eb);
    assert_eq!(eb.status(), Status::Ok);
    assert_eq!(
        eb.outbox_len().unwrap(),
        0,
        "the offline edit reached the imported log"
    );
}

/// [FRK-5]: a space moves to another relay through an import. Each other
/// device signs in on the new relay and syncs with its own state file.
#[test]
fn space_moves_to_another_relay() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"before the move");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    // The new relay, with its own data directory and tenant.
    let dir2 = tempfile::tempdir().unwrap();
    let relay2 = Relay::open(relay_config(dir2.path())).unwrap();
    let tenant2 = relay2.add_user("sam").unwrap();
    let old_relay = std::mem::replace(&mut w.relay, relay2);
    w.tenant = tenant2;
    let token = w.sign_in(&w.keys[0]).token;
    let mut imp = ea.import_space(w.space(), &token).unwrap();
    run_import(&w, &mut imp).unwrap();
    drop(ea);
    // Both devices open their engines on the new tenant handle.
    let mut ea = w.engine(&a);
    let mut eb = w.engine(&b);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    assert_eq!((ea.status(), eb.status()), (Status::Ok, Status::Ok));
    b.pull(&eb).unwrap();
    assert_eq!(b.state, vec![b"before the move".to_vec()]);
    b.edit(&eb, b"after the move");
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    assert!(a.state.contains(&b"after the move".to_vec()));
    drop(old_relay);
}

/// DESIGN.md "Data retention": after the loss of every device, a new
/// device imports the export file with the recovery key, and a full
/// recovery opens it (`PROTOCOL.md` 13.4).
#[test]
fn export_file_and_recovery_key_restore_a_lost_space() {
    let (mut w, mut a, _b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"kept");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    let file = ea.export_log().unwrap();
    let parsed = snailfish_protocol::export::parse(&file).unwrap();
    assert_eq!(
        parsed.header.head.position,
        ea.verified_head().unwrap().position
    );
    snailfish_protocol::export::check_log(&parsed).unwrap();
    drop(ea);
    // The relay loses the space, and each device is gone.
    assert!(w.relay.operator_delete("sam", &w.log_id).unwrap());
    let kc = new_device_keys().unwrap();
    let token = w.sign_in(&kc).token;
    let rk = w.recovery_key.clone();
    let mut imp = crate::lifecycle::import_file(&file, w.space(), &kc, &token, Some(&rk)).unwrap();
    run_import(&w, &mut imp).unwrap();
    assert!(imp.finished());
    let dir = w.root.join("c");
    let mut ec = Engine::open_recovery(&dir, w.space(), &kc, &rk, "C").unwrap();
    w.exchange(&mut ec);
    w.exchange(&mut ec);
    assert_eq!(ec.status(), Status::Ok);
    let mut c = w.dev("c");
    c.pull(&ec).unwrap();
    assert_eq!(c.state, vec![b"kept".to_vec()]);
}

/// [FRK-5]: an import of a file that the relay already holds fails with
/// `space_exists`, and a damaged file fails before any request.
#[test]
fn import_refusals_reach_the_app() {
    let (mut w, a, _b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let token = w.sign_in(&w.keys[0]).token;
    let mut imp = ea.import_space(w.space(), &token).unwrap();
    assert_eq!(
        run_import(&w, &mut imp),
        Err(EngineError::Refused {
            code: "space_exists".into()
        })
    );
    // A file of this log for another app, and a good file for another log.
    let good = ea.export_log().unwrap();
    let mut other_app = w.space();
    other_app.app_id = "com.example.other".into();
    assert!(matches!(
        crate::lifecycle::import_file(&good, other_app, &new_device_keys().unwrap(), &token, None),
        Err(EngineError::Invalid(_))
    ));
    let mut other_log = w.space();
    other_log.log_id = format!("l_{}", "00".repeat(16));
    assert!(matches!(
        crate::lifecycle::import_file(&good, other_log, &new_device_keys().unwrap(), &token, None),
        Err(EngineError::Invalid(_))
    ));
    let mut file = ea.export_log().unwrap();
    let n = file.len();
    file.truncate(n - 1);
    let kc = new_device_keys().unwrap();
    assert!(matches!(
        crate::lifecycle::import_file(&file, w.space(), &kc, &token, None),
        Err(EngineError::Invalid(_))
    ));
}

/// FRK-6: the key item of the old state file survives the enrollment, which
/// replaces the item of the log. `open_old` refuses a directory with no
/// state file, which would otherwise open with an empty log and give no
/// change back.
#[test]
fn old_keys_open_only_the_old_state_file() {
    let (w, a, _b) = World::new();
    let store = MemStore::new();
    crate::keystore::KeyStore::store(store.as_ref(), &w.log_id, &[7u8; 96]).unwrap();
    crate::keystore::keep_old_keys(store.as_ref(), &w.log_id).unwrap();
    crate::keystore::KeyStore::store(store.as_ref(), &w.log_id, &[8u8; 96]).unwrap();
    assert_eq!(
        store.item(&format!("{}.old", w.log_id)),
        Some(vec![7u8; 96])
    );
    let empty = w.root.join("empty");
    assert!(matches!(
        crate::keystore::open_old(&empty, w.space(), store.as_ref()),
        Err(EngineError::Invalid(_))
    ));
    assert!(!empty.join(crate::STATE_FILE).exists());
    drop(a);
}

/// FRK-7: before the checkpoint check of its first exchange, an enrolled
/// engine refuses the comparison, also when the app gave it the app key.
#[test]
fn comparison_waits_for_the_first_exchange() {
    let (w, a, b) = World::new();
    let ea = w.engine(&a);
    let eb = w.engine(&b);
    assert!(eb.app_key().is_some(), "World::new gives B the app key");
    assert!(matches!(eb.fork_changes(&ea), Err(EngineError::Invalid(_))));
}

/// 10.13 with the size rule of 10.9: each chunk body of an import fits
/// `max_request_bytes` and `max_append_envelopes`, and each chunk but the
/// last is full: the next entry does not fit. Without the exact overhead,
/// a start body passes the limit (`too_large`), or an import sends more
/// requests than it needs.
#[test]
fn import_chunks_are_full_and_fit_the_limits() {
    use snailfish_protocol::wire::{self, Limits, OutEntry, Stub};
    let token = [7u8; 32];
    let keys = new_device_keys().unwrap();
    let device = snailfish_protocol::records::Keys {
        sign: snailfish_protocol::sig::SecretKey::from_seed(&keys.sign_seed).public(),
        seal: Box::new(snailfish_protocol::keys::seal_public(&keys.seal_seed)),
    };
    let entries: Vec<(u64, OutEntry)> = (1..=40u64)
        .map(|p| {
            let cid = format!("c_{}", format!("{p:02x}").repeat(16));
            (
                p,
                OutEntry::Stub(Stub {
                    payload_type: "snailfish.change.v1".into(),
                    change_id: Some(cid),
                    hash: [1; 32],
                }),
            )
        })
        .collect();
    let start = wire::import_start_body(&token, &device, &[]).unwrap().len();
    let chunk = wire::repair_chunk_body(&[0; 16], &[]).unwrap().len();
    // A limit that 5 entries fill exactly: the fifth entry still fits, and
    // the sixth goes to the next chunk.
    let exact: usize = start
        + entries[..5]
            .iter()
            .map(|(p, e)| wire::entry_json(*p, e).unwrap().len() + 1)
            .sum::<usize>();
    let at_limit = Limits {
        max_request_bytes: exact as u64,
        max_append_envelopes: 100,
        ..Limits::default()
    };
    let got = crate::lifecycle::chunks(&entries, &at_limit, start, chunk).unwrap();
    assert_eq!(got[0].len(), 5);
    for (max, n_max) in [(start + 600, 100usize), (start + 3000, 7), (8192, 100)] {
        let limits = Limits {
            max_request_bytes: max as u64,
            max_append_envelopes: n_max as u64,
            ..Limits::default()
        };
        let got = crate::lifecycle::chunks(&entries, &limits, start, chunk).unwrap();
        let flat: Vec<u64> = got.iter().flatten().map(|(p, _)| *p).collect();
        assert_eq!(flat, (1..=40).collect::<Vec<_>>());
        let body = |i: usize, c: &[(u64, OutEntry)]| {
            if i == 0 {
                wire::import_start_body(&token, &device, c).unwrap().len()
            } else {
                wire::repair_chunk_body(&[0; 16], c).unwrap().len()
            }
        };
        let chunks: Vec<_> = got.iter().collect();
        for (i, c) in chunks.iter().enumerate() {
            assert_ne!(c.len(), 0);
            assert!(c.len() <= n_max);
            assert!(body(i, c) <= max, "chunk {i} of {max}: {}", body(i, c));
            if let Some(next) = chunks.get(i + 1) {
                let mut more = (*c).clone();
                more.push(next[0].clone());
                assert!(
                    body(i, &more) > max || c.len() == n_max,
                    "chunk {i} of {max} is not full"
                );
            }
        }
    }
}
