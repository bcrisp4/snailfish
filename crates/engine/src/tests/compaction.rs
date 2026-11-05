//! Log compaction through the real engine and relay (`PROTOCOL.md` section
//! 14, `specs/compaction/test.qnt`). Each test names its model scenario and
//! rules (`specs/conformance.md`).

use super::*;

/// The app state of a test device as snapshot bytes: each change, with a
/// 4-byte length before it ([CMP-2] `export_state`).
fn export(d: &Dev) -> Vec<u8> {
    let mut out = Vec::new();
    for c in &d.state {
        out.extend_from_slice(&u32::try_from(c.len()).unwrap().to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// [CMP-2] `can_import` and `import_state`: `None` if the bytes break the
/// format of `export`.
fn import(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (len, tail) = rest.split_at_checked(4)?;
        let n = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
        let (c, tail) = tail.split_at_checked(n)?;
        out.push(c.to_vec());
        rest = tail;
    }
    Some(out)
}

impl Dev {
    /// The app loop of DESIGN.md "Log compaction": the snapshot of the app
    /// state at the applied position, only with an empty outbox.
    fn write_snapshot(&self, e: &mut Engine) {
        assert!(
            self.outbox.is_empty(),
            "a snapshot needs an empty app outbox"
        );
        e.write_snapshot(&self.applied, &export(self)).unwrap();
    }

    /// Check each new snapshot with `can_import` ([CMP-5]).
    fn check_snapshots(e: &mut Engine) -> usize {
        let snaps = e.unchecked_snapshots().unwrap();
        for s in &snaps {
            e.accept_snapshot(s.position, import(&s.state_bytes).is_some())
                .unwrap();
        }
        snaps.len()
    }

    /// The reset of DESIGN.md "Log compaction" after `ResetRequired`
    /// ([CMP-14], [CMP-16], [DLV-12]).
    fn reset(&mut self, e: &Engine) {
        if let Some(s) = e.usable_snapshot().unwrap() {
            self.state = import(&s.state_bytes).unwrap();
            self.applied = Applied {
                position: s.state_position,
                digest: s.state_digest,
            };
        } else {
            self.state.clear();
            self.applied = e.genesis_base();
        }
        let rows = std::mem::take(&mut self.outbox);
        for r in rows {
            if !e.is_covered(&r.change_id).unwrap() {
                self.state.push(r.change_bytes.clone());
                self.outbox.push(r);
            }
        }
    }

    /// Pull, and reset first if the engine asks for it.
    fn pull_or_reset(&mut self, e: &Engine) -> bool {
        match self.pull(e) {
            Ok(_) => false,
            Err(EngineError::ResetRequired) => {
                self.reset(e);
                self.pull(e).unwrap();
                true
            }
            Err(other) => panic!("{other}"),
        }
    }
}

fn sorted(d: &Dev) -> Vec<Vec<u8>> {
    let mut s = d.state.clone();
    s.sort();
    s
}

/// The stub positions of the verified log of an engine.
fn local_stubs(e: &Engine) -> Vec<u64> {
    let head = e.verified_head().unwrap().position;
    state::log_range(&e.db, 1, head)
        .unwrap()
        .into_iter()
        .filter_map(|(p, x)| matches!(x, snailfish_protocol::wire::OutEntry::Stub(_)).then_some(p))
        .collect()
}

/// The stub positions of the relay log, read from its space file.
fn relay_stubs(w: &World) -> Vec<u64> {
    let tenants = w.relay_data().join("tenants");
    let t = std::fs::read_dir(tenants)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let f = std::fs::read_dir(t.join("spaces"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "db"))
        .unwrap();
    let c = Connection::open(f).unwrap();
    let mut st = c
        .prepare("SELECT position FROM entries WHERE envelope = '' ORDER BY position")
        .unwrap();
    st.query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .map(|p| u64::try_from(p.unwrap()).unwrap())
        .collect()
}

/// A and B, with two changes of A that both apply, then a snapshot of A
/// that both accept. Returns the devices with their engines.
fn compacted() -> (World, Dev, Engine, Dev, Engine) {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    let mut eb = w.engine(&b);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.edit(&ea, b"a2");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    w.exchange(&mut eb);
    b.pull(&eb).unwrap();
    a.write_snapshot(&mut ea);
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    w.exchange(&mut eb);
    assert_eq!(Dev::check_snapshots(&mut ea), 1);
    assert_eq!(Dev::check_snapshots(&mut eb), 1);
    w.exchange(&mut ea);
    assert!(
        relay_stubs(&w).is_empty(),
        "[CMP-6]: one accept is not enough"
    );
    w.exchange(&mut eb);
    w.exchange(&mut ea);
    (w, a, ea, b, eb)
}

/// `specs/compaction/test.qnt::compactTest` ([CMP-5], [CMP-6], [CMP-12],
/// [CMP-13]): after both accepts the relay replaces the changes at 3 and 4
/// with stubs. Each engine does the same after its app applies past the
/// frontier. Security, snapshot and accept records stay in full.
#[test]
fn accepted_snapshot_makes_stubs_on_the_relay_and_each_engine() {
    let (w, mut a, ea, mut b, eb) = compacted();
    // Positions: 1 genesis, 2 grant of B, 3 and 4 the changes, 5 the
    // snapshot, 6 and 7 the accepts.
    assert_eq!(relay_stubs(&w), [3, 4]);
    let s = ea.usable_snapshot().unwrap().unwrap();
    assert_eq!((s.position, s.state_position), (5, 4));
    assert!(local_stubs(&ea).is_empty(), "the engine waits for the app");
    a.pull(&ea).unwrap();
    b.pull(&eb).unwrap();
    assert_eq!(local_stubs(&ea), [3, 4]);
    assert_eq!(local_stubs(&eb), [3, 4]);
    assert_eq!(sorted(&a), sorted(&b));
}

/// `specs/compaction/test.qnt::newDeviceTest` ([CMP-16], [CMP-15], C4,
/// decision D9): a device with a new engine state file fetches pages of 2
/// entries, so the stubs at 3 and 4 come before the snapshot at 5. The stub
/// check waits for the relay head. The applied position 0 is before the
/// frontier, so the app imports the snapshot, then pulls the later change.
#[test]
fn new_device_imports_the_snapshot_and_pulls_the_rest() {
    let (mut w, mut a, mut ea, _b, _eb) = compacted();
    a.edit(&ea, b"a3");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_fetch_entries = 2;
    w.relay = Relay::open(cfg).unwrap();
    let mut fresh = w.dev("b2");
    let tmp = tempfile::tempdir().unwrap();
    let mut eb2 = Engine::open(tmp.path(), w.space(), &w.keys[1]).unwrap();
    w.exchange(&mut eb2);
    assert_eq!(eb2.status(), Status::Ok);
    assert_eq!(local_stubs(&eb2), [3, 4]);
    assert_eq!(
        eb2.changes_after(&fresh.applied, 10),
        Err(EngineError::ResetRequired)
    );
    assert!(fresh.pull_or_reset(&eb2));
    assert_eq!(fresh.applied.position, 8);
    a.pull(&ea).unwrap();
    assert_eq!(sorted(&fresh), sorted(&a));
}

/// `specs/compaction/test.qnt::offlineResetTest` ([CMP-14], [DLV-11],
/// [DLV-12], decision D10): B goes offline with an app DB backup from
/// before its own edit reached the relay. While B is offline, the relay
/// makes stubs. B restores the backup, makes one more edit, and syncs. The
/// reset imports the snapshot, drops the covered outbox row and keeps the
/// later edit.
#[test]
fn offline_device_keeps_its_outbox_edits() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    let mut eb = w.engine(&b);
    w.exchange(&mut ea);
    b.edit(&eb, b"b1");
    let backup = Dev {
        dir: b.dir.clone(),
        applied: b.applied,
        outbox: b.outbox.clone(),
        state: b.state.clone(),
    };
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    b.pull(&eb).unwrap();
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    a.write_snapshot(&mut ea);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    Dev::check_snapshots(&mut ea);
    Dev::check_snapshots(&mut eb);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    assert_eq!(relay_stubs(&w), [3]);
    // B restores its app DB and edits again while offline.
    b = backup;
    b.edit(&eb, b"b2");
    assert_eq!(b.outbox.len(), 2);
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    assert_eq!(eb.status(), Status::Ok);
    assert!(b.pull_or_reset(&eb), "the app DB is before the frontier");
    assert!(b.outbox.is_empty(), "b1 is covered, b2 came back");
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    assert_eq!(sorted(&a), sorted(&b));
    assert_eq!(sorted(&a), [b"b1".to_vec(), b"b2".to_vec()]);
}

/// `specs/compaction/test.qnt::unreadableTest` ([CMP-5]): a snapshot that
/// does not decrypt gets no accept, so every change stays in full.
#[test]
fn snapshot_that_does_not_decrypt_keeps_every_change() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    let mut eb = w.engine(&b);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    w.exchange(&mut eb);
    b.pull(&eb).unwrap();
    // A snapshot whose ciphertext is not an encryption of the AAD of 7.2.
    let head = ea.base().unwrap();
    let at = snailfish_protocol::records::Position {
        position: a.applied.position,
        digest: a.applied.digest,
    };
    let payload =
        snailfish_protocol::write::snapshot(&ea.log_id, &ea.device_id, &head, 1, &at, &[9; 48]);
    ea.add_record_for_test(&payload);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    assert_eq!(Dev::check_snapshots(&mut eb), 0);
    assert!(
        matches!(eb.status(), Status::Degraded { ref cause } if cause.contains("does not decrypt"))
    );
    assert_eq!(Dev::check_snapshots(&mut ea), 0);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    assert_eq!(relay_stubs(&w), Vec::<u64>::new());
    assert_eq!(ea.usable_snapshot().unwrap(), None);
}

/// `specs/compaction/test.qnt::removalTest` ([CMP-4], [CMP-7], [CMP-9]):
/// B never accepts. A removes B, so the snapshot of A is accepted at the
/// removal, and the relay makes stubs. The removal makes `snapshot_due`
/// true on A.
#[test]
fn removal_of_the_blocking_device_ends_the_block() {
    let (mut w, mut a, b) = World::new();
    let mut ea = w.engine(&a);
    let eb = w.engine(&b);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    assert!(!ea.snapshot_due().unwrap());
    a.write_snapshot(&mut ea);
    w.exchange(&mut ea);
    Dev::check_snapshots(&mut ea);
    w.exchange(&mut ea);
    assert!(relay_stubs(&w).is_empty(), "B blocks compaction");
    ea.remove_devices(&[eb.device_id()]).unwrap();
    w.exchange(&mut ea);
    w.exchange(&mut ea);
    assert_eq!(relay_stubs(&w), [3]);
    assert!(ea.snapshot_due().unwrap(), "[CMP-9]");
}

/// [CMP-9] [CMP-10]: a removal goes before a queued snapshot in the same
/// exchange, so the relay refuses the snapshot with `wrong_epoch`. The
/// engine drops it with no `degraded`, and `snapshot_due` asks for a new
/// snapshot with the new key.
#[test]
fn snapshot_after_a_newer_epoch_is_dropped() {
    let (mut w, mut a, b) = World::new();
    let mut ea = w.engine(&a);
    let eb = w.engine(&b);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    a.write_snapshot(&mut ea);
    ea.remove_devices(&[eb.device_id()]).unwrap();
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(crate::compact::pending_records(&ea.db).unwrap(), vec![]);
    assert!(ea.snapshot_due().unwrap());
    a.write_snapshot(&mut ea);
    w.exchange(&mut ea);
    assert_eq!(Dev::check_snapshots(&mut ea), 1);
}

/// [CMP-3], decision D12: a state larger than `max_snapshot_bytes` of the
/// relay writes no snapshot and sets `degraded`.
#[test]
fn snapshot_over_the_relay_limit_is_not_written() {
    let (mut w, mut a, _b) = World::new();
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_snapshot_bytes = 4096;
    w.relay = Relay::open(cfg).unwrap();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    ea.write_snapshot(&a.applied, &[1; 2000]).unwrap();
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(crate::compact::pending_records(&ea.db).unwrap().len(), 1);
    w.exchange(&mut ea);
    ea.write_snapshot(&a.applied, &[1; 5000]).unwrap();
    assert!(matches!(ea.status(), Status::Degraded { ref cause } if cause.contains("4096")));
    assert_eq!(crate::compact::pending_records(&ea.db).unwrap(), vec![]);
}

/// `specs/compaction/test.qnt::repairStubsTest` ([LOG-11], [CMP-17]): the
/// relay goes back to position 2. A repairs the log with its stubs, and the
/// relay holds the stubs again.
#[test]
fn repair_uploads_stubs() {
    let (mut w, mut a, mut ea, mut b, eb) = compacted();
    a.pull(&ea).unwrap();
    b.pull(&eb).unwrap();
    assert_eq!(local_stubs(&ea), [3, 4]);
    w.cut_relay(2);
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(ea.take_repairs().unwrap(), [Repair { first: 3, tip: 7 }]);
    assert_eq!(relay_stubs(&w), [3, 4]);
}

/// [CMP-15]: a relay that sends a stub that no usable snapshot covers stops
/// the engine with `missing records`, also at a later sync.
#[test]
fn uncovered_stub_stops_the_engine() {
    let (mut w, mut a, _b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    // The relay drops the envelope of the change at 3 with no snapshot.
    let tenants = w.relay_data().join("tenants");
    let t = std::fs::read_dir(tenants)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let f = std::fs::read_dir(t.join("spaces"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "db"))
        .unwrap();
    Connection::open(f)
        .unwrap()
        .execute("UPDATE entries SET envelope = '' WHERE position = 3", [])
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut eb2 = Engine::open(tmp.path(), w.space(), &w.keys[1]).unwrap();
    w.exchange(&mut eb2);
    assert_eq!(eb2.status(), Status::MissingRecords);
    let mut eb2 = {
        drop(eb2);
        Engine::open(tmp.path(), w.space(), &w.keys[1]).unwrap()
    };
    w.exchange(&mut eb2);
    assert_eq!(eb2.status(), Status::MissingRecords);
}

/// One exchange with no limit on the number of requests, for the SLO case.
fn exchange_all(w: &World, e: &mut Engine) {
    let mut s = e.start_sync();
    while let Some(req) = s.next_request(e).unwrap() {
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(e, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
}

/// DESIGN.md "SLOs" (M8): the first sync of a new device from one 10 MiB
/// snapshot with 1,000 changes and 100,000 stubs takes under 2 minutes.
/// It measures a wall clock, so it is not part of the test runs. Run:
/// `cargo test -p snailfish-engine --release -- --ignored --nocapture first_sync_slo`.
#[test]
#[ignore = "benchmark of the M8 first-sync SLO, about 1 minute in release mode"]
fn first_sync_slo() {
    // SLO_SCALE divides the counts, for a quick run of the same steps.
    let scale: usize = std::env::var("SLO_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let (mut w, dev_a, dev_b) = World::new();
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_append_envelopes = 1000;
    w.relay = Relay::open(cfg).unwrap();
    let mut ea = w.engine(&dev_a);
    exchange_all(&w, &mut ea);
    let eb_id = w.engine(&dev_b).device_id();
    ea.remove_devices(&[eb_id]).unwrap();
    exchange_all(&w, &mut ea);
    let clock = std::time::Instant::now();
    let push = |ea: &mut Engine, n: usize, tag: &str| {
        let rows: Vec<OutboxRow> = (0..n)
            .map(|i| OutboxRow {
                change_id: ea.new_change_id().unwrap().to_vec(),
                change_bytes: format!("{tag}-{i}").into_bytes(),
            })
            .collect();
        for chunk in rows.chunks(MAX_ENQUEUE) {
            ea.enqueue_many(chunk).unwrap();
        }
        exchange_all(&w, ea);
        assert_eq!(ea.outbox_len().unwrap(), 0);
    };
    push(&mut ea, 100_000 / scale, "old");
    println!("pushed: {:.1} s", clock.elapsed().as_secs_f64());
    let head = ea.verified_head().unwrap();
    ea.changes_after(&head, 1).unwrap();
    ea.write_snapshot(&head, &vec![7; 10 << 20]).unwrap();
    exchange_all(&w, &mut ea);
    let snaps = ea.unchecked_snapshots().unwrap();
    assert_eq!(snaps.len(), 1);
    ea.accept_snapshot(snaps[0].position, true).unwrap();
    exchange_all(&w, &mut ea);
    push(&mut ea, 1000 / scale, "new");
    println!("setup: {:.1} s", clock.elapsed().as_secs_f64());

    let tmp = tempfile::tempdir().unwrap();
    let start = std::time::Instant::now();
    let mut fresh = Engine::open(tmp.path(), w.space(), &w.keys[0]).unwrap();
    exchange_all(&w, &mut fresh);
    let fetched = start.elapsed();
    assert_eq!(fresh.status(), Status::Ok);
    assert_eq!(
        fresh.changes_after(&fresh.genesis_base(), 1),
        Err(EngineError::ResetRequired)
    );
    let snap = fresh.usable_snapshot().unwrap().unwrap();
    let mut at = Applied {
        position: snap.state_position,
        digest: snap.state_digest,
    };
    let mut count = 0;
    loop {
        let batch = fresh.changes_after(&at, MAX_BATCH).unwrap();
        let Some(last) = batch.last() else { break };
        count += batch.len();
        at = Applied {
            position: last.position,
            digest: last.digest,
        };
    }
    let total = start.elapsed();
    assert_eq!((snap.state_bytes.len(), count), (10 << 20, 1000 / scale));
    assert_eq!(local_stubs(&fresh).len(), 100_000 / scale);
    println!(
        "first sync: fetch and verify {:.1} s, total with the import and 1,000 changes {:.1} s",
        fetched.as_secs_f64(),
        total.as_secs_f64()
    );
    assert!(total < std::time::Duration::from_secs(120), "{total:?}");
}
