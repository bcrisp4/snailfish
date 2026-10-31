//! Engine tests through the public API, with the real relay core
//! (`snailfish_relay::core`) as the network and real SQLite files.
//!
//! Each conformance test cites its scenario in `specs/delivery/test.qnt` and
//! its rule IDs (specs/conformance.md). The expected results come from the
//! model scenario, not from this implementation.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{Connection, Transaction, TransactionBehavior};
use snailfish_relay::core::{Config, Relay, Request as RelayRequest};

use super::*;
use crate::setup::{NewDevice, create_space, install_setup, new_device_keys};

const AUTHORITY: &str = "sync.example.net";
const URL: &str = "https://sync.example.net";
const APP: &str = "com.example.tasks";

static RELAY_TIME: AtomicU64 = AtomicU64::new(1_767_225_600);

/// A relay on a temporary directory, with a clock that the test controls.
struct World {
    _dir: tempfile::TempDir,
    root: PathBuf,
    relay: Relay,
    tenant: String,
    log_id: String,
    keys: Vec<DeviceKeys>,
    // A relay fault for the next request: drop the response.
    lose_next: bool,
}

/// One device: its engine directory and its app state (a real app keeps
/// these in its own SQLite file; the tests keep them in memory and model a
/// restart by a new Engine on the same directory).
struct Dev {
    dir: PathBuf,
    applied: Applied,
    outbox: Vec<OutboxRow>,
    state: Vec<Vec<u8>>,
}

fn relay_config(root: &Path) -> Config {
    let mut cfg = Config::new(root.join("relay"), AUTHORITY);
    cfg.clock = Arc::new(|| RELAY_TIME.load(Ordering::SeqCst));
    cfg
}

impl World {
    /// A space with devices A and B: A holds the setup records.
    fn new() -> (Self, Dev, Dev) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let relay = Relay::open(relay_config(&root)).unwrap();
        let tenant = relay.add_user("sam").unwrap();
        let mut ka = new_device_keys().unwrap();
        let mut kb = new_device_keys().unwrap();
        let s = create_space(
            APP,
            &NewDevice {
                keys: ka.clone(),
                name: "A".into(),
            },
            &[NewDevice {
                keys: kb.clone(),
                name: "B".into(),
            }],
        )
        .unwrap();
        ka.app_key = s.app_key;
        kb.app_key = s.app_key;
        let w = Self {
            _dir: dir,
            root: root.clone(),
            relay,
            tenant,
            log_id: s.log_id.clone(),
            keys: vec![ka, kb],
            lose_next: false,
        };
        install_setup(&root.join("a"), w.space(), &w.keys[0], &s.envelopes).unwrap();
        let a = w.dev("a");
        let b = w.dev("b");
        (w, a, b)
    }

    fn space(&self) -> SpaceRef {
        SpaceRef {
            relay_url: URL.into(),
            tenant: self.tenant.clone(),
            log_id: self.log_id.clone(),
            app_id: APP.into(),
        }
    }

    fn dev(&self, name: &str) -> Dev {
        let log = decode_id::<16>(&self.log_id, "l_").unwrap();
        Dev {
            dir: self.root.join(name),
            applied: Applied {
                position: 0,
                digest: snailfish_protocol::hash::digest0(&log),
            },
            outbox: Vec::new(),
            state: Vec::new(),
        }
    }

    fn engine(&self, d: &Dev) -> Engine {
        let i = usize::from(d.dir.ends_with("b"));
        Engine::open(&d.dir, self.space(), &self.keys[i]).unwrap()
    }

    /// The host app loop of DESIGN.md "App integration", one exchange.
    fn exchange(&mut self, e: &mut Engine) {
        let mut s = e.start_sync();
        let mut n: u32 = 0;
        while let Some(req) = s.next_request(e).unwrap() {
            n = n.checked_add(1).unwrap();
            assert!(n < 100, "the exchange does not end");
            let url = req.url.strip_prefix(URL).unwrap();
            let (path, query) = url.split_once('?').unwrap_or((url, ""));
            let resp = self.relay.handle(&RelayRequest {
                method: req.method.clone(),
                path: path.into(),
                query: query.into(),
                headers: req
                    .headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect(),
                body: req.body.clone(),
            });
            if std::mem::take(&mut self.lose_next) {
                // The relay processed the request; the response is lost.
                // The exchange ends with a transport error, as in an app.
                return;
            }
            let headers = vec![Header {
                name: "snailfish-time".into(),
                value: resp.time.to_string(),
            }];
            s.handle_response(e, resp.status, &headers, &resp.body)
                .unwrap();
        }
    }

    /// The relay data directory.
    fn relay_data(&self) -> PathBuf {
        self.root.join("relay")
    }

    /// `snailfish-relay backup` while the relay runs.
    fn backup(&self, name: &str) -> PathBuf {
        let out = self.root.join(name);
        snailfish_relay::ops::backup(&self.relay_data(), &out).unwrap();
        out
    }

    /// `snailfish-relay restore`: the relay core opens files per request, so
    /// the same core serves the restored files.
    fn restore(&self, from: &Path) {
        snailfish_relay::ops::restore(&self.relay_data(), from, true, 1).unwrap();
    }

    /// The restore hold report of the space.
    fn hold(&self) -> snailfish_relay::ops::HoldReport {
        snailfish_relay::ops::hold_report(&self.relay_data(), "sam", &self.log_id).unwrap()
    }

    /// A storage fault: the relay log loses the entries after `n`, with no
    /// restore command and no hold.
    fn cut_relay(&self, n: i64) {
        let tenants = self.relay_data().join("tenants");
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
        c.execute("DELETE FROM entries WHERE position > ?1", [n])
            .unwrap();
        c.execute("DELETE FROM devices WHERE position > ?1", [n])
            .unwrap();
    }

    /// Fetch the relay log through the public route, as a device of the space.
    fn relay_change_ids(&mut self) -> Vec<Vec<u8>> {
        let tmp = tempfile::tempdir().unwrap();
        let mut e = Engine::open(tmp.path(), self.space(), &self.keys[1]).unwrap();
        self.exchange(&mut e);
        let mut out = Vec::new();
        let mut at = e.genesis_base();
        loop {
            let batch = e.changes_after(&at, 500).unwrap();
            let Some(last) = batch.last() else { break };
            at = Applied {
                position: last.position,
                digest: last.digest,
            };
            out.extend(batch.into_iter().map(|c| c.change_id));
        }
        out
    }
}

impl Dev {
    /// Edit: apply and write the outbox row in one app transaction ([DLV-2]).
    fn edit(&mut self, e: &Engine, bytes: &[u8]) -> Vec<u8> {
        let id = e.new_change_id().unwrap().to_vec();
        self.state.push(bytes.to_vec());
        self.outbox.push(OutboxRow {
            change_id: id.clone(),
            change_bytes: bytes.to_vec(),
        });
        id
    }

    fn enqueue(&mut self, e: &mut Engine) -> EnqueueResult {
        e.enqueue_many(&self.outbox).unwrap()
    }

    /// Pull ([DLV-10], [DLV-11]). Returns the number of changes applied.
    fn pull(&mut self, e: &Engine) -> Result<usize, EngineError> {
        let mut applied: usize = 0;
        loop {
            let batch = e.changes_after(&self.applied, 500)?;
            if batch.is_empty() {
                return Ok(applied);
            }
            for c in batch {
                if c.position <= self.applied.position {
                    continue;
                }
                if let Some(i) = self.outbox.iter().position(|r| r.change_id == c.change_id) {
                    self.outbox.remove(i);
                } else {
                    self.state.push(c.change_bytes);
                    applied = applied.checked_add(1).unwrap();
                }
                self.applied = Applied {
                    position: c.position,
                    digest: c.digest,
                };
            }
        }
    }
}

/// [DLV-1], [VER-14]: durable settings and the schema version.
#[test]
fn state_file_is_durable_and_versioned() {
    let (w, a, _) = World::new();
    let e = w.engine(&a);
    let mode: String =
        e.db.pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
    let sync: i64 =
        e.db.pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
    let version: i64 =
        e.db.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
    assert_eq!((mode.as_str(), sync, version), ("wal", 2, SCHEMA_VERSION));
}

#[test]
fn second_engine_on_one_directory_is_refused() {
    let (w, a, _) = World::new();
    let e = w.engine(&a);
    assert!(matches!(
        Engine::open(&a.dir, w.space(), &w.keys[0]),
        Err(EngineError::Locked)
    ));
    drop(e);
    assert!(Engine::open(&a.dir, w.space(), &w.keys[0]).is_ok());
}

/// The state file is bound to one device: other keys on the same
/// directory are refused, so one file never signs for two devices.
#[test]
fn state_file_refuses_other_keys() {
    let (w, a, _) = World::new();
    drop(w.engine(&a));
    assert!(matches!(
        Engine::open(&a.dir, w.space(), &w.keys[1]),
        Err(EngineError::Invalid(_))
    ));
}

/// [VER-15]: a downgrade fails with a clear error and does not change the file.
#[test]
fn newer_schema_is_refused_and_not_changed() {
    let (w, a, _) = World::new();
    drop(w.engine(&a));
    {
        let db = Connection::open(a.dir.join(STATE_FILE)).unwrap();
        db.pragma_update(None, "user_version", 7).unwrap();
    }
    let before = std::fs::read(a.dir.join(STATE_FILE)).unwrap();
    let err = Engine::open(&a.dir, w.space(), &w.keys[0]).err().unwrap();
    assert_eq!(err, EngineError::SchemaTooNew { found: 7 });
    assert_eq!(
        err.to_string(),
        format!(
            "the engine state file has schema version 7, and this engine knows {SCHEMA_VERSION}"
        )
    );
    assert_eq!(std::fs::read(a.dir.join(STATE_FILE)).unwrap(), before);
}

/// `specs/delivery/test.qnt::offlineEditsConvergeTest` (S3, [DLV-2],
/// [DLV-8], [DLV-10], [DLV-11], [MRG-1]): offline edits on two devices
/// converge, and no device applies its own edit again.
#[test]
fn offline_edits_converge() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    // A creates the space on the relay: genesis record and grant to B.
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(ea.verified_head().unwrap().position, 2);
    let mut eb = w.engine(&b);
    a.edit(&ea, b"a1");
    b.edit(&eb, b"b1");
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    assert_eq!((ea.outbox_len().unwrap(), eb.outbox_len().unwrap()), (0, 0));
    assert_eq!(a.pull(&ea).unwrap(), 1, "A applies only B's change");
    assert_eq!(b.pull(&eb).unwrap(), 1, "B applies only A's change");
    assert!(a.outbox.is_empty() && b.outbox.is_empty());
    let mut sa = a.state.clone();
    let mut sb = b.state.clone();
    sa.sort();
    sb.sort();
    assert_eq!(sa, sb);
    assert_eq!(sa, vec![b"a1".to_vec(), b"b1".to_vec()]);
}

/// `specs/delivery/test.qnt::retryAfterLostResponseTest` ([DLV-7],
/// [DLV-8], [WIR-6]): the relay stores the change and the response is lost.
/// The envelope stays in the outbox. The retry sends the same envelope, the
/// relay answers known, and the relay log holds the change once.
#[test]
fn retry_after_lost_response() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let id = a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let sent = state::pending(&mut ea, 10).unwrap()[0].envelope.clone();
    // Lose the response of the append: the 4th request of this exchange
    // (info, fetch, append).
    let mut s = ea.start_sync();
    for _ in 0..2 {
        let req = s.next_request(&mut ea).unwrap().unwrap();
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(&mut ea, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(req.method, "POST");
    let resp = w.relay.handle(&to_relay(&req));
    assert_eq!(resp.status, 200);
    drop(s);
    assert_eq!(
        ea.outbox_len().unwrap(),
        1,
        "the envelope stays until a fetch"
    );
    // A restart, then the next sync.
    drop(ea);
    let mut ea = w.engine(&a);
    assert_eq!(
        state::pending(&mut ea, 10).unwrap()[0].envelope,
        sent,
        "[DLV-7]: the same envelope"
    );
    w.exchange(&mut ea);
    assert_eq!(ea.outbox_len().unwrap(), 0);
    assert_eq!(w.relay_change_ids(), vec![id]);
    assert_eq!(
        a.pull(&ea).unwrap(),
        0,
        "an own change is not applied again"
    );
    assert_eq!(a.outbox, vec![]);
}

/// The `snailfish-time` header of a relay response ([WIR-7]).
fn time(resp: &snailfish_relay::core::Response) -> Vec<Header> {
    vec![Header {
        name: "snailfish-time".into(),
        value: resp.time.to_string(),
    }]
}

fn to_relay(req: &Request) -> RelayRequest {
    let url = req.url.strip_prefix(URL).unwrap();
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    RelayRequest {
        method: req.method.clone(),
        path: path.into(),
        query: query.into(),
        headers: req
            .headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect(),
        body: req.body.clone(),
    }
}

/// Run `n` request and response steps of one exchange through the relay.
fn steps(w: &World, e: &mut Engine, s: &mut Sync, n: usize) -> Vec<(Request, Vec<u8>)> {
    let mut out = Vec::new();
    for _ in 0..n {
        let req = s.next_request(e).unwrap().unwrap();
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(e, resp.status, &time(&resp), &resp.body)
            .unwrap();
        out.push((req, resp.body));
    }
    out
}

fn finish(w: &World, e: &mut Engine, s: &mut Sync) {
    while let Some(req) = s.next_request(e).unwrap() {
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(e, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
}

/// The old engine signs an append, then loses its state file before the
/// request reaches the relay. The new engine encrypts the change again with
/// `new_bytes`, and the old request reaches the relay after the first fetch
/// of the new engine. Returns the new engine and its exchange, just before
/// its append.
fn race_after_engine_loss(w: &mut World, a: &mut Dev, new_bytes: &[u8]) -> (Engine, Sync) {
    let mut ea = w.engine(a);
    w.exchange(&mut ea);
    let id = a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let mut s = ea.start_sync();
    steps(w, &mut ea, &mut s, 2);
    let old = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(old.method, "POST");
    drop(s);
    drop(ea);
    // Engine state loss: the keys stay (T14).
    for f in std::fs::read_dir(&a.dir).unwrap() {
        std::fs::remove_file(f.unwrap().path()).unwrap();
    }
    let mut ea = w.engine(a);
    let r = ea
        .enqueue_many(&[OutboxRow {
            change_id: id,
            change_bytes: new_bytes.to_vec(),
        }])
        .unwrap();
    assert_eq!((r.stored.len(), r.refused.len()), (1, 0));
    let mut s = ea.start_sync();
    steps(w, &mut ea, &mut s, 2);
    let late = w.relay.handle(&to_relay(&old));
    assert_eq!(late.status, 200, "the old append reaches the relay late");
    (ea, s)
}

/// [DLV-8], `specs/delivery/model.qnt` mutant `engineDropsOnAccept`: the
/// relay answers stored, and the exchange stops before the last fetch. The
/// envelope stays in the outbox, also after a restart, because only a fetch
/// shows the change in the verified log.
#[test]
fn stored_answer_keeps_the_envelope_until_a_fetch() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let mut s = ea.start_sync();
    let push = steps(&w, &mut ea, &mut s, 3);
    let (results, _) = snailfish_protocol::wire::parse_append_response(&push[2].1).unwrap();
    assert_eq!(
        results,
        vec![snailfish_protocol::wire::AppendResult::Stored(3)]
    );
    drop(s);
    drop(ea);
    let mut ea = w.engine(&a);
    assert_eq!(ea.outbox_len().unwrap(), 1);
    w.exchange(&mut ea);
    assert_eq!(ea.outbox_len().unwrap(), 0);
}

/// `specs/delivery/test.qnt::pushConflictTest` and
/// `conflictTreatedAsStoredTest` ([WIR-6], [DLV-6], [DLV-8], F4): the relay
/// holds the `change_id` with another record hash and answers conflict with
/// the original position, also after a lower size limit. The engine does
/// not refuse the change. The envelope stays until the last fetch shows the
/// same change bytes, and then the outbox is empty.
#[test]
fn conflict_with_same_bytes_is_stored() {
    let (mut w, mut a, _) = World::new();
    let (mut ea, mut s) = race_after_engine_loss(&mut w, &mut a, b"x");
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_change_bytes = 10;
    w.relay = Relay::open(cfg).unwrap();
    let push = steps(&w, &mut ea, &mut s, 1);
    assert_eq!(push[0].0.method, "POST");
    let (results, _) = snailfish_protocol::wire::parse_append_response(&push[0].1).unwrap();
    assert_eq!(
        results,
        vec![snailfish_protocol::wire::AppendResult::Conflict(3)]
    );
    // Between the answer and the fetch: not refused, envelope kept.
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(ea.outbox_len().unwrap(), 1);
    assert_eq!(
        ea.enqueue_many(&a.outbox).unwrap().refused,
        Vec::<Vec<u8>>::new()
    );
    finish(&w, &mut ea, &mut s);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(ea.outbox_len().unwrap(), 0);
    assert_eq!(
        a.pull(&ea).unwrap(),
        0,
        "the own change is not applied again"
    );
    assert_eq!(a.outbox, vec![]);
    assert_eq!(a.state, vec![b"x".to_vec()]);
}

/// [DLV-6], second clause: the record at the conflict position holds other
/// change bytes for the `change_id` (an app fault). The engine refuses the
/// change for ever and reports degraded, and `enqueue_many` gives it in
/// `refused`, so the app splits or reverts it.
#[test]
fn conflict_with_other_bytes_is_refused() {
    let (mut w, mut a, _) = World::new();
    let (mut ea, mut s) = race_after_engine_loss(&mut w, &mut a, b"y");
    finish(&w, &mut ea, &mut s);
    assert_eq!(
        ea.status(),
        Status::Degraded {
            cause: "refused: conflict".into()
        }
    );
    let id = a.outbox[0].change_id.clone();
    let refused = ea
        .enqueue_many(&[OutboxRow {
            change_id: id.clone(),
            change_bytes: b"y".to_vec(),
        }])
        .unwrap()
        .refused;
    assert_eq!(refused, vec![id]);
}

/// `specs/delivery/test.qnt::enqueueAfterLossTest` (F4, [DLV-5], [DLV-7]):
/// the relay stores a large change, the operator lowers the size limit, and
/// the engine state file is lost. `enqueue_many` stores the change again and
/// does not refuse it, and the relay log holds it once.
#[test]
fn enqueue_after_engine_loss_is_not_refused_for_size() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let id = a.edit(&ea, &[7; 300]);
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_change_bytes = 10;
    w.relay = Relay::open(cfg).unwrap();
    drop(ea);
    for f in std::fs::read_dir(&a.dir).unwrap() {
        std::fs::remove_file(f.unwrap().path()).unwrap();
    }
    let mut ea = w.engine(&a);
    assert_eq!(a.enqueue(&mut ea).refused, Vec::<Vec<u8>>::new());
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(a.enqueue(&mut ea).refused, Vec::<Vec<u8>>::new());
    assert_eq!(ea.outbox_len().unwrap(), 0);
    assert_eq!(w.relay_change_ids(), vec![id]);
}

/// `specs/delivery/test.qnt::refusedAtPushTest` ([DLV-9]): the relay
/// refuses a change for ever. The engine reports degraded, and
/// `enqueue_many` gives the change in `refused`, also after a restart.
#[test]
fn permanent_refusal_is_degraded_and_reported_again() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_change_bytes = 10;
    w.relay = Relay::open(cfg).unwrap();
    let id = a.edit(&ea, &[7; 100]);
    assert_eq!(
        a.enqueue(&mut ea).refused.len(),
        0,
        "F4: enqueue checks no size"
    );
    w.exchange(&mut ea);
    assert!(matches!(ea.status(), Status::Degraded { ref cause } if cause == "refused: too_large"));
    drop(ea);
    let mut ea = w.engine(&a);
    assert_eq!(a.enqueue(&mut ea).refused, vec![id]);
    w.exchange(&mut ea);
    assert!(matches!(ea.status(), Status::Degraded { .. }));
    assert_eq!(w.relay_change_ids(), Vec::<Vec<u8>>::new());
}

/// [DLV-5]: a known `change_id` with other bytes goes into `refused`, and a
/// second call with the same bytes has no effect.
#[test]
fn enqueue_dedupes_and_refuses_other_bytes() {
    let (w, _, _) = World::new();
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), w.space(), &w.keys[1]).unwrap();
    let row = |b: &[u8]| OutboxRow {
        change_id: vec![1; 16],
        change_bytes: b.to_vec(),
    };
    let r = e.enqueue_many(&[row(b"x")]).unwrap();
    assert_eq!((r.stored.len(), r.refused.len()), (1, 0));
    let r = e.enqueue_many(&[row(b"x")]).unwrap();
    assert_eq!((r.stored.len(), r.refused.len()), (0, 0));
    let r = e.enqueue_many(&[row(b"y")]).unwrap();
    assert_eq!(r.refused, vec![vec![1; 16]]);
    assert_eq!(e.outbox_len().unwrap(), 1);
    let too_many: Vec<OutboxRow> = (0..=MAX_ENQUEUE)
        .map(|i| OutboxRow {
            change_id: [u8::try_from(i % 256).unwrap(); 16].to_vec(),
            change_bytes: vec![],
        })
        .collect();
    assert!(matches!(
        e.enqueue_many(&too_many),
        Err(EngineError::Invalid(_))
    ));
    assert!(matches!(
        e.enqueue_many(&[OutboxRow {
            change_id: vec![1; 15],
            change_bytes: vec![]
        }]),
        Err(EngineError::Invalid(_))
    ));
}

/// `specs/delivery/test.qnt::restoredOwnEditReturnsTest` ([DLV-8],
/// [DLV-11]): an app database restore loses an own edit after enqueue. The
/// engine holds it, so the app gets it back through `changes_after`, once.
#[test]
fn restored_own_edit_returns() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"0");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    let backup = (a.applied, a.outbox.clone(), a.state.clone());
    a.edit(&ea, b"1");
    a.enqueue(&mut ea);
    (a.applied, a.outbox, a.state) = backup;
    w.exchange(&mut ea);
    assert_eq!(a.pull(&ea).unwrap(), 1);
    assert_eq!(a.state, vec![b"0".to_vec(), b"1".to_vec()]);
}

/// `specs/delivery/test.qnt::restoredPositionReplaysTest` ([DLV-10],
/// [DLV-11]): an app restore moves the applied position back. The app
/// applies the later changes again, and none twice.
#[test]
fn restored_position_replays() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut eb = w.engine(&b);
    a.edit(&ea, b"0");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    b.pull(&eb).unwrap();
    let backup = (b.applied, b.outbox.clone(), b.state.clone());
    a.edit(&ea, b"1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    w.exchange(&mut eb);
    b.pull(&eb).unwrap();
    (b.applied, b.outbox, b.state) = backup;
    assert_eq!(b.state, vec![b"0".to_vec()]);
    assert_eq!(b.pull(&eb).unwrap(), 1);
    assert_eq!(b.state, vec![b"0".to_vec(), b"1".to_vec()]);
}

/// [DLV-12]: an applied position with another digest raises
/// `ResetRequired`. So does a position after the end of a log that the
/// engine fetched to the relay head (F2).
#[test]
fn reset_required_on_wrong_digest_or_ahead_of_log() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"0");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    a.pull(&ea).unwrap();
    let head = a.applied;
    let mut wrong = head;
    wrong.digest[0] ^= 1;
    assert_eq!(
        ea.changes_after(&wrong, 10),
        Err(EngineError::ResetRequired)
    );
    let ahead = Applied {
        position: head.position + 1,
        digest: head.digest,
    };
    assert_eq!(
        ea.changes_after(&ahead, 10),
        Err(EngineError::ResetRequired)
    );
    // A new engine state file that has not fetched does not raise it.
    let tmp = tempfile::tempdir().unwrap();
    let fresh = Engine::open(tmp.path(), w.space(), &w.keys[0]).unwrap();
    assert_eq!(fresh.changes_after(&head, 10), Ok(vec![]));
}

/// [WIR-7]: the engine corrects its clock from `snailfish-time`. With a
/// device clock one hour slow, the first signed request has `created` at the
/// relay time, not the device time, and the relay accepts it.
#[test]
fn clock_offset_from_relay_time() {
    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    ea.set_clock(|| 1_767_225_600 - 3600);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    let req = s.next_request(&mut ea).unwrap().unwrap();
    let input = &req
        .headers
        .iter()
        .find(|h| h.name == "signature-input")
        .unwrap()
        .value;
    let (p, _) = snailfish_protocol::request::parse_signature_input(input).unwrap();
    assert_eq!(p.created, RELAY_TIME.load(Ordering::SeqCst));
    let resp = w.relay.handle(&to_relay(&req));
    assert!(resp.status < 300, "{}", String::from_utf8_lossy(&resp.body));
}

/// Without a relay time, the engine signs with its own clock.
#[test]
fn without_relay_time_the_device_clock_signs() {
    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    ea.set_clock(|| 1_000_000);
    let mut s = ea.start_sync();
    s.next_request(&mut ea).unwrap();
    let info =
        snailfish_protocol::wire::info_body(&[1], &snailfish_protocol::wire::Limits::default(), 1);
    s.handle_response(&mut ea, 200, &[], &info).unwrap();
    let req = s.next_request(&mut ea).unwrap().unwrap();
    let input = &req
        .headers
        .iter()
        .find(|h| h.name == "signature-input")
        .unwrap()
        .value;
    let (p, _) = snailfish_protocol::request::parse_signature_input(input).unwrap();
    assert_eq!((p.created, p.expires), (1_000_000, 1_000_300));
}

#[test]
fn wrong_authority_pauses() {
    let (mut w, a, _) = World::new();
    let mut sp = w.space();
    sp.relay_url = "https://other.example.net".into();
    let mut e = Engine::open(&a.dir, sp, &w.keys[0]).unwrap();
    let mut s = e.start_sync();
    let req = s.next_request(&mut e).unwrap().unwrap();
    let resp = w.relay.handle(&to_relay_any(&req));
    s.handle_response(&mut e, resp.status, &time(&resp), &resp.body)
        .unwrap();
    let req = s.next_request(&mut e).unwrap().unwrap();
    let resp = w.relay.handle(&to_relay_any(&req));
    assert_eq!(resp.status, 421);
    s.handle_response(&mut e, resp.status, &time(&resp), &resp.body)
        .unwrap();
    assert_eq!(e.status(), Status::RelayAuthority);
    assert_eq!(s.next_request(&mut e).unwrap(), None);
    w.lose_next = false;
}

fn to_relay_any(req: &Request) -> RelayRequest {
    let rest = req.url.split_once("://").unwrap().1;
    let i = rest.find('/').unwrap();
    let url = &rest[i..];
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    RelayRequest {
        method: req.method.clone(),
        path: path.into(),
        query: query.into(),
        headers: req
            .headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect(),
        body: req.body.clone(),
    }
}

/// A relay log that ends before the verified head with another digest than
/// the verified log stops sync with fork ([FRK-1]), and a proxy page is
/// `relay unavailable`.
#[test]
fn shorter_relay_log_with_another_digest_stops_and_proxy_page_pauses() {
    let (mut w, a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut s = ea.start_sync();
    s.next_request(&mut ea).unwrap();
    s.handle_response(&mut ea, 200, &[], b"<html>portal</html>")
        .unwrap();
    assert_eq!(ea.status(), Status::RelayUnavailable);
    let mut s = ea.start_sync();
    s.next_request(&mut ea).unwrap();
    s.handle_response(
        &mut ea,
        200,
        &[],
        &snailfish_protocol::wire::info_body(&[1], &snailfish_protocol::wire::Limits::default(), 1),
    )
    .unwrap();
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert!(req.url.contains("/entries?after=2&"));
    let empty = snailfish_protocol::wire::fetch_response(
        &[],
        &snailfish_protocol::wire::Head {
            position: 1,
            digest: [0; 32],
        },
        false,
        false,
    )
    .unwrap();
    s.handle_response(&mut ea, 200, &[], &empty).unwrap();
    assert!(matches!(ea.status(), Status::Fork { .. }));
}

/// [VER-11]: a relay whose info has a readable `levels` list without this
/// engine level stops sync with `relay too old`, also if the rest of the
/// info has another form. An unreadable info is `relay unavailable`.
#[test]
fn relay_without_engine_level_is_too_old() {
    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    for (body, want) in [
        (&br#"{"levels":[0]}"#[..], Status::RelayTooOld),
        (br#"{"levels":[0],"limits":{}}"#, Status::RelayTooOld),
        (br#"{"levels":"1"}"#, Status::RelayUnavailable),
        (br#"{"levels":[1]}"#, Status::RelayUnavailable),
    ] {
        let mut s = ea.start_sync();
        s.next_request(&mut ea).unwrap();
        s.handle_response(&mut ea, 200, &[], body).unwrap();
        assert_eq!(ea.status(), want, "{}", String::from_utf8_lossy(body));
        assert_eq!(s.next_request(&mut ea).unwrap(), None);
    }
}

/// A relay that answers each fetch with `has_more` and no entries does not
/// keep the app in a loop: the exchange ends with `relay unavailable`.
#[test]
fn empty_pages_with_has_more_end_the_exchange() {
    let (mut w, a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let head = ea.verified_head().unwrap();
    let mut s = ea.start_sync();
    s.next_request(&mut ea).unwrap();
    let info =
        snailfish_protocol::wire::info_body(&[1], &snailfish_protocol::wire::Limits::default(), 1);
    s.handle_response(&mut ea, 200, &[], &info).unwrap();
    let empty = snailfish_protocol::wire::fetch_response(
        &[],
        &snailfish_protocol::wire::Head {
            position: head.position,
            digest: head.digest,
        },
        true,
        false,
    )
    .unwrap();
    let mut fetches: u32 = 0;
    while let Some(req) = s.next_request(&mut ea).unwrap() {
        assert_eq!(req.method, "GET");
        fetches = fetches.checked_add(1).unwrap();
        assert!(fetches <= 10, "the exchange does not end");
        s.handle_response(&mut ea, 200, &[], &empty).unwrap();
    }
    assert_eq!(fetches, 3);
    assert_eq!(ea.status(), Status::RelayUnavailable);
}

/// An edit before the first sync of a new device: the engine has no
/// verified log, so it cannot sign the change with a base from position 1
/// ([LOG-6]). It signs the change after the first fetch, and the relay
/// stores it. The first sync of A also creates the space and appends the
/// grant to B in the setup phase, so B is active.
#[test]
fn edit_before_the_first_sync_is_signed_after_the_fetch() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    let mut eb = w.engine(&b);
    let id_b = b.edit(&eb, b"b-first");
    b.enqueue(&mut eb);
    let id_a = a.edit(&ea, b"a-first");
    a.enqueue(&mut ea);
    // B cannot sync before the space exists.
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(ea.outbox_len().unwrap(), 0);
    w.exchange(&mut eb);
    assert_eq!(eb.status(), Status::Ok);
    assert_eq!(eb.outbox_len().unwrap(), 0);
    let mut ids = w.relay_change_ids();
    ids.sort();
    let mut want = vec![id_a, id_b];
    want.sort();
    assert_eq!(ids, want);
    // Genesis, grant, and the two changes.
    assert_eq!(eb.verified_head().unwrap().position, 4);
}

/// The first sync appends the grant to B before any change of A, so a
/// change of A never names a base before the grant. The grant has its own
/// append request.
#[test]
fn first_sync_appends_the_grant_before_the_changes() {
    let (w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let mut s = ea.start_sync();
    let mut appends = Vec::new();
    while let Some(req) = s.next_request(&mut ea).unwrap() {
        if req.url.ends_with("/append") {
            let items = snailfish_protocol::wire::parse_append(&req.body, 100).unwrap();
            let types: Vec<String> = items
                .into_iter()
                .map(|i| i.unwrap().envelope.payload_type)
                .collect();
            appends.push(types);
        }
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(&mut ea, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
    assert_eq!(
        appends,
        vec![
            vec!["snailfish.grant.v1".to_owned()],
            vec!["snailfish.change.v1".to_owned()]
        ]
    );
}

/// A pending row with no envelope and no verified log is an API misuse,
/// not a silent skip: `pending` refuses it.
#[test]
fn pending_without_a_verified_log_is_refused() {
    let (w, _, _) = World::new();
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), w.space(), &w.keys[1]).unwrap();
    e.enqueue_many(&[OutboxRow {
        change_id: vec![1; 16],
        change_bytes: b"x".to_vec(),
    }])
    .unwrap();
    assert!(matches!(
        state::pending(&mut e, 10),
        Err(EngineError::Invalid(_))
    ));
}

/// The space write level comes from the genesis record ([VER-9]). The
/// engine keeps it in its state file and checks fetched grants against it.
#[test]
fn verified_log_keeps_the_genesis_write_level() {
    let (mut w, a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let tx = Transaction::new_unchecked(&ea.db, TransactionBehavior::Deferred).unwrap();
    let view = state::DbSpace {
        tx: &tx,
        log_id: ea.log_id,
    };
    assert_eq!(
        snailfish_protocol::space::SpaceView::write_level(&view),
        MAX_LEVEL
    );
    tx.execute("UPDATE space SET level = 7", []).unwrap();
    assert_eq!(snailfish_protocol::space::SpaceView::write_level(&view), 7);
}

/// T7: the relay head has the same position as the verified log but
/// another digest. The relay shows another log: `stopped: fork`. The same
/// digest is ok.
#[test]
fn relay_head_with_another_digest_stops() {
    let (mut w, a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let head = ea.verified_head().unwrap();
    for (flip, fork) in [(false, false), (true, true)] {
        let mut digest = head.digest;
        if flip {
            digest[0] ^= 1;
        }
        let body = snailfish_protocol::wire::fetch_response(
            &[],
            &snailfish_protocol::wire::Head {
                position: head.position,
                digest,
            },
            false,
            false,
        )
        .unwrap();
        let mut s = ea.start_sync();
        steps(&w, &mut ea, &mut s, 1);
        s.next_request(&mut ea).unwrap().unwrap();
        s.handle_response(&mut ea, 200, &[], &body).unwrap();
        assert_eq!(matches!(ea.status(), Status::Fork { .. }), fork);
    }
}

/// A relay that refuses a setup record for ever stops sync with
/// `stopped: fork`: the space cannot reach the state that the setup signed.
/// A `bad_base` answer for a setup record is transient.
#[test]
fn refused_setup_record_stops_and_bad_base_does_not() {
    for (code, stops) in [("not_active", true), ("bad_base", false)] {
        let (w, a, _) = World::new();
        let mut ea = w.engine(&a);
        let mut s = ea.start_sync();
        // info, create, fetch
        steps(&w, &mut ea, &mut s, 3);
        let req = s.next_request(&mut ea).unwrap().unwrap();
        assert_eq!(req.method, "POST", "the grant to B");
        let body = snailfish_protocol::wire::append_response(
            &[snailfish_protocol::wire::AppendResult::Refused(code.into())],
            &snailfish_protocol::wire::Head {
                position: 1,
                digest: [0; 32],
            },
        );
        s.handle_response(&mut ea, 200, &[], &body).unwrap();
        assert_eq!(matches!(ea.status(), Status::Fork { .. }), stops, "{code}");
    }
}

/// A `bad_base` answer for a change is transient ([LOG-6]): the change is
/// not refused and stays in the outbox. Any other refusal is permanent
/// ([DLV-9]).
#[test]
fn bad_base_for_a_change_is_not_a_refusal() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 2);
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(req.method, "POST");
    let body = snailfish_protocol::wire::append_response(
        &[snailfish_protocol::wire::AppendResult::Refused(
            "bad_base".into(),
        )],
        &snailfish_protocol::wire::Head {
            position: 2,
            digest: [0; 32],
        },
    );
    s.handle_response(&mut ea, 200, &[], &body).unwrap();
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(a.enqueue(&mut ea).refused, Vec::<Vec<u8>>::new());
    assert_eq!(ea.outbox_len().unwrap(), 1);
}

/// An append response with another number of results than envelopes is
/// a fault of the relay: `relay unavailable`, and nothing is refused.
#[test]
fn append_response_with_wrong_length_is_unreadable() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 2);
    s.next_request(&mut ea).unwrap().unwrap();
    let body = snailfish_protocol::wire::append_response(
        &[
            snailfish_protocol::wire::AppendResult::Refused("too_large".into()),
            snailfish_protocol::wire::AppendResult::Refused("too_large".into()),
        ],
        &snailfish_protocol::wire::Head {
            position: 2,
            digest: [0; 32],
        },
    );
    s.handle_response(&mut ea, 200, &[], &body).unwrap();
    assert_eq!(ea.status(), Status::RelayUnavailable);
    assert_eq!(a.enqueue(&mut ea).refused, Vec::<Vec<u8>>::new());
}

/// [WIR-7]: an `expired` answer makes the engine send the request once
/// more with a new signature from the corrected clock. A second `expired`
/// answer is `stopped: clock skew`.
#[test]
fn expired_is_retried_once_then_clock_skew() {
    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    let first = s.next_request(&mut ea).unwrap().unwrap();
    let expired = snailfish_protocol::wire::error_body("expired", "");
    s.handle_response(&mut ea, 401, &[], &expired).unwrap();
    assert_eq!(ea.status(), Status::Ok);
    let second = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(
        (second.method.as_str(), second.url.as_str()),
        (first.method.as_str(), first.url.as_str())
    );
    let sig = |r: &Request| {
        r.headers
            .iter()
            .find(|h| h.name == "signature")
            .unwrap()
            .value
            .clone()
    };
    assert_ne!(sig(&first), sig(&second), "a new nonce and signature");
    s.handle_response(&mut ea, 401, &[], &expired).unwrap();
    assert_eq!(ea.status(), Status::ClockSkew);
    assert_eq!(s.next_request(&mut ea).unwrap(), None);
}

/// A `space_exists` answer to the create request means that the relay
/// holds another genesis record for this log ID: `stopped: fork`.
#[test]
fn space_exists_is_a_fork() {
    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(req.method, "PUT");
    let body = snailfish_protocol::wire::error_body("space_exists", "");
    s.handle_response(&mut ea, 409, &[], &body).unwrap();
    assert!(matches!(ea.status(), Status::Fork { .. }));
}

/// A request with a body has `content-type: application/json`, and a
/// request without one has none. Each signed envelope names the device in
/// `keyid` ([LOG-2]: a writer sets it to the author ID).
#[test]
fn request_headers_and_envelope_keyid() {
    let (w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    let mut s = ea.start_sync();
    let mut seen = Vec::new();
    while let Some(req) = s.next_request(&mut ea).unwrap() {
        let ct = req
            .headers
            .iter()
            .any(|h| h.name == "content-type" && h.value == "application/json");
        seen.push((req.method.clone(), ct));
        if req.url.ends_with("/append") {
            let items = snailfish_protocol::wire::parse_append(&req.body, 100).unwrap();
            for raw in items.into_iter().flatten() {
                if raw.envelope.payload_type == "snailfish.change.v1" {
                    let v: serde_json::Value = serde_json::from_str(&raw.json).unwrap();
                    assert_eq!(v["signatures"][0]["keyid"], ea.device_id());
                }
            }
        }
        let resp = w.relay.handle(&to_relay(&req));
        s.handle_response(&mut ea, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
    assert!(seen.iter().all(|(m, ct)| *ct == (m != "GET")), "{seen:?}");
    assert!(seen.iter().any(|(m, _)| m == "POST"));
}

/// A fetched change whose `change_id` the verified log holds already is a
/// relay fault: `stopped: fork`, and nothing is stored.
#[test]
fn fetched_duplicate_change_id_stops() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"x");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    let head = ea.verified_head().unwrap();
    // Sign a second change with the same change_id at position 4.
    let cid: [u8; 16] = a.outbox[0].change_id.clone().try_into().unwrap();
    let base = snailfish_protocol::records::Position {
        position: head.position,
        digest: head.digest,
    };
    let payload =
        snailfish_protocol::write::change(&ea.log_id, &ea.device_id, &base, 1, &cid, &[0; 40]);
    let sig = ea.sign.sign_record("snailfish.change.v1", &payload);
    let env = snailfish_protocol::envelope::write_json("snailfish.change.v1", &payload, &sig, "k");
    let rh = snailfish_protocol::hash::record_hash("snailfish.change.v1", &payload, &sig);
    let digest = snailfish_protocol::hash::digest_next(
        &head.digest,
        head.position + 1,
        &snailfish_protocol::hash::entry_hash("snailfish.change.v1", Some(&cid), &rh),
    );
    let body = snailfish_protocol::wire::fetch_response(
        &[(head.position + 1, env)],
        &snailfish_protocol::wire::Head {
            position: head.position + 1,
            digest,
        },
        false,
        false,
    )
    .unwrap();
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    s.next_request(&mut ea).unwrap().unwrap();
    s.handle_response(&mut ea, 200, &[], &body).unwrap();
    assert!(matches!(ea.status(), Status::Fork { .. }));
    assert_eq!(ea.verified_head().unwrap(), head);
}

/// The engine checks a grant against the write level of the genesis
/// record ([VER-9]): a grant with a level below it is a relay fault.
#[test]
fn fetched_grant_below_the_write_level_stops() {
    let dir = tempfile::tempdir().unwrap();
    let ka = new_device_keys().unwrap();
    let kb = new_device_keys().unwrap();
    let mut setup = create_space(
        APP,
        &NewDevice {
            keys: ka.clone(),
            name: "A".into(),
        },
        &[NewDevice {
            keys: kb,
            name: "B".into(),
        }],
    )
    .unwrap();
    // Raise the genesis write level to 2 by hand: the engine writes level 1
    // grants, so the grant to B is below the write level.
    let g = snailfish_protocol::envelope::Envelope::parse(setup.envelopes[0].as_bytes()).unwrap();
    let text = String::from_utf8(g.payload).unwrap().replacen(
        "\"level\":1,\"device\"",
        "\"level\":2,\"device\"",
        1,
    );
    assert!(text.contains("\"level\":2,\"device\""));
    let secret_hint = &setup.recovery_key;
    let secret = snailfish_protocol::recovery::parse(secret_hint).unwrap();
    let (rs, _) = snailfish_protocol::recovery::derive(&secret);
    let rk = snailfish_protocol::sig::SecretKey::from_seed(&rs);
    let sig = rk.sign_record("snailfish.genesis.v1", text.as_bytes());
    setup.envelopes[0] = snailfish_protocol::envelope::write_json(
        "snailfish.genesis.v1",
        text.as_bytes(),
        &sig,
        "r",
    );
    let log = decode_id::<16>(&setup.log_id, "l_").unwrap();
    let mut view = snailfish_protocol::space::MemorySpace::new(log);
    let genv =
        snailfish_protocol::envelope::Envelope::parse(setup.envelopes[0].as_bytes()).unwrap();
    view.apply(&snailfish_protocol::space::check_genesis(&genv, &log, None).unwrap());
    // The grant's base digest is for the old genesis, so build the fetch
    // from the protocol view and check the engine refuses the record.
    let grant =
        snailfish_protocol::envelope::Envelope::parse(setup.envelopes[1].as_bytes()).unwrap();
    let v = snailfish_protocol::space::check_append(
        &view,
        &grant,
        snailfish_protocol::space::Mode::Verify,
    );
    assert!(
        matches!(v, snailfish_protocol::space::Verdict::Refused(_)),
        "{v:?}"
    );
    let _ = (dir, ka);
}

/// [VER-15]: a version 1 state file (M1) migrates forward to the current
/// schema and keeps its relay info.
#[test]
fn version_1_state_file_migrates() {
    let (w, _, _) = World::new();
    let tmp = tempfile::tempdir().unwrap();
    {
        let db = Connection::open(tmp.path().join(STATE_FILE)).unwrap();
        db.execute_batch(
            "CREATE TABLE relay_info (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL);
             INSERT INTO relay_info VALUES (1, x'7b7d');
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    let e = Engine::open(tmp.path(), w.space(), &w.keys[1]).unwrap();
    let v: i64 =
        e.db.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
    assert_eq!(v, SCHEMA_VERSION);
    let body: Vec<u8> =
        e.db.query_row("SELECT body FROM relay_info", [], |r| r.get(0))
            .unwrap();
    assert_eq!(body, b"{}");
    assert_eq!(e.outbox_len().unwrap(), 0);
}

/// [DLV-4]: `enqueue_many` takes exactly [`MAX_ENQUEUE`] rows.
#[test]
fn enqueue_takes_500_rows() {
    let (w, _, _) = World::new();
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::open(dir.path(), w.space(), &w.keys[1]).unwrap();
    let rows: Vec<OutboxRow> = (0..MAX_ENQUEUE)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            OutboxRow {
                change_id: id.to_vec(),
                change_bytes: vec![],
            }
        })
        .collect();
    assert_eq!(e.enqueue_many(&rows).unwrap().stored.len(), MAX_ENQUEUE);
}

/// The device keys never reach a log line: the `Debug` form shows none.
#[test]
fn device_keys_debug_hides_the_keys() {
    let k = DeviceKeys {
        sign_seed: [0xab; 32],
        seal_seed: [0xcd; 32],
        app_key: [0xef; 32],
    };
    assert_eq!(format!("{k:?}"), "DeviceKeys(..)");
}

/// The engine clock is the system time when no test sets it ([WIR-7]).
#[test]
fn system_time_is_the_wall_clock() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(system_time().abs_diff(now) <= 5);
}

#[test]
fn authority_is_the_signed_authority() {
    assert_eq!(
        sync::authority("https://Sync.Example.net"),
        "sync.example.net"
    );
    assert_eq!(sync::authority("https://h:443"), "h");
    assert_eq!(sync::authority("http://h:80"), "h");
    assert_eq!(sync::authority("http://h:8443"), "h:8443");
    assert_eq!(sync::authority("https://h:80"), "h:80");
}

/// The relay routes only `/v1/...` and the signature covers the path as
/// sent, so a relay URL with a path can never sync. Open refuses it.
#[test]
fn relay_url_with_a_path_is_refused() {
    let (w, a, _) = World::new();
    for bad in [
        "https://h/prefix",
        "https://h/prefix/",
        "https://h?x=1",
        "https://u@h",
        "ftp://h",
        "h",
        "https://",
    ] {
        let mut sp = w.space();
        sp.relay_url = bad.into();
        assert!(
            matches!(
                Engine::open(&a.dir, sp, &w.keys[0]),
                Err(EngineError::Invalid(_))
            ),
            "{bad}"
        );
    }
    let mut sp = w.space();
    sp.relay_url = format!("{URL}/");
    let mut e = Engine::open(&a.dir, sp, &w.keys[0]).unwrap();
    let req = e.start_sync().next_request(&mut e).unwrap().unwrap();
    assert_eq!(req.url, format!("{URL}/v1/info"));
}

/// `specs/delivery/test.qnt::refusedAtPushTest`, [DLV-9]: a change that no
/// append body can hold is refused for ever and reported as `degraded`. The
/// other changes go in batches that fit `max_request_bytes`, so no request
/// gets 413 (`PROTOCOL.md` 10.4).
#[test]
fn append_batches_fit_the_request_limit() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_request_bytes = 8_000;
    w.relay = Relay::open(cfg).unwrap();
    let small: Vec<Vec<u8>> = (0..6u8).map(|i| a.edit(&ea, &[i; 1_000])).collect();
    let big = a.edit(&ea, &[9; 7_000]);
    a.enqueue(&mut ea);

    let mut s = ea.start_sync();
    let mut appends = 0;
    while let Some(req) = s.next_request(&mut ea).unwrap() {
        assert!(req.body.len() <= 8_000, "a body over the limit");
        appends += usize::from(req.method == "POST");
        let resp = w.relay.handle(&to_relay(&req));
        assert_ne!(resp.status, 413);
        s.handle_response(&mut ea, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
    assert!(appends >= 2, "the changes need more than one request");
    assert!(matches!(ea.status(), Status::Degraded { ref cause } if cause == "refused: too_large"));
    assert_eq!(a.enqueue(&mut ea).refused, vec![big]);
    let mut on_relay = w.relay_change_ids();
    on_relay.sort();
    let mut want = small;
    want.sort();
    assert_eq!(on_relay, want);
}

/// The batch limits are exact: a body of exactly `max_request_bytes` and a
/// batch of exactly `max_append_envelopes` are valid (`PROTOCOL.md` 10.4).
/// Without this, a body one byte over the limit gets 413 at every sync, or
/// the engine sends more requests than it must.
#[test]
fn batch_limits_are_exact() {
    use sync::{Item, batch};
    let limits = |bytes: u64, count: u64| snailfish_protocol::wire::Limits {
        max_request_bytes: bytes,
        max_append_envelopes: count,
        ..snailfish_protocol::wire::Limits::default()
    };
    let change = |i: u8, len: usize| (Item::Change([i; 16]), "x".repeat(len));
    let shape = |b: &sync::Batches| b.iter().map(Vec::len).collect::<Vec<_>>();
    // `{"envelopes":[]}` is 16 bytes. Two envelopes of 10 bytes and a comma
    // fill 37 bytes exactly.
    let (b, big) = batch((0..3).map(|i| change(i, 10)).collect(), &limits(37, 100));
    assert_eq!((shape(&b), big), (vec![2, 1], vec![]));
    let (b, _) = batch((0..3).map(|i| change(i, 10)).collect(), &limits(36, 100));
    assert_eq!(shape(&b), vec![1, 1, 1]);
    for x in &b {
        let envs: Vec<String> = x.iter().map(|(_, e)| e.clone()).collect();
        assert!(snailfish_protocol::wire::append_body(&envs).len() <= 36);
    }
    // One envelope that fills the body exactly is sent. One byte more is
    // refused, and the next change still goes.
    let (b, big) = batch(
        vec![change(1, 21), change(2, 22), change(3, 5)],
        &limits(37, 100),
    );
    assert_eq!((shape(&b), big), (vec![1, 1], vec![[2; 16]]));
    // The count limit.
    let (b, _) = batch((0..5).map(|i| change(i, 1)).collect(), &limits(1_000, 2));
    assert_eq!(shape(&b), vec![2, 2, 1]);
    // A setup record that does not fit goes alone: the relay answer decides.
    let (b, big) = batch(
        vec![change(1, 5), (Item::Setup(2), "x".repeat(40)), change(3, 5)],
        &limits(37, 100),
    );
    assert_eq!((shape(&b), big), (vec![1, 1, 1], vec![]));
}

/// A 413 `too_large` answer is `degraded` (`PROTOCOL.md` 10.3), and a 422
/// `invalid_record` answer to the create request is `stopped: fork`.
#[test]
fn too_large_degrades_and_refused_genesis_stops() {
    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(req.method, "PUT");
    let body = snailfish_protocol::wire::error_body("invalid_record", "");
    s.handle_response(&mut ea, 422, &[], &body).unwrap();
    assert!(matches!(ea.status(), Status::Fork { .. }));

    let (w, a, _) = World::new();
    let mut ea = w.engine(&a);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    s.next_request(&mut ea).unwrap().unwrap();
    let body = snailfish_protocol::wire::error_body("too_large", "");
    s.handle_response(&mut ea, 413, &[], &body).unwrap();
    assert!(matches!(ea.status(), Status::Degraded { ref cause } if cause == "refused: too_large"));
}

/// `specs/spacelog/test.qnt::creatorHoldsGenesisTest`, [LOG-9]: the device
/// that made the space holds its genesis record from the setup. A relay
/// that answers the create request and then serves another genesis record
/// for the same log, with the same app and a valid signature, stops sync.
#[test]
fn relay_with_another_genesis_record_stops() {
    let (w, a, _) = World::new();
    let log = decode_id::<16>(&w.log_id, "l_").unwrap();
    let other = crate::setup::make_space(
        log,
        APP,
        &NewDevice {
            keys: new_device_keys().unwrap(),
            name: "X".into(),
        },
        &[],
    )
    .unwrap();
    let genesis = &other.envelopes[0];
    let env = snailfish_protocol::envelope::Envelope::parse(genesis.as_bytes()).unwrap();
    let digest = snailfish_protocol::space::check_genesis(&env, &log, None)
        .unwrap()
        .digest;
    let head = snailfish_protocol::wire::Head {
        position: 1,
        digest,
    };

    let mut ea = w.engine(&a);
    let mut s = ea.start_sync();
    steps(&w, &mut ea, &mut s, 1);
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert_eq!(req.method, "PUT");
    s.handle_response(
        &mut ea,
        201,
        &[],
        &snailfish_protocol::wire::head_body(&head),
    )
    .unwrap();
    let req = s.next_request(&mut ea).unwrap().unwrap();
    assert!(req.url.contains("/entries?after=0&"));
    let page =
        snailfish_protocol::wire::fetch_response(&[(1, genesis.clone())], &head, false, false)
            .unwrap();
    s.handle_response(&mut ea, 200, &[], &page).unwrap();
    assert!(
        matches!(ea.status(), Status::Fork { ref cause } if cause.contains("genesis")),
        "{:?}",
        ea.status()
    );
    assert_eq!(ea.verified_head().unwrap().position, 0);
}

#[test]
fn change_ids_differ() {
    let (w, a, _) = World::new();
    let e = w.engine(&a);
    assert_ne!(e.new_change_id().unwrap(), e.new_change_id().unwrap());
}

/// S6, `specs/delivery/test.qnt::relayRestoreRepairTest` ([LOG-10],
/// [LOG-11], [LOG-14], [LOG-15]): the operator restores a backup without
/// the last two changes. The hold keeps a new change of A in its outbox
/// (`paused: restore hold`). A repairs the log in a repair session and the
/// app learns of the repair. Both devices report, the operator releases the
/// hold, and the new change reaches the log. No change is lost or applied
/// twice.
#[test]
fn relay_restore_repair_and_release() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut eb = w.engine(&b);
    w.exchange(&mut eb);
    let backup = w.backup("b1");
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    b.edit(&eb, b"b1");
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    w.exchange(&mut ea);
    assert_eq!(ea.verified_head().unwrap().position, 4);
    assert_eq!(ea.take_repairs().unwrap(), [] as [Repair; 0]);
    w.restore(&backup);
    // One entry per request, so the repair needs a start and a chunk.
    let mut cfg = relay_config(&w.root);
    cfg.limits.max_append_envelopes = 1;
    w.relay = Relay::open(cfg).unwrap();

    a.edit(&ea, b"a2");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::RestoreHold);
    assert_eq!(
        ea.outbox_len().unwrap(),
        1,
        "the change waits in the outbox"
    );
    assert_eq!(ea.take_repairs().unwrap(), [Repair { first: 3, tip: 4 }]);
    assert!(ea.take_repairs().unwrap().is_empty(), "taken once");
    assert_eq!(w.hold().repairs.len(), 1, "one session with two requests");
    w.exchange(&mut eb);
    assert_eq!(eb.status(), Status::RestoreHold);
    assert!(eb.take_repairs().unwrap().is_empty(), "A repaired first");
    let rep = w.hold();
    assert_eq!(rep.head, 4);
    assert_eq!(rep.devices.len(), 2);
    assert!(
        rep.devices
            .iter()
            .all(|d| d.state == snailfish_relay::ops::TipState::Reported)
    );
    assert_eq!(rep.not_repaired(), [] as [&str; 0]);
    assert_eq!(rep.repairs.len(), 1);

    snailfish_relay::ops::release_hold(&w.relay_data(), "sam", &w.log_id, false).unwrap();
    w.exchange(&mut ea);
    assert_eq!(ea.status(), Status::Ok);
    assert_eq!(ea.outbox_len().unwrap(), 0);
    w.exchange(&mut eb);
    assert_eq!(a.pull(&ea).unwrap(), 1);
    assert_eq!(b.pull(&eb).unwrap(), 2);
    let mut sa = a.state.clone();
    let mut sb = b.state.clone();
    sa.sort();
    sb.sort();
    assert_eq!(sa, sb);
    assert_eq!(sa, [b"a1".to_vec(), b"a2".to_vec(), b"b1".to_vec()]);
}

/// `specs/delivery/test.qnt::notRepairedMarkTest` ([LOG-14], [LOG-15],
/// F3): B loses its engine state file during a hold. Its new engine fetches
/// during the hold and stays fresh, so the report marks B "not repaired".
/// `release-hold` refuses without `--force`. After the release, a fetch to
/// the relay head with no hold ends the fresh flag.
#[test]
fn new_engine_state_file_is_not_repaired_until_the_hold_ends() {
    let (mut w, a, b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut eb = w.engine(&b);
    w.exchange(&mut eb);
    let backup = w.backup("b1");
    w.restore(&backup);
    drop(eb);
    std::fs::remove_dir_all(&b.dir).unwrap();
    let mut eb = w.engine(&b);
    w.exchange(&mut eb);
    w.exchange(&mut eb);
    w.exchange(&mut ea);
    let rep = w.hold();
    assert_eq!(rep.not_repaired(), [eb.device_id().as_str()]);
    assert!(snailfish_relay::ops::release_hold(&w.relay_data(), "sam", &w.log_id, false).is_err());
    snailfish_relay::ops::release_hold(&w.relay_data(), "sam", &w.log_id, true).unwrap();
    w.exchange(&mut eb);
    assert_eq!(eb.status(), Status::Ok);
    // A second restore: B now reports a state file that is not new.
    w.restore(&backup);
    w.exchange(&mut eb);
    assert_eq!(w.hold().not_repaired(), [] as [&str; 0]);
}

/// `specs/delivery/test.qnt::forkStopsTest` ([FRK-1], [LOG-6], T7): a
/// silent relay rollback, then B appends two changes. The second change has
/// a base that is not in the verified log of A, so A stops with
/// `stopped: fork` and stores nothing.
#[test]
fn record_with_a_base_outside_the_verified_log_stops_with_fork() {
    let (mut w, mut a, mut b) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    let mut eb = w.engine(&b);
    w.exchange(&mut eb);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    assert_eq!(ea.verified_head().unwrap().position, 3);
    w.cut_relay(2);
    b.edit(&eb, b"b1");
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    b.edit(&eb, b"b2");
    b.enqueue(&mut eb);
    w.exchange(&mut eb);
    assert_eq!(eb.verified_head().unwrap().position, 4);
    let before = ea.verified_head().unwrap();
    w.exchange(&mut ea);
    match ea.status() {
        Status::Fork { cause } => assert!(cause.contains("bad_base"), "{cause}"),
        other => panic!("expected fork, got {other:?}"),
    }
    assert_eq!(ea.verified_head().unwrap(), before);
}

/// [WIR-2]: a fetched record with a bad signature changes no state: the
/// engine stops with fork and its verified log is the same.
#[test]
fn fetched_record_with_a_bad_signature_changes_no_state() {
    let (mut w, mut dev_a, dev_b) = World::new();
    let mut ea = w.engine(&dev_a);
    w.exchange(&mut ea);
    dev_a.edit(&ea, b"a1");
    dev_a.enqueue(&mut ea);
    w.exchange(&mut ea);
    let mut eb = w.engine(&dev_b);
    let mut s = eb.start_sync();
    let mut forged = false;
    while let Some(req) = s.next_request(&mut eb).unwrap() {
        let mut resp = w.relay.handle(&to_relay(&req));
        if req.url.contains("/entries?") && !forged {
            let body = String::from_utf8(resp.body).unwrap();
            // Flip one base64 character of the last signature.
            let i = body.rfind("\"sig\":\"").unwrap() + 7;
            let mut bytes = body.into_bytes();
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
            resp.body = bytes;
            forged = true;
        }
        s.handle_response(&mut eb, resp.status, &time(&resp), &resp.body)
            .unwrap();
    }
    assert!(matches!(eb.status(), Status::Fork { .. }));
    assert_eq!(eb.verified_head().unwrap().position, 0);
}

fn chunk_sizes(entries: &[(u64, String)], limits: &snailfish_protocol::wire::Limits) -> Vec<usize> {
    let base = snailfish_protocol::wire::Head {
        position: 9,
        digest: [7; 32],
    };
    crate::sync::repair_chunks(entries.to_vec(), &base, limits)
        .iter()
        .map(Vec::len)
        .collect()
}

/// [LOG-10], PROTOCOL.md 10.9: repair chunks hold at most
/// `max_append_envelopes` entries, and each body is at most
/// `max_request_bytes`, at the exact limits. A larger entry goes alone.
#[test]
fn repair_chunks_fit_the_limits_exactly() {
    use snailfish_protocol::wire::{self, Head, Limits};
    let base = Head {
        position: 9,
        digest: [7; 32],
    };
    let env = "{\"payloadType\":\"x\"}".to_owned();
    let entries: Vec<(u64, String)> = (10..15).map(|p| (p, env.clone())).collect();
    let mut l = Limits {
        max_append_envelopes: 2,
        ..Limits::default()
    };
    assert_eq!(chunk_sizes(&entries, &l), [2, 2, 1]);
    l.max_append_envelopes = 5;
    assert_eq!(chunk_sizes(&entries, &l), [5]);
    // The start body of exactly two entries fits; one byte less does not.
    let two = wire::repair_start_body(&base, &entries[..2]).unwrap().len();
    l.max_request_bytes = two as u64;
    let got = chunk_sizes(&entries, &l);
    assert_eq!(got[0], 2);
    l.max_request_bytes = two as u64 - 1;
    assert_eq!(chunk_sizes(&entries, &l)[0], 1);
    // Later chunks are chunk bodies: exactly two entries fit.
    let chunk_two = wire::repair_chunk_body(&[0; 16], &entries[2..4])
        .unwrap()
        .len();
    l.max_request_bytes = chunk_two.max(two) as u64;
    let sizes = chunk_sizes(&entries, &l);
    assert_eq!(sizes.iter().sum::<usize>(), 5);
    for (i, c) in crate::sync::repair_chunks(entries.clone(), &base, &l)
        .iter()
        .enumerate()
    {
        let len = if i == 0 {
            wire::repair_start_body(&base, c).unwrap().len()
        } else {
            wire::repair_chunk_body(&[0; 16], c).unwrap().len()
        };
        assert!(len as u64 <= l.max_request_bytes, "chunk {i}");
    }
    // An entry larger than the limit goes alone, for the relay allowance.
    l.max_request_bytes = 10;
    assert_eq!(chunk_sizes(&entries, &l), [1, 1, 1, 1, 1]);
}

/// [LOG-7] `specs/spacelog/test.qnt::concurrentGrantsTest`: the engine reads
/// the last security record of its verified log, which the base rule of
/// each fetched security record compares against. The log holds the
/// genesis record (1), the grant to B (2) and a change (3).
#[test]
fn verified_log_knows_its_last_security_record() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    assert_eq!(ea.verified_head().unwrap().position, 3);
    let tx = Transaction::new_unchecked(&ea.db, TransactionBehavior::Deferred).unwrap();
    let view = state::DbSpace {
        tx: &tx,
        log_id: ea.log_id,
    };
    assert_eq!(
        snailfish_protocol::space::SpaceView::last_security(&view),
        2
    );
}

/// [LOG-10]: the relay refuses a verified entry in a repair request, so the
/// two logs disagree and the engine stops with fork, with a repair cause.
/// The same code for a create names the genesis record.
#[test]
fn refused_repair_entry_stops_with_fork() {
    let (mut w, mut a, _) = World::new();
    let mut ea = w.engine(&a);
    w.exchange(&mut ea);
    a.edit(&ea, b"a1");
    a.enqueue(&mut ea);
    w.exchange(&mut ea);
    w.cut_relay(2);
    for code in ["uncovered_stub", "invalid_record"] {
        let mut s = ea.start_sync();
        while let Some(req) = s.next_request(&mut ea).unwrap() {
            let resp = w.relay.handle(&to_relay(&req));
            if req.url.ends_with("/repair") {
                let body = snailfish_protocol::wire::error_body(code, "");
                s.handle_response(&mut ea, 422, &time(&resp), &body)
                    .unwrap();
            } else {
                s.handle_response(&mut ea, resp.status, &time(&resp), &resp.body)
                    .unwrap();
            }
        }
        match ea.status() {
            Status::Fork { cause } => {
                assert!(cause.contains(&format!("repair entry: {code}")), "{cause}");
            }
            other => panic!("{code}: expected fork, got {other:?}"),
        }
    }
    let (w2, b2, _) = World::new();
    let mut eb = w2.engine(&b2);
    let mut s = eb.start_sync();
    while let Some(req) = s.next_request(&mut eb).unwrap() {
        if req.method == "PUT" {
            let body = snailfish_protocol::wire::error_body("invalid_record", "");
            s.handle_response(&mut eb, 422, &[], &body).unwrap();
        } else {
            let resp = w2.relay.handle(&to_relay(&req));
            s.handle_response(&mut eb, resp.status, &time(&resp), &resp.body)
                .unwrap();
        }
    }
    match eb.status() {
        Status::Fork { cause } => assert!(cause.contains("genesis"), "{cause}"),
        other => panic!("expected fork, got {other:?}"),
    }
}
