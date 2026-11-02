//! The shared test vectors through the exported functions of the binding
//! crate (DESIGN.md M1). Each export forwards to `snailfish_engine::codec`, so
//! these tests cover both layers. The Python and Swift tests run the same
//! checks across the FFI.
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish as codec;
use snailfish::{Envelope, PayloadClass};

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    ::hex::decode(v.as_str().unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn log_chain_signatures_and_key_sets() {
    let p = load("protocol.json");
    let mut seeds = std::collections::BTreeMap::new();
    let mut seal = std::collections::BTreeMap::new();
    for d in p["devices"].as_array().unwrap() {
        let pk = codec::sign_public_key(&hex(&d["sign_seed"])).unwrap();
        // A seal key of the wrong size names no device. The error text
        // reaches the app, so it must name the field.
        let err = codec::device_id(&pk, &[0; 1215]).unwrap_err();
        assert_eq!(err.to_string(), "seal_pk must be 1216 bytes");
        let engine_err = snailfish_engine::codec::device_id(&pk, &[0; 1215]).unwrap_err();
        assert_eq!(engine_err.to_string(), "seal_pk must be 1216 bytes");
        let spk = codec::seal_public_key(&hex(&d["seal_seed"])).unwrap();
        assert_eq!(codec::device_id(&pk, &spk).unwrap(), s(&d["id"]));
        seeds.insert(s(&d["name"]).to_owned(), pk);
        seal.insert(s(&d["id"]).to_owned(), hex(&d["seal_seed"]));
    }
    for r in p["recovery"].as_array().unwrap() {
        let secret = codec::recovery_parse(s(&r["display"])).unwrap();
        let derived = codec::recovery_derive(&secret).unwrap();
        let pk = codec::sign_public_key(&derived[0]).unwrap();
        let spk = codec::seal_public_key(&derived[1]).unwrap();
        assert_eq!(codec::recovery_id(&pk, &spk).unwrap(), s(&r["id"]));
        seeds.insert(s(&r["name"]).to_owned(), pk);
        seal.insert(s(&r["id"]).to_owned(), derived[1].clone());
    }
    let log = &p["log"];
    let mut digest = codec::digest0(s(&log["log_id"])).unwrap();
    let mut opened = 0;
    for e in log["entries"].as_array().unwrap() {
        let env = codec::parse_envelope(s(&e["envelope"]).as_bytes()).unwrap();
        assert!(codec::verify_record(
            &seeds[s(&e["signer"])],
            &env.payload_type,
            &env.payload,
            &env.sig
        ));
        // [WIR-1]: the signature of another record does not verify.
        let mut bad_sig = env.sig.clone();
        bad_sig[0] ^= 1;
        assert!(!codec::verify_record(
            &seeds[s(&e["signer"])],
            &env.payload_type,
            &env.payload,
            &bad_sig
        ));
        let info = codec::check_payload(&env.payload_type, &env.payload).unwrap();
        assert_eq!(info.log, s(&log["log_id"]));
        let rh = codec::record_hash(&env.payload_type, &env.payload, &env.sig).unwrap();
        assert_eq!(rh, hex(&e["record_hash"]));
        let eh = codec::entry_hash(&env.payload_type, &info.change_id, &rh).unwrap();
        assert_eq!(eh, hex(&e["entry_hash"]));
        digest = codec::digest_next(&digest, e["position"].as_u64().unwrap(), &eh).unwrap();
        assert_eq!(digest, hex(&e["digest"]));
        assert_eq!(
            codec::envelope_to_json(&env, &info.author).unwrap(),
            s(&e["envelope"])
        );
        for ks in &info.key_sets {
            let keys = codec::open_key_set(
                &seal[&ks.to],
                s(&log["log_id"]),
                &ks.to,
                &ks.epochs,
                &ks.sealed,
            )
            .unwrap();
            assert_eq!(keys.len(), ks.epochs.len());
            for (epoch, key) in ks.epochs.iter().zip(keys) {
                assert_eq!(key, hex(&log["app_keys"][epoch.to_string()]));
                let c = codec::key_commitment(s(&log["log_id"]), *epoch, &key).unwrap();
                assert_eq!(c, hex(&log["commitments"][epoch.to_string()]));
            }
            opened += 1;
        }
        if matches!(
            env.payload_type.as_str(),
            "snailfish.change.v1" | "snailfish.snapshot.v1"
        ) {
            let epoch = if e["name"] == "change-epoch-2" {
                "2"
            } else {
                "1"
            };
            let plain = codec::decrypt_payload(
                &hex(&log["app_keys"][epoch]),
                &env.payload_type,
                &env.payload,
            )
            .unwrap();
            let c = p["ciphertexts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["entry"] == e["position"])
                .unwrap();
            assert_eq!(plain, hex(&c["plaintext"]));
        }
    }
    assert_eq!(opened, p["key_sets"].as_array().unwrap().len());
}

#[test]
fn envelopes_strict_json_and_recovery_keys() {
    let p = load("protocol.json");
    for e in p["envelopes"].as_array().unwrap() {
        let r = codec::parse_envelope(s(&e["envelope"]).as_bytes());
        assert_eq!(r.is_ok(), e["valid"].as_bool().unwrap(), "{}", e["name"]);
        if let Ok(Envelope {
            payload_type,
            payload,
            sig,
        }) = r
        {
            assert_eq!(
                codec::record_hash(&payload_type, &payload, &sig).unwrap(),
                hex(&e["record_hash"])
            );
        }
    }
    for c in load("strict-json.json")["cases"].as_array().unwrap() {
        let bytes = c["payload"]
            .as_str()
            .map_or_else(|| hex(&c["payload_hex"]), |t| t.as_bytes().to_vec());
        let r = codec::check_payload(s(&c["payload_type"]), &bytes);
        assert_eq!(r.is_ok(), c["valid"].as_bool().unwrap(), "{}", c["name"]);
    }
    let r = load("recovery-key.json");
    for c in r["valid"].as_array().unwrap() {
        assert_eq!(
            codec::recovery_parse(s(&c["text"])).unwrap(),
            hex(&c["secret"])
        );
    }
    for c in r["invalid"].as_array().unwrap() {
        assert!(
            codec::recovery_parse(s(&c["text"])).is_err(),
            "{}",
            c["name"]
        );
    }
    assert_eq!(
        codec::classify("snailfish.grant.v2"),
        PayloadClass::UpdateRequired
    );
}

#[test]
fn cctv_ed25519() {
    let v = load("third_party/cctv-ed25519.json");
    let all = v.as_array().unwrap();
    assert_eq!(all.len(), 914);
    for t in all {
        let flags: Vec<&str> = t["flags"]
            .as_array()
            .map(|f| f.iter().map(s).collect())
            .unwrap_or_default();
        let expected = flags
            .iter()
            .all(|f| *f == "low_order_component_A" || *f == "low_order_component_R");
        let ok = codec::ed25519_verify(&hex(&t["key"]), s(&t["msg"]).as_bytes(), &hex(&t["sig"]));
        assert_eq!(ok, expected, "vector {}", t["number"]);
    }
}

#[test]
fn frames_statements_and_recovery_display() {
    let p = load("protocol.json");
    for f in p["frames"].as_array().unwrap() {
        let parts: Vec<Vec<u8>> = f["parts"].as_array().unwrap().iter().map(hex).collect();
        assert_eq!(codec::frame(&parts), hex(&f["frame"]));
    }
    for st in p["statements"].as_array().unwrap() {
        let env = codec::parse_envelope(s(&st["envelope"]).as_bytes()).unwrap();
        codec::check_statement(&env.payload_type, &env.payload).unwrap();
        assert!(codec::check_statement(&env.payload_type, b"{}").is_err());
    }
    for r in p["recovery"].as_array().unwrap() {
        assert_eq!(
            codec::recovery_display(&hex(&r["secret"])).unwrap(),
            s(&r["display"])
        );
    }
}

/// A key store in memory, as a host app implements it. `fail` makes each
/// call fail, as the keychain does without its entitlement.
#[derive(Default)]
struct MemStore {
    items: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    fail: bool,
}

impl MemStore {
    fn shared() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// The stored app key: the last 32 bytes of the item.
    fn app_key(&self, account: &str) -> Option<Vec<u8>> {
        let items = self.items.lock().unwrap();
        items.get(account).map(|b| b[64..].to_vec())
    }
}

impl snailfish::KeyStore for MemStore {
    fn load(&self, account: String) -> Result<Option<Vec<u8>>, snailfish::KeyStoreError> {
        if self.fail {
            return Err(snailfish::KeyStoreError::Failed {
                message: "errSecMissingEntitlement".into(),
            });
        }
        Ok(self.items.lock().unwrap().get(&account).cloned())
    }

    fn store(&self, account: String, secret: Vec<u8>) -> Result<(), snailfish::KeyStoreError> {
        if self.fail {
            return Err(snailfish::KeyStoreError::Failed {
                message: "errSecMissingEntitlement".into(),
            });
        }
        self.items.lock().unwrap().insert(account, secret);
        Ok(())
    }
}

fn space(log_id: &str, tenant: &str) -> snailfish::SpaceRef {
    snailfish::SpaceRef {
        relay_url: "https://sync.example.net".into(),
        tenant: tenant.into(),
        log_id: log_id.into(),
        app_id: "com.example.tasks".into(),
    }
}

/// Send each request of one exchange to the relay core, as a host app does.
fn exchange(relay: &snailfish_relay::core::Relay, engine: &std::sync::Arc<snailfish::Engine>) {
    let sync = engine.clone().start_sync().unwrap();
    while let Some(req) = sync.next_request().unwrap() {
        let url = req.url.strip_prefix("https://sync.example.net").unwrap();
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let resp = relay.handle(&snailfish_relay::core::Request {
            method: req.method,
            path: path.into(),
            query: query.into(),
            headers: req.headers.into_iter().map(|h| (h.name, h.value)).collect(),
            body: req.body,
        });
        let time = vec![snailfish::Header {
            name: "snailfish-time".into(),
            value: resp.time.to_string(),
        }];
        sync.handle_response(resp.status, &time, &resp.body)
            .unwrap();
    }
}

/// One request to the relay core, as the host app sends it.
/// The native sign-in of `PROTOCOL.md` 12.2 and 12.3 through the binding,
/// against the real relay core. The relay issues the code for the challenge,
/// in place of the browser approval. A marshalling fault in `SignIn` or
/// `SetupToken` fails here ([USR-4], [USR-5]).
fn sign_in(relay: &snailfish_relay::core::Relay, keys: &snailfish::DeviceKeys) -> String {
    let redirect = "com.example.tasks:/cb";
    let si = snailfish::SignIn::new("https://sync.example.net", redirect).unwrap();
    let url = si.authorize_url();
    let (_, query) = url.split_once('?').unwrap();
    let field = |k: &str| {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(&format!("{k}=")))
            .unwrap()
            .to_owned()
    };
    let code = relay
        .issue_code("sam", &field("code_challenge"), redirect)
        .unwrap();
    let back = format!("{redirect}?code={code}&state={}", field("state"));
    let req = si
        .token_request(&back, keys, snailfish_relay::core::system_time())
        .unwrap();
    let (status, headers, body) = send(relay, req);
    let t = si.read_token(status, &headers, &body).unwrap();
    assert!(t.token.starts_with("st_"));
    t.token
}

fn send(
    relay: &snailfish_relay::core::Relay,
    req: snailfish::Request,
) -> (u16, Vec<snailfish::Header>, Vec<u8>) {
    let url = req.url.strip_prefix("https://sync.example.net").unwrap();
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let resp = relay.handle(&snailfish_relay::core::Request {
        method: req.method,
        path: path.into(),
        query: query.into(),
        headers: req.headers.into_iter().map(|h| (h.name, h.value)).collect(),
        body: req.body,
    });
    let time = vec![snailfish::Header {
        name: "snailfish-time".into(),
        value: resp.time.to_string(),
    }];
    (resp.status, time, resp.body)
}

/// Run an enrollment through the binding objects until both sides end.
/// Each side answers the code comparison with its value of `answers`.
fn drive(
    relay: &snailfish_relay::core::Relay,
    t: &snailfish::TrustedEnrollment,
    n: &snailfish::NewEnrollment,
    answers: (bool, bool),
) {
    use snailfish::EnrollState as S;
    let end = |s: &S| matches!(s, S::Done | S::Failed { .. });
    for _ in 0..400 {
        let (ts, ns) = (t.state().unwrap(), n.state().unwrap());
        if end(&ts) && end(&ns) {
            return;
        }
        if matches!(ts, S::Compare { .. }) {
            t.confirm(answers.0).unwrap();
        }
        if matches!(ns, S::Compare { .. }) {
            n.confirm(answers.1).unwrap();
        }
        if let Some(req) = t.next_request().unwrap() {
            let (st, h, b) = send(relay, req);
            t.handle_response(st, &h, &b).unwrap();
        }
        if let Some(req) = n.next_request().unwrap() {
            let (st, _, b) = send(relay, req);
            n.handle_response(st, &b).unwrap();
        }
    }
    panic!("the enrollment does not end");
}

/// The engine object through the binding: setup, the directory lock, an
/// enrollment of B where B shows the session, a change from A to B
/// through the real relay core, and the status variants. A marshalling
/// fault in any record or enrollment state fails here ([ENR-1] to
/// [ENR-9]).
#[test]
fn engine_object_syncs_two_devices() {
    let dir = tempfile::tempdir().unwrap();
    let relay = snailfish_relay::core::Relay::open(snailfish_relay::core::Config::new(
        dir.path().join("relay"),
        "sync.example.net",
    ))
    .unwrap();
    let tenant = relay.add_user("sam").unwrap();
    let mut ka = snailfish::new_device_keys().unwrap();
    let kb = snailfish::new_device_keys().unwrap();
    let dev = |k: &snailfish::DeviceKeys, n: &str| snailfish::NewDevice {
        keys: k.clone(),
        name: n.into(),
    };
    let setup = snailfish::create_space("com.example.tasks", &dev(&ka, "A")).unwrap();
    let short_seed = snailfish::DeviceKeys {
        sign_seed: vec![1; 31],
        ..ka.clone()
    };
    assert!(matches!(
        snailfish::create_space("com.example.tasks", &dev(&short_seed, "A")),
        Err(snailfish::SnailfishError::Invalid { .. })
    ));
    assert_eq!(setup.envelopes.len(), 1);
    assert!(codec::recovery_parse(&setup.recovery_key).is_ok());
    ka.app_key.clone_from(&setup.app_key);
    let sp = space(&setup.log_id, &tenant);
    let pa = dir.path().join("a");
    let pa = pa.to_str().unwrap();
    // A store failure crosses the binding with its cause (C62).
    let failing = std::sync::Arc::new(MemStore {
        fail: true,
        ..MemStore::default()
    });
    let err = snailfish::Engine::open(pa, sp.clone(), failing)
        .err()
        .unwrap();
    assert!(
        matches!(&err, snailfish::SnailfishError::KeyStore { message } if message.contains("errSecMissingEntitlement")),
        "{err:?}"
    );
    let sa = MemStore::shared();
    snailfish::install_setup(
        pa,
        sp.clone(),
        &ka,
        &setup.envelopes,
        &sign_in(&relay, &ka),
        sa.clone(),
    )
    .unwrap();
    let a = std::sync::Arc::new(snailfish::Engine::open(pa, sp.clone(), sa.clone()).unwrap());
    let locked = snailfish::Engine::open(pa, sp.clone(), sa.clone())
        .err()
        .unwrap();
    assert!(matches!(locked, snailfish::SnailfishError::Locked));
    assert_eq!(
        locked.to_string(),
        "another engine uses this data directory"
    );
    exchange(&relay, &a);
    assert_eq!(a.status().unwrap(), snailfish::Status::Ok);
    assert_eq!(sa.app_key(&setup.log_id), Some(setup.app_key.clone()));

    let ne = snailfish::NewEnrollment::new("https://sync.example.net", &kb, "B", None).unwrap();
    let payload = ne.payload().unwrap().unwrap();
    assert_eq!(codec::enroll_parse_payload(&payload).unwrap().role, "n");
    assert_eq!(ne.relay_url().unwrap(), "https://sync.example.net");
    assert_eq!(ne.code().unwrap().len(), 39);
    let te = snailfish::TrustedEnrollment::new(a.clone(), Some(payload), None).unwrap();
    assert_eq!(te.payload().unwrap(), None);
    assert_eq!(te.code().unwrap(), Some(ne.code().unwrap()));
    drive(&relay, &te, &ne, (true, true));
    assert_eq!(te.state().unwrap(), snailfish::EnrollState::Done);
    assert_eq!(ne.state().unwrap(), snailfish::EnrollState::Done);
    assert_eq!(a.verified_head().unwrap().position, 2);
    assert_eq!(a.grants_to_confirm().unwrap(), Vec::<String>::new());
    assert!(matches!(
        a.confirm_grant(&a.device_id().unwrap(), None),
        Err(snailfish::SnailfishError::Invalid { .. })
    ));
    let joined = ne.joined().unwrap().unwrap();
    assert_eq!(
        (joined.tenant.as_str(), joined.position),
        (tenant.as_str(), 2)
    );
    assert_eq!(joined.digest, a.verified_head().unwrap().digest);
    let pb = dir.path().join("b");
    let pb = pb.to_str().unwrap();
    let sb = MemStore::shared();
    let mut bad = joined.clone();
    bad.digest = vec![0; 31];
    assert!(matches!(
        snailfish::install_enrollment(pb, sp.clone(), &kb, &bad, sb.clone()),
        Err(snailfish::SnailfishError::Invalid { .. })
    ));
    snailfish::install_enrollment(pb, sp.clone(), &kb, &joined, sb.clone()).unwrap();
    let b = std::sync::Arc::new(snailfish::Engine::open(pb, sp, sb.clone()).unwrap());
    // B gets the app key from its grant after the checkpoint check, and the
    // engine writes it to B's key store.
    assert_eq!(sb.app_key(&setup.log_id), Some(vec![0; 32]));
    exchange(&relay, &b);
    assert_eq!(sb.app_key(&setup.log_id), Some(setup.app_key.clone()));
    change_reaches_b(&relay, &a, &b);
}

/// A change of A reaches B through the relay, and the reset rule of
/// `changes_after` crosses the binding ([DLV-10], [DLV-12]).
fn change_reaches_b(
    relay: &snailfish_relay::core::Relay,
    a: &std::sync::Arc<snailfish::Engine>,
    b: &std::sync::Arc<snailfish::Engine>,
) {
    let id = a.new_change_id().unwrap();
    assert_eq!(id.len(), 16);
    let r = a
        .enqueue_many(&[snailfish::OutboxRow {
            change_id: id.clone(),
            change_bytes: b"rename".to_vec(),
        }])
        .unwrap();
    assert_eq!((r.stored, r.refused), (vec![id.clone()], vec![]));
    assert_eq!(a.outbox_len().unwrap(), 1);
    exchange(relay, a);
    assert_eq!(a.outbox_len().unwrap(), 0);
    exchange(relay, b);
    let base = b.genesis_base().unwrap();
    assert_eq!((base.position, base.digest.len()), (0, 32));
    let got = b.changes_after(&base, 500).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].position, &got[0].change_id, &got[0].change_bytes[..]),
        (3, &id, &b"rename"[..])
    );
    let at = snailfish::Applied {
        position: got[0].position,
        digest: got[0].digest.clone(),
    };
    assert_eq!(b.changes_after(&at, 500).unwrap(), vec![]);
    let mut wrong = at;
    wrong.digest[0] ^= 1;
    assert!(matches!(
        b.changes_after(&wrong, 500),
        Err(snailfish::SnailfishError::ResetRequired)
    ));
    assert_ne!(a.device_id().unwrap(), b.device_id().unwrap());
}

/// [ENR-7] through the binding: a code mismatch on the new device ends
/// both sides with `Failed`, and A appends no grant.
#[test]
fn enrollment_mismatch_through_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let relay = snailfish_relay::core::Relay::open(snailfish_relay::core::Config::new(
        dir.path().join("relay"),
        "sync.example.net",
    ))
    .unwrap();
    let tenant = relay.add_user("sam").unwrap();
    let mut ka = snailfish::new_device_keys().unwrap();
    let setup = snailfish::create_space(
        "com.example.tasks",
        &snailfish::NewDevice {
            keys: ka.clone(),
            name: "A".into(),
        },
    )
    .unwrap();
    ka.app_key.clone_from(&setup.app_key);
    let sp = space(&setup.log_id, &tenant);
    let pa = dir.path().join("a");
    let pa = pa.to_str().unwrap();
    let sa = MemStore::shared();
    snailfish::install_setup(
        pa,
        sp.clone(),
        &ka,
        &setup.envelopes,
        &sign_in(&relay, &ka),
        sa.clone(),
    )
    .unwrap();
    let a = std::sync::Arc::new(snailfish::Engine::open(pa, sp, sa.clone()).unwrap());
    exchange(&relay, &a);
    let te = snailfish::TrustedEnrollment::new(a.clone(), None, None).unwrap();
    assert_eq!(te.payload().unwrap(), None, "no payload before the open");
    let (st, h, b) = send(&relay, te.next_request().unwrap().unwrap());
    te.handle_response(st, &h, &b).unwrap();
    let kb = snailfish::new_device_keys().unwrap();
    let ne =
        snailfish::NewEnrollment::new("https://sync.example.net", &kb, "B", te.payload().unwrap())
            .unwrap();
    drive(&relay, &te, &ne, (true, false));
    assert!(matches!(
        te.state().unwrap(),
        snailfish::EnrollState::Failed { .. }
    ));
    assert!(matches!(
        ne.state().unwrap(),
        snailfish::EnrollState::Failed { .. }
    ));
    assert_eq!(ne.joined().unwrap(), None);
    exchange(&relay, &a);
    assert_eq!(a.verified_head().unwrap().position, 1);
}

/// `vectors/enroll.json` through the exported enrollment functions
/// (`PROTOCOL.md` 11.1 and 11.2). The Python and Swift tests run the same
/// cases across the FFI.
#[test]
fn enroll_vectors_through_the_binding() {
    let v = load("enroll.json");
    for c in v["codes"].as_array().unwrap() {
        let session = codec::enroll_parse_code(s(&c["display"])).unwrap();
        assert_eq!(codec::enroll_display(&session).unwrap(), s(&c["display"]));
        let p = codec::enroll_parse_payload(s(&c["payload_n"])).unwrap();
        assert_eq!((p.role.as_str(), p.session), ("n", session));
    }
    assert!(codec::enroll_display(&[0; 15]).is_err());
    for c in v["typed"]["invalid"].as_array().unwrap() {
        assert!(codec::enroll_parse_code(s(&c["text"])).is_err());
    }
    for c in v["payloads"]["invalid"].as_array().unwrap() {
        assert!(codec::enroll_parse_payload(s(&c["text"])).is_err());
    }
    let ts = v["transcripts"].as_array().unwrap();
    for t in ts {
        let session = codec::enroll_parse_code(&ts_display(t)).unwrap();
        let c =
            codec::enroll_commitment(&session, s(&t["t_id"]), s(&t["n_id"]), &hex(&t["t_nonce"]))
                .unwrap();
        assert_eq!(c, hex(&t["commitment"]));
        let code = codec::enroll_code(
            &session,
            s(&t["t_id"]),
            s(&t["n_id"]),
            &hex(&t["t_nonce"]),
            &hex(&t["n_nonce"]),
        )
        .unwrap();
        assert_eq!(code, s(&t["code"]));
    }
    for c in v["confirmations"].as_array().unwrap() {
        let t = ts.iter().find(|t| t["name"] == c["transcript"]).unwrap();
        let session = codec::enroll_parse_code(&ts_display(t)).unwrap();
        let ok = codec::enroll_check_confirm(
            s(&c["envelope"]).as_bytes(),
            &session,
            s(&t["t_id"]),
            s(&t["new_device"]).as_bytes(),
            &hex(&t["t_nonce"]),
            &hex(&t["n_nonce"]),
        )
        .is_ok();
        assert_eq!(ok, c["valid"].as_bool().unwrap(), "{}", s(&c["name"]));
    }
}

/// The typed code of the session of a transcript case.
fn ts_display(t: &Value) -> String {
    let id = ::hex::decode(s(&t["session"]).strip_prefix("e_").unwrap()).unwrap();
    codec::enroll_display(&id).unwrap()
}

/// S6 through the binding: after a restore, the engine repairs the lost
/// position, reports the repair through `take_repairs`, and the relay holds
/// the space (`Status::RestoreHold`).
#[test]
fn engine_object_reports_a_repair() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("relay");
    let relay = snailfish_relay::core::Relay::open(snailfish_relay::core::Config::new(
        &data,
        "sync.example.net",
    ))
    .unwrap();
    let tenant = relay.add_user("sam").unwrap();
    let mut ka = snailfish::new_device_keys().unwrap();
    let first = snailfish::NewDevice {
        keys: ka.clone(),
        name: "A".into(),
    };
    let setup = snailfish::create_space("com.example.tasks", &first).unwrap();
    ka.app_key.clone_from(&setup.app_key);
    let sp = space(&setup.log_id, &tenant);
    let pa = dir.path().join("a");
    let pa = pa.to_str().unwrap();
    let sa = MemStore::shared();
    snailfish::install_setup(
        pa,
        sp.clone(),
        &ka,
        &setup.envelopes,
        &sign_in(&relay, &ka),
        sa.clone(),
    )
    .unwrap();
    let a = std::sync::Arc::new(snailfish::Engine::open(pa, sp, sa.clone()).unwrap());
    exchange(&relay, &a);
    let backup = dir.path().join("backup");
    snailfish_relay::ops::backup(&data, &backup).unwrap();
    let id = a.new_change_id().unwrap();
    a.enqueue_many(&[snailfish::OutboxRow {
        change_id: id,
        change_bytes: b"x".to_vec(),
    }])
    .unwrap();
    exchange(&relay, &a);
    assert_eq!(a.verified_head().unwrap().position, 2);
    snailfish_relay::ops::restore(&data, &backup, true, 1).unwrap();
    assert_eq!(a.take_repairs().unwrap(), vec![]);
    exchange(&relay, &a);
    assert_eq!(a.status().unwrap(), snailfish::Status::RestoreHold);
    assert_eq!(
        a.take_repairs().unwrap(),
        vec![snailfish::Repair { first: 2, tip: 2 }]
    );
}

/// [LOG-7] through the binding: A enrolls C while B enrolls D on the same
/// base. The grant of D reaches the relay first, so the enrollment on A
/// reaches `ConfirmAgain`, and `grants_to_confirm` names C until the user
/// confirms again.
#[test]
fn confirm_again_crosses_the_binding() {
    use snailfish::EnrollState as S;
    let dir = tempfile::tempdir().unwrap();
    let relay = snailfish_relay::core::Relay::open(snailfish_relay::core::Config::new(
        dir.path().join("relay"),
        "sync.example.net",
    ))
    .unwrap();
    let tenant = relay.add_user("sam").unwrap();
    let mut ka = snailfish::new_device_keys().unwrap();
    let setup = snailfish::create_space(
        "com.example.tasks",
        &snailfish::NewDevice {
            keys: ka.clone(),
            name: "A".into(),
        },
    )
    .unwrap();
    ka.app_key.clone_from(&setup.app_key);
    let sp = space(&setup.log_id, &tenant);
    let pa = dir.path().join("a");
    let pa = pa.to_str().unwrap();
    let sa = MemStore::shared();
    snailfish::install_setup(
        pa,
        sp.clone(),
        &ka,
        &setup.envelopes,
        &sign_in(&relay, &ka),
        sa.clone(),
    )
    .unwrap();
    let a = std::sync::Arc::new(snailfish::Engine::open(pa, sp.clone(), sa.clone()).unwrap());
    exchange(&relay, &a);
    let open = |t: &snailfish::TrustedEnrollment| {
        let (st, h, b) = send(&relay, t.next_request().unwrap().unwrap());
        t.handle_response(st, &h, &b).unwrap();
    };
    // B joins, then syncs once, so it can grant.
    let kb = snailfish::new_device_keys().unwrap();
    let tb = snailfish::TrustedEnrollment::new(a.clone(), None, None).unwrap();
    open(&tb);
    let nb =
        snailfish::NewEnrollment::new("https://sync.example.net", &kb, "B", tb.payload().unwrap())
            .unwrap();
    drive(&relay, &tb, &nb, (true, true));
    let pb = dir.path().join("b");
    let pb = pb.to_str().unwrap();
    let sb = MemStore::shared();
    snailfish::install_enrollment(
        pb,
        sp.clone(),
        &kb,
        &nb.joined().unwrap().unwrap(),
        sb.clone(),
    )
    .unwrap();
    let b = std::sync::Arc::new(snailfish::Engine::open(pb, sp, sb.clone()).unwrap());
    exchange(&relay, &b);
    exchange(&relay, &a);

    // A runs until its grant of C is about to go, and holds that request.
    let tc = snailfish::TrustedEnrollment::new(a.clone(), None, None).unwrap();
    open(&tc);
    let nc = snailfish::NewEnrollment::new(
        "https://sync.example.net",
        &snailfish::new_device_keys().unwrap(),
        "C",
        tc.payload().unwrap(),
    )
    .unwrap();
    let held = drive_until_append(&relay, &tc, &nc);
    // B enrolls D to the end.
    let td = snailfish::TrustedEnrollment::new(b.clone(), None, None).unwrap();
    open(&td);
    let nd = snailfish::NewEnrollment::new(
        "https://sync.example.net",
        &snailfish::new_device_keys().unwrap(),
        "D",
        td.payload().unwrap(),
    )
    .unwrap();
    drive(&relay, &td, &nd, (true, true));
    assert_eq!(td.state().unwrap(), S::Done);

    let (st, h, bd) = send(&relay, held);
    tc.handle_response(st, &h, &bd).unwrap();
    for _ in 0..50 {
        if tc.state().unwrap() == S::ConfirmAgain {
            break;
        }
        if let Some(req) = tc.next_request().unwrap() {
            let (st, h, bd) = send(&relay, req);
            tc.handle_response(st, &h, &bd).unwrap();
        }
    }
    assert_eq!(tc.state().unwrap(), S::ConfirmAgain);
    assert_eq!(a.grants_to_confirm().unwrap().len(), 1);
    tc.confirm(true).unwrap();
    drive(&relay, &tc, &nc, (true, true));
    assert_eq!(
        (tc.state().unwrap(), nc.state().unwrap()),
        (S::Done, S::Done)
    );
    assert_eq!(a.grants_to_confirm().unwrap(), Vec::<String>::new());
}

/// Run an enrollment until the trusted side sends its first append, and
/// return that request unsent.
fn drive_until_append(
    relay: &snailfish_relay::core::Relay,
    t: &snailfish::TrustedEnrollment,
    n: &snailfish::NewEnrollment,
) -> snailfish::Request {
    use snailfish::EnrollState as S;
    for _ in 0..200 {
        if matches!(t.state().unwrap(), S::Compare { .. }) {
            t.confirm(true).unwrap();
        }
        if matches!(n.state().unwrap(), S::Compare { .. }) {
            n.confirm(true).unwrap();
        }
        if let Some(req) = t.next_request().unwrap() {
            if req.url.ends_with("/append") {
                return req;
            }
            let (st, h, bd) = send(relay, req);
            t.handle_response(st, &h, &bd).unwrap();
        }
        if let Some(req) = n.next_request().unwrap() {
            let (st, _, bd) = send(relay, req);
            n.handle_response(st, &bd).unwrap();
        }
    }
    panic!("no append");
}

/// [USR-6] through the binding: a setup token of another device stops the
/// engine with `stopped: setup failed`. A malformed new token is refused,
/// and a new token of this device creates the space.
#[test]
fn setup_failure_and_new_token_cross_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = snailfish_relay::core::Config::new(dir.path().join("relay"), "sync.example.net");
    cfg.secrets_dir = dir.path().join("secrets");
    let relay = snailfish_relay::core::Relay::open(cfg).unwrap();
    let tenant = relay.add_user("sam").unwrap();
    let mut ka = snailfish::new_device_keys().unwrap();
    let other = snailfish::new_device_keys().unwrap();
    let setup = snailfish::create_space(
        "com.example.tasks",
        &snailfish::NewDevice {
            keys: ka.clone(),
            name: "A".into(),
        },
    )
    .unwrap();
    ka.app_key.clone_from(&setup.app_key);
    let sp = space(&setup.log_id, &tenant);
    let pa = dir.path().join("a");
    let pa = pa.to_str().unwrap();
    let sa = MemStore::shared();
    snailfish::install_setup(
        pa,
        sp.clone(),
        &ka,
        &setup.envelopes,
        &sign_in(&relay, &other),
        sa.clone(),
    )
    .unwrap();
    let a = std::sync::Arc::new(snailfish::Engine::open(pa, sp, sa.clone()).unwrap());
    exchange(&relay, &a);
    let status = a.status().unwrap();
    assert_eq!(
        status,
        snailfish::Status::SetupFailed {
            cause: "bad_setup".into()
        }
    );
    assert_eq!(snailfish::status_text(&status), "stopped: setup failed");
    assert_eq!(
        snailfish::status_text(&snailfish::Status::Quota),
        "paused: quota"
    );
    assert!(a.set_setup_token("st_00").is_err());
    a.set_setup_token(&sign_in(&relay, &ka)).unwrap();
    exchange(&relay, &a);
    assert_eq!(a.status().unwrap(), snailfish::Status::Ok);
}
