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

/// The engine object through the binding: setup, the directory lock, a
/// change from A to B through the real relay core, and the status
/// variants. A marshalling fault in any record fails here.
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
    let mut kb = snailfish::new_device_keys().unwrap();
    let dev = |k: &snailfish::DeviceKeys, n: &str| snailfish::NewDevice {
        keys: k.clone(),
        name: n.into(),
    };
    // The app key of a new device is not read: setup makes it.
    let mut kb_no_app_key = kb.clone();
    kb_no_app_key.app_key = vec![];
    let setup = snailfish::create_space(
        "com.example.tasks",
        &dev(&ka, "A"),
        &[dev(&kb_no_app_key, "B")],
    )
    .unwrap();
    let short_seed = snailfish::DeviceKeys {
        sign_seed: vec![1; 31],
        ..ka.clone()
    };
    assert!(matches!(
        snailfish::create_space("com.example.tasks", &dev(&short_seed, "A"), &[]),
        Err(snailfish::SnailfishError::Invalid { .. })
    ));
    assert_eq!(setup.envelopes.len(), 2);
    assert!(codec::recovery_parse(&setup.recovery_key).is_ok());
    ka.app_key.clone_from(&setup.app_key);
    kb.app_key.clone_from(&setup.app_key);
    let sp = space(&setup.log_id, &tenant);
    let pa = dir.path().join("a");
    let pa = pa.to_str().unwrap();
    snailfish::install_setup(pa, sp.clone(), &ka, &setup.envelopes).unwrap();
    let a = std::sync::Arc::new(snailfish::Engine::open(pa, sp.clone(), &ka).unwrap());
    let locked = snailfish::Engine::open(pa, sp.clone(), &ka).err().unwrap();
    assert!(matches!(locked, snailfish::SnailfishError::Locked));
    assert_eq!(
        locked.to_string(),
        "another engine uses this data directory"
    );
    let short = snailfish::DeviceKeys {
        app_key: vec![0; 31],
        ..kb.clone()
    };
    let pb = dir.path().join("b");
    let pb = pb.to_str().unwrap();
    assert!(matches!(
        snailfish::Engine::open(pb, sp.clone(), &short),
        Err(snailfish::SnailfishError::Invalid { .. })
    ));
    let b = std::sync::Arc::new(snailfish::Engine::open(pb, sp, &kb).unwrap());

    exchange(&relay, &a);
    assert_eq!(a.status().unwrap(), snailfish::Status::Ok);
    assert_eq!(a.verified_head().unwrap().position, 2);
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
    exchange(&relay, &a);
    assert_eq!(a.outbox_len().unwrap(), 0);
    exchange(&relay, &b);
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
