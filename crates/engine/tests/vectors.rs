//! The shared test vectors through `snailfish_engine::codec`, the API that
//! the bindings forward to (DESIGN.md M1). The Python and Swift tests run the
//! same checks through their bindings.
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_engine::codec::{self, Envelope, PayloadClass};

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
        let info = codec::check_payload(&env.payload_type, &env.payload).unwrap();
        assert_eq!(info.log, s(&log["log_id"]));
        let rh = codec::record_hash(&env.payload_type, &env.payload, &env.sig).unwrap();
        assert_eq!(rh, hex(&e["record_hash"]));
        let eh = codec::entry_hash(&env.payload_type, info.change_id.as_deref(), &rh).unwrap();
        assert_eq!(eh, hex(&e["entry_hash"]));
        digest = codec::digest_next(&digest, e["position"].as_u64().unwrap(), &eh).unwrap();
        assert_eq!(digest, hex(&e["digest"]));
        assert_eq!(
            codec::envelope_to_json(&env, &info.author).unwrap(),
            s(&e["envelope"])
        );
        for ks in codec::key_sets(&env.payload_type, &env.payload).unwrap() {
            let keys = codec::open_key_set(
                &seal[&ks.to],
                s(&log["log_id"]),
                &ks.to,
                &ks.epochs,
                &ks.sealed,
            )
            .unwrap();
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
