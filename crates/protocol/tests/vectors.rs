//! The shared test vectors in `vectors/` (DESIGN.md M1).
//!
//! The Go generator in `tools/vectorgen` makes `protocol.json`,
//! `strict-json.json` and `recovery-key.json` from `PROTOCOL.md` alone, so
//! these tests compare this crate with a second implementation. The files in
//! `vectors/third_party/` come from C2SP CCTV, RFC 9180 and
//! `draft-ietf-hpke-pq`.
#![cfg(test)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable as _, Serializable as _};
use serde_json::Value;
use snailfish_protocol::encoding::{decode_id, encode_id, frame};
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::hash::{digest_next, digest0, entry_hash};
use snailfish_protocol::keys::{
    change_aad, decrypt, device_id, encrypt_with_nonce, key_commitment, key_set_info, open_key_set,
    recovery_id, seal_key_set_with_randomness, seal_public, snapshot_aad,
};
use snailfish_protocol::records::{self, Author, Body, Record, Statement};
use snailfish_protocol::{recovery, sig};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(name: &str) -> Value {
    let path = root().join("vectors").join(name);
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&text).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    ::hex::decode(v.as_str().unwrap()).unwrap()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

/// The signing and sealing secrets of each named party, by name and by ID.
struct Parties {
    sign_seed: BTreeMap<String, [u8; 32]>,
    seal_seed_by_id: BTreeMap<[u8; 32], [u8; 32]>,
}

fn parties(p: &Value) -> Parties {
    let mut out = Parties {
        sign_seed: BTreeMap::new(),
        seal_seed_by_id: BTreeMap::new(),
    };
    for d in p["devices"].as_array().unwrap() {
        let sign_seed = hex32(&d["sign_seed"]);
        let seal_seed = hex32(&d["seal_seed"]);
        let sign_pk = sig::SecretKey::from_seed(&sign_seed).public();
        let seal_pk = seal_public(&seal_seed);
        assert_eq!(sign_pk.to_vec(), hex(&d["sign_pk"]), "device {}", d["name"]);
        assert_eq!(seal_pk.to_vec(), hex(&d["seal_pk"]), "device {}", d["name"]);
        let id = device_id(&sign_pk, &seal_pk);
        assert_eq!(encode_id("d_", &id), s(&d["id"]));
        out.sign_seed.insert(s(&d["name"]).to_owned(), sign_seed);
        out.seal_seed_by_id.insert(id, seal_seed);
    }
    for r in p["recovery"].as_array().unwrap() {
        let secret: [u8; 16] = hex(&r["secret"]).try_into().unwrap();
        assert_eq!(recovery::display(&secret), s(&r["display"]));
        assert_eq!(recovery::parse(s(&r["display"])), Ok(secret));
        let (sign_seed, seal_seed) = recovery::derive(&secret);
        assert_eq!(sign_seed, hex32(&r["sign_seed"]));
        assert_eq!(seal_seed, hex32(&r["seal_seed"]));
        let sign_pk = sig::SecretKey::from_seed(&sign_seed).public();
        let seal_pk = seal_public(&seal_seed);
        assert_eq!(sign_pk.to_vec(), hex(&r["sign_pk"]));
        assert_eq!(seal_pk.to_vec(), hex(&r["seal_pk"]));
        let id = recovery_id(&sign_pk, &seal_pk);
        assert_eq!(encode_id("r_", &id), s(&r["id"]));
        out.sign_seed.insert(s(&r["name"]).to_owned(), sign_seed);
        out.seal_seed_by_id.insert(id, seal_seed);
    }
    out
}

#[test]
fn frames() {
    let p = load("protocol.json");
    for f in p["frames"].as_array().unwrap() {
        let parts: Vec<Vec<u8>> = f["parts"].as_array().unwrap().iter().map(hex).collect();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        assert_eq!(frame(&refs), hex(&f["frame"]));
    }
}

/// Parse and check each log entry: envelope, writer form, signature, record
/// hash, entry hash, digest chain, payload fields and key commitments.
fn verified_log(p: &Value, who: &Parties) -> Vec<Record> {
    let log = &p["log"];
    let log_id = decode_id::<16>(s(&log["log_id"]), "l_").unwrap();
    let mut digest = digest0(&log_id);
    assert_eq!(digest.to_vec(), hex(&log["digest0"]));
    let mut out = Vec::new();
    for (i, e) in log["entries"].as_array().unwrap().iter().enumerate() {
        let n = e["position"].as_u64().unwrap();
        assert_eq!(
            n,
            u64::try_from(i).unwrap().wrapping_add(1),
            "dense positions [LOG-1]"
        );
        let env = Envelope::parse(s(&e["envelope"]).as_bytes()).unwrap();
        assert_eq!(env.payload_type, s(&e["payload_type"]));
        assert_eq!(env.payload, s(&e["payload"]).as_bytes());
        assert_eq!(env.sig.to_vec(), hex(&e["sig"]));
        let signer = sig::SecretKey::from_seed(&who.sign_seed[s(&e["signer"])]);
        let pk = sig::PublicKey::from_bytes(&signer.public()).unwrap();
        assert_eq!(
            pk.verify_record(&env.payload_type, &env.payload, &env.sig),
            Ok(()),
            "entry {n}"
        );
        assert_eq!(signer.sign_record(&env.payload_type, &env.payload), env.sig);
        let rec = records::parse_payload(&env.payload_type, &env.payload)
            .unwrap_or_else(|err| panic!("entry {n}: {err}"));
        assert_eq!(rec.log, log_id);
        assert_eq!(
            env.to_json(&encode_id(author_prefix(&rec.author), rec.author.id())),
            s(&e["envelope"]),
            "writer form"
        );
        let rh = env.record_hash();
        assert_eq!(rh.to_vec(), hex(&e["record_hash"]), "entry {n}");
        assert_eq!(
            rec.change_id().map(|c| c.to_vec()).unwrap_or_default(),
            hex(&e["change_id"])
        );
        let eh = entry_hash(&env.payload_type, rec.change_id(), &rh);
        assert_eq!(eh.to_vec(), hex(&e["entry_hash"]), "entry {n}");
        digest = digest_next(&digest, n, &eh);
        assert_eq!(digest.to_vec(), hex(&e["digest"]), "entry {n}");
        if let Body::Genesis { commitment, .. } | Body::Epoch { commitment, .. } = &rec.body {
            let epoch = if let Body::Epoch { epoch, .. } = &rec.body {
                *epoch
            } else {
                1
            };
            let key = hex32(&log["app_keys"][epoch.to_string()]);
            assert_eq!(&key_commitment(&log_id, epoch, &key), commitment);
            assert_eq!(
                commitment.to_vec(),
                hex(&log["commitments"][epoch.to_string()])
            );
        }
        out.push(rec);
    }
    // Each base names an earlier entry with its digest [LOG-6].
    let digests: Vec<Vec<u8>> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| hex(&e["digest"]))
        .collect();
    for (i, rec) in out.iter().enumerate().skip(1) {
        let b = usize::try_from(rec.base.position).unwrap();
        assert!((1..=i).contains(&b), "entry {i}+1: base {b}");
        assert_eq!(rec.base.digest.to_vec(), digests[b.wrapping_sub(1)]);
    }
    out
}

fn author_prefix(a: &Author) -> &'static str {
    match a {
        Author::Device(_) => "d_",
        Author::Recovery(_) => "r_",
    }
}

#[test]
fn log_entries() {
    let p = load("protocol.json");
    let who = parties(&p);
    let recs = verified_log(&p, &who);
    assert_eq!(recs.len(), 11);
    // The recovery proof is a signature by the new recovery key [WIR-2].
    let log_id = recs[0].log;
    let Body::Recovery {
        recovery, proof, ..
    } = &recs[10].body
    else {
        panic!("entry 11")
    };
    let pk = sig::PublicKey::from_bytes(&recovery.sign).unwrap();
    let msg = frame(&[
        b"snailfish.recovery-proof.v1",
        &log_id,
        &recovery.sign,
        &recovery.seal[..],
    ]);
    assert_eq!(pk.verify_raw(&msg, proof), Ok(()));
}

#[test]
fn statements() {
    let p = load("protocol.json");
    let who = parties(&p);
    for st in p["statements"].as_array().unwrap() {
        let env = Envelope::parse(s(&st["envelope"]).as_bytes()).unwrap();
        assert_eq!(env.payload, s(&st["payload"]).as_bytes());
        let signer = sig::SecretKey::from_seed(&who.sign_seed[s(&st["signer"])]);
        let pk = sig::PublicKey::from_bytes(&signer.public()).unwrap();
        assert_eq!(
            pk.verify_record(&env.payload_type, &env.payload, &env.sig),
            Ok(())
        );
        assert_eq!(env.record_hash().to_vec(), hex(&st["record_hash"]));
        let parsed = records::parse_statement(&env.payload_type, &env.payload).unwrap();
        match (s(&st["name"]), parsed) {
            ("checkpoint", Statement::Checkpoint { at, .. }) => assert_eq!(at.position, 11),
            ("delete", Statement::Delete { head, .. }) => assert_eq!(head.position, 11),
            (name, other) => panic!("{name}: {other:?}"),
        }
    }
}

fn key_sets_of(rec: &Record) -> &[records::KeySet] {
    match &rec.body {
        Body::Genesis { keys, .. }
        | Body::Grant { keys, .. }
        | Body::Epoch { keys, .. }
        | Body::Recovery { keys, .. } => keys,
        _ => &[],
    }
}

/// Rust opens each key set that Go `crypto/hpke` sealed.
#[test]
fn key_sets_from_go_open() {
    let p = load("protocol.json");
    let who = parties(&p);
    let recs = verified_log(&p, &who);
    let mut count = 0;
    for k in p["key_sets"].as_array().unwrap() {
        let rec = &recs[usize::try_from(k["entry"].as_u64().unwrap())
            .unwrap()
            .wrapping_sub(1)];
        let ks = &key_sets_of(rec)[usize::try_from(k["index"].as_u64().unwrap()).unwrap()];
        assert_eq!(encode_id(author_prefix(&ks.to), ks.to.id()), s(&k["to"]));
        let epochs: Vec<u64> = k["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_u64().unwrap())
            .collect();
        assert_eq!(ks.epochs, epochs);
        assert_eq!(key_set_info(&rec.log, ks.to.id(), &epochs), hex(&k["info"]));
        let opened = open_key_set(
            &who.seal_seed_by_id[ks.to.id()],
            &rec.log,
            ks.to.id(),
            &epochs,
            &ks.sealed,
        )
        .unwrap();
        assert_eq!(opened.concat(), hex(&k["plaintext"]));
        count += 1;
    }
    let total: usize = recs.iter().map(|r| key_sets_of(r).len()).sum();
    assert_eq!(count, total, "every key set in the log has a vector");
}

/// Rust seals each key set again for Go to open (`make vectors-check`).
#[test]
fn key_sets_from_rust_seal_for_go() {
    let p = load("protocol.json");
    let who = parties(&p);
    let recs = verified_log(&p, &who);
    let mut out = Vec::new();
    for (i, k) in p["key_sets"].as_array().unwrap().iter().enumerate() {
        let rec = &recs[usize::try_from(k["entry"].as_u64().unwrap())
            .unwrap()
            .wrapping_sub(1)];
        let ks = &key_sets_of(rec)[usize::try_from(k["index"].as_u64().unwrap()).unwrap()];
        let seed = who.seal_seed_by_id[ks.to.id()];
        let keys: Vec<[u8; 32]> = hex(&k["plaintext"]).as_chunks::<32>().0.to_vec();
        let randomness = [u8::try_from(i).unwrap(); 64];
        let sealed = seal_key_set_with_randomness(
            randomness,
            &seal_public(&seed),
            &rec.log,
            ks.to.id(),
            &ks.epochs,
            &keys,
        )
        .unwrap();
        assert_eq!(
            open_key_set(&seed, &rec.log, ks.to.id(), &ks.epochs, &sealed).unwrap(),
            keys
        );
        out.push(serde_json::json!({
            "seal_seed": ::hex::encode(seed),
            "to": s(&k["to"]),
            "log_id": s(&p["log"]["log_id"]),
            "epochs": ks.epochs,
            "sealed": ::hex::encode(&sealed),
            "plaintext": s(&k["plaintext"]),
        }));
    }
    // `make vectors-check` sets RUST_SEALED and gives the file to Go.
    let Some(path) = std::env::var_os("RUST_SEALED").map(PathBuf::from) else {
        return;
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    let text = serde_json::to_string_pretty(&serde_json::json!({ "key_sets": out })).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn ciphertexts() {
    let p = load("protocol.json");
    let who = parties(&p);
    let recs = verified_log(&p, &who);
    let cts = p["ciphertexts"].as_array().unwrap();
    assert_eq!(cts.len(), 3);
    for c in cts {
        let rec = &recs[usize::try_from(c["entry"].as_u64().unwrap())
            .unwrap()
            .wrapping_sub(1)];
        let (epoch, aad, ct) = match &rec.body {
            Body::Change {
                epoch,
                change_id,
                ciphertext,
            } => (
                *epoch,
                change_aad(&rec.log, *epoch, change_id, rec.author.id()),
                ciphertext,
            ),
            Body::Snapshot {
                epoch,
                state,
                ciphertext,
            } => (
                *epoch,
                snapshot_aad(
                    &rec.log,
                    *epoch,
                    rec.author.id(),
                    state.position,
                    &state.digest,
                ),
                ciphertext,
            ),
            other => panic!("{other:?}"),
        };
        assert_eq!(aad, hex(&c["aad"]));
        let key = hex32(&p["log"]["app_keys"][epoch.to_string()]);
        assert_eq!(decrypt(&key, &aad, ct).unwrap(), hex(&c["plaintext"]));
        let nonce: [u8; 24] = hex(&c["nonce"]).try_into().unwrap();
        assert_eq!(
            &encrypt_with_nonce(&key, &nonce, &aad, &hex(&c["plaintext"])),
            ct
        );
        // [DLV-13]: a ciphertext under other routing fields does not decrypt.
        let other = change_aad(&rec.log, epoch.wrapping_add(1), &[0; 16], rec.author.id());
        assert!(decrypt(&key, &other, ct).is_err());
    }
}

#[test]
fn envelopes() {
    let p = load("protocol.json");
    for e in p["envelopes"].as_array().unwrap() {
        let parsed = Envelope::parse(s(&e["envelope"]).as_bytes());
        let valid = e["valid"].as_bool().unwrap();
        assert_eq!(parsed.is_ok(), valid, "{}: {parsed:?}", e["name"]);
        if let Ok(env) = parsed {
            // [WIR-3]: the layout and the keyid do not change the record hash.
            assert_eq!(
                env.record_hash().to_vec(),
                hex(&e["record_hash"]),
                "{}",
                e["name"]
            );
        }
    }
}

#[test]
fn strict_json() {
    let v = load("strict-json.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 50);
    for c in cases {
        let bytes = match &c["payload"] {
            Value::String(text) => text.as_bytes().to_vec(),
            _ => hex(&c["payload_hex"]),
        };
        let result = records::parse_payload(s(&c["payload_type"]), &bytes);
        assert_eq!(
            result.is_ok(),
            c["valid"].as_bool().unwrap(),
            "{} (rule {}): {result:?}",
            c["name"],
            c["rule"]
        );
    }
}

#[test]
fn recovery_keys() {
    let v = load("recovery-key.json");
    for c in v["valid"].as_array().unwrap() {
        assert_eq!(
            recovery::parse(s(&c["text"])).map(|k| k.to_vec()),
            Ok(hex(&c["secret"])),
            "{}",
            c["text"]
        );
    }
    for c in v["invalid"].as_array().unwrap() {
        assert!(recovery::parse(s(&c["text"])).is_err(), "{}", c["name"]);
    }
}

/// All 914 C2SP CCTV Ed25519 vectors. `verify_strict` with the canonical key
/// check accepts a vector only if its flags are a subset of the two
/// low-order-component flags (`PROTOCOL.md` 7.1).
#[test]
fn cctv_ed25519() {
    let v = load("third_party/cctv-ed25519.json");
    let all = v.as_array().unwrap();
    assert_eq!(all.len(), 914);
    let mut accepted = 0;
    for t in all {
        let flags: Vec<&str> = t["flags"]
            .as_array()
            .map(|f| f.iter().map(s).collect())
            .unwrap_or_default();
        let expected = flags
            .iter()
            .all(|f| matches!(*f, "low_order_component_A" | "low_order_component_R"));
        let key = hex32(&t["key"]);
        let sig: [u8; 64] = hex(&t["sig"]).try_into().unwrap();
        let ok = sig::PublicKey::from_bytes(&key)
            .is_ok_and(|pk| pk.verify_raw(s(&t["msg"]).as_bytes(), &sig).is_ok());
        assert_eq!(ok, expected, "vector {} flags {flags:?}", t["number"]);
        accepted += usize::from(ok);
    }
    assert!(accepted > 0);
}

/// Replays a fixed byte string as randomness. `hpke` derives an ephemeral key
/// pair from `Nsk` random bytes, and X-Wing reads 64 bytes, so the vector
/// `ikmE` reproduces the vector `enc`.
struct Fixed(Vec<u8>);

impl TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            dst.len() <= self.0.len(),
            "the vector gives too little randomness"
        );
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

fn hpke_case<K: hpke::Kem>(t: &Value) {
    type A = hpke::aead::ChaCha20Poly1305;
    type F = hpke::kdf::HkdfSha256;
    let (sk, pk) = K::derive_keypair(&hex(&t["ikmR"]));
    assert_eq!(pk.to_bytes().to_vec(), hex(&t["pkRm"]));
    assert_eq!(sk.to_bytes().to_vec(), hex(&t["skRm"]));
    let info = hex(&t["info"]);
    let (enc, mut sender) = hpke::setup_sender_with_rng::<A, F, K>(
        &hpke::OpModeS::Base,
        &pk,
        &info,
        &mut Fixed(hex(&t["ikmE"])),
    )
    .unwrap();
    assert_eq!(enc.to_bytes().to_vec(), hex(&t["enc"]));
    let enc = K::EncappedKey::from_bytes(&hex(&t["enc"])).unwrap();
    let mut receiver =
        hpke::setup_receiver::<A, F, K>(&hpke::OpModeR::Base, &sk, &enc, &info).unwrap();
    let encs = t["encryptions"].as_array().unwrap();
    assert_ne!(encs.len(), 0);
    for e in encs {
        let ct = sender.seal(&hex(&e["pt"]), &hex(&e["aad"])).unwrap();
        assert_eq!(ct, hex(&e["ct"]));
        assert_eq!(receiver.open(&ct, &hex(&e["aad"])).unwrap(), hex(&e["pt"]));
    }
    for x in t["exports"].as_array().unwrap() {
        let mut out = vec![0u8; usize::try_from(x["L"].as_u64().unwrap()).unwrap()];
        sender
            .export(&hex(&x["exporter_context"]), &mut out)
            .unwrap();
        assert_eq!(out, hex(&x["exported_value"]));
    }
}

#[test]
fn hpke_rfc9180() {
    let v = load("third_party/hpke-rfc9180.json");
    let cases = v.as_array().unwrap();
    assert_eq!(cases.len(), 1);
    hpke_case::<hpke::kem::X25519HkdfSha256>(&cases[0]);
}

#[test]
fn hpke_pq_xwing() {
    let v = load("third_party/hpke-pq.json");
    let cases = v.as_array().unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0]["kem_id"].as_u64(), Some(0x647a));
    hpke_case::<hpke::kem::XWing>(&cases[0]);
}
