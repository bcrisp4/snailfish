//! The request signatures and append checks of `vectors/http.json`
//! (`PROTOCOL.md` sections 8 and 10). The Go generator in `tools/vectorgen`
//! makes the file from `PROTOCOL.md` alone.
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::encoding::decode_id;
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::request::{self, Params, Target};
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::space::{MemorySpace, Mode, Verdict, check_append, check_genesis};
use snailfish_protocol::wire;

fn load() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/http.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn key(h: &Value, name: &str) -> Option<(SecretKey, [u8; 32])> {
    let d = h["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)?;
    let seed: [u8; 32] = hex::decode(s(&d["sign_seed"])).unwrap().try_into().unwrap();
    Some((
        SecretKey::from_seed(&seed),
        decode_id::<32>(s(&d["id"]), "d_").unwrap(),
    ))
}

fn headers(c: &Value) -> Vec<(String, String)> {
    c["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (s(&p[0]).to_owned(), s(&p[1]).to_owned()))
        .collect()
}

/// The space of the vectors: every device of `space.log`.
fn space(h: &Value) -> MemorySpace {
    let log = decode_id::<16>(s(&h["log_id"]), "l_").unwrap();
    let mut sp = MemorySpace::new(log);
    for (i, e) in h["space"]["log"].as_array().unwrap().iter().enumerate() {
        let env = Envelope::parse(s(&e["envelope"]).as_bytes()).unwrap();
        let acc = if i == 0 {
            check_genesis(&env, &log, None).unwrap()
        } else {
            let Some(signer) = env_author(&env) else {
                panic!("entry {i} has no device author")
            };
            match check_append(&sp, &env, Mode::Verify) {
                Verdict::Store(a) => {
                    assert_eq!(a.record.author.id(), &signer);
                    *a
                }
                other => panic!("entry {i}: {other:?}"),
            }
        };
        assert_eq!(hex::encode(acc.digest), s(&e["digest"]));
        assert_eq!(hex::encode(acc.record_hash), s(&e["record_hash"]));
        sp.apply(&acc);
    }
    sp
}

fn env_author(env: &Envelope) -> Option<[u8; 32]> {
    snailfish_protocol::records::parse_payload(&env.payload_type, &env.payload)
        .ok()
        .map(|r| *r.author.id())
}

/// A relay check of 8.6, with the nonce store of the vectors (step 7).
fn relay_check(h: &Value, sp: &MemorySpace, c: &Value, authority: &str) -> Result<(), String> {
    let hs = headers(c);
    let pairs: Vec<(&str, &str)> = hs.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let t = Target {
        method: s(&c["method"]),
        authority,
        path: s(&c["path"]),
        query: s(&c["query"]),
    };
    let now = h["now"].as_u64().unwrap();
    let v = request::check(&pairs, &t, s(&c["body"]).as_bytes(), now, |id| {
        sp.devices.get(id).copied()
    })
    .map_err(|e| e.code().to_owned())?;
    let used = h["used_nonces"].as_array().unwrap().iter().any(|p| {
        s(&p[0]) == snailfish_protocol::encoding::encode_id("d_", &v.keyid)
            && s(&p[1]) == hex::encode(v.nonce)
    });
    if used {
        return Err("nonce_reused".into());
    }
    Ok(())
}

#[test]
fn signed_requests_match_go_bytes_and_verify() {
    let h = load();
    let sp = space(&h);
    let cases = h["signed"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for c in cases {
        let name = s(&c["name"]);
        let (sk, id) = key(&h, s(&c["signer"])).unwrap();
        let t = Target {
            method: s(&c["method"]),
            authority: s(&c["authority"]),
            path: s(&c["path"]),
            query: s(&c["query"]),
        };
        let p = Params {
            created: c["created"].as_u64().unwrap(),
            expires: c["expires"].as_u64().unwrap(),
            nonce: hex::decode(s(&c["nonce"])).unwrap().try_into().unwrap(),
            keyid: id,
        };
        let body = s(&c["body"]).as_bytes();
        assert_eq!(
            request::content_digest(body),
            s(&c["content_digest"]),
            "{name}"
        );
        let line = request::params_line(&p);
        assert_eq!(line, s(&c["signature_params"]), "{name}");
        assert_eq!(
            request::signature_base(&t, s(&c["content_digest"]), &line),
            s(&c["signature_base"]),
            "{name}"
        );
        let signed = request::sign(&sk, &t, body, &p);
        let ours: Vec<(String, String)> = signed
            .pairs()
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(ours, headers(c), "{name}");
        // The relay of the vectors uses its configured authority. A case for
        // another authority verifies only against that authority.
        assert_eq!(
            relay_check(&h, &sp, c, s(&c["authority"])),
            Ok(()),
            "{name}"
        );
    }
}

#[test]
fn invalid_requests_give_the_go_error() {
    let h = load();
    let sp = space(&h);
    let cases = h["invalid"].as_array().unwrap();
    assert!(cases.len() >= 18);
    for c in cases {
        assert_eq!(
            relay_check(&h, &sp, c, s(&h["authority"])),
            Err(s(&c["error"]).to_owned()),
            "{}",
            s(&c["name"])
        );
    }
}

#[test]
fn append_cases_give_the_go_results() {
    let h = load();
    let base = space(&h);
    let max_change = usize::try_from(h["limits"]["max_change_bytes"].as_u64().unwrap()).unwrap();
    let max_env = h["limits"]["max_append_envelopes"].as_u64().unwrap();
    let cases = h["append"].as_array().unwrap();
    assert!(cases.len() >= 18);
    for c in cases {
        let name = s(&c["name"]);
        let (_, signer) = key(&h, s(&c["signer"])).unwrap();
        let mut sp = base.clone();
        let items = wire::parse_append(s(&c["body"]).as_bytes(), max_env).unwrap();
        let mut got = Vec::new();
        for item in items {
            let r = match item {
                Err(_) => (
                    "refused".to_owned(),
                    None,
                    Some("invalid_record".to_owned()),
                ),
                Ok(raw) => match check_append(
                    &sp,
                    &raw.envelope,
                    Mode::Relay {
                        signer,
                        max_change_bytes: max_change,
                        hold: false,
                    },
                ) {
                    Verdict::Store(a) => {
                        sp.apply(&a);
                        ("stored".into(), Some(a.position), None)
                    }
                    Verdict::Known(p) => ("known".into(), Some(p), None),
                    Verdict::Conflict(p) => ("conflict".into(), Some(p), None),
                    Verdict::Refused(r) => ("refused".into(), None, Some(r.code().to_owned())),
                },
            };
            got.push(r);
        }
        let want: Vec<(String, Option<u64>, Option<String>)> = c["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    s(&r["status"]).to_owned(),
                    r["position"].as_u64(),
                    r["error"].as_str().map(str::to_owned),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
        let head = sp.digests.len().checked_sub(1).unwrap();
        assert_eq!(Some(head as u64), c["head"]["position"].as_u64(), "{name}");
        assert_eq!(
            hex::encode(sp.digests[head]),
            s(&c["head"]["digest"]),
            "{name}"
        );
    }
}
