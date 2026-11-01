//! The enrollment transcript of `enroll` against the Go vectors in
//! `vectors/enroll.json` (`PROTOCOL.md` 11.1 and 11.2, [ENR-1], [ENR-4],
//! [ENR-7]). The Go generator is a second implementation of the same text,
//! so a misreading in one of them fails here.
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::encoding::{decode_id, frame};
use snailfish_protocol::enroll::{
    self, Payload, Role, Transcript, check_confirm, commitment, parse_code, parse_payload,
};
use snailfish_protocol::envelope::Envelope;
use snailfish_protocol::records::parse_device_json;

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/enroll.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} is not a string"))
}

fn session(v: &Value) -> [u8; 16] {
    decode_id::<16>(s(v, "session"), "e_").unwrap()
}

fn hex32(v: &Value, k: &str) -> [u8; 32] {
    hex::decode(s(v, k)).unwrap().try_into().unwrap()
}

fn list(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap()
}

#[test]
fn codes_and_payloads_match_go() {
    let v = vectors();
    let relay = s(&v, "relay_url");
    for c in list(&v["codes"]) {
        let id = session(c);
        assert_eq!(enroll::display(&id), s(c, "display"), "{}", s(c, "name"));
        assert_eq!(enroll::display(&id).replace('-', ""), s(c, "symbols"));
        for (role, key) in [(Role::Trusted, "payload_t"), (Role::New, "payload_n")] {
            let p = Payload {
                role,
                relay_url: relay.into(),
                session: id,
            };
            assert_eq!(enroll::payload(&p), s(c, key));
            assert_eq!(parse_payload(s(c, key)), Ok(p));
        }
    }
}

#[test]
fn typed_code_reader_matches_go() {
    let v = vectors();
    for c in list(&v["typed"]["valid"]) {
        assert_eq!(parse_code(s(c, "text")), Ok(session(c)), "{}", s(c, "name"));
    }
    for c in list(&v["typed"]["invalid"]) {
        assert!(parse_code(s(c, "text")).is_err(), "{}", s(c, "name"));
    }
}

#[test]
fn payload_reader_matches_go() {
    let v = vectors();
    for c in list(&v["payloads"]["valid"]) {
        let p = parse_payload(s(c, "text")).unwrap_or_else(|e| panic!("{}: {e}", s(c, "name")));
        assert_eq!(p.role.letter(), s(c, "role"));
        assert_eq!(p.relay_url, s(c, "relay_url"));
        assert_eq!(p.session, session(c));
    }
    for c in list(&v["payloads"]["invalid"]) {
        assert!(parse_payload(s(c, "text")).is_err(), "{}", s(c, "name"));
    }
}

/// [ENR-4] [ENR-7]: the commitment and the 6-digit code of each Go
/// transcript, also the frames, so a wrong part order fails with a clear
/// diff and not only a different hash.
#[test]
fn transcripts_match_go() {
    let v = vectors();
    for t in list(&v["transcripts"]) {
        let name = s(t, "name");
        let id = session(t);
        let t_id = decode_id::<32>(s(t, "t_id"), "d_").unwrap();
        let n_id = decode_id::<32>(s(t, "n_id"), "d_").unwrap();
        let (tn, nn) = (hex32(t, "t_nonce"), hex32(t, "n_nonce"));
        let cf = frame(&[
            b"snailfish.enroll-commit.v1",
            &id,
            b"trusted",
            &t_id,
            b"new",
            &n_id,
            &tn,
        ]);
        assert_eq!(hex::encode(cf), s(t, "commit_frame"), "{name}");
        assert_eq!(
            commitment(&id, &t_id, &n_id, &tn),
            hex32(t, "commitment"),
            "{name}"
        );
        let kf = frame(&[
            b"snailfish.enroll-code.v1",
            &id,
            b"trusted",
            &t_id,
            b"new",
            &n_id,
            &tn,
            &nn,
        ]);
        assert_eq!(hex::encode(kf), s(t, "code_frame"), "{name}");
        assert_eq!(
            enroll::format_code(enroll::code_value(&hex32(t, "digits"))),
            s(t, "code")
        );
        assert_eq!(
            enroll::code(&id, &t_id, &n_id, &tn, &nn),
            s(t, "code"),
            "{name}"
        );
        let d = parse_device_json(s(t, "new_device").as_bytes()).unwrap();
        assert_eq!(d.id, n_id);
    }
}

/// [ENR-7] 11.2: the trusted device accepts exactly the valid Go
/// confirmations of each transcript.
#[test]
fn confirmations_match_go() {
    let v = vectors();
    let transcripts = list(&v["transcripts"]);
    for c in list(&v["confirmations"]) {
        let name = s(c, "name");
        let t = transcripts
            .iter()
            .find(|t| t["name"] == c["transcript"])
            .unwrap();
        let tr = Transcript {
            session: session(t),
            t_id: decode_id::<32>(s(t, "t_id"), "d_").unwrap(),
            new_device: parse_device_json(s(t, "new_device").as_bytes()).unwrap(),
            t_nonce: hex32(t, "t_nonce"),
            n_nonce: hex32(t, "n_nonce"),
        };
        let got = Envelope::parse(s(c, "envelope").as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|e| check_confirm(&e, &tr).map_err(|e| e.to_string()));
        assert_eq!(
            got.is_ok(),
            c["valid"].as_bool().unwrap(),
            "{name}: {got:?}"
        );
    }
}
