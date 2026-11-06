//! The export file reader (`PROTOCOL.md` section 15, [FRK-3]) against the Go
//! cases in `vectors/export.json`. Go reads each case with its own reader,
//! so a misreading of section 15 in one of them fails here or in
//! `make vectors-check`.
#![cfg(test)]

use std::path::PathBuf;

use serde_json::Value;
use snailfish_protocol::export::{self, CheckError, Header};
use snailfish_protocol::wire::{OutEntry, RepairItem};

fn cases() -> Vec<Value> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/export.json");
    let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    v["cases"].as_array().unwrap().clone()
}

fn file(name: &str) -> Vec<u8> {
    cases().into_iter().find(|c| c["name"] == name).unwrap()["file"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec()
}

#[test]
fn each_case_gets_its_verdict() {
    let cases = cases();
    assert!(cases.len() >= 15);
    for c in &cases {
        let name = c["name"].as_str().unwrap();
        let bytes = c["file"].as_str().unwrap().as_bytes();
        let form = export::parse(bytes);
        assert_eq!(
            form.is_ok(),
            c["valid_form"].as_bool().unwrap(),
            "{name}: {form:?}"
        );
        if let Ok(f) = form {
            let log = export::check_log(&f);
            assert_eq!(
                log.is_ok(),
                c["valid_log"].as_bool().unwrap(),
                "{name}: {log:?}"
            );
        }
    }
}

#[test]
fn check_log_names_the_failure() {
    let f = export::parse(&file("head-digest-wrong")).unwrap();
    assert_eq!(export::check_log(&f).unwrap_err(), CheckError::Digest);
    let f = export::parse(&file("header-wrong-app")).unwrap();
    assert!(matches!(export::check_log(&f), Err(CheckError::Genesis(_))));
    let f = export::parse(&file("tampered-payload")).unwrap();
    assert!(matches!(
        export::check_log(&f),
        Err(CheckError::Chain(3, _))
    ));
}

/// A file that `write` makes from a parsed file is the same file, so an
/// engine and the user page write what the import reads.
#[test]
fn write_round_trips_each_valid_file() {
    for name in ["full", "change-and-snapshot-stubs"] {
        let bytes = file(name);
        let f = export::parse(&bytes).unwrap();
        let staged = export::check_log(&f).unwrap();
        assert_eq!(staged.len(), f.entries.len());
        let out: Vec<(u64, OutEntry)> = f
            .entries
            .iter()
            .map(|(p, e)| {
                let e = match e {
                    RepairItem::Envelope(r) => OutEntry::Envelope(r.json.clone()),
                    RepairItem::Stub(s) => OutEntry::Stub(s.clone()),
                    RepairItem::Invalid(_) => unreachable!(),
                };
                (*p, e)
            })
            .collect();
        let header = Header { ..f.header.clone() };
        assert_eq!(export::write(&header, &out).unwrap(), bytes, "{name}");
    }
}
