//! Fuzz the HTTP API body readers (`PROTOCOL.md` section 10).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::wire;

fuzz_target!(|data: &[u8]| {
    // Each accepted append item keeps its exact JSON text, and the text
    // parses to the same envelope, so the relay stores what it checked.
    if let Ok(items) = wire::parse_append(data, 100) {
        for item in items.into_iter().flatten() {
            let again = snailfish_protocol::envelope::Envelope::parse(item.json.as_bytes());
            assert_eq!(again.as_ref(), Ok(&item.envelope));
        }
    }
    let _ = wire::parse_genesis(data);
    if let Ok(f) = wire::parse_fetch(data) {
        for (p, e) in f.entries {
            match e {
                wire::FetchEntry::Envelope(r) => {
                    assert!(
                        snailfish_protocol::envelope::Envelope::parse(r.json.as_bytes()).is_ok()
                    );
                }
                // [CMP-1]: a stub that the reader takes reads back the same
                // from the JSON of its writer.
                wire::FetchEntry::Stub(s) => {
                    let head = wire::Head {
                        position: p,
                        digest: [0; 32],
                    };
                    let body = wire::fetch_response(
                        &[(p, wire::OutEntry::Stub(s.clone()))],
                        &head,
                        false,
                        false,
                    )
                    .unwrap();
                    let back = wire::parse_fetch(&body).unwrap();
                    assert_eq!(back.entries[0].1, wire::FetchEntry::Stub(s));
                }
            }
        }
    }
    let _ = wire::parse_append_response(data);
    let _ = wire::parse_info(data);
    let _ = wire::parse_error(data);
    let _ = wire::parse_repair_started(data);
    let _ = wire::parse_repair_next(data);
    let _ = wire::parse_repair_finished(data);
});
