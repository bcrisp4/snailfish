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
        for (_, e) in f.entries {
            if let wire::FetchEntry::Envelope(r) = e {
                assert!(snailfish_protocol::envelope::Envelope::parse(r.json.as_bytes()).is_ok());
            }
        }
    }
    let _ = wire::parse_append_response(data);
    let _ = wire::parse_info(data);
    let _ = wire::parse_error(data);
});
