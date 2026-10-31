//! Fuzz the repair request readers (`PROTOCOL.md` 10.9).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::wire::{self, RepairItem};

fn check_entries(entries: &[(u64, RepairItem)]) {
    // An accepted envelope keeps its exact JSON text, and the text parses to
    // the same envelope, so the relay stages what it checked.
    for (_, item) in entries {
        if let RepairItem::Envelope(r) = item {
            let again = snailfish_protocol::envelope::Envelope::parse(r.json.as_bytes());
            assert_eq!(again.as_ref(), Ok(&r.envelope));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = wire::parse_repair_start(data, 100) {
        assert!((1..=100).contains(&s.entries.len()));
        check_entries(&s.entries);
    }
    if let Ok(c) = wire::parse_repair_chunk(data, 100) {
        assert!((1..=100).contains(&c.entries.len()));
        check_entries(&c.entries);
    }
    if let Ok(f) = wire::parse_repair_finish(data) {
        assert_eq!(wire::parse_repair_finish(&wire::repair_finish_body(&f)), Ok(f));
    }
});
