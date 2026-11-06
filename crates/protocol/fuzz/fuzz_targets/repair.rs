//! Fuzz the repair request readers (`PROTOCOL.md` 10.9).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::space::MemorySpace;
use snailfish_protocol::wire::{self, RepairItem};

fn check_entries(entries: &[(u64, RepairItem)]) {
    // An accepted envelope keeps its exact JSON text, and the text parses to
    // the same envelope, so the relay stages what it checked.
    let view = MemorySpace::new([0; 16]);
    for (_, item) in entries {
        match item {
            RepairItem::Envelope(r) => {
                let again = snailfish_protocol::envelope::Envelope::parse(r.json.as_bytes());
                assert_eq!(again.as_ref(), Ok(&r.envelope));
            }
            // [CMP-1] [LOG-11]: the stub check never panics. A stub that it
            // takes is a change stub with a valid change ID or a snapshot
            // stub with none, and its JSON reads back the same.
            RepairItem::Stub(s) => {
                if let Ok(st) = snailfish_protocol::repair::stub_entry(&view, 1, s) {
                    assert_eq!(
                        st.change_id.is_some(),
                        st.payload_type == "snailfish.change.v1"
                    );
                    let body = format!(
                        r#"{{"session":"00000000000000000000000000000000","entries":[{{"position":1,"stub":{}}}]}}"#,
                        s.to_json()
                    );
                    let back = wire::parse_repair_chunk(body.as_bytes(), 1).unwrap();
                    assert!(matches!(&back.entries[0].1, RepairItem::Stub(x) if x == s));
                }
            }
            RepairItem::Invalid(_) => {}
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
        assert_eq!(
            wire::parse_repair_finish(&wire::repair_finish_body(&f)),
            Ok(f)
        );
    }
});
