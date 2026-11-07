//! Fuzz the deletion and import request readers (`PROTOCOL.md` 10.12 and
//! 10.13).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::wire::{self, OutEntry, RepairItem};

fuzz_target!(|data: &[u8]| {
    if let Ok(d) = wire::parse_delete(data)
        && let Ok(s) = &d.statement
    {
        let again = wire::parse_delete(&wire::delete_body(&s.json, d.setup.as_ref())).unwrap();
        assert_eq!(again, d);
    }
    if let Ok(s) = wire::parse_import_start(data, 100) {
        assert!((1..=100).contains(&s.entries.len()));
        // A start body with only stubs and envelopes writes back the same.
        let out: Option<Vec<(u64, OutEntry)>> = s
            .entries
            .iter()
            .map(|(p, e)| match e {
                RepairItem::Envelope(r) => Some((*p, OutEntry::Envelope(r.json.clone()))),
                RepairItem::Stub(x) => Some((*p, OutEntry::Stub(x.clone()))),
                RepairItem::Invalid(_) => None,
            })
            .collect();
        if let Some(out) = out {
            let again = wire::parse_import_start(
                &wire::import_start_body(&s.setup, &s.device, &out).unwrap(),
                100,
            )
            .unwrap();
            assert_eq!(again, s);
        }
    }
});
