//! Fuzz the export file reader (`PROTOCOL.md` section 15, [FRK-3]).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::export;
use snailfish_protocol::wire::{OutEntry, RepairItem};

fuzz_target!(|data: &[u8]| {
    let Ok(f) = export::parse(data) else { return };
    // Section 15: dense positions from 1 to head.position.
    assert_eq!(f.entries.len() as u64, f.header.head.position);
    for (i, (p, _)) in f.entries.iter().enumerate() {
        assert_eq!(*p, i as u64 + 1);
    }
    // The chain check never panics, and a file that passes it writes back
    // to a file that parses to the same entries.
    if export::check_log(&f).is_ok() {
        let out: Vec<(u64, OutEntry)> = f
            .entries
            .iter()
            .map(|(p, e)| match e {
                RepairItem::Envelope(r) => (*p, OutEntry::Envelope(r.json.clone())),
                RepairItem::Stub(s) => (*p, OutEntry::Stub(s.clone())),
                RepairItem::Invalid(_) => unreachable!("check_log refuses an invalid envelope"),
            })
            .collect();
        let again = export::parse(&export::write(&f.header, &out).unwrap()).unwrap();
        assert_eq!(again, f);
    }
});
