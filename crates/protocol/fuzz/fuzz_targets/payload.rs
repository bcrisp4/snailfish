//! Fuzz the strict payload parser with arbitrary bytes ([WIR-4]).
//! Input: a payload type, a NUL byte, then the payload bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::records;

fuzz_target!(|data: &[u8]| {
    let (ptype, payload) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (&b"snailfish.change.v1"[..], data),
    };
    let Ok(ptype) = std::str::from_utf8(ptype) else {
        return;
    };
    // The parser must never panic. If it accepts a payload, the payload is
    // valid UTF-8 JSON, because rule 1 refuses every other byte string.
    if records::parse_payload(ptype, payload).is_ok()
        || records::parse_statement(ptype, payload).is_ok()
    {
        assert!(std::str::from_utf8(payload).is_ok());
    }
});
