//! Fuzz the enrollment code and payload readers with arbitrary text
//! (`PROTOCOL.md` 11.1).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::enroll;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // The readers must never panic. An accepted code or payload reads back
    // to the same value from its writer form.
    if let Ok(session) = enroll::parse_code(text) {
        assert_eq!(enroll::parse_code(&enroll::display(&session)), Ok(session));
    }
    if let Ok(p) = enroll::parse_payload(text) {
        assert_eq!(enroll::parse_payload(&enroll::payload(&p)), Ok(p));
    }
});
