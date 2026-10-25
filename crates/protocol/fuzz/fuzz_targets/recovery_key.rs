//! Fuzz the recovery key reader with arbitrary text (`PROTOCOL.md` section 9).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::recovery;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // The reader must never panic. If it accepts a text, the display form of
    // the secret must read back to the same secret.
    if let Ok(secret) = recovery::parse(text) {
        assert_eq!(recovery::parse(&recovery::display(&secret)), Ok(secret));
    }
});
