//! Fuzz `pae::decode` with arbitrary bytes, and check the round trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::pae;

fuzz_target!(|data: &[u8]| {
    // decode must never panic. If it accepts the bytes, encode must give the
    // same bytes back, so PAE has exactly one encoding for each input.
    if let Some((payload_type, payload)) = pae::decode(data) {
        assert_eq!(pae::encode(payload_type, payload), data);
    }
});
