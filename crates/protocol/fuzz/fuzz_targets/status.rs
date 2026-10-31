//! Fuzz the status report reader (`PROTOCOL.md` 10.8).
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::wire;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = wire::parse_status(data) {
        assert_eq!(wire::parse_status(&wire::status_body(&r)), Ok(r));
    }
    let _ = wire::parse_status_response(data);
});
