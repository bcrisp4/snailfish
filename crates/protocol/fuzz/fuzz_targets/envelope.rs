//! Fuzz the envelope reader with arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::envelope::Envelope;

fuzz_target!(|data: &[u8]| {
    // The reader must never panic. If it accepts an envelope, the writer
    // form must parse back to the same envelope, so the record hash does not
    // depend on the layout ([WIR-3]).
    if let Ok(env) = Envelope::parse(data) {
        let again = Envelope::parse(env.to_json("k").as_bytes());
        assert_eq!(again.as_ref(), Ok(&env));
        assert_eq!(again.map(|e| e.record_hash()), Ok(env.record_hash()));
    }
});
