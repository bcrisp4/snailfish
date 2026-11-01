//! Fuzz the enrollment session bodies with arbitrary bytes
//! (`PROTOCOL.md` 10.10). The relay parses the writes of an unsigned
//! caller, and each device parses the session object from the relay.
#![no_main]

use libfuzzer_sys::fuzz_target;
use snailfish_protocol::enroll::Role;
use snailfish_protocol::mailbox::{self, Slot, Write};

const TENANT: &str = "t_00112233445566778899aabbccddeeff";

fuzz_target!(|data: &[u8]| {
    // The parsers must never panic. An accepted write is a message of the
    // route's own writer, and its stored text is valid JSON.
    for (role, tenant) in [(Role::New, None), (Role::Trusted, Some(TENANT))] {
        if let Ok(Write::Message(slot, text)) = mailbox::parse_write(data, role, tenant) {
            assert_eq!(slot.writer(), role);
            assert!(mailbox::same_message(&text, &text));
            assert!(slot != Slot::TrustedDone || role == Role::Trusted);
        }
    }
    if let Ok(session) = mailbox::parse_open(data) {
        assert_eq!(
            mailbox::parse_open(&mailbox::open_body(&session)),
            Ok(session)
        );
    }
    let _ = mailbox::parse_session(data);
});
