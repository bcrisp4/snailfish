//! `check_builder` links `webauthn-rs`. Run with `--features webauthn`.

#![cfg(all(test, feature = "webauthn"))]

use snailfish_relay::passkey::check_builder;

/// Without this, a relay with an authority that cannot be a `WebAuthn`
/// relying party would start, and passkey sign-in would fail later.
#[test]
fn check_builder_refuses_an_invalid_authority() {
    assert!(check_builder("relay.example.net").is_ok());
    assert!(check_builder("relay.example.net:8443").is_ok());
    assert!(check_builder("").is_err());
    assert!(check_builder("bad host").is_err());
}
