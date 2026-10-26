//! `WebAuthn` link check for the container build (feature `webauthn`).
//!
//! M5 adds passkey sign-in. This function links `webauthn-rs` with the
//! vendored OpenSSL now, so a missing build prerequisite shows up early.

use openssl as _;
use webauthn_rs::WebauthnBuilder;
use webauthn_rs::prelude::Url;

/// Build a `WebauthnBuilder` for the configured authority.
///
/// # Errors
///
/// A text that names the failed step. It holds no identifier.
pub fn check_builder(authority: &str) -> Result<(), String> {
    let host = authority.split(':').next().unwrap_or(authority);
    let origin = Url::parse(&format!("https://{authority}"))
        .map_err(|_| "the authority is not a valid origin".to_owned())?;
    WebauthnBuilder::new(host, &origin)
        .map(|_| ())
        .map_err(|_| "the authority is not a valid WebAuthn relying party".to_owned())
}
