//! Snailfish relay.
//!
//! The relay orders records and enforces quotas. It verifies records with the
//! same `snailfish-protocol` crate as the engine, and it holds no key that
//! decrypts app data (DESIGN.md "Crypto boundary").
//!
//! [`core`] holds all SQLite and protocol logic and needs no async runtime.
//! [`http`] is the thin HTTP edge. Each handler calls the core once, inside
//! `spawn_blocking`. [`ops`] holds the operator commands: backup, restore
//! and the restore hold.

pub mod core;
pub mod http;
pub mod ops;
pub mod store;

#[cfg(feature = "webauthn")]
pub mod passkey;
