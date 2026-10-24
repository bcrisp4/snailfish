//! Snailfish protocol: record types, envelopes, signature input, verification,
//! log digests and space state.
//!
//! This crate does no I/O. The relay and the sync engine both depend on it, so
//! both apply the same verification rules (DESIGN.md "Code layout"). The Quint
//! models in `specs/` are the source of truth for its behaviour.

pub mod pae;
