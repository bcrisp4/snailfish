//! Snailfish sync engine.
//!
//! A synchronous state machine with no network I/O: it builds each request and
//! reads each response, and the host app sends the bytes (DESIGN.md "Sync
//! engine"). `specs/delivery/model.qnt` is the source of truth for the
//! delivery rules that this crate implements.

pub use snailfish_protocol as protocol;
