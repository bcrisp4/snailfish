//! UniFFI bindings for the Snailfish sync engine (Swift and Python).
//!
//! UniFFI is added in M1. This crate holds no logic: each function forwards to
//! `snailfish-engine`.

pub use snailfish_engine as engine;
