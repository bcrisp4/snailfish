//! Snailfish protocol: record types, envelopes, signature input, verification,
//! log digests and space state.
//!
//! This crate does no I/O. The relay and the sync engine both depend on it, so
//! both apply the same verification rules (DESIGN.md "Code layout"). The Quint
//! models in `specs/` are the source of truth for its behaviour. `PROTOCOL.md`
//! gives the exact bytes.

pub mod encoding;
pub mod enroll;
pub mod envelope;
pub mod hash;
pub mod keys;
pub mod mailbox;
pub mod pae;
pub mod records;
pub mod recovery;
pub mod repair;
pub mod request;
pub mod sig;
pub mod space;
pub mod strict;
pub mod wire;
pub mod write;

#[cfg(test)]
mod testutil {
    /// Flip bit `n` of `bytes`, with `n` taken modulo the bit length. Do
    /// nothing for an empty slice.
    pub fn flip_bit(bytes: &mut [u8], n: usize) {
        let Some(n) = n.checked_rem(bytes.len().wrapping_mul(8)) else {
            return;
        };
        bytes[n / 8] ^= 1 << (n % 8);
    }
}
