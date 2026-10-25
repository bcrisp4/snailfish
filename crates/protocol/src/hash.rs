//! Record hash, entry hash and log digest (`PROTOCOL.md` section 5).

use crate::encoding::{Hash32, hash_frame, u64be};

/// The record hash: [LOG-3]. It covers the decoded payload type, payload and
/// signature, so a change of the envelope layout or the `keyid` does not
/// change it ([WIR-3]).
#[must_use]
pub fn record_hash(payload_type: &str, payload: &[u8], sig: &[u8; 64]) -> Hash32 {
    hash_frame(&[
        b"snailfish.record-hash.v1",
        payload_type.as_bytes(),
        payload,
        sig,
    ])
}

/// The entry hash: [LOG-4]. `change_id` is `None` for each record that is not
/// a change. A stub holds the same three inputs ([CMP-1]).
#[must_use]
pub fn entry_hash(
    payload_type: &str,
    change_id: Option<&[u8; 16]>,
    record_hash: &Hash32,
) -> Hash32 {
    let cid: &[u8] = change_id.map_or(&[], |c| c.as_slice());
    hash_frame(&[
        b"snailfish.entry-hash.v1",
        payload_type.as_bytes(),
        cid,
        record_hash,
    ])
}

/// The log digest at position 0: [LOG-5].
#[must_use]
pub fn digest0(log_id: &[u8; 16]) -> Hash32 {
    hash_frame(&[b"snailfish.log-root.v1", log_id])
}

/// The log digest at position `n` from the digest at `n - 1`: [LOG-5].
#[must_use]
pub fn digest_next(prev: &Hash32, n: u64, entry_hash: &Hash32) -> Hash32 {
    hash_frame(&[b"snailfish.log-digest.v1", prev, &u64be(n), entry_hash])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without the position in the digest input, a relay could move an entry
    /// to another position and keep the digest.
    #[test]
    fn digest_depends_on_position_previous_digest_and_entry() {
        let d0 = digest0(&[1; 16]);
        let e = [2; 32];
        let d1 = digest_next(&d0, 1, &e);
        assert_ne!(d1, digest_next(&d0, 2, &e));
        assert_ne!(d1, digest_next(&digest0(&[3; 16]), 1, &e));
        assert_ne!(d1, digest_next(&d0, 1, &[4; 32]));
    }

    /// A stub with another change ID must not give the same entry hash
    /// (C50): the digest authenticates the change ID.
    #[test]
    fn entry_hash_covers_change_id_and_type() {
        let r = [5; 32];
        let a = entry_hash("snailfish.change.v1", Some(&[1; 16]), &r);
        assert_ne!(a, entry_hash("snailfish.change.v1", Some(&[2; 16]), &r));
        assert_ne!(a, entry_hash("snailfish.change.v1", None, &r));
        assert_ne!(a, entry_hash("snailfish.snapshot.v1", Some(&[1; 16]), &r));
    }
}
