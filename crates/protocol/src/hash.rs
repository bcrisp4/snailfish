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

// No Kani harness: each function here is one SHA-256 call, and CBMC cannot
// finish it. The frame layout that feeds the hash is proved in `encoding.rs`
// (`frame_layout`). The property tests below cover the hash inputs.
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Without the frame, a relay could move bytes between the payload
        /// type and the payload and keep the record hash ([LOG-3]).
        #[test]
        fn record_hash_separates_type_and_payload(
            t in "[a-z.0-9]{1,24}",
            payload in proptest::collection::vec(any::<u8>(), 0..32),
            sig in any::<[u8; 32]>(),
            split in 0usize..24,
        ) {
            let sig = [sig, sig].concat().try_into().unwrap();
            let cut = split.min(t.len().wrapping_sub(1));
            let (head, tail) = t.split_at(cut);
            let moved = [tail.as_bytes(), &payload].concat();
            prop_assert_ne!(
                record_hash(&t, &payload, &sig),
                record_hash(head, &moved, &sig)
            );
        }

        /// A change of any one input changes the record hash ([LOG-3]).
        #[test]
        fn record_hash_covers_each_input(
            t in "[a-z.0-9]{0,24}",
            payload in proptest::collection::vec(any::<u8>(), 0..32),
            sig in any::<[u8; 32]>(),
            byte in 0usize..64,
            bit in 0u8..8,
        ) {
            let sig: [u8; 64] = [sig, sig].concat().try_into().unwrap();
            let base = record_hash(&t, &payload, &sig);
            let mut sig2 = sig;
            sig2[byte] ^= 1 << bit;
            prop_assert_ne!(base, record_hash(&t, &payload, &sig2));
            let mut payload2 = payload.clone();
            payload2.push(0);
            prop_assert_ne!(base, record_hash(&t, &payload2, &sig));
            prop_assert_ne!(base, record_hash(&format!("{t}x"), &payload, &sig));
        }

        /// The entry hash covers the type, the change ID and the record hash
        /// ([LOG-4]). `None` and each `Some` give different hashes.
        #[test]
        fn entry_hash_covers_each_input(
            t in "[a-z.0-9]{1,24}",
            cid in any::<[u8; 16]>(),
            rh in any::<[u8; 32]>(),
            byte in 0usize..32,
            bit in 0u8..8,
        ) {
            let base = entry_hash(&t, Some(&cid), &rh);
            let mut rh2 = rh;
            rh2[byte] ^= 1 << bit;
            prop_assert_ne!(base, entry_hash(&t, Some(&cid), &rh2));
            let mut cid2 = cid;
            cid2[byte % 16] ^= 1 << bit;
            prop_assert_ne!(base, entry_hash(&t, Some(&cid2), &rh));
            prop_assert_ne!(base, entry_hash(&t, None, &rh));
            prop_assert_ne!(base, entry_hash(&format!("{t}x"), Some(&cid), &rh));
        }

        /// A position or a previous digest or an entry change moves the
        /// digest ([LOG-5]). The root depends on the log ID.
        #[test]
        fn digest_covers_each_input(
            log in any::<[u8; 16]>(),
            log2 in any::<[u8; 16]>(),
            prev in any::<[u8; 32]>(),
            prev2 in any::<[u8; 32]>(),
            e in any::<[u8; 32]>(),
            e2 in any::<[u8; 32]>(),
            n in any::<u64>(),
            n2 in any::<u64>(),
        ) {
            prop_assert_eq!(log == log2, digest0(&log) == digest0(&log2));
            let base = digest_next(&prev, n, &e);
            prop_assert_eq!(base, digest_next(&prev, n, &e));
            prop_assert_eq!(n == n2, base == digest_next(&prev, n2, &e));
            prop_assert_eq!(prev == prev2, base == digest_next(&prev2, n, &e));
            prop_assert_eq!(e == e2, base == digest_next(&prev, n, &e2));
        }
    }

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
