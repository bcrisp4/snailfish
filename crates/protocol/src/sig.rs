//! Ed25519 signatures over the DSSE PAE (`PROTOCOL.md` 7.1, [WIR-1]).

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::pae;

/// An Ed25519 public key that passed the canonical-encoding check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

/// A refused key or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    /// The bytes do not decode to a curve point.
    BadKey,
    /// The bytes are a non-canonical encoding of the decoded point.
    NonCanonicalKey,
    /// The point has small order. `verify_strict` refuses each signature
    /// with it, so a record must not introduce it.
    WeakKey,
    /// `verify_strict` refuses the signature.
    BadSignature,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadKey => "public key is not a curve point",
            Self::NonCanonicalKey => "public key encoding is not canonical",
            Self::WeakKey => "public key has small order",
            Self::BadSignature => "signature does not verify",
        })
    }
}

impl std::error::Error for SigError {}

impl PublicKey {
    /// Decode a public key.
    ///
    /// `verify_strict` accepts non-canonical public key encodings, so this
    /// function refuses bytes that differ from the canonical encoding of
    /// the decoded point (DESIGN.md "Cryptography"). It also refuses a key of
    /// small order (`PROTOCOL.md` 7.1).
    ///
    /// # Errors
    ///
    /// [`SigError::BadKey`], [`SigError::NonCanonicalKey`] or
    /// [`SigError::WeakKey`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SigError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| SigError::BadKey)?;
        if key.to_edwards().compress().as_bytes() != bytes {
            return Err(SigError::NonCanonicalKey);
        }
        if key.is_weak() {
            return Err(SigError::WeakKey);
        }
        Ok(Self(key))
    }

    /// The 32 bytes of the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify `sig` over raw `msg` with `verify_strict`.
    ///
    /// # Errors
    ///
    /// [`SigError::BadSignature`].
    pub fn verify_raw(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), SigError> {
        self.0
            .verify_strict(msg, &Signature::from_bytes(sig))
            .map_err(|_| SigError::BadSignature)
    }

    /// Verify a record signature over `PAE(payload_type, payload)`.
    ///
    /// # Errors
    ///
    /// [`SigError::BadSignature`].
    pub fn verify_record(
        &self,
        payload_type: &str,
        payload: &[u8],
        sig: &[u8; 64],
    ) -> Result<(), SigError> {
        self.verify_raw(&pae::encode(payload_type, payload), sig)
    }
}

/// An Ed25519 signing key.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// A signing key from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The public key.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign raw bytes.
    #[must_use]
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }

    /// Sign `PAE(payload_type, payload)`.
    #[must_use]
    pub fn sign_record(&self, payload_type: &str, payload: &[u8]) -> [u8; 64] {
        self.sign_raw(&pae::encode(payload_type, payload))
    }
}

// No Kani harness: every function here runs Ed25519 or SHA-256 arithmetic,
// and CBMC cannot finish it. The property tests below and the C2SP CCTV
// vectors cover them. The PAE bytes that feed the signature are proved in
// `pae.rs`.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_errors_name_the_cause() {
        assert_eq!(SigError::WeakKey.to_string(), "public key has small order");
    }
    use proptest::prelude::*;

    proptest! {
        /// Each key from a seed passes the key check, and sign then verify
        /// succeeds. A bit flip in the message, the signature or the payload
        /// type is refused ([WIR-1]).
        #[test]
        fn sign_verify_round_trip_and_refusal(
            seed in any::<[u8; 32]>(),
            msg in proptest::collection::vec(any::<u8>(), 0..64),
            sig_bit in 0usize..512,
            msg_bit in any::<usize>(),
        ) {
            let sk = SecretKey::from_seed(&seed);
            let pk = PublicKey::from_bytes(&sk.public()).unwrap();
            prop_assert_eq!(pk.to_bytes(), sk.public());
            let sig = sk.sign_raw(&msg);
            prop_assert_eq!(pk.verify_raw(&msg, &sig), Ok(()));

            let mut bad_sig = sig;
            bad_sig[sig_bit / 8] ^= 1 << (sig_bit % 8);
            prop_assert_eq!(pk.verify_raw(&msg, &bad_sig), Err(SigError::BadSignature));

            if !msg.is_empty() {
                let mut bad_msg = msg.clone();
                crate::testutil::flip_bit(&mut bad_msg, msg_bit);
                prop_assert_eq!(pk.verify_raw(&bad_msg, &sig), Err(SigError::BadSignature));
            }

            let rsig = sk.sign_record("snailfish.change.v1", &msg);
            prop_assert_eq!(pk.verify_record("snailfish.change.v1", &msg, &rsig), Ok(()));
            prop_assert_eq!(
                pk.verify_record("snailfish.change.v2", &msg, &rsig),
                Err(SigError::BadSignature)
            );
            // Another key must not verify the signature.
            let mut other = seed;
            other[0] ^= 1;
            let pk2 = PublicKey::from_bytes(&SecretKey::from_seed(&other).public()).unwrap();
            prop_assert_eq!(pk2.verify_raw(&msg, &sig), Err(SigError::BadSignature));
        }

        /// `from_bytes` never panics on any 32 bytes. It accepts a key only
        /// if the key re-encodes to the same bytes (`PROTOCOL.md` 7.1).
        #[test]
        fn from_bytes_accepts_only_canonical_keys(bytes in any::<[u8; 32]>()) {
            if let Ok(pk) = PublicKey::from_bytes(&bytes) {
                prop_assert_eq!(pk.to_bytes(), bytes);
            }
        }

        /// Setting the high bit of the last byte of a valid key gives a
        /// different point or a refusal, and `from_bytes` returns a key only
        /// when the bytes are canonical.
        #[test]
        fn sign_bit_flip_never_gives_the_same_key(seed in any::<[u8; 32]>()) {
            let good = SecretKey::from_seed(&seed).public();
            let mut flipped = good;
            flipped[31] ^= 0x80;
            if let Ok(pk) = PublicKey::from_bytes(&flipped) {
                prop_assert_eq!(pk.to_bytes(), flipped);
                prop_assert_ne!(flipped, good);
            }
        }
    }

    /// A signature for one payload type must not verify for another
    /// ([WIR-1]).
    #[test]
    fn signature_binds_payload_type() {
        let sk = SecretKey::from_seed(&[7; 32]);
        let pk = PublicKey::from_bytes(&sk.public()).unwrap();
        let sig = sk.sign_record("snailfish.change.v1", b"{}");
        assert_eq!(pk.verify_record("snailfish.change.v1", b"{}", &sig), Ok(()));
        assert_eq!(
            pk.verify_record("snailfish.snapshot.v1", b"{}", &sig),
            Err(SigError::BadSignature)
        );
        assert_eq!(
            pk.verify_record("snailfish.change.v1", b"{ }", &sig),
            Err(SigError::BadSignature)
        );
    }

    /// The identity point has the canonical form 01 00 .. 00 and the
    /// alternative form 01 00 .. 80 (x = -0).
    #[test]
    fn refuses_non_canonical_and_small_order_keys() {
        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        assert_eq!(PublicKey::from_bytes(&canonical), Err(SigError::WeakKey));
        let mut alt = canonical;
        alt[31] = 0x80;
        assert_eq!(PublicKey::from_bytes(&alt), Err(SigError::NonCanonicalKey));
        let good = SecretKey::from_seed(&[3; 32]).public();
        assert!(PublicKey::from_bytes(&good).is_ok());
    }
}
