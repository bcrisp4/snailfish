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
    /// `verify_strict` refuses the signature.
    BadSignature,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadKey => "public key is not a curve point",
            Self::NonCanonicalKey => "public key encoding is not canonical",
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
    /// the decoded point (DESIGN.md "Cryptography").
    ///
    /// # Errors
    ///
    /// [`SigError::BadKey`] or [`SigError::NonCanonicalKey`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SigError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| SigError::BadKey)?;
        if key.to_edwards().compress().as_bytes() != bytes {
            return Err(SigError::NonCanonicalKey);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn refuses_non_canonical_key_encoding() {
        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        assert!(PublicKey::from_bytes(&canonical).is_ok());
        let mut alt = canonical;
        alt[31] = 0x80;
        assert_eq!(PublicKey::from_bytes(&alt), Err(SigError::NonCanonicalKey));
    }
}
