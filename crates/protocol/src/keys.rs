//! App keys, change encryption, key commitments, IDs and key sets
//! (`PROTOCOL.md` 2.2, 6.2, 7.2 and 7.3).

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _};
use sha2::{Digest as _, Sha256};

use crate::encoding::{Hash32, frame, hash_frame, u64be};

type Kem = hpke::kem::XWing;
type Kdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// The size of an X-Wing public key.
pub const SEAL_PK_LEN: usize = 1216;
/// The size of an X-Wing encapsulation.
pub const ENC_LEN: usize = 1120;
/// The size of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// The size of the AEAD tag.
pub const TAG_LEN: usize = 16;

/// A refused or failed crypto operation. The variants carry no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The operating system CSPRNG failed.
    Random,
    /// The X-Wing public key does not decode.
    BadSealKey,
    /// The sealed bytes have the wrong length.
    BadLength,
    /// The AEAD or HPKE tag does not verify.
    Decrypt,
    /// An opened key does not match its commitment.
    Commitment,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Random => "the operating system CSPRNG failed",
            Self::BadSealKey => "the X-Wing public key does not decode",
            Self::BadLength => "the sealed bytes have the wrong length",
            Self::Decrypt => "decryption failed",
            Self::Commitment => "an opened key does not match its commitment",
        })
    }
}

impl std::error::Error for KeyError {}

/// Fill `buf` from the operating system CSPRNG.
///
/// # Errors
///
/// [`KeyError::Random`] if the CSPRNG fails. The caller must not continue
/// with a partial buffer.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], KeyError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| KeyError::Random)?;
    Ok(out)
}

/// The device ID of a device: `PROTOCOL.md` 2.2.
#[must_use]
pub fn device_id(sign_pk: &[u8; 32], seal_pk: &[u8]) -> Hash32 {
    hash_frame(&[b"snailfish.device-id.v1", sign_pk, seal_pk])
}

/// The recovery ID of a recovery key: `PROTOCOL.md` 2.2.
#[must_use]
pub fn recovery_id(sign_pk: &[u8; 32], seal_pk: &[u8]) -> Hash32 {
    hash_frame(&[b"snailfish.recovery-id.v1", sign_pk, seal_pk])
}

/// The key commitment of the app key of one epoch: `PROTOCOL.md` 6.2.
#[must_use]
pub fn key_commitment(log_id: &[u8; 16], epoch: u64, key: &[u8; 32]) -> Hash32 {
    hash_frame(&[b"snailfish.key-commitment.v1", log_id, &u64be(epoch), key])
}

/// The X-Wing public key of a 32-byte private key seed.
#[must_use]
pub fn seal_public(seed: &[u8; 32]) -> Vec<u8> {
    // from_bytes only checks the length, and the seed has the right length.
    match <Kem as hpke::Kem>::PrivateKey::from_bytes(seed) {
        Ok(sk) => Kem::sk_to_pk(&sk).to_bytes().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// The associated data of a change: `PROTOCOL.md` 7.2.
#[must_use]
pub fn change_aad(log_id: &[u8; 16], epoch: u64, change_id: &[u8; 16], author: &Hash32) -> Vec<u8> {
    frame(&[
        b"snailfish.change.v1",
        log_id,
        &u64be(epoch),
        change_id,
        author,
    ])
}

/// The associated data of a snapshot: `PROTOCOL.md` 7.2.
#[must_use]
pub fn snapshot_aad(
    log_id: &[u8; 16],
    epoch: u64,
    author: &Hash32,
    state_position: u64,
    state_digest: &Hash32,
) -> Vec<u8> {
    frame(&[
        b"snailfish.snapshot.v1",
        log_id,
        &u64be(epoch),
        author,
        &u64be(state_position),
        state_digest,
    ])
}

/// Encrypt with an app key and a given nonce: `nonce || AEAD output`.
/// Use [`encrypt`] outside tests, so that each change has a new random nonce.
#[must_use]
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut out = nonce.to_vec();
    // Encryption fails only for a plaintext longer than about 256 GiB.
    if let Ok(ct) = cipher.encrypt(
        &XNonce::from(*nonce),
        Payload {
            msg: plaintext,
            aad,
        },
    ) {
        out.extend_from_slice(&ct);
    }
    out
}

/// Encrypt with an app key and a random 24-byte nonce (`PROTOCOL.md` 7.2).
///
/// # Errors
///
/// [`KeyError::Random`].
pub fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
    Ok(encrypt_with_nonce(key, &random_bytes()?, aad, plaintext))
}

/// Decrypt `nonce || AEAD output` with an app key.
///
/// # Errors
///
/// [`KeyError::BadLength`] or [`KeyError::Decrypt`].
pub fn decrypt(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
    if ciphertext.len() < NONCE_LEN.saturating_add(TAG_LEN) {
        return Err(KeyError::BadLength);
    }
    let (nonce, body) = ciphertext.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KeyError::BadLength)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(&XNonce::from(nonce), Payload { msg: body, aad })
        .map_err(|_| KeyError::Decrypt)
}

/// The HPKE `info` of a key set: `PROTOCOL.md` 7.3.
#[must_use]
pub fn key_set_info(log_id: &[u8; 16], recipient: &Hash32, epochs: &[u64]) -> Vec<u8> {
    let encoded: Vec<[u8; 8]> = epochs.iter().map(|e| u64be(*e)).collect();
    let mut parts: Vec<&[u8]> = vec![b"snailfish.keyset.v1", log_id, recipient];
    parts.extend(encoded.iter().map(<[u8; 8]>::as_slice));
    frame(&parts)
}

/// The length of the `sealed` bytes of a key set with `epochs` keys.
#[must_use]
pub fn sealed_len(epochs: usize) -> usize {
    ENC_LEN
        .saturating_add(epochs.saturating_mul(32))
        .saturating_add(TAG_LEN)
}

/// A deterministic generator that the seal functions use. It expands 64
/// bytes of seed with SHA-256 in counter mode. X-Wing encapsulation reads
/// exactly 64 bytes, so in practice the output is the seed itself.
struct SeededRng {
    seed: [u8; 64],
    counter: u64,
    buf: Vec<u8>,
}

impl SeededRng {
    fn new(seed: [u8; 64]) -> Self {
        Self {
            seed,
            counter: 0,
            buf: seed.to_vec(),
        }
    }
}

impl TryRng for SeededRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for slot in dst.iter_mut() {
            if self.buf.is_empty() {
                self.counter = self.counter.wrapping_add(1);
                self.buf = Sha256::digest(frame(&[
                    b"snailfish.seeded-rng.v1",
                    &self.seed,
                    &u64be(self.counter),
                ]))
                .to_vec();
            }
            *slot = self.buf.remove(0);
        }
        Ok(())
    }
}

impl TryCryptoRng for SeededRng {}

/// Seal the app keys of `epochs` to one recipient with 64 bytes of
/// encapsulation randomness. Use [`seal_key_set`] outside tests.
///
/// # Errors
///
/// [`KeyError::BadSealKey`] or [`KeyError::BadLength`].
pub fn seal_key_set_with_randomness(
    randomness: [u8; 64],
    recipient_seal_pk: &[u8],
    log_id: &[u8; 16],
    recipient: &Hash32,
    epochs: &[u64],
    keys: &[[u8; 32]],
) -> Result<Vec<u8>, KeyError> {
    if keys.len() != epochs.len() || keys.is_empty() {
        return Err(KeyError::BadLength);
    }
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient_seal_pk)
        .map_err(|_| KeyError::BadSealKey)?;
    let plaintext: Vec<u8> = keys.iter().flatten().copied().collect();
    let info = key_set_info(log_id, recipient, epochs);
    let (enc, ct) = hpke::single_shot_seal_with_rng::<HpkeAead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &info,
        &plaintext,
        b"",
        &mut SeededRng::new(randomness),
    )
    .map_err(|_| KeyError::BadSealKey)?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Seal the app keys of `epochs` to one recipient (`PROTOCOL.md` 7.3).
///
/// # Errors
///
/// [`KeyError::Random`], [`KeyError::BadSealKey`] or [`KeyError::BadLength`].
pub fn seal_key_set(
    recipient_seal_pk: &[u8],
    log_id: &[u8; 16],
    recipient: &Hash32,
    epochs: &[u64],
    keys: &[[u8; 32]],
) -> Result<Vec<u8>, KeyError> {
    seal_key_set_with_randomness(
        random_bytes()?,
        recipient_seal_pk,
        log_id,
        recipient,
        epochs,
        keys,
    )
}

/// Open a key set with the recipient's X-Wing private key seed. Return one
/// app key for each epoch in `epochs`, in order.
///
/// The caller must check each key against its commitment before use, because
/// HPKE base mode does not authenticate the sender (DESIGN.md "Cryptography").
///
/// # Errors
///
/// [`KeyError::BadLength`] or [`KeyError::Decrypt`].
pub fn open_key_set(
    seal_seed: &[u8; 32],
    log_id: &[u8; 16],
    recipient: &Hash32,
    epochs: &[u64],
    sealed: &[u8],
) -> Result<Vec<[u8; 32]>, KeyError> {
    if sealed.len() != sealed_len(epochs.len()) || epochs.is_empty() {
        return Err(KeyError::BadLength);
    }
    let (enc, ct) = sealed.split_at(ENC_LEN);
    let sk =
        <Kem as hpke::Kem>::PrivateKey::from_bytes(seal_seed).map_err(|_| KeyError::BadLength)?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| KeyError::BadLength)?;
    let info = key_set_info(log_id, recipient, epochs);
    let plain =
        hpke::single_shot_open::<HpkeAead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &info, ct, b"")
            .map_err(|_| KeyError::Decrypt)?;
    Ok(plain.as_chunks::<32>().0.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_refuses_changed_associated_data() {
        let key = [1u8; 32];
        let ct = encrypt_with_nonce(&key, &[2; 24], b"aad", b"hello");
        assert_eq!(decrypt(&key, b"aad", &ct), Ok(b"hello".to_vec()));
        assert_eq!(decrypt(&key, b"aae", &ct), Err(KeyError::Decrypt));
        assert_eq!(decrypt(&key, b"aad", &ct[..39]), Err(KeyError::BadLength));
    }

    /// A key set sealed for one log, recipient or epoch list must not open
    /// for another. Without this, a relay could move a key set between
    /// records.
    #[test]
    fn key_set_binds_log_recipient_and_epochs() {
        let seed = [9u8; 32];
        let pk = seal_public(&seed);
        let rid = [3u8; 32];
        let sealed = seal_key_set_with_randomness(
            [4; 64],
            &pk,
            &[5; 16],
            &rid,
            &[1, 2],
            &[[6; 32], [7; 32]],
        )
        .unwrap();
        assert_eq!(sealed.len(), sealed_len(2));
        assert_eq!(
            open_key_set(&seed, &[5; 16], &rid, &[1, 2], &sealed),
            Ok(vec![[6; 32], [7; 32]])
        );
        assert_eq!(
            open_key_set(&seed, &[0; 16], &rid, &[1, 2], &sealed),
            Err(KeyError::Decrypt)
        );
        assert_eq!(
            open_key_set(&seed, &[5; 16], &[0; 32], &[1, 2], &sealed),
            Err(KeyError::Decrypt)
        );
        assert_eq!(
            open_key_set(&seed, &[5; 16], &rid, &[1, 3], &sealed),
            Err(KeyError::Decrypt)
        );
        assert_eq!(
            open_key_set(&[8; 32], &[5; 16], &rid, &[1, 2], &sealed),
            Err(KeyError::Decrypt)
        );
        assert_eq!(
            open_key_set(&seed, &[5; 16], &rid, &[1], &sealed),
            Err(KeyError::BadLength)
        );
    }
}
