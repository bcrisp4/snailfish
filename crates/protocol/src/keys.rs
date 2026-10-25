//! App keys, change encryption, key commitments, IDs and key sets
//! (`PROTOCOL.md` 2.2, 6.2, 7.2 and 7.3).

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _};

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
pub fn device_id(sign_pk: &[u8; 32], seal_pk: &[u8; SEAL_PK_LEN]) -> Hash32 {
    hash_frame(&[b"snailfish.device-id.v1", sign_pk, seal_pk])
}

/// The recovery ID of a recovery key: `PROTOCOL.md` 2.2.
#[must_use]
pub fn recovery_id(sign_pk: &[u8; 32], seal_pk: &[u8; SEAL_PK_LEN]) -> Hash32 {
    hash_frame(&[b"snailfish.recovery-id.v1", sign_pk, seal_pk])
}

/// The key commitment of the app key of one epoch: `PROTOCOL.md` 6.2.
#[must_use]
pub fn key_commitment(log_id: &[u8; 16], epoch: u64, key: &[u8; 32]) -> Hash32 {
    hash_frame(&[b"snailfish.key-commitment.v1", log_id, &u64be(epoch), key])
}

/// The X-Wing public key of a 32-byte private key seed.
#[must_use]
pub fn seal_public(seed: &[u8; 32]) -> [u8; SEAL_PK_LEN] {
    let mut out = [0u8; SEAL_PK_LEN];
    // hpke 0.14 `PrivateKey::from_bytes` for X-Wing checks only the length,
    // and a 32-byte seed has the right length, so the error arm is dead.
    // The fixed-size result makes an empty key impossible for callers.
    if let Ok(sk) = <Kem as hpke::Kem>::PrivateKey::from_bytes(seed) {
        out.copy_from_slice(&Kem::sk_to_pk(&sk).to_bytes());
    }
    out
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

/// Encrypt with an app key and a random 24-byte nonce (`PROTOCOL.md` 7.2).
///
/// # Errors
///
/// [`KeyError::Random`].
pub fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
    Ok(seal_aead(key, &random_bytes()?, aad, plaintext))
}

/// Encrypt with an app key and a given nonce: `nonce || AEAD output`.
///
/// Many devices share one app key and no counter, so a nonce that repeats
/// breaks the AEAD. Production code calls [`encrypt`], and this function
/// exists only with the `test-vectors` feature.
#[cfg(any(test, feature = "test-vectors"))]
#[must_use]
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    seal_aead(key, nonce, aad, plaintext)
}

fn seal_aead(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
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

/// Gives the 64 bytes of X-Wing encapsulation randomness to `hpke`, once.
///
/// X-Wing encapsulation reads exactly 64 bytes in one call (`hpke` 0.14). The
/// source never expands its input. Each other read gets zeros and sets
/// `misused`, and [`seal_with`] then refuses the result, so the seal fails
/// closed if a later `hpke` reads differently.
struct Encap64 {
    bytes: Option<[u8; 64]>,
    misused: bool,
}

impl TryRng for Encap64 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.misused = true;
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.misused = true;
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        match self.bytes.take() {
            Some(bytes) if dst.len() == bytes.len() => dst.copy_from_slice(&bytes),
            _ => {
                self.misused = true;
                dst.fill(0);
            }
        }
        Ok(())
    }
}

// The bytes come from the operating system CSPRNG in production.
impl TryCryptoRng for Encap64 {}

impl Encap64 {
    /// True if `hpke` read the 64 bytes exactly once and nothing else.
    fn read_once(&self) -> bool {
        !self.misused && self.bytes.is_none()
    }
}

/// Seal the app keys of `epochs` to one recipient with 64 given bytes of
/// encapsulation randomness.
///
/// Repeated randomness gives the same encapsulation to the same key.
/// Production code calls [`seal_key_set`], and this function exists only
/// with the `test-vectors` feature.
///
/// # Errors
///
/// [`KeyError::BadSealKey`] or [`KeyError::BadLength`].
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_key_set_with_randomness(
    randomness: [u8; 64],
    recipient_seal_pk: &[u8],
    log_id: &[u8; 16],
    recipient: &Hash32,
    epochs: &[u64],
    keys: &[[u8; 32]],
) -> Result<Vec<u8>, KeyError> {
    seal_with(
        randomness,
        recipient_seal_pk,
        log_id,
        recipient,
        epochs,
        keys,
    )
}

fn seal_with(
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
    let mut rng = Encap64 {
        bytes: Some(randomness),
        misused: false,
    };
    let (enc, ct) = hpke::single_shot_seal_with_rng::<HpkeAead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        &info,
        &plaintext,
        b"",
        &mut rng,
    )
    .map_err(|_| KeyError::BadSealKey)?;
    if !rng.read_once() {
        return Err(KeyError::Random);
    }
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
    seal_with(
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

    /// The app shows these texts. None may be empty or hold key material.
    #[test]
    fn key_errors_name_the_cause() {
        assert_eq!(KeyError::Decrypt.to_string(), "decryption failed");
        assert_eq!(
            KeyError::Random.to_string(),
            "the operating system CSPRNG failed"
        );
    }

    /// The seal accepts only the one 64-byte read of X-Wing. Each other read
    /// must make the seal fail, so that no encapsulation uses zero bytes.
    #[test]
    fn encap_source_flags_each_other_read() {
        let mut a = Encap64 {
            bytes: Some([7; 64]),
            misused: false,
        };
        // Not read at all: refused.
        assert!(!a.read_once());
        let mut buf = [0u8; 64];
        a.try_fill_bytes(&mut buf).unwrap();
        assert_eq!((buf, a.misused), ([7; 64], false));
        assert!(a.read_once());
        // Read twice: refused.
        a.try_fill_bytes(&mut buf).unwrap();
        assert_eq!((buf, a.misused), ([0; 64], true));
        assert!(!a.read_once());
        let mut b = Encap64 {
            bytes: Some([7; 64]),
            misused: false,
        };
        let mut short = [1u8; 32];
        b.try_fill_bytes(&mut short).unwrap();
        assert_eq!((short, b.misused), ([0; 32], true));
        let mut c = Encap64 {
            bytes: Some([7; 64]),
            misused: false,
        };
        assert_eq!((c.try_next_u32().unwrap(), c.misused), (0, true));
        // A wrong read with the 64 bytes still unread: refused.
        assert!(!c.read_once());
        let mut d = Encap64 {
            bytes: Some([7; 64]),
            misused: false,
        };
        assert_eq!((d.try_next_u64().unwrap(), d.misused), (0, true));
    }

    use proptest::prelude::*;

    fn seal_pk_strategy() -> impl Strategy<Value = [u8; SEAL_PK_LEN]> {
        proptest::collection::vec(any::<u8>(), SEAL_PK_LEN)
            .prop_map(|v| v.try_into().unwrap_or([0; SEAL_PK_LEN]))
    }

    proptest! {
        /// The device ID and the recovery ID cover both keys and have
        /// separate domains (`PROTOCOL.md` 2.2). Without the domain, a
        /// recovery key could pose as a device with the same keys.
        #[test]
        fn ids_cover_keys_and_domain(
            sign in any::<[u8; 32]>(),
            sign2 in any::<[u8; 32]>(),
            seal in seal_pk_strategy(),
            idx in 0usize..SEAL_PK_LEN,
            bit in 0u8..8,
        ) {
            prop_assert_ne!(device_id(&sign, &seal), recovery_id(&sign, &seal));
            let mut seal2 = seal;
            seal2[idx] ^= 1 << bit;
            prop_assert_ne!(device_id(&sign, &seal), device_id(&sign, &seal2));
            prop_assert_ne!(recovery_id(&sign, &seal), recovery_id(&sign, &seal2));
            prop_assert_eq!(sign == sign2, device_id(&sign, &seal) == device_id(&sign2, &seal));
            prop_assert_eq!(sign == sign2, recovery_id(&sign, &seal) == recovery_id(&sign2, &seal));
        }

        /// The commitment binds the log, the epoch and the key (`PROTOCOL.md`
        /// 6.2), so a key cannot pass as the key of another epoch or log.
        #[test]
        fn key_commitment_covers_each_input(
            log in any::<[u8; 16]>(),
            log2 in any::<[u8; 16]>(),
            epoch in any::<u64>(),
            epoch2 in any::<u64>(),
            key in any::<[u8; 32]>(),
            key2 in any::<[u8; 32]>(),
        ) {
            let base = key_commitment(&log, epoch, &key);
            prop_assert_eq!(log == log2, base == key_commitment(&log2, epoch, &key));
            prop_assert_eq!(epoch == epoch2, base == key_commitment(&log, epoch2, &key));
            prop_assert_eq!(key == key2, base == key_commitment(&log, epoch, &key2));
        }

        /// The key set info is injective over its inputs (`PROTOCOL.md` 7.3).
        /// Small epoch values make equal inputs likely.
        #[test]
        fn key_set_info_is_injective(
            log in prop::sample::select(vec![[0u8; 16], [1; 16]]),
            log2 in prop::sample::select(vec![[0u8; 16], [1; 16]]),
            rcp in prop::sample::select(vec![[0u8; 32], [1; 32]]),
            rcp2 in prop::sample::select(vec![[0u8; 32], [1; 32]]),
            epochs in proptest::collection::vec(0u64..3, 0..4),
            epochs2 in proptest::collection::vec(0u64..3, 0..4),
        ) {
            let same = log == log2 && rcp == rcp2 && epochs == epochs2;
            prop_assert_eq!(
                same,
                key_set_info(&log, &rcp, &epochs) == key_set_info(&log2, &rcp2, &epochs2)
            );
        }

        /// The change AAD and the snapshot AAD cover each field and differ
        /// from each other (`PROTOCOL.md` 7.2). Without this, a relay could
        /// replay a ciphertext under another log, epoch or author.
        #[test]
        fn aads_cover_each_field(
            log in any::<[u8; 16]>(),
            epoch in any::<u64>(),
            cid in any::<[u8; 16]>(),
            author in any::<[u8; 32]>(),
            pos in any::<u64>(),
            digest in any::<[u8; 32]>(),
        ) {
            let c = change_aad(&log, epoch, &cid, &author);
            let mut other = log;
            other[0] ^= 1;
            prop_assert_ne!(&c, &change_aad(&other, epoch, &cid, &author));
            prop_assert_ne!(&c, &change_aad(&log, epoch.wrapping_add(1), &cid, &author));
            let mut cid2 = cid;
            cid2[15] ^= 1;
            prop_assert_ne!(&c, &change_aad(&log, epoch, &cid2, &author));
            let mut author2 = author;
            author2[31] ^= 1;
            prop_assert_ne!(&c, &change_aad(&log, epoch, &cid, &author2));

            let s = snapshot_aad(&log, epoch, &author, pos, &digest);
            prop_assert_ne!(&c, &s);
            prop_assert_ne!(&s, &snapshot_aad(&other, epoch, &author, pos, &digest));
            prop_assert_ne!(&s, &snapshot_aad(&log, epoch.wrapping_add(1), &author, pos, &digest));
            prop_assert_ne!(&s, &snapshot_aad(&log, epoch, &author2, pos, &digest));
            prop_assert_ne!(&s, &snapshot_aad(&log, epoch, &author, pos.wrapping_add(1), &digest));
            let mut digest2 = digest;
            digest2[0] ^= 1;
            prop_assert_ne!(&s, &snapshot_aad(&log, epoch, &author, pos, &digest2));
        }

        /// Encrypt then decrypt returns the plaintext. A changed bit in the
        /// ciphertext, the AAD or the key is refused (`PROTOCOL.md` 7.2).
        #[test]
        fn encrypt_round_trip_and_refusal(
            key in any::<[u8; 32]>(),
            aad in proptest::collection::vec(any::<u8>(), 0..32),
            pt in proptest::collection::vec(any::<u8>(), 0..64),
            ct_bit in any::<usize>(),
            aad_bit in any::<usize>(),
            key_bit in 0usize..256,
        ) {
            let ct = encrypt(&key, &aad, &pt).unwrap();
            prop_assert_eq!(ct.len(), NONCE_LEN.wrapping_add(pt.len()).wrapping_add(TAG_LEN));
            prop_assert_eq!(decrypt(&key, &aad, &ct), Ok(pt));

            let mut bad = ct.clone();
            crate::testutil::flip_bit(&mut bad, ct_bit);
            prop_assert_eq!(decrypt(&key, &aad, &bad), Err(KeyError::Decrypt));

            if !aad.is_empty() {
                let mut bad_aad = aad.clone();
                crate::testutil::flip_bit(&mut bad_aad, aad_bit);
                prop_assert_eq!(decrypt(&key, &bad_aad, &ct), Err(KeyError::Decrypt));
            }
            let mut bad_key = key;
            bad_key[key_bit / 8] ^= 1 << (key_bit % 8);
            prop_assert_eq!(decrypt(&bad_key, &aad, &ct), Err(KeyError::Decrypt));
        }

        /// A ciphertext shorter than nonce plus tag is a length error and
        /// never a panic.
        #[test]
        fn decrypt_refuses_short_input(
            key in any::<[u8; 32]>(),
            ct in proptest::collection::vec(any::<u8>(), 0..40),
        ) {
            prop_assert_eq!(decrypt(&key, b"", &ct), Err(KeyError::BadLength));
        }

        /// `open_key_set` refuses each length other than `sealed_len` before
        /// any HPKE work.
        #[test]
        fn open_key_set_refuses_wrong_length(
            n in 0usize..4,
            len in 0usize..1300,
        ) {
            prop_assume!(len != sealed_len(n));
            let epochs: Vec<u64> = (1..=n as u64).collect();
            prop_assert_eq!(
                open_key_set(&[1; 32], &[2; 16], &[3; 32], &epochs, &vec![0; len]),
                Err(KeyError::BadLength)
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// A key set round-trips for random keys and epochs, and a flipped
        /// bit in the sealed bytes is refused (`PROTOCOL.md` 7.3).
        #[test]
        fn key_set_round_trip(
            seed in any::<[u8; 32]>(),
            log in any::<[u8; 16]>(),
            rcp in any::<[u8; 32]>(),
            keys in proptest::collection::vec(any::<[u8; 32]>(), 1..4),
            first in 1u64..1000,
            bit in any::<usize>(),
        ) {
            let epochs: Vec<u64> = (0..u64::try_from(keys.len()).unwrap()).map(|i| first.wrapping_add(i)).collect();
            let pk = seal_public(&seed);
            let sealed = seal_key_set(&pk, &log, &rcp, &epochs, &keys).unwrap();
            prop_assert_eq!(sealed.len(), sealed_len(keys.len()));
            prop_assert_eq!(open_key_set(&seed, &log, &rcp, &epochs, &sealed), Ok(keys));
            let mut bad = sealed.clone();
            crate::testutil::flip_bit(&mut bad, bit);
            prop_assert!(open_key_set(&seed, &log, &rcp, &epochs, &bad).is_err());
        }

        /// `seal_public` is a function of the seed, and the seed decides the
        /// key. `seal_key_set` refuses a bad recipient key and a count
        /// mismatch.
        #[test]
        fn seal_public_and_seal_refusals(seed in any::<[u8; 32]>(), seed2 in any::<[u8; 32]>()) {
            let pk = seal_public(&seed);
            prop_assert_eq!(pk, seal_public(&seed));
            prop_assert_eq!(seed == seed2, pk == seal_public(&seed2));
            prop_assert_eq!(
                seal_key_set(&pk[1..], &[0; 16], &[0; 32], &[1], &[[0; 32]]),
                Err(KeyError::BadSealKey)
            );
            prop_assert_eq!(
                seal_key_set(&pk, &[0; 16], &[0; 32], &[1, 2], &[[0; 32]]),
                Err(KeyError::BadLength)
            );
            prop_assert_eq!(
                seal_key_set(&pk, &[0; 16], &[0; 32], &[], &[]),
                Err(KeyError::BadLength)
            );
        }
    }

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

/// Kani proofs. Run with `cargo kani -p snailfish-protocol`.
///
/// No harness covers `encrypt`, `decrypt`, `seal_key_set`, `open_key_set`,
/// `seal_public`, `device_id`, `recovery_id` or `key_commitment`. They run
/// ChaCha20-Poly1305, X-Wing or SHA-256, which CBMC cannot finish. The
/// property tests cover them, and `frame_layout` in `encoding.rs` covers the
/// frame under each hash input. The harnesses below cover the layout of the
/// AAD and the HPKE info, and the length rule of the sealed bytes.
#[cfg(kani)]
mod proofs {
    use super::{ENC_LEN, TAG_LEN, change_aad, key_set_info, sealed_len};

    /// `PROTOCOL.md` 7.3: for 0 to 8 epochs, `sealed_len` is the X-Wing
    /// encapsulation, 32 bytes for each key and the tag. It never saturates.
    /// Bound: 0 to 8 epochs.
    #[kani::proof]
    fn sealed_len_is_exact() {
        let k: usize = kani::any_where(|&n| n <= 8);
        assert!(sealed_len(k) == 1120 + 32 * k + 16);
        assert!(ENC_LEN == 1120 && TAG_LEN == 16);
        assert!(sealed_len(k) > ENC_LEN);
    }

    /// `PROTOCOL.md` 7.3: `key_set_info` is a frame of the label, the log
    /// ID, the recipient and one 8-byte part for each epoch, in order.
    /// Bound: 1 symbolic epoch and a symbolic log ID and recipient. A run
    /// with 2 epochs took 331 s, so the unit test
    /// `key_set_info_is_injective` covers longer epoch lists (sampled).
    #[kani::proof]
    #[kani::unwind(40)]
    fn key_set_info_layout() {
        let log: [u8; 16] = kani::any();
        let rcp: [u8; 32] = kani::any();
        let e: u64 = kani::any();
        let out = key_set_info(&log, &rcp, &[e]);
        // 8 + 19, 8 + 16, 8 + 32, then 8 + 8
        assert!(out.len() == 27 + 24 + 40 + 16);
        assert!(&out[8..27] == b"snailfish.keyset.v1");
        assert!(out[27 + 7] == 16 && &out[35..51] == &log[..]);
        assert!(out[51 + 7] == 32 && &out[59..91] == &rcp[..]);
        assert!(out[91 + 7] == 8 && &out[99..107] == &e.to_be_bytes()[..]);
    }

    /// `PROTOCOL.md` 7.2: `change_aad` is a frame of the label, the log ID,
    /// the 8-byte epoch, the change ID and the author, in this order.
    /// Bound: fixed lengths, symbolic content.
    #[kani::proof]
    #[kani::unwind(40)]
    fn change_aad_layout() {
        let log: [u8; 16] = kani::any();
        let epoch: u64 = kani::any();
        let cid: [u8; 16] = kani::any();
        let author: [u8; 32] = kani::any();
        let out = change_aad(&log, epoch, &cid, &author);
        // 8 + 19, 8 + 16, 8 + 8, 8 + 16, 8 + 32
        assert!(out.len() == 27 + 24 + 16 + 24 + 40);
        assert!(&out[8..27] == b"snailfish.change.v1");
        assert!(out[27 + 7] == 16 && &out[35..35 + 16] == &log[..]);
        assert!(out[51 + 7] == 8 && &out[59..67] == &epoch.to_be_bytes()[..]);
        assert!(out[67 + 7] == 16 && &out[75..91] == &cid[..]);
        assert!(out[91 + 7] == 32 && &out[99..131] == &author[..]);
    }
}
