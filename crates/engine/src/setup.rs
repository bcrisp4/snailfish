//! The M2 space setup: the genesis record and the grants of a new space,
//! made from key files on one machine (M2 decision 2).
//!
//! M4 replaces the second half with enrollment. The records are real: the
//! relay and each engine check them with the same space-state check.

use std::path::Path;

use snailfish_protocol::encoding::{Hash32, encode_id};
use snailfish_protocol::envelope;
use snailfish_protocol::hash::{digest_next, digest0, entry_hash};
use snailfish_protocol::keys::{self, SEAL_PK_LEN};
use snailfish_protocol::records::{Author, Device, KeySet, Keys, Position};
use snailfish_protocol::recovery;
use snailfish_protocol::sig::SecretKey;
use snailfish_protocol::write;

use crate::{DeviceKeys, EngineError, SpaceRef};

/// The public part of a device for its grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    /// The Ed25519 seed. Setup needs only the public key, but a demo keeps
    /// both in one key file.
    pub keys: DeviceKeys,
    /// The device name.
    pub name: String,
}

/// The result of [`create_space`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceSetup {
    /// The log ID text.
    pub log_id: String,
    /// The recovery key in its display form. The app shows it once.
    pub recovery_key: String,
    /// The app key of epoch 1.
    pub app_key: [u8; 32],
    /// The genesis envelope, then one grant envelope for each other device.
    pub envelopes: Vec<String>,
}

fn rand<const N: usize>() -> Result<[u8; N], EngineError> {
    keys::random_bytes().map_err(|_| EngineError::Random)
}

fn device_of(k: &DeviceKeys, name: &str) -> (Device, Box<[u8; SEAL_PK_LEN]>) {
    let sign = SecretKey::from_seed(&k.sign_seed).public();
    let seal = Box::new(keys::seal_public(&k.seal_seed));
    let id = keys::device_id(&sign, &seal);
    (
        Device {
            id,
            keys: Keys {
                sign,
                seal: seal.clone(),
            },
            name: name.to_owned(),
            level: crate::MAX_LEVEL,
        },
        seal,
    )
}

fn seal_to(
    seal: &[u8; SEAL_PK_LEN],
    log: &[u8; 16],
    to: Author,
    app_key: &[u8; 32],
) -> Result<KeySet, EngineError> {
    let sealed = keys::seal_key_set(&seal[..], log, to.id(), &[1], &[*app_key])
        .map_err(|e| EngineError::Invalid(format!("seal: {e}")))?;
    Ok(KeySet {
        to,
        epochs: vec![1],
        sealed,
    })
}

/// Make a new space: a random log ID, a recovery key, the app key of epoch
/// 1, the genesis record with the first device, and a grant to each other
/// device signed by the first device.
///
/// The `app_key` of each [`DeviceKeys`] is ignored: the setup makes the app
/// key and returns it.
///
/// # Errors
///
/// [`EngineError::Random`] and [`EngineError::Invalid`].
pub fn create_space(
    app_id: &str,
    first: &NewDevice,
    others: &[NewDevice],
) -> Result<SpaceSetup, EngineError> {
    let log: [u8; 16] = rand()?;
    let secret: [u8; 16] = rand()?;
    let app_key: [u8; 32] = rand()?;
    let (r_sign_seed, r_seal_seed) = recovery::derive(&secret);
    let r_sign = SecretKey::from_seed(&r_sign_seed);
    let r_seal = Box::new(keys::seal_public(&r_seal_seed));
    let rid = keys::recovery_id(&r_sign.public(), &r_seal);
    let (dev, dev_seal) = device_of(&first.keys, &first.name);
    let mut sets = vec![
        seal_to(&dev_seal, &log, Author::Device(dev.id), &app_key)?,
        seal_to(&r_seal, &log, Author::Recovery(rid), &app_key)?,
    ];
    sets.sort_by(|a, b| a.to.id().cmp(b.to.id()));
    let commitment = keys::key_commitment(&log, 1, &app_key);
    let base0 = Position {
        position: 0,
        digest: digest0(&log),
    };
    let recovery_keys = Keys {
        sign: r_sign.public(),
        seal: r_seal,
    };
    let payload = write::genesis(
        &log,
        &Author::Recovery(rid),
        &base0,
        &write::Genesis {
            app: app_id,
            recovery: &recovery_keys,
            level: crate::MAX_LEVEL,
            device: &dev,
            commitment: &commitment,
            keys: &sets,
        },
    );
    let t = "snailfish.genesis.v1";
    let sig = r_sign.sign_record(t, &payload);
    let genesis = envelope::write_json(t, &payload, &sig, &encode_id("r_", &rid));
    let rh = snailfish_protocol::hash::record_hash(t, &payload, &sig);
    let mut digest: Hash32 = digest_next(&base0.digest, 1, &entry_hash(t, None, &rh));
    let mut envelopes = vec![genesis];
    let a_sign = SecretKey::from_seed(&first.keys.sign_seed);
    for (i, other) in others.iter().enumerate() {
        let (d, seal) = device_of(&other.keys, &other.name);
        let set = seal_to(&seal, &log, Author::Device(d.id), &app_key)?;
        let pos = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        let base = Position {
            position: pos,
            digest,
        };
        let payload = write::grant(&log, &Author::Device(dev.id), &base, &d, &set);
        let t = "snailfish.grant.v1";
        let sig = a_sign.sign_record(t, &payload);
        envelopes.push(envelope::write_json(
            t,
            &payload,
            &sig,
            &encode_id("d_", &dev.id),
        ));
        let rh = snailfish_protocol::hash::record_hash(t, &payload, &sig);
        digest = digest_next(&digest, pos.saturating_add(1), &entry_hash(t, None, &rh));
    }
    Ok(SpaceSetup {
        log_id: encode_id("l_", &log),
        recovery_key: recovery::display(&secret),
        app_key,
        envelopes,
    })
}

/// New device keys from the CSPRNG. The app key is all zero until a setup
/// or an enrollment gives it.
///
/// # Errors
///
/// [`EngineError::Random`].
pub fn new_device_keys() -> Result<DeviceKeys, EngineError> {
    Ok(DeviceKeys {
        sign_seed: rand()?,
        seal_seed: rand()?,
        app_key: [0; 32],
    })
}

/// Give the setup records to the engine of the first device in `data_dir`,
/// so that its next sync creates the space on the relay and appends the
/// grants.
///
/// # Errors
///
/// As [`crate::Engine::open`], and [`EngineError::Invalid`] for an envelope
/// that does not parse.
pub fn install_setup(
    data_dir: &Path,
    space: SpaceRef,
    keys: &DeviceKeys,
    envelopes: &[String],
) -> Result<(), EngineError> {
    let e = crate::Engine::open(data_dir, space, keys)?;
    crate::state::add_setup(&e.db, envelopes)
}
