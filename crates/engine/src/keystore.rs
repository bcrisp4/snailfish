//! The host key store (DESIGN.md "App integration", T14).
//!
//! The host app implements [`KeyStore`]: the Swift app with the data
//! protection keychain, the Python demo with a file. The engine decides
//! what to store and when. The host only reads and writes one secret item
//! for each space, named by the log ID text.
//!
//! The item is 96 bytes: the signing seed, the X-Wing seed and the app key
//! of epoch 1, 32 bytes each. The app key is all zero until the engine
//! has it: a new device opens it from its grant after the checkpoint check
//! ([ENR-9]).

use std::path::Path;
use std::sync::Arc;

use crate::{DeviceKeys, Engine, EngineError, SpaceRef};

const ITEM_LEN: usize = 96;

/// The secret store of the host app.
///
/// A failure must not fall back to weaker storage. The Swift app fails on
/// `errSecMissingEntitlement` and does not use the file-based keychain
/// (C62). The engine stops the call that needs the key.
pub trait KeyStore: Send + Sync {
    /// Read the item `account`, or `None` if it does not exist.
    ///
    /// # Errors
    ///
    /// The cause, with no secret.
    fn load(&self, account: &str) -> Result<Option<Vec<u8>>, String>;

    /// Write the item `account` durably. Replace an item that exists.
    ///
    /// # Errors
    ///
    /// The cause, with no secret.
    fn store(&self, account: &str, secret: &[u8]) -> Result<(), String>;
}

fn encode(k: &DeviceKeys) -> Vec<u8> {
    [&k.sign_seed[..], &k.seal_seed[..], &k.app_key[..]].concat()
}

fn decode(b: &[u8]) -> Result<DeviceKeys, EngineError> {
    let bad =
        || EngineError::KeyStore(format!("the key item is {} bytes, not {ITEM_LEN}", b.len()));
    let (sign_seed, rest) = b.split_first_chunk::<32>().ok_or_else(bad)?;
    let (seal_seed, rest) = rest.split_first_chunk::<32>().ok_or_else(bad)?;
    let app_key: &[u8; 32] = rest.try_into().map_err(|_| bad())?;
    Ok(DeviceKeys {
        sign_seed: *sign_seed,
        seal_seed: *seal_seed,
        app_key: *app_key,
    })
}

fn put(store: &dyn KeyStore, account: &str, keys: &DeviceKeys) -> Result<(), EngineError> {
    store
        .store(account, &encode(keys))
        .map_err(EngineError::KeyStore)
}

/// Open the engine in `data_dir` with the keys of `space` from `store`.
///
/// If the engine opens the app key from its grant, it writes the key to
/// `store` before it returns.
///
/// # Errors
///
/// [`EngineError::KeyStore`] if the store fails or holds no item for the
/// space, and the errors of [`Engine::open`].
pub fn open(
    data_dir: &Path,
    space: SpaceRef,
    store: Arc<dyn KeyStore>,
) -> Result<Engine, EngineError> {
    let account = space.log_id.clone();
    let keys = match store.load(&account).map_err(EngineError::KeyStore)? {
        Some(b) => decode(&b)?,
        None => {
            return Err(EngineError::KeyStore(format!(
                "the key store holds no keys for {account}"
            )));
        }
    };
    let mut e = Engine::open(data_dir, space, &keys)?;
    e.key_store = Some(store);
    e.app_key_stored = keys.app_key != [0; 32];
    e.keep_app_key()?;
    Ok(e)
}

/// [`crate::setup::install_setup`], then write the keys to `store`.
///
/// The engine state comes first. A crash between the two steps leaves a
/// state file with no keys, and [`open`] then fails. The relay holds no
/// space yet, so the user can sign in again with no loss.
///
/// # Errors
///
/// As [`crate::setup::install_setup`], and [`EngineError::KeyStore`].
pub fn install_setup(
    data_dir: &Path,
    space: SpaceRef,
    keys: &DeviceKeys,
    envelopes: &[String],
    setup_token: &str,
    store: &dyn KeyStore,
) -> Result<(), EngineError> {
    let account = space.log_id.clone();
    crate::setup::install_setup(data_dir, space, keys, envelopes, setup_token)?;
    put(store, &account, keys)
}

/// [`crate::setup::install_enrollment`], then write the keys to `store`.
///
/// The engine state comes first, so no stored keys exist without the
/// checkpoint ([ENR-9]). The keys of a new device have an all-zero app
/// key: the engine opens it from the grant after the checkpoint check, and
/// then writes it to the store.
///
/// # Errors
///
/// As [`crate::setup::install_enrollment`], and [`EngineError::KeyStore`].
pub fn install_enrollment(
    data_dir: &Path,
    space: SpaceRef,
    keys: &DeviceKeys,
    joined: &crate::enroll::Joined,
    store: &dyn KeyStore,
) -> Result<(), EngineError> {
    let account = space.log_id.clone();
    crate::setup::install_enrollment(data_dir, space, keys, joined)?;
    put(store, &account, keys)
}

impl Engine {
    /// Write the app key to the key store once the engine has it. An engine
    /// that [`open`] did not open has no store, and this does nothing.
    pub(crate) fn keep_app_key(&mut self) -> Result<(), EngineError> {
        let (Some(store), Some(app_key)) = (&self.key_store, self.app_key) else {
            return Ok(());
        };
        if self.app_key_stored {
            return Ok(());
        }
        // The engine keeps no signing seed, so read the item again and
        // replace only the app key.
        let account = &self.space.log_id;
        let Some(b) = store.load(account).map_err(EngineError::KeyStore)? else {
            return Err(EngineError::KeyStore(format!(
                "the key store holds no keys for {account}"
            )));
        };
        let keys = DeviceKeys {
            app_key,
            ..decode(&b)?
        };
        put(store.as_ref(), account, &keys)?;
        self.app_key_stored = true;
        Ok(())
    }
}
