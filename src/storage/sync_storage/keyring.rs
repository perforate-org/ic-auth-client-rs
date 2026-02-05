//! OS keyring-backed storage for native environments.

use crate::storage::{DecodeError, StorageError, StoredKey, sync_storage::AuthClientStorage};
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const KEYRING_STORAGE_PREFIX: &str = "ic-";
const KEYRING_BUNDLE_KEY: &str = "bundle";
const KEYRING_BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct KeyringBundle {
    version: u32,
    values: HashMap<String, StoredKeyRepr>,
}

impl KeyringBundle {
    fn empty() -> Self {
        Self {
            version: KEYRING_BUNDLE_VERSION,
            values: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
enum StoredKeyRepr {
    String(String),
    Raw(String),
}

impl From<StoredKey> for StoredKeyRepr {
    fn from(value: StoredKey) -> Self {
        match value {
            StoredKey::String(string) => StoredKeyRepr::String(string),
            StoredKey::Raw(bytes) => StoredKeyRepr::Raw(BASE64_STANDARD_NO_PAD.encode(bytes)),
            #[cfg(feature = "wasm-js")]
            StoredKey::CryptoKeyPair(_) => StoredKeyRepr::String(String::new()),
        }
    }
}

impl TryFrom<StoredKeyRepr> for StoredKey {
    type Error = DecodeError;

    fn try_from(value: StoredKeyRepr) -> Result<Self, Self::Error> {
        match value {
            StoredKeyRepr::String(string) => Ok(StoredKey::String(string)),
            StoredKeyRepr::Raw(encoded) => {
                let bytes = BASE64_STANDARD_NO_PAD
                    .decode(encoded)
                    .map_err(DecodeError::Base64)?;
                Ok(StoredKey::Raw(bytes))
            }
        }
    }
}

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Clone)]
pub struct KeyringStorage {
    service_name: String,
}

impl KeyringStorage {
    /// Creates a new instance of [`KeyringStorage`].
    pub fn new<T>(service_name: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            service_name: service_name.into(),
        }
    }

    fn bundle_entry(&self) -> Result<Entry, StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, KEYRING_BUNDLE_KEY);
        Ok(Entry::new(&self.service_name, &key)?)
    }

    fn load_bundle(&self) -> Result<Option<KeyringBundle>, StorageError> {
        let entry = self.bundle_entry()?;
        match entry.get_secret() {
            Ok(value) => {
                let bundle: KeyringBundle = serde_json::from_slice(&value).map_err(|e| {
                    StorageError::Decode(DecodeError::Key(format!(
                        "Failed to decode keyring bundle: {e}"
                    )))
                })?;
                Ok(Some(bundle))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn store_bundle(&self, bundle: &KeyringBundle) -> Result<(), StorageError> {
        let entry = self.bundle_entry()?;
        let encoded = serde_json::to_vec(bundle).map_err(|e| {
            StorageError::Decode(DecodeError::Key(format!(
                "Failed to encode keyring bundle: {e}"
            )))
        })?;
        entry.set_secret(&encoded)?;
        Ok(())
    }
}

impl AuthClientStorage for KeyringStorage {
    fn get(&mut self, key: &str) -> Result<Option<StoredKey>, StorageError> {
        if let Some(bundle) = self.load_bundle()? {
            if let Some(stored) = bundle.values.get(key).cloned() {
                let value = StoredKey::try_from(stored)?;
                return Ok(Some(value));
            }

            return Ok(None);
        }

        Ok(None)
    }

    fn set(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError> {
        let mut bundle = self.load_bundle()?.unwrap_or_else(KeyringBundle::empty);
        bundle.values.insert(key.to_string(), value.into());
        self.store_bundle(&bundle)?;
        Ok(())
    }

    fn remove(&mut self, key: &str) -> Result<(), StorageError> {
        if let Some(mut bundle) = self.load_bundle()? {
            let removed = bundle.values.remove(key);
            if removed.is_some() {
                self.store_bundle(&bundle)?;
            }
            return Ok(());
        }
        Ok(())
    }
}

impl From<KeyringStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: KeyringStorage) -> Self {
        Box::new(storage)
    }
}
