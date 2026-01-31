//! OS keyring-backed storage for native environments.

use crate::storage::{
    DecodeError, KEY_STORAGE_KEY, StorageError, StoredKey, sync_storage::AuthClientStorage,
};
use keyring::Entry;

const KEYRING_STORAGE_PREFIX: &str = "ic-";

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
}

impl AuthClientStorage for KeyringStorage {
    fn get(&mut self, key: &str) -> Result<Option<StoredKey>, StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key);
        let entry = Entry::new(&self.service_name, &key)?;
        match entry.get_secret() {
            Ok(value) => {
                if key.ends_with(KEY_STORAGE_KEY) {
                    return Ok(Some(StoredKey::Raw(value)));
                }
                let string = String::from_utf8(value)
                    .map_err(|e| StorageError::Decode(DecodeError::Ed25519(e.to_string())))?;
                Ok(Some(StoredKey::String(string)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key);
        let entry = Entry::new(&self.service_name, &key)?;
        let bytes: Vec<u8> = if key.ends_with(KEY_STORAGE_KEY) {
            match value {
                StoredKey::Raw(value) => value,
                StoredKey::String(string) => StoredKey::String(string)
                    .decode()
                    .map_err(StorageError::from)?,
                #[cfg(feature = "wasm-js")]
                StoredKey::CryptoKeyPair(_) => {
                    return Err(StorageError::Keyring(
                        "CryptoKeyPair cannot be stored in keyring".to_string(),
                    ));
                }
            }
        } else {
            match value {
                StoredKey::String(string) => string.into_bytes(),
                StoredKey::Raw(value) => value,
                #[cfg(feature = "wasm-js")]
                StoredKey::CryptoKeyPair(_) => {
                    return Err(StorageError::Keyring(
                        "CryptoKeyPair cannot be stored in keyring".to_string(),
                    ));
                }
            }
        };
        entry.set_secret(&bytes)?;
        Ok(())
    }

    fn remove(&mut self, key: &str) -> Result<(), StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key);
        let entry = Entry::new(&self.service_name, &key)?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl From<KeyringStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: KeyringStorage) -> Self {
        Box::new(storage)
    }
}
