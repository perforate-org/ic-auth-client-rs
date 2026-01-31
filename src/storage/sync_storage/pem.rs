//! File-based storage implementation for native environments.
//!
//! This storage backend persists both private keys and delegation chains to the filesystem,
//! allowing usage in environments where an OS keyring is not available.

use crate::storage::{
    DecodeError, KEY_STORAGE_KEY, StorageError, StoredKey, sync_storage::AuthClientStorage,
};
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use pkcs8::{
    LineEnding, ObjectIdentifier, PrivateKeyInfo, SecretDocument, der::pem::PemLabel,
    spki::AlgorithmIdentifierRef,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

const PEM_STORAGE_PREFIX: &str = "ic-";
const STORAGE_FILE_EXTENSION: &str = "json";
const KEY_FILE_EXTENSION: &str = "pem";
const ED25519_OID: &str = "1.3.101.112";

/// File-based storage backend that persists values to JSON files on disk.
#[derive(Debug, Clone)]
pub struct PemStorage {
    directory: PathBuf,
}

impl PemStorage {
    /// Creates a new instance of [`PemStorage`].
    ///
    /// # Arguments
    ///
    /// * `directory` - The directory where the storage files will be stored.
    ///
    /// # Returns
    ///
    /// A new instance of [`PemStorage`].
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Imports a PEM file containing an Ed25519 private key and stores it using the storage format.
    pub fn import_private_key_from_pem_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<(), StorageError> {
        let raw_key = Self::decode_pem_private_key_from_path(path.as_ref())?;
        self.write_private_key_pem(&raw_key)?;
        Ok(())
    }

    fn ensure_directory(&self) -> Result<(), StorageError> {
        if self.directory.as_os_str().is_empty() {
            return Ok(()); // current directory
        }
        fs::create_dir_all(&self.directory)?;
        Ok(())
    }

    fn file_path(&self, key: &str) -> PathBuf {
        let sanitized_key = sanitize_key(key);
        self.directory.join(format!(
            "{PEM_STORAGE_PREFIX}{sanitized_key}.{STORAGE_FILE_EXTENSION}"
        ))
    }

    fn key_file_path(&self) -> PathBuf {
        self.directory.join(format!(
            "{PEM_STORAGE_PREFIX}{KEY_STORAGE_KEY}.{KEY_FILE_EXTENSION}"
        ))
    }

    fn read_private_key_pem(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let path = self.key_file_path();
        match fs::read_to_string(&path) {
            Ok(contents) => Self::decode_pem_private_key(&contents).map(Some),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    fn write_private_key_pem(&self, key: &[u8; 32]) -> Result<(), StorageError> {
        self.ensure_directory()?;
        let algorithm = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap(ED25519_OID),
            parameters: None,
        };
        let info = PrivateKeyInfo::new(algorithm, key);
        let document =
            SecretDocument::encode_msg(&info).map_err(|e| StorageError::File(e.to_string()))?;
        let pem = document
            .to_pem(PrivateKeyInfo::PEM_LABEL, LineEnding::LF)
            .map_err(|e| StorageError::File(e.to_string()))?;
        fs::write(self.key_file_path(), pem.as_bytes())?;
        Ok(())
    }

    fn decode_pem_private_key(contents: &str) -> Result<[u8; 32], StorageError> {
        let (_, document) =
            SecretDocument::from_pem(contents).map_err(|e| StorageError::File(e.to_string()))?;
        let info: PrivateKeyInfo<'_> = document
            .decode_msg()
            .map_err(|e| StorageError::File(e.to_string()))?;
        if info.algorithm.oid != ObjectIdentifier::new_unwrap(ED25519_OID) {
            return Err(StorageError::Decode(DecodeError::Ed25519(
                "Unsupported key algorithm".to_string(),
            )));
        }
        let bytes: [u8; 32] = info
            .private_key
            .try_into()
            .map_err(|_| StorageError::Decode(DecodeError::Ed25519("Invalid key length".into())))?;
        Ok(bytes)
    }

    fn decode_pem_private_key_from_path(path: &Path) -> Result<[u8; 32], StorageError> {
        let data = fs::read_to_string(path)?;
        Self::decode_pem_private_key(&data)
    }

    fn read_json_value(&self, key: &str) -> Result<Option<StoredKey>, StorageError> {
        let path = self.file_path(key);
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let value: PemStoredValue = serde_json::from_str(&contents)
                    .map_err(|e| StorageError::File(e.to_string()))?;
                Ok(Some(StoredKey::try_from(value)?))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    fn write_json_value(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError> {
        #[cfg(feature = "wasm-js")]
        if matches!(value, StoredKey::CryptoKeyPair(_)) {
            return Err(StorageError::File(
                "CryptoKeyPair cannot be stored in PEM storage".to_string(),
            ));
        }
        self.ensure_directory()?;
        let path = self.file_path(key);
        let serialized = serde_json::to_string(&PemStoredValue::from(&value))
            .map_err(|e| StorageError::File(e.to_string()))?;
        fs::write(path, serialized)?;
        Ok(())
    }

    fn remove_json_file(&self, key: &str) -> Result<(), StorageError> {
        let path = self.file_path(key);
        match fs::remove_file(&path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    fn stored_key_to_raw(value: StoredKey) -> Result<[u8; 32], StorageError> {
        match value {
            StoredKey::Raw(bytes) => bytes.try_into().map_err(|_| {
                StorageError::Decode(DecodeError::Ed25519("Invalid slice length".into()))
            }),
            StoredKey::String(string) => {
                let stored = StoredKey::String(string);
                stored.decode_ed25519().map_err(StorageError::from)
            }
            #[cfg(feature = "wasm-js")]
            StoredKey::CryptoKeyPair(_) => Err(StorageError::File(
                "CryptoKeyPair cannot be stored in PEM storage".to_string(),
            )),
        }
    }
}

fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
enum PemStoredValue {
    Raw(String),
    String(String),
}

impl From<&StoredKey> for PemStoredValue {
    fn from(value: &StoredKey) -> Self {
        match value {
            StoredKey::Raw(bytes) => {
                PemStoredValue::Raw(BASE64_STANDARD_NO_PAD.encode(bytes.as_slice()))
            }
            StoredKey::String(string) => PemStoredValue::String(string.clone()),
            #[cfg(feature = "wasm-js")]
            StoredKey::CryptoKeyPair(_) => PemStoredValue::String("".to_string()),
        }
    }
}

impl TryFrom<PemStoredValue> for StoredKey {
    type Error = DecodeError;

    fn try_from(value: PemStoredValue) -> Result<Self, Self::Error> {
        match value {
            PemStoredValue::Raw(data) => {
                let decoded = BASE64_STANDARD_NO_PAD
                    .decode(data)
                    .map_err(DecodeError::Base64)?;
                Ok(StoredKey::Raw(decoded))
            }
            PemStoredValue::String(string) => Ok(StoredKey::String(string)),
        }
    }
}

impl AuthClientStorage for PemStorage {
    fn get(&mut self, key: &str) -> Result<Option<StoredKey>, StorageError> {
        if key == KEY_STORAGE_KEY {
            if let Some(raw_key) = self.read_private_key_pem()? {
                return Ok(Some(StoredKey::Raw(raw_key.to_vec())));
            }
            if let Some(legacy) = self.read_json_value(key)? {
                if let Ok(raw) = legacy.decode_ed25519().map_err(StorageError::from) {
                    self.write_private_key_pem(&raw)?;
                    let _ = self.remove_json_file(key);
                    return Ok(Some(StoredKey::Raw(raw.to_vec())));
                }
                return Ok(Some(legacy));
            }
            return Ok(None);
        }
        self.read_json_value(key)
    }

    fn set(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError> {
        if key == KEY_STORAGE_KEY {
            match value {
                StoredKey::Raw(bytes) => {
                    if bytes.len() == 32 {
                        let raw: [u8; 32] = bytes.try_into().map_err(|_| {
                            StorageError::Decode(DecodeError::Ed25519(
                                "Invalid slice length".into(),
                            ))
                        })?;
                        self.write_private_key_pem(&raw)?;
                        let _ = self.remove_json_file(key);
                    } else {
                        self.ensure_directory()?;
                        self.write_json_value(key, StoredKey::Raw(bytes))?;
                        let _ = fs::remove_file(self.key_file_path());
                    }
                }
                StoredKey::String(string) => {
                    let stored = StoredKey::String(string);
                    if let Ok(raw) = Self::stored_key_to_raw(stored.clone()) {
                        self.write_private_key_pem(&raw)?;
                        let _ = self.remove_json_file(key);
                    } else {
                        self.write_json_value(key, stored)?;
                        let _ = fs::remove_file(self.key_file_path());
                    }
                }
                #[cfg(feature = "wasm-js")]
                StoredKey::CryptoKeyPair(_) => {
                    return Err(StorageError::File(
                        "CryptoKeyPair cannot be stored in PEM storage".to_string(),
                    ));
                }
            }
            return Ok(());
        }
        self.write_json_value(key, value)
    }

    fn remove(&mut self, key: &str) -> Result<(), StorageError> {
        if key == KEY_STORAGE_KEY {
            let path = self.key_file_path();
            match fs::remove_file(&path) {
                Ok(_) => (),
                Err(e) if e.kind() == ErrorKind::NotFound => (),
                Err(e) => return Err(StorageError::from(e)),
            }
            let _ = self.remove_json_file(key);
            return Ok(());
        }
        self.remove_json_file(key)
    }
}

impl From<PemStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: PemStorage) -> Self {
        Box::new(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_directory() -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("ic-auth-client-test-{unique}"));
        path
    }

    #[test]
    fn pem_storage_persists_raw_keys() {
        let dir = temp_directory();
        let mut storage = PemStorage::new(dir.clone());
        let key = [42u8; 32];
        storage
            .set("identity", StoredKey::from(key))
            .expect("store key");
        let retrieved = storage.get("identity").expect("read key").unwrap();
        assert_eq!(retrieved.decode_ed25519().unwrap(), key);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pem_storage_persists_strings() {
        let dir = temp_directory();
        let mut storage = PemStorage::new(dir.clone());
        storage
            .set("delegation", StoredKey::String("value".into()))
            .expect("store value");
        let retrieved = storage.get("delegation").expect("read value").unwrap();
        assert_eq!(retrieved.encode(), "value");
        storage.remove("delegation").expect("remove");
        let after_remove = storage.get("delegation").expect("read missing");
        assert!(after_remove.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pem_storage_persists_identity_as_pem() {
        let dir = temp_directory();
        let mut storage = PemStorage::new(dir.clone());
        let key = [7u8; 32];
        storage
            .set(KEY_STORAGE_KEY, StoredKey::from(key))
            .expect("store key");
        let retrieved = storage
            .get(KEY_STORAGE_KEY)
            .expect("read key")
            .expect("missing key");
        assert_eq!(retrieved.decode_ed25519().unwrap(), key);
        let pem_key = storage
            .read_private_key_pem()
            .expect("read pem")
            .expect("missing pem");
        assert_eq!(pem_key, key);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pem_storage_migrates_legacy_identity_json() {
        let dir = temp_directory();
        let mut storage = PemStorage::new(dir.clone());
        let key = [9u8; 32];
        storage
            .write_json_value(KEY_STORAGE_KEY, StoredKey::from(key))
            .expect("write legacy json");
        let legacy_path = storage.file_path(KEY_STORAGE_KEY);
        assert!(legacy_path.exists());

        let retrieved = storage
            .get(KEY_STORAGE_KEY)
            .expect("read key")
            .expect("missing key");
        assert_eq!(retrieved.decode_ed25519().unwrap(), key);
        assert!(storage.key_file_path().exists());
        assert!(!legacy_path.exists());
        let _ = fs::remove_dir_all(dir);
    }
}
