//! Password-protected file storage for Android/Kotlin native environments.

use crate::storage::{DecodeError, StorageError, StoredKey, sync_storage::AuthClientStorage};
use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead as _, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::{collections::HashMap, fs, io::ErrorKind, path::PathBuf};

const PASSWORD_STORAGE_PREFIX: &str = "ic-password-";
const PASSWORD_STORAGE_SUFFIX: &str = ".json";

/// The format written now: PBKDF2-HMAC-SHA256 for the key, ChaCha20-Poly1305
/// for the payload.
const PASSWORD_STORAGE_VERSION: u32 = 2;
/// The format older releases wrote: a chained SHA-256 pseudo-KDF, an XOR
/// keystream and a SHA-256 tag. Read so that existing files keep working; every
/// write upgrades them to the current format.
const LEGACY_PASSWORD_STORAGE_VERSION: u32 = 1;
/// PBKDF2-HMAC-SHA256 rounds for new bundles (OWASP's 2023 recommendation).
///
/// Test builds derive with a cheap round count: the format and the checks are
/// what those tests are about, and one 600k-round derivation per storage
/// operation would put the suite in the minutes.
#[cfg(not(test))]
const KDF_ROUNDS: u32 = 600_000;
#[cfg(test)]
const KDF_ROUNDS: u32 = 1_000;
const SALT_LENGTH: usize = 16;
/// ChaCha20-Poly1305's nonce length; the tag rides on the ciphertext.
const NONCE_LENGTH: usize = 12;
/// The legacy format's nonce and tag lengths.
const LEGACY_NONCE_LENGTH: usize = 16;
const LEGACY_TAG_LENGTH: usize = 32;

/// File-backed storage that encrypts all values with a user-provided password.
#[derive(Debug, Clone)]
pub struct PasswordStorage {
    file_path: PathBuf,
    password: String,
}

impl PasswordStorage {
    /// Creates a new password-protected storage bound to a service name.
    pub fn new<T, P, S>(service_name: T, directory: P, password: S) -> Self
    where
        T: AsRef<str>,
        P: Into<PathBuf>,
        S: Into<String>,
    {
        let directory = directory.into();
        let file_name = format!(
            "{PASSWORD_STORAGE_PREFIX}{}{PASSWORD_STORAGE_SUFFIX}",
            sanitize_name(service_name.as_ref())
        );
        let file_path = directory.join(file_name);
        Self {
            file_path,
            password: password.into(),
        }
    }

    fn ensure_directory(&self) -> Result<(), StorageError> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn load_bundle(&self) -> Result<Option<PasswordBundle>, StorageError> {
        match fs::read_to_string(&self.file_path) {
            Ok(contents) => {
                let encrypted: EncryptedBundle = serde_json::from_str(&contents).map_err(|e| {
                    StorageError::File(format!("Invalid encrypted bundle JSON: {e}"))
                })?;
                let decrypted = self.decrypt_payload(&encrypted)?;
                let bundle: PasswordBundle = serde_json::from_slice(&decrypted).map_err(|e| {
                    StorageError::File(format!("Invalid decrypted bundle JSON: {e}"))
                })?;
                Ok(Some(bundle))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    fn store_bundle(&self, bundle: &PasswordBundle) -> Result<(), StorageError> {
        self.ensure_directory()?;
        let bytes = serde_json::to_vec(bundle)
            .map_err(|e| StorageError::File(format!("Failed to encode bundle JSON: {e}")))?;
        let encrypted = self.encrypt_payload(&bytes);
        let serialized = serde_json::to_vec(&encrypted)
            .map_err(|e| StorageError::File(format!("Failed to encode encrypted bundle: {e}")))?;
        self.write_private_atomically(&serialized)
    }

    /// Writes the bundle to a temporary file and renames it over the old one.
    ///
    /// The rename is atomic on every platform this targets, so a crash mid-write
    /// leaves the previous bundle rather than a truncated one. The file is
    /// readable only by its owner: it holds the session's keys, encrypted with a
    /// password that may be weaker than the file's protection.
    fn write_private_atomically(&self, bytes: &[u8]) -> Result<(), StorageError> {
        self.ensure_directory()?;
        let mut unique = [0u8; 8];
        rand::rng().fill_bytes(&mut unique);
        let unique = u64::from_le_bytes(unique);
        let temporary = PathBuf::from(format!("{}.{unique}.tmp", self.file_path.display()));
        let written = (|| -> Result<(), StorageError> {
            let mut file = fs::File::create(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            set_private_permissions(&temporary)?;
            Ok(())
        })();
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, &self.file_path) {
            let _ = fs::remove_file(&temporary);
            return Err(StorageError::from(error));
        }
        Ok(())
    }

    fn delete_bundle_file_if_exists(&self) -> Result<(), StorageError> {
        match fs::remove_file(&self.file_path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    /// The key for a bundle's salt, through PBKDF2-HMAC-SHA256.
    fn derive_key(&self, salt: &[u8], rounds: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(self.password.as_bytes(), salt, rounds, &mut key);
        key
    }

    fn encrypt_payload(&self, plaintext: &[u8]) -> EncryptedBundle {
        let mut salt = [0u8; SALT_LENGTH];
        rand::rng().fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);

        let key = self.derive_key(&salt, KDF_ROUNDS);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), plaintext)
            .expect("a message of any length fits ChaCha20-Poly1305's limits");

        EncryptedBundle {
            version: PASSWORD_STORAGE_VERSION,
            salt: BASE64_STANDARD_NO_PAD.encode(salt),
            nonce: BASE64_STANDARD_NO_PAD.encode(nonce),
            tag: None,
            ciphertext: BASE64_STANDARD_NO_PAD.encode(ciphertext),
        }
    }

    fn decrypt_payload(&self, bundle: &EncryptedBundle) -> Result<Vec<u8>, StorageError> {
        match bundle.version {
            PASSWORD_STORAGE_VERSION => self.decrypt_payload_v2(bundle),
            LEGACY_PASSWORD_STORAGE_VERSION => self.decrypt_payload_legacy(bundle),
            version => Err(StorageError::Decode(DecodeError::Key(format!(
                "Unsupported password bundle version: {version}"
            )))),
        }
    }

    fn decrypt_payload_v2(&self, bundle: &EncryptedBundle) -> Result<Vec<u8>, StorageError> {
        let salt = decode_base64_field(&bundle.salt)?;
        let nonce = decode_base64_field(&bundle.nonce)?;
        let nonce: [u8; NONCE_LENGTH] = nonce.try_into().map_err(|_| {
            StorageError::Decode(DecodeError::Key(
                "Invalid nonce length in password bundle".to_string(),
            ))
        })?;
        let ciphertext = decode_base64_field(&bundle.ciphertext)?;

        let key = self.derive_key(&salt, KDF_ROUNDS);
        let cipher = ChaCha20Poly1305::new((&key).into());
        cipher
            .decrypt(&Nonce::from(nonce), ciphertext.as_ref())
            .map_err(|_| {
                StorageError::Decode(DecodeError::Key(
                    "Failed to decrypt bundle (password may be invalid)".to_string(),
                ))
            })
    }

    /// Reads a bundle the older format wrote.
    ///
    /// Kept so that an installation upgrading this crate does not lose the
    /// session it had: the next write re-encrypts it in the current format.
    fn decrypt_payload_legacy(&self, bundle: &EncryptedBundle) -> Result<Vec<u8>, StorageError> {
        let salt = decode_base64_field(&bundle.salt)?;
        let nonce = decode_base64_field(&bundle.nonce)?;
        let tag = decode_base64_field(bundle.tag.as_deref().ok_or_else(|| {
            StorageError::Decode(DecodeError::Key(
                "a version 1 password bundle needs a tag".to_string(),
            ))
        })?)?;
        let mut ciphertext = decode_base64_field(&bundle.ciphertext)?;
        if nonce.len() != LEGACY_NONCE_LENGTH {
            return Err(StorageError::Decode(DecodeError::Key(
                "Invalid nonce length in password bundle".to_string(),
            )));
        }
        if tag.len() != LEGACY_TAG_LENGTH {
            return Err(StorageError::Decode(DecodeError::Key(
                "Invalid tag length in password bundle".to_string(),
            )));
        }

        let key = derive_key_legacy(self.password.as_bytes(), &salt);
        let expected = sha256_bytes(&[&key, &nonce, &ciphertext]);
        if !constant_time_eq(&expected, &tag) {
            return Err(StorageError::Decode(DecodeError::Key(
                "Failed to decrypt bundle (password may be invalid)".to_string(),
            )));
        }
        apply_stream_xor(&mut ciphertext, &key, &nonce);
        Ok(ciphertext)
    }
}

fn decode_base64_field(encoded: &str) -> Result<Vec<u8>, StorageError> {
    BASE64_STANDARD_NO_PAD
        .decode(encoded)
        .map_err(DecodeError::Base64)
        .map_err(StorageError::from)
}

/// Leaves a bundle readable only by its owner.
#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &std::path::Path) -> Result<(), StorageError> {
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBundle {
    version: u32,
    salt: String,
    nonce: String,
    /// Only a version 1 bundle carries one: the current format's tag rides on
    /// the ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordBundle {
    version: u32,
    values: HashMap<String, StoredKeyRepr>,
}

impl PasswordBundle {
    fn empty() -> Self {
        Self {
            version: PASSWORD_STORAGE_VERSION,
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

impl AuthClientStorage for PasswordStorage {
    fn get(&mut self, key: &str) -> Result<Option<StoredKey>, StorageError> {
        if let Some(bundle) = self.load_bundle()? {
            if let Some(stored) = bundle.values.get(key).cloned() {
                return Ok(Some(StoredKey::try_from(stored)?));
            }
        }
        Ok(None)
    }

    fn set(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError> {
        let mut bundle = self.load_bundle()?.unwrap_or_else(PasswordBundle::empty);
        bundle.values.insert(key.to_string(), value.into());
        self.store_bundle(&bundle)
    }

    fn remove(&mut self, key: &str) -> Result<(), StorageError> {
        if let Some(mut bundle) = self.load_bundle()? {
            if bundle.values.remove(key).is_some() {
                if bundle.values.is_empty() {
                    self.delete_bundle_file_if_exists()?;
                } else {
                    self.store_bundle(&bundle)?;
                }
            }
        }
        Ok(())
    }
}

impl From<PasswordStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: PasswordStorage) -> Self {
        Box::new(storage)
    }
}

fn sanitize_name(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The older format's pseudo-KDF over SHA-256.
fn derive_key_legacy(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut state = sha256_bytes(&[password, salt]);
    for _ in 0..100_000 {
        state = sha256_bytes(&[&state, password, salt]);
    }
    state
}

fn sha256_bytes(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn apply_stream_xor(buffer: &mut [u8], key: &[u8; 32], nonce: &[u8]) {
    let mut counter: u64 = 0;
    let mut offset = 0usize;

    while offset < buffer.len() {
        let counter_bytes = counter.to_le_bytes();
        let block = sha256_bytes(&[key, nonce, &counter_bytes]);
        let remaining = buffer.len() - offset;
        let take = remaining.min(block.len());
        for i in 0..take {
            buffer[offset + i] ^= block[i];
        }
        offset += take;
        counter = counter.saturating_add(1);
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (l, r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_directory() -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        path.push(format!("ic-auth-client-password-test-{unique}"));
        path
    }

    #[test]
    fn password_storage_roundtrip() {
        let dir = temp_directory();
        let mut storage = PasswordStorage::new("service", &dir, "password");

        storage
            .set("identity", StoredKey::Raw(vec![1, 2, 3]))
            .expect("store");
        storage
            .set("delegation", StoredKey::String("ok".to_string()))
            .expect("store");

        let identity = storage
            .get("identity")
            .expect("get")
            .expect("exists")
            .decode()
            .expect("decode");
        assert_eq!(identity, vec![1, 2, 3]);

        let delegation = storage
            .get("delegation")
            .expect("get")
            .expect("exists")
            .encode();
        assert_eq!(delegation, "ok");

        let _ = fs::remove_dir_all(dir);
    }

    /// Writes a bundle in the format older releases produced.
    fn write_legacy_bundle(storage: &PasswordStorage, bundle: &PasswordBundle) {
        let plaintext = serde_json::to_vec(bundle).expect("encode");
        let mut salt = [7u8; SALT_LENGTH];
        rand::rng().fill_bytes(&mut salt);
        let mut nonce = [0u8; LEGACY_NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);
        let key = derive_key_legacy(storage.password.as_bytes(), &salt);
        let mut ciphertext = plaintext.clone();
        apply_stream_xor(&mut ciphertext, &key, &nonce);
        let tag = sha256_bytes(&[&key, &nonce, &ciphertext]);
        let legacy = EncryptedBundle {
            version: LEGACY_PASSWORD_STORAGE_VERSION,
            salt: BASE64_STANDARD_NO_PAD.encode(salt),
            nonce: BASE64_STANDARD_NO_PAD.encode(nonce),
            tag: Some(BASE64_STANDARD_NO_PAD.encode(tag)),
            ciphertext: BASE64_STANDARD_NO_PAD.encode(ciphertext),
        };
        storage.ensure_directory().expect("directory");
        fs::write(
            &storage.file_path,
            serde_json::to_vec(&legacy).expect("encode"),
        )
        .expect("write");
    }

    #[test]
    fn a_legacy_bundle_is_read_and_upgraded_on_the_next_write() {
        let dir = temp_directory();
        let mut storage = PasswordStorage::new("service", &dir, "password");
        let mut bundle = PasswordBundle::empty();
        bundle.values.insert(
            "identity".to_string(),
            StoredKeyRepr::Raw("AQID".to_string()),
        );
        write_legacy_bundle(&storage, &bundle);

        let stored = storage
            .get("identity")
            .expect("get")
            .expect("exists")
            .decode()
            .expect("decode");
        assert_eq!(stored, vec![1, 2, 3]);

        // The next write replaces the file in the current format.
        storage
            .set("delegation", StoredKey::String("ok".to_string()))
            .expect("store");
        let raw = fs::read_to_string(&storage.file_path).expect("read");
        let written: EncryptedBundle = serde_json::from_str(&raw).expect("parse");
        assert_eq!(written.version, PASSWORD_STORAGE_VERSION);
        assert!(written.tag.is_none(), "the tag rides on the ciphertext");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_tampered_bundle_is_refused() {
        let dir = temp_directory();
        let mut storage = PasswordStorage::new("service", &dir, "password");
        storage
            .set("identity", StoredKey::Raw(vec![4, 5, 6]))
            .expect("store");

        let raw = fs::read_to_string(&storage.file_path).expect("read");
        let mut bundle: EncryptedBundle = serde_json::from_str(&raw).expect("parse");
        let mut ciphertext = BASE64_STANDARD_NO_PAD
            .decode(&bundle.ciphertext)
            .expect("decode");
        ciphertext[0] ^= 0xff;
        bundle.ciphertext = BASE64_STANDARD_NO_PAD.encode(ciphertext);
        fs::write(
            &storage.file_path,
            serde_json::to_vec(&bundle).expect("encode"),
        )
        .expect("write");

        let mut reader = PasswordStorage::new("service", &dir, "password");
        let error = reader
            .get("identity")
            .expect_err("must refuse the ciphertext");
        assert!(error.to_string().contains("password may be invalid"));

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_bundle_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_directory();
        let mut storage = PasswordStorage::new("service", &dir, "password");
        storage
            .set("identity", StoredKey::Raw(vec![1]))
            .expect("store");

        let mode = fs::metadata(&storage.file_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn password_storage_rejects_wrong_password() {
        let dir = temp_directory();
        let mut writer = PasswordStorage::new("service", &dir, "right-pass");
        writer
            .set("identity", StoredKey::Raw(vec![9, 9, 9]))
            .expect("store");

        let mut reader = PasswordStorage::new("service", &dir, "wrong-pass");
        let err = reader.get("identity").expect_err("must fail to decrypt");
        assert!(err.to_string().contains("password may be invalid"));

        let _ = fs::remove_dir_all(dir);
    }
}
