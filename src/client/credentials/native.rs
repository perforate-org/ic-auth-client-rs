//! Credentials in the native platform's secure stores.
//!
//! Native has no IndexedDB and no `localStorage`; what it has is the v5 stores
//! this crate already ships: the OS keyring, PEM files and a password-encrypted
//! file. This store maps the v11 [`CredentialStorage`] seam onto one of them,
//! chosen at construction. A native install is one user on one machine, so the
//! medium is `shared = false` and `durable = true`.
//!
//! The key type is Ed25519 because every one of those media holds bytes, and
//! Ed25519's private key is exactly its 32-byte seed.

use std::sync::Mutex;

use async_trait::async_trait;

use crate::ArcIdentity;
use crate::client::credentials::{
    Credential, CredentialStorage, SecretRegistry, decode_native_record, encode_native_record,
};
use crate::client::error::AuthClientError;
use crate::key::{BaseKeyType, KeyWithRaw};
use crate::storage::sync_storage::AuthClientStorage;
use crate::storage::{StorageError, StoredKey};

/// Credentials in one of the native secure stores.
///
/// Port of the native mapping proposed in `credential-storage.md` §5: the
/// existing keyring / PEM / password stores sit behind the new trait.
pub struct NativeCredentialStorage {
    backend: Mutex<Box<dyn AuthClientStorage>>,
    registry: SecretRegistry,
}

impl std::fmt::Debug for NativeCredentialStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCredentialStorage")
            .finish_non_exhaustive()
    }
}

impl NativeCredentialStorage {
    /// A store over an arbitrary v5 backend.
    pub fn new(backend: Box<dyn AuthClientStorage>) -> Self {
        Self {
            backend: Mutex::new(backend),
            registry: SecretRegistry::new(),
        }
    }

    /// A store in the OS keyring under `service_name`.
    #[cfg(feature = "keyring")]
    pub fn keyring(service_name: impl Into<String>) -> Self {
        Self::new(Box::new(crate::storage::sync_storage::KeyringStorage::new(
            service_name,
        )))
    }

    /// A store in JSON/PEM files under `directory`.
    #[cfg(feature = "pem")]
    pub fn pem(directory: impl Into<std::path::PathBuf>) -> Self {
        Self::new(Box::new(crate::storage::sync_storage::PemStorage::new(
            directory.into(),
        )))
    }

    /// A store in a password-encrypted file under `directory`.
    #[cfg(feature = "android-password")]
    pub fn password(
        service_name: impl AsRef<str>,
        directory: impl Into<std::path::PathBuf>,
        password: impl Into<String>,
    ) -> Self {
        Self::new(Box::new(
            crate::storage::sync_storage::PasswordStorage::new(
                service_name.as_ref(),
                directory,
                password,
            ),
        ))
    }

    fn backend_error(error: StorageError) -> AuthClientError {
        AuthClientError::Storage(error.to_string())
    }
}

#[async_trait(?Send)]
impl CredentialStorage for NativeCredentialStorage {
    fn shared(&self) -> bool {
        false
    }

    fn durable(&self) -> bool {
        true
    }

    async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
        use rand::Rng as _;
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let identity = crate::key::KeyWithRaw::new(seed).identity;
        self.registry.remember(&identity, seed.to_vec());
        Ok(identity)
    }

    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
        let stored = {
            let mut backend = self
                .backend
                .lock()
                .expect("the native credential store is not poisoned");
            backend.get(slot).map_err(Self::backend_error)?
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        match stored {
            StoredKey::String(json) => {
                let Some((key_type, secret, chain_json)) = decode_native_record(&json) else {
                    return Ok(None);
                };
                let identity =
                    KeyWithRaw::new_with_type(key_type, secret.clone()).map_err(|error| {
                        AuthClientError::Storage(format!("stored key is unreadable: {error}"))
                    })?;
                self.registry.remember(&identity.identity, secret);
                let chain = match chain_json {
                    None => None,
                    // A chain this version cannot read makes the record
                    // unreadable rather than fatal, the same as a corrupt key.
                    Some(chain) => {
                        match serde_json::from_str::<crate::delegation_chain::DelegationChain>(
                            &chain,
                        ) {
                            Ok(chain) => Some(chain),
                            Err(_) => return Ok(None),
                        }
                    }
                };
                Ok(Some(Credential {
                    identity: identity.identity,
                    chain,
                }))
            }
            StoredKey::Raw(bytes) => {
                // A bare Ed25519 seed, which is what the v5 stores hold under
                // their own keys. No chain goes with it.
                let key: [u8; 32] = match bytes.as_slice().try_into() {
                    Ok(key) => key,
                    Err(_) => return Ok(None),
                };
                let identity = KeyWithRaw::new(key).identity;
                self.registry.remember(&identity, key.to_vec());
                Ok(Some(Credential::key_only(identity)))
            }
        }
    }

    async fn set(&self, slot: &str, credential: Credential) -> Result<(), AuthClientError> {
        let secret = self
            .registry
            .secret_for(&credential.identity)
            .ok_or_else(|| {
                AuthClientError::Storage(
                    "this store can only serialise a key it generated or read".to_string(),
                )
            })?;
        let key_type = BaseKeyType::from_identity(&credential.identity).ok_or_else(|| {
            AuthClientError::Storage("the credential's key type is not serialisable".to_string())
        })?;
        let chain_json = credential.chain.as_ref().map(|chain| chain.to_json());
        let record = encode_native_record(key_type, &secret, chain_json.as_deref());
        let mut backend = self
            .backend
            .lock()
            .expect("the native credential store is not poisoned");
        backend
            .set(slot, StoredKey::String(record))
            .map_err(Self::backend_error)
    }

    async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
        let mut backend = self
            .backend
            .lock()
            .expect("the native credential store is not poisoned");
        backend.remove(slot).map_err(Self::backend_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_directory() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos();
        path.push(format!("ic-auth-client-credentials-{unique}"));
        path
    }

    fn delegation_chain() -> crate::delegation_chain::DelegationChain {
        crate::delegation_chain::DelegationChain::new(Vec::new(), vec![1, 2, 3])
    }

    #[cfg(feature = "pem")]
    #[test]
    fn pem_store_round_trips_a_credential() {
        futures::executor::block_on(async {
            let directory = temp_directory();
            let store = NativeCredentialStorage::pem(directory.clone());

            assert!(!store.shared());
            assert!(store.durable());

            let identity = store.create().await.unwrap();
            let public_key = identity.public_key().unwrap();
            store
                .set(
                    "session",
                    Credential::with_chain(identity, delegation_chain()),
                )
                .await
                .unwrap();

            let stored = store.get("session").await.unwrap().unwrap();
            assert_eq!(stored.identity.public_key().unwrap(), public_key);
            assert!(stored.chain.is_some());
            assert!(store.get("app").await.unwrap().is_none());

            store.remove("session").await.unwrap();
            assert!(store.get("session").await.unwrap().is_none());
            let _ = std::fs::remove_dir_all(directory);
        });
    }

    #[cfg(feature = "pem")]
    #[test]
    fn pem_store_survives_a_reopen() {
        futures::executor::block_on(async {
            let directory = temp_directory();
            let identity = {
                let store = NativeCredentialStorage::pem(directory.clone());
                let identity = store.create().await.unwrap();
                store
                    .set("app", Credential::key_only(identity.clone()))
                    .await
                    .unwrap();
                identity
            };

            let reopened = NativeCredentialStorage::pem(directory.clone());
            let stored = reopened.get("app").await.unwrap().unwrap();
            assert_eq!(
                stored.identity.public_key().unwrap(),
                identity.public_key().unwrap()
            );
            assert!(stored.chain.is_none());
            let _ = std::fs::remove_dir_all(directory);
        });
    }

    #[cfg(feature = "pem")]
    #[test]
    fn a_record_it_cannot_read_reports_nothing() {
        let directory = temp_directory();
        {
            let mut backend = crate::storage::sync_storage::PemStorage::new(directory.clone());
            backend
                .set("session", StoredKey::String("not a record".to_string()))
                .unwrap();
        }
        let store = NativeCredentialStorage::pem(directory.clone());
        let stored = futures::executor::block_on(store.get("session")).unwrap();
        assert!(stored.is_none());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn ed25519_is_the_key_type_it_generates() {
        futures::executor::block_on(async {
            let store = NativeCredentialStorage::new(Box::new(MemoryBackend::default()));
            let identity = store.create().await.unwrap();
            assert_eq!(
                BaseKeyType::from_identity(&identity),
                Some(BaseKeyType::Ed25519)
            );
        });
    }

    /// A backend that keeps values in memory, so the trait mapping is testable
    /// without a keyring or a filesystem.
    #[derive(Default)]
    struct MemoryBackend {
        values: std::collections::HashMap<String, StoredKey>,
    }

    impl AuthClientStorage for MemoryBackend {
        fn get(&mut self, key: &str) -> Result<Option<StoredKey>, StorageError> {
            Ok(self.values.get(key).cloned())
        }
        fn set(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError> {
            self.values.insert(key.to_string(), value);
            Ok(())
        }
        fn remove(&mut self, key: &str) -> Result<(), StorageError> {
            self.values.remove(key);
            Ok(())
        }
    }

    #[test]
    fn a_credential_round_trips_through_a_backend() {
        futures::executor::block_on(async {
            let store = NativeCredentialStorage::new(Box::new(MemoryBackend::default()));
            let identity = store.create().await.unwrap();
            store
                .set(
                    "session",
                    Credential::with_chain(identity, delegation_chain()),
                )
                .await
                .unwrap();
            let stored = store.get("session").await.unwrap().unwrap();
            assert!(stored.chain.is_some());
            assert!(store.get("missing").await.unwrap().is_none());
            store.remove("session").await.unwrap();
            assert!(store.get("session").await.unwrap().is_none());
        });
    }
}
