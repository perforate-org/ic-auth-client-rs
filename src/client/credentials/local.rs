//! Credentials in `localStorage` (wasm).
//!
//! Port of upstream `credentials/local-credential-storage.ts`. `localStorage`
//! holds strings, so the key has to be one: this generates an Ed25519 identity,
//! whose private bytes serialise, rather than the non-extractable key the
//! IndexedDB store uses. That is the trade the medium imposes, and it is why
//! generation belongs to the store.

use async_trait::async_trait;
use rand::Rng as _;

use crate::ArcIdentity;
use crate::client::credentials::wasm;
use crate::client::credentials::{
    Credential, CredentialStorage, SecretRegistry, decode_credential_record,
    decode_ed25519_identity_json, ed25519_identity_from_seed, encode_credential_record,
    encode_ed25519_identity_json,
};
use crate::client::error::AuthClientError;

/// Credentials in `localStorage`, for where IndexedDB is unavailable.
///
/// Port of upstream `LocalCredentialStorage` (`local-credential-storage.ts:19-68`):
/// `shared = true`, `durable = true`, and the key type is Ed25519.
pub struct LocalCredentialStorage {
    prefix: String,
    registry: SecretRegistry,
}

impl std::fmt::Debug for LocalCredentialStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCredentialStorage")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl Default for LocalCredentialStorage {
    fn default() -> Self {
        Self::new("ic-")
    }
}

impl LocalCredentialStorage {
    /// A store whose slots are prefixed with `prefix`, so two clients under one
    /// origin can be kept apart.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            registry: SecretRegistry::new(),
        }
    }

    /// The `localStorage` key one slot is stored under.
    pub fn storage_key(&self, slot: &str) -> String {
        format!("{}{slot}", self.prefix)
    }

    fn storage(&self) -> Result<web_sys::Storage, AuthClientError> {
        wasm::local_storage()
            .ok_or_else(|| AuthClientError::Storage("Could not find local storage.".to_string()))
    }
}

#[async_trait(?Send)]
impl CredentialStorage for LocalCredentialStorage {
    fn shared(&self) -> bool {
        true
    }

    fn durable(&self) -> bool {
        true
    }

    async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let identity = ed25519_identity_from_seed(&seed);
        self.registry.remember(&identity, seed.to_vec());
        Ok(identity)
    }

    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
        let storage = self.storage()?;
        let Some(raw) = storage
            .get_item(&self.storage_key(slot))
            .map_err(|error| AuthClientError::Storage(wasm::display(&error)))?
        else {
            return Ok(None);
        };
        let Some(record) = decode_credential_record(&raw) else {
            // A record written by an incompatible version, or one the browser
            // has truncated. Reporting nothing lets the caller acquire again.
            return Ok(None);
        };
        let Some(seed) = decode_ed25519_identity_json(&record.key) else {
            return Ok(None);
        };
        let identity = ed25519_identity_from_seed(&seed);
        self.registry.remember(&identity, seed.to_vec());

        let chain = match record.chain {
            None => None,
            Some(chain) => match crate::delegation_chain::DelegationChain::from_any_json(&chain) {
                Ok(chain) => Some(chain),
                Err(_) => return Ok(None),
            },
        };
        Ok(Some(Credential { identity, chain }))
    }

    async fn set(&self, slot: &str, credential: Credential) -> Result<(), AuthClientError> {
        let secret = self
            .registry
            .secret_for(&credential.identity)
            .ok_or_else(|| {
                AuthClientError::Storage(
                    "this store can only serialise an Ed25519 key it generated or read".to_string(),
                )
            })?;
        let seed: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
            AuthClientError::Storage("the Ed25519 key material is not 32 bytes".to_string())
        })?;
        let key_json = encode_ed25519_identity_json(&seed);
        let chain_json = credential.chain.as_ref().map(|chain| chain.to_js_json());
        let record = encode_credential_record(&key_json, chain_json.as_deref());
        let storage = self.storage()?;
        storage
            .set_item(&self.storage_key(slot), &record)
            .map_err(|error| AuthClientError::Storage(wasm::display(&error)))
    }

    async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
        let storage = self.storage()?;
        storage
            .remove_item(&self.storage_key(slot))
            .map_err(|error| AuthClientError::Storage(wasm::display(&error)))
    }
}
