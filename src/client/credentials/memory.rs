//! In-memory credential storage.
//!
//! Port of upstream `credentials/memory-credential-storage.ts`: `shared =
//! false`, `durable = false`, and the key type is P-256.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::client::credentials::{Credential, CredentialStorage};
use crate::client::error::AuthClientError;
use rand::Rng as _;

use crate::ArcIdentity;
use crate::key::{BaseKeyType, KeyWithRaw};

/// Generates a fresh identity of the given base key type, using the platform
/// RNG.
pub(crate) fn create_identity(key_type: BaseKeyType) -> Result<ArcIdentity, AuthClientError> {
    let raw_key = match key_type {
        BaseKeyType::Ed25519 => {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            bytes.to_vec()
        }
        BaseKeyType::Prime256v1 => crate::key::random_p256_secret_key()
            .to_sec1_der()
            .map_err(|error| AuthClientError::Storage(format!("P-256 key encoding: {error}")))?
            .to_vec(),
        BaseKeyType::Secp256k1 => crate::key::random_k256_secret_key()
            .to_sec1_der()
            .map_err(|error| AuthClientError::Storage(format!("secp256k1 key encoding: {error}")))?
            .to_vec(),
    };
    let key = KeyWithRaw::new_with_type(key_type, raw_key)
        .map_err(|error| AuthClientError::Storage(error.to_string()))?;
    Ok(ArcIdentity::from(crate::key::Key::WithRaw(key)))
}

/// Credentials in memory, for a caller that keeps nothing on disk.
///
/// Upstream's memory store hands records back as given rather than round-
/// tripping them through an encoding, which is what lets it hold a
/// non-extractable key at all; this port always holds readable key material, so
/// a `HashMap` of cloned credentials is equivalent.
#[derive(Debug)]
pub struct MemoryCredentialStorage {
    entries: Mutex<HashMap<String, Credential>>,
    key_type: BaseKeyType,
}

impl MemoryCredentialStorage {
    /// A store that generates keys of the given type.
    pub fn new(key_type: BaseKeyType) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            key_type,
        }
    }
}

impl Default for MemoryCredentialStorage {
    fn default() -> Self {
        Self::new(BaseKeyType::Ed25519)
    }
}

#[async_trait(?Send)]
impl CredentialStorage for MemoryCredentialStorage {
    fn shared(&self) -> bool {
        false
    }

    fn durable(&self) -> bool {
        false
    }

    async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
        create_identity(self.key_type)
    }

    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
        Ok(self
            .entries
            .lock()
            .expect("memory credential store is not poisoned")
            .get(slot)
            .cloned())
    }

    async fn set(&self, slot: &str, credential: Credential) -> Result<(), AuthClientError> {
        self.entries
            .lock()
            .expect("memory credential store is not poisoned")
            .insert(slot.to_string(), credential);
        Ok(())
    }

    async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
        self.entries
            .lock()
            .expect("memory credential store is not poisoned")
            .remove(slot);
        Ok(())
    }
}
