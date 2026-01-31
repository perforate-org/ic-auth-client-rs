//! Key management functionality for cryptographic operations.
//!
//! The module defines types for handling cryptographic keys that can contain both
//! raw key material and identity interfaces. This is particularly useful when working
//! with the Internet Computer (IC) agent where you need both access to raw keys
//! and the ability to use them as identities for signing operations.
//!
//! # Main Types
//!
//! - [`Key`] - An enum that can represent either a key with raw bytes or just an identity
//! - [`KeyWithRaw`] - A struct that contains both raw key bytes and the associated identity
//! - [`BaseKeyType`] - An enum representing supported key types (Ed25519, Prime256v1, Secp256k1)
//!
//! # Examples
//!
//! ```rust
//! use ic_auth_client::key::{Key, KeyWithRaw};
//!
//! // Create a key from raw bytes
//! let raw_key = [0u8; 32]; // Your actual key bytes
//! let key_with_raw = KeyWithRaw::new(raw_key);
//! let key = Key::WithRaw(key_with_raw);
//!
//! // Use the key as an identity
//! let identity = key.as_arc_identity();
//!
//! // Get public key bytes
//! if let Some(public_key) = key.public_key() {
//!     println!("Public key: {:?}", public_key);
//! }
//! ```

use crate::ArcIdentity;
use ic_agent::identity::{BasicIdentity, Identity, Prime256v1Identity, Secp256k1Identity};
use k256::SecretKey as K256SecretKey;
use p256::SecretKey as P256SecretKey;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

const ED25519_KEY_LABEL: &str = "Ed25519";
const PRIME256V1_KEY_LABEL: &str = "Prime256v1";
const SECP256K1_KEY_LABEL: &str = "Secp256k1";

/// A key that contains both the raw key bytes and the associated identity.
///
/// This struct wraps raw key material with its corresponding identity implementation,
/// providing access to both the raw key bytes and the identity interface.
#[derive(Clone, Debug)]
pub struct KeyWithRaw {
    pub(crate) key_type: BaseKeyType,
    pub(crate) key: Vec<u8>,
    pub(crate) identity: ArcIdentity,
}

impl KeyWithRaw {
    /// Creates a new `KeyWithRaw` from a raw 32-byte Ed25519 key.
    ///
    /// # Arguments
    ///
    /// * `raw_key` - A 32-byte array containing the raw key material
    ///
    /// # Returns
    ///
    /// A new `KeyWithRaw` instance with the key and its associated Ed25519 identity
    pub fn new(raw_key: [u8; 32]) -> Self {
        KeyWithRaw {
            key_type: BaseKeyType::Ed25519,
            key: raw_key.to_vec(),
            identity: ArcIdentity::Ed25519(Arc::new(BasicIdentity::from_raw_key(&raw_key))),
        }
    }

    /// Creates a new `KeyWithRaw` from raw key bytes and the specified key type.
    pub fn new_with_type(
        key_type: BaseKeyType,
        raw_key: Vec<u8>,
    ) -> Result<Self, crate::storage::DecodeError> {
        let identity = match key_type {
            BaseKeyType::Ed25519 => {
                let bytes: [u8; 32] = raw_key.clone().try_into().map_err(|_| {
                    crate::storage::DecodeError::Ed25519("Invalid slice length".to_string())
                })?;
                ArcIdentity::Ed25519(Arc::new(BasicIdentity::from_raw_key(&bytes)))
            }
            BaseKeyType::Prime256v1 => {
                let secret = P256SecretKey::from_sec1_der(&raw_key).map_err(|e| {
                    crate::storage::DecodeError::Key(format!("Prime256v1 key decode error: {e}"))
                })?;
                ArcIdentity::Prime256v1(Arc::new(Prime256v1Identity::from_private_key(secret)))
            }
            BaseKeyType::Secp256k1 => {
                let secret = K256SecretKey::from_sec1_der(&raw_key).map_err(|e| {
                    crate::storage::DecodeError::Key(format!("Secp256k1 key decode error: {e}"))
                })?;
                ArcIdentity::Secp256k1(Arc::new(Secp256k1Identity::from_private_key(secret)))
            }
        };

        Ok(KeyWithRaw {
            key_type,
            key: raw_key,
            identity,
        })
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte raw key array
    pub fn raw_key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the key type for this raw key.
    pub fn key_type(&self) -> BaseKeyType {
        self.key_type
    }
}

/// Represents a cryptographic key that can be either a raw key with its bytes or just an identity.
///
/// This enum allows for flexible key handling where sometimes you need access to the raw key
/// material and sometimes you only need the identity interface.
#[derive(Clone, Debug)]
pub enum Key {
    /// A key that includes both raw key bytes and the identity
    WithRaw(KeyWithRaw),
    /// A key that only provides the identity interface without raw bytes
    Identity(ArcIdentity),
}

impl Key {
    /// Returns the key as an `Arc<dyn Identity>` for use with the IC agent.
    ///
    /// # Returns
    ///
    /// An `Arc<dyn Identity>` that can be used for signing operations
    pub fn as_arc_identity(&self) -> Arc<dyn Identity> {
        match self {
            Key::WithRaw(key) => key.identity.as_arc_identity(),
            Key::Identity(identity) => identity.as_arc_identity(),
        }
    }

    /// Returns the public key bytes if available.
    ///
    /// # Returns
    ///
    /// An `Option<Vec<u8>>` containing the public key bytes, or `None` if not available
    pub fn public_key(&self) -> Option<Vec<u8>> {
        match self {
            Key::WithRaw(key) => key.identity.public_key(),
            Key::Identity(identity) => identity.public_key(),
        }
    }
}

impl From<Key> for ArcIdentity {
    fn from(key: Key) -> Self {
        match key {
            Key::WithRaw(key) => key.identity,
            Key::Identity(identity) => identity,
        }
    }
}

impl From<&Key> for ArcIdentity {
    fn from(key: &Key) -> Self {
        match key {
            Key::WithRaw(key) => key.identity.clone(),
            Key::Identity(identity) => identity.clone(),
        }
    }
}

impl From<ArcIdentity> for Key {
    fn from(identity: ArcIdentity) -> Self {
        Key::Identity(identity)
    }
}

impl From<&ArcIdentity> for Key {
    fn from(identity: &ArcIdentity) -> Self {
        Key::Identity(identity.clone())
    }
}

/// Enum representing the type of base key used for the identity.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Default)]
pub enum BaseKeyType {
    /// Ed25519 base key type.
    #[default]
    Ed25519,
    /// Prime256v1 (P-256/secp256r1) base key type.
    Prime256v1,
    /// Secp256k1 base key type.
    Secp256k1,
}

impl fmt::Display for BaseKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseKeyType::Ed25519 => write!(f, "{}", ED25519_KEY_LABEL),
            BaseKeyType::Prime256v1 => write!(f, "{}", PRIME256V1_KEY_LABEL),
            BaseKeyType::Secp256k1 => write!(f, "{}", SECP256K1_KEY_LABEL),
        }
    }
}

impl std::str::FromStr for BaseKeyType {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            ED25519_KEY_LABEL => Ok(BaseKeyType::Ed25519),
            PRIME256V1_KEY_LABEL => Ok(BaseKeyType::Prime256v1),
            SECP256K1_KEY_LABEL => Ok(BaseKeyType::Secp256k1),
            _ => Err(()),
        }
    }
}

impl BaseKeyType {
    /// Determines the base key type for a given identity, if known.
    pub fn from_identity(identity: &ArcIdentity) -> Option<Self> {
        match identity {
            ArcIdentity::Anonymous(_) => None,
            ArcIdentity::Delegated(_) => None,
            ArcIdentity::Ed25519(_) => Some(BaseKeyType::Ed25519),
            ArcIdentity::Prime256v1(_) => Some(BaseKeyType::Prime256v1),
            ArcIdentity::Secp256k1(_) => Some(BaseKeyType::Secp256k1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey as K256SecretKey;
    use p256::SecretKey as P256SecretKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_prime256v1_key_with_raw() {
        let mut rng = OsRng;
        let secret = P256SecretKey::random(&mut rng);
        let raw = secret.to_sec1_der().unwrap().to_vec();
        let key = KeyWithRaw::new_with_type(BaseKeyType::Prime256v1, raw).unwrap();
        assert_eq!(key.key_type(), BaseKeyType::Prime256v1);
        assert!(key.identity.public_key().is_some());
    }

    #[test]
    fn test_secp256k1_key_with_raw() {
        let mut rng = OsRng;
        let secret = K256SecretKey::random(&mut rng);
        let raw = secret.to_sec1_der().unwrap().to_vec();
        let key = KeyWithRaw::new_with_type(BaseKeyType::Secp256k1, raw).unwrap();
        assert_eq!(key.key_type(), BaseKeyType::Secp256k1);
        assert!(key.identity.public_key().is_some());
    }

    #[test]
    fn test_prime256v1_invalid_key_bytes() {
        let result = KeyWithRaw::new_with_type(BaseKeyType::Prime256v1, vec![0u8; 31]);
        assert!(result.is_err());
    }

    #[test]
    fn test_secp256k1_invalid_key_bytes() {
        let result = KeyWithRaw::new_with_type(BaseKeyType::Secp256k1, vec![0u8; 31]);
        assert!(result.is_err());
    }
}
