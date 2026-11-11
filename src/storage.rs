//! Storage module for managing key storage.
//!
//! This module provides utilities for storing and retrieving keys securely.
//! It includes support for both asynchronous and synchronous storage backends.

use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use thiserror::Error;

pub mod js_compat;
#[cfg(feature = "native")]
pub mod sync_storage;

/// The key the PEM store keeps its identity material under.
pub const KEY_STORAGE_KEY: &str = "identity";

/// Enum for storing different types of keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredKey {
    /// A string representation (typically JSON or base64).
    String(String),
    /// Raw key data.
    Raw(Vec<u8>),
}

impl StoredKey {
    /// Decodes the stored key into raw bytes.
    ///
    /// For `String` variants, decodes from base64. For `Raw` variants, returns the bytes directly.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::Base64` if base64 decoding fails.
    pub fn decode(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
            StoredKey::String(s) => {
                let bytes = BASE64_STANDARD_NO_PAD
                    .decode(s)
                    .map_err(DecodeError::Base64)?;
                Ok(bytes)
            }
            StoredKey::Raw(bytes) => Ok(bytes.clone()),
        }
    }

    /// Decodes the stored key into a 32-byte array for Ed25519 keys.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::Ed25519` if the decoded data is not exactly 32 bytes.
    pub fn decode_ed25519(&self) -> Result<[u8; 32], DecodeError> {
        let bytes = self.decode()?;
        bytes
            .try_into()
            .map_err(|_| DecodeError::Ed25519("Invalid slice length".to_string()))
    }

    /// Encodes the stored key as a string.
    ///
    /// For `String` variants, returns the string directly. For `Raw` variants, encodes as base64.
    pub fn encode(&self) -> String {
        match self {
            StoredKey::String(s) => s.clone(),
            StoredKey::Raw(bytes) => BASE64_STANDARD_NO_PAD.encode(bytes),
        }
    }
}

impl From<[u8; 32]> for StoredKey {
    fn from(value: [u8; 32]) -> Self {
        StoredKey::Raw(value.to_vec())
    }
}

impl TryFrom<Vec<u8>> for StoredKey {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(StoredKey::Raw(value))
    }
}

impl From<String> for StoredKey {
    fn from(value: String) -> Self {
        StoredKey::String(value)
    }
}

/// Error type for key decoding operations.
///
/// This enum represents the various errors that can occur when decoding
/// stored keys, including Ed25519-specific errors and base64 decoding errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeError {
    /// An error related to Ed25519 key operations.
    ///
    /// This variant is used for Ed25519-specific errors, such as invalid
    /// key lengths or malformed key data.
    #[error("Ed25519 error: {0}")]
    Ed25519(String),
    /// An error that occurred during base64 decoding.
    ///
    /// This variant wraps base64 decoding errors that can occur when
    /// converting string-encoded keys back to binary format.
    #[error("Base64 error: {0}")]
    Base64(base64::DecodeError),
    /// An error related to key decoding or parsing.
    #[error("Key error: {0}")]
    Key(String),
}

/// Error type for storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    /// An error from the keyring.
    #[error("Keyring error: {0}")]
    Keyring(String),
    /// An error from the web-sys storage.
    #[error("Web Sys error: {0}")]
    WebSys(String),
    /// An error from filesystem storage.
    #[error("File storage error: {0}")]
    File(String),
    /// An error that occurred during decoding.
    #[error("Decode error: {0}")]
    Decode(#[from] DecodeError),
}

#[cfg(feature = "keyring")]
impl From<keyring::Error> for StorageError {
    fn from(err: keyring::Error) -> Self {
        StorageError::Keyring(err.to_string())
    }
}

#[cfg(feature = "wasm-js")]
impl From<web_sys::wasm_bindgen::JsValue> for StorageError {
    fn from(err: web_sys::wasm_bindgen::JsValue) -> Self {
        StorageError::WebSys(
            err.as_string()
                .unwrap_or_else(|| "unknown websys error".to_string()),
        )
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::File(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_stored_key_encode_decode() {
        let mut rng = rand::rng();
        let signing_key = SigningKey::generate(&mut rng);
        let raw_key = signing_key.to_bytes();

        let encoded = StoredKey::Raw(raw_key.to_vec()).encode();
        let key = StoredKey::String(encoded);
        let decoded = key.decode_ed25519().unwrap();
        assert_eq!(raw_key, decoded);
    }
}
