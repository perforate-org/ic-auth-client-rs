//! Storage implementations for authentication client data.
//!
//! This module provides keyring and filesystem-based storage for secure credential management.

use crate::storage::{StorageError, StoredKey};

#[cfg(feature = "keyring")]
pub mod keyring;
#[cfg(feature = "android-password")]
pub mod password;
#[cfg(feature = "pem")]
pub mod pem;

#[cfg(feature = "keyring")]
pub use keyring::KeyringStorage;
#[cfg(feature = "android-password")]
pub use password::PasswordStorage;
#[cfg(feature = "pem")]
pub use pem::PemStorage;

/// Trait for persisting user authentication data.
pub trait AuthClientStorage: Send {
    /// Retrieves a stored value by key.
    ///
    /// # Arguments
    /// * `key` - The key to look up in storage
    ///
    /// # Returns
    /// * `Ok(Some(StoredKey))` if the key exists in storage
    /// * `Ok(None)` if the key does not exist
    /// * `Err(StorageError)` if an error occurred
    fn get(&mut self, key: &str) -> Result<Option<StoredKey>, StorageError>;

    /// Stores a key-value pair in the storage.
    ///
    /// # Arguments
    /// * `key` - The key to store the value under
    /// * `value` - The value to store
    ///
    /// # Returns
    /// * `Ok(())` if the value was successfully stored
    /// * `Err(StorageError)` if an error occurred during storage
    fn set(&mut self, key: &str, value: StoredKey) -> Result<(), StorageError>;

    /// Removes a stored value by key.
    ///
    /// # Arguments
    /// * `key` - The key to remove from storage
    ///
    /// # Returns
    /// * `Ok(())` if the key was successfully removed
    /// * `Err(StorageError)` if an error occurred during removal
    fn remove(&mut self, key: &str) -> Result<(), StorageError>;
}
