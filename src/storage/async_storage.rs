//! Storage implementations for authentication client data.
//!
//! This module provides browser-based storage for secure credential management.

use super::{StorageError, StoredKey};
use futures::future::LocalBoxFuture;
use idb::{Database, DatabaseEvent, Factory, ObjectStoreParams, TransactionMode};
use js_sys::Reflect;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::js_sys;
use web_sys::{CryptoKey, CryptoKeyPair, Storage, js_sys::Uint8Array};

const LOCAL_STORAGE_PREFIX: &str = "ic-";
type StorageFuture<'a, T> = LocalBoxFuture<'a, T>;

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalStorage;

impl LocalStorage {
    /// Creates a new instance of [`LocalStorage`].
    pub fn new() -> Self {
        Self
    }

    fn get_local_storage(&self) -> Option<Storage> {
        match gloo_utils::window().local_storage() {
            Ok(storage) => storage,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not find local storage: {_e:?}");
                None
            }
        }
    }
}

impl AuthClientStorage for LocalStorage {
    fn get<'a>(
        &'a mut self,
        key: &'a str,
    ) -> StorageFuture<'a, Result<Option<StoredKey>, StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            let value = local_storage.get_item(&key)?;
            Ok(value.map(StoredKey::String))
        })
    }

    fn set<'a>(
        &'a mut self,
        key: &'a str,
        value: StoredKey,
    ) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            match value {
                StoredKey::String(value) => {
                    local_storage.set_item(&key, value.as_ref())?;
                }
                StoredKey::Raw(bytes) => {
                    let value = StoredKey::Raw(bytes).encode();
                    local_storage.set_item(&key, value.as_ref())?;
                }
                #[cfg(feature = "wasm-js")]
                StoredKey::CryptoKeyPair(_) => {
                    return Err(StorageError::WebSys(
                        "CryptoKeyPair cannot be stored in LocalStorage".to_string(),
                    ));
                }
            }
            Ok(())
        })
    }

    fn remove<'a>(&'a mut self, key: &'a str) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            local_storage.remove_item(&key)?;
            Ok(())
        })
    }

    fn contains_key<'a>(
        &'a mut self,
        key: &'a str,
    ) -> StorageFuture<'a, Result<bool, StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            Ok(local_storage.get_item(&key)?.is_some())
        })
    }

    fn clear<'a>(&'a mut self) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let mut keys_to_remove = Vec::new();
            let len = local_storage.length()?;
            for i in 0..len {
                if let Some(key) = local_storage.key(i)? {
                    if key.starts_with(LOCAL_STORAGE_PREFIX) {
                        keys_to_remove.push(key);
                    }
                }
            }
            for key in keys_to_remove {
                local_storage.remove_item(&key)?;
            }
            Ok(())
        })
    }
}

impl From<LocalStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: LocalStorage) -> Self {
        Box::new(storage)
    }
}

/// IndexedDB-backed storage implementation.
#[derive(Debug, Clone)]
pub struct IdbStorage {
    db_name: String,
    store_name: String,
}

impl IdbStorage {
    /// Default IndexedDB database name.
    pub const DEFAULT_DB_NAME: &'static str = "auth-client-db";
    /// Default IndexedDB object store name.
    pub const DEFAULT_STORE_NAME: &'static str = "ic-keyval";

    /// Creates a new [`IdbStorage`] with default database and store names.
    pub async fn new() -> Result<Self, StorageError> {
        Self::with_options(Self::DEFAULT_DB_NAME, Self::DEFAULT_STORE_NAME).await
    }

    /// Creates a new [`IdbStorage`] with the provided database and store names.
    pub async fn with_options(db_name: &str, store_name: &str) -> Result<Self, StorageError> {
        let storage = Self {
            db_name: db_name.to_string(),
            store_name: store_name.to_string(),
        };
        storage.ensure_db().await?;
        Ok(storage)
    }

    async fn ensure_db(&self) -> Result<(), StorageError> {
        let _ = self.open_database().await?;
        Ok(())
    }

    async fn open_database(&self) -> Result<Database, StorageError> {
        let factory = Factory::new().map_err(idb_error)?;
        let mut open_request = factory.open(&self.db_name, Some(1)).map_err(idb_error)?;
        let store_name_owned = self.store_name.clone();
        open_request.on_upgrade_needed(move |event| {
            if let Ok(database) = event.database() {
                if !database
                    .store_names()
                    .iter()
                    .any(|name| name == &store_name_owned)
                {
                    let params = ObjectStoreParams::new();
                    let _ = database.create_object_store(&store_name_owned, params);
                }
            }
        });
        open_request.await.map_err(idb_error)
    }
}

impl From<IdbStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: IdbStorage) -> Self {
        Box::new(storage)
    }
}

impl AuthClientStorage for IdbStorage {
    fn get<'a>(
        &'a mut self,
        key: &'a str,
    ) -> StorageFuture<'a, Result<Option<StoredKey>, StorageError>> {
        Box::pin(async move {
            let db = self.open_database().await?;
            let transaction = db
                .transaction(&[self.store_name.as_str()], TransactionMode::ReadOnly)
                .map_err(idb_error)?;
            let store = transaction
                .object_store(&self.store_name)
                .map_err(idb_error)?;
            let request = store.get(JsValue::from_str(key)).map_err(idb_error)?;
            let value = request.await.map_err(idb_error)?;
            let _ = transaction.await.map_err(idb_error)?;
            Ok(value.and_then(stored_key_from_js))
        })
    }

    fn set<'a>(
        &'a mut self,
        key: &'a str,
        value: StoredKey,
    ) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let db = self.open_database().await?;
            let transaction = db
                .transaction(&[self.store_name.as_str()], TransactionMode::ReadWrite)
                .map_err(idb_error)?;
            let store = transaction
                .object_store(&self.store_name)
                .map_err(idb_error)?;
            let value = stored_key_to_js(value);
            store
                .put(&value, Some(&JsValue::from_str(key)))
                .map_err(idb_error)?
                .await
                .map_err(idb_error)?;
            let _ = transaction
                .commit()
                .map_err(idb_error)?
                .await
                .map_err(idb_error)?;
            Ok(())
        })
    }

    fn remove<'a>(&'a mut self, key: &'a str) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let db = self.open_database().await?;
            let transaction = db
                .transaction(&[self.store_name.as_str()], TransactionMode::ReadWrite)
                .map_err(idb_error)?;
            let store = transaction
                .object_store(&self.store_name)
                .map_err(idb_error)?;
            store
                .delete(JsValue::from_str(key))
                .map_err(idb_error)?
                .await
                .map_err(idb_error)?;
            let _ = transaction
                .commit()
                .map_err(idb_error)?
                .await
                .map_err(idb_error)?;
            Ok(())
        })
    }

    fn contains_key<'a>(
        &'a mut self,
        key: &'a str,
    ) -> StorageFuture<'a, Result<bool, StorageError>> {
        Box::pin(async move { Ok(self.get(key).await?.is_some()) })
    }

    fn clear<'a>(&'a mut self) -> StorageFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let db = self.open_database().await?;
            let transaction = db
                .transaction(&[self.store_name.as_str()], TransactionMode::ReadWrite)
                .map_err(idb_error)?;
            let store = transaction
                .object_store(&self.store_name)
                .map_err(idb_error)?;
            store.clear().map_err(idb_error)?.await.map_err(idb_error)?;
            let _ = transaction
                .commit()
                .map_err(idb_error)?
                .await
                .map_err(idb_error)?;
            Ok(())
        })
    }
}

fn stored_key_to_js(value: StoredKey) -> JsValue {
    match value {
        StoredKey::String(string) => JsValue::from_str(&string),
        StoredKey::Raw(bytes) => {
            let array = Uint8Array::from(bytes.as_slice());
            array.into()
        }
        #[cfg(feature = "wasm-js")]
        StoredKey::CryptoKeyPair(pair) => JsValue::from(pair),
    }
}

fn stored_key_from_js(value: JsValue) -> Option<StoredKey> {
    if value.is_string() {
        return value.as_string().map(StoredKey::String);
    }
    #[cfg(feature = "wasm-js")]
    {
        if let Ok(pair) = value.clone().dyn_into::<CryptoKeyPair>() {
            return Some(StoredKey::CryptoKeyPair(pair));
        }
        if value.is_object() {
            let private_key = Reflect::get(&value, &JsValue::from_str("privateKey"))
                .ok()
                .and_then(|val| val.dyn_into::<CryptoKey>().ok());
            let public_key = Reflect::get(&value, &JsValue::from_str("publicKey"))
                .ok()
                .and_then(|val| val.dyn_into::<CryptoKey>().ok());
            if let (Some(private_key), Some(public_key)) = (private_key, public_key) {
                return Some(StoredKey::CryptoKeyPair(CryptoKeyPair::new(
                    &private_key,
                    &public_key,
                )));
            }
        }
    }
    if value.is_instance_of::<js_sys::Uint8Array>() || value.is_instance_of::<js_sys::ArrayBuffer>()
    {
        let array = Uint8Array::new(&value);
        let mut buffer = vec![0u8; array.length() as usize];
        array.copy_to(&mut buffer);
        return Some(StoredKey::Raw(buffer));
    }
    None
}

fn idb_error(error: idb::Error) -> StorageError {
    StorageError::WebSys(error.to_string())
}

/// Trait for persisting user authentication data.
pub trait AuthClientStorage: Send {
    /// Retrieves a stored value by key from the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to retrieve the value for. The key will be prefixed with the storage prefix.
    ///
    /// # Returns
    /// Returns `Ok(Some(StoredKey))` if the key exists in storage, `Ok(None)` if not, or
    /// `Err(StorageError)` if there was an error accessing the storage.
    fn get<'a>(
        &'a mut self,
        key: &'a str,
    ) -> StorageFuture<'a, Result<Option<StoredKey>, StorageError>>;

    /// Stores a value with the given key in the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to store the value under. The key will be prefixed with the storage prefix.
    /// - `value`: The value to store, which will be encoded before storage.
    ///
    /// # Returns
    /// Returns `Ok(())` if the value was successfully stored, or `Err(StorageError)` if there was an
    /// error accessing the storage or storing the value.
    fn set<'a>(
        &'a mut self,
        key: &'a str,
        value: StoredKey,
    ) -> StorageFuture<'a, Result<(), StorageError>>;

    /// Removes a stored value by key from the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to remove from storage. The key will be prefixed with the storage prefix.
    ///
    /// # Returns
    /// Returns `Ok(())` if the key was successfully removed or didn't exist, or `Err(StorageError)`
    /// if there was an error accessing the storage.
    fn remove<'a>(&'a mut self, key: &'a str) -> StorageFuture<'a, Result<(), StorageError>>;

    /// Checks if a key exists in storage.
    fn contains_key<'a>(
        &'a mut self,
        key: &'a str,
    ) -> StorageFuture<'a, Result<bool, StorageError>>;

    /// Clears all stored keys in the storage backend.
    fn clear<'a>(&'a mut self) -> StorageFuture<'a, Result<(), StorageError>>;
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_local_storage() {
        let mut storage = LocalStorage;
        let value = StoredKey::String("value".to_string());
        storage.set("test", value).await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, Some(StoredKey::String("value".to_string())));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, None);
    }

    #[wasm_bindgen_test]
    async fn test_indexeddb_storage_string_roundtrip() {
        let mut storage = IdbStorage::new().await.unwrap();
        let value = StoredKey::String("value".to_string());
        storage.set("test", value).await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, Some(StoredKey::String("value".to_string())));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, None);
    }

    #[wasm_bindgen_test]
    async fn test_indexeddb_storage_raw_roundtrip_and_clear() {
        let mut storage = IdbStorage::new().await.unwrap();
        let value = StoredKey::Raw(vec![1, 2, 3, 4]);
        storage.set("test", value.clone()).await.unwrap();
        let saved_value = storage.get("test").await.unwrap();
        assert_eq!(saved_value, Some(value));
        storage.clear().await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, None);
    }
}
