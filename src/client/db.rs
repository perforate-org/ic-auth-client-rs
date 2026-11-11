//! IndexedDB key/value layer used by the wasm credential store.
//!
//! Port of upstream `src/client/db.ts`: one object store, out-of-line string
//! keys, no key path and no indexes. Two browser behaviours are the reason this
//! is a wrapper rather than a call site:
//!
//! - a connection can be force-closed by the browser at any time; the `close`
//!   event drops the cached connection so the next operation opens a fresh one;
//! - Chrome can force-close a connection without firing that event, and the
//!   next transaction then throws `InvalidStateError`. That error is matched by
//!   name (a `DOMException` is not an `Error`), the connection is dropped and
//!   the action retried **once** (`db.ts:89-127`).
//!
//! Opening is eager, so an unavailable database fails at creation rather than at
//! first use, and a failed open is never cached (`db.ts:68-78`, test
//! `idb-credential-storage.test.ts:98-106`). This module only runs in a browser
//! or a worker: `idb` needs `indexedDB`, so its behaviour is exercised by the
//! Playwright/browser harness rather than by native unit tests.

use std::cell::RefCell;
use std::rc::Rc;

use futures::FutureExt as _;
use futures::future::{LocalBoxFuture, Shared};
use idb::{Database, DatabaseEvent as _, Factory, ObjectStoreParams, TransactionMode};
use wasm_bindgen::JsValue;

use crate::client::error::AuthClientError;

/// Increment when the shape of what is stored changes.
pub const DB_VERSION: u32 = 1;

/// The default database.
pub const AUTH_DB_NAME: &str = "auth-client-db";

/// The default object store.
pub const OBJECT_STORE_NAME: &str = "ic-keyval";

/// Options for [`IdbKeyVal::create`].
///
/// Port of upstream `DBCreateOptions` (`db.ts:49-53`); every field is optional
/// and the defaults are [`AUTH_DB_NAME`], [`OBJECT_STORE_NAME`] and
/// [`DB_VERSION`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DBCreateOptions {
    /// Name for the IndexedDB database.
    pub db_name: Option<String>,
    /// Name for the object store inside it.
    pub store_name: Option<String>,
    /// Database version; increment to upgrade.
    pub version: Option<u32>,
}

impl DBCreateOptions {
    /// Options that resolve to every default.
    pub fn new() -> Self {
        Self::default()
    }

    /// The database name.
    pub fn with_db_name(mut self, db_name: impl Into<String>) -> Self {
        self.db_name = Some(db_name.into());
        self
    }

    /// The object store name.
    pub fn with_store_name(mut self, store_name: impl Into<String>) -> Self {
        self.store_name = Some(store_name.into());
        self
    }

    /// The database version.
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// The three values an open needs, with defaults applied.
    pub fn resolved(&self) -> (String, String, u32) {
        (
            self.db_name
                .clone()
                .unwrap_or_else(|| AUTH_DB_NAME.to_string()),
            self.store_name
                .clone()
                .unwrap_or_else(|| OBJECT_STORE_NAME.to_string()),
            self.version.unwrap_or(DB_VERSION),
        )
    }
}

type OpenFuture = Shared<LocalBoxFuture<'static, Result<Rc<Database>, String>>>;

/// A key/value store over one IndexedDB object store.
///
/// Port of upstream `IdbKeyVal` (`db.ts:59-158`). Cloneable, so several stores
/// (a credential store and the state mirror) can share one connection.
#[derive(Clone)]
pub struct IdbKeyVal {
    inner: Rc<IdbKeyValInner>,
}

struct IdbKeyValInner {
    db_name: String,
    store_name: String,
    version: u32,
    /// The open connection, dropped when the browser closes it.
    database: RefCell<Option<Rc<Database>>>,
    /// The open in flight, shared so concurrent first accesses open once.
    opening: RefCell<Option<OpenFuture>>,
}

impl std::fmt::Debug for IdbKeyVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdbKeyVal")
            .field("db_name", &self.inner.db_name)
            .field("store_name", &self.inner.store_name)
            .field("version", &self.inner.version)
            .finish_non_exhaustive()
    }
}

impl IdbKeyVal {
    /// Opens the database eagerly and returns the store.
    pub async fn create(options: DBCreateOptions) -> Result<Self, AuthClientError> {
        let (db_name, store_name, version) = options.resolved();
        let store = Self {
            inner: Rc::new(IdbKeyValInner {
                db_name,
                store_name,
                version,
                database: RefCell::new(None),
                opening: RefCell::new(None),
            }),
        };
        store.open().await?;
        Ok(store)
    }

    /// The value under `key`, or `None` where there is none.
    ///
    /// `undefined` is normalised to `None`, as upstream does
    /// (`db.ts:146-148`).
    pub async fn get(&self, key: &str) -> Result<Option<JsValue>, AuthClientError> {
        let database = self.open().await?;
        let store_name = self.inner.store_name.clone();
        match get_value(&database, &store_name, key).await {
            Ok(value) => Ok(value),
            Err(error) if is_invalid_state_error(&error) => {
                self.invalidate();
                let database = self.open().await?;
                get_value(&database, &store_name, key)
                    .await
                    .map_err(map_idb_error)
            }
            Err(error) => Err(map_idb_error(error)),
        }
    }

    /// Stores `value` under `key`.
    pub async fn set(&self, key: &str, value: &JsValue) -> Result<(), AuthClientError> {
        let database = self.open().await?;
        let store_name = self.inner.store_name.clone();
        match set_value(&database, &store_name, key, value).await {
            Ok(()) => Ok(()),
            Err(error) if is_invalid_state_error(&error) => {
                self.invalidate();
                let database = self.open().await?;
                set_value(&database, &store_name, key, value)
                    .await
                    .map_err(map_idb_error)
            }
            Err(error) => Err(map_idb_error(error)),
        }
    }

    /// Removes `key`.
    pub async fn remove(&self, key: &str) -> Result<(), AuthClientError> {
        let database = self.open().await?;
        let store_name = self.inner.store_name.clone();
        match remove_value(&database, &store_name, key).await {
            Ok(()) => Ok(()),
            Err(error) if is_invalid_state_error(&error) => {
                self.invalidate();
                let database = self.open().await?;
                remove_value(&database, &store_name, key)
                    .await
                    .map_err(map_idb_error)
            }
            Err(error) => Err(map_idb_error(error)),
        }
    }

    async fn open(&self) -> Result<Rc<Database>, AuthClientError> {
        if let Some(database) = self.inner.database.borrow().clone() {
            return Ok(database);
        }
        let shared = {
            let mut opening = self.inner.opening.borrow_mut();
            match opening.as_ref() {
                Some(shared) => shared.clone(),
                None => {
                    let shared = open_database(self.inner.clone()).boxed_local().shared();
                    *opening = Some(shared.clone());
                    shared
                }
            }
        };
        let result = shared.await;
        // Whatever happened, the next call starts a fresh attempt rather than
        // reusing this one: a failed open is not cached.
        *self.inner.opening.borrow_mut() = None;
        result.map_err(AuthClientError::Storage)
    }

    fn invalidate(&self) {
        *self.inner.database.borrow_mut() = None;
        *self.inner.opening.borrow_mut() = None;
    }
}

/// Opens the database, with the upgrade policy this port follows: if the object
/// store already exists it is emptied, because there is no record-level
/// migration (`db.ts:11-26`).
fn open_database(
    inner: Rc<IdbKeyValInner>,
) -> LocalBoxFuture<'static, Result<Rc<Database>, String>> {
    Box::pin(async move {
        let factory = Factory::new().map_err(|error| error.to_string())?;
        let mut request = factory
            .open(&inner.db_name, Some(inner.version))
            .map_err(|error| error.to_string())?;
        let store_name = inner.store_name.clone();
        request.on_upgrade_needed(move |event| {
            let Ok(database) = event.database() else {
                return;
            };
            if database
                .store_names()
                .iter()
                .any(|name| name == &store_name)
            {
                // This version's whole migration path: empty the store.
                if let Ok(transaction) =
                    database.transaction(&[store_name.as_str()], TransactionMode::ReadWrite)
                {
                    if let Ok(store) = transaction.object_store(&store_name) {
                        let _ = store.clear();
                    }
                    let _ = transaction.commit();
                }
                return;
            }
            let _ = database.create_object_store(&store_name, ObjectStoreParams::new());
        });

        let mut database = request.await.map_err(|error| error.to_string())?;

        // The browser can force-close the connection; the hook drops it so the
        // next operation opens a fresh one.
        let weak = Rc::downgrade(&inner);
        database.on_close(move |_| {
            if let Some(inner) = weak.upgrade() {
                *inner.database.borrow_mut() = None;
            }
        });

        let database = Rc::new(database);
        *inner.database.borrow_mut() = Some(database.clone());
        Ok(database)
    })
}

async fn get_value(
    database: &Database,
    store_name: &str,
    key: &str,
) -> Result<Option<JsValue>, idb::Error> {
    let transaction = database.transaction(&[store_name], TransactionMode::ReadOnly)?;
    let store = transaction.object_store(store_name)?;
    let request = store.get(JsValue::from_str(key))?;
    let value = request.await?;
    let _ = transaction.await?;
    match value {
        Some(value) if !value.is_undefined() => Ok(Some(value)),
        _ => Ok(None),
    }
}

async fn set_value(
    database: &Database,
    store_name: &str,
    key: &str,
    value: &JsValue,
) -> Result<(), idb::Error> {
    let transaction = database.transaction(&[store_name], TransactionMode::ReadWrite)?;
    let store = transaction.object_store(store_name)?;
    store.put(value, Some(&JsValue::from_str(key)))?.await?;
    let _ = transaction.commit()?.await?;
    Ok(())
}

async fn remove_value(database: &Database, store_name: &str, key: &str) -> Result<(), idb::Error> {
    let transaction = database.transaction(&[store_name], TransactionMode::ReadWrite)?;
    let store = transaction.object_store(store_name)?;
    store.delete(JsValue::from_str(key))?.await?;
    let _ = transaction.commit()?.await?;
    Ok(())
}

/// The name of a JS exception, if it has one.
fn js_error_name(value: &JsValue) -> Option<String> {
    web_sys::js_sys::Reflect::get(value, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string())
}

/// Whether an IndexedDB failure is the force-closed-connection one.
///
/// Matched by name because a `DOMException` does not inherit `Error`
/// (`db.ts:113-120`).
fn is_invalid_state_error(error: &idb::Error) -> bool {
    match error {
        idb::Error::TransactionOpenFailed(value) => {
            js_error_name(value).as_deref() == Some("InvalidStateError")
        }
        idb::Error::DomException(exception) => exception.name() == "InvalidStateError",
        _ => false,
    }
}

fn map_idb_error(error: idb::Error) -> AuthClientError {
    AuthClientError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_resolve_to_the_documented_defaults() {
        let (db_name, store_name, version) = DBCreateOptions::new().resolved();
        assert_eq!(db_name, "auth-client-db");
        assert_eq!(store_name, "ic-keyval");
        assert_eq!(version, 1);
        assert_eq!(db_name, AUTH_DB_NAME);
        assert_eq!(store_name, OBJECT_STORE_NAME);
        assert_eq!(version, DB_VERSION);
    }

    #[test]
    fn options_override_one_field_at_a_time() {
        let options = DBCreateOptions::new()
            .with_db_name("state-db")
            .with_store_name("state-store")
            .with_version(3);
        assert_eq!(
            options.resolved(),
            ("state-db".to_string(), "state-store".to_string(), 3)
        );

        let options = DBCreateOptions {
            db_name: Some("only-db".to_string()),
            ..DBCreateOptions::new()
        };
        assert_eq!(
            options.resolved(),
            (
                "only-db".to_string(),
                OBJECT_STORE_NAME.to_string(),
                DB_VERSION
            )
        );
    }
}
