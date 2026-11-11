//! Secure credentials in IndexedDB (wasm).
//!
//! Port of upstream `credentials/idb-credential-storage.ts`. IndexedDB is what
//! a browser offers that can hold a key whose private half a page cannot read,
//! so it is the default store. One record per slot:
//! `{ keyPair: CryptoKeyPair, chain?: string }`.
//!
//! ## The one deliberate difference from upstream
//!
//! Upstream generates a **non-extractable** key pair: the private key never
//! leaves WebCrypto. A Rust client has no WebCrypto signing identity — it signs
//! with the `p256` crate — so it must be able to read its own key back after a
//! reload. This store therefore generates the key with `p256`, imports it into
//! WebCrypto as an **extractable** pair, keeps the private bytes for signing,
//! and writes the pair so JS v11 can read the record.
//!
//! What that costs is one-directional interop:
//!
//! - Rust → JS works: `ECDSAKeyIdentity.fromKeyPair` only exports the public
//!   half, which is exportable regardless of the private key's flag.
//! - JS → Rust is best effort: a pair JS v11 wrote is non-extractable, so
//!   `exportKey("jwk", privateKey)` is refused. This store then reports the
//!   slot as empty rather than guessing — signing in again is the safe answer,
//!   and the alternative is an identity Rust cannot use anyway.
//!
//! The record shape, database name, store name, version and upgrade policy all
//! match upstream exactly, so a record this store writes is the record v11
//! reads.

use std::cell::RefCell;

use async_trait::async_trait;
use wasm_bindgen::JsValue;

use crate::ArcIdentity;
use crate::client::credentials::p256;
use crate::client::credentials::wasm;
use crate::client::credentials::{Credential, CredentialStorage, SecretRegistry};
use crate::client::db::{DBCreateOptions, IdbKeyVal};
use crate::client::error::AuthClientError;

/// Credentials in IndexedDB: `shared = true`, `durable = true`, P-256 keys.
///
/// Port of upstream `IdbCredentialStorage` (`idb-credential-storage.ts:1-82`).
pub struct IdbCredentialStorage {
    options: DBCreateOptions,
    /// Opened on first use, and forgotten again if opening failed, so a later
    /// call retries rather than reusing a rejected attempt.
    database: RefCell<Option<IdbKeyVal>>,
    registry: SecretRegistry,
}

impl std::fmt::Debug for IdbCredentialStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdbCredentialStorage")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Default for IdbCredentialStorage {
    fn default() -> Self {
        Self::new(DBCreateOptions::new())
    }
}

impl IdbCredentialStorage {
    /// A store in the database named by `options`.
    pub fn new(options: DBCreateOptions) -> Self {
        Self {
            options,
            database: RefCell::new(None),
            registry: SecretRegistry::new(),
        }
    }

    async fn database(&self) -> Result<IdbKeyVal, AuthClientError> {
        if let Some(database) = self.database.borrow().clone() {
            return Ok(database);
        }
        // Not stored on failure: the next call opens again.
        let created = IdbKeyVal::create(self.options.clone()).await?;
        *self.database.borrow_mut() = Some(created.clone());
        Ok(created)
    }
}

#[async_trait(?Send)]
impl CredentialStorage for IdbCredentialStorage {
    fn shared(&self) -> bool {
        true
    }

    fn durable(&self) -> bool {
        true
    }

    async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
        let (identity, secret) = p256::generate()?;
        self.registry.remember(&identity, secret);
        Ok(identity)
    }

    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
        let database = self.database().await?;
        let Some(record) = database.get(slot).await? else {
            return Ok(None);
        };
        let Some(key_pair) =
            wasm::get_prop(&record, "keyPair").and_then(|value| p256::key_pair_from_value(&value))
        else {
            return Ok(None);
        };
        // `None` here is the JS→Rust limit described above: a non-extractable
        // pair cannot be turned back into key material Rust can sign with.
        let Some(secret) = p256::secret_from_key_pair(&key_pair).await? else {
            return Ok(None);
        };
        let Ok(identity) = p256::identity_from_scalar(&secret) else {
            return Ok(None);
        };
        self.registry.remember(&identity, secret);

        let chain = match wasm::get_string(&record, "chain") {
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
                    "this store can only serialise a key it generated or read".to_string(),
                )
            })?;
        let key_pair = p256::key_pair_from_secret(&secret).await?;
        let record: JsValue = wasm::object().into();
        wasm::set_prop(&record, "keyPair", &JsValue::from(key_pair))
            .map_err(|error| AuthClientError::Storage(wasm::display(&error)))?;
        if let Some(chain) = &credential.chain {
            wasm::set_prop(&record, "chain", &JsValue::from_str(&chain.to_js_json()))
                .map_err(|error| AuthClientError::Storage(wasm::display(&error)))?;
        }
        let database = self.database().await?;
        database.set(slot, &record).await
    }

    async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
        let database = self.database().await?;
        database.remove(slot).await
    }
}
