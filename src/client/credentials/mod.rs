//! Where the material a client acts with is kept.
//!
//! Port of upstream `src/client/credentials/`. A credential is an identity and
//! the delegation that authorises it, held as one record: a delegation is
//! issued to a key, and held apart the two can disagree, leaving every reader
//! to decide what a chain whose key is missing means.

// The codecs and helpers below are what the JavaScript stores use; a
// native build compiles the stores that need them out, and would otherwise
// report every one of them as dead.
#![cfg_attr(not(feature = "wasm-js"), allow(dead_code))]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::client::error::AuthClientError;
use crate::client::platform::PlatformBounds;
use crate::delegation_chain::DelegationChain;
use crate::{ArcIdentity, key::BaseKeyType};

#[cfg(feature = "wasm-js")]
pub mod idb;
#[cfg(feature = "wasm-js")]
pub mod local;
#[cfg(feature = "native")]
pub mod native;
#[cfg(feature = "wasm-js")]
pub mod shared_memory;

mod memory;

#[cfg(feature = "wasm-js")]
pub(crate) mod p256;
#[cfg(feature = "wasm-js")]
pub(crate) mod wasm;

pub use memory::MemoryCredentialStorage;

#[cfg(feature = "wasm-js")]
pub use idb::IdbCredentialStorage;
#[cfg(feature = "wasm-js")]
pub use local::LocalCredentialStorage;
#[cfg(feature = "native")]
pub use native::NativeCredentialStorage;
#[cfg(feature = "wasm-js")]
pub use shared_memory::{
    DEFAULT_SHARED_MEMORY_NAME, SharedMemoryCredentialStorage, SharedMemoryOptions,
};

/// An identity, and the delegation that authorises it.
///
/// Port of upstream `Credential` (`credentials/credential-storage.ts:12-20`).
/// The chain is absent only while a ceremony is in flight, under the
/// session-pending slot: there is a key, and no delegation for it yet.
#[derive(Clone)]
pub struct Credential {
    /// The key that signs.
    pub identity: ArcIdentity,
    /// The delegation issued to that key.
    pub chain: Option<DelegationChain>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("identity", &self.identity)
            .field("chain", &self.chain.is_some())
            .finish()
    }
}

impl Credential {
    /// A credential whose key has no delegation yet.
    pub fn key_only(identity: ArcIdentity) -> Self {
        Self {
            identity,
            chain: None,
        }
    }

    /// A credential with the delegation issued to its key.
    pub fn with_chain(identity: ArcIdentity, chain: DelegationChain) -> Self {
        Self {
            identity,
            chain: Some(chain),
        }
    }

    /// The DER-encoded public key of this credential's identity.
    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        self.identity.public_key()
    }

    /// Whether this credential has the delegation that makes it usable.
    ///
    /// A key without a chain is not a credential upstream
    /// (`session/session-identity.ts:87-88`).
    pub fn is_complete(&self) -> bool {
        self.chain.is_some()
    }
}

/// Holds the material a client acts with, a credential per slot.
///
/// Port of upstream `CredentialStorage` (`credentials/credential-storage.ts:32-56`).
/// Asynchronous, because using a credential means making a call and a
/// non-extractable key needs a store that can hold one. A store declares two
/// things about its medium that the library cannot infer: whether another tab
/// reads what it writes, and whether what it writes survives the document being
/// torn down.
#[async_trait(?Send)]
pub trait CredentialStorage: PlatformBounds {
    /// Whether another tab of this origin reads what this writes.
    fn shared(&self) -> bool;

    /// Whether what this writes survives the document being torn down.
    fn durable(&self) -> bool;

    /// A fresh identity of this store's own type, not persisted.
    ///
    /// Generation belongs to the store because the medium decides the key type:
    /// one that has to serialise needs a key whose private bytes are readable.
    async fn create(&self) -> Result<ArcIdentity, AuthClientError>;

    /// The credential stored under `slot`, or `None` where there is none usable.
    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError>;

    /// Stores a credential under `slot`.
    async fn set(&self, slot: &str, credential: Credential) -> Result<(), AuthClientError>;

    /// Removes whatever is stored under `slot`.
    async fn remove(&self, slot: &str) -> Result<(), AuthClientError>;
}

/// A credential store the client holds behind an `Arc`.
pub type SharedCredentialStorage = Arc<dyn CredentialStorage>;

/// Builds an identity of the given base key type from freshly generated key
/// material.
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn generate_identity(key_type: BaseKeyType) -> Result<ArcIdentity, AuthClientError> {
    memory::create_identity(key_type)
}

// ---------------------------------------------------------------------------
// What a store persists
// ---------------------------------------------------------------------------

/// What one `localStorage` slot holds: the key as JSON, and the chain as JSON.
///
/// Port of upstream `StoredCredential` (`local-credential-storage.ts:4-8`).
/// `chain` is omitted rather than written as `null` when there is none, which
/// is what `JSON.stringify` does to an `undefined` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredCredentialRecord {
    /// `JSON.stringify(identity.toJSON())`.
    pub key: String,
    /// `JSON.stringify(chain.toJSON())`, when there is a chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
}

/// Encodes a credential as the string `localStorage` holds under a slot.
pub(crate) fn encode_credential_record(key_json: &str, chain_json: Option<&str>) -> String {
    let record = StoredCredentialRecord {
        key: key_json.to_string(),
        chain: chain_json.map(str::to_string),
    };
    serde_json::to_string(&record).expect("a stored credential record is serialisable")
}

/// Decodes a credential record, answering `None` where the medium holds
/// something this version cannot read.
///
/// Corrupt records are reported as absent rather than as an error: a caller
/// that finds nothing acquires again, which is safer than failing a page load
/// (`local-credential-storage.ts:36-45`).
pub(crate) fn decode_credential_record(raw: &str) -> Option<StoredCredentialRecord> {
    let record: StoredCredentialRecord = serde_json::from_str(raw).ok()?;
    if record.key.is_empty() {
        return None;
    }
    Some(record)
}

/// The DER prefix of an Ed25519 public key, as hex (OID 1.3.101.112).
const ED25519_DER_PREFIX_HEX: &str = "302a300506032b6570032100";

/// Encodes an Ed25519 seed the way `Ed25519KeyIdentity.toJSON` does.
///
/// The JS shape is a two-element JSON array: the DER-encoded public key as hex,
/// then the private key as hex. JS writes the 32-byte seed; a 64-byte
/// seed-plus-public form is also accepted on read, because some versions and
/// the existing JS-compatibility layer write it.
pub(crate) fn encode_ed25519_identity_json(seed: &[u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let public_der_hex = format!("{ED25519_DER_PREFIX_HEX}{}", hex::encode(public_key));
    serde_json::to_string(&[public_der_hex, hex::encode(seed)])
        .expect("an Ed25519 identity JSON is serialisable")
}

/// Decodes an Ed25519 seed from the JS identity JSON.
pub(crate) fn decode_ed25519_identity_json(json: &str) -> Option<[u8; 32]> {
    let [_, secret_hex]: [String; 2] = serde_json::from_str(json).ok()?;
    let secret = hex::decode(secret_hex).ok()?;
    // JS writes the 32-byte seed; the compatibility layer writes seed || public
    // (64 bytes). Signing only ever uses the first 32 bytes, as JS does
    // (`ed25519.js:178`).
    let seed: [u8; 32] = secret.get(..32)?.try_into().ok()?;
    Some(seed)
}

/// An identity for a raw Ed25519 seed.
pub(crate) fn ed25519_identity_from_seed(seed: &[u8; 32]) -> ArcIdentity {
    crate::key::KeyWithRaw::new(*seed).identity
}

/// The record a native store keeps for one slot.
///
/// Native media hold key material that has to be readable, so unlike the
/// browser stores this is the store's own encoding, not a JS-compatible one:
/// the secret is base64, and the chain is the Rust JSON form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) struct NativeCredentialRecord {
    /// Base64 (no padding) of the private key bytes the key type expects.
    pub key: String,
    /// Which curve the bytes are for.
    pub key_type: BaseKeyType,
    /// The chain as JSON, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
}

/// Encodes a native credential record.
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn encode_native_record(
    key_type: BaseKeyType,
    secret: &[u8],
    chain_json: Option<&str>,
) -> String {
    use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
    let record = NativeCredentialRecord {
        key: BASE64_STANDARD_NO_PAD.encode(secret),
        key_type,
        chain: chain_json.map(str::to_string),
    };
    serde_json::to_string(&record).expect("a native credential record is serialisable")
}

/// Decodes a native credential record into its key type, private bytes and
/// optional chain JSON.
#[cfg_attr(not(feature = "native"), allow(dead_code))]
pub(crate) fn decode_native_record(raw: &str) -> Option<(BaseKeyType, Vec<u8>, Option<String>)> {
    use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
    let record: NativeCredentialRecord = serde_json::from_str(raw).ok()?;
    let secret = BASE64_STANDARD_NO_PAD.decode(record.key).ok()?;
    if secret.is_empty() {
        return None;
    }
    Some((record.key_type, secret, record.chain))
}

/// Remembers the private bytes of the identities a store made or read.
///
/// A store is handed an [`ArcIdentity`], and the `Identity` trait exposes only
/// the public half: the key material needed to serialise a credential is not
/// readable back from it. So a store remembers the bytes at the moment it
/// generates a key or decodes one from its medium, keyed by the DER public key,
/// which every identity can answer with. This is the Rust port's stand-in for
/// upstream's type parameter, which ties each store to the identity type it can
/// serialise (`credential-storage.ts:39-47`).
#[derive(Default)]
pub(crate) struct SecretRegistry {
    secrets: std::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl SecretRegistry {
    /// A registry holding nothing.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Remembers the private bytes belonging to `identity`.
    pub(crate) fn remember(&self, identity: &ArcIdentity, secret: Vec<u8>) {
        let Some(public_key) = identity.public_key() else {
            return;
        };
        if let Ok(mut secrets) = self.secrets.lock() {
            secrets.insert(public_key, secret);
        }
    }

    /// The private bytes belonging to `identity`, when this store has seen them.
    pub(crate) fn secret_for(&self, identity: &ArcIdentity) -> Option<Vec<u8>> {
        let public_key = identity.public_key()?;
        let secrets = self.secrets.lock().ok()?;
        secrets.get(&public_key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_json() -> String {
        crate::delegation_chain::DelegationChain::new(Vec::new(), vec![1, 2, 3]).to_json()
    }

    #[test]
    fn credential_record_round_trips_without_a_chain() {
        let raw = encode_credential_record("[\"a\",\"b\"]", None);
        assert_eq!(raw, r#"{"key":"[\"a\",\"b\"]"}"#);
        let record = decode_credential_record(&raw).unwrap();
        assert_eq!(record.key, "[\"a\",\"b\"]");
        assert_eq!(record.chain, None);
    }

    #[test]
    fn credential_record_round_trips_with_a_chain() {
        let chain = chain_json();
        let raw = encode_credential_record("[\"a\",\"b\"]", Some(&chain));
        let record = decode_credential_record(&raw).unwrap();
        assert_eq!(record.key, "[\"a\",\"b\"]");
        assert_eq!(record.chain.as_deref(), Some(chain.as_str()));
    }

    #[test]
    fn corrupt_credential_record_is_none() {
        assert_eq!(decode_credential_record("not a credential"), None);
        assert_eq!(decode_credential_record(""), None);
        assert_eq!(decode_credential_record("{}"), None);
        assert_eq!(decode_credential_record(r#"{"chain":"x"}"#), None);
        assert_eq!(decode_credential_record(r#"{"key":1}"#), None);
    }

    #[test]
    fn ed25519_identity_json_matches_the_js_shape() {
        let seed = [7u8; 32];
        let json = encode_ed25519_identity_json(&seed);
        let parsed: [String; 2] = serde_json::from_str(&json).unwrap();
        assert!(parsed[0].starts_with(ED25519_DER_PREFIX_HEX));
        assert_eq!(parsed[0].len(), ED25519_DER_PREFIX_HEX.len() + 64);
        assert_eq!(parsed[1], hex::encode(seed));
        assert_eq!(decode_ed25519_identity_json(&json), Some(seed));
    }

    #[test]
    fn ed25519_identity_json_accepts_seed_plus_public() {
        let seed = [9u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut secret = seed.to_vec();
        secret.extend_from_slice(signing_key.verifying_key().as_bytes());
        let json = serde_json::to_string(&[
            format!(
                "{ED25519_DER_PREFIX_HEX}{}",
                hex::encode(signing_key.verifying_key().to_bytes())
            ),
            hex::encode(&secret),
        ])
        .unwrap();
        assert_eq!(decode_ed25519_identity_json(&json), Some(seed));
    }

    #[test]
    fn corrupt_ed25519_identity_json_is_none() {
        assert_eq!(decode_ed25519_identity_json("not json"), None);
        assert_eq!(decode_ed25519_identity_json("[]"), None);
        assert_eq!(decode_ed25519_identity_json(r#"["aa","zz"]"#), None);
        assert_eq!(decode_ed25519_identity_json(r#"["aa","00"]"#), None);
    }

    #[test]
    fn native_record_round_trips() {
        let chain = chain_json();
        let raw = encode_native_record(BaseKeyType::Ed25519, &[1u8; 32], Some(&chain));
        let (key_type, secret, decoded_chain) = decode_native_record(&raw).unwrap();
        assert_eq!(key_type, BaseKeyType::Ed25519);
        assert_eq!(secret, vec![1u8; 32]);
        assert_eq!(decoded_chain.as_deref(), Some(chain.as_str()));

        let raw = encode_native_record(BaseKeyType::Prime256v1, &[2u8; 40], None);
        let (key_type, secret, decoded_chain) = decode_native_record(&raw).unwrap();
        assert_eq!(key_type, BaseKeyType::Prime256v1);
        assert_eq!(secret, vec![2u8; 40]);
        assert_eq!(decoded_chain, None);
    }

    #[test]
    fn corrupt_native_record_is_none() {
        assert_eq!(decode_native_record("not a record"), None);
        assert_eq!(
            decode_native_record(r#"{"key":"","key_type":"Ed25519"}"#),
            None
        );
        assert_eq!(
            decode_native_record(r#"{"key":"!!","key_type":"Ed25519"}"#),
            None
        );
    }

    #[test]
    fn secret_registry_is_keyed_by_the_public_key() {
        let registry = SecretRegistry::new();
        let identity = ed25519_identity_from_seed(&[3u8; 32]);
        assert_eq!(registry.secret_for(&identity), None);
        registry.remember(&identity, vec![3u8; 32]);
        assert_eq!(registry.secret_for(&identity), Some(vec![3u8; 32]));

        // Another identity with the same seed is the same key.
        let same = ed25519_identity_from_seed(&[3u8; 32]);
        assert_eq!(registry.secret_for(&same), Some(vec![3u8; 32]));
    }
}

/// Browser-only checks for the stores that need `localStorage`, IndexedDB,
/// cookies or `BroadcastChannel`.
///
/// `cargo test` on the host cannot run these: they need a real browser (or the
/// Playwright harness under `compat-tests/`). They are compiled and run with
/// `wasm-pack test --headless --chrome` or the repository's browser test
/// runner.
#[cfg(all(test, target_arch = "wasm32"))]
mod browser_tests {
    use super::*;
    use crate::client::state::{
        CookieStateStorage, LocalStateStorage, SessionState, StateStorage, StoredSessionState,
    };
    use ic_agent::export::Principal;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn principal() -> Principal {
        Principal::self_authenticating([1u8, 2, 3])
    }

    fn stored_state() -> StoredSessionState {
        StoredSessionState {
            principal: principal(),
            expiration_ns: 1_893_456_000_000_000_000,
        }
    }

    #[wasm_bindgen_test]
    async fn local_credential_store_round_trips() {
        let store = LocalCredentialStorage::new("ic-test-");
        let identity = store.create().await.unwrap();
        store
            .set("session", Credential::key_only(identity.clone()))
            .await
            .unwrap();

        let stored = store.get("session").await.unwrap().unwrap();
        assert_eq!(
            stored.identity.public_key().unwrap(),
            identity.public_key().unwrap()
        );
        assert!(stored.chain.is_none());

        // The record is the v11 shape: a JSON object with `key`, no `chain`.
        let raw = web_sys::window()
            .unwrap()
            .local_storage()
            .unwrap()
            .unwrap()
            .get_item("ic-test-session")
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(parsed["key"].is_string());
        assert!(parsed.get("chain").is_none());

        store.remove("session").await.unwrap();
        assert!(store.get("session").await.unwrap().is_none());
    }

    #[wasm_bindgen_test]
    async fn local_credential_store_reports_nothing_for_a_corrupt_record() {
        let storage = web_sys::window().unwrap().local_storage().unwrap().unwrap();
        storage.set_item("ic-test-bad", "not a credential").unwrap();
        let store = LocalCredentialStorage::new("ic-test-");
        assert!(store.get("bad").await.unwrap().is_none());
        storage.remove_item("ic-test-bad").unwrap();
    }

    #[wasm_bindgen_test]
    fn local_state_store_writes_the_pipe_format() {
        let store = LocalStateStorage::new();
        store.set("ic-test-state", stored_state());
        let read = store.get("ic-test-state").unwrap();
        assert_eq!(read.principal, principal());
        assert_eq!(read.expiration_ns, 1_893_456_000_000_000_000);
        assert!(read.held);

        let raw = web_sys::window()
            .unwrap()
            .local_storage()
            .unwrap()
            .unwrap()
            .get_item("ic-test-state")
            .unwrap()
            .unwrap();
        assert_eq!(
            raw,
            format!("{}|1893456000000000000", principal().to_text())
        );

        store.remove("ic-test-state");
        assert!(store.get("ic-test-state").is_none());
    }

    #[wasm_bindgen_test]
    async fn idb_key_value_round_trips() {
        let db = crate::client::db::IdbKeyVal::create(
            crate::client::db::DBCreateOptions::new()
                .with_db_name("ic-auth-client-test-db")
                .with_store_name("ic-keyval"),
        )
        .await
        .unwrap();
        db.set("a", &wasm_bindgen::JsValue::from_str("b"))
            .await
            .unwrap();
        let value = db.get("a").await.unwrap().unwrap();
        assert_eq!(value.as_string().as_deref(), Some("b"));
        db.remove("a").await.unwrap();
        assert!(db.get("a").await.unwrap().is_none());
    }

    #[wasm_bindgen_test]
    async fn idb_credential_store_round_trips() {
        let store = IdbCredentialStorage::new(
            crate::client::db::DBCreateOptions::new()
                .with_db_name("ic-auth-client-test-credentials")
                .with_store_name("ic-keyval"),
        );
        let identity = store.create().await.unwrap();
        store
            .set("app", Credential::key_only(identity.clone()))
            .await
            .unwrap();
        let stored = store.get("app").await.unwrap().unwrap();
        assert_eq!(
            stored.identity.public_key().unwrap(),
            identity.public_key().unwrap()
        );
        store.remove("app").await.unwrap();
        assert!(store.get("app").await.unwrap().is_none());
    }

    #[wasm_bindgen_test]
    fn cookie_store_round_trips_and_composes_held() {
        // The domain has to be this host or above it; the runner's own host is
        // the one domain that always passes.
        let host = web_sys::window().unwrap().location().hostname().unwrap();
        let store = CookieStateStorage::new(host).unwrap();
        store.set("ic-test-cookie-state", stored_state());
        let read = store.get("ic-test-cookie-state").unwrap();
        assert_eq!(read.principal, principal());
        assert!(read.held);

        // The cookie is the domain's; without the per-origin claim the same
        // record reads as not held.
        store.discard("ic-test-cookie-state");
        let read: Option<SessionState> = store.get("ic-test-cookie-state");
        assert!(read.is_some());
        assert!(!read.unwrap().held);

        store.remove("ic-test-cookie-state");
        assert!(store.get("ic-test-cookie-state").is_none());
    }
}
