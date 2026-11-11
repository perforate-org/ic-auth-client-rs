//! Credentials shared across tabs without a durable medium (wasm).
//!
//! Port of upstream `credentials/shared-memory-credential-storage.ts`. For an
//! environment with no durable medium — IndexedDB and `localStorage` both
//! unavailable, or an application that has decided nothing may reach disk —
//! where every tab minting for itself is still worth avoiding. Every write is
//! broadcast and every instance applies what it receives, so a steady-state
//! read is local and immediate.
//!
//! ## The wire format and its interop limit
//!
//! Upstream sends `{ slot, keyPair: CryptoKeyPair, chain?: string }` and relies
//! on a structured clone carrying a key handle that signs and cannot be
//! exported. Rust signs with `p256`, not with a WebCrypto handle, so a received
//! non-extractable pair is unusable: its private half cannot be exported. This
//! port therefore sends **both** forms in one message:
//!
//! ```text
//! { kind: "put", slot, keyPair: CryptoKeyPair, key: { kty, crv, x, y, d }, chain?: string }
//! ```
//!
//! - JS v11 reads `keyPair` and ignores the extra `key` field, so a Rust writer
//!   is understood by JS.
//! - Rust reads `key` and ignores `keyPair`, so Rust peers agree.
//! - A JS v11 writer sends only `keyPair`; Rust can adopt it only if the pair is
//!   extractable, and reports the slot as absent otherwise. This is the same
//!   best-effort limit the IndexedDB store documents.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use async_trait::async_trait;
use futures::FutureExt as _;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::BroadcastChannel;
use web_sys::CryptoKeyPair;
use web_sys::js_sys::{Array, Function, Promise};

use crate::ArcIdentity;
use crate::client::credentials::p256;
use crate::client::credentials::wasm::{self, SharedDone};
use crate::client::credentials::{Credential, CredentialStorage, SecretRegistry};
use crate::client::error::AuthClientError;

/// The channel and lock prefix every instance agrees on by default.
pub const DEFAULT_SHARED_MEMORY_NAME: &str = "ic-credentials";

/// Options for [`SharedMemoryCredentialStorage`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedMemoryOptions {
    /// The channel and lock prefix the tabs of this origin share.
    pub name: Option<String>,
}

impl SharedMemoryOptions {
    /// Options that resolve to the default name.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses `name` for the channel and the lock prefix.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Credentials in memory, replicated to the other tabs of this origin.
///
/// Port of upstream `SharedMemoryCredentialStorage`
/// (`shared-memory-credential-storage.ts:78-303`): `shared = true`,
/// `durable = false`.
pub struct SharedMemoryCredentialStorage {
    inner: Rc<SharedInner>,
    on_message: RefCell<Option<Closure<dyn FnMut(web_sys::MessageEvent)>>>,
}

struct SharedInner {
    name: String,
    channel: Option<BroadcastChannel>,
    /// On the instance and never on the module, so two clients on one page keep
    /// their own replicas.
    replica: RefCell<HashMap<String, Credential>>,
    registry: SecretRegistry,
    /// Resolves once there is nothing left to wait for on a cold start.
    synced: SharedDone,
    /// The last queued incoming message, so reads await work already in hand
    /// and the work lands in arrival order.
    last_applied: RefCell<Option<Rc<SharedDone>>>,
    /// The resolve function of this instance's presence lock.
    presence_release: RefCell<Option<Function>>,
    /// The lock callback, kept alive for the instance's life.
    presence_callback: RefCell<Option<Closure<dyn FnMut() -> JsValue>>>,
    /// Whoever is waiting for the offer answering this instance's `ask`.
    announce_offer: RefCell<Option<Rc<SharedDone>>>,
    closed: Cell<bool>,
}

impl std::fmt::Debug for SharedMemoryCredentialStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedMemoryCredentialStorage")
            .field("name", &self.inner.name)
            .field("durable", &false)
            .finish_non_exhaustive()
    }
}

impl Default for SharedMemoryCredentialStorage {
    fn default() -> Self {
        Self::new(SharedMemoryOptions::new())
    }
}

impl SharedMemoryCredentialStorage {
    /// A replica on the named channel.
    pub fn new(options: SharedMemoryOptions) -> Self {
        let name = options
            .name
            .unwrap_or_else(|| DEFAULT_SHARED_MEMORY_NAME.to_string());
        let channel = wasm::broadcast_channel(&name);
        let inner = Rc::new(SharedInner {
            name,
            channel: channel.clone(),
            replica: RefCell::new(HashMap::new()),
            registry: SecretRegistry::new(),
            synced: SharedDone::new(),
            last_applied: RefCell::new(None),
            presence_release: RefCell::new(None),
            presence_callback: RefCell::new(None),
            announce_offer: RefCell::new(None),
            closed: Cell::new(false),
        });

        let on_message = channel.as_ref().map(|channel| {
            let weak = Rc::downgrade(&inner);
            let closure = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
                move |event: web_sys::MessageEvent| {
                    if let Some(inner) = weak.upgrade() {
                        inner.receive(event.data());
                    }
                },
            );
            channel.set_onmessage(Some(closure.as_ref().unchecked_ref()));
            closure
        });

        // Cold-start sync: find the peers that already run, ask them for what
        // they hold, and resolve `synced` when an answer arrives or every peer
        // has gone.
        let inner_for_sync = inner.clone();
        wasm_bindgen_futures::spawn_local(async move {
            inner_for_sync.open_replica().await;
            inner_for_sync.synced.complete();
        });

        Self {
            inner,
            on_message: RefCell::new(on_message),
        }
    }

    /// The channel and lock prefix this replica uses.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Stops replicating and lets go of the name a peer waits on.
    ///
    /// Only needed when you replace a store while the page lives; the document
    /// going away does the same thing (`shared-memory-credential-storage.ts:131-135`).
    pub fn close(&self) {
        if self.inner.closed.replace(true) {
            return;
        }
        if let Some(channel) = &self.inner.channel {
            channel.set_onmessage(None);
            channel.close();
        }
        self.on_message.borrow_mut().take();
        if let Some(release) = self.inner.presence_release.borrow_mut().take() {
            let _ = release.call0(&JsValue::UNDEFINED);
        }
        self.inner.presence_callback.borrow_mut().take();
    }
}

#[async_trait(?Send)]
impl CredentialStorage for SharedMemoryCredentialStorage {
    fn shared(&self) -> bool {
        true
    }

    fn durable(&self) -> bool {
        false
    }

    async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
        let (identity, secret) = p256::generate()?;
        self.inner.registry.remember(&identity, secret);
        Ok(identity)
    }

    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
        // A read reflects everything received, not everything that has finished
        // being rebuilt: applying is asynchronous, so a message already in hand
        // would otherwise read as a miss.
        let synced = self.inner.synced.clone();
        synced.await;
        self.inner.await_applied().await;
        Ok(self.inner.replica.borrow().get(slot).cloned())
    }

    async fn set(&self, slot: &str, credential: Credential) -> Result<(), AuthClientError> {
        self.inner
            .replica
            .borrow_mut()
            .insert(slot.to_string(), credential.clone());
        if let Some(message) = self.inner.to_wire_entry(slot, &credential).await {
            let _ = wasm::set_prop(&message, "kind", &JsValue::from_str("put"));
            self.inner.post(&message);
        }
        Ok(())
    }

    async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
        self.inner.replica.borrow_mut().remove(slot);
        self.inner.post(&drop_message(slot));
        Ok(())
    }
}

impl SharedInner {
    /// Takes this instance's presence lock, then waits for the peers that
    /// already had one — asking them for what they hold
    /// (`shared-memory-credential-storage.ts:164-192`).
    async fn open_replica(self: &Rc<Self>) {
        if self.channel.is_none() {
            return;
        }
        let Some(navigator) = wasm::get_prop(&wasm::global(), "navigator") else {
            return;
        };
        let Some(locks) = wasm::get_prop(&navigator, "locks") else {
            // Nothing can be enumerated and nothing can answer, so waiting
            // could only cost a load.
            return;
        };

        let peers = self.claim_presence(&locks).await;
        if peers.is_empty() {
            return;
        }

        let answered = Rc::new(SharedDone::new());
        *self.announce_offer.borrow_mut() = Some(answered.clone());
        self.post(&ask_message());

        // A peer that answers ends the wait; a peer that dies without answering
        // ends it too, because its lock is granted the moment the browser
        // releases it. So the wait is bounded by the peers themselves.
        let answered_future = answered.as_ref().clone().boxed_local();
        let locks_for_gone = locks.clone();
        let gone_everywhere = async move {
            futures::future::join_all(
                peers
                    .into_iter()
                    .map(|peer| request_lock_gone(locks_for_gone.clone(), peer)),
            )
            .await;
        }
        .boxed_local();
        futures::future::select(answered_future, gone_everywhere).await;
    }

    /// Enumerates the peers holding a presence lock, then takes this instance's
    /// own.
    ///
    /// In that order: a snapshot taken after would include this instance, and
    /// it would then wait for a lock it holds itself
    /// (`shared-memory-credential-storage.ts:194-227`).
    async fn claim_presence(self: &Rc<Self>, locks: &JsValue) -> Vec<String> {
        let mine = self.presence_name();
        let prefix = format!("{}:alive:", self.name);

        let mut peers = Vec::new();
        if let Ok(promise) = wasm::call_method(locks, "query", &[]) {
            if let Ok(snapshot) = wasm::await_promise(promise).await {
                if let Some(held) =
                    wasm::get_prop(&snapshot, "held").and_then(|held| held.dyn_into::<Array>().ok())
                {
                    for index in 0..held.length() {
                        let lock = held.get(index);
                        if let Some(name) = wasm::get_string(&lock, "name") {
                            if name != mine && name.starts_with(&prefix) {
                                peers.push(name);
                            }
                        }
                    }
                }
            }
        }

        // Not awaited: the request resolves only when the lock is released,
        // which is when this instance is done with it.
        let release = Rc::new(RefCell::new(None::<Function>));
        let release_for_callback = release.clone();
        let promise = Promise::new(&mut move |resolve, _reject| {
            *release_for_callback.borrow_mut() = Some(resolve);
        });
        let callback = Closure::<dyn FnMut() -> JsValue>::new(move || promise.clone().into());
        let options: JsValue = wasm::object().into();
        let _ = wasm::set_prop(&options, "mode", &JsValue::from_str("exclusive"));
        let _ = wasm::call_method(
            locks,
            "request",
            &[
                JsValue::from_str(&mine),
                options,
                callback.as_ref().unchecked_ref::<Function>().clone().into(),
            ],
        );
        *self.presence_release.borrow_mut() = release.borrow_mut().take();
        *self.presence_callback.borrow_mut() = Some(callback);

        peers
    }

    fn presence_name(&self) -> String {
        let id = wasm::random_uuid().unwrap_or_else(|| {
            format!("{}-{}", web_sys::js_sys::Date::now(), rand::random::<u64>())
        });
        format!("{}:alive:{id}", self.name)
    }

    fn receive(self: &Rc<Self>, data: JsValue) {
        let Some(kind) = wasm::get_string(&data, "kind") else {
            return;
        };
        match kind.as_str() {
            "ask" => {
                // Answered from what is queued as well as what has landed, so
                // an instance asked while still applying an earlier message
                // does not describe a state it is halfway out of.
                self.enqueue(Box::new(move |inner| {
                    Box::pin(async move { inner.offer().await })
                }));
            }
            "drop" => {
                let Some(slot) = wasm::get_string(&data, "slot") else {
                    return;
                };
                self.enqueue(Box::new(move |inner| {
                    Box::pin(async move {
                        inner.replica.borrow_mut().remove(&slot);
                    })
                }));
            }
            "put" => {
                let entry = data.clone();
                self.enqueue(Box::new(move |inner| {
                    Box::pin(async move {
                        let _ = inner.apply(&entry, true).await;
                    })
                }));
            }
            "offer" => {
                let entries = wasm::get_prop(&data, "entries")
                    .and_then(|entries| entries.dyn_into::<Array>().ok());
                let Some(entries) = entries else {
                    return;
                };
                self.enqueue(Box::new(move |inner| {
                    Box::pin(async move {
                        for index in 0..entries.length() {
                            let entry = entries.get(index);
                            let _ = inner.apply(&entry, false).await;
                        }
                        // Last, so the answer is complete before anything
                        // waiting on it wakes.
                        if let Some(done) = inner.announce_offer.borrow_mut().take() {
                            done.complete();
                        }
                    })
                }));
            }
            // An unknown kind is ignored: a channel reaches one origin, and
            // what keeps a stranger harmless is that it is never answered.
            _ => {}
        }
    }

    fn enqueue(
        self: &Rc<Self>,
        work: Box<dyn FnOnce(Rc<SharedInner>) -> futures::future::LocalBoxFuture<'static, ()>>,
    ) {
        let previous = self.last_applied.borrow_mut().take();
        let done = Rc::new(SharedDone::new());
        *self.last_applied.borrow_mut() = Some(done.clone());
        let inner = self.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Some(previous) = previous {
                previous.as_ref().clone().await;
            }
            work(inner.clone()).await;
            done.complete();
            let current = inner.last_applied.borrow().clone();
            if let Some(current) = current {
                if Rc::ptr_eq(&current, &done) {
                    *inner.last_applied.borrow_mut() = None;
                }
            }
        });
    }

    async fn await_applied(self: &Rc<Self>) {
        loop {
            let Some(tail) = self.last_applied.borrow().clone() else {
                return;
            };
            tail.as_ref().clone().await;
            let current = self.last_applied.borrow().clone();
            match current {
                Some(current) if Rc::ptr_eq(&current, &tail) => return,
                Some(_) => continue,
                None => return,
            }
        }
    }

    /// Answers an `ask` with everything held, even when empty: the asker is
    /// waiting and "I have nothing" is an answer.
    async fn offer(self: Rc<Self>) {
        let entries: Vec<(String, Credential)> = self
            .replica
            .borrow()
            .iter()
            .map(|(slot, credential)| (slot.clone(), credential.clone()))
            .collect();
        let mut wires = Vec::with_capacity(entries.len());
        for (slot, credential) in entries {
            if let Some(wire) = self.to_wire_entry(&slot, &credential).await {
                wires.push(wire);
            }
        }
        let message: JsValue = wasm::object().into();
        let _ = wasm::set_prop(&message, "kind", &JsValue::from_str("offer"));
        let _ = wasm::set_prop(&message, "entries", &wasm::array(wires).into());
        self.post(&message);
    }

    /// Rebuilds one received record, `overwrite` false meaning "fill gaps
    /// only".
    async fn apply(self: &Rc<Self>, entry: &JsValue, overwrite: bool) -> Option<()> {
        let slot = wasm::get_string(entry, "slot")?;
        if !overwrite && self.replica.borrow().contains_key(&slot) {
            return Some(());
        }

        let secret = match wasm::get_prop(entry, "key") {
            Some(key) => p256::secret_from_jwk(&key),
            None => None,
        };
        let secret = match secret {
            Some(secret) => secret,
            None => {
                let key_pair = wasm::get_prop(entry, "keyPair")?
                    .dyn_into::<CryptoKeyPair>()
                    .ok()?;
                p256::secret_from_key_pair(&key_pair).await.ok()??
            }
        };
        let identity = p256::identity_from_scalar(&secret).ok()?;
        self.registry.remember(&identity, secret);

        let chain = match wasm::get_string(entry, "chain") {
            None => None,
            Some(chain) => {
                Some(crate::delegation_chain::DelegationChain::from_any_json(&chain).ok()?)
            }
        };
        self.replica
            .borrow_mut()
            .insert(slot, Credential { identity, chain });
        Some(())
    }

    /// One credential in the wire shape `{ slot, key, keyPair?, chain? }`.
    ///
    /// The shape is upstream's `WireCredential` plus the Rust-native `key`
    /// field, so a JS v11 peer reads `keyPair` and a Rust peer reads `key`.
    async fn to_wire_entry(
        self: &Rc<Self>,
        slot: &str,
        credential: &Credential,
    ) -> Option<JsValue> {
        let secret = self.registry.secret_for(&credential.identity)?;
        let message: JsValue = wasm::object().into();
        wasm::set_prop(&message, "slot", &JsValue::from_str(slot)).ok()?;
        if let Ok(key) = p256::jwk_from_secret(&secret) {
            wasm::set_prop(&message, "key", &key).ok()?;
        }
        if let Ok(key_pair) = p256::key_pair_from_secret(&secret).await {
            wasm::set_prop(&message, "keyPair", &JsValue::from(key_pair)).ok()?;
        }
        if let Some(chain) = &credential.chain {
            wasm::set_prop(&message, "chain", &JsValue::from_str(&chain.to_js_json())).ok()?;
        }
        Some(message)
    }

    fn post(&self, message: &JsValue) {
        if self.closed.get() {
            return;
        }
        if let Some(channel) = &self.channel {
            // A closed channel or a payload the browser will not clone costs a
            // peer the write; this instance's replica already has it.
            let _ = channel.post_message(message);
        }
    }
}

fn ask_message() -> JsValue {
    let message: JsValue = wasm::object().into();
    let _ = wasm::set_prop(&message, "kind", &JsValue::from_str("ask"));
    message
}

fn drop_message(slot: &str) -> JsValue {
    let message: JsValue = wasm::object().into();
    let _ = wasm::set_prop(&message, "kind", &JsValue::from_str("drop"));
    let _ = wasm::set_prop(&message, "slot", &JsValue::from_str(slot));
    message
}

/// Requests a peer's presence lock, resolving when the peer is gone.
fn request_lock_gone(locks: JsValue, name: String) -> futures::future::LocalBoxFuture<'static, ()> {
    Box::pin(async move {
        let callback = Closure::<dyn FnMut() -> JsValue>::new(|| JsValue::UNDEFINED);
        let options: JsValue = wasm::object().into();
        let _ = wasm::set_prop(&options, "mode", &JsValue::from_str("exclusive"));
        if let Ok(promise) = wasm::call_method(
            &locks,
            "request",
            &[
                JsValue::from_str(&name),
                options,
                callback.as_ref().unchecked_ref::<Function>().clone().into(),
            ],
        ) {
            let _ = wasm::await_promise(promise).await;
        }
        // Kept alive for the request's life: a future cancelled by `select`
        // must not leave a dropped callback for the browser to invoke.
        callback.forget();
    })
}
