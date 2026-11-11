//! Sign-in state in `localStorage` (wasm).
//!
//! Port of upstream `state/local-state-storage.ts`. The record is shared by
//! every tab of an origin and survives a reload, which is what makes it the
//! default store. Workers cannot read `localStorage`, so a tab mirrors each
//! record it writes or subscribes to into IndexedDB and announces it on a
//! channel, and a worker loads the mirror into memory and changes nothing.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;

use crate::client::credentials::wasm::{self, JsListener, SharedDone};
use crate::client::db::{DBCreateOptions, IdbKeyVal};
use crate::client::state::{
    READ_ONLY_MESSAGE, SessionState, StateListener, StateStorage, StoredSessionState, Subscription,
    decode_state_record, encode_state_record,
};

/// Where tabs mirror their `localStorage` records for workers.
pub(crate) const MIRROR_DB_NAME: &str = "auth-client-state-db";
/// The object store inside [`MIRROR_DB_NAME`].
pub(crate) const MIRROR_STORE_NAME: &str = "ic-keyval";
/// The channel a tab announces a mirrored record on, carrying only its key.
pub(crate) const MIRROR_CHANNEL: &str = "ic-session-state";

/// State in `localStorage`, so every tab of an origin agrees on it.
///
/// Port of upstream `LocalStateStorage` (`local-state-storage.ts:38-216`).
pub struct LocalStateStorage {
    inner: Rc<LocalStateInner>,
}

struct LocalStateInner {
    /// True in a worker, which reads what its tabs mirror and changes nothing.
    read_only: bool,
    /// Fired on a same-tab write: `storage` reaches the other tabs of an origin
    /// and deliberately not the one that wrote.
    subscribers: RefCell<HashMap<String, Vec<(u64, Rc<dyn Fn()>)>>>,
    next_id: Cell<u64>,
    /// In a worker: the mirrored records.
    mirrored: RefCell<HashMap<String, Option<String>>>,
    /// The loads queued so far, for `ready`.
    loads: RefCell<Vec<Rc<SharedDone>>>,
    /// The last queued load, so a later load always lands last.
    load_tail: RefCell<Option<Rc<SharedDone>>>,
}

impl std::fmt::Debug for LocalStateStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStateStorage")
            .field("read_only", &self.inner.read_only)
            .finish_non_exhaustive()
    }
}

impl Clone for LocalStateStorage {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Default for LocalStateStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalStateStorage {
    /// A store that reads `localStorage`, or only the mirror where there is no
    /// `localStorage` (a worker).
    pub fn new() -> Self {
        Self {
            inner: Rc::new(LocalStateInner {
                read_only: !wasm::has_local_storage(),
                subscribers: RefCell::new(HashMap::new()),
                next_id: Cell::new(0),
                mirrored: RefCell::new(HashMap::new()),
                loads: RefCell::new(Vec::new()),
                load_tail: RefCell::new(None),
            }),
        }
    }
}

impl StateStorage for LocalStateStorage {
    fn get(&self, key: &str) -> Option<SessionState> {
        let raw = self.inner.raw(key)?;
        let stored = decode_state_record(&raw)?;
        Some(SessionState {
            principal: stored.principal,
            expiration_ns: stored.expiration_ns,
            // This record is written by this origin and read by no other, so
            // having one and holding a credential for it are the same thing.
            held: true,
        })
    }

    fn set(&self, key: &str, state: StoredSessionState) {
        assert!(!self.inner.read_only, "{READ_ONLY_MESSAGE}");
        let Some(storage) = wasm::local_storage() else {
            return;
        };
        let _ = storage.set_item(key, &encode_state_record(&state));
        self.inner.fire(key);
        self.inner.mirror(key);
    }

    fn remove(&self, key: &str) {
        assert!(!self.inner.read_only, "{READ_ONLY_MESSAGE}");
        let Some(storage) = wasm::local_storage() else {
            return;
        };
        let _ = storage.remove_item(key);
        self.inner.fire(key);
        self.inner.mirror(key);
    }

    fn discard(&self, key: &str) {
        // The same as remove: this store publishes nothing beyond the origin.
        self.remove(key);
    }

    fn subscribe(&self, key: &str, listener: StateListener) -> Subscription {
        let inner = self.inner.clone();
        let key_owned = key.to_string();
        let last: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(inner.raw(key)));
        let inner_for_check = inner.clone();
        let key_for_check = key_owned.clone();
        let check: Rc<dyn Fn()> = Rc::new(move || {
            let now = inner_for_check.raw(&key_for_check);
            let changed = {
                let mut last = last.borrow_mut();
                if *last != now {
                    *last = now;
                    true
                } else {
                    false
                }
            };
            if changed {
                crate::client::platform::Listener::call(listener.as_ref());
            }
        });
        let id = inner.register(&key_owned, check.clone());

        // A tab mirrors what it holds now, which also repairs a mirror an
        // earlier version or a closing page left behind; a worker loads it.
        if inner.read_only {
            LocalStateInner::load(inner.clone(), key_owned.clone());
        } else {
            inner.mirror(&key_owned);
        }

        let mut listeners: Vec<JsListener> = Vec::new();
        let channel = wasm::broadcast_channel(MIRROR_CHANNEL);
        let mut channel_closure: Option<Closure<dyn FnMut(web_sys::MessageEvent)>> = None;
        if let Some(channel) = &channel {
            let inner_for_message = inner.clone();
            let key_for_message = key_owned.clone();
            let check_for_message = check.clone();
            let closure = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
                move |event: web_sys::MessageEvent| {
                    if event.data().as_string().as_deref() != Some(key_for_message.as_str()) {
                        return;
                    }
                    if inner_for_message.read_only {
                        LocalStateInner::load(inner_for_message.clone(), key_for_message.clone());
                    } else {
                        check_for_message();
                    }
                },
            );
            channel.set_onmessage(Some(closure.as_ref().unchecked_ref()));
            channel_closure = Some(closure);
        }

        if let Some(target) = wasm::event_target() {
            let target: JsValue = target.into();
            let check_for_storage = check.clone();
            let key_for_storage = key_owned.clone();
            listeners.push(JsListener::new(target, "storage", move |event: JsValue| {
                // `key` is null when a tab cleared the whole store, which
                // changes this too.
                match wasm::get_property(&event, "key") {
                    None => {}
                    Some(value) if value.is_null() => check_for_storage(),
                    Some(value) => {
                        if value.as_string().as_deref() == Some(key_for_storage.as_str()) {
                            check_for_storage();
                        }
                    }
                }
            }));
        }

        // `storage` is the only notice this store gets, and a page restored
        // from the back-forward cache was not listening while it was frozen. So
        // the record is re-read when the page is shown or regains focus.
        if let Some(document) = wasm::document() {
            let check_for_visibility = check.clone();
            let document_for_visibility = document.clone();
            listeners.push(JsListener::new(
                document.clone(),
                "visibilitychange",
                move |_event: JsValue| {
                    if wasm::get_string(&document_for_visibility, "visibilityState").as_deref()
                        == Some("visible")
                    {
                        check_for_visibility();
                    }
                },
            ));
        }
        if let Some(target) = wasm::event_target() {
            let target: JsValue = target.into();
            let check_for_pageshow = check.clone();
            listeners.push(JsListener::new(target.clone(), "pageshow", move |_| {
                check_for_pageshow();
            }));
            let check_for_focus = check.clone();
            listeners.push(JsListener::new(target, "focus", move |_| {
                check_for_focus();
            }));
        }

        let inner_for_unsubscribe = inner.clone();
        let key_for_unsubscribe = key_owned;
        let unsubscribe: Box<dyn crate::client::platform::Unsubscribe> = Box::new(move || {
            inner_for_unsubscribe.unregister(&key_for_unsubscribe, id);
            if let Some(channel) = &channel {
                channel.set_onmessage(None);
                channel.close();
            }
            drop(channel_closure);
            drop(listeners);
        });
        Subscription::new(unsubscribe)
    }

    fn is_read_only(&self) -> bool {
        self.inner.read_only
    }

    fn ready(&self) -> Pin<Box<dyn Future<Output = ()> + '_>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            loop {
                let batch: Vec<Rc<SharedDone>> = inner.loads.borrow().clone();
                for done in batch {
                    done.as_ref().clone().await;
                }
                // Every load queued while this waited has to have landed too,
                // so the test is "nothing is still pending", not "the list did
                // not grow": completed loads are pruned.
                if inner.loads.borrow().iter().all(|done| done.is_done()) {
                    return;
                }
            }
        })
    }
}

impl LocalStateInner {
    fn raw(&self, key: &str) -> Option<String> {
        if self.read_only {
            return self.mirrored.borrow().get(key).cloned().flatten();
        }
        wasm::local_storage()?.get_item(key).ok().flatten()
    }

    fn register(&self, key: &str, check: Rc<dyn Fn()>) -> u64 {
        let id = {
            let next = self.next_id.get();
            self.next_id.set(next + 1);
            next
        };
        self.subscribers
            .borrow_mut()
            .entry(key.to_string())
            .or_default()
            .push((id, check));
        id
    }

    fn unregister(&self, key: &str, id: u64) {
        if let Some(checks) = self.subscribers.borrow_mut().get_mut(key) {
            checks.retain(|(check_id, _)| *check_id != id);
        }
    }

    fn fire(&self, key: &str) {
        let checks: Vec<Rc<dyn Fn()>> = self
            .subscribers
            .borrow()
            .get(key)
            .map(|checks| checks.iter().map(|(_, check)| check.clone()).collect())
            .unwrap_or_default();
        for check in checks {
            check();
        }
    }

    fn mirror(self: &Rc<Self>, key: &str) {
        let inner = self.clone();
        let key = key.to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let Ok(db) = IdbKeyVal::create(DBCreateOptions {
                db_name: Some(MIRROR_DB_NAME.to_string()),
                store_name: Some(MIRROR_STORE_NAME.to_string()),
                version: None,
            })
            .await
            else {
                return;
            };
            // Read after the await and right before the write: IndexedDB
            // applies writes in the order they are made, so the last to land
            // holds what is current.
            let raw = inner.raw(&key);
            let value = wasm::object();
            let raw_value = match &raw {
                Some(raw) => JsValue::from_str(raw),
                None => JsValue::NULL,
            };
            if wasm::set_prop(&value, "raw", &raw_value).is_err() {
                return;
            }
            if db.set(&key, &value.into()).await.is_err() {
                return;
            }
            if let Some(channel) = wasm::broadcast_channel(MIRROR_CHANNEL) {
                let _ = channel.post_message(&JsValue::from_str(&key));
                channel.close();
            }
        });
    }

    fn load(self: Rc<Self>, key: String) {
        let previous = self.load_tail.borrow_mut().take();
        let done = Rc::new(SharedDone::new());
        *self.load_tail.borrow_mut() = Some(done.clone());
        self.loads.borrow_mut().push(done.clone());

        wasm_bindgen_futures::spawn_local(async move {
            if let Some(previous) = previous {
                previous.as_ref().clone().await;
            }
            let raw = async {
                let db = IdbKeyVal::create(DBCreateOptions {
                    db_name: Some(MIRROR_DB_NAME.to_string()),
                    store_name: Some(MIRROR_STORE_NAME.to_string()),
                    version: None,
                })
                .await
                .ok()?;
                let value = db.get(&key).await.ok()??;
                match wasm::get_property(&value, "raw") {
                    Some(value) if !value.is_null() => value.as_string(),
                    _ => None,
                }
            }
            .await;
            self.mirrored.borrow_mut().insert(key.clone(), raw);
            self.fire(&key);
            done.complete();
            self.loads.borrow_mut().retain(|load| !load.is_done());
        });
    }
}
