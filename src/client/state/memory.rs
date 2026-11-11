//! In-memory state storage.
//!
//! Port of upstream `state/memory-state-storage.ts`. Nothing reaches past this
//! instance, so a record here is always one the client holds, and two clients
//! handed the same instance learn about each other's writes through
//! subscriptions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::client::state::{
    SessionState, StateListener, StateStorage, StoredSessionState, Subscription,
};

/// One registered listener, with the record it was last told about.
struct ListenerEntry {
    id: u64,
    /// The record as one string, so "changed" means the same thing here as it
    /// does in the localStorage store.
    last: Mutex<Option<String>>,
    listener: StateListener,
}

/// A state store with no medium behind it.
///
/// Two clients can share one instance, so a subscription on the same key fires
/// for both.
pub struct MemoryStateStorage {
    entries: Mutex<HashMap<String, StoredSessionState>>,
    listeners: Arc<Mutex<HashMap<String, Vec<Arc<ListenerEntry>>>>>,
    next_listener_id: Mutex<u64>,
}

impl Default for MemoryStateStorage {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            next_listener_id: Mutex::new(0),
        }
    }
}

impl std::fmt::Debug for MemoryStateStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStateStorage").finish_non_exhaustive()
    }
}

impl MemoryStateStorage {
    /// A store holding nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The record as one comparable string, or `None` when nothing is stored.
    fn raw(&self, key: &str) -> Option<String> {
        self.entries
            .lock()
            .expect("memory state store is not poisoned")
            .get(key)
            .map(|stored| format!("{}|{}", stored.principal.to_text(), stored.expiration_ns))
    }

    fn notify(&self, key: &str) {
        let raw = self.raw(key);
        let listeners = {
            let guard = self
                .listeners
                .lock()
                .expect("memory state store is not poisoned");
            guard.get(key).cloned().unwrap_or_default()
        };
        for entry in listeners {
            let changed = {
                let mut last = entry.last.lock().expect("listener state is not poisoned");
                if *last == raw {
                    false
                } else {
                    *last = raw.clone();
                    true
                }
            };
            if changed {
                entry.listener.call();
            }
        }
    }
}

impl StateStorage for MemoryStateStorage {
    fn get(&self, key: &str) -> Option<SessionState> {
        self.entries
            .lock()
            .expect("memory state store is not poisoned")
            .get(key)
            .map(|stored| SessionState {
                principal: stored.principal,
                expiration_ns: stored.expiration_ns,
                // Nothing reaches past this instance, so a record here is always
                // one it holds.
                held: true,
            })
    }

    fn set(&self, key: &str, state: StoredSessionState) {
        self.entries
            .lock()
            .expect("memory state store is not poisoned")
            .insert(key.to_string(), state);
        self.notify(key);
    }

    fn remove(&self, key: &str) {
        self.entries
            .lock()
            .expect("memory state store is not poisoned")
            .remove(key);
        self.notify(key);
    }

    fn subscribe(&self, key: &str, listener: StateListener) -> Subscription {
        let id = {
            let mut next = self
                .next_listener_id
                .lock()
                .expect("memory state store is not poisoned");
            *next += 1;
            *next
        };
        let listener = Arc::new(ListenerEntry {
            id,
            last: Mutex::new(self.raw(key)),
            listener,
        });
        self.listeners
            .lock()
            .expect("memory state store is not poisoned")
            .entry(key.to_string())
            .or_default()
            .push(listener.clone());

        let key = key.to_string();
        let listeners = self.listeners.clone();
        Subscription::new(Box::new(move || {
            if let Ok(mut guard) = listeners.lock()
                && let Some(registered) = guard.get_mut(&key)
            {
                registered.retain(|entry| entry.id != listener.id);
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ic_agent::export::Principal;

    use super::*;

    fn principal() -> Principal {
        Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
    }

    #[test]
    fn set_get_remove() {
        let store = MemoryStateStorage::new();
        assert_eq!(store.get("state"), None);
        store.set(
            "state",
            StoredSessionState {
                principal: principal(),
                expiration_ns: 42,
            },
        );
        let state = store.get("state").unwrap();
        assert_eq!(state.principal, principal());
        assert_eq!(state.expiration_ns, 42);
        assert!(state.held);
        store.remove("state");
        assert_eq!(store.get("state"), None);
    }

    #[test]
    fn listeners_fire_on_change_and_stop_when_dropped() {
        let store = Arc::new(MemoryStateStorage::new());
        let fires = Arc::new(AtomicUsize::new(0));
        let counter = fires.clone();
        let subscription = store.subscribe(
            "state",
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );

        store.set(
            "state",
            StoredSessionState {
                principal: principal(),
                expiration_ns: 1,
            },
        );
        assert_eq!(fires.load(Ordering::SeqCst), 1);

        // Writing the same record again is not news.
        store.set(
            "state",
            StoredSessionState {
                principal: principal(),
                expiration_ns: 1,
            },
        );
        assert_eq!(fires.load(Ordering::SeqCst), 1);

        subscription.unsubscribe();
        store.remove("state");
        assert_eq!(fires.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn discard_is_remove_for_a_store_that_publishes_nothing() {
        let store = MemoryStateStorage::new();
        store.set(
            "state",
            StoredSessionState {
                principal: principal(),
                expiration_ns: 1,
            },
        );
        store.discard("state");
        assert_eq!(store.get("state"), None);
    }
}
