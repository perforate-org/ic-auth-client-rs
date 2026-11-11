//! Sign-in state in a native file-backed store.
//!
//! Native has no cookies and no per-origin storage: a state record is one
//! install's knowledge of its sign-in, so it is a JSON file under a directory
//! the caller passes. Writes are atomic (write-then-rename), the store is never
//! read-only, and subscriptions are in-process.
//!
//! `resumable` is `false`: the record does not reach past this install, so there
//! is no sibling to bring a sign-in back for.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::client::error::AuthClientError;
use crate::client::state::{
    SessionState, StateListener, StateStorage, StoredSessionState, Subscription,
};

/// The file one directory's state record lives in.
pub const STATE_FILE_NAME: &str = "ic-session-state.json";

/// The shape version of that file.
const STATE_FILE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    entries: HashMap<String, StoredStateRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredStateRecord {
    principal: String,
    expiration_ns: u64,
}

/// Sign-in state in a JSON file, shared in-process by every client handed the
/// same store.
pub struct NativeStateStorage {
    directory: PathBuf,
    entries: Mutex<HashMap<String, StoredSessionState>>,
    listeners: Arc<Mutex<HashMap<String, Vec<(u64, StateListener)>>>>,
    next_listener_id: Mutex<u64>,
}

impl std::fmt::Debug for NativeStateStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeStateStorage")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

impl NativeStateStorage {
    /// A store backed by `<directory>/ic-session-state.json`.
    ///
    /// A file this version cannot read is treated as no record at all, which is
    /// the same answer a corrupt browser record gives: signing in again is
    /// always safe, failing to start is not.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, AuthClientError> {
        let directory = directory.into();
        let entries = Self::load(&directory)?;
        Ok(Self {
            directory,
            entries: Mutex::new(entries),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            next_listener_id: Mutex::new(0),
        })
    }

    /// The file the record is persisted to.
    pub fn file_path(&self) -> PathBuf {
        self.directory.join(STATE_FILE_NAME)
    }

    fn load(directory: &Path) -> Result<HashMap<String, StoredSessionState>, AuthClientError> {
        let path = directory.join(STATE_FILE_NAME);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HashMap::new());
            }
            Err(error) => {
                return Err(AuthClientError::Storage(format!(
                    "could not read the state file: {error}"
                )));
            }
        };
        let file: StateFile = match serde_json::from_str(&contents) {
            Ok(file) => file,
            // A truncated or foreign file is not a reason to fail a start.
            Err(_) => return Ok(HashMap::new()),
        };
        if file.version != STATE_FILE_VERSION {
            return Ok(HashMap::new());
        }
        let mut entries = HashMap::new();
        for (key, record) in file.entries {
            let Ok(principal) = ic_agent::export::Principal::from_text(&record.principal) else {
                continue;
            };
            entries.insert(
                key,
                StoredSessionState {
                    principal,
                    expiration_ns: record.expiration_ns,
                },
            );
        }
        Ok(entries)
    }

    /// Writes the whole record atomically, so a crash mid-write cannot leave a
    /// half file behind.
    fn persist(
        &self,
        entries: &HashMap<String, StoredSessionState>,
    ) -> Result<(), AuthClientError> {
        std::fs::create_dir_all(&self.directory).map_err(|error| {
            AuthClientError::Storage(format!("could not create the state directory: {error}"))
        })?;
        let file = StateFile {
            version: STATE_FILE_VERSION,
            entries: entries
                .iter()
                .map(|(key, state)| {
                    (
                        key.clone(),
                        StoredStateRecord {
                            principal: state.principal.to_text(),
                            expiration_ns: state.expiration_ns,
                        },
                    )
                })
                .collect(),
        };
        let serialized = serde_json::to_vec(&file).map_err(|error| {
            AuthClientError::Storage(format!("could not encode state: {error}"))
        })?;

        let path = self.file_path();
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, &serialized).map_err(|error| {
            AuthClientError::Storage(format!("could not write the state file: {error}"))
        })?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            AuthClientError::Storage(format!("could not replace the state file: {error}"))
        })
    }

    fn notify(&self, key: &str) {
        let listeners = {
            let Ok(listeners) = self.listeners.lock() else {
                return;
            };
            listeners.get(key).cloned().unwrap_or_default()
        };
        for (_, listener) in listeners {
            crate::client::platform::Listener::call(listener.as_ref());
        }
    }
}

impl StateStorage for NativeStateStorage {
    fn get(&self, key: &str) -> Option<SessionState> {
        let entries = self.entries.lock().ok()?;
        let stored = entries.get(key)?;
        Some(SessionState {
            principal: stored.principal,
            expiration_ns: stored.expiration_ns,
            // Written by this store and read by nobody else: holding a record
            // and holding a credential for it are the same thing.
            held: true,
        })
    }

    fn set(&self, key: &str, state: StoredSessionState) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.insert(key.to_string(), state);
        // A write that cannot be persisted is still one this process can use;
        // the cost is signing in again after a restart. The lock is held across
        // the write so two threads cannot persist their snapshots out of order.
        let _ = self.persist(&entries);
        drop(entries);
        self.notify(key);
    }

    fn remove(&self, key: &str) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.remove(key);
        let _ = self.persist(&entries);
        drop(entries);
        self.notify(key);
    }

    fn subscribe(&self, key: &str, listener: StateListener) -> Subscription {
        let id = {
            let Ok(mut next) = self.next_listener_id.lock() else {
                return Subscription::empty();
            };
            *next += 1;
            *next
        };
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners
                .entry(key.to_string())
                .or_default()
                .push((id, listener));
        }

        let key = key.to_string();
        let listeners = self.listeners.clone();
        Subscription::new(Box::new(move || {
            if let Ok(mut listeners) = listeners.lock()
                && let Some(slot) = listeners.get_mut(&key)
            {
                slot.retain(|(listener_id, _)| *listener_id != id);
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::export::Principal;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_directory() -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos();
        path.push(format!("ic-auth-client-state-{unique}"));
        path
    }

    fn principal() -> Principal {
        Principal::self_authenticating([1u8, 2, 3])
    }

    fn state(expiration_ns: u64) -> StoredSessionState {
        StoredSessionState {
            principal: principal(),
            expiration_ns,
        }
    }

    #[test]
    fn round_trips_through_the_file() {
        let directory = temp_directory();
        {
            let store = NativeStateStorage::new(&directory).unwrap();
            assert_eq!(store.get("ic-session-state"), None);
            store.set("ic-session-state", state(42));
            let read = store.get("ic-session-state").unwrap();
            assert_eq!(read.principal, principal());
            assert_eq!(read.expiration_ns, 42);
            assert!(read.held);
        }

        // A new store over the same directory reads what was written.
        let reopened = NativeStateStorage::new(&directory).unwrap();
        let read = reopened.get("ic-session-state").unwrap();
        assert_eq!(read.expiration_ns, 42);
        reopened.remove("ic-session-state");
        assert_eq!(reopened.get("ic-session-state"), None);
        assert_eq!(
            NativeStateStorage::new(&directory)
                .unwrap()
                .get("ic-session-state"),
            None
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn the_file_is_atomic_json_with_a_version() {
        let directory = temp_directory();
        let store = NativeStateStorage::new(&directory).unwrap();
        store.set("ic-session-state", state(7));
        let contents = std::fs::read_to_string(store.file_path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(value["version"], serde_json::json!(STATE_FILE_VERSION));
        assert_eq!(
            value["entries"]["ic-session-state"]["expiration_ns"],
            serde_json::json!(7)
        );
        assert!(!store.file_path().with_extension("json.tmp").exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_corrupt_file_reads_as_no_record() {
        let directory = temp_directory();
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(STATE_FILE_NAME), "not json").unwrap();
        let store = NativeStateStorage::new(&directory).unwrap();
        assert_eq!(store.get("ic-session-state"), None);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn listeners_fire_and_unsubscribe() {
        let directory = temp_directory();
        let store = Arc::new(NativeStateStorage::new(&directory).unwrap());
        let fires = Arc::new(AtomicUsize::new(0));
        let counter = fires.clone();
        let subscription = store.subscribe(
            "ic-session-state",
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        store.set("ic-session-state", state(1));
        assert_eq!(fires.load(Ordering::SeqCst), 1);
        subscription.unsubscribe();
        store.remove("ic-session-state");
        assert_eq!(fires.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn it_is_never_read_only_and_not_resumable() {
        let directory = temp_directory();
        let store = NativeStateStorage::new(&directory).unwrap();
        assert!(!store.is_read_only());
        assert!(!store.resumable());
        let _ = std::fs::remove_dir_all(directory);
    }
}
