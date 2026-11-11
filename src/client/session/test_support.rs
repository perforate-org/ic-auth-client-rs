//! Shared fakes for the session layer's tests.
//!
//! The session layer is deliberately free of any agent, canister or DOM, so
//! these replace the clock, the mint source, the credential store and the
//! scheduler; the lock manager has a real in-process implementation that the
//! tests use directly.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
#[cfg(feature = "native")]
use ic_agent::export::Principal;
use ic_agent::identity::{Delegation, SignedDelegation};
use parking_lot::Mutex;

use crate::ArcIdentity;
use crate::client::credentials::{Credential, CredentialStorage};
use crate::client::error::AuthClientError;
use crate::client::platform::Listener;
use crate::client::session::app_delegation_source::{AppDelegationSource, SessionError};
use crate::client::session::identity::{Clock, ScheduledTask, Scheduler};
use crate::delegation_chain::DelegationChain;
use crate::key::BaseKeyType;

/// A one-hop chain rooted at `root` and delegating to `leaf`.
pub fn chain_to(root: &[u8], leaf: &[u8], expiration_ns: u64) -> DelegationChain {
    DelegationChain::new(
        vec![SignedDelegation {
            delegation: Delegation {
                pubkey: leaf.to_vec(),
                expiration: expiration_ns,
                targets: None,
                permissions: None,
            },
            signature: vec![1],
        }],
        root.to_vec(),
    )
}

/// A clock the test moves by hand.
#[derive(Clone, Default)]
pub struct FakeClock {
    now_ms: Arc<AtomicU64>,
}

impl FakeClock {
    /// A clock reading `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            now_ms: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, milliseconds: u64) {
        self.now_ms.fetch_add(milliseconds, Ordering::SeqCst);
    }

    /// Sets the clock.
    #[cfg(feature = "native")]
    pub fn set(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// A mint source that signs its answer to whatever key it was handed, unless a
/// test says otherwise.
pub struct FakeSource {
    account: Mutex<Vec<u8>>,
    leaf_override: Mutex<Option<Vec<u8>>>,
    lifetime_ms: Mutex<i64>,
    errors: Mutex<VecDeque<SessionError>>,
    failure: Mutex<Option<SessionError>>,
    calls: AtomicUsize,
    clock: FakeClock,
}

impl FakeSource {
    /// A source rooted at `account`, minting delegations that live for
    /// `lifetime_ms` from the clock's current reading.
    pub fn new(account: Vec<u8>, clock: FakeClock, lifetime_ms: i64) -> Self {
        Self {
            account: Mutex::new(account),
            leaf_override: Mutex::new(None),
            lifetime_ms: Mutex::new(lifetime_ms),
            errors: Mutex::new(VecDeque::new()),
            failure: Mutex::new(None),
            calls: AtomicUsize::new(0),
            clock,
        }
    }

    /// How many mints were asked for.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The account the next mint is rooted at.
    pub fn account(&self) -> Vec<u8> {
        self.account.lock().clone()
    }

    /// Changes the account the next mint is rooted at.
    pub fn set_account(&self, account: Vec<u8>) {
        *self.account.lock() = account;
    }

    /// Makes the next mint authorise a key other than the one asked for.
    pub fn set_leaf_override(&self, leaf: Vec<u8>) {
        *self.leaf_override.lock() = Some(leaf);
    }

    /// Queues an error for the next mint.
    pub fn push_error(&self, error: SessionError) {
        self.errors.lock().push_back(error);
    }

    /// Makes every mint fail with `error` until cleared.
    pub fn fail_with(&self, error: Option<SessionError>) {
        *self.failure.lock() = error;
    }
}

#[async_trait(?Send)]
impl AppDelegationSource for FakeSource {
    async fn mint(&self, app_public_key: &[u8]) -> Result<DelegationChain, SessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.errors.lock().pop_front() {
            return Err(error);
        }
        if let Some(error) = self.failure.lock().clone() {
            return Err(error);
        }
        let leaf = self
            .leaf_override
            .lock()
            .clone()
            .unwrap_or_else(|| app_public_key.to_vec());
        let root = self.account.lock().clone();
        let lifetime = *self.lifetime_ms.lock();
        let expires_ms = (self.clock.now_ms() as i64 + lifetime).max(0) as u64;
        Ok(chain_to(&root, &leaf, expires_ms * 1_000_000))
    }
}

/// A credential store that can claim to be shared between tabs, and counts the
/// removals it was asked for.
pub struct SharedMemoryStore {
    entries: Mutex<HashMap<String, Credential>>,
    shared: bool,
    removals: AtomicUsize,
}

impl SharedMemoryStore {
    /// A store that is (or is not) readable by other tabs.
    pub fn new(shared: bool) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            shared,
            removals: AtomicUsize::new(0),
        }
    }

    /// How many removals were asked for.
    pub fn removals(&self) -> usize {
        self.removals.load(Ordering::SeqCst)
    }
}

#[async_trait(?Send)]
impl CredentialStorage for SharedMemoryStore {
    fn shared(&self) -> bool {
        self.shared
    }

    fn durable(&self) -> bool {
        false
    }

    async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
        crate::client::credentials::generate_identity(BaseKeyType::Ed25519)
    }

    async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
        Ok(self.entries.lock().get(slot).cloned())
    }

    async fn set(&self, slot: &str, credential: Credential) -> Result<(), AuthClientError> {
        self.entries.lock().insert(slot.to_string(), credential);
        Ok(())
    }

    async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
        self.removals.fetch_add(1, Ordering::SeqCst);
        self.entries.lock().remove(slot);
        Ok(())
    }
}

/// A scheduler that fires only when the test says so.
#[derive(Default, Clone)]
pub struct FakeScheduler {
    tasks: Arc<Mutex<Vec<FakeTask>>>,
}

struct FakeTask {
    callback: Arc<dyn Listener>,
    cancelled: Arc<AtomicBool>,
}

struct FakeHandle {
    cancelled: Arc<AtomicBool>,
}

impl ScheduledTask for FakeHandle {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl Scheduler for FakeScheduler {
    fn schedule(&self, _delay_ms: u64, callback: Arc<dyn Listener>) -> Box<dyn ScheduledTask> {
        let cancelled = Arc::new(AtomicBool::new(false));
        self.tasks.lock().push(FakeTask {
            callback,
            cancelled: cancelled.clone(),
        });
        Box::new(FakeHandle { cancelled })
    }
}

impl FakeScheduler {
    /// How many scheduled tasks are still live.
    pub fn pending(&self) -> usize {
        self.tasks
            .lock()
            .iter()
            .filter(|task| !task.cancelled.load(Ordering::SeqCst))
            .count()
    }

    /// Fires every live task, once. Tasks scheduled while firing are left for
    /// the next call, so a rotation does not run away.
    pub fn fire_all(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock());
        for task in tasks {
            if !task.cancelled.load(Ordering::SeqCst) {
                task.callback.call();
            }
        }
    }
}

/// The self-authenticating principal of a DER-encoded key.
#[cfg(feature = "native")]
pub fn account_principal(key_der: &[u8]) -> Principal {
    Principal::self_authenticating(key_der)
}
