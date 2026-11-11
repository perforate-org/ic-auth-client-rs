//! An identity that replaces its own delegation as it ages.
//!
//! Port of upstream `session/session-identity.ts`. What an application signs
//! with is a short-lived app delegation rooted at the account key; this type
//! holds it and replaces it as it approaches expiry, so the object an agent
//! holds for hours stays valid.
//!
//! # The rotation state machine
//!
//! ```text
//!                  create()                        first prepare() / request
//!   no credential ────────► credential (locked read-or-mint) ────────────► serving
//!        │                        │                                          │
//!        │                        │ mint fails SessionGone                  │ ms_left <= 15s
//!        │                        ▼                                          ▼
//!        │                  on_session_gone()                      mint behind current (if
//!        │                  throw SessionGone                       > 10s), else await mint
//!        │                        │                                          │
//!        │                        │ SessionUnsupported                       │ rotation scheduled at
//!        │                        ▼                                          │ ms_left - 15s
//!        │                  latch + dispose()                                 ▼
//!        │                  throw same error                          adopt → schedule again
//!        │
//!        └─ session already past the 10s block margin → on_session_gone() + throw
//! ```
//!
//! # Constants
//!
//! | Constant | Value | Why |
//! | --- | --- | --- |
//! | [`BLOCK_MARGIN_MS`] | 10 s | a delegation must outlive a request's flight time, or the replica rejects it |
//! | [`PRE_MINT_THRESHOLD_MS`] | 15 s | when a replacement is minted; covers one mint only |
//!
//! # Rust deviations
//!
//! `ic_agent::Identity::sign` is synchronous, so it cannot await a mint. The
//! async entry point is [`SessionIdentity::prepare`]: a caller that wants the
//! block margin honoured calls it before issuing requests (and [`refresh`] from
//! foreground/activity hooks). `sign` uses the delegation currently held and
//! fails rather than signing with an expired one.
//!
//! [`refresh`]: SessionIdentity::refresh

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
use std::time::Duration;

use futures::channel::oneshot;
use ic_agent::agent::EnvelopeContent;
use ic_agent::export::Principal;
use ic_agent::identity::{Delegation, Identity, Signature, SignedDelegation};
use parking_lot::Mutex;

use crate::client::credentials::{Credential, SharedCredentialStorage};
use crate::client::platform::{Listener, PlatformBounds};
use crate::client::session::app_delegation_source::{
    AppDelegationSource, Held, SessionError, SessionGoneError, account_of, ms_left,
};
use crate::client::session::app_lock::{LockManager, MintWork, default_lock_manager};
use crate::delegation_chain::DelegationChain;

/// How much life a delegation needs left to be handed to a caller.
///
/// Covers a request's flight time, because the delegation has to still be valid
/// when the replica verifies the request it was attached to.
pub const BLOCK_MARGIN_MS: u64 = 10_000;

/// When a replacement is minted.
///
/// Covers one mint and nothing more: minting early discards the rest of a
/// delegation's life, so an active session consumes lifetime at
/// `ttl / (ttl - threshold)` and every second here costs update calls on every
/// active session. A refresh is scheduled for this moment rather than waiting
/// for a request to arrive inside the window, which is what keeps it small.
pub const PRE_MINT_THRESHOLD_MS: u64 = 15_000;

/// Time, injectable so the rotation arithmetic can be tested.
pub trait Clock: PlatformBounds {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::client::now::now_ns() / 1_000_000
    }
}

/// The clock this target uses unless one is injected.
pub fn default_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// A scheduled callback that can be cancelled.
pub trait ScheduledTask: PlatformBounds {
    /// Stops the callback firing, where it has not already fired.
    fn cancel(&self);
}

/// Schedules a callback, injectable so a test can decide when a rotation is due.
pub trait Scheduler: PlatformBounds {
    /// Runs `callback` after `delay_ms`, unless cancelled first.
    fn schedule(&self, delay_ms: u64, callback: Arc<dyn Listener>) -> Box<dyn ScheduledTask>;
}

/// The scheduler this target uses unless one is injected.
pub fn default_scheduler() -> Arc<dyn Scheduler> {
    Arc::new(PlatformScheduler)
}

#[cfg(feature = "wasm-js")]
mod platform_scheduler {
    use super::*;

    /// Schedules through `setTimeout`, so a backgrounded tab's throttled timers
    /// are the platform's business rather than ours.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct PlatformScheduler;

    struct WasmTask {
        cancelled: Arc<AtomicBool>,
    }

    impl ScheduledTask for WasmTask {
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    impl Scheduler for PlatformScheduler {
        fn schedule(&self, delay_ms: u64, callback: Arc<dyn Listener>) -> Box<dyn ScheduledTask> {
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = cancelled.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let delay = delay_ms.min(u32::MAX as u64) as u32;
                gloo_timers::future::TimeoutFuture::new(delay).await;
                if !flag.load(Ordering::SeqCst) {
                    callback.call();
                }
            });
            Box::new(WasmTask { cancelled })
        }
    }
}

#[cfg(feature = "wasm-js")]
pub use platform_scheduler::PlatformScheduler;

#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
mod platform_scheduler {
    use super::*;

    /// Schedules on a detached thread: there is no ambient executor a library
    /// can spawn onto, and a refresh nobody awaits must not hold the process
    /// open.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct PlatformScheduler;

    struct ThreadTask {
        cancelled: Arc<AtomicBool>,
    }

    impl ScheduledTask for ThreadTask {
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    impl Scheduler for PlatformScheduler {
        fn schedule(&self, delay_ms: u64, callback: Arc<dyn Listener>) -> Box<dyn ScheduledTask> {
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = cancelled.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(delay_ms));
                if !flag.load(Ordering::SeqCst) {
                    callback.call();
                }
            });
            Box::new(ThreadTask { cancelled })
        }
    }
}

#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
pub use platform_scheduler::PlatformScheduler;

/// Whether a credential is acceptable for a mint or an adoption.
///
/// Its own trait rather than `dyn Fn(&Held) -> bool + PlatformBounds`, because a
/// trait object may carry only one non-auto trait.
pub trait CredentialPredicate: PlatformBounds {
    /// Whether `held` may be used.
    fn accepts(&self, held: &Held) -> bool;
}

impl<F: Fn(&Held) -> bool + PlatformBounds> CredentialPredicate for F {
    fn accepts(&self, held: &Held) -> bool {
        self(held)
    }
}

/// What a read or a mint needs, bundled so it can be cloned into the work a
/// lock runs.
pub(crate) struct MintContext {
    source: Arc<dyn AppDelegationSource>,
    storage: SharedCredentialStorage,
    slot: String,
    locks: Arc<dyn LockManager>,
    clock: Arc<dyn Clock>,
}

impl MintContext {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn ms_left(&self, chain: &DelegationChain) -> i64 {
        ms_left(chain, self.now_ms())
    }

    /// The lock a mint is serialised on, or `None` where none is worth taking.
    fn lock_name(&self) -> Option<String> {
        // A store no other tab can read has nothing another tab could adopt, so
        // serialising would spread the mints without preventing any of them.
        if self.storage.shared() {
            Some(self.slot.clone())
        } else {
            None
        }
    }
}

/// Whether a session has enough left that minting against it returns something
/// usable.
fn session_has_life_left(now_ms: u64, session_expires_at_ms: u64) -> bool {
    session_expires_at_ms as i64 - now_ms as i64 > BLOCK_MARGIN_MS as i64
}

/// Reads what the slot holds, or `None` where it holds nothing usable.
///
/// `evict_spent` may only be set by a caller holding the mint lock: the store
/// reaches every tab of the origin, so a lock-free read that removed what it
/// declined could delete a credential another tab minted between the read and
/// the removal.
async fn read_slot(
    ctx: &MintContext,
    evict_spent: bool,
    verify: Option<&dyn CredentialPredicate>,
) -> Result<Option<Held>, SessionError> {
    let stored = match ctx.storage.get(&ctx.slot).await {
        Ok(stored) => stored,
        // A store that cannot answer is treated as empty: the mint that follows
        // is the recovery, and the read is not the operation the caller asked
        // for.
        Err(_) => None,
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let Some(chain) = stored.chain else {
        return Ok(None);
    };

    // A spent credential goes rather than merely being declined. The state is
    // the only thing meant to outlive a delegation, and it records who is signed
    // in on its own, so nothing here is worth keeping once it can no longer
    // sign.
    if ms_left(&chain, ctx.now_ms()) <= 0 {
        if evict_spent {
            // Best effort. A credential that cannot be removed is still one this
            // tab refuses, so a failure costs tidiness and not correctness.
            let _ = ctx.storage.remove(&ctx.slot).await;
        }
        return Ok(None);
    }

    let held = Held {
        identity: stored.identity,
        chain,
    };
    if let Some(verify) = verify
        && !verify.accepts(&held)
    {
        return Ok(None);
    }
    Ok(Some(held))
}

/// The one place an app credential is minted and written.
///
/// Reads the slot under the lock and mints only where what it finds cannot be
/// used. The lock alone would merely serialise: five tabs waking together would
/// queue politely and then make five calls one after another. The read inside it
/// is what turns serialising into suppressing, and it is why the floor is one
/// mint per origin rather than one per tab.
async fn acquire_credential(
    ctx: Arc<MintContext>,
    verify: Option<Arc<dyn CredentialPredicate>>,
    adopt: bool,
    on_gone: Arc<dyn Listener>,
) -> Result<Held, SessionError> {
    let lock_name = ctx.lock_name();
    let locks = ctx.locks.clone();
    let ctx_for_work = Arc::clone(&ctx);
    let work: MintWork = Box::new(move |stolen| {
        let ctx = Arc::clone(&ctx_for_work);
        let verify = verify.clone();
        let on_gone = on_gone.clone();
        Box::pin(async move {
            let stored = read_slot(&ctx, true, verify.as_deref()).await?;
            // Read either way, so a spent record is evicted; adopted only where
            // the caller could say which account it expects.
            if adopt
                && let Some(stored) = stored
                && ctx.ms_left(&stored.chain) > PRE_MINT_THRESHOLD_MS as i64
            {
                return Ok(stored);
            }

            let identity =
                ctx.storage.create().await.map_err(|error| {
                    SessionError::Retryable(format!("credential storage: {error}"))
                })?;
            let key_der = identity.public_key().ok_or_else(|| {
                SessionError::Retryable(
                    "the credential store made a key with no public key".to_string(),
                )
            })?;
            let chain = match ctx.source.mint(&key_der).await {
                Ok(chain) => chain,
                Err(error) => {
                    if error.is_gone() {
                        on_gone.call();
                    }
                    return Err(error);
                }
            };

            let held = Held { identity, chain };
            if let Some(verify) = verify.as_deref()
                && !verify.accepts(&held)
            {
                return Err(SessionError::AccountMismatch(
                    crate::client::session::app_delegation_source::AccountMismatchError,
                ));
            }

            // Checked here, after the calls have returned and before anything is
            // written: a sign-out elsewhere took the lock away while this was in
            // flight, and it has already cleared the slot this would write to.
            if stolen.is_aborted() {
                on_gone.call();
                return Err(SessionGoneError.into());
            }

            // A credential that cannot be written is still one this tab can use.
            // The cost of a failed write is that other tabs mint for themselves,
            // which is what they do without a lock at all.
            let _ = ctx
                .storage
                .set(
                    &ctx.slot,
                    Credential::with_chain(held.identity.clone(), held.chain.clone()),
                )
                .await;
            Ok(held)
        })
    });

    locks.with_mint_lock(lock_name.as_deref(), work).await
}

/// One in-flight mint, shared by every caller that asks while it runs.
#[derive(Default)]
struct MintGate {
    in_flight: bool,
    waiters: Vec<oneshot::Sender<Result<Held, SessionError>>>,
}

enum MintStart {
    Leader,
    Follower(oneshot::Receiver<Result<Held, SessionError>>),
}

/// Clears the in-flight flag when the leading mint goes away without finishing
/// (a cancelled future), so followers do not wait forever.
struct LeaderGuard {
    inner: Arc<Inner>,
    done: bool,
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut gate = self.inner.gate.lock();
        gate.in_flight = false;
        let error = Err(SessionError::Retryable(
            "the mint was cancelled".to_string(),
        ));
        for waiter in gate.waiters.drain(..) {
            let _ = waiter.send(error.clone());
        }
    }
}

struct Inner {
    ctx: Arc<MintContext>,
    account: Principal,
    session_expires_at_ms: u64,
    on_session_gone: Arc<dyn Listener>,
    scheduler: Arc<dyn Scheduler>,
    held: Mutex<Option<Held>>,
    gate: Mutex<MintGate>,
    current_was_used: AtomicBool,
    scheduled: Mutex<Option<Box<dyn ScheduledTask>>>,
    reported_gone: AtomicBool,
    unsupported: Mutex<Option<SessionError>>,
    disposed: AtomicBool,
}

// `ic-agent`'s `Identity` is `Send + Sync` on every target. On wasm there is one
// thread, so the stores, sources and schedulers this type holds (which are not
// `Send` because their futures are `!Send` by design, see `platform.rs`) can be
// held in an identity handed to the agent. No reference to this type ever
// crosses a thread: the wasm build does not start one.
#[cfg(not(feature = "native"))]
unsafe impl Send for Inner {}
#[cfg(not(feature = "native"))]
unsafe impl Sync for Inner {}

impl Inner {
    /// A single-flight mint: concurrent callers share one attempt.
    async fn mint(self: &Arc<Self>) -> Result<Held, SessionError> {
        loop {
            let start = {
                let mut gate = self.gate.lock();
                if gate.in_flight {
                    let (sender, receiver) = oneshot::channel();
                    gate.waiters.push(sender);
                    MintStart::Follower(receiver)
                } else {
                    gate.in_flight = true;
                    MintStart::Leader
                }
            };

            match start {
                MintStart::Leader => {
                    let mut guard = LeaderGuard {
                        inner: self.clone(),
                        done: false,
                    };
                    let result = self.mint_once().await;
                    guard.done = true;
                    drop(guard);

                    let mut gate = self.gate.lock();
                    gate.in_flight = false;
                    for waiter in gate.waiters.drain(..) {
                        let _ = waiter.send(result.clone());
                    }
                    return result;
                }
                MintStart::Follower(receiver) => match receiver.await {
                    Ok(result) => return result,
                    // The leader vanished without answering; try to lead.
                    Err(_) => continue,
                },
            }
        }
    }

    async fn mint_once(self: &Arc<Self>) -> Result<Held, SessionError> {
        // A session this library cannot act for will answer the same way every
        // time, so nothing is gained by asking again: the rotation stops and the
        // error reaches the caller. The record is left alone — the sign-in is
        // alive, and retracting it would sign every tab on the domain out of it.
        if let Some(unsupported) = self.unsupported.lock().clone() {
            return Err(unsupported);
        }

        // A delegation lasts min(its ttl, what remains of the session), so
        // minting against an almost finished session returns one already too
        // short to use, and refreshing on the delegation alone would mint
        // without end.
        if !session_has_life_left(self.ctx.now_ms(), self.session_expires_at_ms) {
            self.report_gone();
            return Err(SessionGoneError.into());
        }

        let expected = Some(self.account);
        let verify: Arc<dyn CredentialPredicate> =
            Arc::new(move |held: &Held| held.is_for_account(expected));
        let inner = self.clone();
        let on_gone: Arc<dyn Listener> = Arc::new(move || inner.report_gone());

        let result = acquire_credential(self.ctx.clone(), Some(verify), true, on_gone).await;
        match result {
            Ok(credential) => {
                self.adopt(credential.clone());
                Ok(credential)
            }
            Err(error) => {
                // Latched, and the rotation dropped: asking again would return
                // the same answer, and a timer that keeps firing for it is a
                // timer that never stops.
                if error.is_unsupported() {
                    *self.unsupported.lock() = Some(error.clone());
                    self.dispose();
                }
                Err(error)
            }
        }
    }

    fn adopt(self: &Arc<Self>, credential: Held) {
        *self.held.lock() = Some(credential.clone());
        self.current_was_used.store(false, Ordering::SeqCst);
        self.schedule(&credential.chain);
    }

    fn schedule(self: &Arc<Self>, chain: &DelegationChain) {
        self.cancel_scheduled();
        if self.disposed.load(Ordering::SeqCst) {
            return;
        }
        let delay = self.ms_left(chain) - PRE_MINT_THRESHOLD_MS as i64;
        if delay <= 0 {
            return;
        }

        let inner = self.clone();
        let callback: Arc<dyn Listener> = Arc::new(move || {
            // Only refresh a credential something used — signing a request, or
            // a caller saying somebody is here. Each one earns the next refresh
            // and no more, so an application nobody is using lets its delegation
            // lapse rather than refreshing for as long as a tab is open.
            if !inner.current_was_used.load(Ordering::SeqCst) {
                return;
            }
            inner.mint_blocking();
        });
        let task = self.scheduler.schedule(delay as u64, callback);
        *self.scheduled.lock() = Some(task);
    }

    fn cancel_scheduled(&self) {
        if let Some(task) = self.scheduled.lock().take() {
            task.cancel();
        }
    }

    /// Runs one mint, blocking this thread where the target allows it.
    fn mint_blocking(self: &Arc<Self>) {
        #[cfg(feature = "wasm-js")]
        {
            let inner = self.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = inner.mint().await;
            });
        }
        #[cfg(all(not(feature = "wasm-js"), feature = "native"))]
        {
            let _ = futures::executor::block_on(self.mint());
        }
    }

    /// Starts a mint without waiting for it.
    ///
    /// Scheduled through the scheduler rather than a raw thread so a test can
    /// decide when it runs.
    fn mint_in_background(self: &Arc<Self>) {
        let inner = self.clone();
        let callback: Arc<dyn Listener> = Arc::new(move || inner.mint_blocking());
        let _ = self.scheduler.schedule(0, callback);
    }

    /// The credential to serve a request with, minting where it must.
    async fn usable(self: &Arc<Self>) -> Result<Held, SessionError> {
        let current = self.held.lock().clone();
        if let Some(current) = current {
            let left = self.ms_left(&current.chain);
            if left > PRE_MINT_THRESHOLD_MS as i64 {
                return Ok(current);
            }
            if left > BLOCK_MARGIN_MS as i64 {
                // Enough life to serve this request while a replacement is on
                // its way.
                self.mint_in_background();
                return Ok(current);
            }
        }
        self.mint().await
    }

    /// "Somebody is here": mints now if a replacement is due.
    async fn refresh_if_due(self: &Arc<Self>) {
        let current = self.held.lock().clone();
        if let Some(current) = current {
            if self.ms_left(&current.chain) > PRE_MINT_THRESHOLD_MS as i64 {
                return;
            }
        } else {
            // Nothing held yet, so what another tab left is worth having before
            // minting.
            let expected = Some(self.account);
            let verify: Arc<dyn CredentialPredicate> =
                Arc::new(move |held: &Held| held.is_for_account(expected));
            if let Ok(Some(stored)) = read_slot(&self.ctx, false, Some(&*verify)).await
                && self.ms_left(&stored.chain) > PRE_MINT_THRESHOLD_MS as i64
            {
                self.adopt(stored);
                return;
            }
        }
        // Silent by design: nothing is waiting on this path.
        let _ = self.mint().await;
    }

    fn ms_left(&self, chain: &DelegationChain) -> i64 {
        self.ctx.ms_left(chain)
    }

    fn dispose(&self) {
        self.disposed.store(true, Ordering::SeqCst);
        self.cancel_scheduled();
    }

    fn report_gone(self: &Arc<Self>) {
        if self.reported_gone.swap(true, Ordering::SeqCst) {
            return;
        }
        self.dispose();
        self.on_session_gone.call();
    }
}

/// Options for [`SessionIdentity::create`].
pub struct SessionIdentityCreateOptions {
    /// When the session itself ends. Nothing is minted past this.
    pub session_expires_at_ms: u64,
    /// Where app delegations are minted from.
    pub source: Arc<dyn AppDelegationSource>,
    /// Where the app credential is kept.
    pub storage: SharedCredentialStorage,
    /// The slot the app credential lives under, and the name of the lock that
    /// serialises minting into it.
    pub slot: String,
    /// Called once when the session turns out to be gone.
    pub on_session_gone: Arc<dyn Listener>,
    /// The account the caller expects, where it knows one.
    ///
    /// Absent only where the caller has no account to name, which is why a read
    /// that cannot check it does not adopt: a mint reports the account, and is
    /// the only thing that can establish one.
    pub expected_account: Option<Principal>,
    /// The clock to measure expirations with.
    pub clock: Option<Arc<dyn Clock>>,
    /// The scheduler that decides when a rotation is due.
    pub scheduler: Option<Arc<dyn Scheduler>>,
    /// The lock manager that serialises minting across tabs.
    pub locks: Option<Arc<dyn LockManager>>,
}

/// Options for [`SessionIdentity::new`].
pub struct SessionIdentityOptions {
    /// The account's key, which every app delegation is rooted at.
    pub account_key: Vec<u8>,
    /// When the session itself ends. Nothing is minted past this.
    pub session_expires_at_ms: u64,
    /// Where app delegations are minted from.
    pub source: Arc<dyn AppDelegationSource>,
    /// Where the app credential is kept.
    pub storage: SharedCredentialStorage,
    /// The slot the app credential lives under.
    pub slot: String,
    /// Called once when the session turns out to be gone.
    pub on_session_gone: Arc<dyn Listener>,
    /// The clock to measure expirations with.
    pub clock: Option<Arc<dyn Clock>>,
    /// The scheduler that decides when a rotation is due.
    pub scheduler: Option<Arc<dyn Scheduler>>,
    /// The lock manager that serialises minting across tabs.
    pub locks: Option<Arc<dyn LockManager>>,
}

/// An identity whose credential is short-lived and replaced under the caller.
///
/// It presents an ordinary app delegation to `ic-agent`, but the key and
/// delegation it signs with are replaced as they age, which is why an agent can
/// hold this object for hours: an agent keeps whatever identity it was given, so
/// a snapshot of one credential would sign with it until it expired.
///
/// The principal comes from the account's key rather than from whatever is
/// current, so a rotation is invisible to the holder.
pub struct SessionIdentity {
    inner: Arc<Inner>,
    account: Principal,
    account_key: Vec<u8>,
}

impl std::fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionIdentity")
            .field("principal", &self.account.to_text())
            .field("has_delegation", &self.inner.held.lock().is_some())
            .field("disposed", &self.inner.disposed.load(Ordering::SeqCst))
            .finish()
    }
}

impl SessionIdentity {
    /// Builds an identity for a session, resolving the account key it needs.
    ///
    /// The account key cannot be worked out from the session — the session chain
    /// is rooted at the session's own key, and the state carries the account's
    /// principal, which is a hash of the account key rather than the key. So the
    /// only two places one can come from are a credential the store already
    /// holds and a mint, and a caller with neither has to wait for the mint
    /// before an identity exists at all.
    ///
    /// That resolution goes through the same locked read-or-mint every rotation
    /// uses, which is what keeps the app slot to one writer.
    pub async fn create(options: SessionIdentityCreateOptions) -> Result<Self, SessionError> {
        let SessionIdentityCreateOptions {
            session_expires_at_ms,
            source,
            storage,
            slot,
            on_session_gone,
            expected_account,
            clock,
            scheduler,
            locks,
        } = options;

        let clock = clock.unwrap_or_else(default_clock);
        if !session_has_life_left(clock.now_ms(), session_expires_at_ms) {
            on_session_gone.call();
            return Err(SessionGoneError.into());
        }

        let ctx = Arc::new(MintContext {
            source,
            storage,
            slot,
            locks: locks.unwrap_or_else(default_lock_manager),
            clock,
        });

        let verify: Option<Arc<dyn CredentialPredicate>> = Some(Arc::new(move |held: &Held| {
            held.is_for_account(expected_account)
        }));
        // A caller that cannot name the account has nothing to check the slot
        // against, so it mints rather than trusting what is there.
        let adopt = expected_account.is_some();
        let credential =
            acquire_credential(ctx.clone(), verify, adopt, on_session_gone.clone()).await?;

        let account = account_of(&credential.chain);
        let account_key = credential.chain.public_key.clone();
        let identity = Self {
            inner: Arc::new(Inner {
                ctx,
                account,
                session_expires_at_ms,
                on_session_gone,
                scheduler: scheduler.unwrap_or_else(default_scheduler),
                held: Mutex::new(None),
                gate: Mutex::default(),
                current_was_used: AtomicBool::new(false),
                scheduled: Mutex::new(None),
                reported_gone: AtomicBool::new(false),
                unsupported: Mutex::new(None),
                disposed: AtomicBool::new(false),
            }),
            account,
            account_key,
        };
        identity.inner.adopt(credential);
        Ok(identity)
    }

    /// Builds an identity around a known account key, holding no delegation yet.
    ///
    /// The account's key is the root of every app delegation, so an empty chain
    /// rooted at it answers [`Identity::public_key`] and the principal before
    /// anything is minted.
    pub fn new(options: SessionIdentityOptions) -> Self {
        let SessionIdentityOptions {
            account_key,
            session_expires_at_ms,
            source,
            storage,
            slot,
            on_session_gone,
            clock,
            scheduler,
            locks,
        } = options;
        let account = Principal::self_authenticating(&account_key);
        Self {
            inner: Arc::new(Inner {
                ctx: Arc::new(MintContext {
                    source,
                    storage,
                    slot,
                    locks: locks.unwrap_or_else(default_lock_manager),
                    clock: clock.unwrap_or_else(default_clock),
                }),
                account,
                session_expires_at_ms,
                on_session_gone,
                scheduler: scheduler.unwrap_or_else(default_scheduler),
                held: Mutex::new(None),
                gate: Mutex::default(),
                current_was_used: AtomicBool::new(false),
                scheduled: Mutex::new(None),
                reported_gone: AtomicBool::new(false),
                unsupported: Mutex::new(None),
                disposed: AtomicBool::new(false),
            }),
            account,
            account_key,
        }
    }

    /// The account this identity answers for, whether or not a delegation is
    /// held.
    pub fn principal(&self) -> Principal {
        self.account
    }

    /// The account key every app delegation is rooted at.
    pub fn account_key(&self) -> &[u8] {
        &self.account_key
    }

    /// The delegation currently held, or an empty chain rooted at the account
    /// key before anything is minted.
    pub fn delegation(&self) -> DelegationChain {
        match self.inner.held.lock().clone() {
            Some(held) => held.chain,
            None => DelegationChain::new(Vec::new(), self.account_key.clone()),
        }
    }

    /// Whether a delegation is held.
    pub fn has_delegation(&self) -> bool {
        self.inner.held.lock().is_some()
    }

    /// When the delegation currently held expires, in milliseconds.
    pub fn delegation_expires_at_ms(&self) -> u64 {
        self.inner
            .held
            .lock()
            .as_ref()
            .map(|held| crate::client::session::app_delegation_source::expires_at_ms(&held.chain))
            .unwrap_or(0)
    }

    /// Ensures a usable delegation is held, minting one where it must.
    ///
    /// This is the asynchronous half of `ic-agent`'s synchronous `sign`: a
    /// caller about to issue requests calls it first, so the 10-second block
    /// margin is honoured and the request is not signed with a delegation the
    /// replica will reject. It also counts as use, exactly as signing does.
    pub async fn prepare(&self) -> Result<(), SessionError> {
        self.inner.usable().await?;
        self.inner.current_was_used.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Says somebody is here, and mints now if one is due.
    ///
    /// For a caller that knows the moment is a good one, such as a page load, a
    /// tab coming back to the foreground, or a pointer moving. The caller says
    /// when; this still decides whether, so a credential with plenty of life
    /// left costs no call.
    ///
    /// It is never a no-op in effect: being here counts as use, exactly as
    /// signing a request does, so the credential held afterwards has earned the
    /// next rotation.
    pub async fn refresh(&self) {
        self.inner.refresh_if_due().await;
        // After, not before: both branches above can replace what is held, and
        // adopting resets this.
        self.inner.current_was_used.store(true, Ordering::SeqCst);
    }

    /// Drops the scheduled refresh.
    ///
    /// Does not clear storage and does not report the session gone.
    pub fn dispose(&self) {
        self.inner.dispose();
    }

    /// Whether [`SessionIdentity::dispose`] has been called.
    pub fn is_disposed(&self) -> bool {
        self.inner.disposed.load(Ordering::SeqCst)
    }

    /// The latched "this session cannot be acted for" error, where one was seen.
    pub fn unsupported(&self) -> Option<SessionError> {
        self.inner.unsupported.lock().clone()
    }

    /// The identity as an `ic-agent` identity.
    pub fn as_arc_identity(self: &Arc<Self>) -> Arc<dyn Identity> {
        self.clone()
    }

    fn held_for_signing(&self) -> Result<Held, String> {
        let held = self
            .inner
            .held
            .lock()
            .clone()
            .ok_or_else(|| "This identity holds no delegation yet".to_string())?;
        if self.inner.ms_left(&held.chain) <= 0 {
            return Err("This identity's delegation has expired; call prepare() first".to_string());
        }
        Ok(held)
    }

    fn attach_chain(&self, signature: &mut Signature) {
        signature.public_key = Some(self.account_key.clone());
        signature.delegations = Some(
            self.inner
                .held
                .lock()
                .as_ref()
                .map(|held| held.chain.delegations.clone())
                .unwrap_or_default(),
        );
    }
}

impl Identity for SessionIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.account)
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.account_key.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        let held = self.held_for_signing()?;
        let mut signature = held
            .identity
            .as_arc_identity()
            .sign(content)
            .map_err(|error| error.to_string())?;
        self.attach_chain(&mut signature);
        Ok(signature)
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        let held = self.held_for_signing()?;
        let mut signature = held
            .identity
            .as_arc_identity()
            .sign_delegation(content)
            .map_err(|error| error.to_string())?;
        self.attach_chain(&mut signature);
        Ok(signature)
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let held = self.held_for_signing()?;
        let mut signature = held
            .identity
            .as_arc_identity()
            .sign_arbitrary(content)
            .map_err(|error| error.to_string())?;
        self.attach_chain(&mut signature);
        Ok(signature)
    }

    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        self.inner
            .held
            .lock()
            .as_ref()
            .map(|held| held.chain.delegations.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use crate::client::credentials::CredentialStorage;
    use crate::client::session::test_support::{
        FakeClock, FakeScheduler, FakeSource, SharedMemoryStore, chain_to,
    };
    use crate::key::BaseKeyType;

    fn delegations_json(delegations: &[SignedDelegation]) -> String {
        serde_json::to_string(delegations).expect("delegations serialise")
    }

    const MINUTE: u64 = 60_000;
    const TTL_MS: i64 = 5 * MINUTE as i64;

    fn account_key() -> Vec<u8> {
        crate::client::credentials::generate_identity(BaseKeyType::Ed25519)
            .expect("a key")
            .public_key()
            .expect("a public key")
    }

    struct Harness {
        identity: Arc<SessionIdentity>,
        clock: FakeClock,
        scheduler: FakeScheduler,
        source: Arc<FakeSource>,
        store: Arc<SharedMemoryStore>,
        gone: Arc<AtomicUsize>,
        slot: String,
    }

    fn harness_with(
        clock: FakeClock,
        session_ms: u64,
        lifetime_ms: i64,
        account: Vec<u8>,
        adopt_expected: bool,
        store: Arc<SharedMemoryStore>,
    ) -> Harness {
        let slot = "app".to_string();
        let expected_account = adopt_expected.then(|| Principal::self_authenticating(&account));
        let source = Arc::new(FakeSource::new(account.clone(), clock.clone(), lifetime_ms));
        let scheduler = FakeScheduler::default();
        let gone = Arc::new(AtomicUsize::new(0));
        let gone_for_callback = gone.clone();
        let on_gone: Arc<dyn Listener> = Arc::new(move || {
            gone_for_callback.fetch_add(1, Ordering::SeqCst);
        });
        let identity =
            futures::executor::block_on(SessionIdentity::create(SessionIdentityCreateOptions {
                session_expires_at_ms: clock.now_ms() + session_ms,
                source: source.clone(),
                storage: store.clone(),
                slot: slot.clone(),
                on_session_gone: on_gone,
                expected_account,
                clock: Some(Arc::new(clock.clone())),
                scheduler: Some(Arc::new(scheduler.clone())),
                locks: None,
            }))
            .expect("a session with life left");
        Harness {
            identity: Arc::new(identity),
            clock,
            scheduler,
            source,
            store,
            gone,
            slot,
        }
    }

    fn harness(session_ms: u64, lifetime_ms: i64) -> Harness {
        harness_with(
            FakeClock::new(1_000_000),
            session_ms,
            lifetime_ms,
            account_key(),
            false,
            Arc::new(SharedMemoryStore::new(true)),
        )
    }

    #[test]
    fn answers_for_the_account_principal_before_anything_is_minted() {
        let harness = harness(30 * MINUTE, TTL_MS);
        assert_eq!(
            harness.identity.principal(),
            Principal::self_authenticating(harness.source.account())
        );
        // `create` mints once to establish the account key; after that the
        // identity answers without another call.
        assert_eq!(harness.source.calls(), 1);
    }

    #[test]
    fn prepare_reuses_the_delegation_it_holds() {
        let harness = harness(30 * MINUTE, TTL_MS);
        let calls = harness.source.calls();
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        assert_eq!(harness.source.calls(), calls);
    }

    #[test]
    fn concurrent_prepares_share_one_mint() {
        let harness = harness(30 * MINUTE, TTL_MS);
        let calls = harness.source.calls();
        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();

        futures::executor::block_on(async {
            let (a, b, c) = futures::join!(
                harness.identity.prepare(),
                harness.identity.prepare(),
                harness.identity.prepare()
            );
            assert!(a.is_ok() && b.is_ok() && c.is_ok());
        });
        assert_eq!(harness.source.calls(), calls + 1);
    }

    #[test]
    fn serves_from_inside_the_threshold_and_mints_behind_it() {
        let harness = harness(30 * MINUTE, TTL_MS);
        let calls = harness.source.calls();
        let before = harness.identity.delegation();

        harness.clock.advance((TTL_MS as u64) - 12_000);
        harness.identity.dispose(); // isolate the request path from the schedule
        futures::executor::block_on(harness.identity.prepare()).unwrap();

        // Served from what was held, with a replacement scheduled behind it.
        assert_eq!(harness.identity.delegation().to_json(), before.to_json());
        assert_eq!(harness.scheduler.pending(), 1);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls + 1);
    }

    #[test]
    fn the_margin_constants_are_the_upstream_values() {
        assert_eq!(BLOCK_MARGIN_MS, 10_000);
        assert_eq!(PRE_MINT_THRESHOLD_MS, 15_000);
    }

    #[test]
    fn the_pre_mint_threshold_is_where_a_background_mint_starts() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let before = harness.identity.delegation();

        // Exactly the threshold: still more than the block margin, so the held
        // delegation serves the request while a replacement is started behind
        // it. One second more and it would be minted in the foreground.
        harness.clock.advance(TTL_MS as u64 - PRE_MINT_THRESHOLD_MS);
        harness.identity.dispose();
        futures::executor::block_on(harness.identity.prepare()).unwrap();

        assert_eq!(harness.identity.delegation().to_json(), before.to_json());
        assert_eq!(harness.scheduler.pending(), 1);
    }

    #[test]
    fn the_block_margin_is_where_serving_waits_for_a_mint() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let before = harness.identity.delegation();

        // Exactly the block margin: not enough life left to hand to a caller,
        // because the delegation must outlive the request's flight time.
        harness.clock.advance(TTL_MS as u64 - BLOCK_MARGIN_MS);
        harness.identity.dispose();
        futures::executor::block_on(harness.identity.prepare()).unwrap();

        assert_ne!(harness.identity.delegation().to_json(), before.to_json());
    }

    #[test]
    fn waits_for_a_mint_inside_the_block_margin() {
        let harness = harness(30 * MINUTE, TTL_MS);
        let calls = harness.source.calls();
        let before = harness.identity.delegation();

        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();
        futures::executor::block_on(harness.identity.prepare()).unwrap();

        assert_eq!(harness.source.calls(), calls + 1);
        assert_ne!(harness.identity.delegation().to_json(), before.to_json());
    }

    #[test]
    fn a_scheduled_rotation_mints_for_a_used_delegation() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let calls = harness.source.calls();

        harness.clock.advance((TTL_MS as u64) - 15_000);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls + 1);
    }

    #[test]
    fn lets_an_unused_delegation_lapse_instead_of_refreshing_it() {
        let harness = harness(30 * MINUTE, TTL_MS);
        // The create-mint is adopted unused, so its rotation earns nothing.
        let calls = harness.source.calls();
        harness.clock.advance(TTL_MS as u64);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls);
    }

    #[test]
    fn refresh_mints_when_one_is_due() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let calls = harness.source.calls();
        harness.identity.dispose();

        harness.clock.advance((TTL_MS as u64) - 12_000);
        futures::executor::block_on(harness.identity.refresh());
        assert_eq!(harness.source.calls(), calls + 1);
    }

    #[test]
    fn refresh_does_nothing_when_the_delegation_is_healthy() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let calls = harness.source.calls();
        futures::executor::block_on(harness.identity.refresh());
        assert_eq!(harness.source.calls(), calls);
    }

    #[test]
    fn refresh_keeps_an_activity_kept_alive_rotation_going() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let calls = harness.source.calls();

        harness.clock.advance((TTL_MS as u64) - 15_000);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls + 1);

        // The replacement has served nothing; a refresh has to be enough.
        futures::executor::block_on(harness.identity.refresh());
        harness.clock.advance((TTL_MS as u64) - 15_000);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls + 2);
    }

    #[test]
    fn reports_a_gone_session_once_and_only_for_no_such_session() {
        let harness = harness(30 * MINUTE, TTL_MS);
        harness
            .source
            .fail_with(Some(SessionError::Gone(SessionGoneError)));
        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();

        let first = futures::executor::block_on(harness.identity.prepare());
        let second = futures::executor::block_on(harness.identity.prepare());
        assert!(first.is_err() && second.is_err());
        assert_eq!(harness.gone.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn latches_an_unsupported_session_and_stops_asking() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        harness.source.fail_with(Some(SessionError::Unsupported(
            crate::client::session::app_delegation_source::SessionUnsupportedError(
                "read-only".to_string(),
            ),
        )));
        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();

        let first = futures::executor::block_on(harness.identity.prepare());
        assert!(first.is_err());
        let asked = harness.source.calls();

        harness.clock.advance(TTL_MS as u64 * 3);
        let second = futures::executor::block_on(harness.identity.prepare());
        assert!(second.is_err());
        assert_eq!(harness.source.calls(), asked);
        // Alive, just unusable here: nothing reports it gone.
        assert_eq!(harness.gone.load(Ordering::SeqCst), 0);
        assert!(harness.identity.unsupported().is_some());
    }

    #[test]
    fn keeps_the_session_when_a_mint_fails_for_any_other_reason() {
        let harness = harness(30 * MINUTE, TTL_MS);
        harness
            .source
            .push_error(SessionError::Retryable("boundary node unreachable".into()));
        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();

        let result = futures::executor::block_on(harness.identity.prepare());
        assert!(result.is_err());
        assert_eq!(harness.gone.load(Ordering::SeqCst), 0);

        // Retryable: the next request tries again.
        let calls = harness.source.calls();
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        assert_eq!(harness.source.calls(), calls + 1);
    }

    #[test]
    fn does_not_mint_against_a_session_with_nothing_left() {
        // The create-mint is refused before it starts: a session with less than
        // the block margin left cannot back a usable delegation.
        let store = Arc::new(SharedMemoryStore::new(true));
        let clock = FakeClock::new(2_000_000);
        let source = Arc::new(FakeSource::new(account_key(), clock.clone(), TTL_MS));
        let gone = Arc::new(AtomicUsize::new(0));
        let gone_cb = gone.clone();
        let error =
            futures::executor::block_on(SessionIdentity::create(SessionIdentityCreateOptions {
                session_expires_at_ms: clock.now_ms() + 5_000,
                source: source.clone(),
                storage: store,
                slot: "app".to_string(),
                on_session_gone: Arc::new(move || {
                    gone_cb.fetch_add(1, Ordering::SeqCst);
                }),
                expected_account: None,
                clock: Some(Arc::new(clock)),
                scheduler: None,
                locks: None,
            }))
            .unwrap_err();
        assert!(error.is_gone());
        assert_eq!(source.calls(), 0);
        assert_eq!(gone.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn refuses_a_delegation_rooted_at_another_account() {
        let harness = harness(30 * MINUTE, TTL_MS);
        let stranger = account_key();
        harness.source.set_account(stranger);
        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();

        let error = futures::executor::block_on(harness.identity.prepare()).unwrap_err();
        assert!(error.is_account_mismatch());
    }

    #[test]
    fn refuses_a_delegation_issued_to_a_key_it_did_not_make() {
        let harness = harness(30 * MINUTE, TTL_MS);
        harness.source.set_leaf_override(account_key());
        harness.clock.advance((TTL_MS as u64) - 5_000);
        harness.identity.dispose();

        let error = futures::executor::block_on(harness.identity.prepare()).unwrap_err();
        assert!(error.is_account_mismatch());
    }

    #[test]
    fn persists_what_it_mints_so_another_tab_can_use_it() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let stored = futures::executor::block_on(harness.store.get(&harness.slot))
            .unwrap()
            .expect("a stored credential");
        assert_eq!(
            stored.chain.expect("a chain").to_json(),
            harness.identity.delegation().to_json()
        );
    }

    #[test]
    fn adopts_what_the_store_already_holds_instead_of_minting() {
        let clock = FakeClock::new(1_000_000);
        let account = account_key();
        let expected = Some(Principal::self_authenticating(&account));
        let store = Arc::new(SharedMemoryStore::new(true));
        let first = harness_with(
            clock.clone(),
            30 * MINUTE,
            TTL_MS,
            account.clone(),
            true,
            store.clone(),
        );
        let minted = first.identity.delegation();

        let source = Arc::new(FakeSource::new(account, clock.clone(), TTL_MS));
        let identity =
            futures::executor::block_on(SessionIdentity::create(SessionIdentityCreateOptions {
                session_expires_at_ms: clock.now_ms() + 30 * MINUTE,
                source: source.clone(),
                storage: store,
                slot: "app".to_string(),
                on_session_gone: Arc::new(|| {}),
                expected_account: expected,
                clock: Some(Arc::new(clock)),
                scheduler: None,
                locks: None,
            }))
            .expect("an identity");
        assert_eq!(source.calls(), 0);
        assert_eq!(identity.delegation().to_json(), minted.to_json());
    }

    #[test]
    fn ignores_a_stored_credential_rooted_at_another_account() {
        let clock = FakeClock::new(1_000_000);
        let account = account_key();
        let expected = Some(Principal::self_authenticating(&account));
        let store = Arc::new(SharedMemoryStore::new(true));
        // A live credential left by a previous sign-in as somebody else.
        let stranger = account_key();
        let stranger_key =
            crate::client::credentials::generate_identity(BaseKeyType::Ed25519).expect("a key");
        futures::executor::block_on(store.set(
            "app",
            Credential::with_chain(
                stranger_key.clone(),
                chain_to(&stranger, &stranger_key.public_key().unwrap(), u64::MAX),
            ),
        ))
        .unwrap();

        let source = Arc::new(FakeSource::new(account.clone(), clock.clone(), TTL_MS));
        let identity =
            futures::executor::block_on(SessionIdentity::create(SessionIdentityCreateOptions {
                session_expires_at_ms: clock.now_ms() + 30 * MINUTE,
                source: source.clone(),
                storage: store,
                slot: "app".to_string(),
                on_session_gone: Arc::new(|| {}),
                expected_account: expected,
                clock: Some(Arc::new(clock)),
                scheduler: None,
                locks: None,
            }))
            .expect("an identity");
        // Minted rather than adopted, and answers for the account it expected.
        assert_eq!(source.calls(), 1);
        assert_eq!(
            identity.principal(),
            Principal::self_authenticating(&account)
        );
    }

    #[test]
    fn mints_rather_than_adopting_when_no_account_is_named() {
        let clock = FakeClock::new(1_000_000);
        let account = account_key();
        let store = Arc::new(SharedMemoryStore::new(true));
        let held =
            crate::client::credentials::generate_identity(BaseKeyType::Ed25519).expect("a key");
        futures::executor::block_on(store.set(
            "app",
            Credential::with_chain(
                held.clone(),
                chain_to(&account, &held.public_key().unwrap(), u64::MAX),
            ),
        ))
        .unwrap();

        let source = Arc::new(FakeSource::new(account.clone(), clock.clone(), TTL_MS));
        let identity =
            futures::executor::block_on(SessionIdentity::create(SessionIdentityCreateOptions {
                session_expires_at_ms: clock.now_ms() + 30 * MINUTE,
                source: source.clone(),
                storage: store,
                slot: "app".to_string(),
                on_session_gone: Arc::new(|| {}),
                expected_account: None,
                clock: Some(Arc::new(clock)),
                scheduler: None,
                locks: None,
            }))
            .expect("an identity");
        // Nothing to check the slot against, so the slot is not trusted.
        assert_eq!(source.calls(), 1);
        let _ = identity;
    }

    #[test]
    fn removes_a_stored_credential_whose_delegation_has_run_out() {
        let clock = FakeClock::new(1_000_000);
        let account = account_key();
        let store = Arc::new(SharedMemoryStore::new(true));
        let spent =
            crate::client::credentials::generate_identity(BaseKeyType::Ed25519).expect("a key");
        futures::executor::block_on(store.set(
            "app",
            Credential::with_chain(
                spent.clone(),
                chain_to(&account, &spent.public_key().unwrap(), 1),
            ),
        ))
        .unwrap();

        let harness = harness_with(
            clock.clone(),
            30 * MINUTE,
            TTL_MS,
            account.clone(),
            false,
            store.clone(),
        );
        let removals = store.removals();
        assert_eq!(removals, 1);
        assert!(harness.identity.has_delegation());
    }

    #[test]
    fn does_not_evict_a_credential_merely_close_to_expiry() {
        let clock = FakeClock::new(1_000_000);
        let account = account_key();
        let store = Arc::new(SharedMemoryStore::new(true));
        let nearly =
            crate::client::credentials::generate_identity(BaseKeyType::Ed25519).expect("a key");
        futures::executor::block_on(store.set(
            "app",
            Credential::with_chain(
                nearly.clone(),
                chain_to(
                    &account,
                    &nearly.public_key().unwrap(),
                    (clock.now_ms() + 5_000) * 1_000_000,
                ),
            ),
        ))
        .unwrap();

        let _harness = harness_with(
            clock,
            30 * MINUTE,
            TTL_MS,
            account.clone(),
            false,
            store.clone(),
        );
        assert_eq!(store.removals(), 0);
    }

    #[test]
    fn stops_scheduling_once_disposed() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let calls = harness.source.calls();
        harness.identity.dispose();

        harness.clock.advance(TTL_MS as u64);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls);
    }

    #[test]
    fn does_not_let_a_glance_cancel_its_own_rotation() {
        let harness = harness(30 * MINUTE, TTL_MS);
        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let calls = harness.source.calls();
        futures::executor::block_on(harness.identity.refresh());

        harness.clock.advance((TTL_MS as u64) - 15_000);
        harness.scheduler.fire_all();
        assert_eq!(harness.source.calls(), calls + 1);
    }

    #[test]
    fn signs_with_the_delegation_it_holds_and_the_account_key() {
        let harness = harness(30 * MINUTE, TTL_MS);
        // Before a delegation is held, signing says so rather than guessing.
        let empty = SessionIdentity::new(SessionIdentityOptions {
            account_key: account_key(),
            session_expires_at_ms: 1_000_000 + 30 * MINUTE,
            source: Arc::new(FakeSource::new(
                account_key(),
                FakeClock::new(1_000_000),
                TTL_MS,
            )),
            storage: Arc::new(SharedMemoryStore::new(false)),
            slot: "app".to_string(),
            on_session_gone: Arc::new(|| {}),
            clock: Some(Arc::new(FakeClock::new(1_000_000))),
            scheduler: None,
            locks: None,
        });
        let content = EnvelopeContent::Query {
            ingress_expiry: 0,
            sender: empty.principal(),
            canister_id: Principal::anonymous(),
            method_name: "m".to_string(),
            arg: vec![],
            nonce: None,
            sender_info: None,
        };
        assert!(empty.sign(&content).is_err());

        futures::executor::block_on(harness.identity.prepare()).unwrap();
        let signature = harness.identity.sign(&content).expect("a signature");
        assert_eq!(
            signature.public_key,
            Some(harness.identity.account_key().to_vec())
        );
        assert_eq!(
            delegations_json(&signature.delegations.expect("delegations")),
            delegations_json(&harness.identity.delegation().delegations)
        );
        assert_eq!(
            harness.identity.sender().unwrap(),
            harness.identity.principal()
        );
        assert_eq!(
            delegations_json(&harness.identity.delegation_chain()),
            delegations_json(&harness.identity.delegation().delegations)
        );
    }
}
