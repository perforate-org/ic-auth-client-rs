//! The cross-tab locks a ceremony and a mint take.
//!
//! Port of upstream `session/app-lock.ts`. Coordination may only ever
//! **suppress** work, never be required for it: where the platform has no lock
//! manager, every operation runs straight away and the caller pays for a
//! duplicate mint rather than failing.
//!
//! Two kinds of lock, because two kinds of span:
//!
//! - [`LockManager::with_mint_lock`] wraps one call (the mint) and is released
//!   when the call returns.
//! - [`LockManager::steal_lock`] is held across a span (a ceremony is several
//!   calls and then several writes) and released by the holder, or on drop.
//!
//! Both are taken *stealing* where they can be: the newer intent is the one to
//! honour, and a sign-out the user asked for must not queue behind a canister
//! call in another tab. The incumbent learns through [`StealSignal`], which is
//! the only thing an in-flight mint can act on — a call already sent cannot be
//! recalled, so the signal is what tells it to throw its result away instead of
//! writing it.
//!
//! # Platforms
//!
//! - `wasm-js`: the Web Locks API (`navigator.locks`) through `js_sys`, because
//!   `web-sys`'s `LockManager` bindings need `--cfg web_sys_unstable_apis`.
//!   Where the API is absent this falls back to running immediately.
//! - `native`: an in-process manager keyed by name. Cross-process coordination
//!   is out of scope for a single desktop application, and is documented as
//!   such.
//! - Tests inject their own [`LockManager`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use parking_lot::Mutex;

use crate::client::platform::PlatformBounds;
use crate::client::session::app_delegation_source::{Held, SessionError, SessionGoneError};

/// Fires when the lock a caller holds is taken away by someone else.
///
/// Cloneable, so the holder and the work it runs can both watch it.
#[derive(Clone)]
pub struct StealSignal(Arc<StealSignalState>);

struct StealSignalState {
    aborted: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl StealSignal {
    /// A signal that has not fired.
    pub fn new() -> Self {
        Self(Arc::new(StealSignalState {
            aborted: AtomicBool::new(false),
            waker: Mutex::new(None),
        }))
    }

    /// Whether the lock has been taken away.
    pub fn is_aborted(&self) -> bool {
        self.0.aborted.load(Ordering::SeqCst)
    }

    /// Fires the signal, waking whoever awaits it.
    ///
    /// Idempotent.
    pub fn abort(&self) {
        if !self.0.aborted.swap(true, Ordering::SeqCst)
            && let Some(waker) = self.0.waker.lock().take()
        {
            waker.wake();
        }
    }

    /// A future that resolves when the signal fires.
    pub fn aborted(&self) -> StealWait {
        StealWait(self.clone())
    }

    /// Whether two signals are the same lock grant.
    #[cfg(feature = "native")]
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Default for StealSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StealSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealSignal")
            .field("aborted", &self.is_aborted())
            .finish()
    }
}

/// The future behind [`StealSignal::aborted`].
pub struct StealWait(StealSignal);

impl Future for StealWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let signal = &self.0;
        if signal.is_aborted() {
            return Poll::Ready(());
        }
        *signal.0.waker.lock() = Some(cx.waker().clone());
        // Re-checked after storing the waker: an abort that landed in between
        // would otherwise find no waker to wake.
        if signal.is_aborted() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// A lock held across a span, and a signal for losing it.
///
/// Unlike [`LockManager::with_mint_lock`], what needs guarding here is not one
/// call but a span, so the lock is held by the handle and released by the
/// holder — or when the handle is dropped.
pub struct HeldLock {
    /// Fires when someone else takes this lock away.
    pub stolen: StealSignal,
    release: Mutex<Option<ReleaseFn>>,
}

#[cfg(feature = "native")]
type ReleaseFn = Box<dyn FnOnce() + Send + Sync>;

#[cfg(not(feature = "native"))]
type ReleaseFn = Box<dyn FnOnce()>;

impl HeldLock {
    /// A held lock that runs `release` when it is given up.
    pub fn new<R>(stolen: StealSignal, release: R) -> Self
    where
        R: FnOnce() + PlatformBounds + 'static,
    {
        Self {
            stolen,
            release: Mutex::new(Some(Box::new(release))),
        }
    }

    /// A handle for a lock that was never taken, which never reports a steal.
    pub fn none() -> Self {
        Self {
            stolen: StealSignal::new(),
            release: Mutex::new(None),
        }
    }

    /// Gives the lock up.
    ///
    /// Idempotent, and safe to call after it was stolen: releasing a lock this
    /// holder no longer has does nothing.
    pub fn release(&self) {
        if let Some(release) = self.release.lock().take() {
            release();
        }
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        self.release();
    }
}

impl std::fmt::Debug for HeldLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldLock")
            .field("stolen", &self.stolen.is_aborted())
            .finish()
    }
}

/// The work a mint lock runs, handed the signal for losing the lock.
///
/// Boxed and `'static` because a platform lock may run it from a callback that
/// outlives the call that started it. The work owns clones of whatever it
/// needs rather than borrowing the identity.
pub type MintWork = Box<
    dyn FnOnce(StealSignal) -> Pin<Box<dyn Future<Output = Result<Held, SessionError>> + 'static>>
        + 'static,
>;

/// Runs work under a named lock, where the platform has one.
///
/// The lock is the library coordinating with itself rather than anything a
/// store provides, so a store answers only whether another tab can read it and
/// needs to know nothing about the Web Locks API.
#[async_trait::async_trait(?Send)]
pub trait LockManager: PlatformBounds {
    /// Runs `work` while holding `name`, or runs it immediately where there is
    /// no lock.
    ///
    /// The work is handed a signal that fires when the lock is taken away by
    /// [`LockManager::steal_mint_lock`]. A steal also settles this call at once
    /// with [`SessionError::Gone`], rather than waiting for a mint whose result
    /// is going to be discarded.
    async fn with_mint_lock(
        &self,
        name: Option<&str>,
        work: MintWork,
    ) -> Result<Held, SessionError>;

    /// Takes the mint lock away from whoever holds it, without waiting for
    /// them.
    async fn steal_mint_lock(&self, name: Option<&str>);

    /// Takes a lock away from whoever holds it and keeps it until released.
    fn steal_lock(&self, name: Option<&str>) -> HeldLock;
}

/// Runs `work` under `name` through `locks`.
pub async fn with_mint_lock(
    locks: &dyn LockManager,
    name: Option<&str>,
    work: MintWork,
) -> Result<Held, SessionError> {
    locks.with_mint_lock(name, work).await
}

/// Takes the mint lock away through `locks`.
pub async fn steal_mint_lock(locks: &dyn LockManager, name: Option<&str>) {
    locks.steal_mint_lock(name).await;
}

/// Takes a lock away and holds it, through `locks`.
pub fn steal_lock(locks: &dyn LockManager, name: Option<&str>) -> HeldLock {
    locks.steal_lock(name)
}

/// A manager with no coordination behind it.
///
/// What a target with no lock manager gets: every operation runs straight away,
/// and a duplicate mint costs calls and never correctness.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopLockManager;

#[async_trait::async_trait(?Send)]
impl LockManager for NoopLockManager {
    async fn with_mint_lock(
        &self,
        _name: Option<&str>,
        work: MintWork,
    ) -> Result<Held, SessionError> {
        work(StealSignal::new()).await
    }

    async fn steal_mint_lock(&self, _name: Option<&str>) {}

    fn steal_lock(&self, _name: Option<&str>) -> HeldLock {
        HeldLock::none()
    }
}

// ---------------------------------------------------------------------------
// native: in-process coordination
// ---------------------------------------------------------------------------

#[cfg(feature = "native")]
mod native_impl {
    use std::collections::{HashMap, VecDeque};

    use futures::channel::oneshot;

    use super::*;

    /// The locks one process holds, keyed by name.
    ///
    /// A native installation is one "origin", so in-process coordination is the
    /// whole of it; cross-process coordination is out of scope.
    #[derive(Debug, Default)]
    pub struct InProcessLockManager {
        locks: Mutex<HashMap<String, Arc<NameLock>>>,
    }

    #[derive(Debug, Default)]
    struct NameLock {
        state: Mutex<NameLockState>,
    }

    #[derive(Debug, Default)]
    struct NameLockState {
        holder: Option<StealSignal>,
        waiters: VecDeque<oneshot::Sender<StealSignal>>,
    }

    impl InProcessLockManager {
        /// A manager holding no locks yet.
        pub fn new() -> Self {
            Self::default()
        }

        fn lock_for(&self, name: &str) -> Arc<NameLock> {
            self.locks
                .lock()
                .entry(name.to_string())
                .or_default()
                .clone()
        }
    }

    /// Waits for the lock, or takes it if it is free.
    async fn acquire(lock: &Arc<NameLock>) -> StealSignal {
        loop {
            let receiver = {
                let mut state = lock.state.lock();
                if state.holder.is_none() {
                    let signal = StealSignal::new();
                    state.holder = Some(signal.clone());
                    return signal;
                }
                let (sender, receiver) = oneshot::channel();
                state.waiters.push_back(sender);
                receiver
            };
            // The sender is dropped without sending when its lock is released
            // to nobody, which is not a grant; loop and try again.
            match receiver.await {
                Ok(signal) => return signal,
                Err(_) => continue,
            }
        }
    }

    /// Releases `lock` if `signal` is the grant that still holds it.
    fn release(lock: &NameLock, signal: &StealSignal) {
        let mut state = lock.state.lock();
        if !state
            .holder
            .as_ref()
            .is_some_and(|holder| holder.same(signal))
        {
            // Stolen: the lock already moved on, and releasing it here would
            // hand it away twice.
            return;
        }
        state.holder = None;
        grant_next(&mut state);
    }

    fn grant_next(state: &mut NameLockState) {
        while let Some(waiter) = state.waiters.pop_front() {
            let signal = StealSignal::new();
            state.holder = Some(signal.clone());
            if waiter.send(signal).is_ok() {
                return;
            }
            // The waiter went away before the lock could be handed over.
            state.holder = None;
        }
    }

    #[async_trait::async_trait(?Send)]
    impl LockManager for InProcessLockManager {
        async fn with_mint_lock(
            &self,
            name: Option<&str>,
            work: MintWork,
        ) -> Result<Held, SessionError> {
            let Some(name) = name else {
                return work(StealSignal::new()).await;
            };
            let lock = self.lock_for(name);
            let signal = acquire(&lock).await;

            let work = work(signal.clone());
            let stolen = signal.aborted();
            futures::pin_mut!(stolen);
            match futures::future::select(work, stolen).await {
                futures::future::Either::Left((result, _)) => {
                    release(&lock, &signal);
                    result
                }
                // Stolen: the result this mint was going to write is no longer
                // wanted, so the caller is told at once rather than waiting for
                // calls whose answer is already discarded.
                futures::future::Either::Right(((), _)) => {
                    release(&lock, &signal);
                    Err(SessionGoneError.into())
                }
            }
        }

        async fn steal_mint_lock(&self, name: Option<&str>) {
            let Some(name) = name else {
                return;
            };
            let lock = self.lock_for(name);
            let mut state = lock.state.lock();
            if let Some(holder) = state.holder.take() {
                holder.abort();
            }
            grant_next(&mut state);
        }

        fn steal_lock(&self, name: Option<&str>) -> HeldLock {
            let Some(name) = name else {
                return HeldLock::none();
            };
            let lock = self.lock_for(name);
            let mut state = lock.state.lock();
            if let Some(holder) = state.holder.take() {
                holder.abort();
            }
            let signal = StealSignal::new();
            state.holder = Some(signal.clone());
            drop(state);

            let lock = lock.clone();
            let held = signal.clone();
            HeldLock::new(signal, move || release(&lock, &held))
        }
    }
}

#[cfg(feature = "native")]
pub use native_impl::InProcessLockManager;

// ---------------------------------------------------------------------------
// wasm-js: Web Locks through js_sys
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-js")]
mod web_impl {
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen::JsValue;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_futures::{JsFuture, spawn_local};
    use web_sys::js_sys::{Function, Object, Promise, Reflect};

    use super::*;

    /// The Web Locks API, where the browser has one.
    ///
    /// `navigator.locks` is reached through `js_sys` rather than `web-sys`
    /// because the generated `LockManager` bindings require
    /// `--cfg web_sys_unstable_apis`. Where the API is missing, every operation
    /// runs without coordination.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WebLocks;

    fn locks_object() -> Option<JsValue> {
        let window = web_sys::window()?;
        let navigator = window.navigator();
        let locks = Reflect::get(navigator.as_ref(), &JsValue::from_str("locks")).ok()?;
        (!locks.is_undefined() && !locks.is_null()).then_some(locks)
    }

    fn request_function(locks: &JsValue) -> Option<Function> {
        Reflect::get(locks, &JsValue::from_str("request"))
            .ok()?
            .dyn_into()
            .ok()
    }

    fn options_with_steal() -> JsValue {
        let options = Object::new();
        let _ = Reflect::set(&options, &JsValue::from_str("steal"), &JsValue::TRUE);
        options.unchecked_ref::<JsValue>().clone()
    }

    fn is_abort_error(error: &JsValue) -> bool {
        Reflect::get(error, &JsValue::from_str("name"))
            .ok()
            .and_then(|name| name.as_string())
            .is_some_and(|name| name == "AbortError")
    }

    fn call_request(
        request: &Function,
        locks: &JsValue,
        name: &str,
        callback: &JsValue,
    ) -> Option<Promise> {
        request
            .call2(locks, &JsValue::from_str(name), callback)
            .ok()?
            .dyn_into()
            .ok()
    }

    #[async_trait::async_trait(?Send)]
    impl LockManager for WebLocks {
        async fn with_mint_lock(
            &self,
            name: Option<&str>,
            work: MintWork,
        ) -> Result<Held, SessionError> {
            let locks_and_request = locks_object()
                .and_then(|locks| request_function(&locks).map(|request| (locks, request)));
            let (Some(name), Some((locks, request))) = (name, locks_and_request) else {
                return work(StealSignal::new()).await;
            };

            let signal = StealSignal::new();
            let (sender, receiver) =
                futures::channel::oneshot::channel::<Result<Held, SessionError>>();

            // The callback's promise is what the platform keeps the lock for, so
            // it resolves only once the mint has finished. The result travels
            // back through the channel rather than through JS.
            //
            // The executor closure is `FnMut` although the callback runs once;
            // the pieces are taken out of a slot so moving them into the spawned
            // future is not a move out of a captured variable.
            let mut callback_slot = Some((work, signal.clone(), sender));
            let promise = Promise::new(&mut move |resolve, _reject| {
                let (work, work_signal, sender) =
                    callback_slot.take().expect("the lock callback runs once");
                let resolve = resolve.clone();
                spawn_local(async move {
                    let result = work(work_signal).await;
                    let _ = sender.send(result);
                    let _ = resolve.call0(&JsValue::NULL);
                });
            });

            let callback =
                Closure::once_into_js(move || promise.unchecked_ref::<JsValue>().clone());
            let requested = match call_request(&request, &locks, name, callback.unchecked_ref()) {
                Some(requested) => requested,
                None => {
                    return Err(SessionError::Retryable(
                        "the browser refused to take the mint lock".into(),
                    ));
                }
            };

            match JsFuture::from(requested).await {
                Ok(_) => match receiver.await {
                    Ok(result) => result,
                    Err(_) => Err(SessionError::Retryable(
                        "the mint lock callback never ran".into(),
                    )),
                },
                // A steal rejects this document's request, in this document.
                // That rejection is the only notice another tab's sign-out can
                // deliver, so it is turned into the signal the work watches.
                Err(_) => {
                    signal.abort();
                    Err(SessionGoneError.into())
                }
            }
        }

        async fn steal_mint_lock(&self, name: Option<&str>) {
            let locks_and_request = locks_object()
                .and_then(|locks| request_function(&locks).map(|request| (locks, request)));
            let (Some(name), Some((locks, request))) = (name, locks_and_request) else {
                return;
            };
            let callback = Closure::once_into_js(|| JsValue::UNDEFINED);
            let Some(requested) = call_request_with_options(&request, &locks, name, &callback)
            else {
                return;
            };
            let _ = JsFuture::from(requested).await;
        }

        fn steal_lock(&self, name: Option<&str>) -> HeldLock {
            let locks_and_request = locks_object()
                .and_then(|locks| request_function(&locks).map(|request| (locks, request)));
            let (Some(name), Some((locks, request))) = (name, locks_and_request) else {
                return HeldLock::none();
            };

            let signal = StealSignal::new();
            // The promise the callback returns stays pending until `release`, so
            // the platform keeps the lock held for the whole span.
            let pending = std::rc::Rc::new(std::cell::RefCell::new(None::<Function>));
            let pending_for_promise = pending.clone();
            let promise = Promise::new(&mut move |resolve, _reject| {
                *pending_for_promise.borrow_mut() = Some(resolve);
            });
            let callback =
                Closure::once_into_js(move || promise.unchecked_ref::<JsValue>().clone());
            let Some(requested) = call_request_with_options(&request, &locks, name, &callback)
            else {
                return HeldLock::none();
            };

            let stolen = signal.clone();
            let requested_for_catch = requested.clone();
            spawn_local(async move {
                if let Err(error) = JsFuture::from(requested_for_catch).await {
                    // Only a steal, which arrives as an `AbortError`. A request
                    // can fail for reasons that are nothing to do with another
                    // holder, and reporting one of those as a steal would tell
                    // the caller its work was superseded when nothing had
                    // superseded it.
                    if is_abort_error(&error) {
                        stolen.abort();
                    }
                }
            });

            HeldLock::new(signal, move || {
                if let Some(resolve) = pending.borrow_mut().take() {
                    let _ = resolve.call0(&JsValue::NULL);
                }
            })
        }
    }

    fn call_request_with_options(
        request: &Function,
        locks: &JsValue,
        name: &str,
        callback: &JsValue,
    ) -> Option<Promise> {
        request
            .call3(
                locks,
                &JsValue::from_str(name),
                &options_with_steal(),
                callback,
            )
            .ok()?
            .dyn_into()
            .ok()
    }
}

#[cfg(feature = "wasm-js")]
pub use web_impl::WebLocks;

/// The lock manager this target uses.
#[cfg(feature = "wasm-js")]
pub fn default_lock_manager() -> Arc<dyn LockManager> {
    Arc::new(WebLocks)
}

/// The lock manager this target uses.
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
pub fn default_lock_manager() -> Arc<dyn LockManager> {
    Arc::new(InProcessLockManager::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::credentials::generate_identity;

    use crate::delegation_chain::DelegationChain;
    use crate::key::BaseKeyType;

    fn held() -> Held {
        Held {
            identity: generate_identity(BaseKeyType::Ed25519).expect("a key"),
            chain: DelegationChain::new(vec![], vec![1, 2, 3]),
        }
    }

    fn ok_work() -> MintWork {
        Box::new(|_stolen| Box::pin(async { Ok(held()) }))
    }

    #[cfg(feature = "native")]
    mod native {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        #[test]
        fn runs_the_work_and_returns_its_result() {
            let locks = InProcessLockManager::new();
            let result = futures::executor::block_on(locks.with_mint_lock(Some("mint"), ok_work()));
            assert!(result.is_ok());
        }

        #[test]
        fn runs_unserialised_where_no_other_tab_could_read_the_store() {
            let locks = InProcessLockManager::new();
            let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
            let first = order.clone();
            let second = order.clone();

            let (a, b) = futures::executor::block_on(async move {
                let one = locks.with_mint_lock(
                    None,
                    Box::new(move |_| {
                        Box::pin(async move {
                            first.lock().push("first in");
                            futures_timer::Delay::new(Duration::from_millis(10)).await;
                            first.lock().push("first out");
                            Ok(held())
                        })
                    }),
                );
                let two = locks.with_mint_lock(
                    None,
                    Box::new(move |_| {
                        Box::pin(async move {
                            second.lock().push("second in");
                            Ok(held())
                        })
                    }),
                );
                futures::join!(one, two)
            });
            assert!(a.is_ok() && b.is_ok());
            assert_eq!(*order.lock(), vec!["first in", "second in", "first out"]);
        }

        #[test]
        fn serialises_two_callers_on_the_same_name() {
            let locks = Arc::new(InProcessLockManager::new());
            let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
            let one = order.clone();
            let two = order.clone();
            let manager = locks.clone();

            futures::executor::block_on(async move {
                let a = manager.with_mint_lock(
                    Some("mint"),
                    Box::new(move |_| {
                        Box::pin(async move {
                            one.lock().push("first in");
                            futures_timer::Delay::new(Duration::from_millis(10)).await;
                            one.lock().push("first out");
                            Ok(held())
                        })
                    }),
                );
                let b = manager.with_mint_lock(
                    Some("mint"),
                    Box::new(move |_| {
                        Box::pin(async move {
                            two.lock().push("second in");
                            Ok(held())
                        })
                    }),
                );
                let (a, b) = futures::join!(a, b);
                assert!(a.is_ok() && b.is_ok());
            });

            assert_eq!(*order.lock(), vec!["first in", "first out", "second in"]);
        }

        #[test]
        fn frees_the_lock_when_the_work_fails() {
            let locks = InProcessLockManager::new();
            let failed = futures::executor::block_on(locks.with_mint_lock(
                Some("mint"),
                Box::new(|_| {
                    Box::pin(async { Err(SessionError::Retryable("mint failed".into())) })
                }),
            ));
            assert!(failed.is_err());

            let after = futures::executor::block_on(locks.with_mint_lock(Some("mint"), ok_work()));
            assert!(after.is_ok());
        }

        #[test]
        fn the_signal_does_not_fire_while_the_lock_is_held() {
            let locks = InProcessLockManager::new();
            let seen = Arc::new(AtomicBool::new(true));
            let seen_in_work = seen.clone();
            futures::executor::block_on(locks.with_mint_lock(
                Some("mint"),
                Box::new(move |stolen| {
                    Box::pin(async move {
                        seen_in_work.store(stolen.is_aborted(), Ordering::SeqCst);
                        Ok(held())
                    })
                }),
            ))
            .unwrap();
            assert!(!seen.load(Ordering::SeqCst));
        }

        #[test]
        fn a_steal_settles_the_caller_at_once() {
            let locks = Arc::new(InProcessLockManager::new());
            let manager = locks.clone();
            let started = Arc::new(AtomicUsize::new(0));
            let started_in_work = started.clone();

            futures::executor::block_on(async move {
                // Never released: a caller that waits for this work would wait
                // forever, which is exactly what the steal must not do.
                let (_release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
                let mint = manager.with_mint_lock(
                    Some("mint"),
                    Box::new(move |_stolen| {
                        Box::pin(async move {
                            started_in_work.fetch_add(1, Ordering::SeqCst);
                            let _ = release_rx.await;
                            Ok(held())
                        })
                    }),
                );

                let steal = manager.steal_mint_lock(Some("mint"));
                let (result, ()) = futures::join!(mint, steal);
                // The steal settles the caller at once; the work future is
                // dropped rather than left parked on a result that would be
                // discarded.
                assert!(result.is_err());
                assert_eq!(started.load(Ordering::SeqCst), 1);
            });
        }

        #[test]
        fn a_steal_fires_the_incumbent_signal() {
            let locks = Arc::new(InProcessLockManager::new());
            let manager = locks.clone();
            let stashed = Arc::new(Mutex::new(None::<StealSignal>));
            let stash = stashed.clone();

            futures::executor::block_on(async move {
                let (_release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
                let mint = manager.with_mint_lock(
                    Some("mint"),
                    Box::new(move |stolen| {
                        // The work is handed the signal at the moment it starts;
                        // keep it so the test can look at it after the steal.
                        *stash.lock() = Some(stolen.clone());
                        Box::pin(async move {
                            let _ = release_rx.await;
                            Ok(held())
                        })
                    }),
                );
                let steal = manager.steal_mint_lock(Some("mint"));
                let (result, ()) = futures::join!(mint, steal);
                assert!(result.is_err());
            });

            assert!(
                stashed
                    .lock()
                    .as_ref()
                    .expect("the work started")
                    .is_aborted()
            );
        }

        #[test]
        fn steal_does_not_wait_for_the_holder() {
            let locks = Arc::new(InProcessLockManager::new());
            let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
            let order_in_work = order.clone();
            let order_for_check = order.clone();
            let manager = locks.clone();

            futures::executor::block_on(async move {
                let (_release_tx, release_rx) = futures::channel::oneshot::channel::<()>();
                let mint = manager.with_mint_lock(
                    Some("mint"),
                    Box::new(move |_| {
                        Box::pin(async move {
                            order_in_work.lock().push("mint in");
                            let _ = release_rx.await;
                            order_in_work.lock().push("mint out");
                            Ok(held())
                        })
                    }),
                );
                let steal = async {
                    manager.steal_mint_lock(Some("mint")).await;
                    order.lock().push("stolen");
                };
                let (_, ()) = futures::join!(mint, steal);
            });
            // The caller did not wait for the mint; the in-flight work future is
            // dropped rather than allowed to finish (Rust cancels a future when
            // it is dropped, which is stronger than upstream discarding its
            // result).
            assert_eq!(*order_for_check.lock(), vec!["mint in", "stolen"]);
        }

        #[test]
        fn steals_nothing_where_there_is_no_lock_to_steal() {
            let locks = InProcessLockManager::new();
            futures::executor::block_on(locks.steal_mint_lock(Some("mint")));
            futures::executor::block_on(locks.steal_mint_lock(None));
        }

        #[test]
        fn a_held_lock_is_kept_until_released() {
            let locks = InProcessLockManager::new();
            let held = locks.steal_lock(Some("ceremony"));
            assert!(!held.stolen.is_aborted());
            held.release();
            assert!(!held.stolen.is_aborted());
            // Releasing twice does nothing.
            held.release();
        }

        #[test]
        fn a_held_lock_tells_the_incumbent_it_lost_it() {
            let locks = InProcessLockManager::new();
            let first = locks.steal_lock(Some("ceremony"));
            let second = locks.steal_lock(Some("ceremony"));
            assert!(first.stolen.is_aborted());
            assert!(!second.stolen.is_aborted());
            second.release();
        }

        #[test]
        fn a_held_lock_leaves_a_different_lock_alone() {
            let locks = InProcessLockManager::new();
            let channel = locks.steal_lock(Some("channel"));
            let _sign_in = locks.steal_lock(Some("sign-in"));
            assert!(!channel.stolen.is_aborted());
            channel.release();
        }

        #[test]
        fn dropping_a_held_lock_releases_it() {
            let locks = InProcessLockManager::new();
            {
                let held = locks.steal_lock(Some("ceremony"));
                assert!(!held.stolen.is_aborted());
            }
            // A second holder can take the lock now, and the first handle is
            // gone, so nothing is left holding it.
            let second = locks.steal_lock(Some("ceremony"));
            assert!(!second.stolen.is_aborted());
            second.release();
        }

        #[test]
        fn no_lock_fallback_runs_immediately_and_never_reports_a_steal() {
            let locks = NoopLockManager;
            let result = futures::executor::block_on(locks.with_mint_lock(Some("mint"), ok_work()));
            assert!(result.is_ok());
            let held = locks.steal_lock(Some("ceremony"));
            assert!(!held.stolen.is_aborted());
            held.release();
        }
    }

    #[test]
    fn a_signal_is_cloneable_and_idempotent() {
        let signal = StealSignal::new();
        let clone = signal.clone();
        assert!(!clone.is_aborted());
        signal.abort();
        assert!(clone.is_aborted());
        signal.abort();
        assert!(clone.is_aborted());
    }
}
