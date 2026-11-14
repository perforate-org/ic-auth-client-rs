//! Platform capability bounds used by the client's trait objects.
//!
//! The wasm build hands trait objects to JavaScript and single-threaded
//! Web APIs, so a store or a channel legitimately holds `JsValue`s and is
//! neither `Send` nor `Sync`. The native build exports the client through
//! UniFFI, which requires `Send + Sync`.
//!
//! Rather than duplicate every trait definition per target, the traits take
//! this one supertrait: empty on wasm, `Send + Sync` on native.

/// Marks a type that this target's client may hand to a trait object.
#[cfg(feature = "native")]
pub trait PlatformBounds: Send + Sync {}

/// Marks a type that this target's client may hand to a trait object.
#[cfg(feature = "native")]
impl<T: Send + Sync + ?Sized> PlatformBounds for T {}

/// Marks a type that this target's client may hand to a trait object.
#[cfg(not(feature = "native"))]
pub trait PlatformBounds {}

/// Marks a type that this target's client may hand to a trait object.
#[cfg(not(feature = "native"))]
impl<T: ?Sized> PlatformBounds for T {}

/// A callback the client can hold and call.
///
/// `dyn Fn() + PlatformBounds` is not a legal trait object (additional traits
/// on a trait object must be auto traits), so callbacks are boxed behind this
/// one-method trait instead. Any `Fn() + PlatformBounds` closure implements it
/// through the blanket impl below.
pub trait Listener: PlatformBounds {
    /// Calls the callback.
    fn call(&self);
}

impl<F: Fn() + PlatformBounds> Listener for F {
    fn call(&self) {
        (self)();
    }
}

/// An unhook the client can hold and run once.
pub trait Unsubscribe: PlatformBounds {
    /// Runs the unhook.
    fn call_once(self: Box<Self>);
}

impl<F: FnOnce() + PlatformBounds> Unsubscribe for F {
    fn call_once(self: Box<Self>) {
        self();
    }
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A future to run in the background, built where it will be polled.
///
/// The storage traits' futures are not `Send` on native (their stores are
/// synchronous underneath), so a future cannot be moved between threads: the
/// executor runs a task that **builds** it on the executor's own thread. A
/// native mint also performs canister calls, which need that thread's Tokio
/// reactor, and this is the seam that provides one.
pub trait ExecutorTask: PlatformBounds {
    /// Builds the future, on the thread that will poll it.
    fn build(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()>>>;
}

impl<F> ExecutorTask for F
where
    F: FnOnce() -> Pin<Box<dyn Future<Output = ()>>> + PlatformBounds,
{
    fn build(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()>>> {
        (self)()
    }
}

/// Runs background work: a rotation's mint, the bookkeeping after a session
/// turns out gone.
pub trait Executor: PlatformBounds {
    /// Runs `task` without waiting for it.
    fn spawn(&self, task: Box<dyn ExecutorTask>);
}

/// Runs `factory` on the platform's executor.
pub fn spawn(
    factory: impl FnOnce() -> Pin<Box<dyn Future<Output = ()>>> + PlatformBounds + 'static,
) {
    default_executor().spawn(Box::new(factory));
}

/// The executor this target uses unless one is injected.
#[cfg(feature = "wasm-js")]
pub fn default_executor() -> Arc<dyn Executor> {
    Arc::new(WasmExecutor)
}

/// The executor this target uses unless one is injected.
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
pub fn default_executor() -> Arc<dyn Executor> {
    Arc::new(native_executor::NativeExecutor)
}

#[cfg(feature = "wasm-js")]
mod wasm_executor {
    use super::*;

    /// Runs on the browser's task queue, like `spawn_local`.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WasmExecutor;

    impl Executor for WasmExecutor {
        fn spawn(&self, task: Box<dyn ExecutorTask>) {
            wasm_bindgen_futures::spawn_local(task.build());
        }
    }
}

#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
mod native_executor {
    use super::*;
    use std::sync::{Mutex, OnceLock, mpsc};

    type Task = Box<dyn ExecutorTask>;

    /// One worker per process, because a runtime is not free and a rotation is
    /// the only thing that needs one.
    static WORKER: OnceLock<Mutex<mpsc::Sender<Task>>> = OnceLock::new();

    fn worker() -> &'static Mutex<mpsc::Sender<Task>> {
        WORKER.get_or_init(|| {
            let (sender, receiver) = mpsc::channel::<Task>();
            std::thread::Builder::new()
                .name("ic-auth-client-executor".to_string())
                .spawn(move || {
                    // `enable_all` gives the runtime the reactor a mint's HTTP
                    // calls need; `LocalSet` lets the `!Send` futures run on
                    // this one thread.
                    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    else {
                        return;
                    };
                    let local = tokio::task::LocalSet::new();
                    while let Ok(task) = receiver.recv() {
                        local.block_on(&runtime, task.build());
                    }
                })
                .expect("failed to spawn the auth client executor thread");
            Mutex::new(sender)
        })
    }

    /// Runs tasks on one dedicated thread: there is no ambient executor a
    /// library can spawn onto, and a refresh nobody awaits must not hold the
    /// process open.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct NativeExecutor;

    impl Executor for NativeExecutor {
        fn spawn(&self, task: Task) {
            let sender = match worker().lock() {
                Ok(sender) => sender,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Err(mpsc::SendError(task)) = sender.send(task) {
                // The worker only dies if it panicked: do the work here rather
                // than drop it, even though there is no reactor on this thread.
                drop(sender);
                futures::executor::block_on(task.build());
            }
        }
    }
}

#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
pub use native_executor::NativeExecutor;
#[cfg(feature = "wasm-js")]
pub use wasm_executor::WasmExecutor;

#[cfg(test)]
mod tests {
    #[cfg(all(not(feature = "wasm-js"), feature = "native"))]
    #[test]
    fn the_native_executor_runs_futures_on_a_reactor() {
        use super::spawn;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        let done = Arc::new(AtomicBool::new(false));
        let flag = done.clone();
        spawn(move || {
            Box::pin(async move {
                // `sleep` only resolves inside a Tokio runtime, so this also
                // proves the executor provides the reactor a mint's canister
                // calls need.
                tokio::time::sleep(Duration::from_millis(10)).await;
                flag.store(true, Ordering::SeqCst);
            })
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "the executor did not run the task"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
