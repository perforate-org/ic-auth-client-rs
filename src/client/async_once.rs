//! Run one asynchronous initialisation once, however many callers ask for it.
//!
//! The client restores its session once per instance and every method that needs
//! the restored state (`ready`, `get_identity`, `sign_in`) waits on the same
//! work. Upstream memoises the promise; Rust cannot store a `!Send` future in a
//! `Send` client, so this type memoises the *outcome* instead: the work runs in
//! the first caller's future and later callers wait on a waker queue.
//!
//! A failure is not cached: the next caller retries, which is upstream's
//! behaviour (`auth-client.ts:1659-1675`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

enum State {
    /// Nobody has started the work.
    Idle,
    /// One caller is running the work; these wait for it.
    Running(Vec<Waker>),
    /// The work finished successfully.
    Done,
}

/// Where [`AsyncOnce::get_or_init`] is.
enum Acquired {
    /// The caller must run the work itself.
    Run,
    /// Somebody else is running it; wait to be woken.
    Wait,
    /// It has already finished.
    Done,
}

/// An initialisation that runs at most once.
pub struct AsyncOnce {
    state: Mutex<State>,
}

impl AsyncOnce {
    /// A cell that has not run yet.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::Idle),
        }
    }

    /// Whether the work has finished.
    pub fn is_done(&self) -> bool {
        matches!(
            *self.state.lock().expect("async once is not poisoned"),
            State::Done
        )
    }

    /// Runs `initialise` once and resolves once it has finished.
    ///
    /// A failed initialisation is forgotten, so a later caller runs it again.
    pub async fn get_or_init<F, Fut, E>(&self, initialise: F) -> Result<(), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        loop {
            match self.acquire() {
                Acquired::Done => return Ok(()),
                Acquired::Wait => {
                    // Wait for whoever is running it, then look again: either it
                    // succeeded, or it failed and reset the cell for us to run.
                    Wait { cell: self }.await;
                }
                Acquired::Run => {
                    let result = initialise().await;
                    self.finish(result.is_ok());
                    return result;
                }
            }
        }
    }

    /// Registers this caller's interest, deciding what it must do next.
    fn acquire(&self) -> Acquired {
        let mut state = self.state.lock().expect("async once is not poisoned");
        match &mut *state {
            State::Done => Acquired::Done,
            State::Running(waiters) => {
                // The waker is registered by the waiter itself once it polls;
                // the slot here only marks that somebody is waiting.
                waiters.push(Waker::noop().clone());
                Acquired::Wait
            }
            State::Idle => {
                *state = State::Running(Vec::new());
                Acquired::Run
            }
        }
    }

    /// Publishes the outcome, waking everyone who waited.
    fn finish(&self, succeeded: bool) {
        let waiters = {
            let mut state = self.state.lock().expect("async once is not poisoned");
            match std::mem::replace(
                &mut *state,
                if succeeded { State::Done } else { State::Idle },
            ) {
                State::Running(waiters) => waiters,
                other => {
                    *state = other;
                    Vec::new()
                }
            }
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

impl Default for AsyncOnce {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AsyncOnce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncOnce")
            .field("done", &self.is_done())
            .finish()
    }
}

/// Waits for the initialisation another caller is running.
struct Wait<'a> {
    cell: &'a AsyncOnce,
}

impl Future for Wait<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.cell.state.lock().expect("async once is not poisoned");
        match &mut *state {
            State::Done => Poll::Ready(()),
            State::Running(waiters) => {
                // Replace the marker pushed by `acquire` with this task's own
                // waker; duplicates are harmless (a waker may be woken twice).
                waiters.push(context.waker().clone());
                Poll::Pending
            }
            // The initiator failed and reset the cell: run it again ourselves by
            // reporting ready, so the caller's loop starts a new attempt.
            State::Idle => Poll::Ready(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn runs_once_and_reports_done() {
        let once = AsyncOnce::new();
        let runs = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let cell = &once;
            let counter = runs.clone();
            futures::executor::block_on(async move {
                cell.get_or_init(|| async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), String>(())
                })
                .await
                .unwrap();
            });
        }

        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(once.is_done());
    }

    #[test]
    fn failure_is_not_cached() {
        let once = AsyncOnce::new();
        let attempts = Arc::new(AtomicUsize::new(0));

        let first = futures::executor::block_on(async {
            let counter = attempts.clone();
            once.get_or_init(|| async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<(), String>("boom".to_string())
            })
            .await
        });
        assert_eq!(first.unwrap_err(), "boom");
        assert!(!once.is_done());

        let second: Result<(), String> = futures::executor::block_on(async {
            let counter = attempts.clone();
            once.get_or_init(|| async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok::<(), String>(())
            })
            .await
        });
        assert!(second.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_callers_share_one_run() {
        let once = Arc::new(AsyncOnce::new());
        let runs = Arc::new(AtomicUsize::new(0));

        let mut first = {
            let once = once.clone();
            let runs = runs.clone();
            Box::pin(async move {
                once.get_or_init(|| async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    // Yield once so the second caller has a chance to arrive.
                    futures::pending!();
                    Ok::<(), String>(())
                })
                .await
            })
        };
        let mut second = {
            let once = once.clone();
            let runs = runs.clone();
            Box::pin(async move {
                once.get_or_init(|| async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), String>(())
                })
                .await
            })
        };

        // Poll the first once (it is pending inside the initialiser), then poll
        // the second, which must wait rather than start a second run.
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(first.as_mut().poll(&mut context).is_pending());
        assert!(second.as_mut().poll(&mut context).is_pending());
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
