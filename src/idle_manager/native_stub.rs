use super::{Context, IdleManager, IdleManagerOptions};
use parking_lot::Mutex;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

impl std::fmt::Debug for IdleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleManager")
            .field("idle_timeout", &self.idle_timeout)
            .field("callbacks", &{ self.context.lock().callbacks.lock().len() })
            .finish()
    }
}

impl Drop for IdleManager {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl IdleManager {
    pub(super) fn new_native_stub(options: Option<IdleManagerOptions>) -> Self {
        let callbacks = options
            .as_ref()
            .map(|options| options.on_idle.clone())
            .unwrap_or_else(|| Arc::new(Mutex::new(Vec::new())));

        let idle_timeout = options
            .as_ref()
            .and_then(|options| options.idle_timeout)
            .unwrap_or(Self::DEFAULT_IDLE_TIMEOUT);

        Self {
            context: Arc::new(Mutex::new(Context { callbacks })),
            idle_timeout,
            running: Arc::new(AtomicBool::new(true)),
            event_sender: Arc::new(Mutex::new(futures::channel::mpsc::channel(1).0)),
            _drop_sender: Arc::new(Mutex::new(futures::channel::oneshot::channel().0)),
        }
    }

    pub(super) fn exit_native_stub(&mut self) {
        if self.running.swap(false, Ordering::SeqCst) {
            for callback in self.context.lock().callbacks.lock().iter_mut() {
                (callback)();
            }
        }
    }

    pub(super) fn reset_timer_native_stub(&self) {
        // No-op on non-desktop native targets.
    }
}
