//! Cross-platform idle detection library for Rust applications.
//!
//! This library provides functionality to detect when a system becomes idle (no user interaction)
//! and execute callbacks accordingly. It supports both native platforms and WebAssembly targets.
//!
//! ## Features
//!
//! - Cross-platform idle detection (native and WASM)
//! - Configurable idle timeout duration
//! - Multiple callback registration support
//! - Automatic event listening for user interactions
//! - Scroll event debouncing (for web targets)
//!
//! ## Usage
//!
//! ```ignore
//! use ic_auth_client::idle_manager::{IdleManager, IdleManagerOptions};
//!
//! // Create an idle manager with default settings
//! let mut idle_manager = IdleManager::new(None);
//!
//! // Register a callback to execute when idle
//! idle_manager.register_callback(|| {
//!     println!("System is now idle!");
//! });
//!
//! // Or create with custom options
//! let options = IdleManagerOptions::builder()
//!     .idle_timeout(5 * 60 * 1000) // 5 minutes
//!     .capture_scroll(true)
//!     .on_idle(|| println!("Custom idle callback"))
//!     .build();
//!
//! let mut idle_manager = IdleManager::new(Some(options));
//!
//! // Reset the idle timer manually
//! idle_manager.reset_timer();
//!
//! // Clean up when done
//! idle_manager.exit();
//! ```
//!
//! ## Platform Support
//!
//! - **Native**: Uses system-level event detection
//! - **WebAssembly**: Uses browser event listeners for DOM interactions

use parking_lot::Mutex;
use std::sync::Arc;

#[cfg(all(
    feature = "native",
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]
mod native;
#[cfg(all(
    feature = "native",
    not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
))]
mod native_stub;
#[cfg(not(feature = "native"))]
mod wasm_js;

/// A callback function to be executed when the system becomes idle.
pub type Callback = Box<dyn FnMut() + Send>;

#[derive(Default)]
pub(crate) struct Context {
    pub(crate) callbacks: Arc<Mutex<Vec<Callback>>>,
}

/// IdleManager is a struct that manages idle state and events.
/// It provides functionality to register callbacks that are triggered when the system becomes idle,
/// and to reset the idle timer when certain events occur.
#[derive(Clone)]
pub struct IdleManager {
    context: Arc<Mutex<Context>>,
    idle_timeout: u32,
    #[cfg(not(feature = "native"))]
    js_sender: Arc<Mutex<futures::channel::mpsc::Sender<wasm_js::JsMessage>>>,
    #[cfg(feature = "native")]
    running: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature = "native")]
    event_sender: Arc<Mutex<futures::channel::mpsc::Sender<()>>>,
    #[cfg(feature = "native")]
    _drop_sender: Arc<Mutex<futures::channel::oneshot::Sender<()>>>,
}

impl IdleManager {
    /// Default idle timeout duration in milliseconds (10 minutes).
    pub const DEFAULT_IDLE_TIMEOUT: u32 = 10 * 60 * 1000;
    /// Default scroll debounce duration in milliseconds.
    #[cfg(feature = "wasm-js")]
    pub const DEFAULT_SCROLL_DEBOUNCE: u32 = 100;

    /// Constructs a new [`IdleManager`] with the given options.
    pub fn new(options: Option<IdleManagerOptions>) -> Self {
        #[cfg(all(
            feature = "native",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        {
            Self::new_native(options)
        }

        #[cfg(all(
            feature = "native",
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            Self::new_native_stub(options)
        }

        #[cfg(not(feature = "native"))]
        {
            Self::new_wasm_js(options)
        }
    }

    /// Exits the idle state, cancels any timeouts, removes event listeners, and executes all registered callbacks.
    pub fn exit(&mut self) {
        #[cfg(all(
            feature = "native",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        {
            self.exit_native();
        }

        #[cfg(all(
            feature = "native",
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            self.exit_native_stub();
        }

        #[cfg(not(feature = "native"))]
        {
            self.exit_wasm_js();
        }
    }

    /// Resets the idle timer, cancelling any existing timeout and setting a new one.
    pub fn reset_timer(&self) {
        #[cfg(all(
            feature = "native",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        {
            self.reset_timer_native();
        }

        #[cfg(all(
            feature = "native",
            not(any(target_os = "macos", target_os = "linux", target_os = "windows"))
        ))]
        {
            self.reset_timer_native_stub();
        }

        #[cfg(not(feature = "native"))]
        {
            self.reset_timer_wasm_js();
        }
    }

    /// Registers a callback to be executed when the system becomes idle.
    pub fn register_callback<F>(&self, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        self.context
            .lock()
            .callbacks
            .lock()
            .push(Box::new(callback));
    }
}

/// IdleManagerOptions is a struct that contains options for configuring an [`IdleManager`].
#[derive(Default, Clone, bon::Builder)]
pub struct IdleManagerOptions {
    /// Callback functions to be executed when the system becomes idle.
    #[builder(field)]
    pub on_idle: Arc<Mutex<Vec<Callback>>>,
    /// The duration of inactivity after which the system is considered idle in milliseconds.
    pub idle_timeout: Option<u32>,
    /// A flag indicating whether to capture scroll events.
    pub capture_scroll: Option<bool>,
    /// A delay for debouncing scroll events in milliseconds.
    pub scroll_debounce: Option<u32>,
}

impl std::fmt::Debug for IdleManagerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let callback_count = self.on_idle.lock().len();
        f.debug_struct("IdleManagerOptions")
            .field("on_idle", &format!("{} callbacks", callback_count))
            .field("idle_timeout", &self.idle_timeout)
            .field("capture_scroll", &self.capture_scroll)
            .field("scroll_debounce", &self.scroll_debounce)
            .finish()
    }
}

#[allow(dead_code)]
impl<S: idle_manager_options_builder::State> IdleManagerOptionsBuilder<S> {
    /// Sets a callback to be executed when the system becomes idle.
    ///
    /// It is possible to set multiple callbacks.
    pub fn on_idle(self, value: fn()) -> Self {
        self.on_idle
            .lock()
            .push(Box::new(value) as Box<dyn FnMut() + Send>);
        self
    }
}
