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
