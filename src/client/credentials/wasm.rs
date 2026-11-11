//! The small JavaScript surface the browser stores share.
//!
//! Upstream reaches for `globalThis`, `localStorage`, `document`, `crypto`,
//! `BroadcastChannel` and Web Locks directly. A Rust port could bind each of
//! those through `web-sys`, but the stores run in a page, a worker and a
//! service worker, and a typed `Window` binding is wrong in two of the three.
//! So the properties are read off `globalThis` by name: whatever is there is
//! what this context has, and a missing one is a capability this context does
//! not have rather than a compile-time assumption.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::JsFuture;
use web_sys::js_sys::{Array, Function, Object, Reflect};

/// `globalThis`.
pub(crate) fn global() -> JsValue {
    web_sys::js_sys::global().into()
}

/// A property of a JS object, `None` where it is absent or null.
pub(crate) fn get_prop(target: &JsValue, name: &str) -> Option<JsValue> {
    Reflect::get(target, &JsValue::from_str(name))
        .ok()
        .filter(|value| !value.is_undefined() && !value.is_null())
}

/// A string property of a JS object.
pub(crate) fn get_string(target: &JsValue, name: &str) -> Option<String> {
    get_prop(target, name).and_then(|value| value.as_string())
}

/// A property of a JS object, including one that is `null` or `undefined`.
///
/// Event payloads use `null` to mean something (`storage` reports a cleared
/// store as `key === null`), so the filtering [`get_prop`] does would lose it.
pub(crate) fn get_property(target: &JsValue, name: &str) -> Option<JsValue> {
    Reflect::get(target, &JsValue::from_str(name)).ok()
}

/// Sets a property of a JS object.
pub(crate) fn set_prop(target: &JsValue, name: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(target, &JsValue::from_str(name), value).map(|_| ())
}

/// Calls a method on a JS object by name.
pub(crate) fn call_method(
    target: &JsValue,
    name: &str,
    args: &[JsValue],
) -> Result<JsValue, JsValue> {
    let method = get_prop(target, name)
        .ok_or_else(|| JsValue::from_str(&format!("{name} is not available")))?;
    let method: Function = method
        .dyn_into()
        .map_err(|_| JsValue::from_str(&format!("{name} is not a function")))?;
    let array = array(args.to_vec());
    method.apply(target, &array)
}

/// `globalThis.localStorage`, where this context has one.
///
/// Reading the property itself throws where the browser blocks storage for the
/// page, which is why upstream wraps the read (`local-state-storage.ts:17-24`).
pub(crate) fn local_storage() -> Option<web_sys::Storage> {
    get_prop(&global(), "localStorage")?.dyn_into().ok()
}

/// Whether this context has `localStorage`.
pub(crate) fn has_local_storage() -> bool {
    local_storage().is_some()
}

/// `globalThis.document`, where this context has one.
pub(crate) fn document() -> Option<JsValue> {
    get_prop(&global(), "document")
}

/// `globalThis.location`, where this context has one.
pub(crate) fn location() -> Option<JsValue> {
    get_prop(&global(), "location")
}

/// `globalThis.location.hostname`.
pub(crate) fn location_hostname() -> Option<String> {
    get_string(&location()?, "hostname")
}

/// `globalThis.location.protocol`.
pub(crate) fn location_protocol() -> Option<String> {
    get_string(&location()?, "protocol")
}

/// `globalThis.crypto`.
pub(crate) fn crypto() -> Option<JsValue> {
    get_prop(&global(), "crypto")
}

/// `globalThis.crypto.subtle`.
pub(crate) fn subtle() -> Option<web_sys::SubtleCrypto> {
    get_prop(&crypto()?, "subtle")?.dyn_into().ok()
}

/// `crypto.randomUUID()`, where this browser has it.
pub(crate) fn random_uuid() -> Option<String> {
    call_method(&crypto()?, "randomUUID", &[])
        .ok()
        .and_then(|value| value.as_string())
}

/// A `BroadcastChannel` on `name`, where this context has the API.
pub(crate) fn broadcast_channel(name: &str) -> Option<web_sys::BroadcastChannel> {
    web_sys::BroadcastChannel::new(name).ok()
}

/// `globalThis` as an event target.
pub(crate) fn event_target() -> Option<web_sys::EventTarget> {
    web_sys::js_sys::global().dyn_into().ok()
}

/// Registers an event listener on a JS object.
pub(crate) fn add_event_listener(target: &JsValue, event: &str, listener: &Function) {
    let _ = call_method(
        target,
        "addEventListener",
        &[JsValue::from_str(event), listener.clone().into()],
    );
}

/// Removes an event listener registered with [`add_event_listener`].
pub(crate) fn remove_event_listener(target: &JsValue, event: &str, listener: &Function) {
    let _ = call_method(
        target,
        "removeEventListener",
        &[JsValue::from_str(event), listener.clone().into()],
    );
}

/// Awaits a JS promise.
pub(crate) async fn await_promise(promise: JsValue) -> Result<JsValue, JsValue> {
    let promise: web_sys::js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| JsValue::from_str("not a promise"))?;
    JsFuture::from(promise).await
}

/// A new plain JS object.
pub(crate) fn object() -> Object {
    Object::new()
}

/// A JS array from a list of values.
pub(crate) fn array(values: Vec<JsValue>) -> Array {
    let array = Array::new();
    for value in values {
        array.push(&value);
    }
    array
}

/// A JS value as a string, for error reporting.
pub(crate) fn display(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            web_sys::js_sys::JSON::stringify(value)
                .ok()
                .and_then(|v| v.as_string())
        })
        .unwrap_or_else(|| "unknown JS value".to_string())
}

/// A completion signal several futures can wait on.
///
/// Upstream chains promises for the same reason: incoming replication work has
/// to land in arrival order, and a read must not answer before the work already
/// in hand has landed (`shared-memory-credential-storage.ts:97-101`,
/// `local-state-storage.ts:50-59`). A `SharedDone` is a promise a Rust future
/// can hand out clones of and complete once.
#[derive(Clone)]
pub(crate) struct SharedDone {
    state: Rc<RefCell<DoneState>>,
}

enum DoneState {
    Pending(Vec<Waker>),
    Done,
}

impl SharedDone {
    /// A signal not yet completed.
    pub(crate) fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(DoneState::Pending(Vec::new()))),
        }
    }

    /// Completes the signal, waking everything waiting on it.
    pub(crate) fn complete(&self) {
        let wakers = {
            let mut state = self.state.borrow_mut();
            match &mut *state {
                DoneState::Done => return,
                DoneState::Pending(wakers) => {
                    let wakers = std::mem::take(wakers);
                    *state = DoneState::Done;
                    wakers
                }
            }
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// Whether the signal has already completed.
    pub(crate) fn is_done(&self) -> bool {
        matches!(&*self.state.borrow(), DoneState::Done)
    }
}

impl Future for SharedDone {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.borrow_mut();
        match &mut *state {
            DoneState::Done => Poll::Ready(()),
            DoneState::Pending(wakers) => {
                if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                    wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

/// An event listener that unregisters itself when dropped.
///
/// The closure must outlive the registration: a `Closure` that is dropped while
/// the event target still holds the function leaves a callback that throws when
/// the browser next fires the event.
pub(crate) struct JsListener {
    target: JsValue,
    event: String,
    closure: Closure<dyn FnMut(JsValue)>,
}

impl JsListener {
    /// Registers `callback` for `event` on `target`.
    pub(crate) fn new(
        target: JsValue,
        event: &str,
        callback: impl FnMut(JsValue) + 'static,
    ) -> Self {
        let closure = Closure::<dyn FnMut(JsValue)>::new(callback);
        let function: &Function = closure.as_ref().unchecked_ref();
        add_event_listener(&target, event, function);
        Self {
            target,
            event: event.to_string(),
            closure,
        }
    }
}

impl Drop for JsListener {
    fn drop(&mut self) {
        let function: &Function = self.closure.as_ref().unchecked_ref();
        remove_event_listener(&self.target, &self.event, function);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_done_is_ready_once_completed() {
        let done = SharedDone::new();
        assert!(!done.is_done());
        done.complete();
        assert!(done.is_done());
        // A second completion is harmless.
        done.complete();
        assert!(done.is_done());
    }
}
