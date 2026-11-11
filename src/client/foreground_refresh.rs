//! Browser hints that somebody is here.
//!
//! Port of upstream `src/client/foreground-refresh.ts`. A backgrounded tab has
//! its timers throttled, so its delegation can lapse while nobody is looking and
//! the first click after coming back waits for a mint; returning to the tab is
//! early enough to hide that.
//!
//! Both watchers hook the same claim --- somebody is here --- and return an
//! unhook, or nothing where there is no DOM. Whether a mint is actually due is
//! not decided here: that is the rotating identity's pre-mint threshold, which
//! is what keeps a resting hand from costing more than one mint per refresh
//! interval. The watchers themselves neither debounce nor throttle, matching
//! upstream.
//!
//! # Where the DOM is not
//!
//! On `native` there is no DOM to hook and both return `None`; a host
//! application calls [`SessionIdentity::refresh`](crate::client::session::SessionIdentity::refresh)
//! on its own lifecycle events (window focus, app resume) instead. A partial DOM
//! polyfill is checked API by API, because throwing there would contradict the
//! promise that this hooks nothing where there is no DOM.

use std::sync::Arc;

use crate::client::platform::{Listener, Unsubscribe};

/// A callback fired when the page comes back to the foreground.
pub type ForegroundListener = Arc<dyn Listener>;

/// Unhooks a watcher.
pub type Unwatch = Box<dyn Unsubscribe>;

/// Watches for the page becoming visible again.
///
/// Port of upstream `watchForeground` (`foreground-refresh.ts:17`): a
/// `visibilitychange` that leaves the page visible, a window `focus` (which
/// catches two visible windows side by side, where moving between them is not a
/// visibility change), and `pageshow` (a page restored from the back-forward
/// cache resumes with timers that never ran).
///
/// On a target with no DOM there is nothing to watch and this returns `None`.
pub fn watch_foreground(listener: ForegroundListener) -> Option<Unwatch> {
    #[cfg(feature = "wasm-js")]
    {
        wasm::watch_foreground(listener)
    }
    #[cfg(all(not(feature = "wasm-js"), feature = "native"))]
    {
        let _ = listener;
        None
    }
}

/// Watches for the user using the page: a pointer, a key, a touch.
///
/// Port of upstream `watchActivity` (`foreground-refresh.ts:72`). `pointerdown`
/// covers a mouse, a finger and a pen in one, which is the only press event a
/// phone reliably produces; the rest are the list the retired idle timer
/// listened to, put to the opposite use.
///
/// On a target with no DOM there is nothing to watch and this returns `None`.
pub fn watch_activity(listener: ForegroundListener) -> Option<Unwatch> {
    #[cfg(feature = "wasm-js")]
    {
        wasm::watch_activity(listener)
    }
    #[cfg(all(not(feature = "wasm-js"), feature = "native"))]
    {
        let _ = listener;
        None
    }
}

#[cfg(feature = "wasm-js")]
mod wasm {
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen::JsValue;
    use wasm_bindgen::closure::Closure;
    use web_sys::js_sys::{Function, Object, Reflect};

    use super::{ForegroundListener, Unwatch};
    use crate::client::platform::Unsubscribe;

    /// The list upstream listens to, verbatim.
    const ACTIVITY_EVENTS: [&str; 6] = [
        "pointerdown",
        "mousedown",
        "mousemove",
        "keydown",
        "touchstart",
        "wheel",
    ];

    /// One registered listener, and what is needed to remove it.
    struct Hook {
        target: JsValue,
        event: String,
        callback: Function,
        // Kept alive for as long as the hook is: dropping the closure would
        // leave the JS function pointing at freed Rust state.
        _closure: Closure<dyn FnMut(JsValue)>,
    }

    /// The unhook: removes every listener it registered.
    struct UnwatchAll {
        hooks: Vec<Hook>,
    }

    impl Unsubscribe for UnwatchAll {
        fn call_once(self: Box<Self>) {
            for hook in self.hooks {
                let Some(remove) = function_of(&hook.target, "removeEventListener") else {
                    continue;
                };
                let _ = remove.call3(
                    &hook.target,
                    &JsValue::from_str(&hook.event),
                    hook.callback.as_ref(),
                    &JsValue::UNDEFINED,
                );
            }
        }
    }

    fn function_of(target: &JsValue, name: &str) -> Option<Function> {
        Reflect::get(target, &JsValue::from_str(name))
            .ok()?
            .dyn_into()
            .ok()
    }

    fn is_visible(document: &JsValue) -> bool {
        Reflect::get(document, &JsValue::from_str("visibilityState"))
            .ok()
            .and_then(|state| state.as_string())
            .is_some_and(|state| state == "visible")
    }

    fn passive_options() -> JsValue {
        let options = Object::new();
        let _ = Reflect::set(&options, &JsValue::from_str("passive"), &JsValue::TRUE);
        options.unchecked_ref::<JsValue>().clone()
    }

    fn add_listener<F>(
        target: &JsValue,
        event: &str,
        callback: F,
        options: &JsValue,
    ) -> Option<Hook>
    where
        F: FnMut(JsValue) + 'static,
    {
        let add = function_of(target, "addEventListener")?;
        let closure: Closure<dyn FnMut(JsValue)> =
            Closure::wrap(Box::new(callback) as Box<dyn FnMut(JsValue)>);
        let function: Function = closure.as_ref().unchecked_ref::<Function>().clone();
        add.call3(
            target,
            &JsValue::from_str(event),
            function.as_ref(),
            options,
        )
        .ok()?;
        Some(Hook {
            target: target.clone(),
            event: event.to_string(),
            callback: function,
            _closure: closure,
        })
    }

    /// The document and window as raw values, or nothing where either is
    /// missing.
    fn dom() -> Option<(JsValue, JsValue)> {
        let window = web_sys::window()?;
        let document = window.document()?;
        Some((
            document.unchecked_ref::<JsValue>().clone(),
            window.unchecked_ref::<JsValue>().clone(),
        ))
    }

    pub(super) fn watch_foreground(listener: ForegroundListener) -> Option<Unwatch> {
        let (document, window) = dom()?;
        // Every API this hooks, checked one at a time: a partial DOM polyfill can
        // define `document` without the event methods.
        if function_of(&document, "addEventListener").is_none()
            || function_of(&window, "addEventListener").is_none()
        {
            return None;
        }

        let mut hooks = Vec::new();

        let document_for_check = document.clone();
        let on_foreground = listener.clone();
        hooks.push(add_listener(
            &document,
            "visibilitychange",
            move |_| {
                if is_visible(&document_for_check) {
                    on_foreground.call();
                }
            },
            &JsValue::UNDEFINED,
        )?);

        let on_focus = listener.clone();
        hooks.push(add_listener(
            &window,
            "focus",
            move |_| on_focus.call(),
            &JsValue::UNDEFINED,
        )?);

        hooks.push(add_listener(
            &window,
            "pageshow",
            move |_| listener.call(),
            &JsValue::UNDEFINED,
        )?);

        Some(Box::new(UnwatchAll { hooks }))
    }

    pub(super) fn watch_activity(listener: ForegroundListener) -> Option<Unwatch> {
        let (document, _window) = dom()?;
        if function_of(&document, "addEventListener").is_none() {
            return None;
        }

        // Passive: these never call `preventDefault`, and saying so keeps a
        // listener on `mousemove` and `wheel` off the path that decides whether a
        // scroll may start.
        let options = passive_options();
        let mut hooks = Vec::new();
        for event in ACTIVITY_EVENTS {
            let listener = listener.clone();
            hooks.push(add_listener(
                &document,
                event,
                move |_| listener.call(),
                &options,
            )?);
        }
        Some(Box::new(UnwatchAll { hooks }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener() -> ForegroundListener {
        Arc::new(|| {})
    }

    #[cfg(all(not(feature = "wasm-js"), feature = "native"))]
    #[test]
    fn native_hooks_nothing() {
        // There is no DOM to hook; a host application calls `refresh()` on its
        // own lifecycle events instead.
        assert!(watch_foreground(listener()).is_none());
        assert!(watch_activity(listener()).is_none());
    }

    #[cfg(feature = "wasm-js")]
    #[test]
    fn wasm_does_not_panic_without_a_document() {
        // wasm-bindgen tests run in Node here, where there is no `window`; the
        // watcher must decline rather than throw.
        assert!(watch_foreground(listener()).is_none());
        assert!(watch_activity(listener()).is_none());
    }
}
