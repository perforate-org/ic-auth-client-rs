//! Sign-in state in a cookie, shared across sibling subdomains (wasm).
//!
//! Port of upstream `state/cookie-state-storage.ts`. A cookie is the only thing
//! that crosses between origins, which is what lets one sign-out end them all:
//! the record is the domain's rather than this origin's. It carries no chain and
//! no key, so a sibling acting on it asks the identity provider to re-issue
//! rather than treating it as proof.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use wasm_bindgen::JsValue;

use crate::client::credentials::wasm::{self, JsListener};
use crate::client::error::AuthClientError;
use crate::client::state::local::LocalStateStorage;
use crate::client::state::{
    COOKIE_PROBE_NAME, READ_ONLY_MESSAGE, RECORD_MAX_AGE_SECONDS, SessionState, StateListener,
    StateStorage, StoredSessionState, Subscription, cookie_attributes, decode_cookie_record,
    encode_cookie_record, encode_uri_component, is_loopback_host, read_cookie_value, state_of,
};

/// The state of a sign-in, in a cookie, so every sibling of a domain shares it.
///
/// Port of upstream `CookieStateStorage` (`cookie-state-storage.ts:59-304`).
pub struct CookieStateStorage {
    inner: Rc<CookieInner>,
}

struct CookieInner {
    domain: String,
    /// The attributes every cookie this store writes carries.
    attributes: String,
    /// The per-origin claim on the sign-in the cookie names.
    local: LocalStateStorage,
    subscribers: RefCell<HashMap<String, Vec<(u64, Rc<dyn Fn()>)>>>,
    next_id: Cell<u64>,
}

impl std::fmt::Debug for CookieStateStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieStateStorage")
            .field("domain", &self.inner.domain)
            .field("attributes", &self.inner.attributes)
            .finish_non_exhaustive()
    }
}

impl CookieStateStorage {
    /// A cookie store scoped to `domain`, e.g. `example.com` so `a.example.com`
    /// and `b.example.com` share one sign-in.
    ///
    /// The domain has to be this host or one above it, and the browser has to
    /// accept a cookie scoped to it: the constructor refuses otherwise rather
    /// than let the sign-in appear over the moment it is written
    /// (`cookie-state-storage.ts:90-150`).
    pub fn new(domain: impl Into<String>) -> Result<Self, AuthClientError> {
        let domain = domain.into();
        let hostname = wasm::location_hostname();
        let loopback =
            is_loopback_host(&domain) && hostname.as_deref().is_none_or(is_loopback_host);

        if !loopback {
            if let Some(hostname) = hostname.as_deref() {
                if hostname != domain && !hostname.ends_with(&format!(".{domain}")) {
                    return Err(AuthClientError::InvalidOptions(format!(
                        "A cookie cannot be scoped to '{domain}' from '{hostname}': the domain has to be this host or one above it"
                    )));
                }
            }
        }

        let secure = wasm::location_protocol().as_deref() == Some("https:");
        let attributes = cookie_attributes(&domain, loopback, secure);

        // The check above cannot see a public suffix: 'app.co.uk' ends with
        // '.co.uk', so `domain: 'co.uk'` passes it and the browser then refuses
        // the cookie. No API exposes the list, so the only test that agrees
        // with the browser is to write one and read it back — which catches
        // cookies being switched off at the same time.
        if wasm::document().is_some() {
            let hostname = hostname.unwrap_or_default();
            let accepted = {
                write_cookie(&attributes, COOKIE_PROBE_NAME, "1", None);
                document_cookie_header()
                    .map(|header| read_cookie_value(&header, COOKIE_PROBE_NAME).is_some())
                    .unwrap_or(false)
            };
            // Always clean up: no Max-Age on the write, so even a cleanup that
            // fails dies with the browser.
            write_cookie(&attributes, COOKIE_PROBE_NAME, "", Some(0));
            if !accepted {
                return Err(AuthClientError::InvalidOptions(format!(
                    "A cookie scoped to '{domain}' cannot be written from '{hostname}': the browser refused it. The domain may be a public suffix, or cookies may be disabled."
                )));
            }
        }

        Ok(Self {
            inner: Rc::new(CookieInner {
                domain,
                attributes,
                local: LocalStateStorage::new(),
                subscribers: RefCell::new(HashMap::new()),
                next_id: Cell::new(0),
            }),
        })
    }

    /// The domain this store is scoped to.
    pub fn domain(&self) -> &str {
        &self.inner.domain
    }

    /// The attributes every cookie this store writes carries.
    pub fn attributes(&self) -> &str {
        &self.inner.attributes
    }
}

impl CookieInner {
    fn register(&self, key: &str, check: Rc<dyn Fn()>) -> u64 {
        let id = {
            let next = self.next_id.get();
            self.next_id.set(next + 1);
            next
        };
        self.subscribers
            .borrow_mut()
            .entry(key.to_string())
            .or_default()
            .push((id, check));
        id
    }

    fn unregister(&self, key: &str, id: u64) {
        if let Some(checks) = self.subscribers.borrow_mut().get_mut(key) {
            checks.retain(|(check_id, _)| *check_id != id);
        }
    }

    fn fire(&self, key: &str) {
        let checks: Vec<Rc<dyn Fn()>> = self
            .subscribers
            .borrow()
            .get(key)
            .map(|checks| checks.iter().map(|(_, check)| check.clone()).collect())
            .unwrap_or_default();
        for check in checks {
            check();
        }
    }
}

impl StateStorage for CookieStateStorage {
    fn get(&self, key: &str) -> Option<SessionState> {
        read_state(&self.inner.local, key)
    }

    fn set(&self, key: &str, state: StoredSessionState) {
        assert!(!self.is_read_only(), "{READ_ONLY_MESSAGE}");
        // The local record first, so nothing reads the cookie as held before it
        // is.
        self.inner.local.set(key, state);
        write_cookie(
            &self.inner.attributes,
            key,
            &encode_cookie_record(&state),
            Some(RECORD_MAX_AGE_SECONDS),
        );
        self.inner.fire(key);
    }

    fn remove(&self, key: &str) {
        assert!(!self.is_read_only(), "{READ_ONLY_MESSAGE}");
        self.inner.local.remove(key);
        write_cookie(&self.inner.attributes, key, "", Some(0));
        self.inner.fire(key);
    }

    /// Drops this origin's claim on the sign-in, leaving the cookie for the
    /// siblings.
    ///
    /// An origin whose chain turns out to be dead cannot tell a revoked session
    /// from one a sibling replaced by signing in, and in the second case that
    /// sibling wrote this cookie a moment ago. So the record stands and this
    /// origin reads it as not held, which is what sends it to acquire its own
    /// (`cookie-state-storage.ts:196-207`).
    fn discard(&self, key: &str) {
        assert!(!self.is_read_only(), "{READ_ONLY_MESSAGE}");
        self.inner.local.remove(key);
        self.inner.fire(key);
    }

    fn resumable(&self) -> bool {
        // This is the store whose record reaches past one origin, so it is the
        // store whose siblings arrive holding no credential and needing the
        // provider to have kept the session (`cookie-state-storage.ts:69`).
        true
    }

    fn subscribe(&self, key: &str, listener: StateListener) -> Subscription {
        let inner = self.inner.clone();
        let key_owned = key.to_string();
        let local = inner.local.clone();
        let local_for_check = local.clone();
        let key_for_check = key_owned.clone();
        let last: Rc<RefCell<String>> =
            Rc::new(RefCell::new(state_of(read_state(&local, key).as_ref())));
        let check: Rc<dyn Fn()> = Rc::new(move || {
            let now = state_of(read_state(&local_for_check, &key_for_check).as_ref());
            let changed = {
                let mut last = last.borrow_mut();
                if *last != now {
                    *last = now;
                    true
                } else {
                    false
                }
            };
            if changed {
                crate::client::platform::Listener::call(listener.as_ref());
            }
        });
        let id = inner.register(&key_owned, check.clone());

        // A worker hears of a change through this origin's claim.
        if inner.local.is_read_only() {
            let bridge: StateListener = std::sync::Arc::new({
                let check = check.clone();
                move || check()
            });
            let local_subscription = inner.local.subscribe(key, bridge);
            let key_for_unsubscribe = key_owned;
            let unsubscribe: Box<dyn crate::client::platform::Unsubscribe> = Box::new(move || {
                inner.unregister(&key_for_unsubscribe, id);
                drop(local_subscription);
            });
            return Subscription::new(unsubscribe);
        }

        let mut listeners: Vec<JsListener> = Vec::new();

        // The local half is in `localStorage`, which raises `storage` in every
        // tab of this origin but the one that wrote. That is how a sibling tab
        // hears that this origin dropped its claim, which no cookie event can
        // carry.
        if let Some(target) = wasm::event_target() {
            let target: JsValue = target.into();
            let check_for_storage = check.clone();
            let key_for_storage = key_owned.clone();
            listeners.push(JsListener::new(target, "storage", move |event: JsValue| {
                match wasm::get_property(&event, "key") {
                    None => {}
                    Some(value) if value.is_null() => check_for_storage(),
                    Some(value) => {
                        if value.as_string().as_deref() == Some(key_for_storage.as_str()) {
                            check_for_storage();
                        }
                    }
                }
            }));
        }

        // `document.cookie` raises no event and no `BroadcastChannel` crosses
        // origins, so a sibling's sign-out is visible only by looking: on
        // visibility, pageshow, focus, and the Cookie Store API where it
        // exists.
        if let Some(document) = wasm::document() {
            let check_for_visibility = check.clone();
            let document_for_visibility = document.clone();
            listeners.push(JsListener::new(
                document.clone(),
                "visibilitychange",
                move |_event: JsValue| {
                    if wasm::get_string(&document_for_visibility, "visibilityState").as_deref()
                        == Some("visible")
                    {
                        check_for_visibility();
                    }
                },
            ));
            if let Some(cookie_store) = wasm::get_prop(&wasm::global(), "cookieStore") {
                let check_for_cookie_store = check.clone();
                listeners.push(JsListener::new(
                    cookie_store,
                    "change",
                    move |_event: JsValue| check_for_cookie_store(),
                ));
            }
        }
        if let Some(target) = wasm::event_target() {
            let target: JsValue = target.into();
            let check_for_pageshow = check.clone();
            listeners.push(JsListener::new(target.clone(), "pageshow", move |_| {
                check_for_pageshow();
            }));
            let check_for_focus = check.clone();
            listeners.push(JsListener::new(target, "focus", move |_| {
                check_for_focus();
            }));
        }

        let key_for_unsubscribe = key_owned;
        let unsubscribe: Box<dyn crate::client::platform::Unsubscribe> = Box::new(move || {
            inner.unregister(&key_for_unsubscribe, id);
            drop(listeners);
        });
        Subscription::new(unsubscribe)
    }

    fn is_read_only(&self) -> bool {
        self.inner.local.is_read_only()
    }

    fn ready(&self) -> Pin<Box<dyn Future<Output = ()> + '_>> {
        self.inner.local.ready()
    }
}

/// What this store answers for `key`: the cookie's record plus this origin's
/// claim on it.
fn read_state(local: &LocalStateStorage, key: &str) -> Option<SessionState> {
    if local.is_read_only() {
        return local.get(key);
    }
    let raw = read_cookie_value(&document_cookie_header().unwrap_or_default(), key)?;
    let stored = decode_cookie_record(&raw)?;
    // Compared, not merely counted: a record can outlive the sign-in it was
    // written for, and a sibling signing in as someone else then publishes a
    // cookie this origin has no credential for (`cookie-state-storage.ts:160-174`).
    let claim = local.get(key);
    Some(SessionState {
        principal: stored.principal,
        expiration_ns: stored.expiration_ns,
        held: claim
            .map(|claim| claim.principal == stored.principal)
            .unwrap_or(false),
    })
}

/// The current `document.cookie` string.
fn document_cookie_header() -> Option<String> {
    let document = wasm::document()?;
    Some(wasm::get_string(&document, "cookie").unwrap_or_default())
}

/// Writes one cookie with this store's attributes.
fn write_cookie(attributes: &str, key: &str, value: &str, max_age: Option<u64>) {
    let Some(document) = wasm::document() else {
        return;
    };
    let name = encode_uri_component(key);
    let cookie = match max_age {
        Some(max_age) => format!("{name}={value}; {attributes}; Max-Age={max_age}"),
        None => format!("{name}={value}; {attributes}"),
    };
    let _ = wasm::set_prop(&document, "cookie", &JsValue::from_str(&cookie));
}
