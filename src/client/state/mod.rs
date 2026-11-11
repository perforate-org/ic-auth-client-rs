//! Where the answer to "who is signed in here, and until when" is kept.
//!
//! Port of upstream `src/client/state/`. This is a store of its own because it
//! has to be readable without awaiting; a credential store does not.

// The codecs and helpers below are what the JavaScript stores use; a
// native build compiles the stores that need them out, and would otherwise
// report every one of them as dead.
#![cfg_attr(not(feature = "wasm-js"), allow(dead_code))]

use std::sync::Arc;

use ic_agent::export::Principal;

use crate::client::error::AuthClientError;
use crate::client::platform::PlatformBounds;

#[cfg(feature = "wasm-js")]
pub mod cookie;
#[cfg(feature = "wasm-js")]
pub mod local;
#[cfg(feature = "native")]
pub mod native;

mod memory;

pub use memory::MemoryStateStorage;

#[cfg(feature = "wasm-js")]
pub use cookie::CookieStateStorage;
#[cfg(feature = "wasm-js")]
pub use local::LocalStateStorage;
#[cfg(feature = "native")]
pub use native::NativeStateStorage;

/// What a client knows about its sign-in without holding a credential.
///
/// Port of upstream `SessionState` (`state/state-storage.ts:11-27`). The
/// principal is what an application's canisters see as the caller and the
/// expiration is what the identity provider granted, so neither is a secret and
/// both can live somewhere a page reads synchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionState {
    /// The account this sign-in is for.
    pub principal: Principal,

    /// Nanoseconds since the epoch, matching `Delegation.expiration`.
    pub expiration_ns: u64,

    /// Whether this origin holds a credential for that account, or only knows
    /// the sign-in exists.
    ///
    /// Derived on read and never published: where the record reaches further
    /// than one origin, the record itself cannot carry a per-origin fact.
    pub held: bool,
}

/// What a store persists: the same record without the derived `held` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredSessionState {
    /// The account this sign-in is for.
    pub principal: Principal,
    /// Nanoseconds since the epoch, matching `Delegation.expiration`.
    pub expiration_ns: u64,
}

impl SessionState {
    /// The stored half of this state.
    pub fn stored(&self) -> StoredSessionState {
        StoredSessionState {
            principal: self.principal,
            expiration_ns: self.expiration_ns,
        }
    }

    /// When the sign-in ends, in milliseconds since the Unix epoch.
    pub fn expires_at_ms(&self) -> u64 {
        self.expiration_ns / 1_000_000
    }
}

impl From<(StoredSessionState, bool)> for SessionState {
    fn from((stored, held): (StoredSessionState, bool)) -> Self {
        Self {
            principal: stored.principal,
            expiration_ns: stored.expiration_ns,
            held,
        }
    }
}

/// A listener fired when the state under a slot changes.
pub type StateListener = Arc<dyn crate::client::platform::Listener>;

/// A registered listener, unsubscribed when dropped.
pub struct Subscription {
    unsubscribe: Option<Box<dyn crate::client::platform::Unsubscribe>>,
}

impl Subscription {
    /// A subscription that does nothing when dropped.
    pub fn empty() -> Self {
        Self { unsubscribe: None }
    }

    /// A subscription that runs `unsubscribe` when dropped.
    pub fn new(unsubscribe: Box<dyn crate::client::platform::Unsubscribe>) -> Self {
        Self {
            unsubscribe: Some(unsubscribe),
        }
    }

    /// Unregisters now rather than when dropped.
    pub fn unsubscribe(mut self) {
        if let Some(unsubscribe) = self.unsubscribe.take() {
            unsubscribe.call_once();
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(unsubscribe) = self.unsubscribe.take() {
            unsubscribe.call_once();
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("active", &self.unsubscribe.is_some())
            .finish()
    }
}

/// Holds the state of a sign-in.
///
/// Port of upstream `StateStorage` (`state/state-storage.ts:40-112`).
pub trait StateStorage: PlatformBounds {
    /// The state, or `None` where nothing is signed in within this store's
    /// reach.
    fn get(&self, key: &str) -> Option<SessionState>;

    /// Stores the state.
    fn set(&self, key: &str, state: StoredSessionState);

    /// Removes the state, and anything this store publishes beyond this origin.
    fn remove(&self, key: &str);

    /// Removes what this origin holds, leaving anything shared alone.
    ///
    /// What finding out does, which is a different act from signing out: an
    /// origin whose chain turns out to be dead cannot tell whether the session
    /// was revoked or replaced by a sibling signing in.
    fn discard(&self, key: &str) {
        self.remove(key);
    }

    /// Whether a sign-in kept in this store may be resumed without a ceremony.
    fn resumable(&self) -> bool {
        false
    }

    /// Registers a listener fired when the state under `key` changes, including
    /// when something other than this client changed it.
    fn subscribe(&self, key: &str, listener: StateListener) -> Subscription;

    /// Whether this store only reads the state here, as a store does in a
    /// worker.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Resolves once [`StateStorage::get`] answers with the stored state, for a
    /// store that loads it asynchronously.
    fn ready(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>> {
        Box::pin(async {})
    }
}

/// A state store the client holds behind an `Arc`.
pub type SharedStateStorage = Arc<dyn StateStorage>;

/// The error a state store reports through methods that cannot return one.
///
/// Kept for stores whose writes are best-effort; upstream's stores swallow
/// storage failures for the same reason (`session/session-identity.ts:171-176`).
#[allow(dead_code)]
pub(crate) fn ignore_storage_error<T>(_: Result<T, AuthClientError>) {}

// ---------------------------------------------------------------------------
// The persisted forms
// ---------------------------------------------------------------------------

/// What separates the principal from the expiration in a stored record.
///
/// A pipe rather than JSON because an expiration is a `bigint` and JSON cannot
/// carry one (`local-state-storage.ts:34-36`).
pub(crate) const STATE_RECORD_SEPARATOR: char = '|';

/// How long a browser keeps a cookie record, in seconds.
///
/// 400 days is the browser ceiling for a persistent cookie; the record is
/// deliberately kept past the session's expiry so a sibling can say the session
/// ended rather than that nobody signed in (`cookie-state-storage.ts:5-18`).
pub(crate) const RECORD_MAX_AGE_SECONDS: u64 = 400 * 24 * 60 * 60;

/// The cookie the constructor writes and reads back to find out whether the
/// browser accepts a cookie scoped to the configured domain.
pub(crate) const COOKIE_PROBE_NAME: &str = "ic-cookie-probe";

/// The record as `localStorage` and cookies hold it: `<principal>|<ns>`.
pub(crate) fn encode_state_record(state: &StoredSessionState) -> String {
    format!(
        "{}{}{}",
        state.principal.to_text(),
        STATE_RECORD_SEPARATOR,
        state.expiration_ns
    )
}

/// Reads `<principal>|<ns>`, answering `None` for anything unparseable.
///
/// Upstream destructures the first two `|`-separated fields and ignores the
/// rest, so this does the same; every failure is a record this version cannot
/// read, never a thrown error (`local-state-storage.ts:61-78`).
pub(crate) fn decode_state_record(raw: &str) -> Option<StoredSessionState> {
    let mut fields = raw.split(STATE_RECORD_SEPARATOR);
    let principal_text = fields.next()?;
    let expiration_text = fields.next()?;
    let principal = Principal::from_text(principal_text).ok()?;
    let expiration_ns = expiration_text.parse::<u64>().ok()?;
    Some(StoredSessionState {
        principal,
        expiration_ns,
    })
}

/// What a cookie store compares to decide whether the answer changed.
///
/// Both halves: the cookie every sibling reads, and the `held` this origin
/// derives, because a change in either is a change to the answer
/// (`cookie-state-storage.ts:281-288`).
pub(crate) fn state_of(state: Option<&SessionState>) -> String {
    match state {
        None => String::new(),
        Some(state) => format!(
            "{}{}{}{}{}",
            state.principal.to_text(),
            STATE_RECORD_SEPARATOR,
            state.expiration_ns,
            STATE_RECORD_SEPARATOR,
            state.held
        ),
    }
}

/// Whether a hostname is loopback, which browsers treat as a secure context.
///
/// Port of `isLoopbackHost` (`cookie-state-storage.ts:24-28`).
pub(crate) fn is_loopback_host(hostname: &str) -> bool {
    hostname == "localhost"
        || hostname.ends_with(".localhost")
        || hostname == "127.0.0.1"
        || hostname == "[::1]"
}

/// The characters `encodeURIComponent` leaves alone.
fn is_uri_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}

/// `encodeURIComponent`, over UTF-8.
pub(crate) fn encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if is_uri_unreserved(*byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

/// `decodeURIComponent`, over UTF-8.
///
/// Answers `None` where JS would throw a `URIError`, which is what lets a
/// stray `%` in a cookie name be skipped rather than break every read
/// (`cookie-state-storage.ts:290-304`).
pub(crate) fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            let byte = (hex_digit(high)? << 4) | hex_digit(low)?;
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The attributes every cookie this store writes carries.
///
/// Port of the attribute list at `cookie-state-storage.ts:115-125`: `Domain`
/// is omitted entirely on loopback because browsers reject `Domain=localhost`,
/// and `Secure` only where the page is https.
pub(crate) fn cookie_attributes(domain: &str, loopback: bool, secure: bool) -> String {
    let mut attributes = Vec::new();
    if !loopback {
        attributes.push(format!("Domain={domain}"));
    }
    attributes.push("Path=/".to_string());
    attributes.push("SameSite=Lax".to_string());
    if secure {
        attributes.push("Secure".to_string());
    }
    attributes.join("; ")
}

/// The cookie value for a record: `encodeURIComponent("<principal>|<ns>")`.
pub(crate) fn encode_cookie_record(state: &StoredSessionState) -> String {
    encode_uri_component(&encode_state_record(state))
}

/// Reads a cookie value back into a record.
pub(crate) fn decode_cookie_record(raw: &str) -> Option<StoredSessionState> {
    decode_state_record(raw)
}

/// Reads one cookie's decoded value out of a `document.cookie` string.
///
/// Any cookie on the domain lands in that string, including ones this library
/// did not write. A name or value that cannot be decoded is skipped, so one
/// unrelated malformed cookie cannot break reading the state
/// (`cookie-state-storage.ts:290-304`).
pub(crate) fn read_cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    for entry in cookie_header.split(';') {
        let Some(separator) = entry.find('=') else {
            continue;
        };
        let Some(entry_name) = decode_uri_component(entry[..separator].trim()) else {
            continue;
        };
        if entry_name != name {
            continue;
        }
        let Some(value) = decode_uri_component(entry[separator + 1..].trim()) else {
            continue;
        };
        return Some(value);
    }
    None
}

/// The message a worker store panics with when asked to change the state.
///
/// Upstream throws; the trait methods have no error channel, so the Rust
/// equivalent is to panic with the same text (`local-state-storage.ts:11-15`).
pub(crate) const READ_ONLY_MESSAGE: &str =
    "The sign-in state is read-only in a worker: sign in and sign out from a page of this origin.";

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> Principal {
        Principal::self_authenticating([1u8, 2, 3])
    }

    fn state() -> StoredSessionState {
        StoredSessionState {
            principal: principal(),
            expiration_ns: 1_893_456_000_000_000_000,
        }
    }

    #[test]
    fn state_record_is_pipe_separated_not_json() {
        let raw = encode_state_record(&state());
        assert_eq!(
            raw,
            format!("{}|1893456000000000000", principal().to_text())
        );
        assert!(!raw.contains('{'));
        assert_eq!(decode_state_record(&raw), Some(state()));
    }

    #[test]
    fn corrupt_state_record_is_none() {
        assert_eq!(decode_state_record("not-a-state"), None);
        assert_eq!(decode_state_record("not-a-principal|123"), None);
        assert_eq!(
            decode_state_record(&format!("{}|not-a-number", principal().to_text())),
            None
        );
        assert_eq!(decode_state_record("|1"), None);
        assert_eq!(decode_state_record(""), None);
    }

    #[test]
    fn state_record_ignores_trailing_fields_like_js() {
        let raw = format!("{}|42|extra", principal().to_text());
        assert_eq!(
            decode_state_record(&raw),
            Some(StoredSessionState {
                principal: principal(),
                expiration_ns: 42,
            })
        );
    }

    #[test]
    fn uri_component_matches_encode_uri_component() {
        assert_eq!(encode_uri_component("ic-session-state"), "ic-session-state");
        assert_eq!(encode_uri_component("a b"), "a%20b");
        assert_eq!(encode_uri_component("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(encode_uri_component("!~*'()"), "!~*'()");
        assert_eq!(encode_uri_component("é"), "%C3%A9");
        assert_eq!(decode_uri_component("%C3%A9"), Some("é".to_string()));
    }

    #[test]
    fn uri_component_round_trips_and_rejects_malformed_input() {
        let value = format!("{}|123", principal().to_text());
        let encoded = encode_uri_component(&value);
        assert_eq!(
            decode_uri_component(&encoded).as_deref(),
            Some(value.as_str())
        );
        assert_eq!(decode_uri_component("%"), None);
        assert_eq!(decode_uri_component("%2"), None);
        assert_eq!(decode_uri_component("%zz"), None);
        assert_eq!(decode_uri_component("%FF"), None);
    }

    #[test]
    fn cookie_attributes_follow_the_loopback_and_secure_rules() {
        assert_eq!(
            cookie_attributes("example.com", false, true),
            "Domain=example.com; Path=/; SameSite=Lax; Secure"
        );
        assert_eq!(
            cookie_attributes("example.com", false, false),
            "Domain=example.com; Path=/; SameSite=Lax"
        );
        assert_eq!(
            cookie_attributes("localhost", true, false),
            "Path=/; SameSite=Lax"
        );
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("app.localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("localhost.example.com"));
    }

    #[test]
    fn cookie_record_round_trips() {
        let encoded = encode_cookie_record(&state());
        assert!(!encoded.contains('|'));
        // A cookie value is read back decoded, which is what the store hands
        // to the parser.
        let header = format!("ic-session-state={encoded}");
        let decoded = read_cookie_value(&header, "ic-session-state").unwrap();
        assert_eq!(decoded, encode_state_record(&state()));
        assert_eq!(decode_cookie_record(&decoded), Some(state()));
    }

    #[test]
    fn read_cookie_skips_malformed_entries() {
        let encoded = encode_cookie_record(&state());
        let header = format!("%bad=1; ic-session-state={encoded}; other=x");
        assert_eq!(
            read_cookie_value(&header, "ic-session-state").as_deref(),
            Some(encode_state_record(&state()).as_str())
        );
        assert_eq!(read_cookie_value(&header, "missing"), None);
        assert_eq!(read_cookie_value("", "ic-session-state"), None);
        assert_eq!(
            read_cookie_value("ic-session-state=%zz", "ic-session-state"),
            None
        );
    }

    #[test]
    fn state_of_includes_held() {
        let held = SessionState {
            principal: principal(),
            expiration_ns: 7,
            held: true,
        };
        let not_held = SessionState {
            held: false,
            ..held
        };
        assert_eq!(state_of(None), "");
        assert_ne!(state_of(Some(&held)), state_of(Some(&not_held)));
        assert_eq!(
            state_of(Some(&held)),
            format!("{}|7|true", principal().to_text())
        );
    }
}
