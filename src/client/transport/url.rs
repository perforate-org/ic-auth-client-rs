//! The ICRC-167 browser URL transport (wasm).
//!
//! Port of `@icp-sdk/signer@6.1.0`'s `web/urlTransport.ts`,
//! `web/urlChannel.ts` and `web/urlFlow.ts`. The signer is reached by a
//! top-level navigation that carries one JSON-RPC batch in the fragment of the
//! signer URL; the signer returns the responses in the fragment of the
//! callback URL. Because the navigation unloads the document, the transport
//! persists a call-order-keyed journal in `sessionStorage` and replays it on
//! the return load.
//!
//! The journal codec and the replay/flush state machine are platform-neutral
//! (they only talk to the browser through the [`FlowIo`] trait), so their unit
//! tests run natively; the `web` module is the `web-sys` wiring and its tests
//! need a browser (or at least a DOM).
//!
//! Protocol summary (`docs/port/protocols/signer-protocol.md` §9.5):
//!
//! - storage key: `` icrc167:flow:<callback url> `` (`urlTransport.ts:71`)
//! - flow timeout: `600_000` ms (`urlTransport.ts:72`)
//! - fragment: `message=<JSON-RPC batch>&callback=<callback>&state=<uuid>`
//!   (`urlFlow.ts:351-362`)
//! - journal JSON: `{createdAt, url, results, asyncSlots, requestKeys, pending}`
//!   (`urlFlow.ts:365-378`)
//! - return load: absorb only when `message` is present and `state` matches the
//!   stored `pending.state` (`urlFlow.ts:175-207`); strip the response fragment
//!   whenever `message` is present (`urlFlow.ts:171-173`)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{JsonRpcId, JsonRpcRequest, JsonRpcResponse, SignerError};

/// The default time after which an unfinished flow's journal is ignored.
///
/// `UrlTransportOptions.flowTimeout` default (`urlTransport.ts:72`).
pub const DEFAULT_FLOW_TIMEOUT_MS: u64 = 600_000;

/// The prefix of the default journal key, `icrc167:flow:<callback url>`.
///
/// `UrlTransportOptions.storageKey` default (`urlTransport.ts:71`).
pub const STORAGE_KEY_PREFIX: &str = "icrc167:flow:";

/// The replayed-response divergence guard's message (`urlChannel.ts:104-108`).
pub const DIVERGENCE_REQUEST: &str = "URL transport replay diverged: the request at this step differs from the one sent before the redirect. Issue the same requests in the same order on every load.";

/// The notification rejection message (`urlChannel.ts:92-96`).
pub const NOTIFICATIONS_UNSUPPORTED: &str =
    "The URL transport requires a request id; notifications are not supported";

/// The navigation-sink secure-context refusal (`urlFlow.ts:359-361`).
pub const NON_SECURE_NAVIGATION: &str = "Refusing to navigate to a non-secure-context signer URL";

/// The default journal key for `callback_url`.
pub fn default_storage_key(callback_url: &str) -> String {
    format!("{STORAGE_KEY_PREFIX}{callback_url}")
}

// ---------------------------------------------------------------------------
// URL parsing (platform-neutral, so the secure-context rules are testable)
// ---------------------------------------------------------------------------

/// The parts of a URL the transports need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// The lowercased scheme, without the colon (`https`).
    pub scheme: String,
    /// The lowercased host. IPv4 literals are canonicalised to dotted quad,
    /// IPv6 literals keep their brackets.
    pub host: String,
    /// The explicit port, when the URL carries one.
    pub port: Option<u16>,
    /// The path, beginning with `/` (empty paths become `/`).
    pub path: String,
    /// The query, without the leading `?`.
    pub query: Option<String>,
    /// The fragment, without the leading `#`.
    pub fragment: Option<String>,
}

impl ParsedUrl {
    /// The origin, spelled the way `new URL(...).origin` spells it: the
    /// default port (80/443) is omitted.
    pub fn origin(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        match self.port {
            Some(port) if Some(port) != default_port => {
                format!("{}://{}:{}", self.scheme, self.host, port)
            }
            _ => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Parses an absolute URL far enough for the transports' checks.
///
/// This is a deliberate subset of the WHATWG URL parser: the transports only
/// need the scheme, host, port and whether a fragment is present, and a
/// false-negative (rejecting a URL a browser would accept) is safe whereas a
/// false-positive is not.
pub fn parse_url(value: &str) -> Option<ParsedUrl> {
    let value = value.trim_matches(|c: char| c <= ' ');
    let colon = value.find(':')?;
    let scheme = &value[..colon];
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let rest = &value[colon + 1..];
    // The transports only ever see http(s) URLs, which the WHATWG parser
    // treats as "special" and always gives a host.
    let rest = rest.strip_prefix("//")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let mut tail = &rest[authority_end..];

    // Drop any userinfo; it is not part of the origin.
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };

    let (host, port) = split_host_port(host_port)?;
    let host = canonical_host(&host)?;

    let mut fragment = None;
    if let Some(hash) = tail.find('#') {
        fragment = Some(tail[hash + 1..].to_string());
        tail = &tail[..hash];
    }
    let mut query = None;
    if let Some(question) = tail.find('?') {
        query = Some(tail[question + 1..].to_string());
        tail = &tail[..question];
    }
    let path = if tail.is_empty() {
        "/".to_string()
    } else {
        tail.to_string()
    };

    Some(ParsedUrl {
        scheme: scheme.to_ascii_lowercase(),
        host,
        port,
        path,
        query,
        fragment,
    })
}

fn split_host_port(value: &str) -> Option<(String, Option<u16>)> {
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`.
        let close = rest.find(']')?;
        let host = format!("[{}]", rest[..close].to_ascii_lowercase());
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(port) if !port.is_empty() => Some(parse_port(port)?),
            Some(_) => None,
            None => None,
        };
        return Some((host, port));
    }
    match value.rfind(':') {
        Some(index) => {
            let port = parse_port(&value[index + 1..])?;
            Some((value[..index].to_string(), Some(port)))
        }
        None => Some((value.to_string(), None)),
    }
}

fn parse_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|port| *port <= 65_535)
        .map(|port| port as u16)
}

fn canonical_host(host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    if host.starts_with('[') {
        return Some(host.to_ascii_lowercase());
    }
    let lower = host.to_ascii_lowercase();
    if looks_like_ipv4(&lower) {
        // A host that *looks* like an IPv4 address but does not parse makes the
        // WHATWG parser throw, so a secure-context check must reject it.
        parse_ipv4(&lower)
    } else {
        Some(lower)
    }
}

/// Whether every dot-separated label is a decimal or `0x`-hex IPv4 component.
///
/// Only such a host is run through the IPv4 parser: a domain name that happens
/// to contain hex letters (`dead.beef`) must stay a domain.
fn looks_like_ipv4(host: &str) -> bool {
    host.split('.').all(|part| {
        !part.is_empty()
            && (part.chars().all(|c| c.is_ascii_digit())
                || (part.len() > 2
                    && (part.starts_with("0x") || part.starts_with("0X"))
                    && part[2..].chars().all(|c| c.is_ascii_hexdigit())))
    })
}

fn is_decimal(part: &str) -> bool {
    !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())
}

/// The WHATWG IPv4 parser, reduced to the addresses the transports care about.
fn parse_ipv4(host: &str) -> Option<String> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in &parts {
        let number = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X"))
        {
            if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u32::from_str_radix(hex, 16).ok()?
        } else if part.len() > 1 && part.starts_with('0') {
            if !part.chars().all(|c| ('0'..='7').contains(&c)) {
                return None;
            }
            u32::from_str_radix(&part[1..], 8).ok()?
        } else {
            if !is_decimal(part) {
                return None;
            }
            part.parse::<u32>().ok()?
        };
        numbers.push(number);
    }
    let last = *numbers.last()?;
    for number in &numbers[..numbers.len() - 1] {
        if *number > 255 {
            return None;
        }
    }
    let max_last = match numbers.len() {
        1 => u32::MAX,
        2 => 0x00ff_ffff,
        3 => 0x0000_ffff,
        4 => 0x0000_00ff,
        _ => return None,
    };
    if last > max_last {
        return None;
    }
    // Fold the trailing parts into the last octets, as the WHATWG parser does:
    // `127.1` is `127.0.0.1`, `127.0.1` is `127.0.0.1`.
    let ipv4 = match numbers.len() {
        1 => last,
        2 => (numbers[0] << 24) | last,
        3 => (numbers[0] << 24) | (numbers[1] << 16) | last,
        4 => (numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | last,
        _ => return None,
    };
    Some(format!(
        "{}.{}.{}.{}",
        (ipv4 >> 24) & 0xff,
        (ipv4 >> 16) & 0xff,
        (ipv4 >> 8) & 0xff,
        ipv4 & 0xff
    ))
}

/// Whether `hostname` is a loopback host: `localhost`, `*.localhost`, `[::1]`
/// or `127.0.0.0/8`. (`urlFlow.ts:7-11`.)
pub fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "[::1]"
        || host
            .parse::<std::net::Ipv4Addr>()
            .map(|address| address.octets()[0] == 127)
            .unwrap_or(false)
}

/// Whether `value` is a secure-context URL: `https` on any host, or `http` on
/// a loopback host. (`urlFlow.ts:18-25`.)
pub fn is_secure_context_url(value: &str) -> bool {
    let Some(url) = parse_url(value) else {
        return false;
    };
    url.scheme == "https" || (url.scheme == "http" && is_loopback_host(&url.host))
}

/// The `new URL(...).origin` of `value`, when it parses.
pub fn origin_of(value: &str) -> Option<String> {
    parse_url(value).map(|url| url.origin())
}

/// Validates an ICRC-167 callback URL: absolute, and without a fragment (the
/// transport appends its own). (`urlTransport.ts:113-121`.)
pub fn validate_callback_url(value: &str) -> Result<ParsedUrl, SignerError> {
    let Some(url) = parse_url(value) else {
        return Err(SignerError::Transport("Invalid callback url".into()));
    };
    if url
        .fragment
        .as_deref()
        .is_some_and(|fragment| !fragment.is_empty())
    {
        return Err(SignerError::Transport(
            "Callback url must not contain a fragment".into(),
        ));
    }
    Ok(url)
}

// ---------------------------------------------------------------------------
// `application/x-www-form-urlencoded` codec (the fragment format)
// ---------------------------------------------------------------------------

/// The two fragment parameters the transport reads (`urlFlow.ts:163-165`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FragmentParams {
    /// The JSON-RPC response (or batch) the signer returned.
    pub message: Option<String>,
    /// The `state` the flow sent, echoed by the signer.
    pub state: Option<String>,
}

/// Parses `location.hash` the way `new URLSearchParams(hash.slice(1))` does.
pub fn parse_fragment(hash: &str) -> FragmentParams {
    let raw = hash.strip_prefix('#').unwrap_or(hash);
    let mut params = FragmentParams::default();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = form_decode(key);
        let value = form_decode(value);
        match key.as_str() {
            "message" if params.message.is_none() => params.message = Some(value),
            "state" if params.state.is_none() => params.state = Some(value),
            _ => {}
        }
    }
    params
}

/// Encodes pairs the way `new URLSearchParams({...}).toString()` does.
pub fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    let mut encoded = String::new();
    for (key, value) in pairs {
        if !encoded.is_empty() {
            encoded.push('&');
        }
        form_encode_into(key, &mut encoded);
        encoded.push('=');
        form_encode_into(value, &mut encoded);
    }
    encoded
}

fn form_encode_into(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0xf) as usize] as char);
            }
        }
    }
}

fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1]);
                let low = hex_value(bytes[index + 2]);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        decoded.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        decoded.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

/// Upstream `isJsonRpcResponse` (`transport.ts:21-28`): a JSON-RPC response is
/// an object with `jsonrpc: "2.0"` and a string-or-number `id`.
pub(crate) fn is_json_rpc_response(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some(super::JSON_RPC_VERSION) {
        return false;
    }
    matches!(
        object.get("id"),
        Some(Value::String(_)) | Some(Value::Number(_))
    )
}

/// The serialised form of a [`JsonRpcId`].
pub(crate) fn id_to_value(id: &JsonRpcId) -> Value {
    match id {
        JsonRpcId::Number(number) => Value::Number((*number).into()),
        JsonRpcId::String(string) => Value::String(string.clone()),
        JsonRpcId::Null => Value::Null,
    }
}

/// The response id, when it is the string-or-number shape the protocol wants.
pub(crate) fn response_id(value: &Value) -> Option<JsonRpcId> {
    let id = value.get("id")?;
    match id {
        Value::String(string) => Some(JsonRpcId::String(string.clone())),
        Value::Number(number) => number.as_i64().map(JsonRpcId::Number),
        _ => None,
    }
}

/// Whether a request is a notification (no id, or a `null` id).
pub(crate) fn is_notification(request: &JsonRpcRequest) -> bool {
    matches!(request.id, None | Some(JsonRpcId::Null))
}

/// The replay content fingerprint (`urlChannel.ts:6-7`):
/// `JSON.stringify({method, params: params ?? null})`.
pub fn request_fingerprint(request: &JsonRpcRequest) -> String {
    let fingerprint = serde_json::json!({
        "method": request.method,
        "params": request.params.clone().unwrap_or(Value::Null),
    });
    serde_json::to_string(&fingerprint).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The persisted journal (`StoredFlow`, `urlFlow.ts:58-83,365-378`)
// ---------------------------------------------------------------------------

/// A request awaiting a signer return, identified by its call order and id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// The call-order slot the response belongs to.
    pub index: u64,
    /// The request id the signer will answer.
    pub id: Value,
}

/// The batch currently in flight, with the state that authorises its return.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingBatch {
    /// The random `state` sent in the fragment.
    pub state: String,
    /// The buffered requests, by call order.
    pub requests: Vec<PendingRequest>,
}

/// The journal persisted across the redirect.
///
/// Field names and shapes match upstream `StoredFlow` so a browser that ran
/// either implementation can resume the other's flow. `memoized` is a Rust-only
/// extension for the keyed [`super::Journal`] API; upstream's reader ignores
/// unknown fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StoredFlow {
    /// When the flow started, in epoch milliseconds.
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    /// The redirect target captured on the first load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Completed slots: a memoized value or a raw JSON-RPC response.
    #[serde(default)]
    pub results: BTreeMap<u64, Value>,
    /// Slots whose producer was asynchronous (kept for shape compatibility).
    #[serde(rename = "asyncSlots", default)]
    pub async_slots: Vec<u64>,
    /// The replay divergence fingerprint per request slot.
    #[serde(rename = "requestKeys", default)]
    pub request_keys: BTreeMap<u64, String>,
    /// The batch awaiting a return, when this load navigated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingBatch>,
    /// Keyed memoized values (Rust extension; ignored by the JS reader).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub memoized: BTreeMap<String, Value>,
}

// ---------------------------------------------------------------------------
// The platform seam
// ---------------------------------------------------------------------------

/// The browser operations the journal needs.
///
/// Kept as a trait so the state machine is platform-neutral and its tests run
/// natively. Implementations must be cheap handles (the `web` module's is a
/// bundle of `web-sys` wrappers).
pub trait FlowIo {
    /// Reads a `sessionStorage` value.
    fn storage_get(&self, key: &str) -> Option<String>;
    /// Writes a `sessionStorage` value.
    fn storage_set(&self, key: &str, value: &str);
    /// Removes a `sessionStorage` value.
    fn storage_remove(&self, key: &str);
    /// The current `location.hash`, including the leading `#`.
    fn location_hash(&self) -> String;
    /// `location.pathname + location.search`.
    fn location_path(&self) -> String;
    /// `history.replaceState(null, '', location.pathname + location.search)`.
    fn strip_fragment(&self);
    /// Navigates the current document to `url`.
    fn assign(&self, url: &str) -> Result<(), String>;
    /// The current time in epoch milliseconds.
    fn now_ms(&self) -> u64;
    /// A fresh random UUID.
    fn random_uuid(&self) -> String;
}

fn read_stored(io: &dyn FlowIo, storage_key: &str) -> StoredFlow {
    let Some(raw) = io.storage_get(storage_key) else {
        return StoredFlow::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The flow state machine (`UrlFlow`, `urlFlow.ts:131-379`)
// ---------------------------------------------------------------------------

/// One request buffered for the next redirect.
#[derive(Debug, Clone, PartialEq)]
pub struct BufferedRequest {
    /// The call-order slot the response will be journaled at.
    pub index: u64,
    /// The request itself.
    pub request: JsonRpcRequest,
}

/// The call-order journal for one URL-transport flow (one page load).
///
/// This owns the state `UrlFlow` owns upstream, but performs no I/O of its own:
/// construction reads the fragment/journal and the flush navigates through the
/// supplied [`FlowIo`]. That keeps the replay contract testable without a
/// browser.
#[derive(Debug)]
pub struct UrlFlow {
    url: String,
    callback_url: String,
    storage_key: String,
    flow_timeout_ms: u64,
    results: BTreeMap<u64, Value>,
    async_slots: Vec<u64>,
    request_keys: BTreeMap<u64, String>,
    memoized: BTreeMap<String, Value>,
    created_at: Option<u64>,
    index: u64,
    navigated: bool,
    buffer: Vec<BufferedRequest>,
    return_load: bool,
}

impl UrlFlow {
    /// Builds the flow and decides, from the journal and the fragment, whether
    /// this load is a signer return or a fresh flow (`urlFlow.ts:152-207`).
    pub fn new(
        url: &str,
        callback_url: &str,
        storage_key: &str,
        flow_timeout_ms: u64,
        io: &dyn FlowIo,
    ) -> Self {
        let stored = read_stored(io, storage_key);
        let expired = stored
            .created_at
            .is_some_and(|created_at| io.now_ms().saturating_sub(created_at) > flow_timeout_ms);
        if expired {
            io.storage_remove(storage_key);
        }

        let params = parse_fragment(&io.location_hash());
        // A response fragment must never linger in history or the referrer:
        // strip it whenever one is present, matching or not.
        if params.message.is_some() {
            io.strip_fragment();
        }

        if !expired
            && params.message.is_some()
            && stored
                .pending
                .as_ref()
                .is_some_and(|pending| params.state.as_deref() == Some(pending.state.as_str()))
        {
            let pending = stored.pending.clone().expect("checked above");
            let mut flow = Self {
                url: stored.url.clone().unwrap_or_else(|| url.to_string()),
                callback_url: callback_url.to_string(),
                storage_key: storage_key.to_string(),
                flow_timeout_ms,
                results: stored.results,
                async_slots: stored.async_slots,
                request_keys: stored.request_keys,
                memoized: stored.memoized,
                created_at: stored.created_at,
                index: 0,
                navigated: false,
                buffer: Vec::new(),
                return_load: true,
            };
            flow.absorb_return(&params, &pending);
            flow.persist(io, None);
            flow
        } else {
            Self {
                url: url.to_string(),
                callback_url: callback_url.to_string(),
                storage_key: storage_key.to_string(),
                flow_timeout_ms,
                results: BTreeMap::new(),
                async_slots: Vec::new(),
                request_keys: BTreeMap::new(),
                memoized: BTreeMap::new(),
                created_at: None,
                index: 0,
                navigated: false,
                buffer: Vec::new(),
                return_load: false,
            }
        }
    }

    /// Folds the returned batch into the journal by request id
    /// (`urlFlow.ts:190-200`).
    fn absorb_return(&mut self, params: &FragmentParams, pending: &PendingBatch) {
        let Some(message) = params.message.as_deref() else {
            return;
        };
        let Ok(parsed) = serde_json::from_str::<Value>(message) else {
            return;
        };
        let responses: Vec<&Value> = match &parsed {
            Value::Array(responses) => responses.iter().collect(),
            other => vec![other],
        };
        for request in &pending.requests {
            let matched = responses.iter().find(|response| {
                is_json_rpc_response(response) && response.get("id") == Some(&request.id)
            });
            if let Some(response) = matched {
                self.results.insert(request.index, (*response).clone());
            }
        }
    }

    /// Whether this load continued a signer return.
    pub fn is_return_load(&self) -> bool {
        self.return_load
    }

    /// The effective redirect target (the stored one on a return load).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Reserves the next call-order slot (`urlFlow.ts:209-212`).
    ///
    /// Named after upstream's `next()`; this is a journal counter, not an
    /// `Iterator`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let index = self.index;
        self.index += 1;
        index
    }

    /// The journaled value for a slot, when it has completed.
    pub fn get(&self, index: u64) -> Option<&Value> {
        self.results.get(&index)
    }

    /// The recorded request fingerprint for a slot, if a request owned it.
    pub fn recorded_request_key(&self, index: u64) -> Option<&str> {
        self.request_keys.get(&index).map(String::as_str)
    }

    /// The keyed memoized value, when journaled (`Journal::get`).
    pub fn memoized(&self, key: &str) -> Option<&Value> {
        self.memoized.get(key)
    }

    /// Journals a keyed memoized value (`Journal::put`).
    ///
    /// Returns whether a flush should be scheduled (a request is buffered).
    pub fn put_memoized(&mut self, key: &str, value: Value, io: &dyn FlowIo) -> bool {
        self.memoized.insert(key.to_string(), value);
        self.persist(io, None);
        !self.buffer.is_empty() && !self.navigated
    }

    /// Removes a keyed memoized value (`Journal::remove`).
    pub fn remove_memoized(&mut self, key: &str, io: &dyn FlowIo) {
        if self.memoized.remove(key).is_some() {
            self.persist(io, None);
        }
    }

    /// Buffers an uncached request for the next redirect (`urlFlow.ts:237-241`).
    ///
    /// Returns whether a flush should be scheduled.
    pub fn request(&mut self, index: u64, request: JsonRpcRequest, fingerprint: String) -> bool {
        self.buffer.push(BufferedRequest { index, request });
        self.request_keys.insert(index, fingerprint);
        !self.navigated
    }

    /// Resolves a replayed request from the journal (`urlChannel.ts:98-118`).
    ///
    /// Returns `None` when the slot has not completed yet (the request must be
    /// buffered for the next redirect), and an error when the call order has
    /// diverged from the one recorded before the redirect.
    pub fn replay(
        &self,
        index: u64,
        request: &JsonRpcRequest,
    ) -> Result<Option<JsonRpcResponse>, SignerError> {
        let Some(cached) = self.results.get(&index) else {
            return Ok(None);
        };
        let fingerprint = request_fingerprint(request);
        if self.recorded_request_key(index) != Some(fingerprint.as_str()) {
            return Err(SignerError::Transport(DIVERGENCE_REQUEST.to_string()));
        }
        // Re-stamp with this call's id; it may differ from the original send.
        let mut response = cached.clone();
        let id = request.id.as_ref().map(id_to_value).unwrap_or(Value::Null);
        let Some(object) = response.as_object_mut() else {
            return Err(SignerError::Transport(
                "the URL transport journal holds a non-object response".into(),
            ));
        };
        object.insert("id".to_string(), id);
        serde_json::from_value(response).map(Some).map_err(|error| {
            SignerError::Transport(format!(
                "invalid JSON-RPC response in the URL transport journal: {error}"
            ))
        })
    }

    /// Flushes the buffered batch, navigating to the signer
    /// (`urlFlow.ts:315-363`).
    ///
    /// Returns whether this call navigated.
    pub fn flush(&mut self, io: &dyn FlowIo) -> Result<bool, SignerError> {
        if self.buffer.is_empty() || self.navigated {
            return Ok(false);
        }
        self.navigate(io)?;
        Ok(true)
    }

    fn navigate(&mut self, io: &dyn FlowIo) -> Result<(), SignerError> {
        if self.navigated {
            return Ok(());
        }
        self.navigated = true;

        let batch = std::mem::take(&mut self.buffer);
        let state = io.random_uuid();
        let pending = PendingBatch {
            state: state.clone(),
            requests: batch
                .iter()
                .map(|buffered| PendingRequest {
                    index: buffered.index,
                    id: buffered
                        .request
                        .id
                        .as_ref()
                        .map(id_to_value)
                        .unwrap_or(Value::Null),
                })
                .collect(),
        };
        self.persist(io, Some(pending));

        let message = if batch.len() == 1 {
            serde_json::to_string(&batch[0].request)
        } else {
            let requests: Vec<&JsonRpcRequest> =
                batch.iter().map(|buffered| &buffered.request).collect();
            serde_json::to_string(&requests)
        }
        .map_err(|error| {
            SignerError::Transport(format!("could not serialise the signer request: {error}"))
        })?;
        let fragment = form_urlencode(&[
            ("message", &message),
            ("callback", &self.callback_url),
            ("state", &state),
        ]);
        // Re-assert the scheme at the navigation sink: `self.url` may have been
        // restored from storage, which the constructor's check never saw.
        if !is_secure_context_url(&self.url) {
            return Err(SignerError::Transport(NON_SECURE_NAVIGATION.to_string()));
        }
        io.assign(&format!("{}#{}", self.url, fragment))
            .map_err(|error| {
                SignerError::Transport(format!("could not navigate to the signer: {error}"))
            })
    }

    fn persist(&mut self, io: &dyn FlowIo, pending: Option<PendingBatch>) {
        if self.created_at.is_none() {
            self.created_at = Some(io.now_ms());
        }
        let stored = StoredFlow {
            created_at: self.created_at,
            url: Some(self.url.clone()),
            results: self.results.clone(),
            async_slots: self.async_slots.clone(),
            request_keys: self.request_keys.clone(),
            pending,
            memoized: self.memoized.clone(),
        };
        if let Ok(serialised) = serde_json::to_string(&stored) {
            io.storage_set(&self.storage_key, &serialised);
        }
    }

    /// The configured flow timeout.
    pub fn flow_timeout_ms(&self) -> u64 {
        self.flow_timeout_ms
    }
}

// ---------------------------------------------------------------------------
// wasm-js wiring
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-js")]
mod web {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use async_trait::async_trait;
    use futures::channel::oneshot;
    use gloo_timers::callback::Timeout;
    use wasm_bindgen::JsValue;
    use web_sys::{Crypto, History, Location, Storage, Window};

    use super::{
        DEFAULT_FLOW_TIMEOUT_MS, FlowIo, StoredFlow, UrlFlow, default_storage_key,
        is_secure_context_url, request_fingerprint, validate_callback_url,
    };
    use crate::client::transport::{
        Channel, Journal, JsonRpcRequest, JsonRpcResponse, SharedChannel, SharedJournal,
        SignerError, Transport,
    };

    /// Options for [`UrlTransport`].
    #[derive(Debug, Clone)]
    pub struct UrlTransportOptions {
        /// Time in milliseconds after which an unfinished flow is abandoned.
        pub flow_timeout_ms: u64,
        /// Overrides the journal key (default `icrc167:flow:<callback url>`).
        pub storage_key: Option<String>,
    }

    impl Default for UrlTransportOptions {
        fn default() -> Self {
            Self {
                flow_timeout_ms: DEFAULT_FLOW_TIMEOUT_MS,
                storage_key: None,
            }
        }
    }

    /// The `web-sys` implementation of [`FlowIo`].
    pub(crate) struct WebFlowIo {
        storage: Storage,
        location: Location,
        history: History,
        crypto: Crypto,
    }

    impl WebFlowIo {
        fn new(window: Window) -> Result<Self, SignerError> {
            let storage = window
                .session_storage()
                .map_err(|error| storage_error(&error))?
                .ok_or_else(|| SignerError::Transport("sessionStorage is not available".into()))?;
            let location = window.location();
            let history = window.history().map_err(|error| storage_error(&error))?;
            let crypto = window.crypto().map_err(|error| storage_error(&error))?;
            Ok(Self {
                storage,
                location,
                history,
                crypto,
            })
        }
    }

    fn storage_error(error: &JsValue) -> SignerError {
        SignerError::Transport(format!("browser storage is not available: {error:?}"))
    }

    impl FlowIo for WebFlowIo {
        fn storage_get(&self, key: &str) -> Option<String> {
            self.storage.get_item(key).ok().flatten()
        }

        fn storage_set(&self, key: &str, value: &str) {
            let _ = self.storage.set_item(key, value);
        }

        fn storage_remove(&self, key: &str) {
            let _ = self.storage.remove_item(key);
        }

        fn location_hash(&self) -> String {
            self.location.hash().unwrap_or_default()
        }

        fn location_path(&self) -> String {
            let path = self.location.pathname().unwrap_or_default();
            let search = self.location.search().unwrap_or_default();
            format!("{path}{search}")
        }

        fn strip_fragment(&self) {
            if let Ok(path) = self.location.pathname() {
                let search = self.location.search().unwrap_or_default();
                let _ = self.history.replace_state_with_url(
                    &JsValue::NULL,
                    "",
                    Some(&format!("{path}{search}")),
                );
            }
        }

        fn assign(&self, url: &str) -> Result<(), String> {
            // ICRC-167 navigates with `replace` so the relying-party document
            // does not stay in the back stack behind the signer.
            self.location
                .replace(url)
                .map_err(|error| format!("{error:?}"))
        }

        fn now_ms(&self) -> u64 {
            web_sys::js_sys::Date::now().max(0.0) as u64
        }

        fn random_uuid(&self) -> String {
            self.crypto.random_uuid()
        }
    }

    impl std::fmt::Debug for WebFlowIo {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WebFlowIo").finish_non_exhaustive()
        }
    }

    /// Shared state between the transport, the channel and the journal.
    struct Inner {
        flow: RefCell<UrlFlow>,
        io: WebFlowIo,
        flush_scheduled: Cell<bool>,
        pending_responses: RefCell<Vec<oneshot::Sender<Result<JsonRpcResponse, SignerError>>>>,
    }

    impl Inner {
        fn schedule_flush(self: &Rc<Self>) {
            if self.flush_scheduled.replace(true) {
                return;
            }
            let weak = Rc::downgrade(self);
            let timeout = Timeout::new(0, move || {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                inner.flush_scheduled.set(false);
                let outcome = inner.flow.borrow_mut().flush(&inner.io);
                if let Err(error) = outcome {
                    inner.fail_pending(&error.to_string());
                }
            });
            // The flush is one-shot; leaking the timer handle keeps this
            // closure alive without racing a drop from inside its own callback.
            timeout.forget();
        }

        fn fail_pending(&self, message: &str) {
            let senders: Vec<_> = self.pending_responses.borrow_mut().drain(..).collect();
            for sender in senders {
                let _ = sender.send(Err(SignerError::Transport(message.to_string())));
            }
        }
    }

    /// The ICRC-167 browser URL transport.
    ///
    /// Construct it on the load of the flow's route; the first buffered request
    /// navigates to the signer and the return load replays the journal.
    pub struct UrlTransport {
        inner: Rc<Inner>,
    }

    impl std::fmt::Debug for UrlTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UrlTransport").finish_non_exhaustive()
        }
    }

    impl UrlTransport {
        /// Creates the transport with the upstream defaults.
        ///
        /// Fails when the URL is not a secure context, the callback URL is not
        /// absolute or carries a fragment, or the browser storage is missing
        /// (`urlTransport.ts:109-133`).
        pub fn new(url: &str, callback_url: &str) -> Result<Self, SignerError> {
            Self::with_options(url, callback_url, UrlTransportOptions::default())
        }

        /// Creates the transport with explicit options.
        pub fn with_options(
            url: &str,
            callback_url: &str,
            options: UrlTransportOptions,
        ) -> Result<Self, SignerError> {
            if !is_secure_context_url(url) {
                return Err(SignerError::Transport("Invalid signer RPC url".into()));
            }
            validate_callback_url(callback_url)?;
            let window = web_sys::window().ok_or_else(|| {
                SignerError::Transport("the browser window is not available".into())
            })?;
            let io = WebFlowIo::new(window)?;
            let storage_key = options
                .storage_key
                .clone()
                .unwrap_or_else(|| default_storage_key(callback_url));
            let flow = UrlFlow::new(
                url,
                callback_url,
                &storage_key,
                options.flow_timeout_ms,
                &io,
            );
            Ok(Self {
                inner: Rc::new(Inner {
                    flow: RefCell::new(flow),
                    io,
                    flush_scheduled: Cell::new(false),
                    pending_responses: RefCell::new(Vec::new()),
                }),
            })
        }

        /// The effective redirect target, for diagnostics.
        pub fn url(&self) -> String {
            self.inner.flow.borrow().url().to_string()
        }

        /// The journal this transport persists, for the authentication client.
        #[allow(clippy::arc_with_non_send_sync)] // the seam is `Arc`, wasm is single-threaded
        pub fn journal(&self) -> SharedJournal {
            std::sync::Arc::new(UrlJournal {
                inner: Rc::clone(&self.inner),
            })
        }
    }

    #[async_trait(?Send)]
    impl Transport for UrlTransport {
        fn open(&self) -> Result<(), SignerError> {
            // ICRC-167 reaches the signer by navigation, which does not need a
            // user gesture. When a batch is already buffered, navigate now
            // (synchronously, inside the caller's gesture); otherwise the
            // macrotask flush coalesces concurrent requests as upstream does.
            self.inner.flow.borrow_mut().flush(&self.inner.io)?;
            Ok(())
        }

        #[allow(clippy::arc_with_non_send_sync)] // the seam is `Arc`, wasm is single-threaded
        async fn establish_channel(&self) -> Result<SharedChannel, SignerError> {
            Ok(std::sync::Arc::new(UrlChannel {
                inner: Rc::clone(&self.inner),
                closed: Cell::new(false),
            }))
        }

        fn journal(&self) -> Option<SharedJournal> {
            Some(UrlTransport::journal(self))
        }
    }

    /// The keyed journal the authentication client uses to survive the redirect.
    ///
    /// Upstream exposes positional `memoize(produce)` steps that share the
    /// channel's call-order counter; this port's seam is a keyed
    /// [`Journal`](crate::client::transport::Journal), so values are journaled
    /// by key in the same persisted [`StoredFlow`] (the `memoized` field).
    pub struct UrlJournal {
        inner: Rc<Inner>,
    }

    impl Journal for UrlJournal {
        fn get(&self, key: &str) -> Option<serde_json::Value> {
            self.inner.flow.borrow().memoized(key).cloned()
        }

        fn put(&self, key: &str, value: serde_json::Value) {
            let schedule = self
                .inner
                .flow
                .borrow_mut()
                .put_memoized(key, value, &self.inner.io);
            if schedule {
                self.inner.schedule_flush();
            }
        }

        fn remove(&self, key: &str) {
            self.inner
                .flow
                .borrow_mut()
                .remove_memoized(key, &self.inner.io);
        }
    }

    /// The ICRC-167 channel: resolves from the journal on a return load,
    /// buffers for the next redirect on a fresh one.
    pub struct UrlChannel {
        inner: Rc<Inner>,
        closed: Cell<bool>,
    }

    impl std::fmt::Debug for UrlChannel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UrlChannel")
                .field("closed", &self.closed.get())
                .finish()
        }
    }

    impl UrlChannel {
        fn ensure_open(&self) -> Result<(), SignerError> {
            if self.closed.get() {
                return Err(SignerError::ChannelClosed);
            }
            Ok(())
        }
    }

    #[async_trait(?Send)]
    impl Channel for UrlChannel {
        async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, SignerError> {
            self.ensure_open()?;
            if super::is_notification(&request) {
                return Err(SignerError::Transport(
                    super::NOTIFICATIONS_UNSUPPORTED.to_string(),
                ));
            }
            let index = self.inner.flow.borrow_mut().next();
            let fingerprint = request_fingerprint(&request);
            let replay = {
                let flow = self.inner.flow.borrow();
                flow.replay(index, &request)?
            };
            if let Some(response) = replay {
                return Ok(response);
            }
            // Buffer for the next redirect. The response never arrives on this
            // load — the document is torn down when the flush navigates — so
            // the future stays pending until the navigation fails or the
            // channel closes.
            let schedule = self
                .inner
                .flow
                .borrow_mut()
                .request(index, request, fingerprint);
            let (sender, receiver) = oneshot::channel();
            self.inner.pending_responses.borrow_mut().push(sender);
            if schedule {
                self.inner.schedule_flush();
            }
            receiver.await.map_err(|_| SignerError::ChannelClosed)?
        }

        fn is_closed(&self) -> bool {
            self.closed.get()
        }

        async fn close(&self) -> Result<(), SignerError> {
            self.closed.set(true);
            self.inner.fail_pending("the signer channel is closed");
            Ok(())
        }
    }

    /// Re-exported for tests and diagnostics: the journal shape persisted for a
    /// callback URL.
    pub fn read_journal(callback_url: &str) -> Option<StoredFlow> {
        let window = web_sys::window()?;
        let storage = window.session_storage().ok()??;
        let raw = storage
            .get_item(&default_storage_key(callback_url))
            .ok()??;
        serde_json::from_str(&raw).ok()
    }
}

#[cfg(feature = "wasm-js")]
pub use web::{UrlChannel, UrlJournal, UrlTransport, UrlTransportOptions, read_journal};

// ---------------------------------------------------------------------------
// Tests: pure journal/replay/flush contract (native-runnable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, VecDeque};

    use serde_json::json;

    use super::*;

    const URL_: &str = "https://signer.example.com/icrc-167";
    const CALLBACK: &str = "https://relying.example.com/signer-callback";
    const KEY: &str = "icrc167:flow";
    const NOW: u64 = 1000;

    #[derive(Default)]
    struct TestIo {
        storage: RefCell<BTreeMap<String, String>>,
        hash: RefCell<String>,
        path: RefCell<String>,
        assigned: RefCell<Vec<String>>,
        stripped: Cell<u32>,
        now: Cell<u64>,
        uuids: RefCell<VecDeque<String>>,
    }

    impl TestIo {
        fn new() -> Self {
            let io = Self::default();
            io.now.set(NOW);
            io.path.replace("/signer-callback".into());
            io
        }

        fn seed(&self, value: &str) {
            self.storage
                .borrow_mut()
                .insert(KEY.to_string(), value.to_string());
        }

        fn stored(&self) -> Option<String> {
            self.storage.borrow().get(KEY).cloned()
        }

        fn stored_json(&self) -> Option<Value> {
            self.stored().map(|raw| serde_json::from_str(&raw).unwrap())
        }

        fn assigned_url(&self) -> String {
            self.assigned
                .borrow()
                .first()
                .cloned()
                .expect("no navigation")
        }

        fn assigned_params(&self) -> FragmentParams {
            let url = self.assigned_url();
            parse_fragment(
                url.split_once('#')
                    .map(|(_, hash)| hash)
                    .unwrap_or_default(),
            )
        }

        fn uuid(&self, value: &str) {
            self.uuids.borrow_mut().push_back(value.to_string());
        }
    }

    impl FlowIo for TestIo {
        fn storage_get(&self, _key: &str) -> Option<String> {
            self.stored()
        }

        fn storage_set(&self, _key: &str, value: &str) {
            self.storage
                .borrow_mut()
                .insert(KEY.to_string(), value.to_string());
        }

        fn storage_remove(&self, _key: &str) {
            self.storage.borrow_mut().remove(KEY);
        }

        fn location_hash(&self) -> String {
            self.hash.borrow().clone()
        }

        fn location_path(&self) -> String {
            self.path.borrow().clone()
        }

        fn strip_fragment(&self) {
            self.stripped.set(self.stripped.get() + 1);
            self.hash.replace(String::new());
        }

        fn assign(&self, url: &str) -> Result<(), String> {
            self.assigned.borrow_mut().push(url.to_string());
            Ok(())
        }

        fn now_ms(&self) -> u64 {
            self.now.get()
        }

        fn random_uuid(&self) -> String {
            self.uuids
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| "S".to_string())
        }
    }

    fn flow(io: &TestIo) -> UrlFlow {
        UrlFlow::new(URL_, CALLBACK, KEY, DEFAULT_FLOW_TIMEOUT_MS, io)
    }

    fn request(id: i64, method: &str) -> JsonRpcRequest {
        JsonRpcRequest::new(id, method, None)
    }

    fn response(id: i64, result: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    fn hash_for(message: &Value, state: &str) -> String {
        format!(
            "#{}",
            form_urlencode(&[
                ("message", &serde_json::to_string(message).unwrap()),
                ("callback", CALLBACK),
                ("state", state),
            ])
        )
    }

    fn returned_flow(io: &TestIo, responses: &Value, state: &str) -> UrlFlow {
        io.hash.replace(hash_for(responses, state));
        flow(io)
    }

    // -- secure-context URL rules (urlFlow.test.ts:75-90) ------------------

    #[test]
    fn secure_context_urls_match_upstream_table() {
        let cases = [
            ("https://signer.example.com/x", true),
            ("http://localhost/x", true),
            ("http://app.localhost/x", true),
            ("http://127.0.0.1/x", true),
            ("http://127.1/x", true),
            ("http://[::1]/x", true),
            ("http://signer.example.com/x", false),
            ("http://127.999.999.999/x", false),
            ("ftp://127.0.0.1/x", false),
            ("not a url", false),
        ];
        for (value, expected) in cases {
            assert_eq!(is_secure_context_url(value), expected, "{value}");
        }
    }

    #[test]
    fn numeric_looking_hosts_are_ipv4_but_hex_domains_are_not() {
        // A host whose labels are all hex letters must stay a domain name, not
        // be rejected by the IPv4 parser.
        assert_eq!(
            origin_of("https://dead.beef/x").as_deref(),
            Some("https://dead.beef")
        );
        assert_eq!(origin_of("https://abc/x").as_deref(), Some("https://abc"));
        assert_eq!(
            origin_of("http://0x7f.0.0.1/x").as_deref(),
            Some("http://127.0.0.1")
        );
        // A numeric host that cannot be an IPv4 address is invalid, like
        // `new URL()` throwing.
        assert_eq!(origin_of("http://127.999.999.999/x"), None);
    }

    #[test]
    fn origin_drops_default_ports_and_keeps_others() {
        assert_eq!(
            origin_of("https://signer.example.com:443/sign").as_deref(),
            Some("https://signer.example.com")
        );
        assert_eq!(
            origin_of("http://127.0.0.1:8080/x").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            origin_of("https://signer.example.com/sign").as_deref(),
            Some("https://signer.example.com")
        );
    }

    #[test]
    fn callback_url_validation_matches_upstream() {
        assert!(validate_callback_url(CALLBACK).is_ok());
        let fragment = validate_callback_url(&format!("{CALLBACK}#x")).unwrap_err();
        assert!(fragment.to_string().contains("fragment"));
        assert!(validate_callback_url("not a url").is_err());
    }

    // -- call-order slots --------------------------------------------------

    #[test]
    fn hands_out_sequential_call_order_slots() {
        let io = TestIo::new();
        let mut flow = flow(&io);
        assert_eq!(flow.next(), 0);
        assert_eq!(flow.next(), 1);
    }

    // -- batching and navigation (urlFlow.test.ts:99-132) ------------------

    #[test]
    fn navigates_a_single_buffered_request() {
        let io = TestIo::new();
        io.uuid("S");
        let mut flow = flow(&io);
        let index = flow.next();
        assert!(flow.request(index, request(1, "icrc27_accounts"), "key".into()));
        assert!(io.assigned.borrow().is_empty());
        assert!(flow.flush(&io).unwrap());

        let params = io.assigned_params();
        let message: Value = serde_json::from_str(&params.message.unwrap()).unwrap();
        assert_eq!(
            message,
            json!({"jsonrpc": "2.0", "id": 1, "method": "icrc27_accounts"})
        );
        let stored = io.stored_json().unwrap();
        assert_eq!(
            stored["pending"],
            json!({"state": "S", "requests": [{"index": 0, "id": 1}]})
        );
        assert_eq!(stored["url"], URL_);
        assert_eq!(stored["createdAt"], NOW);
    }

    #[test]
    fn coalesces_concurrent_requests_into_one_batch() {
        let io = TestIo::new();
        io.uuid("S");
        let mut flow = flow(&io);
        let first = flow.next();
        let second = flow.next();
        flow.request(first, request(1, "icrc34_delegation"), "a".into());
        flow.request(second, request(2, "icrc27_accounts"), "b".into());
        flow.flush(&io).unwrap();

        let params = io.assigned_params();
        let message: Value = serde_json::from_str(&params.message.unwrap()).unwrap();
        assert_eq!(
            message,
            json!([
                {"jsonrpc": "2.0", "id": 1, "method": "icrc34_delegation"},
                {"jsonrpc": "2.0", "id": 2, "method": "icrc27_accounts"}
            ])
        );
        assert_eq!(params.state.as_deref(), Some("S"));
        assert_eq!(
            io.stored_json().unwrap()["pending"]["requests"],
            json!([{"index": 0, "id": 1}, {"index": 1, "id": 2}])
        );
    }

    #[test]
    fn navigates_at_most_once_per_load() {
        let io = TestIo::new();
        io.uuid("S");
        io.uuid("S2");
        let mut flow = flow(&io);
        let first = flow.next();
        flow.request(first, request(1, "a"), "a".into());
        flow.flush(&io).unwrap();
        let second = flow.next();
        flow.request(second, request(2, "b"), "b".into());
        assert!(!flow.flush(&io).unwrap());
        assert_eq!(io.assigned.borrow().len(), 1);
    }

    // -- fresh vs return (urlFlow.test.ts:134-176) -------------------------

    #[test]
    fn fresh_load_ignores_a_completed_leftover_journal() {
        let io = TestIo::new();
        io.uuid("S2");
        let cached = response(1, json!({"accounts": []}));
        io.seed(
            &serde_json::to_string(&json!({"createdAt": NOW, "results": {"0": cached}})).unwrap(),
        );
        let mut flow = flow(&io);
        assert_eq!(flow.get(0), None);
        let index = flow.next();
        flow.request(index, request(9, "icrc27_accounts"), "fresh".into());
        flow.flush(&io).unwrap();
        assert_eq!(io.assigned.borrow().len(), 1);
        assert_eq!(io.stored_json().unwrap()["results"], json!({}));
        assert_eq!(
            io.stored_json().unwrap()["pending"],
            json!({"state": "S2", "requests": [{"index": 0, "id": 9}]})
        );
    }

    #[test]
    fn fresh_load_ignores_a_leftover_pending_without_a_message() {
        let io = TestIo::new();
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "results": {},
                "pending": {"state": "S", "requests": [{"index": 0, "id": 1}]}
            }))
            .unwrap(),
        );
        let flow = flow(&io);
        assert_eq!(flow.get(0), None);
        assert!(!flow.is_return_load());
        assert!(io.assigned.borrow().is_empty());
    }

    // -- absorbing a signer return (urlFlow.test.ts:223-284) ---------------

    #[test]
    fn absorbs_a_batch_return_by_id_and_strips_the_fragment() {
        let io = TestIo::new();
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "results": {},
                "pending": {
                    "state": "S",
                    "requests": [{"index": 0, "id": 1}, {"index": 1, "id": 2}]
                }
            }))
            .unwrap(),
        );
        let responses = json!([response(1, json!({"a": 1})), response(2, json!({"b": 2}))]);
        let flow = returned_flow(&io, &responses, "S");
        assert!(flow.is_return_load());
        assert_eq!(flow.get(0), Some(&response(1, json!({"a": 1}))));
        assert_eq!(flow.get(1), Some(&response(2, json!({"b": 2}))));
        assert_eq!(io.stripped.get(), 1);
        let stored = io.stored_json().unwrap();
        assert_eq!(stored["results"]["0"], response(1, json!({"a": 1})));
        assert!(stored.get("pending").is_none());
    }

    #[test]
    fn strips_a_mismatched_fragment_without_absorbing_it() {
        let io = TestIo::new();
        let seeded = serde_json::to_string(&json!({
            "createdAt": NOW,
            "results": {},
            "pending": {"state": "S", "requests": [{"index": 0, "id": 1}]}
        }))
        .unwrap();
        io.seed(&seeded);
        let flow = returned_flow(&io, &response(1, json!({})), "nope");
        assert_eq!(flow.get(0), None);
        assert!(!flow.is_return_load());
        assert_eq!(io.stripped.get(), 1);
        assert_eq!(io.stored().as_deref(), Some(seeded.as_str()));
    }

    #[test]
    fn preserves_memoized_values_when_absorbing_a_return() {
        let io = TestIo::new();
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "results": {"0": "nonce"},
                "pending": {"state": "S", "requests": [{"index": 1, "id": 9}]}
            }))
            .unwrap(),
        );
        let flow = returned_flow(&io, &response(9, json!({"ok": true})), "S");
        assert_eq!(flow.get(0), Some(&json!("nonce")));
        assert_eq!(flow.get(1), Some(&response(9, json!({"ok": true}))));
    }

    // -- timeout -----------------------------------------------------------

    #[test]
    fn ignores_and_clears_an_expired_flow() {
        let io = TestIo::new();
        io.now.set(NOW + 700_000);
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "results": {"0": "nonce"},
                "pending": {"state": "S", "requests": [{"index": 1, "id": 9}]}
            }))
            .unwrap(),
        );
        let flow = UrlFlow::new(URL_, CALLBACK, KEY, 600_000, &io);
        assert_eq!(flow.get(0), None);
        assert_eq!(io.stored(), None);
    }

    // -- second hop (urlFlow.test.ts:300-376) ------------------------------

    #[test]
    fn second_hop_uses_the_target_persisted_on_the_first_load() {
        let io = TestIo::new();
        io.uuid("S1");
        let mut first = flow(&io);
        let index = first.next();
        first.request(index, request(1, "icrc34_delegation"), "first".into());
        first.flush(&io).unwrap();
        assert_eq!(io.stored_json().unwrap()["url"], URL_);

        let responses = response(1, json!({"ok": true}));
        io.hash.replace(hash_for(&responses, "S1"));
        let mut second = UrlFlow::new(
            "https://default.example.com/",
            CALLBACK,
            KEY,
            DEFAULT_FLOW_TIMEOUT_MS,
            &io,
        );
        assert_eq!(second.get(0), Some(&responses));
        io.uuid("S2");
        let index = second.next();
        second.request(index, request(2, "icrc34_delegation"), "second".into());
        second.flush(&io).unwrap();
        let assigned = io.assigned.borrow().last().cloned().unwrap();
        assert!(assigned.contains(URL_), "{assigned}");
        assert!(!assigned.contains("default.example.com"), "{assigned}");
    }

    #[test]
    fn refuses_to_navigate_to_a_non_secure_target_restored_from_storage() {
        let io = TestIo::new();
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "url": "http://signer.example.com/evil",
                "results": {},
                "pending": {"state": "S", "requests": [{"index": 0, "id": 1}]}
            }))
            .unwrap(),
        );
        let responses = response(1, json!({"ok": true}));
        let mut flow = returned_flow(&io, &responses, "S");
        let index = flow.next();
        flow.request(index, request(2, "icrc34_delegation"), "second".into());
        let error = flow.flush(&io).unwrap_err();
        assert!(error.to_string().contains("non-secure-context"), "{error}");
        assert!(io.assigned.borrow().is_empty());
    }

    // -- replay, divergence guard, re-stamping (urlChannel.test.ts:93-170) --

    #[test]
    fn replays_a_response_and_restamps_it_with_this_calls_id() {
        let io = TestIo::new();
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "results": {},
                "requestKeys": {"0": request_fingerprint(&request(1, "icrc27_accounts"))},
                "pending": {"state": "S", "requests": [{"index": 0, "id": 1}]}
            }))
            .unwrap(),
        );
        let flow = returned_flow(&io, &response(1, json!({"accounts": []})), "S");
        let replay = flow
            .replay(0, &request(77, "icrc27_accounts"))
            .unwrap()
            .expect("replayed");
        assert_eq!(replay.id(), &JsonRpcId::Number(77));
    }

    #[test]
    fn rejects_a_replay_whose_request_diverged() {
        let io = TestIo::new();
        io.seed(
            &serde_json::to_string(&json!({
                "createdAt": NOW,
                "results": {},
                "requestKeys": {"0": request_fingerprint(&request(1, "icrc34_delegation"))},
                "pending": {"state": "S", "requests": [{"index": 0, "id": 1}]}
            }))
            .unwrap(),
        );
        let flow = returned_flow(&io, &response(1, json!({})), "S");
        let error = flow.replay(0, &request(2, "icrc27_accounts")).unwrap_err();
        assert!(error.to_string().contains("diverged"), "{error}");
    }

    #[test]
    fn unmatched_slot_reports_no_replay() {
        let io = TestIo::new();
        let flow = flow(&io);
        assert!(
            flow.replay(0, &request(1, "icrc27_accounts"))
                .unwrap()
                .is_none()
        );
    }

    // -- keyed memoize (Journal) -------------------------------------------

    #[test]
    fn memoized_values_are_keyed_and_survive_a_return_load() {
        let io = TestIo::new();
        io.uuid("S");
        let mut first = flow(&io);
        let index = first.next();
        first.request(index, request(1, "icrc34_delegation"), "k".into());
        assert!(first.put_memoized("derivation-origin", json!("https://app.example.com"), &io));
        first.flush(&io).unwrap();

        let responses = response(1, json!({"ok": true}));
        let second = returned_flow(&io, &responses, "S");
        assert_eq!(
            second.memoized("derivation-origin"),
            Some(&json!("https://app.example.com"))
        );
        assert_eq!(second.get(0), Some(&responses));
        assert_eq!(second.recorded_request_key(0), Some("k"));
        // A fresh load never sees a completed flow's values.
        let io = TestIo::new();
        assert_eq!(flow(&io).memoized("derivation-origin"), None);
    }

    #[test]
    fn removing_a_memoized_value_rewrites_the_journal() {
        let io = TestIo::new();
        let mut flow = flow(&io);
        flow.put_memoized("session-pending", json!({"key": "x"}), &io);
        assert!(io.stored_json().unwrap()["results"].is_object());
        flow.remove_memoized("session-pending", &io);
        let stored = io.stored_json().unwrap();
        assert!(stored.get("memoized").is_none());
    }

    // -- codec -------------------------------------------------------------

    #[test]
    fn fragment_codec_matches_urlsearchparams() {
        let hash = format!(
            "#{}",
            form_urlencode(&[
                (
                    "message",
                    r#"{"jsonrpc":"2.0","id":1,"result":{"a":"b c"}}"#
                ),
                ("callback", "https://relying.example.com/cb?x=1&y=2"),
                ("state", "3f5c"),
            ])
        );
        assert_eq!(
            hash,
            "#message=%7B%22jsonrpc%22%3A%222.0%22%2C%22id%22%3A1%2C%22result%22%3A%7B%22a%22%3A%22b+c%22%7D%7D&callback=https%3A%2F%2Frelying.example.com%2Fcb%3Fx%3D1%26y%3D2&state=3f5c"
        );
        let params = parse_fragment(&hash);
        assert_eq!(
            params.message.as_deref(),
            Some(r#"{"jsonrpc":"2.0","id":1,"result":{"a":"b c"}}"#)
        );
        assert_eq!(params.state.as_deref(), Some("3f5c"));
    }

    #[test]
    fn journal_serialises_with_upstream_field_names() {
        let io = TestIo::new();
        let mut flow = flow(&io);
        flow.put_memoized("k", json!(1), &io);
        let stored = io.stored_json().unwrap();
        for field in ["createdAt", "url", "results", "asyncSlots", "requestKeys"] {
            assert!(stored.get(field).is_some(), "missing {field}: {stored}");
        }
        assert_eq!(stored["asyncSlots"], json!([]));
    }

    #[test]
    fn fingerprints_cover_method_and_params_only() {
        let plain = request(1, "icrc27_accounts");
        let same = request(2, "icrc27_accounts");
        assert_eq!(request_fingerprint(&plain), request_fingerprint(&same));
        let with_params = JsonRpcRequest::new(3, "icrc27_accounts", Some(json!({"a": 1})));
        assert_ne!(
            request_fingerprint(&plain),
            request_fingerprint(&with_params)
        );
        assert!(request_fingerprint(&plain).contains(r#""params":null"#));
    }

    #[test]
    fn notifications_are_recognised() {
        assert!(is_notification(&JsonRpcRequest::notification(
            "icrc29_close_channel",
            None
        )));
        assert!(is_notification(&JsonRpcRequest::new(
            JsonRpcId::Null,
            "x",
            None
        )));
        assert!(!is_notification(&request(1, "x")));
    }
}

// ---------------------------------------------------------------------------
// Browser tests (`wasm-pack test --headless --chrome`)
// ---------------------------------------------------------------------------
//
// These exercise the real `web-sys` wiring: `sessionStorage`, the fragment
// codec through `location.hash`, fragment stripping through
// `history.replaceState`, and a channel replaying a journaled response. They
// need a browser (the repository's `wasm-pack test --headless --chrome`
// target); the pure journal tests above run natively.

#[cfg(all(test, feature = "wasm-js"))]
mod browser_tests {
    use wasm_bindgen_test::*;

    use super::*;
    use crate::client::transport::Transport;

    wasm_bindgen_test_configure!(run_in_browser);

    fn window() -> web_sys::Window {
        web_sys::window().expect("a browser window")
    }

    fn storage() -> web_sys::Storage {
        window()
            .session_storage()
            .expect("sessionStorage")
            .expect("sessionStorage")
    }

    fn test_callback() -> String {
        format!(
            "{}/icrc167-browser-test",
            window().location().origin().expect("origin")
        )
    }

    #[wasm_bindgen_test]
    fn url_transport_journals_a_memoized_value_through_session_storage() {
        let callback = test_callback();
        let key = default_storage_key(&callback);
        let _ = storage().remove_item(&key);

        let transport =
            UrlTransport::new("https://signer.example.com/icrc-167", &callback).expect("transport");
        assert_eq!(transport.url(), "https://signer.example.com/icrc-167");
        let journal = transport.journal();

        assert_eq!(journal.get("derivation-origin"), None);
        let value = serde_json::json!("https://app.example.com");
        journal.put("derivation-origin", value.clone());
        assert_eq!(journal.get("derivation-origin"), Some(value.clone()));

        let stored = read_journal(&callback).expect("journal in sessionStorage");
        assert_eq!(stored.memoized.get("derivation-origin"), Some(&value));
        assert_eq!(
            stored.url.as_deref(),
            Some("https://signer.example.com/icrc-167")
        );

        journal.remove("derivation-origin");
        assert_eq!(journal.get("derivation-origin"), None);
        let _ = storage().remove_item(&key);
    }

    #[wasm_bindgen_test]
    async fn url_channel_replays_a_returned_response_and_strips_the_fragment() {
        let callback = test_callback();
        let key = default_storage_key(&callback);
        let _ = storage().remove_item(&key);

        // Seed the journal a first load would have left behind.
        let request = JsonRpcRequest::new(1, "icrc27_accounts", None);
        let journal = serde_json::json!({
            "createdAt": web_sys::js_sys::Date::now() as u64,
            "url": "https://signer.example.com/icrc-167",
            "results": {},
            "asyncSlots": [],
            "requestKeys": {"0": request_fingerprint(&request)},
            "pending": {"state": "S", "requests": [{"index": 0, "id": 1}]}
        });
        storage()
            .set_item(&key, &journal.to_string())
            .expect("seed journal");

        // The signer's return fragment.
        let returned = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"accounts": []}
        });
        let fragment = form_urlencode(&[
            ("message", &returned.to_string()),
            ("callback", &callback),
            ("state", "S"),
        ]);
        window()
            .location()
            .set_hash(&fragment)
            .expect("set return fragment");

        let transport =
            UrlTransport::new("https://signer.example.com/icrc-167", &callback).expect("transport");
        assert_eq!(
            window().location().hash().unwrap_or_default(),
            "",
            "a response fragment must be stripped from history"
        );

        let channel = transport.establish_channel().await.expect("channel");
        let replay = channel
            .send(JsonRpcRequest::new(77, "icrc27_accounts", None))
            .await
            .expect("replayed response");
        assert_eq!(replay.id(), &JsonRpcId::Number(77));
        assert!(matches!(replay, JsonRpcResponse::Success { .. }));

        // A request that differs from the journaled one is a divergence.
        let divergence = channel
            .send(JsonRpcRequest::new(78, "icrc34_delegation", None))
            .await;
        assert!(divergence.is_err(), "the divergence guard must reject");

        let _ = storage().remove_item(&key);
        let _ = window().location().set_hash("");
    }
}
