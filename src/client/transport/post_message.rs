//! The ICRC-29 `postMessage` window transport (wasm).
//!
//! Port of `@icp-sdk/signer@6.1.0`'s `web/postMessageTransport.ts`,
//! `web/postMessageChannel.ts` and `web/heartbeat/client.ts`.
//!
//! The transport opens (or reuses) a window at the signer URL and establishes a
//! channel with the ICRC-29 heartbeat handshake: it polls `icrc29_status` at
//! [`STATUS_POLLING_RATE_MS`] until the signer answers with `pending` or
//! `ready`, then keeps polling to maintain the channel. `open()` is synchronous
//! on purpose: a browser only lets a popup start inside the user gesture that
//! asked for it, and the authentication client calls `open()` from its
//! synchronous entry point before it awaits anything.
//!
//! The heartbeat state machine ([`HeartbeatState`]) and the ICRC-29 message
//! builders are platform-neutral and unit-tested natively; the `web` module is
//! the `web-sys` wiring, and its tests need a browser (the Playwright harness).
//!
//! Protocol constants (`docs/port/protocols/signer-protocol.md` §9.4):
//!
//! - window name: `` `${new URL(url).origin}-signer-window` ``
//!   (`postMessageTransport.ts:154`)
//! - establish timeout `120_000` ms, pending timeout `300_000` ms, disconnect
//!   timeout `2_000` ms, status polling `300` ms (`postMessageTransport.ts:47-50`)
//! - status poll: `{jsonrpc: "2.0", id, method: "icrc29_status"}` posted to the
//!   signer window with target origin `"*"` (`heartbeat/client.ts:204-206`)
//! - status response: `{jsonrpc: "2.0", id, result: "pending" | "ready"}`, only
//!   accepted when `event.source === signerWindow` (`heartbeat/client.ts:191-198`)
//! - channel responses: only accepted when `event.source === signerWindow`
//!   **and** `event.origin === signerOrigin` (`postMessageChannel.ts:74-84`)

use serde_json::Value;

use super::{
    JsonRpcId, JsonRpcRequest,
    url::{is_json_rpc_response, parse_url, response_id},
};

/// How long to wait for the ICRC-29 handshake, in milliseconds.
///
/// `PostMessageTransportOptions.establishTimeout` default
/// (`postMessageTransport.ts:47`).
pub const ESTABLISH_TIMEOUT_MS: u64 = 120_000;

/// How long the channel may stay `pending` without a heartbeat, in
/// milliseconds (`postMessageTransport.ts:48`).
pub const PENDING_TIMEOUT_MS: u64 = 300_000;

/// How long without a heartbeat before the channel counts as disconnected, in
/// milliseconds (`postMessageTransport.ts:49`).
pub const DISCONNECT_TIMEOUT_MS: u64 = 2_000;

/// The interval between `icrc29_status` polls, in milliseconds
/// (`postMessageTransport.ts:50`).
pub const STATUS_POLLING_RATE_MS: u64 = 300;

/// The ICRC-29 status method (`heartbeat/client.ts:205`).
pub const ICRC29_STATUS_METHOD: &str = "icrc29_status";

/// The notification posted when this end closes the channel.
///
/// The ICRC-29 window transport closes the signer window; the notification lets
/// a signer that keeps state release it first. It is fire-and-forget (no id).
pub const ICRC29_CLOSE_CHANNEL_METHOD: &str = "icrc29_close_channel";

/// The suffix of the signer window name, applied to the signer's origin
/// (`postMessageTransport.ts:154`).
pub const SIGNER_WINDOW_NAME_SUFFIX: &str = "-signer-window";

/// The delay before a heartbeat status poll, in milliseconds.
///
/// `HeartbeatClient` schedules the first poll one interval after it starts
/// (`heartbeat/client.ts:115-118`), so a handshake never posts synchronously.
pub const FIRST_STATUS_POLL_DELAY_MS: u64 = STATUS_POLLING_RATE_MS;

/// The ICRC-29 signer status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerStatus {
    /// The signer window is open but has not finished loading.
    Pending,
    /// The signer is ready to receive requests.
    Ready,
}

impl SignerStatus {
    /// Reads a status from a JSON-RPC `result`.
    pub fn from_value(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "pending" => Some(Self::Pending),
            "ready" => Some(Self::Ready),
            _ => None,
        }
    }

    /// The wire spelling of the status.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
        }
    }
}

/// The `icrc29_status` request a heartbeat poll sends (`heartbeat/client.ts:204-206`).
pub fn status_request(id: &str) -> JsonRpcRequest {
    JsonRpcRequest::new(id.to_string(), ICRC29_STATUS_METHOD, None)
}

/// The fire-and-forget `icrc29_close_channel` notification.
pub fn close_channel_notification() -> JsonRpcRequest {
    JsonRpcRequest::notification(ICRC29_CLOSE_CHANNEL_METHOD, None)
}

/// Classifies an incoming `postMessage` payload as an ICRC-29 status response.
///
/// Port of `HeartbeatClient.#receiveStatusResponse`'s shape check
/// (`heartbeat/client.ts:182-202`): an object with `jsonrpc: "2.0"`, a
/// string-or-number `id` and `result` of `"pending"` or `"ready"`.
pub fn classify_status_response(value: &Value) -> Option<(JsonRpcId, SignerStatus)> {
    if !is_json_rpc_response(value) {
        return None;
    }
    let status = SignerStatus::from_value(value.get("result")?)?;
    let id = response_id(value)?;
    Some((id, status))
}

/// The window name a signer window is opened (or reused) under.
pub fn signer_window_name(signer_url: &str) -> Option<String> {
    parse_url(signer_url).map(|url| format!("{}{SIGNER_WINDOW_NAME_SUFFIX}", url.origin()))
}

/// The narrower secure-context rule of the window transport
/// (`postMessageTransport.ts:103-114`): `https`, `127.0.0.1`, or a host whose
/// last label is `localhost`.
pub fn is_secure_signer_window_url(value: &str) -> bool {
    let Some(url) = parse_url(value) else {
        return false;
    };
    url.scheme == "https"
        || url.host == "127.0.0.1"
        || url.host.split('.').next_back() == Some("localhost")
}

/// The heartbeat's timing configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatOptions {
    /// Time allowed for the first heartbeat response.
    pub establish_timeout_ms: u64,
    /// Time the channel may stay `pending` without a response.
    pub pending_timeout_ms: u64,
    /// Time without a response before the channel is disconnected.
    pub disconnect_timeout_ms: u64,
    /// Interval between status polls.
    pub status_polling_rate_ms: u64,
}

impl Default for HeartbeatOptions {
    fn default() -> Self {
        Self {
            establish_timeout_ms: ESTABLISH_TIMEOUT_MS,
            pending_timeout_ms: PENDING_TIMEOUT_MS,
            disconnect_timeout_ms: DISCONNECT_TIMEOUT_MS,
            status_polling_rate_ms: STATUS_POLLING_RATE_MS,
        }
    }
}

/// One side effect the heartbeat state machine asks its driver to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatAction {
    /// Post a status request with this id to the signer window.
    SendStatusPoll {
        /// The poll's JSON-RPC id.
        id: String,
    },
    /// Schedule the next poll in `after_ms` milliseconds.
    ScheduleStatusPoll {
        /// The delay.
        after_ms: u64,
    },
    /// (Re)start the disconnect/pending timeout.
    ScheduleStatusTimeout {
        /// The delay, chosen from the current status.
        after_ms: u64,
    },
    /// Schedule the establish timeout.
    ScheduleEstablishTimeout {
        /// The delay.
        after_ms: u64,
    },
    /// The handshake completed with this verified origin and status.
    Established {
        /// The `event.origin` the first accepted status response came from.
        origin: String,
        /// The signer's status.
        status: SignerStatus,
    },
    /// The signer's status changed.
    StatusChanged(SignerStatus),
    /// No heartbeat was heard during the establish timeout.
    EstablishTimedOut,
    /// The channel stayed `pending` for the pending timeout.
    PendingTimedOut,
    /// The channel stopped answering heartbeats.
    Disconnected,
}

/// Which timeout fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatTimeout {
    /// The establish timeout.
    Establish,
    /// The maintain-phase status timeout.
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Establishing,
    Maintaining,
    Closed,
}

/// The pure ICRC-29 heartbeat state machine.
///
/// Mirrors `HeartbeatClient` (`web/heartbeat/client.ts`): a polling establish
/// phase with a hard timeout, then a maintain phase whose timeout is reset by
/// every accepted status response. The driver (the `web` module, or a test)
/// creates the poll ids and performs the actions.
#[derive(Debug, Clone)]
pub struct HeartbeatState {
    options: HeartbeatOptions,
    phase: Phase,
    status: Option<SignerStatus>,
    origin: Option<String>,
    establish_pending: Vec<JsonRpcId>,
    maintain_pending: Vec<(JsonRpcId, u64)>,
}

impl HeartbeatState {
    /// A heartbeat that has not started yet.
    pub fn new(options: HeartbeatOptions) -> Self {
        Self {
            options,
            phase: Phase::Establishing,
            status: None,
            origin: None,
            establish_pending: Vec::new(),
            maintain_pending: Vec::new(),
        }
    }

    /// Starts the handshake (`HeartbeatClient` constructor, `client.ts:64-76`).
    pub fn start(&mut self, _now: u64) -> Vec<HeartbeatAction> {
        self.phase = Phase::Establishing;
        vec![
            HeartbeatAction::ScheduleEstablishTimeout {
                after_ms: self.options.establish_timeout_ms,
            },
            HeartbeatAction::ScheduleStatusPoll {
                after_ms: FIRST_STATUS_POLL_DELAY_MS,
            },
        ]
    }

    /// A scheduled poll is due: create the request id (through `next_id`) and
    /// send it. `client.ts:114-118,179` (establish interval and maintain tail).
    pub fn on_poll_due(
        &mut self,
        now: u64,
        next_id: &mut dyn FnMut() -> String,
    ) -> Vec<HeartbeatAction> {
        match self.phase {
            Phase::Establishing => {
                let id = JsonRpcId::String(next_id());
                self.establish_pending.push(id.clone());
                vec![
                    HeartbeatAction::SendStatusPoll { id: id.to_string() },
                    // The establish phase uses setInterval: it keeps polling
                    // until a response or the establish timeout.
                    HeartbeatAction::ScheduleStatusPoll {
                        after_ms: self.options.status_polling_rate_ms,
                    },
                ]
            }
            Phase::Maintaining => {
                let id = JsonRpcId::String(next_id());
                // Drop ids that fell outside the disconnect window
                // (`client.ts:139-141`).
                let disconnect = self.options.disconnect_timeout_ms;
                self.maintain_pending
                    .retain(|(_, time)| time.saturating_add(disconnect) >= now);
                self.maintain_pending.push((id.clone(), now));
                vec![HeartbeatAction::SendStatusPoll { id: id.to_string() }]
            }
            Phase::Closed => Vec::new(),
        }
    }

    /// An incoming status response (`client.ts:89-111,161-179`).
    pub fn on_status_response(
        &mut self,
        origin: &str,
        id: JsonRpcId,
        status: SignerStatus,
        now: u64,
        next_id: &mut dyn FnMut() -> String,
    ) -> Vec<HeartbeatAction> {
        match self.phase {
            Phase::Establishing => {
                if !self.establish_pending.contains(&id) {
                    return Vec::new();
                }
                self.establish_pending.clear();
                self.phase = Phase::Maintaining;
                self.status = Some(status);
                self.origin = Some(origin.to_string());
                let mut actions = vec![
                    HeartbeatAction::Established {
                        origin: origin.to_string(),
                        status,
                    },
                    HeartbeatAction::ScheduleStatusTimeout {
                        after_ms: self.status_timeout(status),
                    },
                ];
                // `#maintain` sends one status request immediately after
                // establishing (`client.ts:177-179`).
                let next = JsonRpcId::String(next_id());
                self.maintain_pending.push((next.clone(), now));
                actions.push(HeartbeatAction::SendStatusPoll {
                    id: next.to_string(),
                });
                actions
            }
            Phase::Maintaining => {
                // The maintain listener schedules the next poll for every
                // accepted status-shaped response, consumed or not
                // (`client.ts:174`).
                let mut actions = Vec::new();
                if self.origin.as_deref() == Some(origin)
                    && let Some(index) = self
                        .maintain_pending
                        .iter()
                        .position(|(pending, _)| *pending == id)
                {
                    self.maintain_pending.remove(index);
                    actions.push(HeartbeatAction::ScheduleStatusTimeout {
                        after_ms: self.status_timeout(status),
                    });
                    if self.status != Some(status) {
                        self.status = Some(status);
                        actions.push(HeartbeatAction::StatusChanged(status));
                    }
                }
                actions.push(HeartbeatAction::ScheduleStatusPoll {
                    after_ms: self.options.status_polling_rate_ms,
                });
                actions
            }
            Phase::Closed => Vec::new(),
        }
    }

    /// A scheduled timeout fired.
    pub fn on_timeout(&mut self, timeout: HeartbeatTimeout, _now: u64) -> Vec<HeartbeatAction> {
        match (self.phase, timeout) {
            (Phase::Establishing, HeartbeatTimeout::Establish) => {
                self.phase = Phase::Closed;
                vec![HeartbeatAction::EstablishTimedOut]
            }
            (Phase::Maintaining, HeartbeatTimeout::Status) => {
                self.phase = Phase::Closed;
                if self.status == Some(SignerStatus::Pending) {
                    vec![HeartbeatAction::PendingTimedOut]
                } else {
                    vec![HeartbeatAction::Disconnected]
                }
            }
            _ => Vec::new(),
        }
    }

    /// The establish-phase timeout while polling.
    pub fn status_timeout(&self, status: SignerStatus) -> u64 {
        match status {
            SignerStatus::Pending => self.options.pending_timeout_ms,
            SignerStatus::Ready => self.options.disconnect_timeout_ms,
        }
    }

    /// The current phase's status, once established.
    pub fn status(&self) -> Option<SignerStatus> {
        self.status
    }

    /// The verified signer origin, once established.
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// The timing configuration.
    pub fn options(&self) -> HeartbeatOptions {
        self.options
    }

    /// Whether the handshake has completed.
    pub fn is_established(&self) -> bool {
        self.phase == Phase::Maintaining
    }

    /// Whether the heartbeat has stopped (timeout, disconnect or close).
    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// Stops the heartbeat.
    pub fn stop(&mut self) {
        self.phase = Phase::Closed;
    }
}

// ---------------------------------------------------------------------------
// wasm-js wiring
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm-js")]
mod web {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::{Rc, Weak};

    use async_trait::async_trait;
    use futures::channel::oneshot;
    use gloo_timers::callback::Timeout;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use web_sys::{Crypto, MessageEvent, Window};

    use super::{
        DISCONNECT_TIMEOUT_MS, ESTABLISH_TIMEOUT_MS, HeartbeatAction, HeartbeatOptions,
        HeartbeatState, HeartbeatTimeout, PENDING_TIMEOUT_MS, STATUS_POLLING_RATE_MS, SignerStatus,
        classify_status_response, close_channel_notification, is_secure_signer_window_url,
        signer_window_name, status_request,
    };
    use crate::client::transport::url::{is_json_rpc_response, response_id};
    use crate::client::transport::{
        Channel, JsonRpcId, JsonRpcRequest, JsonRpcResponse, SharedChannel, SignerError, Transport,
    };

    /// Options for [`PostMessageTransport`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PostMessageTransportOptions {
        /// The `window.open` features string; empty opens a tab.
        pub window_opener_features: String,
        /// The ICRC-29 timing knobs.
        pub heartbeat: HeartbeatOptions,
        /// Whether to focus the signer window on send and the opener on close.
        pub manage_focus: bool,
        /// Whether to close the signer window when the handshake times out.
        pub close_on_establish_timeout: bool,
        /// Whether to close the signer window when it stays pending too long.
        pub close_on_pending_timeout: bool,
    }

    impl Default for PostMessageTransportOptions {
        fn default() -> Self {
            Self {
                window_opener_features: String::new(),
                heartbeat: HeartbeatOptions {
                    establish_timeout_ms: ESTABLISH_TIMEOUT_MS,
                    pending_timeout_ms: PENDING_TIMEOUT_MS,
                    disconnect_timeout_ms: DISCONNECT_TIMEOUT_MS,
                    status_polling_rate_ms: STATUS_POLLING_RATE_MS,
                },
                manage_focus: true,
                close_on_establish_timeout: true,
                close_on_pending_timeout: true,
            }
        }
    }

    fn js_from_json<T: serde::Serialize>(value: &T) -> Result<JsValue, SignerError> {
        let json = serde_json::to_string(value).map_err(|error| {
            SignerError::Transport(format!("could not encode message: {error}"))
        })?;
        web_sys::js_sys::JSON::parse(&json)
            .map_err(|error| SignerError::Transport(format!("could not encode message: {error:?}")))
    }

    fn json_from_js(value: &JsValue) -> Option<serde_json::Value> {
        let json = web_sys::js_sys::JSON::stringify(value).ok()?;
        let json = json.as_string()?;
        serde_json::from_str(&json).ok()
    }

    fn same_window(event: &MessageEvent, window: &Window) -> bool {
        match event.source() {
            Some(source) => {
                let source: &JsValue = source.as_ref();
                let window: &JsValue = window.as_ref();
                web_sys::js_sys::Object::is(source, window)
            }
            None => false,
        }
    }

    fn closed(window: &Window) -> bool {
        window.closed().unwrap_or(true)
    }

    type EstablishOutcome = Result<(String, SignerStatus), SignerError>;
    type EstablishSender = oneshot::Sender<EstablishOutcome>;
    type ResponseSender = oneshot::Sender<Result<JsonRpcResponse, SignerError>>;
    type Awaiting = RefCell<HashMap<String, ResponseSender>>;
    type MessageListener = RefCell<Option<Closure<dyn FnMut(MessageEvent)>>>;

    struct TransportInner {
        url: String,
        signer_window_name: String,
        window: Window,
        signer_window: RefCell<Option<Window>>,
        crypto: Crypto,
        options: PostMessageTransportOptions,
    }

    /// The ICRC-29 window `postMessage` transport.
    ///
    /// Call [`Transport::open`] synchronously from the user gesture (the
    /// authentication client does), then await
    /// [`Transport::establish_channel`].
    pub struct PostMessageTransport {
        inner: Rc<TransportInner>,
    }

    impl std::fmt::Debug for PostMessageTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PostMessageTransport")
                .field("url", &self.inner.url)
                .field("signer_window_name", &self.inner.signer_window_name)
                .finish_non_exhaustive()
        }
    }

    impl PostMessageTransport {
        /// Creates the transport with the upstream defaults.
        ///
        /// Fails when the URL is not a secure context for the window transport
        /// (`postMessageTransport.ts:103-117`).
        pub fn new(url: &str, window_opener_features: &str) -> Result<Self, SignerError> {
            let options = PostMessageTransportOptions {
                window_opener_features: window_opener_features.to_string(),
                ..PostMessageTransportOptions::default()
            };
            Self::with_options(url, options)
        }

        /// Creates the transport with explicit options.
        pub fn with_options(
            url: &str,
            options: PostMessageTransportOptions,
        ) -> Result<Self, SignerError> {
            if !is_secure_signer_window_url(url) {
                return Err(SignerError::Transport("Invalid signer RPC url".into()));
            }
            let signer_window_name = signer_window_name(url)
                .ok_or_else(|| SignerError::Transport("Invalid signer RPC url".into()))?;
            let window = web_sys::window().ok_or_else(|| {
                SignerError::Transport("the browser window is not available".into())
            })?;
            let crypto = window.crypto().map_err(|error| {
                SignerError::Transport(format!("crypto is not available: {error:?}"))
            })?;
            Ok(Self {
                inner: Rc::new(TransportInner {
                    url: url.to_string(),
                    signer_window_name,
                    window,
                    signer_window: RefCell::new(None),
                    crypto,
                    options,
                }),
            })
        }

        /// The signer URL.
        pub fn url(&self) -> &str {
            &self.inner.url
        }

        /// The window handle, when [`Transport::open`] has run.
        pub fn signer_window(&self) -> Option<Window> {
            self.inner.signer_window.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl Transport for PostMessageTransport {
        fn open(&self) -> Result<(), SignerError> {
            // Reuse the window this transport already opened unless the user
            // closed it, in which case open a fresh one.
            if let Some(existing) = self.inner.signer_window.borrow().as_ref()
                && !closed(existing)
            {
                return Ok(());
            }
            let opened = self
                .inner
                .window
                .open_with_url_and_target_and_features(
                    &self.inner.url,
                    &self.inner.signer_window_name,
                    &self.inner.options.window_opener_features,
                )
                .map_err(|error| {
                    SignerError::Transport(format!("Signer window could not be opened: {error:?}"))
                })?;
            let Some(window) = opened else {
                return Err(SignerError::Transport(
                    "Signer window could not be opened".into(),
                ));
            };
            *self.inner.signer_window.borrow_mut() = Some(window);
            Ok(())
        }

        #[allow(clippy::arc_with_non_send_sync)] // the seam is `Arc`, wasm is single-threaded
        async fn establish_channel(&self) -> Result<SharedChannel, SignerError> {
            // `open()` is the user-gesture-safe entry point; a caller that
            // skipped it gets one best-effort attempt here (which browsers may
            // popup-block) rather than a confusing hang.
            self.open()?;
            let signer_window = self.inner.signer_window.borrow().clone().ok_or_else(|| {
                SignerError::Transport("Signer window could not be opened".into())
            })?;
            let channel = Rc::new(ChannelShared::new(
                self.inner.window.clone(),
                signer_window,
                self.inner.options.manage_focus,
            ));
            let (sender, receiver) = oneshot::channel();
            let context = Rc::new(HeartbeatContext {
                state: RefCell::new(HeartbeatState::new(self.inner.options.heartbeat)),
                channel: Rc::downgrade(&channel),
                window: self.inner.window.clone(),
                signer_window: channel.signer_window.clone(),
                crypto: self.inner.crypto.clone(),
                options: self.inner.options.clone(),
                timers: RefCell::new(HeartbeatTimers::default()),
                established: RefCell::new(Some(sender)),
                listener: RefCell::new(None),
                stopped: Cell::new(false),
            });
            let handle = HeartbeatHandle {
                context: Rc::clone(&context),
            };
            context.start();
            let outcome = receiver.await;
            match outcome {
                Ok(Ok((origin, status))) => {
                    channel.set_origin(origin);
                    channel.set_status(status);
                    channel.install_response_listener();
                    *channel.heartbeat.borrow_mut() = Some(handle);
                    Ok(std::sync::Arc::new(PostMessageChannel { shared: channel }))
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(SignerError::ChannelClosed),
            }
        }
    }

    #[derive(Default)]
    struct HeartbeatTimers {
        poll: Option<Timeout>,
        status: Option<Timeout>,
        establish: Option<Timeout>,
    }

    struct HeartbeatContext {
        state: RefCell<HeartbeatState>,
        channel: Weak<ChannelShared>,
        window: Window,
        signer_window: Window,
        crypto: Crypto,
        options: PostMessageTransportOptions,
        timers: RefCell<HeartbeatTimers>,
        established: RefCell<Option<EstablishSender>>,
        listener: MessageListener,
        stopped: Cell<bool>,
    }

    impl HeartbeatContext {
        fn now_ms(&self) -> u64 {
            web_sys::js_sys::Date::now().max(0.0) as u64
        }

        fn next_id(&self) -> String {
            self.crypto.random_uuid()
        }

        fn start(self: &Rc<Self>) {
            let weak: Weak<Self> = Rc::downgrade(self);
            let listener = Closure::new(move |event: MessageEvent| {
                let Some(context) = weak.upgrade() else {
                    return;
                };
                context.on_message(event);
            });
            let _ = self
                .window
                .add_event_listener_with_callback("message", listener.as_ref().unchecked_ref());
            *self.listener.borrow_mut() = Some(listener);

            let actions = self.state.borrow_mut().start(self.now_ms());
            self.run(actions);
        }

        fn on_message(self: &Rc<Self>, event: MessageEvent) {
            if self.stopped.get() || self.channel.upgrade().is_none_or(|c| c.is_closed()) {
                return;
            }
            if !same_window(&event, &self.signer_window) {
                return;
            }
            let Some(data) = json_from_js(&event.data()) else {
                return;
            };
            let Some((id, status)) = classify_status_response(&data) else {
                return;
            };
            let now = self.now_ms();
            let mut next_id = || self.next_id();
            let actions = self.state.borrow_mut().on_status_response(
                event.origin().as_str(),
                id,
                status,
                now,
                &mut next_id,
            );
            self.run(actions);
        }

        fn run(self: &Rc<Self>, actions: Vec<HeartbeatAction>) {
            for action in actions {
                self.run_one(action);
            }
        }

        fn run_one(self: &Rc<Self>, action: HeartbeatAction) {
            match action {
                HeartbeatAction::SendStatusPoll { id } => {
                    let request = status_request(&id);
                    if let Ok(value) = js_from_json(&request) {
                        let _ = self.signer_window.post_message(&value, "*");
                    }
                }
                HeartbeatAction::ScheduleStatusPoll { after_ms } => {
                    self.schedule_poll(after_ms);
                }
                HeartbeatAction::ScheduleStatusTimeout { after_ms } => {
                    self.schedule_status_timeout(after_ms);
                }
                HeartbeatAction::ScheduleEstablishTimeout { after_ms } => {
                    self.schedule_establish_timeout(after_ms);
                }
                HeartbeatAction::Established { origin, status } => {
                    let Some(channel) = self.channel.upgrade() else {
                        return;
                    };
                    channel.set_origin(origin);
                    channel.set_status(status);
                    let signer_origin = channel.signer_origin();
                    drop(channel);
                    if let Some(sender) = self.established.borrow_mut().take() {
                        let _ = sender.send(Ok((signer_origin, status)));
                    }
                }
                HeartbeatAction::StatusChanged(status) => {
                    if let Some(channel) = self.channel.upgrade() {
                        channel.set_status(status);
                    }
                }
                HeartbeatAction::EstablishTimedOut => {
                    self.stopped.set(true);
                    if self.options.close_on_establish_timeout {
                        let _ = self.signer_window.close();
                    }
                    if let Some(sender) = self.established.borrow_mut().take() {
                        let _ = sender.send(Err(SignerError::Transport(
                            "Communication channel could not be established within a reasonable time"
                                .into(),
                        )));
                    }
                }
                HeartbeatAction::PendingTimedOut => {
                    self.stopped.set(true);
                    if self.options.close_on_pending_timeout {
                        let _ = self.signer_window.close();
                    }
                    if let Some(channel) = self.channel.upgrade() {
                        channel.close_inner();
                    }
                }
                HeartbeatAction::Disconnected => {
                    self.stopped.set(true);
                    if let Some(channel) = self.channel.upgrade() {
                        channel.close_inner();
                    }
                }
            }
        }

        fn schedule_poll(self: &Rc<Self>, after_ms: u64) {
            let weak: Weak<Self> = Rc::downgrade(self);
            let timeout = Timeout::new(after_ms as u32, move || {
                let Some(context) = weak.upgrade() else {
                    return;
                };
                if context.stopped.get()
                    || context
                        .channel
                        .upgrade()
                        .is_none_or(|channel| channel.is_closed())
                {
                    return;
                }
                let now = context.now_ms();
                let mut next_id = || context.next_id();
                let actions = context.state.borrow_mut().on_poll_due(now, &mut next_id);
                context.run(actions);
            });
            self.timers.borrow_mut().poll = Some(timeout);
        }

        fn schedule_status_timeout(self: &Rc<Self>, after_ms: u64) {
            let weak: Weak<Self> = Rc::downgrade(self);
            let timeout = Timeout::new(after_ms as u32, move || {
                let Some(context) = weak.upgrade() else {
                    return;
                };
                if context.stopped.get() {
                    return;
                }
                let actions = context
                    .state
                    .borrow_mut()
                    .on_timeout(HeartbeatTimeout::Status, context.now_ms());
                context.run(actions);
            });
            self.timers.borrow_mut().status = Some(timeout);
        }

        fn schedule_establish_timeout(self: &Rc<Self>, after_ms: u64) {
            let weak: Weak<Self> = Rc::downgrade(self);
            let timeout = Timeout::new(after_ms as u32, move || {
                let Some(context) = weak.upgrade() else {
                    return;
                };
                if context.stopped.get() {
                    return;
                }
                let actions = context
                    .state
                    .borrow_mut()
                    .on_timeout(HeartbeatTimeout::Establish, context.now_ms());
                context.run(actions);
            });
            self.timers.borrow_mut().establish = Some(timeout);
        }
    }

    /// Keeps the heartbeat's message listener and timers alive for the channel's
    /// lifetime; dropping it stops the heartbeat.
    struct HeartbeatHandle {
        context: Rc<HeartbeatContext>,
    }

    impl Drop for HeartbeatHandle {
        fn drop(&mut self) {
            self.context.stopped.set(true);
            self.context.state.borrow_mut().stop();
            if let Some(listener) = self.context.listener.borrow_mut().take() {
                let _ = self.context.window.remove_event_listener_with_callback(
                    "message",
                    listener.as_ref().unchecked_ref(),
                );
            }
            let mut timers = self.context.timers.borrow_mut();
            timers.poll.take();
            timers.status.take();
            timers.establish.take();
        }
    }

    struct ChannelShared {
        window: Window,
        signer_window: Window,
        signer_origin: RefCell<String>,
        manage_focus: bool,
        status: Cell<SignerStatus>,
        closed: Cell<bool>,
        queue: RefCell<Vec<JsonRpcRequest>>,
        awaiting: Awaiting,
        response_listener: MessageListener,
        heartbeat: RefCell<Option<HeartbeatHandle>>,
    }

    impl ChannelShared {
        fn new(window: Window, signer_window: Window, manage_focus: bool) -> Self {
            Self {
                window,
                signer_window,
                signer_origin: RefCell::new(String::new()),
                manage_focus,
                status: Cell::new(SignerStatus::Ready),
                closed: Cell::new(false),
                queue: RefCell::new(Vec::new()),
                awaiting: RefCell::new(HashMap::new()),
                response_listener: RefCell::new(None),
                heartbeat: RefCell::new(None),
            }
        }

        fn signer_origin(&self) -> String {
            self.signer_origin.borrow().clone()
        }

        fn set_origin(&self, origin: String) {
            *self.signer_origin.borrow_mut() = origin;
        }

        fn set_status(&self, status: SignerStatus) {
            self.status.set(status);
            if status == SignerStatus::Ready {
                self.flush_queue();
            }
        }

        fn is_closed(&self) -> bool {
            self.closed.get() || closed(&self.signer_window)
        }

        fn post(&self, request: &JsonRpcRequest) -> Result<(), SignerError> {
            if self.is_closed() {
                return Err(SignerError::ChannelClosed);
            }
            let value = js_from_json(request)?;
            let origin = self.signer_origin();
            self.signer_window
                .post_message(&value, &origin)
                .map_err(|error| {
                    SignerError::Transport(format!("could not post to the signer: {error:?}"))
                })?;
            if self.manage_focus {
                let _ = self.signer_window.focus();
            }
            Ok(())
        }

        fn flush_queue(&self) {
            let queued: Vec<JsonRpcRequest> = self.queue.borrow_mut().drain(..).collect();
            for request in queued {
                if self.post(&request).is_err() {
                    break;
                }
            }
        }

        fn dispatch_response(&self, event: &MessageEvent) {
            if !same_window(event, &self.signer_window) {
                return;
            }
            if !self.signer_origin.borrow().is_empty()
                && event.origin() != *self.signer_origin.borrow()
            {
                return;
            }
            let Some(data) = json_from_js(&event.data()) else {
                return;
            };
            if !is_json_rpc_response(&data) {
                return;
            }
            let Some(id) = response_id(&data) else {
                return;
            };
            let Some(sender) = self.awaiting.borrow_mut().remove(&id.to_string()) else {
                return;
            };
            match serde_json::from_value::<JsonRpcResponse>(data) {
                Ok(response) => {
                    let _ = sender.send(Ok(response));
                }
                Err(error) => {
                    let _ = sender.send(Err(SignerError::Transport(format!(
                        "invalid JSON-RPC response from the signer: {error}"
                    ))));
                }
            }
        }

        fn install_response_listener(self: &Rc<Self>) {
            let weak: Weak<Self> = Rc::downgrade(self);
            let listener = Closure::new(move |event: MessageEvent| {
                let Some(shared) = weak.upgrade() else {
                    return;
                };
                if shared.closed.get() {
                    return;
                }
                shared.dispatch_response(&event);
            });
            let _ = self
                .window
                .add_event_listener_with_callback("message", listener.as_ref().unchecked_ref());
            *self.response_listener.borrow_mut() = Some(listener);
        }

        fn close_inner(&self) {
            if self.closed.replace(true) {
                return;
            }
            // Tell the signer this end is done before the window goes away.
            if let Ok(value) = js_from_json(&close_channel_notification()) {
                let origin = self.signer_origin();
                let _ = self.signer_window.post_message(&value, &origin);
            }
            let _ = self.signer_window.close();
            if self.manage_focus {
                let _ = self.window.focus();
            }
            let senders: Vec<_> = self
                .awaiting
                .borrow_mut()
                .drain()
                .map(|(_, sender)| sender)
                .collect();
            for sender in senders {
                let _ = sender.send(Err(SignerError::ChannelClosed));
            }
            if let Some(listener) = self.response_listener.borrow_mut().take() {
                let _ = self.window.remove_event_listener_with_callback(
                    "message",
                    listener.as_ref().unchecked_ref(),
                );
            }
        }
    }

    /// A channel to one signer window, created once the heartbeat handshake
    /// completed.
    pub struct PostMessageChannel {
        shared: Rc<ChannelShared>,
    }

    impl std::fmt::Debug for PostMessageChannel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PostMessageChannel")
                .field("closed", &self.shared.is_closed())
                .finish_non_exhaustive()
        }
    }

    #[async_trait(?Send)]
    impl Channel for PostMessageChannel {
        async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, SignerError> {
            if self.shared.is_closed() {
                return Err(SignerError::ChannelClosed);
            }
            if matches!(request.id, None | Some(JsonRpcId::Null)) {
                // The seam's `send` awaits the response that answers the
                // request; a notification has none to await (upstream's
                // fire-and-forget `send` has no Rust equivalent). The only
                // notification this port sends is the close, which
                // `Channel::close` posts directly.
                return Err(SignerError::Transport(
                    "a request without an id cannot be awaited on the postMessage channel".into(),
                ));
            }
            let key = request
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default();
            let (sender, receiver) = oneshot::channel();
            self.shared
                .awaiting
                .borrow_mut()
                .insert(key.clone(), sender);
            if self.shared.status.get() == SignerStatus::Pending {
                self.shared.queue.borrow_mut().push(request);
            } else if let Err(error) = self.shared.post(&request) {
                self.shared.awaiting.borrow_mut().remove(&key);
                return Err(error);
            }
            receiver.await.map_err(|_| SignerError::ChannelClosed)?
        }

        fn is_closed(&self) -> bool {
            self.shared.is_closed()
        }

        async fn close(&self) -> Result<(), SignerError> {
            self.shared.close_inner();
            // Dropping the heartbeat here (outside a timer callback) cancels
            // its listener and timers.
            self.shared.heartbeat.borrow_mut().take();
            Ok(())
        }
    }
}

#[cfg(feature = "wasm-js")]
pub use web::{PostMessageChannel, PostMessageTransport, PostMessageTransportOptions};

// ---------------------------------------------------------------------------
// Tests: pure ICRC-29 message and heartbeat-state-machine contract
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn ids() -> impl FnMut() -> String {
        let mut counter = 0_u32;
        move || {
            counter += 1;
            format!("id-{counter}")
        }
    }

    // -- ICRC-29 message shapes -------------------------------------------

    #[test]
    fn status_poll_is_a_json_rpc_request() {
        let value = serde_json::to_value(status_request("abc")).unwrap();
        assert_eq!(
            value,
            json!({"jsonrpc": "2.0", "id": "abc", "method": "icrc29_status"})
        );
    }

    #[test]
    fn close_channel_is_a_notification() {
        let value = serde_json::to_value(close_channel_notification()).unwrap();
        assert_eq!(
            value,
            json!({"jsonrpc": "2.0", "method": "icrc29_close_channel"})
        );
    }

    #[test]
    fn status_responses_are_classified_and_others_rejected() {
        let ready = json!({"jsonrpc": "2.0", "id": "a", "result": "ready"});
        assert_eq!(
            classify_status_response(&ready),
            Some((JsonRpcId::String("a".into()), SignerStatus::Ready))
        );
        let pending = json!({"jsonrpc": "2.0", "id": 7, "result": "pending"});
        assert_eq!(
            classify_status_response(&pending),
            Some((JsonRpcId::Number(7), SignerStatus::Pending))
        );
        // A normal JSON-RPC result is not a status.
        assert_eq!(
            classify_status_response(&json!({"jsonrpc": "2.0", "id": "a", "result": {"x": 1}})),
            None
        );
        // No id, wrong version, non-object: rejected.
        assert_eq!(
            classify_status_response(&json!({"jsonrpc": "2.0", "result": "ready"})),
            None
        );
        assert_eq!(
            classify_status_response(&json!({"id": "a", "result": "ready"})),
            None
        );
        assert_eq!(classify_status_response(&json!("ready")), None);
        assert_eq!(
            classify_status_response(&json!({"jsonrpc": "2.0", "id": null, "result": "ready"})),
            None
        );
    }

    #[test]
    fn statuses_round_trip() {
        for status in [SignerStatus::Pending, SignerStatus::Ready] {
            assert_eq!(
                SignerStatus::from_value(&json!(status.as_str())),
                Some(status)
            );
        }
        assert_eq!(SignerStatus::from_value(&json!("other")), None);
    }

    #[test]
    fn window_name_is_origin_plus_suffix() {
        assert_eq!(
            signer_window_name("https://signer.example.com/sign").as_deref(),
            Some("https://signer.example.com-signer-window")
        );
        assert_eq!(
            signer_window_name("http://127.0.0.1:8080/sign").as_deref(),
            Some("http://127.0.0.1:8080-signer-window")
        );
        assert_eq!(signer_window_name("not a url"), None);
    }

    #[test]
    fn secure_window_urls_follow_upstream() {
        // `postMessageTransport.ts:103-114`: https anywhere, `127.0.0.1`, or a
        // `localhost` last label.
        for url in [
            "https://signer.example.com/sign",
            "http://localhost:3000",
            "http://app.localhost/sign",
            "http://127.0.0.1:8080",
        ] {
            assert!(is_secure_signer_window_url(url), "{url}");
        }
        for url in [
            "http://signer.example.com/sign",
            "http://127.0.0.2:8080",
            "ftp://signer.example.com/x",
            "not a url",
        ] {
            assert!(!is_secure_signer_window_url(url), "{url}");
        }
        // Upstream's window-transport check tests the hostname without
        // looking at the scheme, so an ftp loopback URL passes it
        // (`postMessageTransport.ts:103-114`).
        assert!(is_secure_signer_window_url("ftp://127.0.0.1/x"));
    }

    // -- heartbeat establish phase ----------------------------------------

    #[test]
    fn start_schedules_the_timeout_and_first_poll() {
        let mut heartbeat = HeartbeatState::new(HeartbeatOptions::default());
        assert_eq!(
            heartbeat.start(0),
            vec![
                HeartbeatAction::ScheduleEstablishTimeout {
                    after_ms: ESTABLISH_TIMEOUT_MS
                },
                HeartbeatAction::ScheduleStatusPoll {
                    after_ms: STATUS_POLLING_RATE_MS
                },
            ]
        );
        assert!(!heartbeat.is_established());
    }

    #[test]
    fn establish_polls_until_a_status_response_arrives() {
        let mut heartbeat = HeartbeatState::new(HeartbeatOptions::default());
        heartbeat.start(0);
        let mut next = ids();
        let actions = heartbeat.on_poll_due(300, &mut next);
        assert_eq!(
            actions,
            vec![
                HeartbeatAction::SendStatusPoll { id: "id-1".into() },
                HeartbeatAction::ScheduleStatusPoll {
                    after_ms: STATUS_POLLING_RATE_MS
                },
            ]
        );

        let actions = heartbeat.on_status_response(
            "https://signer.example.com",
            JsonRpcId::String("id-1".into()),
            SignerStatus::Ready,
            600,
            &mut next,
        );
        assert_eq!(
            actions,
            vec![
                HeartbeatAction::Established {
                    origin: "https://signer.example.com".into(),
                    status: SignerStatus::Ready,
                },
                HeartbeatAction::ScheduleStatusTimeout {
                    after_ms: DISCONNECT_TIMEOUT_MS
                },
                HeartbeatAction::SendStatusPoll { id: "id-2".into() },
            ]
        );
        assert!(heartbeat.is_established());
        assert_eq!(heartbeat.origin(), Some("https://signer.example.com"));
    }

    #[test]
    fn establish_ignores_responses_to_other_ids() {
        let mut heartbeat = HeartbeatState::new(HeartbeatOptions::default());
        heartbeat.start(0);
        let mut next = ids();
        heartbeat.on_poll_due(300, &mut next);
        let actions = heartbeat.on_status_response(
            "https://signer.example.com",
            JsonRpcId::String("nope".into()),
            SignerStatus::Ready,
            400,
            &mut next,
        );
        assert!(actions.is_empty());
        assert!(!heartbeat.is_established());
    }

    #[test]
    fn establish_timeout_stops_the_heartbeat() {
        let mut heartbeat = HeartbeatState::new(HeartbeatOptions::default());
        heartbeat.start(0);
        assert_eq!(
            heartbeat.on_timeout(HeartbeatTimeout::Establish, 120_000),
            vec![HeartbeatAction::EstablishTimedOut]
        );
        assert!(heartbeat.is_closed());
        // A late response no longer does anything.
        let mut next = ids();
        assert!(
            heartbeat
                .on_status_response(
                    "https://signer.example.com",
                    JsonRpcId::String("id-1".into()),
                    SignerStatus::Ready,
                    120_001,
                    &mut next
                )
                .is_empty()
        );
    }

    // -- heartbeat maintain phase -----------------------------------------

    fn established(pending: bool) -> HeartbeatState {
        let mut heartbeat = HeartbeatState::new(HeartbeatOptions::default());
        heartbeat.start(0);
        let mut next = ids();
        heartbeat.on_poll_due(300, &mut next);
        heartbeat.on_status_response(
            "https://signer.example.com",
            JsonRpcId::String("id-1".into()),
            if pending {
                SignerStatus::Pending
            } else {
                SignerStatus::Ready
            },
            400,
            &mut next,
        );
        heartbeat
    }

    #[test]
    fn maintain_resets_the_timeout_on_an_answer_and_schedules_the_next_poll() {
        let mut heartbeat = established(false);
        let mut next = ids();
        let actions = heartbeat.on_status_response(
            "https://signer.example.com",
            JsonRpcId::String("id-2".into()),
            SignerStatus::Ready,
            700,
            &mut next,
        );
        assert_eq!(
            actions,
            vec![
                HeartbeatAction::ScheduleStatusTimeout {
                    after_ms: DISCONNECT_TIMEOUT_MS
                },
                HeartbeatAction::ScheduleStatusPoll {
                    after_ms: STATUS_POLLING_RATE_MS
                },
            ]
        );
    }

    #[test]
    fn maintain_reports_a_status_change() {
        let mut heartbeat = established(true);
        let mut next = ids();
        let actions = heartbeat.on_status_response(
            "https://signer.example.com",
            JsonRpcId::String("id-2".into()),
            SignerStatus::Ready,
            700,
            &mut next,
        );
        assert!(actions.contains(&HeartbeatAction::StatusChanged(SignerStatus::Ready)));
        assert_eq!(heartbeat.status(), Some(SignerStatus::Ready));
        // The timeout now uses the disconnect duration, not the pending one.
        assert!(actions.contains(&HeartbeatAction::ScheduleStatusTimeout {
            after_ms: DISCONNECT_TIMEOUT_MS
        }));
    }

    #[test]
    fn maintain_ignores_answers_from_another_origin() {
        let mut heartbeat = established(false);
        let mut next = ids();
        let actions = heartbeat.on_status_response(
            "https://evil.example.com",
            JsonRpcId::String("id-2".into()),
            SignerStatus::Pending,
            700,
            &mut next,
        );
        // Still schedules the next poll (the accepted-message filter is
        // source/shape only), but does not consume the pending id.
        assert_eq!(
            actions,
            vec![HeartbeatAction::ScheduleStatusPoll {
                after_ms: STATUS_POLLING_RATE_MS
            }]
        );
        assert_eq!(heartbeat.status(), Some(SignerStatus::Ready));
    }

    #[test]
    fn pending_status_uses_the_pending_timeout() {
        let mut heartbeat = established(true);
        assert_eq!(
            heartbeat.on_timeout(HeartbeatTimeout::Status, 300_400),
            vec![HeartbeatAction::PendingTimedOut]
        );
        assert!(heartbeat.is_closed());
    }

    #[test]
    fn ready_status_uses_the_disconnect_timeout() {
        let mut heartbeat = established(false);
        assert_eq!(
            heartbeat.on_timeout(HeartbeatTimeout::Status, 2_400),
            vec![HeartbeatAction::Disconnected]
        );
        assert!(heartbeat.is_closed());
    }

    #[test]
    fn stopping_swallows_late_events() {
        let mut heartbeat = established(false);
        heartbeat.stop();
        let mut next = ids();
        assert!(heartbeat.on_poll_due(1_000, &mut next).is_empty());
        assert!(
            heartbeat
                .on_status_response(
                    "https://signer.example.com",
                    JsonRpcId::String("id-2".into()),
                    SignerStatus::Ready,
                    1_000,
                    &mut next
                )
                .is_empty()
        );
        assert!(
            heartbeat
                .on_timeout(HeartbeatTimeout::Status, 1_000)
                .is_empty()
        );
    }

    #[test]
    fn default_timing_matches_upstream() {
        let options = HeartbeatOptions::default();
        assert_eq!(options.establish_timeout_ms, 120_000);
        assert_eq!(options.pending_timeout_ms, 300_000);
        assert_eq!(options.disconnect_timeout_ms, 2_000);
        assert_eq!(options.status_polling_rate_ms, 300);
    }
}

// ---------------------------------------------------------------------------
// Browser tests (`wasm-pack test --headless --chrome`)
// ---------------------------------------------------------------------------
//
// Constructing the transport touches `window.crypto` and the window handle, so
// these need a browser. Opening the signer window and driving the ICRC-29
// handshake needs a real signer (or the Playwright harness with a stub signer
// page), so that remains a manual/integration check.

#[cfg(all(test, feature = "wasm-js"))]
mod browser_tests {
    use wasm_bindgen_test::*;

    use super::web::PostMessageTransport;

    #[wasm_bindgen_test]
    fn post_message_transport_validates_the_signer_url() {
        assert!(PostMessageTransport::new("http://signer.example.com/sign", "").is_err());
        assert!(PostMessageTransport::new("not a url", "").is_err());

        let transport =
            PostMessageTransport::new("https://signer.example.com/sign", "").expect("transport");
        assert_eq!(transport.url(), "https://signer.example.com/sign");
        assert!(
            transport.signer_window().is_none(),
            "open() has not run yet"
        );
    }

    #[wasm_bindgen_test]
    fn post_message_transport_accepts_loopback_development_urls() {
        assert!(PostMessageTransport::new("http://localhost:3000", "").is_ok());
        assert!(PostMessageTransport::new("http://127.0.0.1:8080/sign", "").is_ok());
    }
}
