//! Native ICRC-167 URL transport.
//!
//! The browser transport ([`super::url`]) gets its response back by navigating
//! the page it already runs in. A native process has no page, so the request
//! goes out through one the application hosts on its own origin
//! (`<relay>/auth/`), the signer answers by navigating that page's callback
//! (`<relay>/auth/callback`), and the page relays the answer to this process
//! over a loopback HTTP listener.
//!
//! One request is one navigation. The signer does not answer JSON-RPC batches
//! (measured against `id.ai`; see `docs/port/native-icrc167.md`), and
//! [`Channel::send`] takes a single request, so batching cannot happen by
//! construction; a batch response is refused if one ever arrives.
//!
//! The pending flow lives in memory only: unlike a page, a native process is
//! not unloaded between the request and its answer, so there is nothing to
//! journal. A crash abandons the attempt and the caller retries.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Deserialize;

use crate::client::base64::base64_url_no_pad;
use crate::client::platform::PlatformBounds;
use crate::client::transport::{
    Channel, JsonRpcRequest, JsonRpcResponse, SharedChannel, SignerError, Transport,
};
use crate::client::webauth::{BrowserOpener, SystemBrowser};

/// The relay page, relative to the relay origin.
pub const RELAY_PAGE_PATH: &str = "/auth/";
/// The page the signer navigates back to.
pub const RELAY_CALLBACK_PATH: &str = "/auth/callback";
/// Where the relay page posts the answer on the loopback listener.
pub const RELAY_POST_PATH: &str = "/icrc167";

/// How long a whole navigation may take before it is abandoned.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// Largest relay POST this transport accepts. Nothing here approaches it; the
/// bound keeps an open loopback port from being used as a memory sink.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Everything that decides where the flow runs.
#[derive(Debug, Clone)]
pub struct NativeUrlTransportOptions {
    /// The signer's transport URL, e.g. `https://id.ai/authorize`.
    pub signer_url: String,
    /// The origin hosting the relay page, e.g. `https://app.example`. Its root
    /// must serve `/.well-known/ii-auth-callbacks` declaring the callback.
    pub relay_origin: String,
    /// The relay page path on that origin.
    pub relay_page: String,
    /// The callback path on that origin.
    pub relay_callback: String,
    /// Whole-navigation deadline.
    pub timeout: Duration,
}

impl NativeUrlTransportOptions {
    /// Options with the default paths and timeout.
    pub fn new(signer_url: impl Into<String>, relay_origin: impl Into<String>) -> Self {
        Self {
            signer_url: signer_url.into(),
            relay_origin: relay_origin.into(),
            relay_page: RELAY_PAGE_PATH.to_string(),
            relay_callback: RELAY_CALLBACK_PATH.to_string(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The relay page's absolute URL.
    pub fn page_url(&self) -> Result<url::Url, SignerError> {
        self.on_relay_origin(&self.relay_page)
    }

    /// The callback's absolute URL.
    pub fn callback_url(&self) -> Result<url::Url, SignerError> {
        self.on_relay_origin(&self.relay_callback)
    }

    fn on_relay_origin(&self, path: &str) -> Result<url::Url, SignerError> {
        let mut url = url::Url::parse(&self.relay_origin)
            .map_err(|error| SignerError::Transport(format!("invalid relay origin: {error}")))?;
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    fn validate(&self) -> Result<(), SignerError> {
        let signer = url::Url::parse(&self.signer_url)
            .map_err(|error| SignerError::Transport(format!("invalid signer URL: {error}")))?;
        if signer.fragment().is_some() {
            return Err(SignerError::Transport(
                "the signer URL must not carry a fragment: the flow writes its own".to_string(),
            ));
        }
        if !is_secure_context(&signer) {
            return Err(SignerError::Transport(
                "the signer URL must be https, or http on a loopback host".to_string(),
            ));
        }

        let origin = url::Url::parse(&self.relay_origin)
            .map_err(|error| SignerError::Transport(format!("invalid relay origin: {error}")))?;
        if !origin.path_is_root()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !is_secure_context(&origin)
        {
            return Err(SignerError::Transport(
                "the relay origin must be a bare https origin (no path, query or fragment)"
                    .to_string(),
            ));
        }

        for (label, path) in [
            ("relay page", &self.relay_page),
            ("relay callback", &self.relay_callback),
        ] {
            if !path.starts_with('/')
                || path.contains('?')
                || path.contains('#')
                || path.contains("..")
            {
                return Err(SignerError::Transport(format!(
                    "the {label} path must start with '/', and carry no query, fragment or '..'"
                )));
            }
        }
        Ok(())
    }
}

fn is_secure_context(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(url::Host::Domain(domain)) => {
                domain == "localhost" || domain.ends_with(".localhost")
            }
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

trait UrlPathExt {
    fn path_is_root(&self) -> bool;
}

impl UrlPathExt for url::Url {
    fn path_is_root(&self) -> bool {
        matches!(self.path(), "" | "/")
    }
}

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

use serde_json::json;

/// The relay page's polling endpoint: the page asks for the next request.
pub const RELAY_POLL_PATH: &str = "/icrc167/poll";

/// How long a page waits for another request before it is told the ceremony is
/// over. This is the gap between two steps of one ceremony, not a user's think
/// time: the page has already answered the previous step when it starts
/// polling.
pub const NEXT_IDLE: Duration = Duration::from_millis(1500);

/// The loopback page a browser hands off to when it cannot read
/// `http://127.0.0.1` from an https page.
pub const RELAY_HANDOFF_PATH: &str = "/icrc167/handoff";

/// The hand-off page, served from the loopback origin.
///
/// Safari blocks an https page from reading `http://127.0.0.1` (mixed content),
/// but a top-level navigation to loopback is allowed. The callback page
/// navigates here instead of failing; this page posts the answer to its own
/// origin, long-polls for the next step, and navigates the same tab again. The
/// token rides in the fragment, so the request for the page itself carries no
/// credentials and there is nothing to cache.
pub const HANDOFF_PAGE: &str = include_str!("handoff.html");

/// What the relay page sends back to the loopback listener.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackPayload {
    /// The callback fragment's `message`: the raw JSON-RPC response.
    pub message: String,
    /// The callback fragment's `state`, echoed from the request.
    pub state: Option<String>,
}

/// One navigation to run: everything a delivery session needs to carry a
/// request to the signer and bring its answer back.
#[derive(Debug, Clone)]
pub struct RelayRequest {
    /// The signer URL, fragment-free.
    pub signer_url: String,
    /// The relay page to open on the first navigation.
    pub page_url: url::Url,
    /// The callback to declare to the signer.
    pub callback_url: url::Url,
    /// The JSON-RPC request, serialized.
    pub message: String,
    /// The single-use state to send and check.
    pub state: String,
    /// How long this step may take.
    pub timeout: Duration,
}

/// One browser tab, several navigations.
///
/// A delivery session is opened once per channel. The first request opens the
/// relay page; every later request of the same channel is handed to the page
/// that is already waiting, so a multi-step ceremony does not flash a new tab
/// per step.
#[async_trait(?Send)]
pub trait CallbackDelivery: PlatformBounds {
    /// Delivers one request through the page and waits for its answer.
    async fn deliver(&self, request: RelayRequest) -> Result<CallbackPayload, SignerError>;
    /// Stops the session, releasing the loopback port and failing waiters.
    fn close(&self);
}

/// A delivery session behind an `Arc`.
pub type SharedDelivery = Arc<dyn CallbackDelivery>;

/// Opens delivery sessions.
pub trait CallbackBroker: PlatformBounds {
    /// Opens a session bound to the transport's options.
    fn open(&self, options: &NativeUrlTransportOptions) -> Result<SharedDelivery, SignerError>;
}

/// The default broker: the system browser plus a loopback listener.
pub struct LoopbackBroker {
    opener: Arc<dyn BrowserOpener>,
    idle: Duration,
}

impl LoopbackBroker {
    /// A broker that opens the system browser.
    pub fn new() -> Self {
        Self {
            opener: Arc::new(SystemBrowser),
            idle: NEXT_IDLE,
        }
    }

    /// A broker with another way of opening the page, for tests and for hosts
    /// that drive their own browser window.
    pub fn with_opener(opener: Arc<dyn BrowserOpener>) -> Self {
        Self {
            opener,
            idle: NEXT_IDLE,
        }
    }

    /// A broker with another way of opening the page and another idle window.
    pub fn with_idle(opener: Arc<dyn BrowserOpener>, idle: Duration) -> Self {
        Self { opener, idle }
    }
}

impl Default for LoopbackBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LoopbackBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackBroker")
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}

impl CallbackBroker for LoopbackBroker {
    fn open(&self, _options: &NativeUrlTransportOptions) -> Result<SharedDelivery, SignerError> {
        // Bound before anything else: the port is part of the page's fragment.
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| {
            SignerError::Transport(format!("could not bind the relay listener: {error}"))
        })?;
        let port = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| {
                SignerError::Transport("the relay listener bound a non-IP address".to_string())
            })?
            .port();

        let state = Arc::new(StdMutex::new(SessionState::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let token = base64_url_no_pad(&random_bytes());

        let serving_state = state.clone();
        let serving_shutdown = shutdown.clone();
        let serving_token = token.clone();
        let idle = self.idle;
        let thread = std::thread::Builder::new()
            .name("ic-auth-client-relay".to_string())
            .spawn(move || {
                serve(
                    server,
                    &serving_token,
                    serving_state,
                    serving_shutdown,
                    idle,
                )
            })
            .map_err(|error| {
                SignerError::Transport(format!("could not start the relay listener: {error}"))
            })?;

        Ok(Arc::new(LoopbackDelivery {
            state,
            shutdown,
            thread: StdMutex::new(Some(thread)),
            opener: self.opener.clone(),
            port,
            token,
            grace: self.idle,
        }))
    }
}

struct SessionState {
    /// A request the page has not picked up yet.
    next: Option<RelayRequest>,
    /// The page's held long-poll, waiting for `next` or an idle "done".
    held_poll: Option<tiny_http::Request>,
    /// One waiter per request, keyed by its state.
    waiters:
        HashMap<String, futures::channel::oneshot::Sender<Result<CallbackPayload, SignerError>>>,
    /// When a request or an answer last moved, for the idle decision.
    last_activity: Instant,
    /// Whether a page from this session is still around to take another
    /// request. Cleared when a page is told "done" or the session closes.
    page_alive: bool,
}

impl SessionState {
    fn new() -> Self {
        Self {
            next: None,
            held_poll: None,
            waiters: HashMap::new(),
            last_activity: Instant::now(),
            page_alive: false,
        }
    }
}

struct LoopbackDelivery {
    state: Arc<StdMutex<SessionState>>,
    shutdown: Arc<AtomicBool>,
    thread: StdMutex<Option<std::thread::JoinHandle<()>>>,
    opener: Arc<dyn BrowserOpener>,
    port: u16,
    token: String,
    /// How long a request waits for an already-open page to pick it up before
    /// the session falls back to opening a new page.
    grace: Duration,
}

impl LoopbackDelivery {
    /// The relay page URL carrying one request's fragment.
    fn navigation_url(&self, request: &RelayRequest) -> String {
        let mut page = request.page_url.clone();
        page.set_fragment(Some(
            &url::form_urlencoded::Serializer::new(String::new())
                .append_pair("signer", &request.signer_url)
                .append_pair("message", &request.message)
                .append_pair("state", &request.state)
                .append_pair("callback", request.callback_url.as_str())
                .append_pair("port", &self.port.to_string())
                .append_pair("token", &self.token)
                .finish(),
        ));
        page.to_string()
    }
}

impl Drop for LoopbackDelivery {
    fn drop(&mut self) {
        self.close();
    }
}

#[async_trait(?Send)]
impl CallbackDelivery for LoopbackDelivery {
    async fn deliver(&self, request: RelayRequest) -> Result<CallbackPayload, SignerError> {
        let (sender, receiver) = futures::channel::oneshot::channel();
        let open = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SignerError::Transport("the relay session is poisoned".to_string()))?;
            if state.waiters.contains_key(&request.state) {
                return Err(SignerError::Transport(
                    "the same request state is already in flight".to_string(),
                ));
            }
            state.waiters.insert(request.state.clone(), sender);
            if state.page_alive {
                // A page from this session is waiting: it will pick this up on
                // its poll. A page that has since gone away is covered by the
                // grace period below.
                if state.next.is_some() {
                    state.waiters.remove(&request.state);
                    return Err(SignerError::Transport(
                        "a request is already queued for the page".to_string(),
                    ));
                }
                match state.held_poll.take() {
                    // The page is holding a poll right now: answer it with the
                    // next navigation instead of waiting for it to ask again.
                    Some(poll) => {
                        state.last_activity = Instant::now();
                        respond_next(poll, &request);
                    }
                    None => {
                        state.next = Some(request.clone());
                        state.last_activity = Instant::now();
                    }
                }
                None
            } else {
                state.page_alive = true;
                state.last_activity = Instant::now();
                Some(self.navigation_url(&request))
            }
        };

        if let Some(url) = open {
            if let Err(error) = self.opener.open(url.as_str()) {
                self.remove_waiter(&request.state);
                return Err(SignerError::Transport(format!(
                    "could not open the browser on the relay page: {error}"
                )));
            }
            return self.wait_payload(Box::pin(receiver), &request).await;
        }

        // The page was believed to be there; give it a moment to pick the
        // request up. A closed tab must not turn into a multi-minute wait.
        let grace = Box::pin(futures_timer::Delay::new(self.grace));
        let receiver = match futures::future::select(Box::pin(receiver), grace).await {
            futures::future::Either::Left((result, _)) => return finish_payload(result),
            futures::future::Either::Right((_, receiver)) => receiver,
        };

        let still_queued = {
            let Ok(mut state) = self.state.lock() else {
                self.remove_waiter(&request.state);
                return Err(SignerError::Transport(
                    "the relay session is poisoned".to_string(),
                ));
            };
            if state
                .next
                .as_ref()
                .is_some_and(|queued| queued.state == request.state)
            {
                state.next = None;
                true
            } else {
                false
            }
        };
        if still_queued {
            let url = self.navigation_url(&request);
            if let Err(error) = self.opener.open(url.as_str()) {
                self.remove_waiter(&request.state);
                return Err(SignerError::Transport(format!(
                    "could not open the browser on the relay page: {error}"
                )));
            }
        }
        self.wait_payload(receiver, &request).await
    }

    fn close(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let thread = self.thread.lock().ok().and_then(|mut thread| thread.take());
        if let Some(thread) = thread {
            let _ = thread.join();
        }
        if let Ok(mut state) = self.state.lock() {
            state.next = None;
            state.page_alive = false;
            for (_, sender) in state.waiters.drain() {
                let _ = sender.send(Err(SignerError::ChannelClosed));
            }
        }
    }
}

impl LoopbackDelivery {
    fn remove_waiter(&self, state_key: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.waiters.remove(state_key);
        }
    }

    async fn wait_payload(
        &self,
        receiver: std::pin::Pin<
            Box<futures::channel::oneshot::Receiver<Result<CallbackPayload, SignerError>>>,
        >,
        request: &RelayRequest,
    ) -> Result<CallbackPayload, SignerError> {
        let delay = Box::pin(futures_timer::Delay::new(request.timeout));
        match futures::future::select(receiver, delay).await {
            futures::future::Either::Left((result, _)) => finish_payload(result),
            futures::future::Either::Right(_) => {
                self.remove_waiter(&request.state);
                Err(SignerError::Timeout)
            }
        }
    }
}

/// Turns the oneshot result into the delivery result.
fn finish_payload(
    result: Result<Result<CallbackPayload, SignerError>, futures::channel::oneshot::Canceled>,
) -> Result<CallbackPayload, SignerError> {
    match result {
        Ok(result) => result,
        Err(_) => Err(SignerError::ChannelClosed),
    }
}

/// The body that hands the page the next navigation of this ceremony.
fn next_body(request: &RelayRequest) -> serde_json::Value {
    json!({
        "next": {
            "signer": request.signer_url,
            "message": request.message,
            "state": request.state,
            "callback": request.callback_url.as_str(),
        }
    })
}

/// Answers a held poll with the next navigation.
fn respond_next(poll: tiny_http::Request, request: &RelayRequest) {
    let _ = poll.respond(json_response(200, &next_body(request)));
}

/// The loopback half: one request at a time, and only from the page holding the
/// token this session was opened with.
fn serve(
    server: tiny_http::Server,
    token: &str,
    state: Arc<StdMutex<SessionState>>,
    shutdown: Arc<AtomicBool>,
    idle: Duration,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        // Release a poll the page is holding once no next request has arrived.
        let released = if let Ok(mut guard) = state.lock() {
            match guard.held_poll.take() {
                Some(poll) if Instant::now().duration_since(guard.last_activity) >= idle => {
                    let _ = poll.respond(json_response(200, &json!({ "done": true })));
                    guard.page_alive = false;
                    true
                }
                Some(poll) => {
                    guard.held_poll = Some(poll);
                    false
                }
                None => false,
            }
        } else {
            false
        };
        let slice = if released {
            Duration::from_millis(10)
        } else {
            Duration::from_millis(100)
        };
        match server.recv_timeout(slice) {
            Ok(None) => continue,
            Ok(Some(request)) => handle(request, token, &state, idle),
            Err(_) => break,
        }
    }

    // Fail everything still outstanding: the session is over.
    if let Ok(mut guard) = state.lock() {
        if let Some(poll) = guard.held_poll.take() {
            let _ = poll.respond(json_response(200, &json!({ "done": true })));
        }
        guard.next = None;
        guard.page_alive = false;
        for (_, sender) in guard.waiters.drain() {
            let _ = sender.send(Err(SignerError::ChannelClosed));
        }
    }
}

/// Answers one HTTP request on the loopback listener.
fn handle(
    mut request: tiny_http::Request,
    token: &str,
    state: &Arc<StdMutex<SessionState>>,
    idle: Duration,
) {
    if request.method() == &tiny_http::Method::Options {
        let _ = request.respond(empty_response(204));
        return;
    }
    let path = request
        .url()
        .split('?')
        .next()
        .unwrap_or_default()
        .to_string();
    // Static, and the token is in the fragment: no credentials to check, and
    // fetching it must never be confused with reporting an answer.
    if request.method() == &tiny_http::Method::Get && path == RELAY_HANDOFF_PATH {
        let _ = request.respond(html_response(200, HANDOFF_PAGE));
        return;
    }
    if !authorized(&request, token) {
        let _ = request.respond(empty_response(401));
        return;
    }
    match (request.method().clone(), path.as_str()) {
        (tiny_http::Method::Post, RELAY_POST_PATH) => {
            if !has_json_content_type(&request) {
                let _ = request.respond(empty_response(415));
                return;
            }
            let Some(body) = read_body(&mut request) else {
                let _ = request.respond(empty_response(400));
                return;
            };
            let Ok(payload) = serde_json::from_slice::<CallbackPayload>(&body) else {
                let _ = request.respond(empty_response(400));
                return;
            };
            let sender = {
                let Ok(mut guard) = state.lock() else {
                    let _ = request.respond(empty_response(500));
                    return;
                };
                let Some(st) = payload.state.clone() else {
                    let _ = request.respond(empty_response(400));
                    return;
                };
                let sender = guard.waiters.remove(&st);
                if sender.is_some() {
                    guard.last_activity = Instant::now();
                    guard.page_alive = true;
                }
                sender
            };
            match sender {
                Some(sender) => {
                    let _ = sender.send(Ok(payload));
                    let _ = request.respond(empty_response(204));
                }
                // A page from an earlier session (or a forged post): nothing is
                // waiting for this state.
                None => {
                    let _ = request.respond(empty_response(409));
                }
            }
        }
        (tiny_http::Method::Get, RELAY_POLL_PATH) => {
            let next = {
                let Ok(mut guard) = state.lock() else {
                    let _ = request.respond(empty_response(500));
                    return;
                };
                match guard.next.take() {
                    Some(next) => {
                        guard.last_activity = Instant::now();
                        guard.page_alive = true;
                        Some(next)
                    }
                    None => {
                        if Instant::now().duration_since(guard.last_activity) >= idle {
                            guard.page_alive = false;
                            None
                        } else {
                            guard.page_alive = true;
                            // Hold the poll; `serve` releases it with done.
                            if let Some(stale) = guard.held_poll.replace(request) {
                                let _ = stale.respond(json_response(200, &json!({ "done": true })));
                            }
                            return;
                        }
                    }
                }
            };
            match next {
                Some(next) => {
                    let _ = request.respond(json_response(200, &next_body(&next)));
                }
                None => {
                    let _ = request.respond(json_response(200, &json!({ "done": true })));
                }
            }
        }
        _ => {
            let _ = request.respond(empty_response(404));
        }
    }
}

fn authorized(request: &tiny_http::Request, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .map(|header| header.value.as_str().to_owned())
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
}

fn has_json_content_type(request: &tiny_http::Request) -> bool {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Content-Type"))
        .map(|header| header.value.as_str().to_owned())
        .is_some_and(|value| value.starts_with("application/json"))
}

fn read_body(request: &mut tiny_http::Request) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    let reader = request.as_reader();
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if body.len() as u64 + read as u64 > MAX_BODY_BYTES as u64 {
                    return None;
                }
                body.extend_from_slice(&buffer[..read]);
            }
            Err(_) => return None,
        }
    }
    Some(body)
}

fn empty_response(status: u16) -> tiny_http::Response<std::io::Empty> {
    tiny_http::Response::empty(status)
        .with_header(header("Access-Control-Allow-Origin", "*"))
        .with_header(header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
        .with_header(header(
            "Access-Control-Allow-Headers",
            "authorization, content-type",
        ))
        .with_header(header("Access-Control-Allow-Private-Network", "true"))
        .with_header(header("Cache-Control", "no-store"))
}

fn json_response(
    status: u16,
    body: &serde_json::Value,
) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let bytes = body.to_string().into_bytes();
    tiny_http::Response::from_data(bytes)
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"))
        .with_header(header("Access-Control-Allow-Origin", "*"))
        .with_header(header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
        .with_header(header(
            "Access-Control-Allow-Headers",
            "authorization, content-type",
        ))
        .with_header(header("Access-Control-Allow-Private-Network", "true"))
        .with_header(header("Cache-Control", "no-store"))
}

fn html_response(status: u16, body: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_data(body.as_bytes().to_vec())
        .with_status_code(status)
        .with_header(header("Content-Type", "text/html; charset=utf-8"))
        .with_header(header("Cache-Control", "no-store"))
}

fn header(name: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn random_bytes() -> [u8; 32] {
    use rand::Rng as _;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// The ICRC-167 URL transport for a native process.
#[derive(Clone)]
pub struct NativeUrlTransport {
    options: NativeUrlTransportOptions,
    broker: Arc<dyn CallbackBroker>,
}

impl NativeUrlTransport {
    /// A transport that opens the system browser on the relay page.
    pub fn new(options: NativeUrlTransportOptions) -> Result<Self, SignerError> {
        Self::with_broker(options, Arc::new(LoopbackBroker::new()))
    }

    /// A transport that delivers through `broker` instead.
    pub fn with_broker(
        options: NativeUrlTransportOptions,
        broker: Arc<dyn CallbackBroker>,
    ) -> Result<Self, SignerError> {
        options.validate()?;
        Ok(Self { options, broker })
    }

    /// The options this transport runs with.
    pub fn options(&self) -> &NativeUrlTransportOptions {
        &self.options
    }
}

impl std::fmt::Debug for NativeUrlTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeUrlTransport")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait(?Send)]
impl Transport for NativeUrlTransport {
    async fn establish_channel(&self) -> Result<SharedChannel, SignerError> {
        let delivery = self
            .broker
            .open(&self.options)
            .map_err(|error| SignerError::Transport(error.to_string()))?;
        Ok(Arc::new(NativeUrlChannel {
            transport: self.clone(),
            delivery,
            closed: AtomicBool::new(false),
        }))
    }
}

struct NativeUrlChannel {
    transport: NativeUrlTransport,
    delivery: SharedDelivery,
    closed: AtomicBool,
}

#[async_trait(?Send)]
impl Channel for NativeUrlChannel {
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, SignerError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SignerError::ChannelClosed);
        }
        let message = serde_json::to_string(&request).map_err(|error| {
            SignerError::Transport(format!("could not encode the request: {error}"))
        })?;
        let state = base64_url_no_pad(&random_bytes());
        let payload = self
            .delivery
            .deliver(RelayRequest {
                signer_url: self.transport.options.signer_url.clone(),
                page_url: self.transport.options.page_url()?,
                callback_url: self.transport.options.callback_url()?,
                message,
                state: state.clone(),
                timeout: self.transport.options.timeout,
            })
            .await?;

        if payload.state.as_deref() != Some(state.as_str()) {
            return Err(SignerError::Protocol(format!(
                "the relay page returned state {:?}, expected {:?}",
                payload.state, state
            )));
        }
        if payload.message.trim_start().starts_with('[') {
            return Err(SignerError::Protocol(
                "the signer answered with a JSON-RPC batch; this transport sends one request at a time"
                    .to_string(),
            ));
        }
        let response: JsonRpcResponse =
            serde_json::from_str(&payload.message).map_err(|error| {
                SignerError::Protocol(format!("unreadable answer from the signer: {error}"))
            })?;
        if Some(response.id()) != request.id.as_ref() {
            return Err(SignerError::Protocol(format!(
                "the signer answered id {:?}, not {:?}",
                response.id(),
                request.id
            )));
        }
        Ok(response)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn close(&self) -> Result<(), SignerError> {
        self.closed.store(true, Ordering::SeqCst);
        self.delivery.close();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::transport::{JsonRpcId, JsonRpcRequest};
    use serde_json::{Value, json};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    // -- a broker that answers without a browser ---------------------------

    type Answer = Box<dyn Fn(&RelayRequest) -> Result<CallbackPayload, SignerError> + Send + Sync>;

    struct FakeDelivery {
        calls: StdMutex<Vec<RelayRequest>>,
        answer: Answer,
    }

    impl FakeDelivery {
        fn new(
            answer: impl Fn(&RelayRequest) -> Result<CallbackPayload, SignerError>
            + Send
            + Sync
            + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                calls: StdMutex::new(Vec::new()),
                answer: Box::new(answer),
            })
        }

        fn calls(&self) -> Vec<RelayRequest> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait(?Send)]
    impl CallbackDelivery for FakeDelivery {
        async fn deliver(&self, request: RelayRequest) -> Result<CallbackPayload, SignerError> {
            self.calls.lock().unwrap().push(request.clone());
            (self.answer)(&request)
        }

        fn close(&self) {}
    }

    struct FakeBroker {
        delivery: Arc<FakeDelivery>,
        opened: AtomicUsize,
    }

    impl FakeBroker {
        fn new(delivery: Arc<FakeDelivery>) -> Arc<Self> {
            Arc::new(Self {
                delivery,
                opened: AtomicUsize::new(0),
            })
        }

        fn opened(&self) -> usize {
            self.opened.load(Ordering::SeqCst)
        }
    }

    impl CallbackBroker for FakeBroker {
        fn open(
            &self,
            _options: &NativeUrlTransportOptions,
        ) -> Result<SharedDelivery, SignerError> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            Ok(self.delivery.clone())
        }
    }

    fn options() -> NativeUrlTransportOptions {
        NativeUrlTransportOptions::new("https://id.ai/authorize", "https://app.example")
    }

    fn answer_with(request: &RelayRequest, value: Value) -> Result<CallbackPayload, SignerError> {
        Ok(CallbackPayload {
            message: serde_json::to_string(&value).expect("json"),
            state: Some(request.state.clone()),
        })
    }

    fn request() -> JsonRpcRequest {
        JsonRpcRequest::new(
            JsonRpcId::Number(1),
            "ii_session_delegation",
            Some(json!({ "sessionPublicKey": "AQID" })),
        )
    }

    fn channel_with(broker: Arc<dyn CallbackBroker>) -> SharedChannel {
        let transport = NativeUrlTransport::with_broker(options(), broker).expect("transport");
        futures::executor::block_on(transport.establish_channel()).expect("channel")
    }

    #[test]
    fn one_session_serves_every_send() {
        let delivery = FakeDelivery::new(|request| {
            answer_with(
                request,
                json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }),
            )
        });
        let broker = FakeBroker::new(delivery.clone());
        let channel = channel_with(broker.clone());

        let first = futures::executor::block_on(channel.send(request())).expect("answer");
        assert!(matches!(first, JsonRpcResponse::Success { .. }));
        let second = futures::executor::block_on(channel.send(request())).expect("answer");
        assert!(matches!(second, JsonRpcResponse::Success { .. }));

        assert_eq!(broker.opened(), 1, "a channel opens one delivery session");
        let calls = delivery.calls();
        assert_eq!(calls.len(), 2);
        assert_ne!(
            calls[0].state, calls[1].state,
            "each step carries a fresh state"
        );
        assert_eq!(
            calls[0].callback_url.as_str(),
            "https://app.example/auth/callback"
        );
        assert_eq!(calls[0].page_url.as_str(), "https://app.example/auth/");
        assert_eq!(calls[0].signer_url, "https://id.ai/authorize");
    }

    #[test]
    fn a_mismatched_state_is_refused() {
        let delivery = FakeDelivery::new(|_request| {
            Ok(CallbackPayload {
                message: json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string(),
                state: Some("not-the-state".to_string()),
            })
        });
        let channel = channel_with(FakeBroker::new(delivery));
        let error = futures::executor::block_on(channel.send(request())).expect_err("refused");
        assert!(matches!(error, SignerError::Protocol(_)), "{error}");
    }

    #[test]
    fn an_answer_for_another_request_is_refused() {
        let delivery = FakeDelivery::new(|request| {
            answer_with(request, json!({ "jsonrpc": "2.0", "id": 7, "result": {} }))
        });
        let channel = channel_with(FakeBroker::new(delivery));
        let error = futures::executor::block_on(channel.send(request())).expect_err("refused");
        assert!(matches!(error, SignerError::Protocol(_)), "{error}");
    }

    #[test]
    fn a_batch_answer_is_refused() {
        let delivery = FakeDelivery::new(|request| {
            Ok(CallbackPayload {
                message: json!([{ "jsonrpc": "2.0", "id": 1, "result": {} }]).to_string(),
                state: Some(request.state.clone()),
            })
        });
        let channel = channel_with(FakeBroker::new(delivery));
        let error = futures::executor::block_on(channel.send(request())).expect_err("refused");
        assert!(matches!(error, SignerError::Protocol(_)), "{error}");
    }

    #[test]
    fn a_refused_request_is_returned_as_the_signer_said() {
        let delivery = FakeDelivery::new(|request| {
            answer_with(
                request,
                json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": 3001, "message": "Action aborted" } }),
            )
        });
        let channel = channel_with(FakeBroker::new(delivery));
        let response = futures::executor::block_on(channel.send(request())).expect("answer");
        let error = response.into_result().expect_err("refused");
        assert!(
            matches!(error, SignerError::Refused { code: 3001, .. }),
            "{error}"
        );
    }

    #[test]
    fn a_closed_channel_sends_nothing() {
        let delivery = FakeDelivery::new(|request| {
            answer_with(request, json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
        });
        let fake = delivery.clone();
        let channel = channel_with(FakeBroker::new(delivery));
        futures::executor::block_on(channel.close()).expect("close");
        let error = futures::executor::block_on(channel.send(request())).expect_err("closed");
        assert!(matches!(error, SignerError::ChannelClosed), "{error}");
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn insecure_or_fragmented_urls_are_refused() {
        let broker = || FakeBroker::new(FakeDelivery::new(|_request| unreachable!()));
        let mut insecure = options();
        insecure.signer_url = "http://id.ai/authorize".to_string();
        assert!(NativeUrlTransport::with_broker(insecure, broker()).is_err());

        let mut fragmented = options();
        fragmented.signer_url = "https://id.ai/authorize#fragment".to_string();
        assert!(NativeUrlTransport::with_broker(fragmented, broker()).is_err());

        let mut pathy = options();
        pathy.relay_origin = "https://app.example/auth".to_string();
        assert!(NativeUrlTransport::with_broker(pathy, broker()).is_err());

        let mut traversal = options();
        traversal.relay_page = "/auth/../evil".to_string();
        assert!(NativeUrlTransport::with_broker(traversal, broker()).is_err());

        let mut local = options();
        local.relay_origin = "http://127.0.0.1:8787".to_string();
        assert!(NativeUrlTransport::with_broker(local, broker()).is_ok());
    }

    // -- the loopback sessions, with a scripted page -----------------------

    /// A page that behaves like `relay/auth/callback.html`: answers the
    /// navigation it was opened with, then long-polls for the next one.
    struct ScriptedBrowser {
        opens: AtomicUsize,
        posts: Arc<StdMutex<Vec<String>>>,
    }

    impl ScriptedBrowser {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                opens: AtomicUsize::new(0),
                posts: Arc::new(StdMutex::new(Vec::new())),
            })
        }

        fn opens(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }

        fn posts(&self) -> Vec<String> {
            self.posts.lock().unwrap().clone()
        }
    }

    impl BrowserOpener for ScriptedBrowser {
        fn open(&self, url: &str) -> Result<(), String> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let url = url.to_string();
            let posts = self.posts.clone();
            std::thread::spawn(move || {
                let Ok(mut navigation) = Navigation::parse(&url) else {
                    return;
                };
                loop {
                    let Ok(request) = serde_json::from_str::<JsonRpcRequest>(&navigation.message)
                    else {
                        return;
                    };
                    let id = serde_json::to_value(&request.id).expect("id");
                    let body = json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } });
                    let payload = json!({ "state": navigation.state, "message": body.to_string() });
                    posts.lock().unwrap().push(navigation.state.clone());
                    if navigation.post(&payload.to_string()).is_err() {
                        return;
                    }
                    match navigation.poll() {
                        Ok(Some(next)) => navigation = next,
                        _ => return,
                    }
                }
            });
            Ok(())
        }
    }

    #[derive(Clone)]
    struct Navigation {
        port: u16,
        token: String,
        message: String,
        state: String,
    }

    impl Navigation {
        fn parse(url: &str) -> Result<Self, String> {
            let url = url::Url::parse(url).map_err(|error| error.to_string())?;
            let fragment = url.fragment().ok_or("no fragment")?;
            let mut fields = std::collections::HashMap::new();
            for (name, value) in url::form_urlencoded::parse(fragment.as_bytes()).into_owned() {
                fields.insert(name, value);
            }
            Ok(Self {
                port: fields
                    .get("port")
                    .ok_or("no port")?
                    .parse()
                    .map_err(|_| "bad port")?,
                token: fields.get("token").ok_or("no token")?.clone(),
                message: fields.get("message").ok_or("no message")?.clone(),
                state: fields.get("state").ok_or("no state")?.clone(),
            })
        }

        fn post(&self, body: &str) -> Result<(), String> {
            self.exchange("POST", RELAY_POST_PATH, Some(body))
        }

        fn poll(&self) -> Result<Option<Self>, String> {
            let (status, body) = self.exchange_with_response("GET", RELAY_POLL_PATH, None)?;
            if status != 200 {
                return Err(format!("poll answered {status}"));
            }
            let parsed: Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
            if parsed.get("done").is_some() {
                return Ok(None);
            }
            let next = parsed
                .get("next")
                .ok_or("poll answered neither next nor done")?;
            let message = next
                .get("message")
                .and_then(Value::as_str)
                .ok_or("no message")?;
            let state = next
                .get("state")
                .and_then(Value::as_str)
                .ok_or("no state")?;
            Ok(Some(Self {
                port: self.port,
                token: self.token.clone(),
                message: message.to_string(),
                state: state.to_string(),
            }))
        }

        /// A request with no credentials, as a browser makes it for the page.
        fn fetch_without_credentials(&self, path: &str) -> Result<(u16, String), String> {
            use std::io::{Read as _, Write as _};
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", self.port))
                .map_err(|error| error.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|error| error.to_string())?;
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .map_err(|error| error.to_string())?;
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .map_err(|error| error.to_string())?;
            let status = response
                .split_whitespace()
                .nth(1)
                .and_then(|status| status.parse().ok())
                .ok_or("unreadable status line")?;
            let body = response
                .split_once("\r\n\r\n")
                .map(|(_, body)| body.to_string())
                .unwrap_or_default();
            Ok((status, body))
        }

        fn exchange(&self, method: &str, path: &str, body: Option<&str>) -> Result<(), String> {
            let (status, _) = self.exchange_with_response(method, path, body)?;
            if status == 204 {
                Ok(())
            } else {
                Err(format!("{method} {path} answered {status}"))
            }
        }

        fn exchange_with_response(
            &self,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> Result<(u16, String), String> {
            use std::io::{Read as _, Write as _};
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", self.port))
                .map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| e.to_string())?;
            let body = body.unwrap_or("");
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                self.token,
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .map_err(|e| e.to_string())?;
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .map_err(|e| e.to_string())?;
            let status = response
                .split_whitespace()
                .nth(1)
                .and_then(|status| status.parse().ok())
                .ok_or("unreadable status line")?;
            let body = response
                .split_once("\r\n\r\n")
                .map(|(_, body)| body.to_string())
                .unwrap_or_default();
            Ok((status, body))
        }
    }

    struct HandoffBrowser {
        page: Arc<StdMutex<Option<(u16, String)>>>,
    }

    impl HandoffBrowser {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                page: Arc::new(StdMutex::new(None)),
            })
        }
    }

    impl BrowserOpener for HandoffBrowser {
        fn open(&self, url: &str) -> Result<(), String> {
            let page = self.page.clone();
            let url = url.to_string();
            std::thread::spawn(move || {
                let Ok(navigation) = Navigation::parse(&url) else {
                    return;
                };
                // The browser loads the page itself without credentials: it is
                // static and the fragment carries the token.
                if let Ok(response) = navigation.fetch_without_credentials(RELAY_HANDOFF_PATH) {
                    *page.lock().unwrap() = Some(response);
                }
                // Then it does what the page's script does.
                let Ok(request) = serde_json::from_str::<JsonRpcRequest>(&navigation.message)
                else {
                    return;
                };
                let id = serde_json::to_value(&request.id).expect("id");
                let body = json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } });
                let payload = json!({ "state": navigation.state, "message": body.to_string() });
                if navigation.post(&payload.to_string()).is_err() {
                    return;
                }
                let _ = navigation.poll();
            });
            Ok(())
        }
    }

    #[test]
    fn the_handoff_page_is_served_without_credentials() {
        let browser = HandoffBrowser::new();
        let transport = NativeUrlTransport::with_broker(
            options(),
            Arc::new(LoopbackBroker::with_idle(
                browser.clone(),
                Duration::from_millis(500),
            )),
        )
        .expect("a transport");
        let channel =
            futures::executor::block_on(transport.establish_channel()).expect("a channel");
        futures::executor::block_on(channel.send(request())).expect("a delivered request");
        let (status, page) = browser
            .page
            .lock()
            .unwrap()
            .clone()
            .expect("the browser fetched the hand-off page");
        assert_eq!(status, 200);
        assert!(page.contains(RELAY_POST_PATH), "{page}");
        assert!(page.contains(RELAY_POLL_PATH), "{page}");
        futures::executor::block_on(channel.close()).expect("close");
    }

    #[test]
    fn the_handoff_page_posts_and_polls_the_loopback() {
        assert!(HANDOFF_PAGE.contains(RELAY_POST_PATH));
        assert!(HANDOFF_PAGE.contains(RELAY_POLL_PATH));
        assert!(HANDOFF_PAGE.contains("Authorization"));
    }

    fn loopback_transport(
        browser: Arc<ScriptedBrowser>,
        idle: Duration,
        timeout: Duration,
    ) -> SharedChannel {
        let mut options = options();
        options.timeout = timeout;
        let broker = LoopbackBroker::with_idle(browser, idle);
        let transport =
            NativeUrlTransport::with_broker(options, Arc::new(broker)).expect("transport");
        futures::executor::block_on(transport.establish_channel()).expect("channel")
    }

    #[test]
    fn a_second_step_rides_the_same_tab() {
        let browser = ScriptedBrowser::new();
        let channel = loopback_transport(
            browser.clone(),
            Duration::from_millis(300),
            Duration::from_secs(5),
        );

        let first = futures::executor::block_on(channel.send(request())).expect("first step");
        assert!(matches!(first, JsonRpcResponse::Success { .. }));
        // The page reports the answer and starts polling for the next step.
        std::thread::sleep(Duration::from_millis(150));

        let second = futures::executor::block_on(channel.send(request())).expect("second step");
        assert!(matches!(second, JsonRpcResponse::Success { .. }));

        assert_eq!(browser.opens(), 1, "the second step used the open tab");
        assert_eq!(browser.posts().len(), 2);
        futures::executor::block_on(channel.close()).expect("close");
    }

    #[test]
    fn a_step_after_the_page_finished_opens_a_new_tab() {
        let browser = ScriptedBrowser::new();
        let channel = loopback_transport(
            browser.clone(),
            Duration::from_millis(150),
            Duration::from_secs(5),
        );

        futures::executor::block_on(channel.send(request())).expect("first step");
        // Let the page's poll time out ("done") and the tab go away.
        std::thread::sleep(Duration::from_millis(600));

        futures::executor::block_on(channel.send(request())).expect("second step");
        assert_eq!(browser.opens(), 2, "a finished page is replaced");
        futures::executor::block_on(channel.close()).expect("close");
    }

    #[test]
    fn closing_the_channel_releases_the_listener() {
        let browser = ScriptedBrowser::new();
        let channel = loopback_transport(
            browser.clone(),
            Duration::from_millis(200),
            Duration::from_secs(5),
        );
        futures::executor::block_on(channel.send(request())).expect("step");
        futures::executor::block_on(channel.close()).expect("close");
        let error = futures::executor::block_on(channel.send(request())).expect_err("closed");
        assert!(matches!(error, SignerError::ChannelClosed), "{error}");
    }

    /// Opens nothing at all: the page never answers.
    struct QuietBrowser;

    impl BrowserOpener for QuietBrowser {
        fn open(&self, _url: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn a_page_that_never_answers_times_out() {
        let mut options = options();
        options.timeout = Duration::from_millis(250);
        let broker = LoopbackBroker::with_opener(Arc::new(QuietBrowser));
        let transport =
            NativeUrlTransport::with_broker(options, Arc::new(broker)).expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let error = futures::executor::block_on(channel.send(request())).expect_err("timeout");
        assert!(matches!(error, SignerError::Timeout), "{error}");
    }

    #[test]
    fn a_wrong_token_is_ignored() {
        struct WrongTokenBrowser;
        impl BrowserOpener for WrongTokenBrowser {
            fn open(&self, url: &str) -> Result<(), String> {
                let url = url.to_string();
                std::thread::spawn(move || {
                    let Ok(navigation) = Navigation::parse(&url) else {
                        return;
                    };
                    let payload = json!({ "state": navigation.state, "message": "{}" }).to_string();
                    let _ = post_with_token(navigation.port, "Bearer wrong-token", &payload);
                });
                Ok(())
            }
        }

        let mut options = options();
        options.timeout = Duration::from_millis(300);
        let broker = LoopbackBroker::with_opener(Arc::new(WrongTokenBrowser));
        let transport =
            NativeUrlTransport::with_broker(options, Arc::new(broker)).expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let error = futures::executor::block_on(channel.send(request())).expect_err("timeout");
        assert!(matches!(error, SignerError::Timeout), "{error}");
    }

    fn post_with_token(port: u16, authorization: &str, body: &str) -> Result<(), String> {
        use std::io::Write as _;
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        let request = format!(
            "POST {RELAY_POST_PATH} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: {authorization}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn a_browser_that_cannot_open_fails_the_send() {
        struct BrokenBrowser;
        impl BrowserOpener for BrokenBrowser {
            fn open(&self, _url: &str) -> Result<(), String> {
                Err("no browser".to_string())
            }
        }

        let broker = LoopbackBroker::with_opener(Arc::new(BrokenBrowser));
        let transport =
            NativeUrlTransport::with_broker(options(), Arc::new(broker)).expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let error = futures::executor::block_on(channel.send(request())).expect_err("no browser");
        assert!(matches!(error, SignerError::Transport(_)), "{error}");
    }
}
