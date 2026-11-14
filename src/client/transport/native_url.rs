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

/// What the relay page sends back to the loopback listener.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackPayload {
    /// The callback fragment's `message`: the raw JSON-RPC response.
    pub message: String,
    /// The callback fragment's `state`, echoed from the request.
    pub state: Option<String>,
}

/// One navigation to run: everything the broker needs to deliver a request to
/// the signer and bring its answer back.
#[derive(Debug, Clone)]
pub struct RelayRequest {
    /// The signer URL, fragment-free.
    pub signer_url: String,
    /// The relay page to open.
    pub page_url: url::Url,
    /// The callback to declare to the signer.
    pub callback_url: url::Url,
    /// The JSON-RPC request, serialized.
    pub message: String,
    /// The single-use state to send and check.
    pub state: String,
    /// How long the navigation may take.
    pub timeout: Duration,
}

/// Runs one navigation and returns what the relay page received.
///
/// The default is [`LoopbackBroker`]; tests and embedded-webview hosts supply
/// their own. Asynchronous and `!Send` because it awaits a page that lives
/// outside this process.
#[async_trait(?Send)]
pub trait CallbackBroker: PlatformBounds {
    /// Opens the relay page for `request` and waits for its answer.
    async fn deliver(&self, request: RelayRequest) -> Result<CallbackPayload, SignerError>;
}

/// The default broker: the system browser plus a loopback listener.
pub struct LoopbackBroker {
    opener: Arc<dyn BrowserOpener>,
}

impl LoopbackBroker {
    /// A broker that opens the system browser.
    pub fn new() -> Self {
        Self {
            opener: Arc::new(SystemBrowser),
        }
    }

    /// A broker with another way of opening the page, for tests and for hosts
    /// that drive their own browser window.
    pub fn with_opener(opener: Arc<dyn BrowserOpener>) -> Self {
        Self { opener }
    }
}

impl Default for LoopbackBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LoopbackBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackBroker").finish_non_exhaustive()
    }
}

#[async_trait(?Send)]
impl CallbackBroker for LoopbackBroker {
    async fn deliver(&self, request: RelayRequest) -> Result<CallbackPayload, SignerError> {
        // Bind before the URL is built: the page has to know the port.
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

        let token = base64_url_no_pad(&random_bytes());

        // The fragment carries the signer URL and the request itself. Neither
        // the relay page's server nor the signer's backend sees the fragment.
        let mut page = request.page_url.clone();
        page.set_fragment(Some(
            &url::form_urlencoded::Serializer::new(String::new())
                .append_pair("signer", &request.signer_url)
                .append_pair("message", &request.message)
                .append_pair("state", &request.state)
                .append_pair("callback", request.callback_url.as_str())
                .append_pair("port", &port.to_string())
                .append_pair("token", &token)
                .finish(),
        ));

        let deadline = Instant::now() + request.timeout;
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = futures::channel::oneshot::channel();
        let serving_shutdown = shutdown.clone();
        let serving_token = token.clone();
        std::thread::spawn(move || {
            let _ = sender.send(serve(server, deadline, &serving_token, &serving_shutdown));
        });

        match self.opener.open(page.as_str()) {
            Ok(()) => {}
            Err(error) => {
                shutdown.store(true, Ordering::SeqCst);
                return Err(SignerError::Transport(format!(
                    "could not open the browser on the relay page: {error}"
                )));
            }
        }

        match receiver.await {
            Ok(result) => result,
            Err(_) => Err(SignerError::ChannelClosed),
        }
    }
}

/// The loopback half: accepts exactly one relay POST, and only with the token
/// the page was given.
fn serve(
    server: tiny_http::Server,
    deadline: Instant,
    token: &str,
    shutdown: &AtomicBool,
) -> Result<CallbackPayload, SignerError> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err(SignerError::ChannelClosed);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SignerError::Timeout);
        }
        // Wake up regularly so an abandoned flow (browser failed to open, or the
        // caller went away) does not keep this thread for the whole timeout.
        let slice = remaining.min(Duration::from_millis(200));
        match server.recv_timeout(slice) {
            Ok(None) => continue,
            Ok(Some(request)) => {
                if let Some(payload) = handle(request, token) {
                    return Ok(payload);
                }
            }
            Err(error) => {
                return Err(SignerError::Transport(format!(
                    "the relay listener failed: {error}"
                )));
            }
        }
    }
}

/// Answers one HTTP request on the loopback listener.
///
/// Returns the payload only for the relay page's authenticated POST; anything
/// else is answered and ignored, because the port is reachable by any process
/// on the machine while the flow runs.
fn handle(mut request: tiny_http::Request, token: &str) -> Option<CallbackPayload> {
    if request.method() == &tiny_http::Method::Options {
        let _ = request.respond(cors(204));
        return None;
    }
    if request.method() != &tiny_http::Method::Post || request.url() != RELAY_POST_PATH {
        let _ = request.respond(tiny_http::Response::empty(404));
        return None;
    }

    let content_type = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Content-Type"))
        .map(|header| header.value.as_str().to_owned());
    if !content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("application/json"))
    {
        let _ = request.respond(tiny_http::Response::empty(415));
        return None;
    }

    let authorization = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .map(|header| header.value.as_str().to_owned());
    let expected = format!("Bearer {token}");
    let authorized = authorization
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()));
    if !authorized {
        let _ = request.respond(tiny_http::Response::empty(401));
        return None;
    }

    // Bounded, because this port is open to anything on the machine.
    let mut body = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    let reader = request.as_reader();
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if body.len() as u64 + read as u64 > MAX_BODY_BYTES as u64 {
                    let _ = request.respond(tiny_http::Response::empty(413));
                    return None;
                }
                body.extend_from_slice(&buffer[..read]);
            }
            Err(_) => break,
        }
    }

    let payload = match serde_json::from_slice::<CallbackPayload>(&body) {
        Ok(payload) => payload,
        Err(_) => {
            let _ = request.respond(tiny_http::Response::empty(400));
            return None;
        }
    };
    let _ = request.respond(cors(204));
    Some(payload)
}

fn cors(status: u16) -> tiny_http::Response<std::io::Empty> {
    tiny_http::Response::empty(status)
        .with_header(header("Access-Control-Allow-Origin", "*"))
        .with_header(header("Access-Control-Allow-Methods", "POST, OPTIONS"))
        .with_header(header(
            "Access-Control-Allow-Headers",
            "authorization, content-type",
        ))
        .with_header(header("Access-Control-Max-Age", "600"))
}

fn header(name: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

/// Compares two byte strings without leaking where they differ.
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
        Ok(Arc::new(NativeUrlChannel {
            transport: self.clone(),
            closed: AtomicBool::new(false),
        }))
    }
}

struct NativeUrlChannel {
    transport: NativeUrlTransport,
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
            .transport
            .broker
            .deliver(RelayRequest {
                signer_url: self.transport.options.signer_url.clone(),
                page_url: self.transport.options.page_url()?,
                callback_url: self.transport.options.callback_url()?,
                message,
                state: state.clone(),
                timeout: self.transport.options.timeout,
            })
            .await?;

        // The page binds the answer to the request it was given; a mismatch is a
        // stray or forged delivery, not something to reason about.
        if payload.state.as_deref() != Some(state.as_str()) {
            return Err(SignerError::Protocol(format!(
                "the relay page returned state {:?}, expected {:?}",
                payload.state, state
            )));
        }
        if payload.message.trim_start().starts_with('[') {
            return Err(SignerError::Protocol(
                "the signer answered with a JSON-RPC batch; this transport sends one request per navigation"
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::transport::{JsonRpcId, JsonRpcRequest};
    use std::sync::Mutex;

    use serde_json::{Value, json};

    /// What a fake broker answers with.
    type Answer = Box<dyn Fn(&RelayRequest) -> Result<CallbackPayload, SignerError> + Send + Sync>;

    /// A broker that records what it was asked to deliver and answers with a
    /// canned payload, standing in for the browser and the signer.
    struct FakeBroker {
        calls: Mutex<Vec<RelayRequest>>,
        answer: Answer,
    }

    impl FakeBroker {
        fn new(
            answer: impl Fn(&RelayRequest) -> Result<CallbackPayload, SignerError>
            + Send
            + Sync
            + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                answer: Box::new(answer),
            })
        }

        fn calls(&self) -> Vec<RelayRequest> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait(?Send)]
    impl CallbackBroker for FakeBroker {
        async fn deliver(&self, request: RelayRequest) -> Result<CallbackPayload, SignerError> {
            self.calls.lock().unwrap().push(request.clone());
            (self.answer)(&request)
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

    fn channel(broker: Arc<FakeBroker>) -> SharedChannel {
        let transport = NativeUrlTransport::with_broker(options(), broker).expect("transport");
        futures::executor::block_on(transport.establish_channel()).expect("channel")
    }

    #[test]
    fn one_send_is_one_navigation() {
        let broker = FakeBroker::new(|request| {
            answer_with(
                request,
                json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } }),
            )
        });
        let channel = channel(broker.clone());

        let first = futures::executor::block_on(channel.send(request())).expect("answer");
        assert!(matches!(first, JsonRpcResponse::Success { .. }));
        assert_eq!(broker.calls().len(), 1);

        let second = futures::executor::block_on(channel.send(request())).expect("answer");
        assert!(matches!(second, JsonRpcResponse::Success { .. }));
        assert_eq!(
            broker.calls().len(),
            2,
            "a second send is a second navigation"
        );

        // Each navigation carries a fresh single-use state, and the page is told
        // which callback to declare.
        let calls = broker.calls();
        assert_ne!(calls[0].state, calls[1].state);
        assert_eq!(
            calls[0].callback_url.as_str(),
            "https://app.example/auth/callback"
        );
        assert_eq!(calls[0].page_url.as_str(), "https://app.example/auth/");
        assert_eq!(calls[0].signer_url, "https://id.ai/authorize");
    }

    #[test]
    fn a_mismatched_state_is_refused() {
        let broker = FakeBroker::new(|_request| {
            Ok(CallbackPayload {
                message: json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string(),
                state: Some("not-the-state".to_string()),
            })
        });
        let channel = channel(broker);
        let error = futures::executor::block_on(channel.send(request())).expect_err("refused");
        assert!(matches!(error, SignerError::Protocol(_)), "{error}");
    }

    #[test]
    fn an_answer_for_another_request_is_refused() {
        let broker = FakeBroker::new(|request| {
            answer_with(request, json!({ "jsonrpc": "2.0", "id": 7, "result": {} }))
        });
        let channel = channel(broker);
        let error = futures::executor::block_on(channel.send(request())).expect_err("refused");
        assert!(matches!(error, SignerError::Protocol(_)), "{error}");
    }

    #[test]
    fn a_batch_answer_is_refused() {
        let broker = FakeBroker::new(|_request| {
            Ok(CallbackPayload {
                message: json!([{ "jsonrpc": "2.0", "id": 1, "result": {} }]).to_string(),
                state: Some(_request.state.clone()),
            })
        });
        let channel = channel(broker);
        let error = futures::executor::block_on(channel.send(request())).expect_err("refused");
        assert!(matches!(error, SignerError::Protocol(_)), "{error}");
    }

    #[test]
    fn a_refused_request_is_returned_as_the_signer_said() {
        let broker = FakeBroker::new(|request| {
            answer_with(
                request,
                json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": 3001, "message": "Action aborted" } }),
            )
        });
        let channel = channel(broker);
        let response = futures::executor::block_on(channel.send(request())).expect("answer");
        let error = response.into_result().expect_err("refused");
        assert!(
            matches!(error, SignerError::Refused { code: 3001, .. }),
            "{error}"
        );
    }

    #[test]
    fn a_closed_channel_sends_nothing() {
        let broker = FakeBroker::new(|request| {
            answer_with(request, json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
        });
        let channel = channel(broker.clone());
        futures::executor::block_on(channel.close()).expect("close");
        let error = futures::executor::block_on(channel.send(request())).expect_err("closed");
        assert!(matches!(error, SignerError::ChannelClosed), "{error}");
        assert!(broker.calls().is_empty());
    }

    #[test]
    fn insecure_or_fragmented_urls_are_refused() {
        let mut insecure = options();
        insecure.signer_url = "http://id.ai/authorize".to_string();
        assert!(
            NativeUrlTransport::with_broker(insecure, FakeBroker::new(|_| unreachable!())).is_err()
        );

        let mut fragmented = options();
        fragmented.signer_url = "https://id.ai/authorize#fragment".to_string();
        assert!(
            NativeUrlTransport::with_broker(fragmented, FakeBroker::new(|_| unreachable!()))
                .is_err()
        );

        let mut pathy = options();
        pathy.relay_origin = "https://app.example/auth".to_string();
        assert!(
            NativeUrlTransport::with_broker(pathy, FakeBroker::new(|_| unreachable!())).is_err()
        );

        let mut traversal = options();
        traversal.relay_page = "/auth/../evil".to_string();
        assert!(
            NativeUrlTransport::with_broker(traversal, FakeBroker::new(|_| unreachable!()))
                .is_err()
        );

        // Loopback hosts are the development exception.
        let mut local = options();
        local.relay_origin = "http://127.0.0.1:8787".to_string();
        assert!(
            NativeUrlTransport::with_broker(local, FakeBroker::new(|_| unreachable!())).is_ok()
        );
    }

    // -- the loopback half --------------------------------------------------

    /// Opens the page by acting as the relay page and the signer at once: it
    /// answers the URL's request and posts the answer back to the listener.
    struct PostingBrowser {
        post: Arc<dyn Fn(&str) -> String + Send + Sync>,
    }

    impl BrowserOpener for PostingBrowser {
        fn open(&self, url: &str) -> Result<(), String> {
            let post = self.post.clone();
            let url = url.to_string();
            std::thread::spawn(move || {
                let (port, token, state, message) = match parse_relay_url(&url) {
                    Ok(parts) => parts,
                    Err(error) => {
                        eprintln!("PostingBrowser: {error}");
                        return;
                    }
                };
                let request: JsonRpcRequest =
                    serde_json::from_str(&message).expect("the transport sends JSON-RPC");
                let id = serde_json::to_value(request.id).expect("id");
                let body = post(&id.to_string());
                let response = json!({ "state": state, "message": body });
                if let Err(error) = post_to_listener(port, &token, &response.to_string()) {
                    eprintln!("PostingBrowser: {error}");
                }
            });
            Ok(())
        }
    }

    fn parse_relay_url(url: &str) -> Result<(u16, String, String, String), String> {
        let url = url::Url::parse(url).map_err(|error| error.to_string())?;
        let fragment = url.fragment().ok_or("no fragment")?;
        let mut fields = std::collections::HashMap::new();
        for (name, value) in url::form_urlencoded::parse(fragment.as_bytes()).into_owned() {
            fields.insert(name, value);
        }
        Ok((
            fields
                .get("port")
                .ok_or("no port")?
                .parse()
                .map_err(|_| "bad port")?,
            fields.get("token").ok_or("no token")?.clone(),
            fields.get("state").ok_or("no state")?.clone(),
            fields.get("message").ok_or("no message")?.clone(),
        ))
    }

    fn post_to_listener(port: u16, token: &str, body: &str) -> Result<(), String> {
        use std::io::{Read as _, Write as _};
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        let request = format!(
            "POST {RELAY_POST_PATH} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| e.to_string())?;
        if !response.starts_with("HTTP/1.1 204") {
            return Err(format!("unexpected listener answer: {response}"));
        }
        Ok(())
    }

    #[test]
    fn the_loopback_relay_carries_the_answer() {
        let broker = LoopbackBroker::with_opener(Arc::new(PostingBrowser {
            post: Arc::new(|id| {
                json!({ "jsonrpc": "2.0", "id": serde_json::from_str::<Value>(id).expect("id"), "result": { "ok": true } })
                    .to_string()
            }),
        }));
        let transport =
            NativeUrlTransport::with_broker(options(), Arc::new(broker)).expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let response = futures::executor::block_on(channel.send(request())).expect("answer");
        assert!(matches!(response, JsonRpcResponse::Success { .. }));
    }

    #[test]
    fn the_loopback_relay_requires_the_token() {
        // The listener ignores the wrong token and keeps waiting for the page
        // that was actually opened, so the test shortens the deadline.
        let mut options = options();
        options.timeout = Duration::from_millis(300);
        let transport = NativeUrlTransport::with_broker(
            options,
            Arc::new(LoopbackBroker::with_opener(Arc::new(UnauthorizedBrowser))),
        )
        .expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let error = futures::executor::block_on(channel.send(request())).expect_err("no answer");
        assert!(matches!(error, SignerError::Timeout), "{error}");
    }

    /// Posts with the wrong bearer token; the listener must ignore it and wait
    /// for the real page (here: until the flow times out).
    struct UnauthorizedBrowser;

    impl BrowserOpener for UnauthorizedBrowser {
        fn open(&self, url: &str) -> Result<(), String> {
            let url = url.to_string();
            std::thread::spawn(move || {
                if let Ok((port, _token, _state, _message)) = parse_relay_url(&url) {
                    let _ = post_with_token(port, "Bearer wrong-token");
                }
            });
            Ok(())
        }
    }

    fn post_with_token(port: u16, authorization: &str) -> Result<(), String> {
        use std::io::Write as _;
        let body = "{\"state\":\"x\",\"message\":\"{}\"}";
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
    fn a_timeout_is_a_timeout() {
        let mut options = options();
        options.timeout = Duration::from_millis(250);

        struct QuietBrowser;
        impl BrowserOpener for QuietBrowser {
            fn open(&self, _url: &str) -> Result<(), String> {
                Ok(())
            }
        }

        let transport = NativeUrlTransport::with_broker(
            options,
            Arc::new(LoopbackBroker::with_opener(Arc::new(QuietBrowser))),
        )
        .expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let error = futures::executor::block_on(channel.send(request())).expect_err("timeout");
        assert!(matches!(error, SignerError::Timeout), "{error}");
    }

    #[test]
    fn a_browser_that_cannot_open_closes_the_flow() {
        struct BrokenBrowser;
        impl BrowserOpener for BrokenBrowser {
            fn open(&self, _url: &str) -> Result<(), String> {
                Err("no browser".to_string())
            }
        }

        let transport = NativeUrlTransport::with_broker(
            options(),
            Arc::new(LoopbackBroker::with_opener(Arc::new(BrokenBrowser))),
        )
        .expect("transport");
        let channel = futures::executor::block_on(transport.establish_channel()).expect("channel");
        let error = futures::executor::block_on(channel.send(request())).expect_err("no browser");
        assert!(matches!(error, SignerError::Transport(_)), "{error}");
    }
}
