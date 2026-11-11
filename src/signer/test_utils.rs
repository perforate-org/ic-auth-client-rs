//! Test doubles for the signer transport seam.
//!
//! Port of the `FakeTransport` / `FakeChannel` pair the upstream package ships
//! for its tests (`@icp-sdk/auth` `tests/client/fake-transport.ts`), adapted to
//! this crate's request/response [`Channel`](crate::client::transport::Channel):
//! a `send` returns the response instead of the response arriving through a
//! listener, so the fake answers by method name and records the requests.
//!
//! The double is compiled for this crate's own tests and, behind the hidden
//! `wasm-compat-test` feature, for wasm-side compatibility checks. It is not
//! part of the public API.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use serde_json::Value;

use crate::client::transport::{
    Channel, JSON_RPC_VERSION, JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse,
    SharedChannel, SharedTransport, SignerError, Transport,
};

/// What a [`FakeTransport`] answers a method with.
#[derive(Debug, Clone)]
enum FakeReply {
    /// A successful result, wrapped in a response echoing the request's id.
    Result(Value),
    /// A JSON-RPC error response.
    Error {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    /// The channel closed before it could answer.
    ChannelClosed,
    /// The signer's window closed before it could answer.
    WindowClosed,
    /// The transport itself failed.
    Transport(String),
}

/// An in-memory [`Transport`] for tests: answers by method name and records
/// every request.
///
/// Handlers are registered per method and are looked up when the request is
/// sent, so a test may register one after the channel exists. A method with no
/// registered reply is a test bug and answers with a protocol error naming it.
///
/// Cloning is cheap and shares the recorded requests and replies, which is what
/// lets a test keep a handle while [`Signer`](crate::signer::Signer) owns the
/// `Arc<dyn Transport>`.
#[derive(Clone, Default)]
pub struct FakeTransport {
    inner: Arc<FakeInner>,
}

#[derive(Default)]
struct FakeInner {
    /// How many channels have been established.
    establishes: AtomicUsize,
    /// Channels with a generation at or below this read as closed: what
    /// [`FakeTransport::force_close`] raises.
    closed_through: AtomicUsize,
    /// How many channels have been closed through the channel API.
    closed_channels: AtomicUsize,
    requests: Mutex<Vec<JsonRpcRequest>>,
    replies: Mutex<HashMap<String, FakeReply>>,
    establish_failure: Mutex<Option<String>>,
    yield_establish: AtomicBool,
    wrong_response_id: AtomicBool,
}

impl FakeTransport {
    /// A transport with nothing registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// The transport behind an `Arc`, ready for
    /// [`SignerOptions`](crate::signer::SignerOptions).
    pub fn shared(&self) -> SharedTransport {
        Arc::new(self.clone())
    }

    /// Answers `method` with a successful result.
    pub fn on_result(&self, method: impl Into<String>, result: Value) {
        self.set_reply(method.into(), FakeReply::Result(result));
    }

    /// Answers `method` with a JSON-RPC error.
    pub fn on_error(
        &self,
        method: impl Into<String>,
        code: i64,
        message: impl Into<String>,
        data: Option<Value>,
    ) {
        self.set_reply(
            method.into(),
            FakeReply::Error {
                code,
                message: message.into(),
                data,
            },
        );
    }

    /// Answers `method` by closing the channel before responding.
    pub fn on_close(&self, method: impl Into<String>) {
        self.set_reply(method.into(), FakeReply::ChannelClosed);
    }

    /// Answers `method` by reporting the signer's window closed.
    pub fn on_window_closed(&self, method: impl Into<String>) {
        self.set_reply(method.into(), FakeReply::WindowClosed);
    }

    /// Answers `method` with a transport-level failure.
    pub fn on_transport_error(&self, method: impl Into<String>, message: impl Into<String>) {
        self.set_reply(method.into(), FakeReply::Transport(message.into()));
    }

    /// Makes the next establishment fail with a transport error.
    pub fn fail_establish(&self, message: impl Into<String>) {
        *self
            .inner
            .establish_failure
            .lock()
            .expect("the fake transport is not poisoned") = Some(message.into());
    }

    /// Stops [`FakeTransport::fail_establish`] from applying.
    pub fn allow_establish(&self) {
        *self
            .inner
            .establish_failure
            .lock()
            .expect("the fake transport is not poisoned") = None;
    }

    /// Makes the next establishment take one round of polling before it
    /// resolves, so a test can observe concurrent callers waiting for it.
    pub fn yield_on_establish(&self) {
        self.inner.yield_establish.store(true, Ordering::SeqCst);
    }

    /// Reads every channel as closed from now on, without closing them first.
    ///
    /// A channel established after this call is open again: this models the
    /// window/transport reporting the channel gone underneath the client.
    pub fn force_close(&self) {
        self.inner.closed_through.store(
            self.inner.establishes.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }

    /// Whether some channel has been closed through the channel API.
    pub fn channel_closed(&self) -> bool {
        self.inner.closed_channels.load(Ordering::SeqCst) > 0
    }

    /// How many channels have been established so far.
    pub fn establish_count(&self) -> usize {
        self.inner.establishes.load(Ordering::SeqCst)
    }

    /// Every request recorded, in the order the channels were asked to send it.
    pub fn requests(&self) -> Vec<JsonRpcRequest> {
        self.inner
            .requests
            .lock()
            .expect("the fake transport is not poisoned")
            .clone()
    }

    /// The method names of every recorded request, in send order.
    pub fn methods(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .map(|request| request.method)
            .collect()
    }

    /// The last recorded request, if any.
    pub fn last_request(&self) -> Option<JsonRpcRequest> {
        self.inner
            .requests
            .lock()
            .expect("the fake transport is not poisoned")
            .last()
            .cloned()
    }

    /// Forgets every recorded request, keeping the replies.
    pub fn clear_requests(&self) {
        self.inner
            .requests
            .lock()
            .expect("the fake transport is not poisoned")
            .clear();
    }

    /// Makes every response carry an id that does not answer the request.
    pub fn answer_with_the_wrong_id(&self) {
        self.inner.wrong_response_id.store(true, Ordering::SeqCst);
    }

    fn set_reply(&self, method: String, reply: FakeReply) {
        self.inner
            .replies
            .lock()
            .expect("the fake transport is not poisoned")
            .insert(method, reply);
    }
}

#[async_trait(?Send)]
impl Transport for FakeTransport {
    async fn establish_channel(&self) -> Result<SharedChannel, SignerError> {
        self.inner.establishes.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = self
            .inner
            .establish_failure
            .lock()
            .expect("the fake transport is not poisoned")
            .clone()
        {
            return Err(SignerError::Transport(message));
        }
        if self.inner.yield_establish.swap(false, Ordering::SeqCst) {
            yield_once().await;
        }
        Ok(Arc::new(FakeChannel {
            inner: Arc::clone(&self.inner),
            generation: self.inner.establishes.load(Ordering::SeqCst),
            closed: AtomicBool::new(false),
        }))
    }
}

/// The channel a [`FakeTransport`] hands out.
///
/// Answers every request from the transport's registered replies and records it
/// first. A request without an id is a JSON-RPC notification, which the
/// request/response channel this crate uses cannot represent, so it is refused
/// rather than left unanswered.
pub struct FakeChannel {
    inner: Arc<FakeInner>,
    /// The establishment this channel belongs to, for [`FakeTransport::force_close`].
    generation: usize,
    closed: AtomicBool,
}

impl FakeChannel {
    fn is_closed_by_transport(&self) -> bool {
        self.generation <= self.inner.closed_through.load(Ordering::SeqCst)
    }

    fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) && !self.is_closed_by_transport() {
            self.inner.closed_channels.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn stamp(&self, id: JsonRpcId) -> JsonRpcId {
        if self.inner.wrong_response_id.load(Ordering::SeqCst) {
            JsonRpcId::String("00000000-0000-4000-8000-000000000000".to_string())
        } else {
            id
        }
    }
}

#[async_trait(?Send)]
impl Channel for FakeChannel {
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, SignerError> {
        if self.is_closed() {
            return Err(SignerError::ChannelClosed);
        }
        self.inner
            .requests
            .lock()
            .expect("the fake transport is not poisoned")
            .push(request.clone());

        let Some(id) = request.id.clone() else {
            return Err(SignerError::Protocol(
                "the request/response channel does not support notifications".to_string(),
            ));
        };
        let reply = self
            .inner
            .replies
            .lock()
            .expect("the fake transport is not poisoned")
            .get(&request.method)
            .cloned();
        let Some(reply) = reply else {
            return Err(SignerError::Protocol(format!(
                "FakeTransport has no reply registered for method {:?}",
                request.method
            )));
        };

        match reply {
            FakeReply::Result(result) => Ok(JsonRpcResponse::Success {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: self.stamp(id),
                result,
            }),
            FakeReply::Error {
                code,
                message,
                data,
            } => Ok(JsonRpcResponse::Failure {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: self.stamp(id),
                error: JsonRpcError {
                    code,
                    message,
                    data,
                },
            }),
            FakeReply::ChannelClosed => {
                self.mark_closed();
                Err(SignerError::ChannelClosed)
            }
            FakeReply::WindowClosed => {
                self.mark_closed();
                Err(SignerError::WindowClosed)
            }
            FakeReply::Transport(message) => Err(SignerError::Transport(message)),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.is_closed_by_transport()
    }

    async fn close(&self) -> Result<(), SignerError> {
        self.mark_closed();
        Ok(())
    }
}

/// A future that is pending once and then ready, waking itself.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn yield_once() -> YieldOnce {
    YieldOnce(false)
}
