//! How the signer is talked to.
//!
//! Port of upstream `@icp-sdk/signer`'s transport layer (`transport.ts`,
//! `web/postMessageTransport.ts`, `web/urlTransport.ts`), reduced to what the
//! authentication client needs: a channel that carries JSON-RPC requests and
//! responses, and a transport that can establish one.
//!
//! The platform implementations live beside this module:
//!
//! - `post_message` --- ICRC-29 `postMessage` transport in a browser window
//! - `url` --- ICRC-167 browser URL transport (redirect), with a journal that
//!   survives the navigation
//!
//! There is no native transport: a non-browser client does not speak the
//! signer protocol at all. It signs in through the identity provider's own
//! non-browser flow instead, which hands a delegation to a loopback listener
//! and needs no hosted bridge page --- see [`crate::client::webauth`].

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::client::platform::PlatformBounds;

#[cfg(any(feature = "wasm-js", test))]
pub mod post_message;
#[cfg(any(feature = "wasm-js", test))]
pub mod url;

/// The JSON-RPC version every message carries.
pub const JSON_RPC_VERSION: &str = "2.0";

/// The JSON-RPC error object.
///
/// Port of upstream `JsonRpcError` (`transport.ts:1-5`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// The error code.
    pub code: i64,
    /// A short human-readable message.
    pub message: String,
    /// Implementation-specific detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC request id, which the wire allows to be a string, a number or
/// null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    /// A numeric id.
    Number(i64),
    /// A string id.
    String(String),
    /// The null id.
    Null,
}

impl fmt::Display for JsonRpcId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonRpcId::Number(id) => write!(f, "{id}"),
            JsonRpcId::String(id) => write!(f, "{id}"),
            JsonRpcId::Null => write!(f, "null"),
        }
    }
}

impl From<i64> for JsonRpcId {
    fn from(id: i64) -> Self {
        JsonRpcId::Number(id)
    }
}

impl From<String> for JsonRpcId {
    fn from(id: String) -> Self {
        JsonRpcId::String(id)
    }
}

/// A JSON-RPC request.
///
/// Port of upstream `JsonRpcRequest` (`transport.ts:6-11`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Always [`JSON_RPC_VERSION`].
    pub jsonrpc: String,
    /// The request id, echoed in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<JsonRpcId>,
    /// The method to call.
    pub method: String,
    /// The method's parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// A request carrying the JSON-RPC version.
    pub fn new(id: impl Into<JsonRpcId>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id: Some(id.into()),
            method: method.into(),
            params,
        }
    }

    /// A notification: a request with no id.
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id: None,
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC response.
///
/// Port of upstream `JsonRpcResponse` (`transport.ts:12-14`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponse {
    /// The method succeeded.
    Success {
        /// Always [`JSON_RPC_VERSION`].
        jsonrpc: String,
        /// The request id being answered.
        id: JsonRpcId,
        /// The method's result.
        result: Value,
    },
    /// The method failed.
    Failure {
        /// Always [`JSON_RPC_VERSION`].
        jsonrpc: String,
        /// The request id being answered.
        id: JsonRpcId,
        /// What went wrong.
        error: JsonRpcError,
    },
}

impl JsonRpcResponse {
    /// The request id this response answers.
    pub fn id(&self) -> &JsonRpcId {
        match self {
            JsonRpcResponse::Success { id, .. } | JsonRpcResponse::Failure { id, .. } => id,
        }
    }

    /// The result value, or the error as a [`SignerError`].
    pub fn into_result(self) -> Result<Value, SignerError> {
        match self {
            JsonRpcResponse::Success { result, .. } => Ok(result),
            JsonRpcResponse::Failure { error, .. } => Err(SignerError::Refused {
                code: error.code,
                message: error.message,
                data: error.data,
            }),
        }
    }
}

/// Everything that can go wrong while talking to a signer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The channel is closed.
    #[error("the signer channel is closed")]
    ChannelClosed,
    /// The signer closed its window (or the user did).
    #[error("the signer window was closed before it answered")]
    WindowClosed,
    /// The transport failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The signer answered with something this crate does not understand.
    #[error("signer protocol error: {0}")]
    Protocol(String),
    /// The signer refused the request.
    #[error("the signer refused: {code} {message}")]
    Refused {
        /// The JSON-RPC error code.
        code: i64,
        /// The signer's message.
        message: String,
        /// The signer's detail.
        data: Option<Value>,
    },
    /// The signer did not answer in time.
    #[error("timed out waiting for the signer")]
    Timeout,
    /// The signer answered with a delegation this crate will not accept.
    #[error("invalid delegation: {0}")]
    InvalidDelegation(String),
    /// The platform cannot provide this transport.
    #[error("unsupported transport: {0}")]
    Unsupported(&'static str),
}

impl SignerError {
    /// The JSON-RPC code for "interaction required", which a silent re-issue
    /// reports.
    pub const CODE_INTERACTION_REQUIRED: i64 = 3002;

    /// The JSON-RPC code for "method not found".
    pub const CODE_METHOD_NOT_FOUND: i64 = -32601;

    /// Whether the signer asked for user interaction.
    pub fn is_interaction_required(&self) -> bool {
        matches!(self, SignerError::Refused { code, .. } if *code == Self::CODE_INTERACTION_REQUIRED)
    }

    /// Whether the signer does not implement the method.
    pub fn is_method_not_found(&self) -> bool {
        matches!(self, SignerError::Refused { code, .. } if *code == Self::CODE_METHOD_NOT_FOUND)
    }

    /// The refusal's reason, when the signer's data carries one.
    pub fn refusal_reason(&self) -> Option<String> {
        match self {
            SignerError::Refused { data, message, .. } => data
                .as_ref()
                .and_then(|data| {
                    data.get("reason")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| {
                            data.get("message")
                                .and_then(Value::as_str)
                                .map(str::to_string)
                        })
                })
                .or_else(|| Some(message.clone())),
            _ => None,
        }
    }
}

/// A channel to one signer.
///
/// Port of upstream `Channel` (`transport.ts:16-37`). Upstream's channel is
/// event based (`send`, `addEventListener('response')`); this port keeps the
/// same semantics as a request/response call, because the Rust client awaits the
/// response it needs and never handles another request's message.
#[async_trait(?Send)]
pub trait Channel: PlatformBounds {
    /// Sends a request and waits for the response that answers it.
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, SignerError>;

    /// Whether the channel is closed.
    fn is_closed(&self) -> bool;

    /// Closes the channel, releasing the signer window if this end owns it.
    async fn close(&self) -> Result<(), SignerError>;
}

/// A channel behind an `Arc`.
pub type SharedChannel = Arc<dyn Channel>;

/// Establishes a channel to a signer.
///
/// Port of upstream `Transport` (`transport.ts:39-41`).
#[async_trait(?Send)]
pub trait Transport: PlatformBounds {
    /// Opens whatever the transport needs to open, **synchronously**.
    ///
    /// A browser only lets a popup or a navigation start inside the user
    /// gesture that asked for it, so the client calls this from the synchronous
    /// entry point (`AuthClient::sign_in`) rather than from inside the awaited
    /// future, whose first poll may already be a microtask too late.
    fn open(&self) -> Result<(), SignerError> {
        Ok(())
    }

    /// Establishes the channel, opening the signer window where the transport
    /// needs one.
    async fn establish_channel(&self) -> Result<SharedChannel, SignerError>;

    /// The journal this transport persists across a page navigation, where it
    /// survives one (the ICRC-167 URL transport).
    fn journal(&self) -> Option<SharedJournal> {
        None
    }
}

/// A transport behind an `Arc`.
pub type SharedTransport = Arc<dyn Transport>;

/// Values persisted across a page navigation by a redirect transport.
///
/// Port of upstream's `UrlTransport.memoize` (`@icp-sdk/signer`
/// `web/urlTransport.ts`), split out so that the authentication client can
/// journal a value without knowing how the medium works.
pub trait Journal: PlatformBounds {
    /// The journaled value for `key`, when the return load finds one.
    fn get(&self, key: &str) -> Option<Value>;

    /// Journals a value for `key`.
    fn put(&self, key: &str, value: Value);

    /// Removes the value journaled for `key`.
    fn remove(&self, key: &str);
}

/// A journal behind an `Arc`.
pub type SharedJournal = Arc<dyn Journal>;

/// A journal with no medium behind it, which is what a window transport uses.
#[derive(Debug, Default)]
pub struct NullJournal;

impl Journal for NullJournal {
    fn get(&self, _key: &str) -> Option<Value> {
        None
    }

    fn put(&self, _key: &str, _value: Value) {}

    fn remove(&self, _key: &str) {}
}

#[cfg(feature = "wasm-js")]
pub use post_message::{PostMessageChannel, PostMessageTransport, PostMessageTransportOptions};
#[cfg(feature = "wasm-js")]
pub use url::{UrlChannel, UrlJournal, UrlTransport, UrlTransportOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serialises_with_version_and_id() {
        let request = JsonRpcRequest::new(1, "icrc25_supported_standards", None);
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "icrc25_supported_standards");
        assert!(json.get("params").is_none());
    }

    #[test]
    fn notification_has_no_id() {
        let request = JsonRpcRequest::notification("icrc29_close_channel", None);
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("id").is_none());
    }

    #[test]
    fn success_and_failure_responses_parse() {
        let success: JsonRpcResponse =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).unwrap();
        assert_eq!(success.id(), &JsonRpcId::Number(1));
        assert!(success.into_result().is_ok());

        let failure: JsonRpcResponse = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":"a","error":{"code":3002,"message":"interaction required"}}"#,
        )
        .unwrap();
        let error = failure.into_result().unwrap_err();
        assert!(error.is_interaction_required());
        assert_eq!(
            error.refusal_reason().as_deref(),
            Some("interaction required")
        );
    }

    #[test]
    fn method_not_found_is_recognised() {
        let error = SignerError::Refused {
            code: -32601,
            message: "method not found".into(),
            data: None,
        };
        assert!(error.is_method_not_found());
        assert!(!error.is_interaction_required());
    }
}
