//! The authentication client, shaped after `@icp-sdk/auth` v11.
//!
//! This module is the Rust port of the upstream JavaScript package's
//! `src/client/` tree. The layering follows upstream closely on purpose, so
//! that behaviour can be traced back to the reference implementation:
//!
//! - `auth_client` --- the client itself: a view on stored sign-in state
//! - [`credentials`] --- where the material a client acts with is kept
//! - [`state`] --- where the answer to "who is signed in here" is kept
//! - [`transport`] --- how the signer is talked to (ICRC-29 / ICRC-167 / native bridge)
//! - [`session`] --- app delegations minted from the Internet Identity canister
//! - [`sso`] --- organization-domain sign-in status
//! - [`notification_consent`] --- whether Internet Identity may send notifications
//! - [`foreground_refresh`] --- browser hints that the user is back
//! - [`error`], [`options`], [`slots`], [`base64`] --- shared vocabulary
//!
//! Upstream's root module deliberately throws; a Rust crate cannot, so the
//! equivalent rule is that everything is exported from this one module and
//! nothing is exported at the crate root that is not part of the v11 surface.

pub(crate) mod async_once;
pub mod base64;
pub mod credentials;
#[cfg(feature = "wasm-js")]
pub mod db;
pub mod error;
pub mod foreground_refresh;
pub mod identity;
pub mod notification_consent;
pub mod options;
pub mod platform;
pub mod session;
pub mod slots;
pub mod sso;
pub mod state;
pub mod transport;
#[cfg(all(
    feature = "native",
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]
pub mod webauth;

mod auth_client;
pub(crate) mod now;

/// Drives a future to completion in the background.
///
/// The session identity reports a gone session from a synchronous callback, and
/// the record bookkeeping that follows needs the (asynchronous) credential
/// store, so it runs behind the browser's task queue. `wasm-js` only: the
/// storage traits' futures are not `Send` on native (their stores are
/// synchronous underneath), so there is nothing there to hand to a thread.
#[cfg(feature = "wasm-js")]
pub(crate) fn spawn_background<F>(future: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    wasm_bindgen_futures::spawn_local(future);
}

pub use auth_client::AuthClient;
#[cfg(feature = "native")]
pub use credentials::native::NativeCredentialStorage;
pub use credentials::{
    Credential, CredentialStorage, MemoryCredentialStorage, SharedCredentialStorage,
};
#[cfg(feature = "wasm-js")]
pub use credentials::{
    idb::IdbCredentialStorage, local::LocalCredentialStorage,
    shared_memory::SharedMemoryCredentialStorage,
};
pub use error::{AuthClientError, AuthClientErrorKind};
pub use identity::ClientIdentity;
pub use options::{
    AuthClientCreateOptions, IDENTITY_CANISTER_DEFAULT, IDENTITY_PROVIDER_DEFAULT,
    IdentityProvider, NotificationConsentStatus, OpenIdProvider, Prompt, SessionStatus,
    SignInOptions, SignOutOptions, SignedAttributes, SsoStatus, TransportMode,
};
pub use slots::{Slots, slots_for};
#[cfg(feature = "native")]
pub use state::native::NativeStateStorage;
pub use state::{
    MemoryStateStorage, SessionState, SharedStateStorage, StateListener, StateStorage,
    StoredSessionState, Subscription,
};
#[cfg(feature = "wasm-js")]
pub use state::{cookie::CookieStateStorage, local::LocalStateStorage};
pub use transport::{
    Channel, JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse, SharedChannel,
    SharedJournal, SharedTransport, SignerError, Transport,
};
#[cfg(feature = "wasm-js")]
pub use transport::{post_message::PostMessageTransport, url::UrlTransport};
