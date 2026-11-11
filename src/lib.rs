#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! ## Features
//!
//! - `keyring` --- Enable secure store relying on platform for `native` feature
//! - `pem` --- Enable PEM support for `native` feature
//! - `android-password` --- Enable password-encrypted file storage for Android/Kotlin native usage
//! - `native` --- Enable native platform support (needs one of `keyring` or `pem` feature)
//! - `tracing` --- Enable logging with [tracing](https://crates.io/crates/tracing)
//! - `wasm-js` *(enabled by default)* --- Enable WebView support

#[cfg(not(any(feature = "native", feature = "wasm-js")))]
compile_error!("Either feature \"native\" or \"wasm-js\" must be enabled for this crate");

#[cfg(feature = "tracing")]
extern crate tracing;

/// The `ic-agent` this crate is built against.
///
/// An identity is only usable with an agent from the *same* `ic-agent` crate
/// instance: another version is another `Identity` trait, and passing this
/// crate's identity to it does not typecheck. Depend on this re-export rather
/// than adding `ic-agent` yourself, so that there is exactly one in the tree.
pub use ic_agent;

pub mod client;
pub mod key;
pub mod signer;
pub mod storage;
mod util;

pub use client::{
    AuthClient, AuthClientCreateOptions, AuthClientError, AuthClientErrorKind, ClientIdentity,
    Credential, CredentialStorage, IdentityProvider, MemoryCredentialStorage, MemoryStateStorage,
    NotificationConsentStatus, OpenIdProvider, Prompt, SessionState, SessionStatus, SignInOptions,
    SignOutOptions, SignedAttributes, Slots, SsoStatus, StoredSessionState, Subscription,
    TransportMode,
};
#[cfg(feature = "native")]
pub use client::{credentials::NativeCredentialStorage, state::NativeStateStorage};
pub use client::{
    credentials::SharedCredentialStorage, state::SharedStateStorage, transport::SharedTransport,
};
#[cfg(feature = "wasm-js")]
pub use client::{
    credentials::{IdbCredentialStorage, LocalCredentialStorage, SharedMemoryCredentialStorage},
    state::{CookieStateStorage, LocalStateStorage},
    transport::{PostMessageTransport, UrlTransport},
};
pub use util::{arc_identity::ArcIdentity, delegation_chain};

#[cfg(feature = "uniffi")]
mod uniffi_bindings;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
