#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! ## Features
//!
//! - `keyring` --- Enable secure store relying on platform for `native` feature
//! - `pem` --- Enable PEM support for `native` feature
//! - `native` --- Enable native platform support (needs one of `keyring` or `pem` feature)
//! - `tracing` --- Enable logging with [tracing](https://crates.io/crates/tracing)
//! - `wasm-js` *(enabled by default)* --- Enable WebView support

#[cfg(not(any(feature = "native", feature = "wasm-js")))]
compile_error!("Either feature \"native\" or \"wasm-js\" must be enabled for this crate");

#[cfg(feature = "tracing")]
#[macro_use]
extern crate tracing;

pub mod api;
mod auth_client;
pub mod idle_manager;
pub mod key;
pub mod option;
pub mod storage;
mod util;

pub use auth_client::*;
pub use idle_manager::IdleManagerOptions;
#[cfg(feature = "native")]
pub use option::native::NativeAuthClientCreateOptions;
#[cfg(feature = "wasm-js")]
pub use option::wasm_js::AuthClientCreateOptions;
pub use option::{AuthClientLoginOptions, IdleOptions};
pub use util::{arc_identity::ArcIdentity, callback, delegation_chain};

#[cfg(feature = "uniffi")]
mod uniffi_bindings;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
