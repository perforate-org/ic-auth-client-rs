//! Authentication client options and configuration types.
//!
//! This module provides the main configuration structures for authentication flows,
//! including login options and idle timeout handling.

use crate::{
    callback::{OnError, OnSuccess},
    idle_manager::IdleManagerOptions,
};

#[cfg(feature = "native")]
pub mod native;
#[cfg(feature = "wasm-js")]
pub mod wasm_js;

/// Options for the [`AuthClient::login_with_options`](crate::AuthClient::login_with_options).
#[derive(Clone, Default, bon::Builder)]
#[builder(on(String, into))]
pub struct AuthClientLoginOptions {
    /// The URL of the identity provider.
    pub identity_provider: Option<String>,

    /// Expiration of the authentication in nanoseconds.
    pub max_time_to_live: Option<u64>,

    /// If present, indicates whether or not the Identity Provider should allow the user to authenticate and/or register using a temporary key/PIN identity.
    ///
    /// Authenticating dapps may want to prevent users from using Temporary keys/PIN identities because Temporary keys/PIN identities are less secure than Passkeys (webauthn credentials) and because Temporary keys/PIN identities generally only live in a browser database (which may get cleared by the browser/OS).
    pub allow_pin_authentication: Option<bool>,

    /// Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
    ///
    /// See: <https://github.com/dfinity/internet-identity/blob/main/docs/ii-spec.mdx#alternative-frontend-origins>
    pub derivation_origin: Option<String>,

    /// Auth Window feature config string.
    ///
    /// # Example
    /// ```ignore
    /// toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100
    /// ```
    pub window_opener_features: Option<String>,

    /// Callback once login has completed.
    #[builder(into)]
    pub on_success: Option<OnSuccess>,

    /// Callback in case authentication fails.
    #[builder(into)]
    pub on_error: Option<OnError>,

    /// Timeout for the authentication process. If not provided, 5 minutes will be used.
    pub timeout: Option<std::time::Duration>,

    /// Extra values to be passed in the login request during the authorize-ready phase.
    pub custom_values: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Options for handling idle timeouts.
#[derive(Default, Clone, Debug, bon::Builder)]
pub struct IdleOptions {
    /// If set to `true`, disables the idle timeout functionality.
    pub disable_idle: Option<bool>,
    /// If set to `true`, disables the default idle timeout callback.
    pub disable_default_idle_callback: Option<bool>,
    /// Options for the [`IdleManager`](crate::idle_manager::IdleManager) that handles idle timeouts.
    pub idle_manager_options: IdleManagerOptions,
}
