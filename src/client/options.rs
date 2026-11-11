//! Options and result types of the v11-shaped client.
//!
//! Port of the option and result types in upstream
//! `src/client/auth-client.ts` (`AuthClientBaseOptions`,
//! `AuthClientCreateOptions`, `AuthClientSignInOptions`, `SessionStatus`,
//! `SsoStatus`, `SignedAttributes`).
//!
//! Names stay close to upstream's so that the documentation of the JavaScript
//! library can be read with a small translation table; Rust naming conventions
//! (snake_case fields, builder methods) are applied.

use ic_agent::export::Principal;

use crate::client::credentials::SharedCredentialStorage;
use crate::client::error::AuthClientError;
use crate::client::state::SharedStateStorage;

/// The default authorize URL a ceremony is rendered at.
///
/// Upstream `auth-client.ts:59`.
pub const IDENTITY_PROVIDER_DEFAULT: &str = "https://id.ai/authorize";

/// The default canister that mints and revokes this application's delegations.
///
/// Upstream `auth-client.ts:60`.
pub const IDENTITY_CANISTER_DEFAULT: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";

/// Where the identity provider is, as two values rather than one.
///
/// A ceremony is rendered at a URL and delegations are minted by a canister, and
/// they are not the same address: a custom domain can front the mainnet
/// canister, and a local deployment changes both. Nothing is derived from the
/// URL --- the origin of one is not a promise about which canister answers
/// there --- so a deployment is named by both or by neither.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct IdentityProvider {
    /// The authorize URL a ceremony is rendered at.
    pub authorize_url: String,
    /// The canister that mints and revokes this application's delegations.
    pub canister_id: Principal,
}

impl IdentityProvider {
    /// A provider named by its two halves.
    pub fn new(authorize_url: impl Into<String>, canister_id: Principal) -> Self {
        Self {
            authorize_url: authorize_url.into(),
            canister_id,
        }
    }
}

impl Default for IdentityProvider {
    fn default() -> Self {
        Self {
            authorize_url: IDENTITY_PROVIDER_DEFAULT.to_string(),
            canister_id: Principal::from_text(IDENTITY_CANISTER_DEFAULT)
                .expect("the default identity canister id is a valid principal"),
        }
    }
}

/// How the client communicates with the identity provider.
///
/// Upstream `auth-client.ts:160-182`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// The identity provider opens in a separate browser tab or window and the
    /// two communicate over the ICRC-29 `postMessage` transport.
    #[default]
    Window,
    /// The current page navigates to the identity provider over the ICRC-167
    /// URL transport, which returns to this same page.
    Redirect,
}

impl TransportMode {
    /// The upstream string for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportMode::Window => "window",
            TransportMode::Redirect => "redirect",
        }
    }
}

/// Whether Internet Identity may answer without user interaction.
///
/// Sent as a `prompt` query param on the authorize URL; an Internet Identity
/// extension inspired by OpenID Connect's `prompt`, and not part of any ICRC
/// standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// `'none'`: answer from a session Internet Identity already holds, or fail
    /// with `interaction_required`.
    None,
    /// `'login'`: run a normal sign-in ceremony.
    Login,
}

impl Prompt {
    /// The upstream string for this prompt.
    pub fn as_str(&self) -> &'static str {
        match self {
            Prompt::None => "none",
            Prompt::Login => "login",
        }
    }
}

/// A one-click OpenID sign-in provider.
///
/// Upstream `auth-client.ts:62-68`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenIdProvider {
    /// `https://accounts.google.com`
    Google,
    /// `https://appleid.apple.com`
    Apple,
    /// `https://login.microsoftonline.com/{tid}/v2.0`
    Microsoft,
}

impl OpenIdProvider {
    /// The provider's authorize URL, as upstream bakes it into the identity
    /// provider URL.
    pub fn url(&self) -> &'static str {
        match self {
            OpenIdProvider::Google => "https://accounts.google.com",
            OpenIdProvider::Apple => "https://appleid.apple.com",
            OpenIdProvider::Microsoft => "https://login.microsoftonline.com/{tid}/v2.0",
        }
    }
}

/// Options for creating an [`AuthClient`](crate::client::AuthClient).
///
/// Port of upstream `AuthClientCreateOptions` (`auth-client.ts:239-271`),
/// including the mutually exclusive one-click entry point.
#[derive(Clone, Default, bon::Builder)]
pub struct AuthClientCreateOptions {
    /// Where credentials are kept. Defaults to the platform's main store.
    pub credential_storage: Option<SharedCredentialStorage>,

    /// Prefix for every slot this client writes under.
    pub namespace: Option<String>,

    /// Where the state of the sign-in is kept.
    pub state_storage: Option<SharedStateStorage>,

    /// Stops this client from watching the browser for signs that somebody is
    /// here.
    pub disable_browser_activity: Option<bool>,

    /// Where the identity provider is.
    pub identity_provider: Option<IdentityProvider>,

    /// The IC host the agent talks to when it mints or revokes delegations.
    ///
    /// Rust-side deviation: upstream passes a whole `HttpAgentOptions` object
    /// (`agentOptions`). The builder of `ic-agent` needs an identity, so this
    /// crate accepts the host here and builds the agent itself.
    pub host: Option<String>,

    /// Derivation origin for the identity provider.
    pub derivation_origin: Option<String>,

    /// Window features string for the authentication popup.
    pub window_opener_features: Option<String>,

    /// How the client communicates with the identity provider.
    pub transport: Option<TransportMode>,

    /// Whether Internet Identity may answer without user interaction.
    pub prompt: Option<Prompt>,

    /// Names which account a silent re-issue is for.
    pub hint: Option<Principal>,

    /// Whether a sign-in kept in the state store may be resumed without a
    /// ceremony.
    pub resumable: Option<bool>,

    /// One-click OpenID sign-in provider. Mutually exclusive with
    /// [`AuthClientCreateOptions::sso_domain`].
    pub open_id_provider: Option<OpenIdProvider>,

    /// Organization domain for one-click SSO sign-in. Mutually exclusive with
    /// [`AuthClientCreateOptions::open_id_provider`].
    pub sso_domain: Option<String>,
}

impl AuthClientCreateOptions {
    /// The identity provider to use, with upstream's default applied.
    pub fn resolved_identity_provider(&self) -> IdentityProvider {
        self.identity_provider.clone().unwrap_or_default()
    }

    /// The transport to use, with upstream's default applied.
    pub fn resolved_transport(&self) -> TransportMode {
        self.transport.unwrap_or_default()
    }

    /// Validates the combinations upstream rejects in the constructor.
    pub(crate) fn validate(&self) -> Result<(), AuthClientError> {
        if self.open_id_provider.is_some() && self.sso_domain.is_some() {
            return Err(AuthClientError::InvalidOptions(
                "open_id_provider and sso_domain are mutually exclusive".to_string(),
            ));
        }
        Ok(())
    }
}

/// Options for [`AuthClient::sign_in`](crate::client::AuthClient::sign_in).
///
/// Port of upstream `AuthClientSignInOptions` (`auth-client.ts:276-300`).
#[derive(Debug, Clone, Default, bon::Builder)]
pub struct SignInOptions {
    /// The maximum time to live for the session, in nanoseconds.
    ///
    /// Sent only when set, so that the provider's own default applies rather
    /// than a number this library invented.
    pub max_time_to_live: Option<u64>,

    /// The maximum time to idle for the session, in nanoseconds.
    pub max_time_to_idle: Option<u64>,

    /// Where to send the page once the sign-in completes. Same-origin `http(s)`
    /// only.
    pub return_to: Option<String>,
}

/// Options for [`AuthClient::sign_out`](crate::client::AuthClient::sign_out).
///
/// Port of upstream `signOut(options)` (`auth-client.ts:1389`).
#[derive(Debug, Clone, Default, bon::Builder)]
pub struct SignOutOptions {
    /// Where to send the page once the sign-out completes. Same-origin `http(s)`
    /// only.
    pub return_to: Option<String>,
}

/// What a client knows about its sign-in, as a value.
///
/// Port of upstream `SessionStatus` (`auth-client.ts:324-332`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// This origin holds a usable credential for the account.
    SignedIn {
        /// The account's principal.
        principal: Principal,
        /// When the sign-in ends, in milliseconds since the Unix epoch.
        expires_at_ms: u64,
    },
    /// A sign-in exists for this domain, but this origin holds no credential
    /// for it.
    SignedInElsewhere {
        /// The account's principal.
        principal: Principal,
        /// When the sign-in ends, in milliseconds since the Unix epoch.
        expires_at_ms: u64,
    },
    /// The sign-in has ended.
    Expired {
        /// The account's principal.
        principal: Principal,
        /// When the sign-in ended, in milliseconds since the Unix epoch.
        expires_at_ms: u64,
    },
    /// Nothing is signed in here.
    SignedOut,
}

impl SessionStatus {
    /// The upstream string for the state.
    pub fn state(&self) -> &'static str {
        match self {
            SessionStatus::SignedIn { .. } => "signed-in",
            SessionStatus::SignedInElsewhere { .. } => "signed-in-elsewhere",
            SessionStatus::Expired { .. } => "expired",
            SessionStatus::SignedOut => "signed-out",
        }
    }

    /// The account this status names, where it names one.
    pub fn principal(&self) -> Option<Principal> {
        match self {
            SessionStatus::SignedIn { principal, .. }
            | SessionStatus::SignedInElsewhere { principal, .. }
            | SessionStatus::Expired { principal, .. } => Some(*principal),
            SessionStatus::SignedOut => None,
        }
    }

    /// When the sign-in ends (or ended), in milliseconds since the Unix epoch.
    pub fn expires_at_ms(&self) -> Option<u64> {
        match self {
            SessionStatus::SignedIn { expires_at_ms, .. }
            | SessionStatus::SignedInElsewhere { expires_at_ms, .. }
            | SessionStatus::Expired { expires_at_ms, .. } => Some(*expires_at_ms),
            SessionStatus::SignedOut => None,
        }
    }
}

/// The status of one-click SSO sign-in for a configured domain.
///
/// Port of upstream `SsoStatus` (`sso.ts:128-132`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoStatus {
    /// Internet Identity has not answered yet.
    Checking,
    /// The domain can sign its users in.
    Available {
        /// The organization's display name, when Internet Identity gave one.
        name: Option<String>,
    },
    /// The configured value is not a domain that Internet Identity will use.
    Invalid {
        /// Why the value was rejected.
        reason: String,
    },
    /// The domain is known but cannot sign in right now.
    Unavailable {
        /// When it is worth asking again, in milliseconds since the Unix epoch.
        retry_after_ms: Option<u64>,
        /// Internet Identity's explanation, when it gave one.
        reason: Option<String>,
    },
}

/// Whether Internet Identity may send notifications to this application.
///
/// Port of upstream `NotificationConsentStatus` (`notification-consent.ts:30-32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationConsentStatus {
    /// Whether consent is granted.
    pub granted: bool,
}

/// Attributes Internet Identity signed for this application.
///
/// Port of upstream `SignedAttributes` (`auth-client.ts:302-305`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttributes {
    /// The signed data.
    pub data: Vec<u8>,
    /// The signature over [`SignedAttributes::data`].
    pub signature: Vec<u8>,
}
