//! The client itself: a view on stored sign-in state.
//!
//! Port of upstream `src/client/auth-client.ts` against the v11 model, in which
//! a sign-in lives in storage and a client is a cheap view on it: the state
//! record says who is signed in here and until when, and the credentials hold
//! the keys and delegations that make requests carry that account.
//!
//! This file owns the lifecycle --- construction, restore, status, subscribe,
//! dispose, sign-out bookkeeping --- and orchestrates the signer, transport and
//! session modules. Phase ordering of the port is tracked in
//! `docs/port/DESIGN.md`; the methods whose machinery is still being
//! ported return [`AuthClientError::Unsupported`] with the reason.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ic_agent::export::Principal;
use ic_agent::identity::{AnonymousIdentity, DelegatedIdentity, Identity as _};
use parking_lot::Mutex;

use crate::ArcIdentity;
use crate::client::async_once::AsyncOnce;
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
use crate::client::credentials::MemoryCredentialStorage;
use crate::client::credentials::{Credential, SharedCredentialStorage};
use crate::client::error::AuthClientError;
use crate::client::identity::ClientIdentity;
use crate::client::notification_consent::{NotificationConsent, NotificationConsentOptions};
use crate::client::options::{
    AuthClientCreateOptions, IdentityProvider, OpenIdProvider, SessionStatus, SignInOptions,
    SignOutOptions, SsoStatus,
};
#[cfg(feature = "wasm-js")]
use crate::client::platform::Unsubscribe;
use crate::client::platform::{Listener, PlatformBounds};
use crate::client::session::app_delegation_source::AppDelegationSource;
use crate::client::session::app_delegation_source::SessionError;
use crate::client::session::identity::{SessionIdentity, SessionIdentityCreateOptions};
use crate::client::session::minter::SessionMinter;
use crate::client::session::{LockManager, steal_lock, steal_mint_lock};
use crate::client::slots::{Slots, slots_for};
use crate::client::sso::{SsoDomain, SsoStatusChecker, sso_domain_service_factory};
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
use crate::client::state::MemoryStateStorage;
use crate::client::state::StoredSessionState;
use crate::client::state::{SharedStateStorage, Subscription};
use crate::client::transport::SharedTransport;
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
use crate::key::BaseKeyType;
use crate::signer::{AttributeRequest, SessionDelegationParams, Signer, SignerOptions};

/// What the client derived from its options at construction time.
///
/// The fields the sign-in orchestration reads are populated now and consumed by
/// the signer/session phases, so a few are not read yet.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Settings {
    /// Where the identity provider is.
    provider: IdentityProvider,
    /// The authorize URL a ceremony is rendered at, with the options baked in.
    authorize_url: String,
    /// How the client talks to the identity provider.
    transport_mode: crate::client::options::TransportMode,
    /// Whether a sign-in kept in the state store may be resumed without a
    /// ceremony.
    resumable: bool,
    /// One-click OpenID sign-in provider, where configured.
    open_id_provider: Option<OpenIdProvider>,
    /// Organization domain for one-click SSO, where configured.
    sso_domain: Option<String>,
    /// The IC host the agent uses for canister calls.
    host: String,
}

impl Settings {
    fn from_options(
        options: &AuthClientCreateOptions,
        state_resumable: bool,
    ) -> Result<Self, AuthClientError> {
        let requested = options.identity_provider.clone().unwrap_or_default();
        let authorize_url = build_authorize_url(options, &requested, state_resumable)?;
        Ok(Self {
            provider: requested,
            authorize_url,
            transport_mode: options.resolved_transport(),
            resumable: options.resumable.unwrap_or(state_resumable),
            open_id_provider: options.open_id_provider,
            sso_domain: options.sso_domain.clone(),
            host: options
                .host
                .clone()
                .unwrap_or_else(|| "https://icp-api.io".to_string()),
        })
    }
}

/// Appends the options that ride on the authorize URL, in upstream's order
/// (`auth-client.ts:505-555`).
fn build_authorize_url(
    options: &AuthClientCreateOptions,
    provider: &IdentityProvider,
    state_resumable: bool,
) -> Result<String, AuthClientError> {
    let mut url = url::Url::parse(&provider.authorize_url).map_err(|error| {
        AuthClientError::InvalidOptions(format!(
            "identity provider authorize URL is not a URL: {error}"
        ))
    })?;

    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(provider) = options.open_id_provider {
        params.push(("openid", provider.url().to_string()));
    }
    if let Some(domain) = &options.sso_domain {
        params.push(("sso", domain.trim().to_string()));
        // The SSO ceremony starts before a delegation is requested, so the
        // channel carries the derivation origin too late to resolve the
        // client: it has to ride on the URL instead.
        if let Some(derivation_origin) = &options.derivation_origin {
            params.push(("derivationOrigin", derivation_origin.clone()));
        }
    }
    if let Some(prompt) = options.prompt {
        params.push(("prompt", prompt.as_str().to_string()));
    }
    if let Some(hint) = options.hint {
        params.push(("hint", hint.to_text()));
    }
    // Written only when true: absent is what the provider reads as "keep
    // nothing", and an explicit `false` would say the same thing louder.
    if options.resumable.unwrap_or(state_resumable) {
        params.push(("resumable", "true".to_string()));
    }
    if !params.is_empty() {
        url.query_pairs_mut().extend_pairs(params);
    }

    Ok(url.to_string())
}

/// The identity the client is currently answering with.
///
/// Three shapes because the client answers for three kinds of sign-in: nothing,
/// a fixed identity (a restored native credential), and the rotating session
/// identity the browser flow installs --- whose delegation is replaced as it
/// ages, which is why it is held rather than snapshotted.
enum IdentityHolder {
    /// Nothing is signed in.
    Anonymous,
    /// A fixed identity.
    Plain(ArcIdentity),
    /// The rotating session identity.
    Session(Arc<SessionIdentity>),
}

impl Default for IdentityHolder {
    fn default() -> Self {
        IdentityHolder::Anonymous
    }
}

impl IdentityHolder {
    /// The identity as an `ic-agent` identity.
    fn as_identity(&self) -> Arc<dyn ic_agent::identity::Identity> {
        match self {
            IdentityHolder::Anonymous => Arc::new(AnonymousIdentity),
            IdentityHolder::Plain(identity) => identity.as_arc_identity(),
            IdentityHolder::Session(identity) => identity.as_arc_identity(),
        }
    }

    /// Whether the client is answering anonymously.
    fn is_anonymous(&self) -> bool {
        matches!(self, IdentityHolder::Anonymous)
    }

    /// The session identity, where this is one.
    fn session(&self) -> Option<Arc<SessionIdentity>> {
        match self {
            IdentityHolder::Session(identity) => Some(identity.clone()),
            _ => None,
        }
    }

    /// The holder as the handle callers get.
    fn to_client_identity(&self) -> ClientIdentity {
        match self.session() {
            Some(session) => ClientIdentity::new(session.as_arc_identity(), Some(session)),
            None => ClientIdentity::plain(self.as_identity()),
        }
    }

    /// Stops anything this identity has scheduled.
    fn dispose(&self) {
        if let IdentityHolder::Session(identity) = self {
            identity.dispose();
        }
    }
}

/// What a page load found in the stores.
enum Restored {
    /// A session credential, as the browser flow writes: it can mint.
    Session(Credential),
    /// One delegation in the `app` slot, as a native sign-in writes: it cannot.
    AppDelegation(Credential),
}

/// What the client holds between calls.
struct Inner {
    /// The identity the client currently answers with.
    identity: Mutex<IdentityHolder>,
    /// Ceremonies in flight, which stand the foreground refresh down: a
    /// ceremony backgrounds the tab and foregrounds it again on its way back.
    interactions: AtomicU64,
    /// Set when the record changed under this client, so the next call that
    /// needs an identity re-hydrates before answering.
    stale: AtomicBool,
    /// Serialises re-hydrates, so two of them never install two identities.
    restore_gate: futures::lock::Mutex<()>,
    /// Whether the client has been disposed.
    disposed: AtomicBool,
    /// The registered listeners.
    listeners: Arc<Mutex<Vec<Arc<dyn Listener>>>>,
    /// The one restore that every method waits for.
    restored: AsyncOnce,
    /// Set while a restore is running, so its own writes are not news.
    restoring: AtomicBool,
    /// The signer, built once so that concurrent requests share one channel ---
    /// upstream keeps a `#signer` field for the same reason
    /// (`auth-client.ts:572-582`).
    signer: Mutex<Option<Signer>>,
    /// The foreground/activity watchers, dropped when the client is disposed.
    #[cfg(feature = "wasm-js")]
    activity: Mutex<Vec<Box<dyn Unsubscribe>>>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            identity: Mutex::new(IdentityHolder::Anonymous),
            interactions: AtomicU64::new(0),
            stale: AtomicBool::new(false),
            restore_gate: futures::lock::Mutex::new(()),
            disposed: AtomicBool::new(false),
            listeners: Arc::new(Mutex::new(Vec::new())),
            restored: AsyncOnce::new(),
            restoring: AtomicBool::new(false),
            signer: Mutex::new(None),
            #[cfg(feature = "wasm-js")]
            activity: Mutex::new(Vec::new()),
        }
    }
}

impl Inner {
    fn notify(&self) {
        let listeners = self.listeners.lock().clone();
        for listener in listeners {
            listener.call();
        }
    }

    fn is_disposed(&self) -> bool {
        self.disposed.load(Ordering::SeqCst)
    }
}

/// A client for Internet Identity authentication, shaped after
/// `@icp-sdk/auth` v11.
///
/// A client is a view on stored state, constructed and disposed per page rather
/// than kept for the lifetime of an application: construct it, call
/// [`AuthClient::ready`] (or any method that needs the stored state) and it
/// answers for whatever sign-in the origin already has.
#[derive(Clone)]
pub struct AuthClient {
    inner: Arc<Inner>,
    options: Arc<AuthClientCreateOptions>,
    settings: Arc<Settings>,
    slots: Arc<Slots>,
    credential_storage: SharedCredentialStorage,
    state_storage: SharedStateStorage,
    /// The transport the signer is reached over, where this platform has one.
    transport: Option<SharedTransport>,
    /// Builds the app-delegation source a sign-in mints through.
    delegation_source_factory: Option<Arc<dyn DelegationSourceFactory>>,
    /// How a non-browser sign-in acquires its delegation.
    #[cfg(all(
        feature = "native",
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    webauth_runner: Option<Arc<dyn crate::client::webauth::WebAuthRunner>>,
    /// The locks this client's ceremonies and mints share.
    ///
    /// One manager per client, so that a ceremony's sign-in lock, a mint's lock
    /// and a sign-out's steal all name the same locks. Native has no browser
    /// lock manager, so its in-process one is per client for the same reason.
    locks: Arc<dyn LockManager>,
    /// The SSO domain checker, for a client constructed with `sso_domain`.
    sso_checker: Option<Arc<SsoStatusChecker>>,
    /// The checker's subscription into this client's listeners.
    sso_subscription: Arc<Mutex<Option<Subscription>>>,
    state_subscription: Arc<Mutex<Option<Subscription>>>,
}

impl std::fmt::Debug for AuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthClient")
            .field("namespace", &self.options.namespace)
            .field("status", &self.get_status())
            .finish_non_exhaustive()
    }
}

impl AuthClient {
    /// Constructs a client.
    ///
    /// Port of upstream `new AuthClient(options)` (`auth-client.ts:427`).
    /// Upstream's constructor eagerly starts restoring the stored session; this
    /// port records the restore in a once-cell that the first awaiting method
    /// runs, because a Rust constructor has no executor to spawn on.
    pub fn new(options: AuthClientCreateOptions) -> Result<Self, AuthClientError> {
        options.validate()?;

        let credential_storage = options
            .credential_storage
            .clone()
            .unwrap_or_else(default_credential_storage);
        let state_storage = options
            .state_storage
            .clone()
            .unwrap_or_else(default_state_storage);
        let slots = Arc::new(slots_for(options.namespace.as_deref()));
        let settings = Arc::new(Settings::from_options(&options, state_storage.resumable())?);

        let transport = default_transport(&settings);
        let mut client = Self {
            inner: Arc::new(Inner::default()),
            options: Arc::new(options),
            settings,
            slots,
            credential_storage,
            state_storage,
            transport,
            delegation_source_factory: None,
            locks: crate::client::session::default_lock_manager(),
            #[cfg(all(
                feature = "native",
                any(target_os = "macos", target_os = "linux", target_os = "windows")
            ))]
            webauth_runner: None,
            sso_checker: None,
            sso_subscription: Arc::new(Mutex::new(None)),
            state_subscription: Arc::new(Mutex::new(None)),
        };
        client.watch_state();
        client.watch_sso();
        #[cfg(feature = "wasm-js")]
        client.watch_activity();
        Ok(client)
    }

    /// Constructs a client over a caller-supplied signer transport.
    ///
    /// The default constructors pick the platform's transport (a browser window
    /// or a redirect on `wasm-js`, the loopback bridge on `native`). This
    /// constructor exists for callers that bring their own: an application that
    /// hosts the signer itself, an embedded runtime, and this crate's tests,
    /// which drive the whole sign-in state machine over a fake transport.
    pub fn with_transport(
        options: AuthClientCreateOptions,
        transport: SharedTransport,
    ) -> Result<Self, AuthClientError> {
        let mut client = Self::new(options)?;
        client.transport = Some(transport);
        Ok(client)
    }

    /// The transport this client talks to the signer over, where it has one.
    pub fn transport(&self) -> Option<&SharedTransport> {
        self.transport.as_ref()
    }

    /// Constructs a client that mints app delegations through a supplied
    /// factory.
    ///
    /// The default mints through the Internet Identity canister described by
    /// `identity_provider`. This exists for deployments that mint elsewhere and
    /// for this crate's tests, which drive the whole sign-in over a fake
    /// source.
    pub fn with_delegation_source_factory(
        options: AuthClientCreateOptions,
        transport: SharedTransport,
        factory: Arc<dyn DelegationSourceFactory>,
    ) -> Result<Self, AuthClientError> {
        let mut client = Self::with_transport(options, transport)?;
        client.delegation_source_factory = Some(factory);
        Ok(client)
    }

    /// Constructs a client that signs in through a supplied non-browser runner.
    ///
    /// The default runner opens the system browser and waits on a loopback
    /// callback. Supplying another lets an application complete the flow its own
    /// way (a custom URL scheme, an embedded webview), and lets this crate's
    /// tests drive the native sign-in without a browser.
    #[cfg(all(
        feature = "native",
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    pub fn with_webauth_runner(
        options: AuthClientCreateOptions,
        runner: Arc<dyn crate::client::webauth::WebAuthRunner>,
    ) -> Result<Self, AuthClientError> {
        let mut client = Self::new(options)?;
        client.webauth_runner = Some(runner);
        Ok(client)
    }

    /// The app-delegation source for a session: the supplied factory's, or the
    /// Internet Identity canister's.
    async fn app_delegation_source(
        &self,
        session_key: &ArcIdentity,
        session_chain: &crate::delegation_chain::DelegationChain,
    ) -> Result<Arc<dyn AppDelegationSource>, AuthClientError> {
        let canister_id = self.settings.provider.canister_id;
        match &self.delegation_source_factory {
            Some(factory) => {
                factory
                    .create(session_key, session_chain, canister_id, &self.settings.host)
                    .await
            }
            None => {
                let minter = SessionMinter::create(
                    session_key.as_arc_identity(),
                    session_chain.clone(),
                    canister_id,
                    Some(self.settings.host.clone()),
                )
                .map_err(AuthClientError::from)?;
                Ok(Arc::new(minter))
            }
        }
    }

    /// A signer client over this client's transport, built once.
    fn signer(&self) -> Result<Signer, AuthClientError> {
        let mut cached = self.inner.signer.lock();
        if let Some(signer) = cached.as_ref() {
            return Ok(signer.clone());
        }
        let transport = self.transport.clone().ok_or(AuthClientError::Unsupported(
            "this platform has no signer transport configured",
        ))?;
        let signer = Signer::new(SignerOptions {
            transport,
            derivation_origin: self.options.derivation_origin.clone(),
        });
        *cached = Some(signer.clone());
        Ok(signer)
    }

    /// The options this client was constructed with.
    pub fn options(&self) -> &AuthClientCreateOptions {
        &self.options
    }

    /// The slot names this client writes under.
    pub fn slots(&self) -> &Slots {
        &self.slots
    }

    /// The credential store this client uses.
    pub fn credential_storage(&self) -> &SharedCredentialStorage {
        &self.credential_storage
    }

    /// The state store this client uses.
    pub fn state_storage(&self) -> &SharedStateStorage {
        &self.state_storage
    }

    /// The authorize URL a ceremony opens, with the client's options baked in.
    pub fn authorize_url(&self) -> &str {
        &self.settings.authorize_url
    }

    /// Resolves once this client has loaded its stored state and restored the
    /// session.
    ///
    /// Port of upstream `ready()` (`auth-client.ts:610`). Only needed where the
    /// state store loads asynchronously (a worker); in a page the status is
    /// correct from construction.
    pub async fn ready(&self) -> Result<(), AuthClientError> {
        self.inner.restored.get_or_init(|| self.restore()).await
    }

    /// The current identity, restoring a previous session if available.
    ///
    /// Port of upstream `getIdentity()` (`auth-client.ts:617`).
    ///
    /// # Errors
    ///
    /// [`AuthClientError::SessionNotHeld`] where the state record says this
    /// origin is signed in but no identity could be acquired for it: returning
    /// an anonymous identity would send calls out unauthenticated.
    pub async fn get_identity(&self) -> Result<ClientIdentity, AuthClientError> {
        self.ready().await?;
        self.settle_identity().await?;
        let holder = self.inner.identity.lock();
        if matches!(
            self.get_status(),
            SessionStatus::SignedIn { .. } | SessionStatus::SignedInElsewhere { .. }
        ) && !self.inner.is_disposed()
        {
            if holder.is_anonymous() {
                return Err(AuthClientError::SessionNotHeld);
            }
        }
        Ok(holder.to_client_identity())
    }

    /// Whether this client is signed in.
    ///
    /// Port of upstream `isAuthenticated()` (`auth-client.ts:653`), which is
    /// synchronous and reads the state record rather than a delegation.
    pub fn is_authenticated(&self) -> bool {
        !self.inner.is_disposed() && matches!(self.get_status(), SessionStatus::SignedIn { .. })
    }

    /// The principal of the signed-in account, where there is one.
    ///
    /// Port of upstream `getPrincipal()` (`auth-client.ts:678`): `None` unless
    /// the status is `signed-in`.
    pub fn get_principal(&self) -> Option<Principal> {
        match self.get_status() {
            SessionStatus::SignedIn { principal, .. } => Some(principal),
            _ => None,
        }
    }

    /// What this client knows about its sign-in.
    ///
    /// Port of upstream `getStatus()` (`auth-client.ts:688`). Expiry is
    /// evaluated on read and writes nothing: the record stays, so every tab and
    /// sibling subdomain reads `expired` rather than `signed-out`.
    pub fn get_status(&self) -> SessionStatus {
        let Some(state) = self.state_storage.get(&self.slots.state) else {
            return SessionStatus::SignedOut;
        };
        let expires_at_ms = state.expires_at_ms();
        if state.expiration_ns <= crate::client::now::now_ns() {
            return SessionStatus::Expired {
                principal: state.principal,
                expires_at_ms,
            };
        }
        if state.held {
            SessionStatus::SignedIn {
                principal: state.principal,
                expires_at_ms,
            }
        } else {
            SessionStatus::SignedInElsewhere {
                principal: state.principal,
                expires_at_ms,
            }
        }
    }

    /// The status of one-click SSO sign-in, where a domain was configured.
    ///
    /// Port of upstream `getSsoStatus()` (`auth-client.ts:728`). `None` when the
    /// client was not constructed with `sso_domain`.
    pub fn get_sso_status(&self) -> Option<SsoStatus> {
        self.sso_checker.as_ref().map(|checker| checker.status())
    }

    /// Asks Internet Identity again whether the configured SSO domain can sign
    /// in.
    ///
    /// Port of upstream `refreshSsoStatus()` (`auth-client.ts:742`).
    pub fn refresh_sso_status(&self) {
        if let Some(checker) = &self.sso_checker {
            checker.refresh();
        }
    }

    /// Registers a listener fired after this client's answer may have changed.
    ///
    /// Port of upstream `subscribe()` (`auth-client.ts:782`). The listener runs
    /// after the status has been refreshed, so a listener reading
    /// [`AuthClient::get_status`] sees what it was told about.
    pub fn subscribe(&self, listener: Arc<dyn Listener>) -> Subscription {
        self.inner.listeners.lock().push(listener.clone());
        let listeners = self.inner.listeners.clone();
        Subscription::new(Box::new(move || {
            listeners
                .lock()
                .retain(|registered| !Arc::ptr_eq(registered, &listener));
        }))
    }

    /// Releases everything this client holds.
    ///
    /// Port of upstream `dispose()` (`auth-client.ts:798`). Not a sign-out:
    /// nothing shared is written.
    pub fn dispose(&self) {
        if let Some(subscription) = self.state_subscription.lock().take() {
            subscription.unsubscribe();
        }
        {
            let holder = self.inner.identity.lock();
            holder.dispose();
        }
        #[cfg(feature = "wasm-js")]
        {
            // Dropping a watcher unhooks it.
            *self.inner.activity.lock() = Vec::new();
        }
        if let Some(subscription) = self.sso_subscription.lock().take() {
            subscription.unsubscribe();
        }
        if let Some(checker) = &self.sso_checker {
            checker.dispose();
        }
        self.inner.disposed.store(true, Ordering::SeqCst);
        self.inner.listeners.lock().clear();
    }

    /// Signs in with Internet Identity.
    ///
    /// Port of upstream `signIn(options?)` (`auth-client.ts:923`). Prefer
    /// [`AuthClient::begin_sign_in`] where the caller runs inside a user gesture:
    /// a browser only lets a popup or a navigation start inside the gesture, and
    /// the first poll of an `async fn` may already be a microtask too late.
    pub async fn sign_in(&self, options: SignInOptions) -> Result<ClientIdentity, AuthClientError> {
        self.begin_sign_in(options)?.await
    }

    /// Starts a sign-in synchronously: opens the signer window (or navigates)
    /// while the caller's user gesture is still in scope, and returns the rest
    /// of the flow as an awaitable.
    pub fn begin_sign_in(&self, options: SignInOptions) -> Result<SignIn, AuthClientError> {
        if self.state_storage.is_read_only() {
            return Err(AuthClientError::Unsupported(
                "a read-only state store cannot sign in",
            ));
        }
        // A lock request ahead of `window.open` is enough for some browsers to
        // refuse the popup, so nothing may ask the platform for anything before
        // this call.
        if let Some(transport) = &self.transport {
            transport.open()?;
        }
        Ok(SignIn {
            client: self.clone(),
            options,
        })
    }

    /// The sign-in choreography, once the window is open.
    ///
    /// Order follows upstream `#runSignIn` (`auth-client.ts:944-1099`): acquire
    /// the session key, ask the signer for the session delegation, mint the app
    /// delegation from the Internet Identity canister inside the ceremony, then
    /// commit the session and the credential.
    async fn run_sign_in(&self, options: SignInOptions) -> Result<ClientIdentity, AuthClientError> {
        // Counted before the first await: this is what stands the foreground
        // refresh down while the ceremony backgrounds the tab and comes back.
        let _interaction = InteractionGuard::new(&self.inner.interactions);

        // A ceremony's writes must not interleave with the constructor's restore.
        self.ready().await?;

        // The namespace's sign-in, taken the way sign-out takes it: a ceremony
        // that dies should not block the next one forever, so this steals rather
        // than queues. It is taken here, after `begin_sign_in` opened the window:
        // a lock request ahead of `window.open` is enough for some browsers to
        // refuse the popup.
        let sign_in_lock = steal_lock(self.locks.as_ref(), Some(&self.slots.state));

        // A non-browser client has no signer window to talk to: it signs in
        // through the identity provider's own non-browser flow, which hands the
        // delegation to a loopback listener (see `crate::client::webauth`).
        #[cfg(all(
            feature = "native",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        if self.transport.is_none() {
            return self.run_webauth_sign_in(options).await;
        }

        let signer = self.signer()?;

        // 1. The session key. A redirect flow needs the same key on the return
        //    load, so it goes through the pending slot and the journal; a window
        //    flow can use a fresh one.
        let (session_identity, pending) = self.session_key_for_sign_in().await?;
        let session_public_key = session_identity.public_key().ok_or_else(|| {
            AuthClientError::Other("the session key has no public key".to_string())
        })?;

        // 2. The session delegation, restricted to the Internet Identity
        //    canister by the provider.
        let session_chain = signer
            .request_session_delegation(SessionDelegationParams {
                session_public_key: &session_public_key,
                max_time_to_live: options.max_time_to_live,
                max_time_to_idle: options.max_time_to_idle,
                derivation_origin: self.options.derivation_origin.as_deref(),
            })
            .await
            .map_err(interaction_error)?;
        signer.close().await;

        // 3. The chain is checked against the key it was requested for: a chain
        //    for another key mints nothing, and failing here names the cause
        //    instead of leaving it to the first request.
        if !crate::client::session::app_delegation_source::chain_authorises_key(
            &session_chain,
            &session_public_key,
        ) {
            return Err(AuthClientError::Other(
                "the session chain does not delegate to the key it was requested for".to_string(),
            ));
        }

        // 4. Mint the app delegation inside the ceremony the user is already
        //    waiting through, so the first request after signing in does not
        //    wait. The account key comes from the mint: the session chain is
        //    rooted at the session's own key, and only a mint reports the key an
        //    application's canisters will see.
        let app_identity = self.credential_storage.create().await?;
        let app_public_key = app_identity
            .public_key()
            .ok_or_else(|| AuthClientError::Other("the app key has no public key".to_string()))?;

        let source = self
            .app_delegation_source(&session_identity, &session_chain)
            .await?;
        let app_chain = source
            .mint(&app_public_key)
            .await
            .map_err(AuthClientError::from)?;

        // A sign-out took the record away while this ceremony was in flight: its
        // result is not this origin's sign-in any more.
        if sign_in_lock.stolen.is_aborted() {
            return Err(AuthClientError::Superseded(
                "a sign-out took over this sign-in".to_string(),
            ));
        }

        // 5. The ceremony's own slot first, not the one every tab acts with:
        //    writing `app` here would change what those tabs hold before this
        //    sign-in has succeeded.
        self.credential_storage
            .set(
                &self.slots.app_pending,
                Credential::with_chain(app_identity.clone(), app_chain.clone()),
            )
            .await?;

        // 6. Commit: the session and the state first, because the state is what
        //    makes this account the one this origin answers for.
        self.credential_storage
            .set(
                &self.slots.session,
                Credential::with_chain(session_identity.clone(), session_chain.clone()),
            )
            .await?;
        if let Some(expiration_ns) = earliest_expiration_ns(&session_chain) {
            self.state_storage.set(
                &self.slots.state,
                crate::client::state::StoredSessionState {
                    principal: Principal::self_authenticating(&app_chain.public_key),
                    expiration_ns,
                },
            );
        }

        // 7. Promote what the ceremony minted into the slot every tab acts with,
        //    overwriting rather than clearing first so the origin is never
        //    credential-less.
        self.credential_storage
            .set(
                &self.slots.app,
                Credential::with_chain(app_identity, app_chain.clone()),
            )
            .await?;
        let _ = self
            .credential_storage
            .remove(&self.slots.app_pending)
            .await;

        // 8. A redirect ceremony's pending key is spent now; best-effort, since
        //    the user is already signed in.
        if pending {
            let _ = self
                .credential_storage
                .remove(&self.slots.session_pending)
                .await;
        }

        // 9. The identity the application acts with: the session identity over
        //    the credential just promoted, so the delegation it signs with is
        //    replaced as it ages without the caller signing in again.
        let session = self
            .open_session(session_identity, session_chain, Some(source), true)
            .await
            .map_err(AuthClientError::from)?;
        let installed = Arc::new(session);
        self.install(IdentityHolder::Session(installed.clone()));
        self.inner.notify();
        let identity = ClientIdentity::new(installed.as_arc_identity(), Some(installed));

        // 10. Navigation last: leaving the page earlier would abandon the flow
        //     partway.
        if let Some(return_to) = options.return_to {
            self.navigate_to(&return_to)?;
        }

        Ok(identity)
    }

    /// Signs in through the identity provider's non-browser flow.
    ///
    /// Port of nothing upstream --- the browser library has no native
    /// counterpart --- but of the protocol Internet Identity serves for it:
    /// discovery at `/.well-known/cli-auth-config`, a loopback callback, and a
    /// form POST carrying the delegation. The flow yields one delegation chain
    /// rooted at the user's key, which is this client's credential on native
    /// (there is no session chain to mint app delegations from).
    ///
    /// `max_time_to_live` is sent as the provider's `ttl` (minutes, rounded
    /// down but never below one); `max_time_to_idle` and `return_to` have no
    /// equivalent in the flow and are ignored. The provider's own screen
    /// decides the delegation's access level and defaults to read-only.
    #[cfg(all(
        feature = "native",
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    async fn run_webauth_sign_in(
        &self,
        options: SignInOptions,
    ) -> Result<ClientIdentity, AuthClientError> {
        let identity = self.credential_storage.create().await?;
        let public_key = identity.public_key().ok_or_else(|| {
            AuthClientError::Other("the session key has no public key".to_string())
        })?;

        let ttl_minutes = options.max_time_to_live.map(|nanoseconds| {
            let minutes = nanoseconds / 60_000_000_000;
            u32::try_from(minutes.max(1)).unwrap_or(u32::MAX)
        });
        let request = crate::client::webauth::WebAuthOptions {
            auth_origin: auth_origin_of(&self.settings.provider.authorize_url),
            app_origin: self.options.derivation_origin.clone(),
            ttl_minutes,
            timeout: crate::client::webauth::DEFAULT_TIMEOUT,
        };
        let chain = match &self.webauth_runner {
            Some(runner) => runner.acquire(&public_key, request).await,
            None => crate::client::webauth::acquire_delegation(&public_key, request).await,
        }
        .map_err(|error| AuthClientError::Other(error.to_string()))?;

        // The flow already validates the chain; this is the same invariant the
        // browser path enforces, so the client's own credential cannot be one
        // that signs nothing.
        if !crate::client::session::app_delegation_source::chain_authorises_key(&chain, &public_key)
        {
            return Err(AuthClientError::Other(
                "the delegation does not authorise the key it was requested for".to_string(),
            ));
        }

        let credential = Credential::with_chain(identity, chain.clone());
        self.credential_storage
            .set(&self.slots.app, credential.clone())
            .await?;
        if let Some(expiration_ns) = earliest_expiration_ns(&chain) {
            self.state_storage.set(
                &self.slots.state,
                crate::client::state::StoredSessionState {
                    principal: Principal::self_authenticating(&chain.public_key),
                    expiration_ns,
                },
            );
        }

        let installed = delegated_identity_for(&credential)
            .ok_or_else(|| AuthClientError::Other("the delegation is unusable".to_string()))?;
        let identity = ClientIdentity::plain(installed.as_arc_identity());
        self.install(IdentityHolder::Plain(installed));
        self.inner.notify();

        if let Some(return_to) = options.return_to {
            self.navigate_to(&return_to)?;
        }
        Ok(identity)
    }

    /// Acquires the session key for a sign-in.
    ///
    /// A window flow completes in one load, so a fresh key is enough. A redirect
    /// flow runs twice --- once on the load that navigates to the provider and
    /// again on the return load that replays the delegation minted for the first
    /// load's key --- so the key has to be readable again afterwards.
    async fn session_key_for_sign_in(&self) -> Result<(ArcIdentity, bool), AuthClientError> {
        if self.settings.transport_mode != crate::client::options::TransportMode::Redirect {
            return Ok((self.credential_storage.create().await?, false));
        }
        if !self.credential_storage.durable() {
            return Err(AuthClientError::InvalidOptions(
                "a redirect sign-in needs a credential store that survives the navigation,                  and this one does not; use a durable store or the window transport"
                    .to_string(),
            ));
        }
        // The key's public half is journaled: not a secret, it survives the
        // redirect as text, and on the return load it says whether the pending
        // slot still holds the key this ceremony started with.
        let journal = self
            .transport
            .as_ref()
            .and_then(|transport| transport.journal());
        let started_with = match journal
            .as_ref()
            .and_then(|journal| journal.get(JOURNAL_SESSION_KEY))
        {
            Some(journaled) => journaled
                .as_str()
                .and_then(crate::client::base64::from_base64_opt),
            None => None,
        };
        let identity = if let Some(stored) = self
            .credential_storage
            .get(&self.slots.session_pending)
            .await?
            .map(|credential| credential.identity)
        {
            stored
        } else {
            let identity = self.credential_storage.create().await?;
            if let Some(journal) = &journal
                && let Some(public_key) = identity.public_key()
            {
                journal.put(
                    JOURNAL_SESSION_KEY,
                    serde_json::Value::String(crate::client::base64::to_base64(&public_key)),
                );
            }
            self.credential_storage
                .set(
                    &self.slots.session_pending,
                    Credential::key_only(identity.clone()),
                )
                .await?;
            identity
        };

        // Empty or holding another flow's key: either way the key this ceremony
        // journaled is no longer in the slot, so the delegation being replayed
        // was minted for a key this flow does not have.
        if let Some(started_with) = started_with
            && identity
                .public_key()
                .map(|public_key| public_key != started_with)
                .unwrap_or(true)
        {
            return Err(AuthClientError::Superseded(
                "this sign-in was superseded by another one in this browser".to_string(),
            ));
        }
        Ok((identity, true))
    }

    /// Signs out, ending the session at the canister where possible.
    ///
    /// Port of upstream `signOut(options?)` (`auth-client.ts:1389`): revoke the
    /// session at the Internet Identity canister, drop the credentials and the
    /// shared state record.
    ///
    /// Revocation is the half that tells the user their apps are signed out, so
    /// a refusal is reported rather than swallowed. A client that holds no
    /// session has nothing to revoke and just clears what it has.
    pub async fn sign_out(&self, options: SignOutOptions) -> Result<(), AuthClientError> {
        if self.state_storage.is_read_only() {
            return Err(AuthClientError::Unsupported(
                "a read-only state store cannot sign out",
            ));
        }
        // Wait for the constructor's restore: hydration racing the deletion
        // below could re-populate the identity from already-read state.
        self.ready().await?;

        // The same lock a ceremony takes, taken the same way: this is the other
        // operation that moves this namespace's sign-in.
        let sign_out_lock = steal_lock(self.locks.as_ref(), Some(&self.slots.state));

        // Read before anything is cleared: the revoke call is made as the
        // session, so it needs what the wipe is about to remove.
        let session = self.session_credential().await.ok().and_then(|credential| {
            credential
                .chain
                .clone()
                .map(|chain| (credential.identity.clone(), chain))
        });

        // Taken away rather than queued for: waiting would make a sign-out the
        // user asked for wait on a canister call in another tab. A mint that
        // loses this lock finishes the call it cannot recall, sees that it lost
        // it, and throws the result away rather than writing a credential into
        // the slot cleared below (`session/identity.rs:351-358`).
        let mint_lock = self
            .credential_storage
            .shared()
            .then(|| self.slots.app.clone());
        steal_mint_lock(self.locks.as_ref(), mint_lock.as_deref()).await;

        // Stop the rotation and any install from here on: the identity this
        // client answers with is being removed.
        {
            let holder = self.inner.identity.lock();
            holder.dispose();
        }
        self.install_anonymous();

        // Ending the session at the canister and clearing what is held here are
        // independent, so they run together: a slow or failing revoke must not
        // hold up a wipe the user asked for, and a user who pressed sign out must
        // not stay signed in on the device in front of them because a call
        // failed.
        //
        // A failed revoke is carried rather than thrown, so the wipe below still
        // finishes, and raised after it --- the device is signed out whatever
        // happened at the canister, and an application that told a user it had
        // signed them out of their apps can find out that it had not.
        let revoke = async {
            let (identity, chain) = session?;
            let minter = SessionMinter::create(
                identity.as_arc_identity(),
                chain,
                self.settings.provider.canister_id,
                Some(self.settings.host.clone()),
            )
            .ok()?;
            minter.revoke().await.err()
        };
        let (revoke_error, cleared) = futures::join!(revoke, self.end_session());
        cleared?;
        self.inner.notify();

        sign_out_lock.release();

        if let Some(error) = revoke_error {
            return Err(AuthClientError::from(error));
        }
        if let Some(return_to) = options.return_to {
            self.navigate_to(&return_to)?;
        }
        Ok(())
    }

    /// Requests signed identity attributes from the identity provider.
    ///
    /// Port of upstream `requestAttributes({keys, nonce})`
    /// (`auth-client.ts:1187`). The nonce is produced by a callback so that the
    /// redirect flow can journal it and reuse the same bytes when it replays.
    pub async fn request_attributes(
        &self,
        keys: Vec<String>,
        nonce: impl FnOnce() -> Vec<u8>,
    ) -> Result<crate::client::options::SignedAttributes, AuthClientError> {
        if self.state_storage.is_read_only() {
            return Err(AuthClientError::Unsupported(
                "a read-only client cannot open a signer channel",
            ));
        }
        // The nonce is produced here rather than by the caller so that a
        // redirect-flow replay can journal it later and reuse the same bytes.
        let nonce = nonce();
        let signer = self.signer()?;
        let attributes = signer
            .request_attributes(AttributeRequest { keys, nonce })
            .await?;
        signer.close().await;
        Ok(attributes)
    }

    /// Asks the user whether Internet Identity may send notifications.
    ///
    /// Port of upstream `requestNotificationConsent()` (`auth-client.ts:1265`).
    pub async fn request_notification_consent(
        &self,
    ) -> Result<crate::client::options::NotificationConsentStatus, AuthClientError> {
        let signer = self.signer()?;
        let result = crate::client::notification_consent::request_notification_consent(
            &signer,
            self.options.derivation_origin.as_deref(),
        )
        .await;
        signer.close().await;
        result
    }

    /// Withdraws notification consent at the canister.
    ///
    /// Port of upstream `revokeNotificationConsent()` (`auth-client.ts:1288`).
    pub async fn revoke_notification_consent(&self) -> Result<(), AuthClientError> {
        self.notification_consent().await?.revoke().await
    }

    /// The notification-consent status recorded at the canister.
    ///
    /// Port of upstream `getNotificationConsentStatus()` (`auth-client.ts:1305`).
    pub async fn get_notification_consent_status(
        &self,
    ) -> Result<crate::client::options::NotificationConsentStatus, AuthClientError> {
        self.notification_consent().await?.status().await
    }

    /// The canister-side consent calls, as the stored session.
    async fn notification_consent(&self) -> Result<NotificationConsent, AuthClientError> {
        let credential = self.session_credential().await?;
        NotificationConsent::create(NotificationConsentOptions {
            session_key: credential.identity.as_arc_identity(),
            session_chain: credential
                .chain
                .clone()
                .ok_or(AuthClientError::SessionNotHeld)?,
            canister_id: self.settings.provider.canister_id,
            host: self.settings.host.clone(),
        })
        .await
    }

    /// The stored session credential: the key and the chain that authorises it.
    async fn session_credential(&self) -> Result<Credential, AuthClientError> {
        let credential = self
            .credential_storage
            .get(&self.slots.session)
            .await?
            .ok_or(AuthClientError::SessionNotHeld)?;
        if credential.chain.is_none() {
            return Err(AuthClientError::SessionNotHeld);
        }
        Ok(credential)
    }

    /// Re-hydrates when the record may have moved under this client.
    ///
    /// Port of upstream `#restoreAgain` (`auth-client.ts:1631-1660`), reduced to
    /// the moment it matters here: upstream re-hydrates eagerly from its
    /// synchronous listener, which a Rust listener cannot await, so the pass is
    /// run by the next call that needs an identity instead. Two conditions send
    /// it: a change the listener saw, and an identity that no longer agrees with
    /// the record (a write that arrived while a restore was running, or from a
    /// store that does not notify).
    async fn settle_identity(&self) -> Result<(), AuthClientError> {
        if self.inner.is_disposed() {
            return Ok(());
        }
        if !self.inner.stale.load(Ordering::SeqCst) && !self.identity_disagrees() {
            return Ok(());
        }
        // One pass at a time: two would both install an identity, and the order
        // they finished in would decide which.
        let _gate = self.inner.restore_gate.lock().await;
        if !self.inner.stale.load(Ordering::SeqCst) && !self.identity_disagrees() {
            return Ok(());
        }
        self.inner.stale.store(false, Ordering::SeqCst);
        self.restore().await
    }

    /// Whether the identity this client holds answers for an account the record
    /// no longer names.
    fn identity_disagrees(&self) -> bool {
        let Some(record) = self
            .state_storage
            .get(&self.slots.state)
            .filter(|_| matches!(self.get_status(), SessionStatus::SignedIn { .. }))
        else {
            return false;
        };
        let holder = self.inner.identity.lock();
        if holder.is_anonymous() {
            return false;
        }
        holder.as_identity().sender().ok() != Some(record.principal)
    }

    /// Restores the stored session into an identity.
    ///
    /// Port of upstream `#restore`/`#hydrate` (`auth-client.ts:1680-1762`),
    /// reduced to the parts this phase implements: the session credential has to
    /// be present and live, the state record has to exist, and the app
    /// credential provides the identity requests are signed with.
    async fn restore(&self) -> Result<(), AuthClientError> {
        self.inner.restoring.store(true, Ordering::SeqCst);
        let result = self.hydrate().await;
        self.inner.restoring.store(false, Ordering::SeqCst);
        result
    }

    async fn hydrate(&self) -> Result<(), AuthClientError> {
        self.state_storage.ready().await;

        let session = self.restore_session().await?;

        // A native sign-in stores one delegation in the `app` slot and has no
        // session chain to mint from, so that credential is acted on as it is.
        #[cfg(all(
            feature = "native",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        ))]
        let app_delegation = if session.is_none() {
            self.credential_storage
                .get(&self.slots.app)
                .await?
                .filter(|app| credential_chain_is_live(app))
        } else {
            None
        };
        #[cfg(not(all(
            feature = "native",
            any(target_os = "macos", target_os = "linux", target_os = "windows")
        )))]
        let app_delegation: Option<Credential> = None;

        let Some(restored) = session
            .map(Restored::Session)
            .or_else(|| app_delegation.map(Restored::AppDelegation))
        else {
            self.forget_unusable_session().await;
            return Ok(());
        };

        // The state decides whether this origin is signed in, so a chain it does
        // not back belongs to a sign-in that has ended.
        if self.state_storage.get(&self.slots.state).is_none() {
            self.end_session().await?;
            self.install_anonymous();
            return Ok(());
        }

        match restored {
            Restored::Session(session) => self.hydrate_session(session).await,
            Restored::AppDelegation(app) => self.hydrate_app(&app).await,
        }
    }

    /// Nothing this origin can act with: forget what cannot stand, and say so.
    async fn forget_unusable_session(&self) {
        // A record that reaches past this origin belongs to whoever published it,
        // so it is discarded rather than removed --- but a record that still
        // claims this origin is signed in is one nothing can answer for, so it
        // goes too. A record already past its expiry says the session ended
        // rather than that this origin holds it, so it is left to say so.
        if !self.state_storage.is_read_only()
            && matches!(self.get_status(), SessionStatus::SignedIn { .. })
        {
            self.drop_session().await;
        }
        self.install_anonymous();
    }

    /// Restores a browser session as the rotating identity.
    async fn hydrate_session(&self, session: Credential) -> Result<(), AuthClientError> {
        // It opens the app credential the slot holds (or mints one), and replaces
        // that delegation as it ages from here on. A record this identity cannot
        // produce a credential for is one this origin cannot act on, so it is
        // dropped rather than restored.
        let chain = session
            .chain
            .clone()
            .ok_or(AuthClientError::SessionNotHeld)?;
        let source = self
            .app_delegation_source(&session.identity, &chain)
            .await?;
        match self
            .open_session(session.identity, chain, Some(source), false)
            .await
        {
            Ok(identity) => {
                if self.inner.is_disposed() {
                    // Disposed while this was in flight: install nothing, and stop
                    // what the identity already scheduled.
                    identity.dispose();
                    self.install_anonymous();
                    return Ok(());
                }
                // A sibling subdomain can have changed the record while this
                // origin was away: credentials rooted at an account the record no
                // longer names belong to a sign-in that has ended.
                let account = self
                    .state_storage
                    .get(&self.slots.state)
                    .map(|state| state.principal);
                if account != Some(identity.principal()) {
                    identity.dispose();
                    self.install_anonymous();
                    self.drop_session().await;
                    return Ok(());
                }
                self.install(IdentityHolder::Session(Arc::new(identity)));
                Ok(())
            }
            Err(SessionError::Gone(_)) | Err(SessionError::AccountMismatch(_)) => {
                self.install_anonymous();
                self.drop_session().await;
                Ok(())
            }
            Err(SessionError::Unsupported(_)) => {
                // A session this library cannot act for: leave the record to say
                // so rather than signing it out.
                self.install_anonymous();
                Ok(())
            }
            Err(error) => Err(AuthClientError::from(error)),
        }
    }

    /// Restores a native sign-in: one delegation in the `app` slot, acted on as
    /// it is (no session chain, so nothing to rotate).
    async fn hydrate_app(&self, app: &Credential) -> Result<(), AuthClientError> {
        if let Some(identity) = delegated_identity_for(app) {
            let account = self
                .state_storage
                .get(&self.slots.state)
                .map(|state| state.principal);
            if account.is_some() && identity_principal(&identity) == account {
                self.install(IdentityHolder::Plain(identity));
                return Ok(());
            }
        }
        self.install_anonymous();
        Ok(())
    }

    /// Opens the session identity over a stored session credential.
    ///
    /// Port of upstream `#openSession` (`auth-client.ts:1520-1574`): the
    /// identity adopts the app credential the slot holds when it can check the
    /// account, and mints when it cannot; a session that never had life left is
    /// reported gone rather than opened.
    async fn open_session(
        &self,
        session_key: ArcIdentity,
        session_chain: crate::delegation_chain::DelegationChain,
        source: Option<Arc<dyn AppDelegationSource>>,
        opening: bool,
    ) -> Result<SessionIdentity, SessionError> {
        let source = match source {
            Some(source) => source,
            None => self
                .app_delegation_source(&session_key, &session_chain)
                .await
                .map_err(|error| SessionError::Retryable(error.to_string()))?,
        };
        let session_expires_at_ms =
            crate::client::session::app_delegation_source::expires_at_ms(&session_chain);
        // The record both callers have written or checked: a ceremony persists
        // the session before this runs, and a restore refuses a record that
        // names nobody. Without it the identity would take its account from
        // whatever the app slot held, which a previous sign-in may still own.
        let held = self
            .state_storage
            .get(&self.slots.state)
            .map(|state| state.stored());
        let identity = SessionIdentity::create(SessionIdentityCreateOptions {
            session_expires_at_ms,
            source,
            storage: self.credential_storage.clone(),
            slot: self.slots.app.clone(),
            on_session_gone: self.session_gone_listener(held, !opening),
            expected_account: held.map(|state| state.principal),
            clock: None,
            scheduler: None,
            locks: Some(self.locks.clone()),
        })
        .await?;
        // The asynchronous half of `ic-agent`'s synchronous `sign`: a delegation
        // inside the block margin must be replaced before the first request.
        identity.prepare().await?;
        Ok(identity)
    }

    /// The listener the session identity calls when its session turns out gone.
    ///
    /// Upstream ends the sign-in or drops this origin's claim on it, depending on
    /// whether the record still names the session the identity was opened over,
    /// and whether that session was ever used (`auth-client.ts:1565-1610`). The
    /// synchronous half (stop answering) runs here; the record half needs the
    /// credential store, which is asynchronous.
    fn session_gone_listener(
        &self,
        held: Option<StoredSessionState>,
        ended: bool,
    ) -> Arc<dyn Listener> {
        let inner = Arc::downgrade(&self.inner);
        #[cfg(feature = "wasm-js")]
        let state_storage = self.state_storage.clone();
        #[cfg(feature = "wasm-js")]
        let credential_storage = self.credential_storage.clone();
        #[cfg(feature = "wasm-js")]
        let slots = self.slots.clone();
        Arc::new(move || {
            if let Some(inner) = inner.upgrade() {
                *inner.identity.lock() = IdentityHolder::Anonymous;
                inner.notify();
            }
            // The record half needs the asynchronous credential store. On native
            // there is no executor to hand a non-`Send` future to, so the record
            // and credentials are left for the next restore (a spent credential
            // is evicted) or a sign-out --- the browser is where this listener
            // runs for a live session anyway.
            #[cfg(feature = "wasm-js")]
            {
                let state_storage = state_storage.clone();
                let credential_storage = credential_storage.clone();
                let slots = slots.clone();
                crate::client::spawn_background(async move {
                    crate::client::session::record::end_or_drop(
                        state_storage,
                        credential_storage,
                        slots,
                        held,
                        ended,
                    )
                    .await;
                });
            }
            #[cfg(not(feature = "wasm-js"))]
            let _ = (held, ended);
        })
    }

    /// Loads the stored session, clearing it where the delegation has expired or
    /// the record cannot be read.
    ///
    /// Port of upstream `#restoreSession` (`auth-client.ts:1795-1808`). The
    /// state record is deliberately kept when the chain is spent: its expiry is
    /// the session's, so a chain this old leaves a record that reads as
    /// `expired`, which is what a page loading after a session ran out should
    /// say.
    async fn restore_session(&self) -> Result<Option<Credential>, AuthClientError> {
        let Some(credential) = self.credential_storage.get(&self.slots.session).await? else {
            return Ok(None);
        };
        // A record with no chain is not a session: only a ceremony's own slot may
        // hold a key alone.
        if !credential_chain_is_live(&credential) {
            if !self.state_storage.is_read_only() {
                crate::client::session::record::clear_credentials(
                    &self.credential_storage,
                    &self.slots,
                )
                .await;
            }
            return Ok(None);
        }
        Ok(Some(credential))
    }

    /// Removes the credentials and the shared record: what signing out does.
    async fn end_session(&self) -> Result<(), AuthClientError> {
        crate::client::session::record::end_session(
            &self.state_storage,
            &self.credential_storage,
            &self.slots,
        )
        .await;
        Ok(())
    }

    async fn drop_session(&self) {
        crate::client::session::record::drop_session(
            &self.state_storage,
            &self.credential_storage,
            &self.slots,
        )
        .await;
    }

    fn install(&self, identity: IdentityHolder) {
        // A restore that was in flight when the client was disposed must not
        // install what it found, or the identity would keep scheduling work for
        // a client nobody holds any more.
        if self.inner.is_disposed() {
            identity.dispose();
            return;
        }
        *self.inner.identity.lock() = identity;
    }

    fn install_anonymous(&self) {
        *self.inner.identity.lock() = IdentityHolder::Anonymous;
    }

    /// Watches the page for signs that somebody is here, and lets the session
    /// identity mint ahead of time when it is.
    ///
    /// Port of upstream's `watchForeground`/`watchActivity` wiring
    /// (`auth-client.ts:460-471`): one claim --- somebody is here --- so one
    /// option governs both, and a ceremony in flight stands it down.
    #[cfg(feature = "wasm-js")]
    fn watch_activity(&self) {
        if self.options.disable_browser_activity.unwrap_or(false) {
            return;
        }
        let inner = Arc::downgrade(&self.inner);
        let listener: Arc<dyn Listener> = Arc::new(move || {
            let Some(inner) = inner.upgrade() else {
                return;
            };
            // A ceremony backgrounds the tab and foregrounds it again on its way
            // back; refreshing there would spend a mint on the identity it is
            // replacing.
            if inner.interactions.load(Ordering::SeqCst) > 0 {
                return;
            }
            let Some(session) = inner.identity.lock().session() else {
                return;
            };
            crate::client::spawn_background(async move { session.refresh().await });
        });

        let mut hooks: Vec<Box<dyn Unsubscribe>> = Vec::new();
        if let Some(unwatch) = crate::client::foreground_refresh::watch_foreground(listener.clone())
        {
            hooks.push(unwatch);
        }
        if let Some(unwatch) = crate::client::foreground_refresh::watch_activity(listener) {
            hooks.push(unwatch);
        }
        *self.inner.activity.lock() = hooks;
    }

    fn watch_state(&self) {
        let inner = self.inner.clone();
        let subscription = self.state_storage.subscribe(
            &self.slots.state,
            Arc::new(move || {
                // A change this client did not cause. A ceremony writes this
                // record itself and installs the identity that goes with it, and
                // a restore writes it too when what it found turns out not to be
                // usable --- reacting to either would re-hydrate mid-ceremony.
                //
                // The held answer is not re-resolved here: this listener is
                // synchronous, and re-hydrating can reach the network. The next
                // call that needs an identity does it (`settle_identity`), so a
                // listener asking who is signed in still reads the record live.
                if inner.interactions.load(Ordering::SeqCst) == 0
                    && !inner.restoring.load(Ordering::SeqCst)
                    && !inner.is_disposed()
                {
                    inner.stale.store(true, Ordering::SeqCst);
                }
                inner.notify();
            }),
        );
        *self.state_subscription.lock() = Some(subscription);
    }

    /// Builds and starts the SSO checker, and forwards its status changes to
    /// this client's listeners.
    fn watch_sso(&mut self) {
        let Some(domain) = self.settings.sso_domain.clone() else {
            return;
        };
        let checker = Arc::new(SsoStatusChecker::new(
            SsoDomain::parse(&domain),
            sso_domain_service_factory(
                self.settings.provider.canister_id,
                self.settings.host.clone(),
            ),
        ));
        let inner = self.inner.clone();
        let subscription = checker.subscribe(Arc::new(move || inner.notify()));
        checker.start();
        *self.sso_subscription.lock() = Some(subscription);
        self.sso_checker = Some(checker);
    }

    fn navigate_to(&self, _url: &str) -> Result<(), AuthClientError> {
        Err(AuthClientError::Unsupported(
            "navigation is not wired yet: it lands with the transport phase",
        ))
    }
}

/// Builds the source a sign-in mints its app delegation from.
///
/// The default source is the Internet Identity canister named by
/// `identity_provider`; a deployment that mints elsewhere (or a test) supplies
/// its own.
#[async_trait::async_trait(?Send)]
pub trait DelegationSourceFactory: PlatformBounds {
    /// Builds the source for the session that was just established.
    async fn create(
        &self,
        session_key: &ArcIdentity,
        session_chain: &crate::delegation_chain::DelegationChain,
        canister_id: Principal,
        host: &str,
    ) -> Result<Arc<dyn AppDelegationSource>, AuthClientError>;
}

/// A started sign-in: the window is open, and awaiting the handle runs the
/// ceremony.
pub struct SignIn {
    client: AuthClient,
    options: SignInOptions,
}

impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIn").finish_non_exhaustive()
    }
}

impl std::future::IntoFuture for SignIn {
    type Output = Result<ClientIdentity, AuthClientError>;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + 'static>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.client.run_sign_in(self.options).await })
    }
}

/// The journal key a redirect sign-in keeps its session key's public half under.
const JOURNAL_SESSION_KEY: &str = "session-key";

impl std::fmt::Display for AuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthClient({})", self.get_status().state())
    }
}

/// Whether a credential's chain is present and unexpired.
fn credential_chain_is_live(credential: &Credential) -> bool {
    credential
        .chain
        .as_ref()
        .map(|chain| chain.is_delegation_valid(None))
        .unwrap_or(false)
}

/// The identity requests are signed with, built from a credential's key and
/// delegation.
fn delegated_identity_for(credential: &Credential) -> Option<ArcIdentity> {
    let chain = credential.chain.as_ref()?;
    let root_key = chain.public_key.clone();
    let signing = credential.identity.as_arc_identity();
    let delegated =
        DelegatedIdentity::new_unchecked(root_key, Box::new(signing), chain.delegations.clone());
    Some(ArcIdentity::Delegated(Arc::new(delegated)))
}

/// Counts one ceremony while it is in flight.
struct InteractionGuard<'a> {
    counter: &'a AtomicU64,
}

impl<'a> InteractionGuard<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter }
    }
}

impl Drop for InteractionGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The origin of the identity provider's authorize URL: where a non-browser
/// client looks for the sign-in route.
#[cfg(all(
    feature = "native",
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]
fn auth_origin_of(authorize_url: &str) -> String {
    url::Url::parse(authorize_url)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null")
        .unwrap_or_else(|| authorize_url.trim_end_matches('/').to_string())
}

/// The earliest delegation expiration in a chain, in nanoseconds: how long the
/// chain authorises anything.
fn earliest_expiration_ns(chain: &crate::delegation_chain::DelegationChain) -> Option<u64> {
    chain
        .delegations
        .iter()
        .map(|d| d.delegation.expiration)
        .min()
}

/// Maps a signer refusal that means "a ceremony was needed" onto the client's
/// error.
fn interaction_error(error: crate::client::transport::SignerError) -> AuthClientError {
    if error.is_interaction_required() {
        AuthClientError::InteractionRequired {
            reason: error.refusal_reason(),
        }
    } else {
        error.into()
    }
}

/// The principal an identity signs as.
fn identity_principal(identity: &ArcIdentity) -> Option<Principal> {
    identity.as_arc_identity().sender().ok()
}

/// The default credential store for this platform.
///
/// Upstream defaults to IndexedDB in a browser. The native build has no single
/// right answer --- a keyring needs a service name, a PEM store a directory ---
/// so it defaults to memory and the application picks a durable store through
/// [`AuthClientCreateOptions::credential_storage`].
#[cfg(feature = "wasm-js")]
fn default_credential_storage() -> SharedCredentialStorage {
    Arc::new(crate::client::credentials::idb::IdbCredentialStorage::default())
}

/// The default credential store for this platform.
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
fn default_credential_storage() -> SharedCredentialStorage {
    Arc::new(MemoryCredentialStorage::new(BaseKeyType::Ed25519))
}

/// The default state store for this platform: `localStorage` in a browser (with
/// its worker mirror), memory elsewhere.
#[cfg(feature = "wasm-js")]
fn default_state_storage() -> SharedStateStorage {
    Arc::new(crate::client::state::local::LocalStateStorage::new())
}

/// The default state store for this platform.
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
fn default_state_storage() -> SharedStateStorage {
    Arc::new(MemoryStateStorage::new())
}

/// The signer transport this platform uses, where the transport layer is
/// available.
///
/// The browser transports and the native bridge land with their phase; a client
/// without one still answers for stored state and reports
/// [`AuthClientError::Unsupported`] from the methods that need a signer.
#[cfg(feature = "wasm-js")]
fn default_transport(_settings: &Settings) -> Option<SharedTransport> {
    None
}

/// The signer transport this platform uses.
#[cfg(all(not(feature = "wasm-js"), feature = "native"))]
fn default_transport(_settings: &Settings) -> Option<SharedTransport> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    // Imported here rather than taken from the parent's cfg'd imports: on a
    // wasm32 test build the parent compiles neither `native` branch, and these
    // tests are compiled for that target too (they only run where a runner
    // exists, but they have to build).
    use crate::client::credentials::MemoryCredentialStorage;
    use crate::client::state::{MemoryStateStorage, StateStorage, StoredSessionState};
    use crate::key::BaseKeyType;
    #[allow(unused_imports)]
    use ic_agent::identity::Identity as _;

    fn account() -> Principal {
        Principal::self_authenticating([7u8; 32])
    }

    #[test]
    fn authorize_url_defaults_to_mainnet_identity_provider() {
        let url = build_authorize_url(
            &AuthClientCreateOptions::default(),
            &IdentityProvider::default(),
            false,
        )
        .unwrap();
        assert_eq!(url, "https://id.ai/authorize");
    }

    #[test]
    fn authorize_url_carries_openid_prompt_hint_and_resumable() {
        let options = AuthClientCreateOptions {
            open_id_provider: Some(OpenIdProvider::Google),
            prompt: Some(crate::client::options::Prompt::None),
            hint: Some(account()),
            resumable: Some(true),
            ..Default::default()
        };
        let url = build_authorize_url(&options, &IdentityProvider::default(), false).unwrap();
        assert!(url.contains("openid=https%3A%2F%2Faccounts.google.com"));
        assert!(url.contains("prompt=none"));
        assert!(url.contains(&format!("hint={}", account().to_text())));
        assert!(url.contains("resumable=true"));
    }

    #[test]
    fn authorize_url_only_carries_derivation_origin_with_sso() {
        let options = AuthClientCreateOptions {
            derivation_origin: Some("https://example.com".to_string()),
            ..Default::default()
        };
        let url = build_authorize_url(&options, &IdentityProvider::default(), false).unwrap();
        assert!(!url.contains("derivationOrigin"));

        let options = AuthClientCreateOptions {
            derivation_origin: Some("https://example.com".to_string()),
            sso_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        let url = build_authorize_url(&options, &IdentityProvider::default(), false).unwrap();
        assert!(url.contains("sso=example.com"));
        assert!(url.contains("derivationOrigin=https%3A%2F%2Fexample.com"));
    }

    #[test]
    fn rejects_both_one_click_entries() {
        let options = AuthClientCreateOptions {
            open_id_provider: Some(OpenIdProvider::Apple),
            sso_domain: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            AuthClient::new(options),
            Err(AuthClientError::InvalidOptions(_))
        ));
    }

    /// The browser sign-in's identity is the rotating session identity, not a
    /// snapshot of one credential.
    mod session_identity_wiring {
        use std::collections::VecDeque;
        use std::sync::Mutex as StdMutex;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use async_trait::async_trait;

        use super::*;
        use crate::client::credentials::CredentialStorage;
        use crate::client::session::test_support::{FakeClock, FakeSource, chain_to};
        use crate::signer::test_utils::FakeTransport;

        struct SingleSourceFactory(Arc<FakeSource>);

        #[async_trait(?Send)]
        impl DelegationSourceFactory for SingleSourceFactory {
            async fn create(
                &self,
                _session_key: &ArcIdentity,
                _session_chain: &crate::delegation_chain::DelegationChain,
                _canister_id: Principal,
                _host: &str,
            ) -> Result<Arc<dyn AppDelegationSource>, AuthClientError> {
                Ok(self.0.clone())
            }
        }

        fn options(
            credentials: Arc<dyn CredentialStorage>,
            state: Arc<MemoryStateStorage>,
        ) -> AuthClientCreateOptions {
            AuthClientCreateOptions {
                credential_storage: Some(credentials),
                state_storage: Some(state),
                ..Default::default()
            }
        }

        fn account() -> ic_agent::identity::BasicIdentity {
            ic_agent::identity::BasicIdentity::from_raw_key(&[11u8; 32])
        }

        fn account_key() -> Vec<u8> {
            account().public_key().unwrap()
        }

        fn now_ms() -> u64 {
            crate::client::now::now_ns() / 1_000_000
        }

        #[test]
        fn restore_opens_the_session_identity_and_adopts_without_minting() {
            let expiration_ns = (now_ms() + 3_600_000) * 1_000_000;
            let session_chain = chain_to(
                &account_key(),
                &ic_agent::identity::BasicIdentity::from_raw_key(&[12u8; 32])
                    .public_key()
                    .unwrap(),
                expiration_ns,
            );
            let app_chain = chain_to(
                &account_key(),
                &ic_agent::identity::BasicIdentity::from_raw_key(&[13u8; 32])
                    .public_key()
                    .unwrap(),
                expiration_ns,
            );

            let credentials = Arc::new(MemoryCredentialStorage::new(BaseKeyType::Ed25519));
            futures::executor::block_on(async {
                credentials
                    .set(
                        "session",
                        Credential::with_chain(
                            ArcIdentity::Ed25519(Arc::new(
                                ic_agent::identity::BasicIdentity::from_raw_key(&[12u8; 32]),
                            )),
                            session_chain,
                        ),
                    )
                    .await
                    .unwrap();
                credentials
                    .set(
                        "app",
                        Credential::with_chain(
                            ArcIdentity::Ed25519(Arc::new(
                                ic_agent::identity::BasicIdentity::from_raw_key(&[13u8; 32]),
                            )),
                            app_chain,
                        ),
                    )
                    .await
                    .unwrap();
            });

            let state = Arc::new(MemoryStateStorage::new());
            let source = Arc::new(FakeSource::new(
                account_key(),
                FakeClock::new(now_ms()),
                3_600_000,
            ));
            let client = AuthClient::with_delegation_source_factory(
                options(credentials, state.clone()),
                FakeTransport::new().shared(),
                Arc::new(SingleSourceFactory(source.clone())),
            )
            .unwrap();
            state.set(
                &client.slots().state,
                StoredSessionState {
                    principal: Principal::self_authenticating(account_key()),
                    expiration_ns,
                },
            );

            futures::executor::block_on(client.ready()).unwrap();

            assert!(client.is_authenticated());
            assert_eq!(
                client.get_principal(),
                Some(Principal::self_authenticating(account_key()))
            );
            // The identity the client answers with signs as the account and
            // presents the adopted app delegation.
            let identity = futures::executor::block_on(client.get_identity()).unwrap();
            assert_eq!(
                identity.sender().unwrap(),
                Principal::self_authenticating(account_key())
            );
            assert_eq!(identity.delegation_chain().len(), 1);
            // Held as the rotating identity, and adopted rather than re-minted:
            // the credential in the slot was still fresh.
            assert!(
                client.inner.identity.lock().session().is_some(),
                "the client holds the rotating session identity"
            );
            assert_eq!(source.calls(), 0, "restore adopts, it does not mint");
        }

        #[test]
        fn sign_in_opens_the_session_identity_after_one_mint() {
            let expiration_ns = (now_ms() + 3_600_000) * 1_000_000;
            let session_leaf = ic_agent::identity::BasicIdentity::from_raw_key(&[12u8; 32])
                .public_key()
                .unwrap();
            let app_leaf = ic_agent::identity::BasicIdentity::from_raw_key(&[13u8; 32])
                .public_key()
                .unwrap();

            // A credential store that hands out the two keys this flow needs in
            // the order it asks for them: the session key, then the app key.
            struct FixedKeys {
                inner: MemoryCredentialStorage,
                created: StdMutex<VecDeque<ArcIdentity>>,
            }

            #[async_trait(?Send)]
            impl CredentialStorage for FixedKeys {
                fn shared(&self) -> bool {
                    false
                }
                fn durable(&self) -> bool {
                    true
                }
                async fn create(&self) -> Result<ArcIdentity, AuthClientError> {
                    Ok(self
                        .created
                        .lock()
                        .unwrap()
                        .pop_front()
                        .expect("the flow asks for exactly the session and app keys"))
                }
                async fn get(&self, slot: &str) -> Result<Option<Credential>, AuthClientError> {
                    self.inner.get(slot).await
                }
                async fn set(
                    &self,
                    slot: &str,
                    credential: Credential,
                ) -> Result<(), AuthClientError> {
                    self.inner.set(slot, credential).await
                }
                async fn remove(&self, slot: &str) -> Result<(), AuthClientError> {
                    self.inner.remove(slot).await
                }
            }

            // The signer answers the session request with a chain rooted at the
            // account and delegating to the session key, restricted to II.
            let canister = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
            let transport = FakeTransport::new();
            transport.on_result(
                "ii_session_delegation",
                serde_json::json!({
                    "publicKey": crate::client::base64::to_base64(&account_key()),
                    "signerDelegation": [{
                        "delegation": {
                            "pubkey": crate::client::base64::to_base64(&session_leaf),
                            "expiration": expiration_ns.to_string(),
                            "targets": [canister.to_text()],
                        },
                        "signature": crate::client::base64::to_base64(&[1, 2, 3]),
                    }],
                }),
            );

            let credentials = Arc::new(FixedKeys {
                inner: MemoryCredentialStorage::new(BaseKeyType::Ed25519),
                created: StdMutex::new(VecDeque::from([
                    ArcIdentity::Ed25519(Arc::new(
                        ic_agent::identity::BasicIdentity::from_raw_key(&[12u8; 32]),
                    )),
                    ArcIdentity::Ed25519(Arc::new(
                        ic_agent::identity::BasicIdentity::from_raw_key(&[13u8; 32]),
                    )),
                ])),
            });
            let state = Arc::new(MemoryStateStorage::new());
            let source = Arc::new(FakeSource::new(
                account_key(),
                FakeClock::new(now_ms()),
                3_600_000,
            ));
            let client = AuthClient::with_delegation_source_factory(
                options(credentials.clone(), state.clone()),
                transport.shared(),
                Arc::new(SingleSourceFactory(source.clone())),
            )
            .unwrap();

            let identity = futures::executor::block_on(client.sign_in(SignInOptions::default()))
                .expect("sign-in completes");

            assert_eq!(
                identity.sender().unwrap(),
                Principal::self_authenticating(account_key())
            );
            assert_eq!(identity.delegation_chain().len(), 1);
            assert_eq!(
                client.get_principal(),
                Some(Principal::self_authenticating(account_key()))
            );
            // One mint for the ceremony; opening the session adopts it instead of
            // spending a second call.
            assert_eq!(source.calls(), 1, "the app delegation is minted once");
            assert!(
                client.inner.identity.lock().session().is_some(),
                "the client holds the rotating session identity"
            );
            let stored = futures::executor::block_on(credentials.get(&client.slots().app))
                .unwrap()
                .expect("the app credential is stored");
            assert_eq!(
                stored.chain.unwrap().public_key,
                account_key(),
                "the app delegation is rooted at the account"
            );
            let _ = (app_leaf, AtomicUsize::new(0).load(Ordering::SeqCst));
        }
    }

    /// A state store that only reads, as a worker's view is. Any write is a
    /// test failure: the client must not write through it.
    struct ReadOnlyStore(MemoryStateStorage);

    impl crate::client::state::StateStorage for ReadOnlyStore {
        fn get(&self, key: &str) -> Option<crate::client::state::SessionState> {
            self.0.get(key)
        }
        fn set(&self, _key: &str, _state: StoredSessionState) {
            panic!("a read-only state store was written");
        }
        fn remove(&self, _key: &str) {
            panic!("a read-only state store was written");
        }
        fn discard(&self, _key: &str) {
            panic!("a read-only state store was written");
        }
        fn is_read_only(&self) -> bool {
            true
        }
        fn subscribe(
            &self,
            key: &str,
            listener: crate::client::state::StateListener,
        ) -> Subscription {
            self.0.subscribe(key, listener)
        }
    }

    fn read_only_client() -> (AuthClient, Arc<MemoryCredentialStorage>) {
        use crate::client::credentials::CredentialStorage;

        let auth = basic_identity(3);
        let session_key = basic_identity(4);
        let account_key = auth.public_key().unwrap();
        let expiration = crate::client::now::now_ns() + 60 * 60 * 1_000_000_000;
        let session_chain = crate::delegation_chain::DelegationChain {
            delegations: vec![session_delegation_to(
                &auth,
                session_key.public_key().unwrap(),
                expiration,
            )],
            public_key: account_key,
        };
        let credentials = Arc::new(MemoryCredentialStorage::new(BaseKeyType::Ed25519));
        futures::executor::block_on(async {
            credentials
                .set(
                    "session",
                    Credential::with_chain(
                        ArcIdentity::Ed25519(Arc::new(session_key)),
                        session_chain,
                    ),
                )
                .await
                .unwrap();
        });
        let client = AuthClient::new(AuthClientCreateOptions {
            credential_storage: Some(credentials.clone()),
            state_storage: Some(Arc::new(ReadOnlyStore(MemoryStateStorage::new()))),
            ..Default::default()
        })
        .unwrap();
        (client, credentials)
    }

    #[test]
    fn a_read_only_state_store_is_not_written_through() {
        // The record is missing (this store publishes nothing) while a live
        // session credential exists: the restore has to drop the session without
        // writing through the store, which traps on its platform's assert.
        let (client, _credentials) = read_only_client();
        futures::executor::block_on(async {
            client.ready().await.unwrap();
            assert_eq!(client.get_status(), SessionStatus::SignedOut);
            assert_eq!(
                client.get_identity().await.unwrap().sender().unwrap(),
                Principal::anonymous()
            );
        });
    }

    #[test]
    fn a_read_only_state_store_makes_sign_in_unsupported() {
        let (client, _credentials) = read_only_client();
        let result = futures::executor::block_on(client.sign_in(SignInOptions::default()));
        assert!(
            matches!(result, Err(AuthClientError::Unsupported(_))),
            "signing in cannot publish to a read-only store"
        );
    }

    #[test]
    fn end_or_drop_leaves_a_read_only_store_alone() {
        use crate::client::credentials::CredentialStorage;

        let (client, credentials) = read_only_client();
        // A read-only store traps on a write, so reaching the end of this call is
        // the assertion that nothing tried. Upstream leaves the credentials for a
        // page to clear too, so they are still there.
        futures::executor::block_on(crate::client::session::record::end_or_drop(
            client.state_storage.clone(),
            Arc::clone(&credentials) as SharedCredentialStorage,
            Arc::clone(&client.slots),
            None,
            true,
        ));
        assert!(
            futures::executor::block_on(credentials.get("session"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_restore_that_finishes_after_dispose_installs_nothing() {
        let (client, _credentials) = signed_in_client();
        client.dispose();
        futures::executor::block_on(client.ready()).unwrap();
        assert!(!client.is_authenticated());
        // A disposed client answers anonymously; what matters is that the restore
        // did not install the identity it found and start its rotation.
        assert_eq!(
            futures::executor::block_on(client.get_identity())
                .unwrap()
                .sender()
                .unwrap(),
            Principal::anonymous()
        );
    }

    #[test]
    fn a_record_changed_elsewhere_is_followed() {
        let (client, credentials) = signed_in_client();
        futures::executor::block_on(async {
            client.ready().await.unwrap();
            assert_eq!(
                client.get_identity().await.unwrap().sender().unwrap(),
                Principal::self_authenticating(basic_identity(3).public_key().unwrap())
            );

            // A peer client on this page, or another tab, signs in as another
            // account through the same stores.
            peer_signs_in(&client, &credentials, 5, 6, 7).await;

            // The record changed, so the next identity answers for it rather
            // than for the sign-in that ended.
            assert_eq!(
                client.get_identity().await.unwrap().sender().unwrap(),
                Principal::self_authenticating(basic_identity(5).public_key().unwrap())
            );
        });
    }

    #[test]
    fn an_identity_that_disagrees_with_the_record_is_replaced() {
        let (client, credentials) = signed_in_client();
        futures::executor::block_on(async {
            client.ready().await.unwrap();

            // A change nobody notified this client about: the mismatch check has
            // to catch it on its own.
            peer_signs_in(&client, &credentials, 5, 6, 7).await;
            client.inner.stale.store(false, Ordering::SeqCst);

            assert_eq!(
                client.get_identity().await.unwrap().sender().unwrap(),
                Principal::self_authenticating(basic_identity(5).public_key().unwrap())
            );
        });
    }

    /// Native sign-in over the identity provider's non-browser flow, driven
    /// through a runner that answers as the provider's page would.
    #[cfg(all(
        feature = "native",
        any(target_os = "macos", target_os = "linux", target_os = "windows")
    ))]
    mod native_sign_in {
        use super::*;
        use crate::client::credentials::CredentialStorage as _;
        use async_trait::async_trait;

        struct FakeRunner {
            account: ic_agent::identity::BasicIdentity,
        }

        #[async_trait(?Send)]
        impl crate::client::webauth::WebAuthRunner for FakeRunner {
            async fn acquire(
                &self,
                session_public_key_der: &[u8],
                _options: crate::client::webauth::WebAuthOptions,
            ) -> Result<
                crate::delegation_chain::DelegationChain,
                crate::client::webauth::WebAuthError,
            > {
                // The provider signs a delegation to the client's key.
                Ok(chain_to(&self.account, session_public_key_der))
            }
        }

        fn chain_to(
            account: &ic_agent::identity::BasicIdentity,
            leaf: &[u8],
        ) -> crate::delegation_chain::DelegationChain {
            use ic_agent::identity::SignedDelegation;
            use ic_agent::identity::{Delegation, Identity as _};

            let delegation = Delegation {
                pubkey: leaf.to_vec(),
                expiration: crate::client::now::now_ns() + 60 * 60 * 1_000_000_000,
                targets: None,
                permissions: None,
            };
            let signature = account.sign_delegation(&delegation).unwrap();
            crate::delegation_chain::DelegationChain {
                delegations: vec![SignedDelegation {
                    delegation,
                    signature: signature.signature.unwrap(),
                }],
                public_key: account.public_key().unwrap(),
            }
        }

        fn client_with(
            credentials: Arc<MemoryCredentialStorage>,
            state: Arc<MemoryStateStorage>,
            runner: Arc<dyn crate::client::webauth::WebAuthRunner>,
        ) -> AuthClient {
            AuthClient::with_webauth_runner(
                AuthClientCreateOptions {
                    credential_storage: Some(credentials),
                    state_storage: Some(state),
                    ..Default::default()
                },
                runner,
            )
            .unwrap()
        }

        fn account_principal(account: &ic_agent::identity::BasicIdentity) -> Principal {
            use ic_agent::identity::Identity as _;
            Principal::self_authenticating(&account.public_key().unwrap())
        }

        #[test]
        fn signs_in_and_restores_through_the_app_slot() {
            let account = ic_agent::identity::BasicIdentity::from_raw_key(&[5u8; 32]);
            let credentials = Arc::new(MemoryCredentialStorage::new(BaseKeyType::Ed25519));
            let state = Arc::new(MemoryStateStorage::new());
            let client = client_with(
                credentials.clone(),
                state.clone(),
                Arc::new(FakeRunner {
                    account: ic_agent::identity::BasicIdentity::from_raw_key(&[5u8; 32]),
                }),
            );

            let identity = futures::executor::block_on(client.sign_in(SignInOptions::default()))
                .expect("sign-in completes");
            assert_eq!(
                identity.sender().unwrap(),
                account_principal(&account),
                "the identity signs as the account the delegation names"
            );
            assert_eq!(identity.delegation_chain().len(), 1);
            assert!(client.is_authenticated());
            assert_eq!(client.get_principal(), Some(account_principal(&account)));

            // The credential is the one the app signs with, and the state record
            // carries the account the provider minted for.
            let stored = futures::executor::block_on(credentials.get(&client.slots().app))
                .unwrap()
                .expect("the app credential was stored");
            assert!(stored.chain.is_some());
            assert_eq!(
                state.get(&client.slots().state).unwrap().principal,
                account_principal(&account)
            );

            // A fresh client over the same stores restores that credential: the
            // single-delegation model is the session on native.
            let restored = client_with(
                credentials.clone(),
                state.clone(),
                Arc::new(FakeRunner {
                    account: ic_agent::identity::BasicIdentity::from_raw_key(&[5u8; 32]),
                }),
            );
            futures::executor::block_on(restored.ready()).unwrap();
            assert!(restored.is_authenticated());
            assert_eq!(
                futures::executor::block_on(restored.get_identity())
                    .unwrap()
                    .sender()
                    .unwrap(),
                account_principal(&account)
            );

            // Signing out clears what the flow wrote; there is no session to
            // revoke at the canister.
            futures::executor::block_on(restored.sign_out(SignOutOptions::default())).unwrap();
            assert_eq!(restored.get_status(), SessionStatus::SignedOut);
            assert!(
                futures::executor::block_on(credentials.get(&restored.slots().app))
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn a_delegation_for_another_key_is_refused() {
            let credentials = Arc::new(MemoryCredentialStorage::new(BaseKeyType::Ed25519));
            let state = Arc::new(MemoryStateStorage::new());

            struct WrongKeyRunner(ic_agent::identity::BasicIdentity);
            #[async_trait(?Send)]
            impl crate::client::webauth::WebAuthRunner for WrongKeyRunner {
                async fn acquire(
                    &self,
                    _session_public_key_der: &[u8],
                    _options: crate::client::webauth::WebAuthOptions,
                ) -> Result<
                    crate::delegation_chain::DelegationChain,
                    crate::client::webauth::WebAuthError,
                > {
                    // A chain for a key nobody asked for.
                    Ok(chain_to(&self.0, &[1, 2, 3]))
                }
            }

            let client = client_with(
                credentials,
                state,
                Arc::new(WrongKeyRunner(
                    ic_agent::identity::BasicIdentity::from_raw_key(&[5u8; 32]),
                )),
            );
            let result = futures::executor::block_on(client.sign_in(SignInOptions::default()));
            assert!(matches!(result, Err(AuthClientError::Other(_))));
            assert_eq!(client.get_status(), SessionStatus::SignedOut);
        }
    }

    #[test]
    fn status_reads_the_state_record() {
        let state = Arc::new(MemoryStateStorage::new());
        let client = AuthClient::new(AuthClientCreateOptions {
            state_storage: Some(state.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(client.get_status(), SessionStatus::SignedOut);
        assert!(!client.is_authenticated());
        assert_eq!(client.get_principal(), None);
        assert_eq!(
            futures::executor::block_on(client.get_identity())
                .unwrap()
                .sender()
                .unwrap(),
            Principal::anonymous()
        );
        let _ = state;
    }

    fn basic_identity(seed: u8) -> ic_agent::identity::BasicIdentity {
        ic_agent::identity::BasicIdentity::from_raw_key(&[seed; 32])
    }

    fn delegation_to(
        from: &ic_agent::identity::BasicIdentity,
        to_public_key: Vec<u8>,
        expiration: u64,
    ) -> ic_agent::identity::SignedDelegation {
        use ic_agent::identity::{Delegation, SignedDelegation};

        let delegation = Delegation {
            pubkey: to_public_key,
            expiration,
            targets: None,
            permissions: None,
        };
        let signature = from.sign_delegation(&delegation).unwrap();
        SignedDelegation {
            delegation,
            signature: signature.signature.unwrap(),
        }
    }

    /// A hop restricted to the identity provider, as a session chain's is.
    fn session_delegation_to(
        from: &ic_agent::identity::BasicIdentity,
        to_public_key: Vec<u8>,
        expiration: u64,
    ) -> ic_agent::identity::SignedDelegation {
        use ic_agent::identity::{Delegation, SignedDelegation};

        let delegation = Delegation {
            pubkey: to_public_key,
            expiration,
            targets: Some(vec![
                Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap(),
            ]),
            permissions: None,
        };
        let signature = from.sign_delegation(&delegation).unwrap();
        SignedDelegation {
            delegation,
            signature: signature.signature.unwrap(),
        }
    }

    /// A client whose stores hold one signed-in account: a state record plus a
    /// session credential and an app credential rooted at the account's key.
    fn signed_in_client() -> (AuthClient, Arc<MemoryCredentialStorage>) {
        signed_in_client_for(3, 4, 9)
    }

    /// Writes the stores a peer signing in as another account would: session and
    /// app credentials rooted at its account, and the record naming it.
    async fn peer_signs_in(
        client: &AuthClient,
        credentials: &MemoryCredentialStorage,
        account_seed: u8,
        session_seed: u8,
        app_seed: u8,
    ) {
        use crate::client::credentials::CredentialStorage;

        let account = basic_identity(account_seed);
        let session_key = basic_identity(session_seed);
        let app = basic_identity(app_seed);
        let account_key = account.public_key().unwrap();
        let expiration = crate::client::now::now_ns() + 60 * 60 * 1_000_000_000;
        let session_chain = crate::delegation_chain::DelegationChain {
            delegations: vec![session_delegation_to(
                &account,
                session_key.public_key().unwrap(),
                expiration,
            )],
            public_key: account_key.clone(),
        };
        let app_chain = crate::delegation_chain::DelegationChain {
            delegations: vec![delegation_to(
                &account,
                app.public_key().unwrap(),
                expiration,
            )],
            public_key: account_key,
        };
        credentials
            .set(
                "session",
                Credential::with_chain(ArcIdentity::Ed25519(Arc::new(session_key)), session_chain),
            )
            .await
            .unwrap();
        credentials
            .set(
                "app",
                Credential::with_chain(ArcIdentity::Ed25519(Arc::new(app)), app_chain),
            )
            .await
            .unwrap();
        client.state_storage().set(
            &client.slots().state,
            StoredSessionState {
                principal: Principal::self_authenticating(
                    basic_identity(account_seed).public_key().unwrap(),
                ),
                expiration_ns: expiration,
            },
        );
    }

    fn signed_in_client_for(
        account_seed: u8,
        session_seed: u8,
        app_seed: u8,
    ) -> (AuthClient, Arc<MemoryCredentialStorage>) {
        use crate::client::credentials::CredentialStorage;

        let account = basic_identity(account_seed);
        let session_key = basic_identity(session_seed);
        let app = basic_identity(app_seed);
        let account_key = account.public_key().unwrap();
        let expiration = crate::client::now::now_ns() + 60 * 60 * 1_000_000_000;
        // A session chain is rooted at the account and restricted to the
        // provider; the app delegation it mints is rooted at the account and
        // signed by the session key.
        let session_chain = crate::delegation_chain::DelegationChain {
            delegations: vec![session_delegation_to(
                &account,
                session_key.public_key().unwrap(),
                expiration,
            )],
            public_key: account_key.clone(),
        };
        let app_chain = crate::delegation_chain::DelegationChain {
            delegations: vec![delegation_to(
                &account,
                app.public_key().unwrap(),
                expiration,
            )],
            public_key: account_key.clone(),
        };

        let credentials = Arc::new(MemoryCredentialStorage::new(BaseKeyType::Ed25519));
        futures::executor::block_on(async {
            credentials
                .set(
                    "session",
                    Credential::with_chain(
                        ArcIdentity::Ed25519(Arc::new(session_key)),
                        session_chain,
                    ),
                )
                .await
                .unwrap();
            credentials
                .set(
                    "app",
                    Credential::with_chain(ArcIdentity::Ed25519(Arc::new(app)), app_chain),
                )
                .await
                .unwrap();
        });

        let state = Arc::new(MemoryStateStorage::new());
        let client = AuthClient::new(AuthClientCreateOptions {
            credential_storage: Some(credentials.clone()),
            state_storage: Some(state.clone()),
            ..Default::default()
        })
        .unwrap();
        state.set(
            &client.slots().state,
            StoredSessionState {
                principal: Principal::self_authenticating(&account_key),
                expiration_ns: expiration,
            },
        );
        (client, credentials)
    }

    #[test]
    fn restores_a_signed_in_session() {
        let (client, _credentials) = signed_in_client();
        futures::executor::block_on(async {
            client.ready().await.unwrap();
            assert!(client.is_authenticated());
            assert_eq!(
                client.get_principal(),
                Some(Principal::self_authenticating(
                    basic_identity(3).public_key().unwrap()
                ))
            );
            assert_eq!(
                client
                    .get_identity()
                    .await
                    .unwrap()
                    .delegation_chain()
                    .len(),
                1
            );
        });
    }

    #[test]
    fn sign_out_clears_credentials_and_state() {
        use crate::client::credentials::CredentialStorage;

        let (client, credentials) = signed_in_client();
        futures::executor::block_on(async {
            client.ready().await.unwrap();
            // Replace the session credential with one the mint layer cannot use,
            // so signing out takes the offline path instead of calling the
            // provider (which the tests must not do).
            credentials
                .set(
                    "session",
                    Credential::with_chain(
                        ArcIdentity::Ed25519(Arc::new(basic_identity(4))),
                        crate::delegation_chain::DelegationChain {
                            delegations: vec![delegation_to(
                                &basic_identity(3),
                                basic_identity(4).public_key().unwrap(),
                                1,
                            )],
                            public_key: basic_identity(3).public_key().unwrap(),
                        },
                    ),
                )
                .await
                .unwrap();
            client.sign_out(SignOutOptions::default()).await.unwrap();
            assert_eq!(client.get_status(), SessionStatus::SignedOut);
            assert!(credentials.get("session").await.unwrap().is_none());
            assert!(credentials.get("app").await.unwrap().is_none());
            assert!(client.state_storage().get(&client.slots().state).is_none());
        });
    }

    #[test]
    fn a_stale_session_credential_is_cleared_but_the_record_is_kept() {
        use crate::client::credentials::CredentialStorage;

        let (client, credentials) = signed_in_client();
        // Replace the session credential with one whose chain has already
        // expired: the record stays, so the status reads `expired`.
        let expired_chain = crate::delegation_chain::DelegationChain {
            delegations: vec![session_delegation_to(
                &basic_identity(3),
                basic_identity(4).public_key().unwrap(),
                1,
            )],
            public_key: basic_identity(3).public_key().unwrap(),
        };
        futures::executor::block_on(async {
            credentials
                .set(
                    "session",
                    Credential::with_chain(
                        ArcIdentity::Ed25519(Arc::new(basic_identity(3))),
                        expired_chain,
                    ),
                )
                .await
                .unwrap();
            client.ready().await.unwrap();
            assert!(credentials.get("session").await.unwrap().is_none());
            // The record still claimed this origin was signed in, so it goes.
            assert!(client.state_storage().get(&client.slots().state).is_none());
            assert_eq!(client.get_status(), SessionStatus::SignedOut);
        });
    }

    #[test]
    fn subscribers_hear_about_a_record_changed_elsewhere() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let state = Arc::new(MemoryStateStorage::new());
        let client = AuthClient::new(AuthClientCreateOptions {
            state_storage: Some(state.clone()),
            ..Default::default()
        })
        .unwrap();
        let fires = Arc::new(AtomicUsize::new(0));
        let counter = fires.clone();
        let subscription = client.subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        // A sibling client writing the same store is news.
        let record = StoredSessionState {
            principal: account(),
            expiration_ns: crate::client::now::now_ns() + 1_000_000_000,
        };
        state.set(&client.slots().state, record);
        assert_eq!(fires.load(Ordering::SeqCst), 1);
        assert!(client.is_authenticated());

        // A write the listener already saw is not repeated.
        state.set(&client.slots().state, record);
        assert_eq!(fires.load(Ordering::SeqCst), 1);

        subscription.unsubscribe();
        state.remove(&client.slots().state);
        assert_eq!(fires.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_disposed_client_is_signed_out() {
        let (client, _credentials) = signed_in_client();
        futures::executor::block_on(async {
            client.ready().await.unwrap();
            assert!(client.is_authenticated());
            client.dispose();
            assert!(!client.is_authenticated());
            // Disposing writes nothing shared.
            assert!(client.state_storage().get(&client.slots().state).is_some());
        });
    }

    #[test]
    fn expired_record_reads_expired_not_signed_out() {
        let state = Arc::new(MemoryStateStorage::new());
        let client = AuthClient::new(AuthClientCreateOptions {
            state_storage: Some(state.clone()),
            ..Default::default()
        })
        .unwrap();
        state.set(
            &client.slots().state,
            StoredSessionState {
                principal: account(),
                expiration_ns: 1,
            },
        );
        match client.get_status() {
            SessionStatus::Expired {
                principal,
                expires_at_ms,
            } => {
                assert_eq!(principal, account());
                assert_eq!(expires_at_ms, 0);
            }
            other => panic!("expected expired, got {other:?}"),
        }
    }
}
