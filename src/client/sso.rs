//! Organization-domain single sign-on status.
//!
//! Port of upstream `src/client/sso.ts`. A client constructed with
//! `sso_domain` reports whether that domain can sign its users in, and asks the
//! Internet Identity canister (`app_sso_domain_check` /
//! `app_sso_domain_status`) when the answer is not already known.
//!
//! Three pieces live here, in upstream's order:
//!
//! - [`normalize_sso_domain`] --- the domain rules, as a pure function;
//! - [`SsoStatusChecker`] --- the cached answer and the polling that produces
//!   it, one update followed by cheap queries with a `500 ms -> 2 s` backoff;
//! - the canister interface, exercised through [`SsoDomainService`] so that a
//!   test can answer without a replica.
//!
//! [`scoped_keys`] is the attribute-key helper that rides on the domain rules.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use candid::{CandidType, Deserialize};
use ic_agent::Agent;
use ic_agent::export::Principal;
use ic_agent::identity::AnonymousIdentity;
use parking_lot::Mutex;
use url::Url;

use crate::client::Subscription;
use crate::client::error::AuthClientError;
use crate::client::options::{OpenIdProvider, SsoStatus};
use crate::client::platform::{Listener, PlatformBounds};

/// The canister method that asks Internet Identity to check a configured
/// domain.
pub(crate) const II_SSO_CHECK_METHOD: &str = "app_sso_domain_check";

/// The canister method that reports a configured domain's status.
pub(crate) const II_SSO_STATUS_METHOD: &str = "app_sso_domain_status";

/// The first and the shortest wait between two status reads.
///
/// Upstream `sso.ts:182`.
pub const SSO_POLL_MIN_MS: u64 = 500;

/// The longest wait between two status reads.
///
/// Upstream `sso.ts:183`.
pub const SSO_POLL_MAX_MS: u64 = 2_000;

/// How long a check may read `Pending` before it is started again. Matches the
/// age at which Internet Identity treats a fetch as abandoned.
///
/// Upstream `sso.ts:189`.
pub const SSO_RECHECK_AFTER_MS: u64 = 120_000;

/// The identity provider's cap on the authority it will fetch.
///
/// Upstream `sso.ts:6`.
const MAX_AUTHORITY_LENGTH: usize = 255;

/// The identity provider's own cap on a DNS name (idna's strict mode).
///
/// Upstream `sso.ts:9`.
const MAX_DNS_NAME_LENGTH: usize = 253;

/// The identity provider's own cap on one DNS label.
///
/// Upstream `sso.ts:10`.
const MAX_DNS_LABEL_LENGTH: usize = 63;

/// How much of a rejected value an error message quotes.
///
/// Upstream `sso.ts:12`.
const MAX_QUOTED_LENGTH: usize = 100;

/// The attribute keys requested from an OpenID provider when none are given.
///
/// Upstream `auth-client.ts:70`.
pub const DEFAULT_OPENID_SCOPE_KEYS: [&str; 3] = ["name", "email", "verified_email"];

/// The attribute keys requested from an organization's SSO when none are given.
///
/// `verified_email` is not available for an organization SSO.
///
/// Upstream `auth-client.ts:72`.
pub const DEFAULT_SSO_SCOPE_KEYS: [&str; 2] = ["name", "email"];

/// `value` for an error message: cut short, and quoted so control characters
/// show escaped.
///
/// Upstream `sso.ts:15-19`, which is `JSON.stringify` of the value cut to
/// [`MAX_QUOTED_LENGTH`] UTF-16 code units.
fn quote(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    let cut = if units.len() > MAX_QUOTED_LENGTH {
        format!("{}…", String::from_utf16_lossy(&units[..MAX_QUOTED_LENGTH]))
    } else {
        value.to_string()
    };
    // `serde_json` escapes a string exactly as `JSON.stringify` does for the
    // code points a domain can contain.
    serde_json::to_string(&cut).unwrap_or_else(|_| format!("\"{cut}\""))
}

/// `localhost`, `127.0.0.1`, or a name under `.localhost` (RFC 6761 reserves the
/// whole domain for loopback), like the identity provider's own check. IPv6
/// loopback is not one, there either.
///
/// Upstream `sso.ts:26-28`.
fn is_loopback_host(hostname: &str) -> bool {
    hostname == "localhost" || hostname == "127.0.0.1" || hostname.ends_with(".localhost")
}

/// What keeps `hostname` from being a DNS name, by the identity provider's
/// rules.
///
/// Upstream `sso.ts:31-53`. The name arrives already lowercased and
/// IDNA-encoded from the URL parser.
fn dns_name_problems(hostname: &str) -> Vec<String> {
    let labels: Vec<&str> = hostname.split('.').collect();
    let mut problems: Vec<String> = Vec::new();
    if labels.len() < 2 {
        problems.push("a single label".to_string());
    }
    if labels.iter().any(|label| label.is_empty()) {
        problems.push("an empty label".to_string());
    }
    if labels
        .iter()
        .any(|label| label.encode_utf16().count() > MAX_DNS_LABEL_LENGTH)
    {
        problems.push(format!(
            "a label longer than {MAX_DNS_LABEL_LENGTH} characters"
        ));
    }
    if labels.iter().any(|label| {
        label
            .chars()
            .any(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
    }) {
        problems.push("a character other than a letter, digit, or hyphen".to_string());
    }
    if labels
        .iter()
        .any(|label| label.starts_with('-') || label.ends_with('-'))
    {
        problems.push("a label starting or ending with a hyphen".to_string());
    }
    // `--` in the third and fourth places is reserved, except for punycode.
    if labels
        .iter()
        .any(|label| label.as_bytes().get(2..4) == Some(b"--") && !label.starts_with("xn--"))
    {
        problems.push("a label with \"--\" in its third and fourth places".to_string());
    }
    if hostname.encode_utf16().count() > MAX_DNS_NAME_LENGTH {
        problems.push(format!(
            "a name longer than {MAX_DNS_NAME_LENGTH} characters"
        ));
    }
    problems
}

/// Joins problems the way upstream's `listed` does (`sso.ts:55-57`).
fn listed(items: &[String]) -> String {
    if items.len() < 2 {
        return items.join("");
    }
    let (last, rest) = items
        .split_last()
        .expect("a non-empty list has a last item");
    format!("{} and {last}", rest.join(", "))
}

/// The length of the `scheme://` prefix, or `0` when the value carries none.
///
/// Upstream `sso.ts:73-74`: `/^[a-z][a-z0-9+.-]*:\/\//i`.
fn scheme_length(value: &str) -> usize {
    let bytes = value.as_bytes();
    let Some(first) = bytes.first() else {
        return 0;
    };
    if !first.is_ascii_alphabetic() {
        return 0;
    }
    let mut index = 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_alphanumeric()
            || bytes[index] == b'+'
            || bytes[index] == b'.'
            || bytes[index] == b'-')
    {
        index += 1;
    }
    if value[index..].starts_with("://") {
        index + 3
    } else {
        0
    }
}

/// The port typed after the host, exactly as typed, or `None`.
///
/// Upstream `sso.ts:84-87`: the portion of the typed authority after any
/// userinfo, matched by `/:([0-9]*)$/`. `URL` drops an empty or default port,
/// so the typed one has to be read from the input itself.
fn typed_port(rest: &str) -> Option<String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let after_userinfo = match authority.rfind('@') {
        Some(index) => &authority[index + 1..],
        None => authority,
    };
    let colon = after_userinfo.rfind(':')?;
    let port = &after_userinfo[colon + 1..];
    if port.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(port.to_string())
    } else {
        None
    }
}

/// Normalizes an SSO domain to the authority the identity provider fetches the
/// discovery document from: lowercased and IDNA-encoded. A loopback host may
/// carry a port, for a local mock provider; any other host may not.
///
/// Upstream `normalizeSsoDomain` (`sso.ts:68-111`). Every problem with the
/// value is reported together, and the value is quoted and cut short.
///
/// # Errors
///
/// The message upstream would throw, e.g.
/// `ssoDomain "dfinity.org/x" has a path`. Callers that store the result as a
/// [`SsoStatus::Invalid`] keep the message as-is.
pub fn normalize_sso_domain(domain: &str) -> Result<String, String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err("ssoDomain cannot be empty".to_string());
    }
    let scheme = scheme_length(trimmed);
    let rest = &trimmed[scheme..];
    let not_a_domain = || format!("ssoDomain {} is not a domain", quote(trimmed));
    let url = Url::parse(&format!("https://{rest}")).map_err(|_| not_a_domain())?;
    let hostname = url.host_str().ok_or_else(not_a_domain)?.to_string();
    let typed = typed_port(rest);
    let href = url.as_str();
    let before_fragment = href.split('#').next().unwrap_or("");

    let mut problems: Vec<String> = Vec::new();
    if scheme != 0 {
        problems.push("a scheme".to_string());
    }
    let has_userinfo =
        !url.username().is_empty() || url.password().is_some_and(|password| !password.is_empty());
    if has_userinfo {
        problems.push("userinfo".to_string());
    }
    if url.path() != "/" {
        problems.push("a path".to_string());
    }
    if before_fragment.contains('?') {
        problems.push("a query".to_string());
    }
    if href.contains('#') {
        problems.push("a fragment".to_string());
    }
    let loopback = is_loopback_host(&hostname);
    if let Some(typed) = &typed {
        if !loopback {
            problems.push("a port, which only loopback hosts may carry".to_string());
        } else {
            let parsed = url.port();
            let kept = !typed.is_empty()
                && parsed.map(|port| port.to_string()).as_deref() == Some(typed.as_str());
            if !kept {
                problems.push("an empty or default port".to_string());
            }
        }
    }
    // Upstream measures the typed value (`trimmed.length`), in UTF-16 code
    // units, and falls back to the DNS rules only when it is short enough.
    if trimmed.encode_utf16().count() > MAX_AUTHORITY_LENGTH {
        problems.push(format!("more than {MAX_AUTHORITY_LENGTH} characters"));
    } else if !loopback {
        problems.extend(dns_name_problems(&hostname));
    }
    if !problems.is_empty() {
        return Err(format!(
            "ssoDomain {} has {}",
            quote(trimmed),
            listed(&problems)
        ));
    }
    // `url.host`: the hostname, plus a port when one survived normalization.
    Ok(match url.port() {
        Some(port) => format!("{hostname}:{port}"),
        None => hostname,
    })
}

/// An SSO domain, or why a typed value is not one.
///
/// Port of upstream's `domain: string | { invalid: string }` constructor
/// argument (`sso.ts:259-260`). Construct one with [`SsoDomain::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoDomain {
    /// A domain that passed [`normalize_sso_domain`].
    Valid(String),
    /// A value that did not, with the reason to report as-is.
    Invalid(String),
}

impl SsoDomain {
    /// Parses a configured `sso_domain` the way the client's constructor does:
    /// a bad value is a status, never an error.
    pub fn parse(value: &str) -> Self {
        match normalize_sso_domain(value) {
            Ok(domain) => SsoDomain::Valid(domain),
            Err(reason) => SsoDomain::Invalid(reason),
        }
    }

    /// The normalized domain, where the value is one.
    pub fn normalized(&self) -> Option<&str> {
        match self {
            SsoDomain::Valid(domain) => Some(domain),
            SsoDomain::Invalid(_) => None,
        }
    }
}

/// What the canister answers `app_sso_domain_status` with.
///
/// Upstream `CandidSsoDomainStatus` (`sso.ts:134-137`) and the inline IDL at
/// `sso.ts:149-160`:
///
/// ```candid
/// type Timestamp = nat64;
/// type Status = variant {
///   Available   : record { name : opt text };
///   Pending;
///   Unavailable : record { retry_after : opt Timestamp; reason : opt text };
/// };
/// ```
#[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SsoDomainStatus {
    /// The domain resolves to a usable SSO configuration.
    Available {
        /// The organization's display name, when it publishes one.
        name: Option<String>,
    },
    /// The identity provider is still fetching the discovery document.
    Pending,
    /// The domain cannot be signed in with right now.
    Unavailable {
        /// Nanoseconds since the Unix epoch after which a fetch happens again.
        retry_after: Option<u64>,
        /// Internet Identity's explanation, when it gives one.
        reason: Option<String>,
    },
}

/// Maps the canister answer to the client's status. `Pending` maps to `None`
/// because `checking` already says the same thing.
///
/// Upstream `fromCandid` (`sso.ts:195-213`).
fn status_from_candid(status: SsoDomainStatus) -> Option<SsoStatus> {
    match status {
        SsoDomainStatus::Available { name } => Some(SsoStatus::Available { name }),
        SsoDomainStatus::Unavailable {
            retry_after,
            reason,
        } => Some(SsoStatus::Unavailable {
            retry_after_ms: retry_after.map(|nanoseconds| nanoseconds / 1_000_000),
            reason,
        }),
        SsoDomainStatus::Pending => None,
    }
}

/// The two Internet Identity methods an SSO domain check calls.
///
/// Port of upstream `SsoDomainService` (`sso.ts:139-143`). Behind a trait so
/// that a test can answer without a replica.
#[async_trait(?Send)]
pub trait SsoDomainService: PlatformBounds {
    /// Asks Internet Identity to (re)start fetching the domain's discovery
    /// document. An update, so it is the expensive half of a check.
    async fn check(&self, domain: &str) -> Result<(), AuthClientError>;

    /// Reads the domain's status. A query, so it needs no consensus and is the
    /// half worth polling.
    async fn status(&self, domain: &str) -> Result<SsoDomainStatus, AuthClientError>;
}

/// An [`SsoDomainService`] behind an `Arc`.
pub type SharedSsoDomainService = Arc<dyn SsoDomainService>;

/// The future a service factory produces.
pub type SsoServiceFuture =
    Pin<Box<dyn Future<Output = Result<SharedSsoDomainService, AuthClientError>> + 'static>>;

/// Builds the service on first use, and again after a failed build.
///
/// Port of upstream's `() => Promise<SsoDomainService>` constructor argument
/// (`sso.ts:262`). A trait rather than a bare `dyn Fn` because a trait object
/// may carry only one non-auto trait, and [`PlatformBounds`] is not auto.
pub trait ServiceFactory: PlatformBounds {
    /// Builds the service.
    fn create(&self) -> SsoServiceFuture;
}

impl<F> ServiceFactory for F
where
    F: Fn() -> SsoServiceFuture + PlatformBounds,
{
    fn create(&self) -> SsoServiceFuture {
        (self)()
    }
}

/// A [`ServiceFactory`] behind an `Arc`.
pub type SsoServiceFactory = Arc<dyn ServiceFactory>;

/// The canister-backed [`SsoDomainService`]: an anonymous agent, because the
/// check runs before anybody has signed in.
///
/// Upstream `createSsoDomainService` (`sso.ts:166-179`).
pub struct CanisterSsoDomainService {
    agent: Agent,
    canister_id: Principal,
}

impl fmt::Debug for CanisterSsoDomainService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanisterSsoDomainService")
            .field("canister_id", &self.canister_id)
            .finish_non_exhaustive()
    }
}

impl CanisterSsoDomainService {
    /// Builds the service, as the anonymous caller.
    ///
    /// # Errors
    ///
    /// [`AuthClientError::Agent`] when the agent cannot be built --- for
    /// example a host that is not a URL.
    pub fn new(canister_id: Principal, host: impl Into<String>) -> Result<Self, AuthClientError> {
        let host = host.into();
        // `AgentBuilder::with_url` unwraps its own parse, so a host that is not
        // a URL would panic; refuse it as an error instead.
        url::Url::parse(&host).map_err(|error| {
            AuthClientError::Agent(format!("the IC host is not a URL: {error}"))
        })?;
        let agent = Agent::builder()
            .with_url(host)
            .with_arc_identity(Arc::new(AnonymousIdentity))
            .build()
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        Ok(Self { agent, canister_id })
    }
}

#[async_trait(?Send)]
impl SsoDomainService for CanisterSsoDomainService {
    async fn check(&self, domain: &str) -> Result<(), AuthClientError> {
        let argument = candid::encode_one(domain)
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        self.agent
            .update(&self.canister_id, II_SSO_CHECK_METHOD)
            .with_arg(argument)
            .call_and_wait()
            .await
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        Ok(())
    }

    async fn status(&self, domain: &str) -> Result<SsoDomainStatus, AuthClientError> {
        let argument = candid::encode_one(domain)
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        let reply = self
            .agent
            .query(&self.canister_id, II_SSO_STATUS_METHOD)
            .with_arg(argument)
            .call()
            .await
            .map_err(|error| AuthClientError::Agent(error.to_string()))?;
        candid::decode_one(&reply).map_err(|error| {
            AuthClientError::Agent(format!(
                "Internet Identity answered {II_SSO_STATUS_METHOD} with something that is not a domain status: {error}"
            ))
        })
    }
}

/// Builds the canister-backed service factory a client's SSO checker uses.
///
/// The same identity provider canister and host the client mints with.
pub fn sso_domain_service_factory(
    canister_id: Principal,
    host: impl Into<String>,
) -> SsoServiceFactory {
    let host = host.into();
    let factory = move || -> SsoServiceFuture {
        let host = host.clone();
        Box::pin(async move {
            CanisterSsoDomainService::new(canister_id, host)
                .map(|service| Arc::new(service) as SharedSsoDomainService)
        })
    };
    Arc::new(factory)
}

/// A clock and a sleeper, so that the checker's timing can be tested without
/// waiting.
#[async_trait(?Send)]
trait SsoTimer: PlatformBounds {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;

    /// Resolves once `duration` has passed.
    async fn sleep(&self, duration: Duration);
}

/// The platform timer: `gloo-timers` in a browser, `futures-timer` elsewhere.
struct PlatformTimer;

#[async_trait(?Send)]
impl SsoTimer for PlatformTimer {
    fn now_ms(&self) -> u64 {
        crate::client::now::now_ns() / 1_000_000
    }

    async fn sleep(&self, duration: Duration) {
        #[cfg(all(target_arch = "wasm32", feature = "wasm-js"))]
        {
            gloo_timers::future::TimeoutFuture::new(duration.as_millis() as u32).await;
        }
        #[cfg(not(all(target_arch = "wasm32", feature = "wasm-js")))]
        {
            futures_timer::Delay::new(duration).await;
        }
    }
}

/// What the checker holds between calls.
struct Inner {
    /// The normalized domain, or `None` for a value that is not a domain.
    domain: Option<String>,
    /// Builds the service on the first call, and again after a failed build.
    create_service: SsoServiceFactory,
    /// The current answer. The same value until it changes.
    status: Mutex<SsoStatus>,
    /// Listeners fired after the status changes.
    listeners: Mutex<Vec<Arc<dyn Listener>>>,
    /// The service, once built.
    service: Mutex<Option<SharedSsoDomainService>>,
    /// The clock and the sleeper.
    timer: Arc<dyn SsoTimer>,
    /// How long a run may stay pending before the update is sent again.
    recheck_after_ms: u64,
    /// Bumped by every start and by dispose, so a run that was replaced drops
    /// its late answers instead of overwriting a newer one.
    run: AtomicU64,
    /// Whether checking has been abandoned for good.
    disposed: AtomicBool,
}

impl fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SsoStatusChecker")
            .field("domain", &self.domain)
            .field("status", &*self.status.lock())
            .field("disposed", &self.disposed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// Asks Internet Identity whether one SSO domain can be signed in with, and
/// holds the answer.
///
/// Port of upstream `SsoStatusChecker` (`sso.ts:241-365`). One update starts
/// the fetch, then the status is read with a query until it is final: a query
/// needs no consensus, so polling it is cheap where polling an update is not.
/// A read that fails is retried at the next interval, so a check ends only on
/// an answer from Internet Identity, or on [`SsoStatusChecker::dispose`].
///
/// Upstream's constructor starts the first check with a timer. Rust has no
/// ambient executor in a constructor, so construction is inert and the owner
/// calls [`SsoStatusChecker::start`] once after wrapping it in an `Arc`.
pub struct SsoStatusChecker {
    inner: Arc<Inner>,
}

impl fmt::Debug for SsoStatusChecker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, formatter)
    }
}

impl SsoStatusChecker {
    /// Builds a checker. It starts at [`SsoStatus::Checking`] for a domain and
    /// at [`SsoStatus::Invalid`] for a value that is not one; nothing is called
    /// until [`SsoStatusChecker::start`] or [`SsoStatusChecker::refresh`].
    ///
    /// Port of upstream's constructor (`sso.ts:259-272`), minus the implicit
    /// first timer.
    pub fn new(domain: SsoDomain, create_service: SsoServiceFactory) -> Self {
        let (domain, status) = match domain {
            SsoDomain::Valid(domain) => (Some(domain), SsoStatus::Checking),
            SsoDomain::Invalid(reason) => (None, SsoStatus::Invalid { reason }),
        };
        Self {
            inner: Arc::new(Inner {
                domain,
                create_service,
                status: Mutex::new(status),
                listeners: Mutex::new(Vec::new()),
                service: Mutex::new(None),
                timer: Arc::new(PlatformTimer),
                recheck_after_ms: SSO_RECHECK_AFTER_MS,
                run: AtomicU64::new(0),
                disposed: AtomicBool::new(false),
            }),
        }
    }

    /// A checker driven by `timer`. Tests use this to run the backoff without
    /// waiting and to keep the abandon window short.
    #[cfg(test)]
    fn with_timer(
        domain: SsoDomain,
        create_service: SsoServiceFactory,
        timer: Arc<dyn SsoTimer>,
        recheck_after_ms: u64,
    ) -> Self {
        let (domain, status) = match domain {
            SsoDomain::Valid(domain) => (Some(domain), SsoStatus::Checking),
            SsoDomain::Invalid(reason) => (None, SsoStatus::Invalid { reason }),
        };
        Self {
            inner: Arc::new(Inner {
                domain,
                create_service,
                status: Mutex::new(status),
                listeners: Mutex::new(Vec::new()),
                service: Mutex::new(None),
                timer,
                recheck_after_ms,
                run: AtomicU64::new(0),
                disposed: AtomicBool::new(false),
            }),
        }
    }

    /// Starts the first check. Upstream does this from its constructor.
    ///
    /// A no-op for a value that is not a domain, and after
    /// [`SsoStatusChecker::dispose`].
    pub fn start(self: &Arc<Self>) {
        if let Some(run) = self.begin() {
            spawn_drive(self.clone(), run);
        }
    }

    /// The current answer. The same value until it changes.
    pub fn status(&self) -> SsoStatus {
        self.inner.status.lock().clone()
    }

    /// Checks again. Does nothing for an `invalid` domain, or once disposed.
    ///
    /// Port of upstream `refresh` (`sso.ts:280-284`): the status goes back to
    /// `checking` first, then a fresh run starts.
    pub fn refresh(self: &Arc<Self>) {
        if !self.can_check() {
            return;
        }
        self.set(SsoStatus::Checking);
        if let Some(run) = self.begin() {
            spawn_drive(self.clone(), run);
        }
    }

    /// Registers a listener fired after the status changes.
    ///
    /// The returned [`Subscription`] unregisters it when dropped.
    pub fn subscribe(&self, listener: Arc<dyn Listener>) -> Subscription {
        self.inner.listeners.lock().push(listener.clone());
        let inner = self.inner.clone();
        Subscription::new(Box::new(move || {
            inner
                .listeners
                .lock()
                .retain(|registered| !Arc::ptr_eq(registered, &listener));
        }))
    }

    /// Stops checking. A call already sent is not recalled; its answer is
    /// dropped.
    ///
    /// Port of upstream `dispose` (`sso.ts:287-292`).
    pub fn dispose(&self) {
        self.inner.disposed.store(true, Ordering::SeqCst);
        self.inner.run.fetch_add(1, Ordering::SeqCst);
    }

    /// The configured domain, when the value was one.
    pub fn domain(&self) -> Option<&str> {
        self.inner.domain.as_deref()
    }

    fn can_check(&self) -> bool {
        self.inner.domain.is_some() && !self.inner.disposed.load(Ordering::SeqCst)
    }

    /// Bumps the run counter and returns the new run, or `None` where checking
    /// cannot start.
    fn begin(&self) -> Option<u64> {
        if !self.can_check() {
            return None;
        }
        Some(
            self.inner
                .run
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1),
        )
    }

    fn is_current(&self, run: u64) -> bool {
        run == self.inner.run.load(Ordering::SeqCst) && !self.inner.disposed.load(Ordering::SeqCst)
    }

    /// The service, built once; a build that failed is built again on the next
    /// call.
    ///
    /// Port of upstream `#serviceFor` (`sso.ts:348-358`).
    async fn service(&self) -> Result<SharedSsoDomainService, AuthClientError> {
        if let Some(service) = self.inner.service.lock().clone() {
            return Ok(service);
        }
        let create_service = self.inner.create_service.clone();
        let service = create_service.create().await?;
        *self.inner.service.lock() = Some(service.clone());
        Ok(service)
    }

    /// Replaces the status and fires the listeners when it actually changed.
    ///
    /// Port of upstream `#set` (`sso.ts:360-364`).
    fn set(&self, next: SsoStatus) {
        {
            let mut status = self.inner.status.lock();
            if *status == next {
                return;
            }
            *status = next;
        }
        let listeners: Vec<Arc<dyn Listener>> = self.inner.listeners.lock().clone();
        for listener in listeners {
            listener.call();
        }
    }

    /// Runs one check to completion: the update, then queries with backoff
    /// until a final answer arrives.
    async fn drive(self: &Arc<Self>, run: u64) {
        self.drive_steps(run, usize::MAX).await;
    }

    /// [`SsoStatusChecker::drive`] with a budget on status reads, so tests can
    /// stop inside the polling loop.
    async fn drive_steps(self: &Arc<Self>, run: u64, max_steps: usize) {
        let Some(domain) = self.inner.domain.clone() else {
            return;
        };
        let mut steps = 0;
        loop {
            if !self.is_current(run) {
                return;
            }
            let checked_at = self.inner.timer.now_ms();
            // A check that cannot be sent is swallowed: the reads below still
            // see whatever Internet Identity has, and a check that never
            // started is started again after the abandon window.
            if let Ok(service) = self.service().await {
                if !self.is_current(run) {
                    return;
                }
                let _ = service.check(&domain).await;
            }
            if !self.is_current(run) {
                return;
            }
            let mut delay = SSO_POLL_MIN_MS;
            loop {
                if !self.is_current(run) {
                    return;
                }
                if steps >= max_steps {
                    return;
                }
                steps += 1;
                let answer = match self.service().await {
                    Ok(service) if self.is_current(run) => {
                        match service.status(&domain).await {
                            Ok(status) => status_from_candid(status),
                            // A read that failed is retried at the next
                            // interval.
                            Err(_) => None,
                        }
                    }
                    _ => None,
                };
                if !self.is_current(run) {
                    return;
                }
                if let Some(status) = answer {
                    self.set(status);
                    return;
                }
                let abandon = self.inner.timer.now_ms().saturating_sub(checked_at)
                    >= self.inner.recheck_after_ms;
                self.inner.timer.sleep(Duration::from_millis(delay)).await;
                if abandon {
                    break;
                }
                delay = (delay * 2).min(SSO_POLL_MAX_MS);
            }
        }
    }
}

/// Drives the checker in the background, on whichever executor the platform
/// has: `spawn_local` in a browser, a plain thread elsewhere.
///
/// The future is created on the thread it runs on when there is one, because
/// the signer-adjacent futures this crate uses are deliberately `!Send`.
fn spawn_drive(checker: Arc<SsoStatusChecker>, run: u64) {
    #[cfg(all(target_arch = "wasm32", feature = "wasm-js"))]
    {
        wasm_bindgen_futures::spawn_local(async move {
            checker.drive(run).await;
        });
    }
    #[cfg(not(all(target_arch = "wasm32", feature = "wasm-js")))]
    {
        std::thread::spawn(move || {
            futures::executor::block_on(async move {
                checker.drive(run).await;
            });
        });
    }
}

/// The attribute keys to scope to an OpenID provider or an organization SSO.
///
/// Upstream `scopedKeys(params)` (`auth-client.ts:1921-1971`). At least one of
/// `open_id_provider` and `sso_domain` is required, and they are mutually
/// exclusive; [`scoped_keys`] reports both violations with upstream's messages.
#[derive(Debug, Clone, Default)]
pub struct ScopedKeysParams<'a> {
    /// The OpenID provider the keys should be scoped to.
    pub open_id_provider: Option<OpenIdProvider>,
    /// The organization domain the keys should be scoped to.
    pub sso_domain: Option<&'a str>,
    /// The attribute keys to scope. Defaults to the entry point's own set.
    pub keys: Option<&'a [&'a str]>,
}

impl<'a> ScopedKeysParams<'a> {
    /// Parameters for one-click OpenID sign-in.
    pub fn for_open_id_provider(provider: OpenIdProvider) -> Self {
        Self {
            open_id_provider: Some(provider),
            ..Self::default()
        }
    }

    /// Parameters for one-click SSO sign-in.
    pub fn for_sso_domain(domain: &'a str) -> Self {
        Self {
            sso_domain: Some(domain),
            ..Self::default()
        }
    }

    /// Replaces the key set.
    pub fn with_keys(mut self, keys: &'a [&'a str]) -> Self {
        self.keys = Some(keys);
        self
    }
}

/// Scopes attribute keys to an OpenID provider or to an organization's SSO.
///
/// When using one-click sign-in, attributes can be scoped to the same entry
/// point so the user grants access in a single step without an additional
/// prompt.
///
/// Port of upstream `scopedKeys` (`auth-client.ts:1921-1971`):
///
/// - OpenID: `openid:<provider-url>:<key>`, default keys
///   [`DEFAULT_OPENID_SCOPE_KEYS`];
/// - SSO: `sso:<normalized-domain>:<key>`, default keys
///   [`DEFAULT_SSO_SCOPE_KEYS`].
///
/// # Errors
///
/// [`AuthClientError::InvalidOptions`] carrying upstream's message: the two
/// entry points are mutually exclusive, at least one is required, and an SSO
/// domain must be a domain.
pub fn scoped_keys(params: ScopedKeysParams<'_>) -> Result<Vec<String>, AuthClientError> {
    if params.open_id_provider.is_some() && params.sso_domain.is_some() {
        return Err(AuthClientError::InvalidOptions(
            "openIdProvider and ssoDomain are mutually exclusive".to_string(),
        ));
    }
    if let Some(domain) = params.sso_domain {
        let domain = normalize_sso_domain(domain).map_err(AuthClientError::InvalidOptions)?;
        let keys = params.keys.unwrap_or(&DEFAULT_SSO_SCOPE_KEYS);
        return Ok(keys
            .iter()
            .map(|key| format!("sso:{domain}:{key}"))
            .collect());
    }
    let Some(provider) = params.open_id_provider else {
        return Err(AuthClientError::InvalidOptions(
            "scopedKeys requires either openIdProvider or ssoDomain".to_string(),
        ));
    };
    let keys = params.keys.unwrap_or(&DEFAULT_OPENID_SCOPE_KEYS);
    Ok(keys
        .iter()
        .map(|key| format!("openid:{}:{key}", provider.url()))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    fn normalize(domain: &str) -> Result<String, String> {
        normalize_sso_domain(domain)
    }

    #[test]
    fn accepts_domains_upstream_accepts() {
        let long_name = format!("{}org", "a.".repeat(125));
        let cases: Vec<(&str, &str)> = vec![
            ("a domain", "dfinity.org"),
            ("a domain with whitespace and capitals", "  DFINITY.org  "),
            ("an internationalized domain", "zürich.example"),
            ("a loopback host with a port", "localhost:11107"),
            ("a loopback address", "127.0.0.1"),
            ("a loopback address with a port", "127.0.0.1:8080"),
            ("a name under .localhost with a port", "app.localhost:8000"),
            ("a domain with a hyphen and digits", "sso-2.dfinity.org"),
            ("a punycode domain", "xn--zrich-kva.example"),
            ("a 253-character name", long_name.as_str()),
        ];
        let expected: Vec<&str> = vec![
            "dfinity.org",
            "dfinity.org",
            "xn--zrich-kva.example",
            "localhost:11107",
            "127.0.0.1",
            "127.0.0.1:8080",
            "app.localhost:8000",
            "sso-2.dfinity.org",
            "xn--zrich-kva.example",
            long_name.as_str(),
        ];
        for ((case, domain), expected) in cases.into_iter().zip(expected) {
            assert_eq!(
                normalize(domain).as_deref(),
                Ok(expected),
                "expected {case} to normalize"
            );
        }
    }

    #[test]
    fn rejects_domains_upstream_rejects() {
        let long_label = format!("{}.org", "a".repeat(64));
        let long_name = format!("aa.{}org", "a.".repeat(124));
        let long_authority = format!("{}.org", "a".repeat(252));
        let cases: Vec<(&str, String)> = vec![
            ("an empty domain", String::new()),
            ("a bare hostname", "dfinity".to_string()),
            (
                "a domain carrying a scheme",
                "https://dfinity.org".to_string(),
            ),
            ("a domain carrying a path", "dfinity.org/sso".to_string()),
            ("a domain carrying a query", "dfinity.org?x=1".to_string()),
            ("a domain carrying a fragment", "dfinity.org#x".to_string()),
            (
                "a domain carrying userinfo",
                "user:pw@dfinity.org".to_string(),
            ),
            (
                "a domain carrying a port",
                "sso.dfinity.org:8443".to_string(),
            ),
            (
                "a domain carrying the default port",
                "dfinity.org:443".to_string(),
            ),
            (
                "a domain carrying an empty port",
                "dfinity.org:".to_string(),
            ),
            (
                "a loopback host with an empty port",
                "localhost:".to_string(),
            ),
            (
                "a loopback host with the default port",
                "localhost:443".to_string(),
            ),
            ("a domain starting with a dot", ".org".to_string()),
            ("a domain with an empty label", "dfinity..org".to_string()),
            ("a label starting with a hyphen", "-dfinity.org".to_string()),
            ("a label ending with a hyphen", "dfinity-.org".to_string()),
            ("a label with an underscore", "df_inity.org".to_string()),
            ("a label over 63 characters", long_label),
            (
                "a label with hyphens in the third and fourth places",
                "ab--cd.org".to_string(),
            ),
            ("a name over 253 characters", long_name),
            ("a domain carrying a space", "dfinity .org".to_string()),
            ("a domain with a trailing dot", "dfinity.org.".to_string()),
            (
                "a loopback host with a trailing dot",
                "localhost.".to_string(),
            ),
            ("an authority over 255 characters", long_authority),
        ];
        for (case, domain) in cases {
            let result = normalize(&domain);
            assert!(
                result.is_err(),
                "expected {case} to be rejected: {domain:?}"
            );
        }
    }

    #[test]
    fn quotes_the_value_in_its_error_cut_to_100_characters() {
        assert_eq!(
            normalize("a\nb.org/x"),
            Err("ssoDomain \"a\\nb.org/x\" has a path".to_string())
        );
        let long = format!("{}/x", "a".repeat(300));
        assert_eq!(
            normalize(&long),
            Err(format!(
                "ssoDomain \"{}\u{2026}\" has a path and more than 255 characters",
                "a".repeat(100)
            ))
        );
    }

    #[test]
    fn names_every_problem_it_finds() {
        assert_eq!(
            normalize("https://user@acme.com:8443/sso?x=1#y"),
            Err("ssoDomain \"https://user@acme.com:8443/sso?x=1#y\" has a scheme, userinfo, a path, a query, a fragment and a port, which only loopback hosts may carry".to_string())
        );
        assert_eq!(
            normalize("-a--cd..org"),
            Err("ssoDomain \"-a--cd..org\" has an empty label, a label starting or ending with a hyphen and a label with \"--\" in its third and fourth places".to_string())
        );
    }

    #[test]
    fn reports_the_empty_value_before_parsing() {
        assert_eq!(
            normalize("   "),
            Err("ssoDomain cannot be empty".to_string())
        );
    }

    #[test]
    fn reports_a_value_the_url_parser_rejects() {
        let result = normalize("https://");
        assert!(result.is_err());
        assert!(result.unwrap_err().ends_with("is not a domain"));
    }

    #[test]
    fn a_parse_failure_is_never_a_status_error() {
        assert_eq!(
            SsoDomain::parse("dfinity"),
            SsoDomain::Invalid("ssoDomain \"dfinity\" has a single label".to_string())
        );
        assert_eq!(
            SsoDomain::parse("dfinity.org").normalized(),
            Some("dfinity.org")
        );
        assert!(matches!(SsoDomain::parse(""), SsoDomain::Invalid(_)));
    }

    #[test]
    fn maps_the_canister_status() {
        assert_eq!(
            status_from_candid(SsoDomainStatus::Available {
                name: Some("DFINITY".to_string())
            }),
            Some(SsoStatus::Available {
                name: Some("DFINITY".to_string())
            })
        );
        assert_eq!(
            status_from_candid(SsoDomainStatus::Available { name: None }),
            Some(SsoStatus::Available { name: None })
        );
        assert_eq!(status_from_candid(SsoDomainStatus::Pending), None);
        assert_eq!(
            status_from_candid(SsoDomainStatus::Unavailable {
                retry_after: Some(1_760_000_000_000_000_000),
                reason: None,
            }),
            Some(SsoStatus::Unavailable {
                retry_after_ms: Some(1_760_000_000_000),
                reason: None,
            })
        );
        assert_eq!(
            status_from_candid(SsoDomainStatus::Unavailable {
                retry_after: None,
                reason: Some("the discovery file is too large".to_string()),
            }),
            Some(SsoStatus::Unavailable {
                retry_after_ms: None,
                reason: Some("the discovery file is too large".to_string()),
            })
        );
    }

    #[test]
    fn candid_status_matches_the_upstream_idl() {
        // The canister answers `variant { Available : record { name : opt text } }`.
        let available = SsoDomainStatus::Available {
            name: Some("DFINITY".to_string()),
        };
        let bytes = candid::encode_one(&available).unwrap();
        let decoded: SsoDomainStatus = candid::decode_one(&bytes).unwrap();
        assert_eq!(decoded, available);

        // `Pending` is a nullary variant.
        let bytes = candid::encode_one(&SsoDomainStatus::Pending).unwrap();
        let decoded: SsoDomainStatus = candid::decode_one(&bytes).unwrap();
        assert_eq!(decoded, SsoDomainStatus::Pending);

        // `Unavailable : record { retry_after : opt nat64; reason : opt text }`.
        let unavailable = SsoDomainStatus::Unavailable {
            retry_after: Some(1_760_000_000_000_000_000),
            reason: Some("not yet".to_string()),
        };
        let bytes = candid::encode_one(&unavailable).unwrap();
        let decoded: SsoDomainStatus = candid::decode_one(&bytes).unwrap();
        assert_eq!(decoded, unavailable);

        // The wire type really is the variant upstream's inline IDL writes, not
        // a record standing in for one.
        let candid_type = <SsoDomainStatus as CandidType>::ty().to_string();
        assert!(
            candid_type.contains("Available : record { name : opt text }"),
            "{candid_type}"
        );
        assert!(
            candid_type
                .contains("Unavailable : record { retry_after : opt nat64; reason : opt text }"),
            "{candid_type}"
        );
        assert!(candid_type.contains("Pending;"), "{candid_type}");
    }

    #[test]
    fn scoped_keys_defaults_to_the_openid_key_set() {
        assert_eq!(
            scoped_keys(ScopedKeysParams::for_open_id_provider(
                OpenIdProvider::Google
            ))
            .unwrap(),
            vec![
                "openid:https://accounts.google.com:name",
                "openid:https://accounts.google.com:email",
                "openid:https://accounts.google.com:verified_email",
            ]
        );
    }

    #[test]
    fn scoped_keys_takes_the_given_openid_keys() {
        assert_eq!(
            scoped_keys(
                ScopedKeysParams::for_open_id_provider(OpenIdProvider::Apple).with_keys(&["email"])
            )
            .unwrap(),
            vec!["openid:https://appleid.apple.com:email"]
        );
    }

    #[test]
    fn scoped_keys_defaults_to_the_sso_key_set() {
        assert_eq!(
            scoped_keys(ScopedKeysParams::for_sso_domain("dfinity.org")).unwrap(),
            vec!["sso:dfinity.org:name", "sso:dfinity.org:email"]
        );
    }

    #[test]
    fn scoped_keys_takes_the_given_sso_keys() {
        assert_eq!(
            scoped_keys(ScopedKeysParams::for_sso_domain("dfinity.org").with_keys(&["email"]))
                .unwrap(),
            vec!["sso:dfinity.org:email"]
        );
    }

    #[test]
    fn scoped_keys_normalizes_the_sso_domain() {
        assert_eq!(
            scoped_keys(ScopedKeysParams::for_sso_domain(" DFINITY.org ").with_keys(&["email"]))
                .unwrap(),
            vec!["sso:dfinity.org:email"]
        );
        assert_eq!(
            scoped_keys(ScopedKeysParams::for_sso_domain("zürich.example").with_keys(&["email"]))
                .unwrap(),
            vec!["sso:xn--zrich-kva.example:email"]
        );
    }

    #[test]
    fn scoped_keys_reports_a_domain_that_is_not_one() {
        let error = scoped_keys(ScopedKeysParams::for_sso_domain("dfinity.org/sso")).unwrap_err();
        assert_eq!(
            error.kind(),
            crate::client::AuthClientErrorKind::InvalidOptions
        );
        assert_eq!(
            error.to_string(),
            "invalid options: ssoDomain \"dfinity.org/sso\" has a path"
        );
    }

    #[test]
    fn scoped_keys_requires_one_entry_point() {
        let error = scoped_keys(ScopedKeysParams::default()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid options: scopedKeys requires either openIdProvider or ssoDomain"
        );
    }

    #[test]
    fn scoped_keys_refuses_both_entry_points() {
        let params = ScopedKeysParams {
            open_id_provider: Some(OpenIdProvider::Google),
            sso_domain: Some("dfinity.org"),
            keys: None,
        };
        let error = scoped_keys(params).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid options: openIdProvider and ssoDomain are mutually exclusive"
        );
    }

    // --- SsoStatusChecker -------------------------------------------------

    struct FakeTimer {
        now_ms: AtomicU64,
        sleeps_ms: Mutex<Vec<u64>>,
    }

    impl FakeTimer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now_ms: AtomicU64::new(0),
                sleeps_ms: Mutex::new(Vec::new()),
            })
        }

        fn sleeps(&self) -> Vec<u64> {
            self.sleeps_ms.lock().clone()
        }
    }

    #[async_trait(?Send)]
    impl SsoTimer for FakeTimer {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }

        async fn sleep(&self, duration: Duration) {
            let millis = duration.as_millis() as u64;
            self.sleeps_ms.lock().push(millis);
            self.now_ms.fetch_add(millis, Ordering::SeqCst);
        }
    }

    struct FakeService {
        answers: Mutex<VecDeque<Result<SsoDomainStatus, String>>>,
        last: Mutex<SsoDomainStatus>,
        checks: AtomicUsize,
        reads: AtomicUsize,
        fail_check: AtomicBool,
    }

    impl FakeService {
        fn new(answers: Vec<SsoDomainStatus>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers.into_iter().map(Ok).collect()),
                last: Mutex::new(SsoDomainStatus::Pending),
                checks: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                fail_check: AtomicBool::new(false),
            })
        }

        fn answer(&self, next: SsoDomainStatus) {
            let mut answers = self.answers.lock();
            answers.clear();
            answers.push_back(Ok(next));
        }

        fn fail_one_read(&self) {
            self.answers.lock().push_front(Err("offline".to_string()));
        }
    }

    #[async_trait(?Send)]
    impl SsoDomainService for FakeService {
        async fn check(&self, _domain: &str) -> Result<(), AuthClientError> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            if self.fail_check.load(Ordering::SeqCst) {
                return Err(AuthClientError::Agent("rejected".to_string()));
            }
            Ok(())
        }

        async fn status(&self, _domain: &str) -> Result<SsoDomainStatus, AuthClientError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            match self.answers.lock().pop_front() {
                Some(Ok(status)) => {
                    *self.last.lock() = status.clone();
                    Ok(status)
                }
                Some(Err(error)) => Err(AuthClientError::Agent(error)),
                None => Ok(self.last.lock().clone()),
            }
        }
    }

    fn factory_for(service: Arc<FakeService>) -> SsoServiceFactory {
        let factory = move || -> SsoServiceFuture {
            let service = service.clone();
            Box::pin(async move { Ok(service as SharedSsoDomainService) })
        };
        Arc::new(factory)
    }

    fn checker(service: Arc<FakeService>, timer: Arc<FakeTimer>) -> Arc<SsoStatusChecker> {
        Arc::new(SsoStatusChecker::with_timer(
            SsoDomain::Valid("dfinity.org".to_string()),
            factory_for(service),
            timer,
            SSO_RECHECK_AFTER_MS,
        ))
    }

    fn drive(checker: &Arc<SsoStatusChecker>, run: u64, steps: usize) {
        futures::executor::block_on(checker.drive_steps(run, steps));
    }

    #[test]
    fn checks_once_when_started_then_reads_the_status() {
        let service = FakeService::new(vec![SsoDomainStatus::Available {
            name: Some("DFINITY".to_string()),
        }]);
        let timer = FakeTimer::new();
        let checker = checker(service.clone(), timer);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = fired.clone();
        let _subscription = checker.subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        assert_eq!(checker.status(), SsoStatus::Checking);
        let run = checker.begin().expect("a valid domain can check");
        drive(&checker, run, 1);

        assert_eq!(service.checks.load(Ordering::SeqCst), 1);
        assert_eq!(service.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            checker.status(),
            SsoStatus::Available {
                name: Some("DFINITY".to_string())
            }
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reports_available_without_a_name_when_the_organization_publishes_none() {
        let service = FakeService::new(vec![SsoDomainStatus::Available { name: None }]);
        let checker = checker(service, FakeTimer::new());
        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert_eq!(checker.status(), SsoStatus::Available { name: None });
    }

    #[test]
    fn reports_unavailable_with_the_time_internet_identity_fetches_again() {
        let retry_at_ms = 1_760_000_000_000u64;
        let service = FakeService::new(vec![SsoDomainStatus::Unavailable {
            retry_after: Some(retry_at_ms * 1_000_000),
            reason: None,
        }]);
        let checker = checker(service, FakeTimer::new());
        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert_eq!(
            checker.status(),
            SsoStatus::Unavailable {
                retry_after_ms: Some(retry_at_ms),
                reason: None
            }
        );
    }

    #[test]
    fn reports_the_reason_internet_identity_gives_for_unavailable() {
        let service = FakeService::new(vec![SsoDomainStatus::Unavailable {
            retry_after: None,
            reason: Some("the discovery file is too large".to_string()),
        }]);
        let checker = checker(service, FakeTimer::new());
        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert_eq!(
            checker.status(),
            SsoStatus::Unavailable {
                retry_after_ms: None,
                reason: Some("the discovery file is too large".to_string()),
            }
        );
    }

    #[test]
    fn polls_with_backoff_while_the_answer_is_pending_and_checks_only_once() {
        let service = FakeService::new(vec![
            SsoDomainStatus::Pending,
            SsoDomainStatus::Pending,
            SsoDomainStatus::Pending,
            SsoDomainStatus::Pending,
            SsoDomainStatus::Available { name: None },
        ]);
        let timer = FakeTimer::new();
        let checker = checker(service.clone(), timer.clone());
        let run = checker.begin().unwrap();
        drive(&checker, run, 5);

        assert_eq!(timer.sleeps(), vec![500, 1_000, 2_000, 2_000]);
        assert_eq!(service.reads.load(Ordering::SeqCst), 5);
        assert_eq!(service.checks.load(Ordering::SeqCst), 1);
        assert_eq!(checker.status(), SsoStatus::Available { name: None });
    }

    #[test]
    fn keeps_checking_while_pending_and_fires_no_listener() {
        let service = FakeService::new(Vec::new());
        let timer = FakeTimer::new();
        let checker = checker(service.clone(), timer);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = fired.clone();
        let _subscription = checker.subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let run = checker.begin().unwrap();
        drive(&checker, run, 4);
        assert_eq!(checker.status(), SsoStatus::Checking);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(service.checks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn checks_again_once_the_answer_has_been_pending_for_the_abandon_window() {
        let service = FakeService::new(Vec::new());
        let timer = FakeTimer::new();
        let checker = Arc::new(SsoStatusChecker::with_timer(
            SsoDomain::Valid("dfinity.org".to_string()),
            factory_for(service.clone()),
            timer,
            10_000,
        ));
        let run = checker.begin().unwrap();
        drive(&checker, run, 10);
        assert_eq!(service.checks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retries_a_status_read_that_failed_at_the_next_interval() {
        let service = FakeService::new(vec![SsoDomainStatus::Available { name: None }]);
        service.fail_one_read();
        let checker = checker(service.clone(), FakeTimer::new());
        let run = checker.begin().unwrap();
        drive(&checker, run, 2);
        assert_eq!(checker.status(), SsoStatus::Available { name: None });
    }

    #[test]
    fn still_reads_the_status_when_the_check_update_fails() {
        let service = FakeService::new(vec![SsoDomainStatus::Available { name: None }]);
        service.fail_check.store(true, Ordering::SeqCst);
        let checker = checker(service, FakeTimer::new());
        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert_eq!(checker.status(), SsoStatus::Available { name: None });
    }

    #[test]
    fn builds_the_service_again_when_building_it_failed() {
        let service = FakeService::new(vec![SsoDomainStatus::Available { name: None }]);
        let fail = Arc::new(AtomicBool::new(true));
        let factory: SsoServiceFactory = {
            let service = service.clone();
            let fail = fail.clone();
            let factory = move || -> SsoServiceFuture {
                let service = service.clone();
                let failed = fail.swap(false, Ordering::SeqCst);
                Box::pin(async move {
                    if failed {
                        Err(AuthClientError::Agent("no agent".to_string()))
                    } else {
                        Ok(service as SharedSsoDomainService)
                    }
                })
            };
            Arc::new(factory)
        };
        let checker = Arc::new(SsoStatusChecker::with_timer(
            SsoDomain::Valid("dfinity.org".to_string()),
            factory,
            FakeTimer::new(),
            SSO_RECHECK_AFTER_MS,
        ));
        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert_eq!(checker.status(), SsoStatus::Available { name: None });
    }

    #[test]
    fn a_value_that_is_not_a_domain_is_invalid_and_never_calls() {
        let service = FakeService::new(Vec::new());
        let reason = "ssoDomain \"x\" has a path".to_string();
        let checker = Arc::new(SsoStatusChecker::with_timer(
            SsoDomain::Invalid(reason.clone()),
            factory_for(service.clone()),
            FakeTimer::new(),
            SSO_RECHECK_AFTER_MS,
        ));
        assert_eq!(checker.status(), SsoStatus::Invalid { reason });
        checker.start();
        checker.refresh();
        assert!(checker.begin().is_none());
        assert_eq!(service.checks.load(Ordering::SeqCst), 0);
        assert_eq!(service.reads.load(Ordering::SeqCst), 0);
        assert!(matches!(checker.status(), SsoStatus::Invalid { .. }));
    }

    #[test]
    fn refresh_checks_again_through_checking() {
        let service = FakeService::new(vec![SsoDomainStatus::Unavailable {
            retry_after: None,
            reason: None,
        }]);
        let checker = checker(service.clone(), FakeTimer::new());
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = fired.clone();
        let _subscription = checker.subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert!(matches!(checker.status(), SsoStatus::Unavailable { .. }));

        service.answer(SsoDomainStatus::Available { name: None });
        // `refresh` and the test's run bump share `begin`, so drive the same
        // way the public entry point would.
        checker.set(SsoStatus::Checking);
        let run = checker.begin().unwrap();
        assert_eq!(checker.status(), SsoStatus::Checking);
        drive(&checker, run, 1);
        assert_eq!(checker.status(), SsoStatus::Available { name: None });
        assert_eq!(service.checks.load(Ordering::SeqCst), 2);
        assert_eq!(fired.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn dispose_stops_a_run_and_drops_its_answer() {
        let service = FakeService::new(vec![SsoDomainStatus::Available { name: None }]);
        let checker = checker(service.clone(), FakeTimer::new());
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = fired.clone();
        let _subscription = checker.subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let run = checker.begin().unwrap();
        checker.dispose();
        drive(&checker, run, 10);
        assert_eq!(service.checks.load(Ordering::SeqCst), 0);
        assert_eq!(service.reads.load(Ordering::SeqCst), 0);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(checker.status(), SsoStatus::Checking);
    }

    #[test]
    fn ignores_refresh_once_disposed() {
        let service = FakeService::new(Vec::new());
        let checker = checker(service.clone(), FakeTimer::new());
        checker.dispose();
        checker.refresh();
        assert!(checker.begin().is_none());
        assert_eq!(service.checks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn keeps_the_same_status_value_until_the_answer_changes() {
        let service = FakeService::new(Vec::new());
        let checker = checker(service.clone(), FakeTimer::new());
        let run = checker.begin().unwrap();
        drive(&checker, run, 3);
        assert_eq!(checker.status(), SsoStatus::Checking);

        service.answer(SsoDomainStatus::Available {
            name: Some("DFINITY".to_string()),
        });
        drive(&checker, run, 1);
        assert_eq!(
            checker.status(),
            SsoStatus::Available {
                name: Some("DFINITY".to_string())
            }
        );
    }

    #[test]
    fn the_canister_service_refuses_a_host_that_is_not_a_url() {
        let canister = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let error = CanisterSsoDomainService::new(canister, "not a url").unwrap_err();
        assert_eq!(error.kind(), crate::client::AuthClientErrorKind::Agent);
    }

    #[cfg(feature = "native")]
    #[test]
    fn the_checker_is_send_and_sync_on_native() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SsoStatusChecker>();
        assert_send_sync::<Arc<SsoStatusChecker>>();
        assert_send_sync::<SsoDomain>();
        assert_send_sync::<SsoDomainStatus>();
    }

    #[test]
    fn subscription_unregisters_on_drop() {
        let service = FakeService::new(vec![SsoDomainStatus::Available { name: None }]);
        let checker = checker(service, FakeTimer::new());
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = fired.clone();
        let subscription = checker.subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        drop(subscription);
        let run = checker.begin().unwrap();
        drive(&checker, run, 1);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }
}
