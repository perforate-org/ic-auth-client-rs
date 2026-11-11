//! Signing in from a non-browser client, without a hosted bridge page.
//!
//! Internet Identity serves a first-party flow for clients that are not web
//! pages (CLIs, desktop apps, anything holding a key outside a browser). It is
//! the flow `icp-cli`'s `icp identity link web` uses, and it removes the need
//! for the `ii-bridge` page this crate used to ship: the identity provider's own
//! page completes the ceremony and hands a delegation to a loopback listener.
//!
//! # Protocol (as implemented by `id.ai` and `icp-cli`)
//!
//! 1. **Discovery.** `GET {auth}/.well-known/cli-auth-config` answers
//!    `{"path":"/cli"}`. The path is the sign-in route at the auth origin.
//! 2. **Request.** The client binds `http://127.0.0.1:<ephemeral>/` and opens
//!    `{auth}{path}#public_key=<b64url DER>&callback=<loopback>&nonce=<b64url>[&domain=<app>][&ttl=<minutes>]`.
//!    The fragment is read by the page only; it never reaches the server and
//!    holds the single-use nonce that proves the POST came from that page.
//! 3. **Sign-in.** The provider authenticates the user, mints a delegation for
//!    the client's public key (a two-hop chain rooted at the user's key when the
//!    provider sub-delegates from its own ephemeral key), and submits it to the
//!    loopback callback as a **top-level form POST** with `delegation`
//!    (`DelegationChain.toJSON()`) and `nonce` fields. A top-level navigation,
//!    not `fetch`, because browsers gate public-origin -> loopback subresource
//!    requests (Chrome's Local Network Access prompt).
//! 4. **Answer.** The loopback server checks the nonce and the chain and
//!    redirects the browser back to `{auth}{path}#status=success` (or `error`),
//!    so the provider's page owns the outcome UI.
//!
//! # Differences from the browser sign-in
//!
//! The flow yields **one delegation chain rooted at the user's key** — the
//! provider's account delegation — not the v11 *session chain* (restricted to
//! the identity canister) that the browser flow's signer channel issues. It
//! therefore cannot seed the two-level session model (`app_prepare_delegation`
//! and rotation need a session chain), and this crate uses the chain directly as
//! the client credential on native. Two consequences worth documenting for
//! callers:
//!
//! - `ttl` bounds the sign-in (minutes, provider default 480); there is no
//!   canister-side revocation for it.
//! - The provider's own screen chooses the access level and defaults to
//!   **read-only** (query calls only); a user who needs update calls must pick
//!   full access there.
//!
//! Signing in "as an app" (the `domain` fragment parameter, called `app_origin`
//! here) requires the user to have enabled CLI access for that identity in the
//! provider's settings; without it the provider shows a "CLI access not enabled"
//! screen and this flow times out.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

use crate::client::base64::base64_url_no_pad;
use crate::client::platform::PlatformBounds;
use crate::delegation_chain::DelegationChain;

/// Where the auth origin publishes the sign-in route for non-browser clients.
pub const CLI_AUTH_CONFIG_PATH: &str = "/.well-known/cli-auth-config";

/// The provider's default delegation lifetime, in minutes.
pub const DEFAULT_TTL_MINUTES: u32 = 480;

/// The longest lifetime this client will ask for or accept, in minutes.
///
/// The provider decides what it grants, so this is a bound on what a
/// *compromised provider page* --- or one that answers with something other than
/// what was asked --- can hand back.
pub const MAX_TTL_MINUTES: u32 = 1_440;

/// The most hops this flow accepts in a delegation chain.
///
/// The provider's own CLI flow produces one or two (an app delegation rides on a
/// prepared account delegation); anything longer is not the ceremony this client
/// started.
pub const MAX_CHAIN_HOPS: usize = 4;

/// How far past the requested lifetime a chain may reach, in seconds: clock
/// skew between this device and the provider.
const TTL_SKEW_SECONDS: u64 = 300;

/// The largest form body the loopback server will read.
const MAX_BODY_BYTES: u64 = 1 << 20;

/// How long the flow waits for the user to finish signing in.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// The path a provider publishes for the flow.
#[derive(Debug, Clone, Deserialize)]
pub struct CliAuthConfig {
    /// The sign-in route below the auth origin, e.g. `/cli`.
    pub path: String,
}

/// What to ask the identity provider for.
#[derive(Debug, Clone)]
pub struct WebAuthOptions {
    /// The auth origin, e.g. `https://id.ai`.
    pub auth_origin: String,
    /// The app origin to derive a principal for (`domain`), or `None` for the
    /// provider's generic CLI identity.
    pub app_origin: Option<String>,
    /// The requested lifetime, in minutes. `None` leaves the provider's default.
    pub ttl_minutes: Option<u32>,
    /// How long to wait for the user.
    pub timeout: Duration,
}

impl Default for WebAuthOptions {
    fn default() -> Self {
        Self {
            auth_origin: "https://id.ai".to_string(),
            app_origin: None,
            ttl_minutes: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// Opens a URL in the user's browser.
pub trait BrowserOpener: Send + Sync {
    /// Opens `url`, returning why it could not when it could not.
    fn open(&self, url: &str) -> Result<(), String>;
}

/// Fetches a provider's discovery document.
pub trait DiscoveryFetcher: Send + Sync {
    /// Fetches and parses `url` as a [`CliAuthConfig`].
    fn fetch(&self, url: &str) -> Result<CliAuthConfig, String>;
}

/// Acquires the delegation, as the client drives it.
///
/// The default runs the flow over the system browser; supplying another lets a
/// caller (or a test) complete it differently --- a custom scheme, an embedded
/// webview, a remote signer.
#[async_trait::async_trait(?Send)]
pub trait WebAuthRunner: PlatformBounds {
    /// Acquires a delegation for `session_public_key_der`.
    async fn acquire(
        &self,
        session_public_key_der: &[u8],
        options: WebAuthOptions,
    ) -> Result<DelegationChain, WebAuthError>;
}

/// The default runner: the system browser and the network.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWebAuthRunner;

#[async_trait::async_trait(?Send)]
impl WebAuthRunner for SystemWebAuthRunner {
    async fn acquire(
        &self,
        session_public_key_der: &[u8],
        options: WebAuthOptions,
    ) -> Result<DelegationChain, WebAuthError> {
        acquire_delegation(session_public_key_der, options).await
    }
}

/// Everything the web-auth flow can fail with.
#[derive(Debug, Error)]
pub enum WebAuthError {
    /// The auth origin does not publish a usable `cli-auth-config`.
    #[error("cli-auth discovery failed: {0}")]
    Discovery(String),
    /// The published login path is empty or not a path.
    #[error("`{url}` published an unusable login path: `{path}`")]
    InvalidLoginPath {
        /// The discovery URL.
        url: String,
        /// What it published.
        path: String,
    },
    /// The loopback server could not start.
    #[error("could not start the loopback callback server: {0}")]
    Server(String),
    /// The browser could not be opened.
    #[error("could not open the browser: {0}")]
    OpenBrowser(String),
    /// Nobody finished signing in in time.
    #[error("timed out waiting for the identity provider")]
    TimedOut,
    /// The provider sent back something that is not a delegation.
    #[error("the identity provider sent an invalid delegation: {0}")]
    InvalidDelegation(String),
    /// The delegation does not authorise the key this client asked for.
    #[error("the delegation does not authorise the requested public key")]
    WrongKey,
}

/// Opens the browser: `open` on macOS, `xdg-open` on Linux, `start` on Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> Result<(), String> {
        webbrowser::open(url)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Fetches discovery over HTTPS.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpDiscovery;

impl DiscoveryFetcher for HttpDiscovery {
    fn fetch(&self, url: &str) -> Result<CliAuthConfig, String> {
        let response = reqwest::blocking::get(url).map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("{} answered {}", url, response.status()));
        }
        response.json().map_err(|error| error.to_string())
    }
}

/// Runs the whole flow on the calling thread: discovery, loopback server,
/// browser, form POST, validation.
///
/// Split from [`acquire_delegation`] so tests can drive it with a fake browser
/// and a fake discovery document without a browser or the network.
pub fn acquire_delegation_blocking(
    session_public_key_der: &[u8],
    options: &WebAuthOptions,
    opener: &dyn BrowserOpener,
    fetcher: &dyn DiscoveryFetcher,
) -> Result<DelegationChain, WebAuthError> {
    let auth_origin = options.auth_origin.trim_end_matches('/').to_string();
    let discovery_url = format!("{auth_origin}{CLI_AUTH_CONFIG_PATH}");
    let config = fetcher
        .fetch(&discovery_url)
        .map_err(WebAuthError::Discovery)?;
    let login_path = config.path.trim();
    if login_path.is_empty() || !login_path.starts_with('/') {
        return Err(WebAuthError::InvalidLoginPath {
            url: discovery_url,
            path: config.path,
        });
    }

    let nonce = base64_url_no_pad(&random_nonce());
    let public_key = base64_url_no_pad(session_public_key_der);
    // Clamped here rather than trusted from the caller: everything downstream
    // (the URL, and the expiry bound the answer is checked against) uses this.
    let ttl_minutes = effective_ttl(options.ttl_minutes);

    let server = tiny_http::Server::http("127.0.0.1:0")
        .map_err(|error| WebAuthError::Server(error.to_string()))?;
    let port = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| WebAuthError::Server("server bound to a non-IP address".to_string()))?
        .port();
    let callback = format!("http://127.0.0.1:{port}/");

    let login_url = build_login_url(
        &auth_origin,
        login_path,
        &public_key,
        &callback,
        &nonce,
        options.app_origin.as_deref(),
        Some(ttl_minutes),
    );
    opener.open(&login_url).map_err(WebAuthError::OpenBrowser)?;

    serve(
        server,
        options.timeout,
        &nonce,
        session_public_key_der,
        &auth_origin,
        login_path,
        ttl_minutes,
    )
}

/// The lifetime to ask for: the provider's default when none was asked for,
/// bounded so a caller cannot request (or be handed) an unbounded session.
fn effective_ttl(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_TTL_MINUTES)
        .clamp(1, MAX_TTL_MINUTES)
}

/// Compares two strings without leaking where they differ.
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

/// Builds the URL the browser is opened at, with the request in the fragment.
fn build_login_url(
    auth_origin: &str,
    login_path: &str,
    public_key_b64: &str,
    callback: &str,
    nonce: &str,
    app_origin: Option<&str>,
    ttl_minutes: Option<u32>,
) -> String {
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    pairs
        .append_pair("public_key", public_key_b64)
        .append_pair("callback", callback)
        .append_pair("nonce", nonce);
    if let Some(origin) = app_origin {
        pairs.append_pair("domain", origin);
    }
    if let Some(ttl) = ttl_minutes {
        pairs.append_pair("ttl", &ttl.to_string());
    }
    format!("{auth_origin}{login_path}#{}", pairs.finish())
}

/// Waits for the identity provider's POST, answers the browser, returns the
/// chain.
fn serve(
    server: tiny_http::Server,
    timeout: Duration,
    expected_nonce: &str,
    session_public_key_der: &[u8],
    auth_origin: &str,
    login_path: &str,
    ttl_minutes: u32,
) -> Result<DelegationChain, WebAuthError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(WebAuthError::TimedOut);
        }
        let Some(mut request) = server
            .recv_timeout(remaining)
            .map_err(|error| WebAuthError::Server(error.to_string()))?
        else {
            return Err(WebAuthError::TimedOut);
        };

        // Anything else on this loopback port is not the provider answering this
        // flow: answer 404 and keep waiting.
        if request.method() != &tiny_http::Method::Post {
            let _ = request.respond(tiny_http::Response::empty(404));
            continue;
        }

        // The provider posts a form; anything else on this port is not the
        // answer this flow is waiting for.
        let content_type = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Content-Type"))
            .map(|header| header.value.as_str().to_owned());
        if let Some(content_type) = content_type
            && !content_type.starts_with("application/x-www-form-urlencoded")
        {
            let _ = request.respond(tiny_http::Response::empty(415));
            continue;
        }

        // Read with a bound rather than to end: this port is open to anything on
        // the machine while the flow runs.
        let mut body_bytes = Vec::new();
        let mut buffer = [0u8; 8 * 1024];
        let mut too_large = false;
        {
            let reader = request.as_reader();
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if body_bytes.len() as u64 + read as u64 > MAX_BODY_BYTES {
                            too_large = true;
                            break;
                        }
                        body_bytes.extend_from_slice(&buffer[..read]);
                    }
                    Err(_) => break,
                }
            }
        }
        if too_large {
            // Larger than any answer this flow produces: refused rather than
            // parsed.
            let _ = request.respond(tiny_http::Response::empty(413));
            continue;
        }
        let Ok(body) = String::from_utf8(body_bytes) else {
            let _ = request.respond(tiny_http::Response::empty(400));
            continue;
        };
        let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();

        // The nonce proves the POST came from the page this flow opened, and is
        // compared without leaking where a guess differed.
        if !form.get("nonce").is_some_and(|provided| {
            constant_time_eq(provided.as_bytes(), expected_nonce.as_bytes())
        }) {
            let _ = request.respond(tiny_http::Response::empty(400).with_header(
                tiny_http::Header::from_bytes("Content-Type", "text/plain").expect("static header"),
            ));
            continue;
        }

        let outcome = form
            .get("delegation")
            .ok_or_else(|| WebAuthError::InvalidDelegation("no `delegation` field".to_string()))
            .and_then(|json| {
                let chain = DelegationChain::from_js_json(json)
                    .map_err(|error| WebAuthError::InvalidDelegation(error.to_string()))?;
                validate_chain(&chain, session_public_key_der, ttl_minutes)?;
                Ok(chain)
            });

        // Answer the browser before returning: the provider's page shows the
        // outcome from this redirect, and a dropped connection would leave it
        // hanging.
        let status = if outcome.is_ok() { "success" } else { "error" };
        let location = format!("{auth_origin}{login_path}#status={status}");
        let response = tiny_http::Response::empty(303).with_header(
            tiny_http::Header::from_bytes("Location", location.as_bytes())
                .expect("a URL is a valid header value"),
        );
        let _ = request.respond(response);

        return outcome;
    }
}

/// Checks the shape this crate is willing to act with: a live chain that
/// terminates at the key that asked for it, reaches no further than the lifetime
/// it was asked for, and is not its own root.
fn validate_chain(
    chain: &DelegationChain,
    session_public_key_der: &[u8],
    ttl_minutes: u32,
) -> Result<(), WebAuthError> {
    if chain.delegations.is_empty() {
        return Err(WebAuthError::InvalidDelegation(
            "the chain has no delegations".to_string(),
        ));
    }
    if chain.delegations.len() > MAX_CHAIN_HOPS {
        return Err(WebAuthError::InvalidDelegation(format!(
            "the chain has {} hops, more than the {MAX_CHAIN_HOPS} this flow accepts",
            chain.delegations.len()
        )));
    }
    if chain.public_key.is_empty() {
        return Err(WebAuthError::InvalidDelegation(
            "the chain names no root key".to_string(),
        ));
    }
    if !chain.is_delegation_valid(None) {
        return Err(WebAuthError::InvalidDelegation(
            "the chain has expired".to_string(),
        ));
    }
    let leaf = chain
        .delegations
        .last()
        .map(|signed| signed.delegation.pubkey.as_slice())
        .unwrap_or_default();
    if leaf != session_public_key_der {
        return Err(WebAuthError::WrongKey);
    }
    // A chain rooted at its own leaf is signed by the key it delegates to: it
    // proves nothing about who the user is.
    if chain.public_key == leaf {
        return Err(WebAuthError::InvalidDelegation(
            "the chain is rooted at the key it delegates to".to_string(),
        ));
    }

    // The provider decides what to grant; this bounds what it may hand back. The
    // skew allowance covers clock drift between this device and the provider.
    let cap = crate::client::now::now_ns()
        .saturating_add((u64::from(ttl_minutes) * 60 + TTL_SKEW_SECONDS) * 1_000_000_000);
    for (index, signed) in chain.delegations.iter().enumerate() {
        if signed.delegation.expiration > cap {
            return Err(WebAuthError::InvalidDelegation(format!(
                "delegation {index} outlives the {ttl_minutes} minute lifetime it was requested with"
            )));
        }
    }
    Ok(())
}

/// 32 random bytes for the single-use nonce.
fn random_nonce() -> [u8; 32] {
    use rand::Rng as _;
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Runs the flow without blocking the caller's executor.
pub async fn acquire_delegation(
    session_public_key_der: &[u8],
    options: WebAuthOptions,
) -> Result<DelegationChain, WebAuthError> {
    let public_key = session_public_key_der.to_vec();
    let (sender, receiver) = futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let result =
            acquire_delegation_blocking(&public_key, &options, &SystemBrowser, &HttpDiscovery);
        let _ = sender.send(result);
    });
    receiver
        .await
        .map_err(|_| WebAuthError::Server("the web-auth thread panicked".to_string()))?
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use ic_agent::identity::{BasicIdentity, Delegation, Identity as _};

    use super::*;

    struct OkDiscovery;
    impl DiscoveryFetcher for OkDiscovery {
        fn fetch(&self, _url: &str) -> Result<CliAuthConfig, String> {
            Ok(CliAuthConfig {
                path: "/cli".to_string(),
            })
        }
    }

    struct FailingDiscovery;
    impl DiscoveryFetcher for FailingDiscovery {
        fn fetch(&self, url: &str) -> Result<CliAuthConfig, String> {
            Err(format!("no config at {url}"))
        }
    }

    struct EmptyPathDiscovery;
    impl DiscoveryFetcher for EmptyPathDiscovery {
        fn fetch(&self, _url: &str) -> Result<CliAuthConfig, String> {
            Ok(CliAuthConfig {
                path: "  ".to_string(),
            })
        }
    }

    struct NoBrowser;
    impl BrowserOpener for NoBrowser {
        fn open(&self, _url: &str) -> Result<(), String> {
            Err("no browser here".to_string())
        }
    }

    /// A browser stand-in: it posts a delegation to the callback it was given,
    /// exactly as the provider's page would.
    struct PostingBrowser {
        chain_json: String,
        nonce_bad: bool,
        opened: AtomicUsize,
        seen: Mutex<Vec<String>>,
    }

    impl PostingBrowser {
        fn new(chain: &DelegationChain) -> Self {
            Self {
                chain_json: chain.to_js_json(),
                nonce_bad: false,
                opened: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn with_bad_nonce(chain: &DelegationChain) -> Self {
            let mut browser = Self::new(chain);
            browser.nonce_bad = true;
            browser
        }
    }

    impl BrowserOpener for PostingBrowser {
        fn open(&self, url: &str) -> Result<(), String> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(url.to_string());

            let fragment = url
                .split_once('#')
                .map(|(_, fragment)| fragment)
                .unwrap_or("");
            let params: HashMap<String, String> = url::form_urlencoded::parse(fragment.as_bytes())
                .into_owned()
                .collect();
            let callback = params.get("callback").cloned().unwrap_or_default();
            let nonce = if self.nonce_bad {
                "not-the-nonce".to_string()
            } else {
                params.get("nonce").cloned().unwrap_or_default()
            };
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("delegation", &self.chain_json)
                .append_pair("nonce", &nonce)
                .finish();

            // A real browser does not block the caller: it navigates, and the
            // form POST arrives while the flow is already waiting for it.
            std::thread::spawn(move || {
                // A real top-level form POST: follow no redirects, just deliver.
                let client = reqwest::blocking::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .expect("client");
                let response = client
                    .post(&callback)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .expect("post to the loopback server");
                assert_eq!(response.status().as_u16(), 303);
            });
            Ok(())
        }
    }

    /// A browser that never posts anything, so the flow must time out.
    struct SilentBrowser;
    impl BrowserOpener for SilentBrowser {
        fn open(&self, _url: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn chain_for(leaf: &[u8]) -> DelegationChain {
        let account = BasicIdentity::from_raw_key(&[7u8; 32]);
        let delegation = Delegation {
            pubkey: leaf.to_vec(),
            expiration: now_ns() + 60 * 60 * 1_000_000_000,
            targets: None,
            permissions: None,
        };
        let signature = account.sign_delegation(&delegation).unwrap();
        DelegationChain {
            delegations: vec![ic_agent::identity::SignedDelegation {
                delegation,
                signature: signature.signature.unwrap(),
            }],
            public_key: account.public_key().unwrap(),
        }
    }

    fn now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn options() -> WebAuthOptions {
        WebAuthOptions {
            auth_origin: "https://id.ai".to_string(),
            app_origin: Some("https://app.example.com".to_string()),
            ttl_minutes: Some(60),
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn login_url_carries_the_request_in_the_fragment() {
        let url = build_login_url(
            "https://id.ai",
            "/cli",
            "PUBKEY",
            "http://127.0.0.1:1234/",
            "NONCE",
            Some("https://app.example.com"),
            Some(60),
        );
        assert!(url.starts_with("https://id.ai/cli#"));
        let fragment = url.split_once('#').unwrap().1;
        let params: HashMap<String, String> = url::form_urlencoded::parse(fragment.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(params.get("public_key").unwrap(), "PUBKEY");
        assert_eq!(params.get("callback").unwrap(), "http://127.0.0.1:1234/");
        assert_eq!(params.get("nonce").unwrap(), "NONCE");
        assert_eq!(params.get("domain").unwrap(), "https://app.example.com");
        assert_eq!(params.get("ttl").unwrap(), "60");
    }

    #[test]
    fn login_url_omits_the_optional_parameters() {
        let url = build_login_url(
            "https://id.ai",
            "/cli",
            "PUBKEY",
            "http://127.0.0.1:1/",
            "NONCE",
            None,
            None,
        );
        let fragment = url.split_once('#').unwrap().1;
        assert!(!fragment.contains("domain="));
        assert!(!fragment.contains("ttl="));
    }

    #[test]
    fn the_requested_lifetime_is_clamped() {
        assert_eq!(effective_ttl(None), DEFAULT_TTL_MINUTES);
        assert_eq!(effective_ttl(Some(0)), 1);
        assert_eq!(effective_ttl(Some(MAX_TTL_MINUTES + 1)), MAX_TTL_MINUTES);
        assert_eq!(effective_ttl(Some(60)), 60);
    }

    #[test]
    fn a_chain_that_outlives_the_requested_lifetime_is_refused() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let leaf_der = leaf.public_key().unwrap();
        let mut chain = chain_for(&leaf_der);
        // Valid, but reaching two hours past what was asked for.
        let long_expiration = now_ns() + 2 * 60 * 60 * 1_000_000_000;
        example_expiration(&mut chain, long_expiration);

        let error = validate_chain(&chain, &leaf_der, 60).expect_err("must be refused");
        assert!(error.to_string().contains("outlives"));
    }

    #[test]
    fn a_chain_rooted_at_its_own_leaf_is_refused() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let leaf_der = leaf.public_key().unwrap();
        let mut chain = chain_for(&leaf_der);
        chain.public_key = leaf_der.clone();

        let error = validate_chain(&chain, &leaf_der, 60).expect_err("must be refused");
        assert!(error.to_string().contains("rooted at the key"));
    }

    fn example_expiration(chain: &mut DelegationChain, expiration: u64) {
        for signed in &mut chain.delegations {
            signed.delegation.expiration = expiration;
        }
    }

    #[test]
    fn the_whole_flow_returns_the_delegation() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let leaf_der = leaf.public_key().unwrap();
        let chain = chain_for(&leaf_der);
        let browser = PostingBrowser::new(&chain);

        let result = acquire_delegation_blocking(&leaf_der, &options(), &browser, &OkDiscovery)
            .expect("the flow completes");

        assert_eq!(result.public_key, chain.public_key);
        assert_eq!(result.delegations.len(), 1);
        assert_eq!(browser.opened.load(Ordering::SeqCst), 1);
        assert!(browser.seen.lock().unwrap()[0].contains("domain="));
    }

    #[test]
    fn a_wrong_nonce_is_refused_and_the_flow_keeps_waiting() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let leaf_der = leaf.public_key().unwrap();
        let chain = chain_for(&leaf_der);

        let browser = PostingBrowser::with_bad_nonce(&chain);
        let options = WebAuthOptions {
            timeout: Duration::from_millis(300),
            ..options()
        };
        let result = acquire_delegation_blocking(&leaf_der, &options, &browser, &OkDiscovery);
        assert!(matches!(result, Err(WebAuthError::TimedOut)));
    }

    #[test]
    fn a_delegation_for_another_key_is_refused() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let other = BasicIdentity::from_raw_key(&[8u8; 32]);
        let chain = chain_for(&other.public_key().unwrap());
        let browser = PostingBrowser::new(&chain);

        let result = acquire_delegation_blocking(
            &leaf.public_key().unwrap(),
            &options(),
            &browser,
            &OkDiscovery,
        );
        assert!(matches!(result, Err(WebAuthError::WrongKey)));
    }

    #[test]
    fn an_expired_delegation_is_refused() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let leaf_der = leaf.public_key().unwrap();
        let account = BasicIdentity::from_raw_key(&[7u8; 32]);
        let delegation = Delegation {
            pubkey: leaf_der.clone(),
            expiration: 1,
            targets: None,
            permissions: None,
        };
        let signature = account.sign_delegation(&delegation).unwrap();
        let chain = DelegationChain {
            delegations: vec![ic_agent::identity::SignedDelegation {
                delegation,
                signature: signature.signature.unwrap(),
            }],
            public_key: account.public_key().unwrap(),
        };
        let browser = PostingBrowser::new(&chain);

        let result = acquire_delegation_blocking(&leaf_der, &options(), &browser, &OkDiscovery);
        assert!(matches!(result, Err(WebAuthError::InvalidDelegation(_))));
    }

    #[test]
    fn discovery_failures_surface_before_the_browser_opens() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let browser = NoBrowser;
        let result = acquire_delegation_blocking(
            &leaf.public_key().unwrap(),
            &options(),
            &browser,
            &FailingDiscovery,
        );
        assert!(matches!(result, Err(WebAuthError::Discovery(_))));

        let result = acquire_delegation_blocking(
            &leaf.public_key().unwrap(),
            &options(),
            &browser,
            &EmptyPathDiscovery,
        );
        assert!(matches!(result, Err(WebAuthError::InvalidLoginPath { .. })));
    }

    #[test]
    fn an_absent_browser_is_an_error() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let result = acquire_delegation_blocking(
            &leaf.public_key().unwrap(),
            &options(),
            &NoBrowser,
            &OkDiscovery,
        );
        assert!(matches!(result, Err(WebAuthError::OpenBrowser(_))));
    }

    #[test]
    fn nobody_signing_in_times_out() {
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let options = WebAuthOptions {
            timeout: Duration::from_millis(200),
            ..options()
        };
        let result = acquire_delegation_blocking(
            &leaf.public_key().unwrap(),
            &options,
            &SilentBrowser,
            &OkDiscovery,
        );
        assert!(matches!(result, Err(WebAuthError::TimedOut)));
    }

    #[test]
    fn the_nonce_is_random_and_url_safe() {
        let first = random_nonce();
        let second = random_nonce();
        assert_ne!(first, second);
        assert_eq!(base64_url_no_pad(&first).len(), 43);
    }

    #[test]
    fn the_timeout_is_bounded_by_the_deadline() {
        // `serve` is the loop above; with a silent browser the call returns
        // after `timeout`, not immediately and not much later.
        let leaf = BasicIdentity::from_raw_key(&[9u8; 32]);
        let options = WebAuthOptions {
            timeout: Duration::from_millis(250),
            ..options()
        };
        let started = Instant::now();
        let _ = acquire_delegation_blocking(
            &leaf.public_key().unwrap(),
            &options,
            &SilentBrowser,
            &OkDiscovery,
        );
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }
}
