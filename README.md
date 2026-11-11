# ic-auth-client

Port of [@icp-sdk/auth](https://www.npmjs.com/package/@icp-sdk/auth) for the Rust programming language.

This is a crate for developers who build the frontend of applications for Internet Computer using Rust as the primary language.

The port follows the **v11 model** of the JavaScript library: a sign-in lives in
storage, and an `AuthClient` is a cheap view on it. Construct one per page, read
the status, sign in or out, and use the identity it hands you with `ic-agent`.

## Version compatibility for `ic-agent`

This crate implements `ic_agent::Identity` and hands out `ic_agent` types, so it
must be built against the same `ic-agent` as the application: another version is
another `Identity` trait, and the identity this crate hands out does not
typecheck against that agent. Two rules keep that from being a guessing game.

- **Depend on this crate only.** Take `ic-agent` types from the re-export
  (`ic_auth_client::ic_agent`) instead of adding `ic-agent` to your own
  `Cargo.toml`. Cargo then resolves one `ic-agent` for the tree, and a mismatch
  cannot happen.
- **The minor version names the pairing.** `ic-auth-client 0.49.x` is built for
  `ic-agent 0.49.*`; our patch releases are fixes within it. A new `ic-agent`
  minor becomes a new minor here, which is also a cargo-visible breaking bump:
  with 0.x semantics `ic-auth-client = "0.49"` does not accept `0.50`.

A scheduled CI workflow watches crates.io for new `ic-agent` releases and opens
the bump (dependency, crate version, changelog and this table, with the full
test matrix), and `scripts/check-agent-compat.sh` fails the build if the version
and the dependency ever drift apart.

| `ic-agent` version | `ic-auth-client` version | upstream `@icp-sdk/auth` |
| ------------------ | ------------------------ | ------------------------ |
| 0.49.\*            | 0.49.\*                   | 11.x                     |
| 0.45.\*            | 0.5.\*                   | 5.x                      |
| 0.44.\*            | 0.4.\*                   | 4.x                      |
| 0.39.\*            | 0.3.\*                   | 3.x                      |
| 0.37.\* or 0.38.\* | 0.1.\* or 0.2.\*         | 3.x                      |

## Quick Start

### Web frontend (browser/WebView)

```rust
use ic_auth_client::client::{AuthClient, AuthClientCreateOptions, SignInOptions};
// Take `ic-agent` from this crate's re-export: the identity it hands out is an
// `Identity` for *this* `ic-agent`, and a second copy in the tree is a second
// trait it would not satisfy.
use ic_auth_client::ic_agent;

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // A client is a view on stored state: construct it wherever you need it.
    let auth_client = AuthClient::new(AuthClientCreateOptions::default())?;

    // Read the answer that storage already holds (this is synchronous).
    if auth_client.is_authenticated() {
        let principal = auth_client.get_principal();
        // ...
    }

    // Sign in. The identity provider opens a window (or navigates, with
    // `transport: TransportMode::Redirect`) and the call resolves with the
    // identity the application signs its requests with.
    let identity = auth_client.sign_in(SignInOptions::default()).await?;

    let agent = ic_agent::Agent::builder()
        .with_url("https://icp-api.io")
        .with_identity(identity)
        .build()?;
    Ok(())
}
```

### Following sign-in changes

```rust
use std::sync::Arc;
use ic_auth_client::client::{AuthClient, AuthClientCreateOptions, SessionStatus};

fn watch(auth_client: &AuthClient) {
    let subscription = auth_client.subscribe(Arc::new(|| {
        // Runs after the client's answer has been refreshed, so `get_status()`
        // reports what the listener was told about.
    }));

    match auth_client.get_status() {
        SessionStatus::SignedIn { principal, expires_at_ms } => { /* ... */ }
        SessionStatus::SignedInElsewhere { .. } => { /* a sibling subdomain holds it */ }
        SessionStatus::Expired { .. } => { /* ... */ }
        SessionStatus::SignedOut => { /* ... */ }
    }
    drop(subscription);
}
```

### Session expiry (formerly the "idle timeout")

There is no `IdleManager` on the v11 client. A sign-in is bounded where it is
issued: pass `max_time_to_live` / `max_time_to_idle` with `sign_in`, the provider
ends a session that goes unused for that idle window, and an idle-out arrives as
`SessionStatus::Expired` --- where a v5 `onIdle` callback used to live:

```rust
fn watch_expiry(auth_client: AuthClient) {
    let subscription = auth_client.subscribe(Arc::new(move |_| {
        if matches!(auth_client.get_status(), SessionStatus::Expired { .. }) {
            // what `onIdle` used to do, e.g. show "your session ended"
        }
    }));
    drop(subscription);
}
```

Leaving both options unset uses the provider's own defaults (currently seven days
of idleness, thirty days in total), so ask for a shorter window if the
application needs one. `IdleManager` itself remains exported for the legacy v5
client only.

## Options

`AuthClientCreateOptions` mirrors the upstream create options:

| Option | Meaning |
| ------ | ------- |
| `identity_provider` | `IdentityProvider { authorize_url, canister_id }`. Defaults to `https://id.ai/authorize` and `rdmx6-jaaaa-aaaaa-aaadq-cai`. |
| `transport` | `TransportMode::Window` (ICRC-29 `postMessage`, default) or `TransportMode::Redirect` (ICRC-167 browser URL transport). |
| `credential_storage` | Where the keys and delegations are kept. Defaults to the platform's main store. |
| `state_storage` | Where "who is signed in here, and until when" is kept. Defaults to the platform's main store. |
| `namespace` | Prefix every slot this client writes under, so two clients can share an origin. |
| `derivation_origin` | Derivation origin for the identity provider. |
| `window_opener_features` | Window features string for the authentication popup. |
| `prompt`, `hint`, `resumable` | Silent re-issue: `Prompt::None` with a `hint` asks Internet Identity to answer without a ceremony, for a sign-in a sibling subdomain already holds. |
| `open_id_provider`, `sso_domain` | One-click OpenID sign-in, or organization-domain SSO (mutually exclusive). |
| `disable_browser_activity` | Stop watching the page for signs that somebody is here. |

`SignInOptions` carries `max_time_to_live` / `max_time_to_idle` (nanoseconds,
sent only when set) and `return_to` (same-origin `http(s)` only).

## What the port covers

| v11 surface | Rust |
| ----------- | ---- |
| `new AuthClient(options)` | `AuthClient::new(options)` |
| `ready()` | `ready().await` |
| `getIdentity()` | `get_identity().await` |
| `isAuthenticated()` / `getPrincipal()` / `getStatus()` | `is_authenticated()` / `get_principal()` / `get_status()` |
| `signIn()` / `signOut()` | `sign_in(options).await` / `sign_out(options).await` |
| `requestAttributes()` | `request_attributes(keys, nonce).await` |
| `subscribe()` / `dispose()` | `subscribe(listener)` (returns a `Subscription`) / `dispose()` |
| `getSsoStatus()` / `refreshSsoStatus()` | `get_sso_status()` / `refresh_sso_status()` |
| notification consent (3 methods) | `request_notification_consent()` / `revoke_notification_consent()` / `get_notification_consent_status()` |
| `OPENID_PROVIDER_URLS`, `scopedKeys` | `OpenIdProvider::url()`, `scoped_keys(..)` |
| `IdleManager` | Not part of the client: a sign-in is bounded by the identity provider. The `idle_manager` module remains exported as a standalone utility. |

### Storage

Credentials and the sign-in state are two stores, as upstream splits them:

- **Credentials** (`CredentialStorage`): a key and the delegation that authorises
  it, per slot (`session`, `session-pending`, `app`, `app-pending`).
  - `wasm-js`: `IdbCredentialStorage` (IndexedDB, P-256), `LocalCredentialStorage`
    (localStorage, Ed25519), `MemoryCredentialStorage`, `SharedMemoryCredentialStorage`.
  - `native`: `NativeCredentialStorage` over the keyring, a PEM file or the
    password-encrypted file store.
- **State** (`StateStorage`): who is signed in here and until when, readable
  without awaiting (`ic-session-state` slot).
  - `wasm-js`: `LocalStateStorage` (localStorage, with an IndexedDB mirror for
    workers), `CookieStateStorage` (shared with sibling subdomains),
    `MemoryStateStorage`.
  - `native`: `NativeStateStorage` (file-backed).

The wasm stores write the same on-disk formats as the JavaScript library so that
both can be used on one origin, with one documented exception: the JavaScript
library keeps non-extractable `CryptoKeyPair`s in IndexedDB, and `ic-agent` signs
synchronously, so this crate stores **extractable** P-256 keys. JavaScript can
read what Rust wrote; Rust reports "no credential" for a key only JavaScript
could create (the user simply signs in again).

## Session lifetime

A browser sign-in is a *session*: the identity provider delegates to a session
key restricted to the provider, and the client mints the delegation it signs
requests with from that session. The client installs this as the rotating
`SessionIdentity` (`client::session::identity`), so:

- a delegation close to its expiry is replaced in the background before a request
  needs it --- `get_identity()` hands out an identity, not a snapshot, and
  signing with it follows the rotation;
- `get_identity()`/`sign_in()` return a `ClientIdentity`, which implements
  `ic_agent::Identity`, so give the agent `with_identity(identity)`; it also
  reports `principal()`, `is_anonymous()` and `delegation_expires_at_ms()`;
- when the session turns out gone (a mint is refused), the client drops to an
  anonymous identity, publishes the record as ended, and notifies `subscribe`
  listeners;
- page foreground/activity events let it mint ahead; `disable_browser_activity`
  turns that off, and a sign-in in flight always stands it down.

## Feature flags

| Feature | Default | Meaning |
| ------- | ------- | ------- |
| `wasm-js` | yes | WebView/browser support (IndexedDB, localStorage, cookies, WebCrypto) |
| `native` | no | Non-WebView support (needs `keyring`, `pem` or `android-password`) |
| `keyring` | no | OS secure store for `native` |
| `pem` | no | PEM file storage for `native` |
| `android-password` | no | Password-encrypted file storage for Android/Kotlin |
| `uniffi`, `swift`, `kotlin` | no | Bindings for Swift/Kotlin consumers |
| `tracing` | no | Logging with `tracing` |

## Native applications (non-WebView)

A native application cannot use `postMessage`, and it needs no bridge page
either: Internet Identity serves a first-party flow for non-browser clients (the
one `icp-cli` uses for `icp identity link web`). The client

1. reads the provider's `/.well-known/cli-auth-config` (on `id.ai` it publishes
   `{"path":"/cli"}`),
2. binds `http://127.0.0.1:<ephemeral>/` and opens the provider's sign-in page
   with the session public key, callback and a single-use nonce in the URL
   fragment,
3. receives the delegation as a form POST from the provider's own page, validates
   it, and answers with a `303` back to the provider so it owns the outcome UI.

```rust
use ic_auth_client::client::{AuthClient, AuthClientCreateOptions};
async fn run_native() -> Result<(), Box<dyn std::error::Error>> {
    let client = AuthClient::new(AuthClientCreateOptions {
        // The origin of the app whose principal you want (the `domain`
        // parameter); omit it for the provider's generic CLI identity.
        derivation_origin: Some("https://my-app.example.com".to_string()),
        ..Default::default()
    })?;
    let identity = client.sign_in(Default::default()).await?;
    Ok(())
}
```

Notes for this flow:

- Signing in **as an app** (`derivation_origin`) needs the user to have enabled
  *CLI access* for that identity in Internet Identity's settings, per browser.
- The provider's screen chooses the delegation's access level and defaults to
  **read-only** (query calls); a user who needs update calls must pick full
  access there.
- `max_time_to_live` is sent as the provider's `ttl` (minutes, default 480).
  `max_time_to_idle` and `return_to` have no equivalent here.
- The delegation is stored as the credential the application signs with and is
  bounded by its own expiry; there is no canister-side revocation for it.
  Pass a durable `credential_storage` and `state_storage` (for example
  `NativeCredentialStorage::keyring(service)` and `NativeStateStorage::new(dir)`)
  if the sign-in should survive a restart.
- No bridge page is involved: Internet Identity's own page completes the flow
  and posts the delegation back, so the `ii-bridge/` template the crate used to
  ship is gone.

## Port status

This crate tracks upstream `@icp-sdk/auth` **11.2.0**. The specification the port
follows lives in [`docs/port/`](docs/port/) --- the protocol and storage
contracts, with upstream `file:line` references, plus `DESIGN.md` (architecture,
decisions, progress log).

The v5 API is **removed**: `AuthClient::builder()`, `login()`/`logout()`,
`NativeAuthClient`, `IdleManager` and the `ii-bridge` page are gone. This crate is
v11-only.

| Area | State |
| ---- | ----- |
| Dependencies to latest stable | done (`ic-agent` 0.49, `rand` 0.10, `ed25519-dalek` 3, `keyring` 4, `uniffi` 0.32 …) |
| `AuthClient` lifecycle (`new`, `ready`, `get_identity`, `is_authenticated`, `get_principal`, `get_status`, `subscribe`, `dispose`, restore/hydrate) | done |
| Signer protocol (`ii_session_delegation`, `ii-icrc3-attributes`, `ii_notification_consent`, delegation validation) | done |
| Browser transports (ICRC-29 `postMessage`, ICRC-167 URL redirect with journal) | done |
| Credential/state stores (IndexedDB, localStorage, cookie, shared-memory, native keyring/PEM/password/file) | done |
| Session layer (rotating `SessionIdentity`, canister minter, cross-tab locks, foreground refresh) | done and wired: sign-in and restore open the rotating identity; foreground/activity refresh mints ahead; a gone session drops the client to anonymous and updates the record |
| SSO status + notification consent | done and wired |
| `sign_in`/`sign_out` orchestration | done, including the native non-browser flow (no bridge) |
| Non-browser sign-in (CLI-auth discovery + loopback callback) | done for desktop |
| UniFFI bindings (`swift`, `kotlin`) | rewritten against the v11 client |
| Native mobile sign-in (iOS/Android) | **remaining**: the provider's flow needs a `127.0.0.1` callback, which needs a platform-hosted equivalent |
| Swift/Kotlin hand-written wrappers, example applications | **remaining** (they still call the removed v5 surface; see [`examples/README.md`](examples/README.md)) |
| Storage-format conformance tests against the JavaScript library (`compat-tests/`) | **remaining** (still targets v5) |

## License

This project is licensed under [Apache License, Version 2.0](./LICENSE-APACHE).
