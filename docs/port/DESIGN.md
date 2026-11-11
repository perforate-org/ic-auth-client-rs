# ic-auth-client-rs — v11.2.0 parity design

Status: living document (Lead-owned). Specs: `protocols/`, `state/` (teammates).

> Implementation status is tracked in the "Progress log" section at the end.

## 0. Decision (user-confirmed)

- Target: **functional parity with `@icp-sdk/auth` v11.2.0** (+ its `@icp-sdk/signer` v6.1.0 dependency), staged so every step compiles and tests pass.
- **Breaking changes allowed**: Rust public API is renamed/reshaped to match the v11 model (`new(options)`, `sign_in`, `sign_out`, `get_identity().await`, `is_authenticated()` sync, …). Swift/Kotlin/uniffi bindings, examples, README/CHANGELOG follow.
- Dependencies go to latest stable (separate workstream, lands first).

Reality check: upstream is ~5.3k lines TS (auth) + ~6.5k lines TS (signer incl. tests). The Rust port therefore *grows* to roughly 8–10k lines. This is a multi-phase project; each phase below is separately shippable.

## 1. What we are porting

Upstream split we mirror:

| Upstream package | What it does | Rust module |
| --- | --- | --- |
| `@icp-sdk/signer` (`src/transport.ts`, `src/signer.ts`, `src/web/*`) | ICRC-25/27/34 JSON-RPC over ICRC-29 postMessage / ICRC-167 URL transport | `src/signer/` |
| `@icp-sdk/auth/client` | session model, sign-in/out, attributes, SSO, notifications | `src/client/` |
| `@icp-sdk/core` (`agent`, `identity`) | already `ic-agent` + `candid` | dependency |

Platform matrix:

| Capability | wasm-js (browser/WebView) | native (desktop/iOS/Android) |
| --- | --- | --- |
| Signer channel | popup/iframe + `postMessage` (ICRC-29) | none: the identity provider's own non-browser flow (`/.well-known/cli-auth-config`) hands a delegation to a loopback listener, so no bridge page is involved |
| Redirect transport (ICRC-167) | `location.replace` + journal | custom-scheme / universal link + journal (phase 5, optional) |
| Credential storage | IndexedDB `CryptoKeyPair` (extractable for us), localStorage, memory, SharedWorker/BroadcastChannel memory | keyring / PEM / password file (existing backends, re-shaped) |
| State storage | localStorage, cookie (cross-subdomain), memory | file-backed store + in-memory notifier |
| Notifications consent | Web Notifications + signer | not applicable (returns `Unsupported`) |
| Canister calls (session mint/revoke, SSO status) | `ic-agent` wasm HttpAgent | `ic-agent` native HttpAgent |

## 2. Hard technical constraints (decided)

### 2.1 Signing is synchronous in Rust
`ic_agent::identity::Identity::sign` is **sync**; JS `SignIdentity.sign` is async and upstream deliberately keeps IDB keys **non-extractable**. Consequences:

- Rust wasm generates/imports **extractable** P-256 `CryptoKeyPair`s. The IDB record keeps the JS shape `{ keyPair, chain }` so JS v11 can read what Rust wrote.
- **JS → Rust interop for IDB credentials is limited**: a credential created by the JS library holds a non-extractable key, which Rust cannot export; the Rust store must treat it as unusable and report "no credential" (caller re-acquires). Rust → JS is fine (extractable keys are usable by JS).
- Every in-memory identity therefore holds readable key material (SEC1/PKCS8 bytes). This is the same trade the pre-v11 crate already made.
- `PartialIdentity` (read-only sessions, v10) is modelled as our own `ClientIdentity { Signing(..), Partial(..) }`; `Partial` returns an error from `sign`, exactly like JS.

### 2.2 Async traits
Storage/transport traits must be dyn-compatible (`Arc<dyn CredentialStorage>`). Use `async-trait` with **`?Send`** futures for the storage traits: wasm futures are `!Send`, and the existing native code already drives futures with `futures::executor::block_on` on the calling thread, so it does not require `Send` futures.

Rules:
- Trait **objects** stay `Send + Sync` where the crate must be usable from uniffi (`AuthClient` is exported to Swift/Kotlin, uniffi requires `Send + Sync`). So keep `JsValue`/`CryptoKeyPair` **out of stored structs** (see 2.1: key material is bytes, storage converts to/from WebCrypto keys internally at the edge).
- Futures returned by storage methods are `!Send` (`#[async_trait(?Send)]`).
- Native blocking entry points keep using `futures::executor::block_on` in `uniffi_bindings`.

### 2.3 JSON-RPC / protocol types
Pure data (`serde_json::Value`-based), no platform types, shared by the two browser transports. A non-browser client does not speak this protocol at all (see `webauth`), so the protocol implementation stays wasm-side.

### 2.4 Canister interface
Add `candid` crate. Define only the methods used (mirrors upstream):
- II session: `app_prepare_delegation`, `app_get_delegation`, `app_revoke_session`
- II SSO: `app_sso_domain_check`, `app_sso_domain_status` (per `sso.ts` idlFactory)
- notification consent: as used by `notification-consent.ts` (via signer, not canister — confirm in spec)

### 2.5 Time / randomness
`web-time` for `SystemTime`/`Instant` on wasm+native; `getrandom` 0.4 with `wasm_js` backend for `rand` 0.10.

## 3. Module layout (target)

```
src/
  lib.rs                     # feature docs, module wiring, re-exports
  client/
    mod.rs
    auth_client.rs           # AuthClient (constructor, restore, signIn/out, attributes, notifications, status, subscribe)  [Lead]
    options.rs               # AuthClientCreateOptions / SignInOptions / SignOutOptions / enums
    error.rs                 # AuthClientError + error classes (SupersededError, SessionNotHeldError, ...)
    slots.rs                 # SLOT_NAMES + slots_for(namespace)
    base64.rs                # byte <-> base64 helpers used by decoding
    credentials/
      mod.rs                 # Credential + CredentialStorage trait
      memory.rs              # MemoryCredentialStorage
      local.rs               # LocalCredentialStorage (localStorage)
      idb.rs                 # IdbCredentialStorage (wasm) -> db.rs
      shared_memory.rs       # SharedMemoryCredentialStorage (wasm worker sharing)
      native.rs              # NativeCredentialStorage (keyring/pem/password backends)
    state/
      mod.rs                 # SessionState + StateStorage trait
      memory.rs
      local.rs
      cookie.rs              # CookieStateStorage (wasm)
      native.rs              # file-backed StateStorage (native)
    signer.rs                # Signer protocol layer (ICRC-25/27/34 requests + validation) [port of signer.ts]
    transport/
      mod.rs                 # Transport/Channel traits + JsonRpc types + TransportMode
      post_message.rs        # wasm: window/popup + ICRC-29 postMessage channel + heartbeat
      url.rs                 # wasm: ICRC-167 URL transport + journal/memoize
    session/
      mod.rs
      identity.rs            # SessionIdentity (self-refreshing delegation)       [port of session-identity.ts]
      minter.rs              # SessionMinter + canister calls                     [port of session-minter.ts]
      delegation.rs          # requestSessionDelegation / InteractionRequiredError
      app_lock.rs            # stealLock / stealMintLock / HeldLock
      app_delegation_source.rs
    sso.rs                   # SsoStatusChecker + domain validation + canister calls
    notification_consent.rs  # consent request/revoke/status
    foreground_refresh.rs    # watchActivity/watchForeground
  webauth.rs                 # native (desktop): II cli-auth flow, loopback callback, no bridge
  db.rs                      # IndexedDB keyval wrapper (wasm); native: not compiled
  keys/
    mod.rs                   # ClientIdentity, ArcIdentity, KeyWithRaw (re-shaped from src/key.rs)
    delegation_chain.rs      # DelegationChain (timestamps as u64, JS-compatible JSON)
  idle_manager/              # kept as an extension (standalone, no longer wired into AuthClient)
```

Legacy modules that are deleted or re-shaped when the new client lands:
`src/auth_client/{wasm_js,native}.rs`, `src/storage/{async_storage,js_compat}.rs`, `src/option.rs`, parts of `src/storage.rs`.
`src/util/{arc_identity,callback,delegation_chain}.rs` move into `src/keys/` + `src/client/`.

## 4. Public API mapping (v11 TS → Rust)

```rust
pub struct AuthClient { .. }
impl AuthClient {
    pub fn new(options: AuthClientCreateOptions) -> Result<Self, AuthClientError>;
    pub async fn ready(&self) -> Result<(), AuthClientError>;
    pub async fn get_identity(&self) -> Result<ClientIdentity, AuthClientError>;
    pub fn is_authenticated(&self) -> bool;
    pub fn get_principal(&self) -> Option<Principal>;
    pub fn get_status(&self) -> SessionStatus;
    pub fn get_sso_status(&self) -> Option<SsoStatus>;
    pub fn refresh_sso_status(&self);
    pub fn subscribe(&self, listener: Arc<dyn Fn() + Send + Sync>) -> Subscription;
    pub fn dispose(&self);
    pub async fn sign_in(&self, options: SignInOptions) -> Result<ClientIdentity, AuthClientError>;
    pub async fn sign_out(&self, options: SignOutOptions) -> Result<(), AuthClientError>;
    pub async fn request_attributes(&self, request: AttributesRequest<'_>) -> Result<SignedAttributes, AuthClientError>;
    pub async fn request_notification_consent(&self) -> Result<NotificationConsentStatus, AuthClientError>;
    pub async fn revoke_notification_consent(&self) -> Result<(), AuthClientError>;
    pub async fn get_notification_consent_status(&self) -> Result<NotificationConsentStatus, AuthClientError>;
}
```

Mapping decisions (rust-idiomatic but faithful):
- `constructor(options = {})` → `AuthClient::new(options)` with `Default`; the JS constructor eagerly starts `#init()`; Rust stores a lazy init future, awaited by `ready()/get_identity()/sign_in()` etc. Rationale: native has no ambient executor in the constructor.
- `identityProvider: {authorizeUrl, canisterId}` → `IdentityProvider { authorize_url: String, canister_id: Principal }`, default `https://id.ai/authorize` + `rdmx6-jaaaa-aaaaa-aaadq-cai`.
- `agentOptions` → `host: Option<String>` + `agent_factory: Option<Arc<dyn AgentFactory>>` (trait builds an `HttpAgent` around a given identity). Document deviation: `HttpAgentOptions` in Rust is not a plain data struct.
- callbacks (`on_success`, `on_error`) from v5 disappear (v11 returns the identity / error).
- `subscribe(listener): () => void` → returns `Subscription` (RAII `unsubscribe` on drop, explicit `.unsubscribe()`).
- `SignedAttributes` → `serde_json::Value`-shaped struct `SignedAttributes { signed_attributes: Value, certificate: Vec<u8> }` (confirm exact shape in spec).
- `SsoStatus` → enum `SsoStatus { Unknown, Invalid { reason }, Checking, Valid { .. }, ... }` (per spec).
- `SessionStatus` → enum `SessionStatus { NoSession, ... }` (per spec).
- Errors: one public `AuthClientError` enum with `kind()` accessors for the JS error classes; `SupersededError`/`SessionGoneError`/`InteractionRequiredError` variants distinguishable for callers.

## 5. Storage model (JS-interoperable)

Slots (namespace prefix `"<ns>:"`): `session`, `session-pending`, `app`, `app-pending`, `ic-session-state`.
- Credential records: `{ keyPair, chain? }` in IDB (IDB db/store/version per `state/credential-storage.md`), `{ identity, delegation? }` shapes in localStorage (per spec).
- State record: `SessionState { principal, expiration (epoch ns), held (derived) }`; cookie name/format/attrs per spec.
- JS compat for v11 is a **tested requirement**: extend `compat-tests/` to `@icp-sdk/auth@11` + `@icp-sdk/core@6` and assert Rust↔JS read/write for every store with extractable keys (document the non-extractable limitation explicitly in README).

## 6. Verification strategy

1. **Unit tests** (native `cargo test`): protocol validation (`assertLeafKey`, `assertTargetScope`, `assertLifetime`), slot naming, state codec, chain validation, SSO domain rules, error mapping.
2. **wasm-pack tests** (`cargo test --target wasm32` + `wasm-bindgen-test`): WebCrypto key handling, IDB wrapper, cookie/localStorage stores, postMessage channel (with fake window), foreground refresh.
3. **Portable fakes** (ported from upstream `tests/client/fake-transport.ts`, `fake-url-transport.ts`): a `FakeTransport` + `FakeUrlTransport` in Rust so the whole `AuthClient` sign-in/out/attributes state machine can be tested hermetically on wasm and native.
4. **Playwright conformance suite** (`compat-tests/`): page loads our wasm client *and* the real `@icp-sdk/signer` e2e mock wallet / `@icp-sdk/auth` v11; assert protocol conformance and cross-library storage compatibility. Reference fixtures: `/tmp/icp-js-signer/e2e/fixtures/{mock-wallet,mock-auth-provider,relying-party}.ts`.
5. **Live e2e** (best effort, not in CI): `dfx` + `internet-identity` canister (needs an II build with `app_prepare_delegation`/`app_get_delegation`/`app_sso_domain_*`), driving the wasm client through a real ceremony.

## 7. Phases (each ends green)

| Phase | Deliverable | Owner |
| --- | --- | --- |
| 0 | deps to latest; specs; this design | deps / spec-* / Lead |
| 1 | new module skeleton + `keys` + traits + `slots` + `base64` + error/options types (compiles, old client still works) | Lead |
| 2 | `signer/` protocol layer + postMessage/URL transports + fake transports + tests | signer-core / signer-web |
| 3 | credentials + state stores (wasm + native) + db wrapper + tests | storage |
| 4 | `AuthClient`: restore/status/subscribe/signIn/signOut/attributes (window transport first, then redirect) | Lead + session |
| 5 | session layer: minter/identity/delegation/app-lock/foreground refresh | session |
| 6 | SSO + SSO domain status + notification consent | features |
| 7 | uniffi/Swift/Kotlin, examples, ii-bridge, README/CHANGELOG, compat-tests v11 | bindings |
| 8 | full verification: unit + wasm-pack + Playwright conformance | Lead |

## 8. Open questions

- Exact ICRC-29 channel framing / heartbeat behaviour (spec-protocols).
- Notification consent: signer message shape and canister interaction (spec-protocols).
- SSO polling constants and `SsoStatus` variants (spec-protocols).
- IDB db names/version + localStorage record shapes (spec-state).
- Whether `IdleManager` stays exported (proposal: keep as standalone extension, not wired into `AuthClient`).
- Rust `rust-version` bump needed for new deps (deps workstream reports).

## 9. Progress log

Appendix, newest last. Acceptance for every entry: `cargo check`/`test` for
`native,keyring` + `native,pem` and the wasm32 `wasm-js` check are green, plus
`cargo clippy` on touched files.

| Entry | Landed |
| --- | --- |
| Dependencies | latest stable: `ic-agent` 0.49.3, `ic-transport-types` 0.49.3, `ed25519-dalek` 3, `rand` 0.10, `keyring` 4.2, `uniffi` 0.32.2, `base64` 0.23, `getrandom` 0.4, `gloo-*` 0.3/0.4, `wasm-bindgen` 0.2.130, `web-sys` 0.3.107. Deliberate pins: `k256` 0.13.4 / `p256` 0.13.2 / `pkcs8` 0.10 / `sha2` 0.10 (ic-agent's stack, so one copy of ecdsa/elliptic-curve/sec1/pkcs8). New: `async-trait`, `candid` 0.10, `serde_bytes`, `web-time`, `url` (non-optional). MSRV 1.95. |
| Layout | `src/client/**` + `src/signer/**` skeleton: traits (`Transport`/`Channel`/`Journal`, `CredentialStorage`, `StateStorage`), `platform::PlatformBounds` (Send+Sync on native, empty on wasm), `Listener`/`Unsubscribe`, `slots`, `base64`, `options`, `error`, `async_once`. |
| Client stage A | `AuthClient`: options resolution, authorize-URL assembly (openid/sso/derivationOrigin/prompt/hint/resumable), `ready`, `get_identity` (with `SessionNotHeld`), `is_authenticated`, `get_principal`, `get_status`, `subscribe`, `dispose`, restore/hydrate/drop/end-session, `sign_out` local half. 36 unit tests. `sign_in`, `request_attributes`, notification consent and SSO are declared and return `Unsupported` until their phases land. |
| Legacy | The v5 `AuthClient` (`src/auth_client/**`) and its storage still compile and are still exported at the crate root, so the crate remains usable while the v11 surface is completed. |
| Signer | `src/signer/` (protocol + client + fake transport) landed: `ii_session_delegation`, `ii-icrc3-attributes`, `ii_notification_consent`, delegation-chain validation (leaf/targets/lifetime), decimal-string expirations, standard base64, ICRC-25/27/29/34/49 method constants. |
| Transports | ICRC-29 `postMessage` (window open, status polling, heartbeat, close) and ICRC-167 URL transport (fragment batch, callback/state, sessionStorage journal with call-order replay and divergence guard) under `src/client/transport/`. |
| Stores | wasm: `IdbCredentialStorage` (db `auth-client-db`/`ic-keyval` v1, extractable P-256 imported into WebCrypto), `LocalCredentialStorage`, `SharedMemoryCredentialStorage` (BroadcastChannel + Web Locks), `LocalStateStorage` (+ worker IDB mirror), `CookieStateStorage`; native: `NativeCredentialStorage` (keyring/PEM/password) and file-backed `NativeStateStorage`. Defaults follow upstream: IDB + localStorage on wasm. |
| Session | `src/client/session/`: hand-written II Candid (`app_prepare_delegation`/`app_get_delegation`/`app_revoke_session`), `SessionMinter`, rotating `SessionIdentity` (10s block margin, 15s pre-mint, single-flight mint, scheduled rotation), cross-tab locks (Web Locks on wasm, in-process native), `foreground_refresh` watchers. |
| Features | `sso.rs` (domain normalization + `SsoStatusChecker` with 500ms→2s backoff, 120s abandon) and `notification_consent.rs` (signer call + canister status/revoke) landed and wired into `AuthClient`: `get_sso_status`, `refresh_sso_status`, the three notification methods. |
| Client stage B | `sign_in` now: opens the signer window synchronously (`begin_sign_in`), acquires the session key (window or redirect-pending+journal), requests the session delegation, verifies the chain, mints the app delegation, writes `app-pending` → `session` + state record → `app`, installs the identity and notifies. `sign_out` clears the local half (canister revoke needs the session identity, below). |
| Verification | `native,keyring` 289 passed / 0 failed / 2 ignored; `native,pem` 296 / 0 / 2; wasm32 `wasm-js` check 0 errors; `wasm-js,wasm-compat-test` check 0 errors; wasm32 test compile 0 errors; `native,keyring,android-password`, `...,swift`, `...,kotlin` checks 0 errors. The 2 ignored tests are the legacy `idle_manager::native` rdev-timer tests, which need a desktop input session (documented in place). Remaining `cargo clippy` warnings are wasm-only codecs that are dead code on native builds (gating is a follow-up polish), plus the pre-existing legacy lints. |
| Native sign-in | No bridge page is needed. `src/client/webauth.rs` implements the identity provider's non-browser flow: discovery at `{auth}/.well-known/cli-auth-config` (live on `id.ai` -> `{"path":"/cli"}`), a `127.0.0.1` loopback listener, the `public_key`/`callback`/`nonce`(+`domain`,`ttl`) fragment, the top-level form POST carrying `DelegationChain.toJSON()`, nonce/leaf/expiry validation, and a `303 {auth}{path}#status=...` answer so the provider keeps the UI. `AuthClient::sign_in` takes this path when it has no signer transport; the resulting chain is used directly as the credential (there is no session chain to mint app delegations from), stored in the `app` slot with the state record, and restored by the native fallback in `hydrate`. 13 auth-client + 11 webauth tests, including an end-to-end run against the real loopback server. Deviations: `max_time_to_idle`/`return_to` have no equivalent; the provider's screen chooses the access level (read-only by default) and app-mode sign-in needs the user's "CLI access" toggle. |
| v5 removal | The pre-v11 client is gone: `src/auth_client/**`, `src/idle_manager/**`, `src/option*`, `src/api.rs`, `src/storage/async_storage.rs` and `src/util/callback.rs` were deleted, `src/lib.rs` is v11-only, `storage/` keeps only what the v11 client needs (`DecodeError`/`StoredKey`, the JS delegation codec, and the native keyring/PEM/password backends), Cargo lost `rdev`/`portpicker`/unused `gloo-*`/`wasm-timer`/`serde-wasm-bindgen`/`percent-encoding`/`web-time`/`serde_bytes`/`serde_test`, `ii-bridge/` was deleted, and the UniFFI surface was rewritten for the v11 client (blocking wrappers over `sign_in`/`sign_out`, `AuthIdentity` with `sign_arbitrary` + `delegation_chain_json`). Verification after removal: `native,keyring` 299 pass / 0 fail, `native,pem` 306 pass / 0 fail, wasm32 `wasm-js` and `wasm-js,wasm-compat-test` 0 errors, `swift`/`kotlin`/`android-password` 0 errors. |
| Session identity wired | `AuthClient` now holds an `IdentityHolder` (`Anonymous` / `Plain` / `Session`) and installs the rotating identity in both browser paths: sign-in step 9 opens it over the just-promoted app credential (one mint total --- the opening adopts instead of re-minting), and `hydrate` opens it from the restored session chain with the record's account as `expectedAccount` (`auth-client.ts:1520-1574`). The rest follows upstream: `onSessionGone` drops to anonymous synchronously and runs `#endOrDrop` (`auth-client.ts:1585-1620`) in the background --- publish `expired` when a used session's record is unchanged, `endSession` when a ceremony's session was never usable, `dropSession` when a sibling owns the record. `watchForeground`/`watchActivity` are wired to `SessionIdentity::refresh` behind `disable_browser_activity` and an in-flight-ceremony guard (`auth-client.ts:460-471`); `dispose` stops the identity's schedule and unhooks the watchers. Public API consequence: `get_identity`/`sign_in` return `Arc<dyn Identity>` (agent: `with_arc_identity`). Native keeps the single-delegation model: its webauth credential is installed as `Plain` and never opened as a session. Tests: 2 new wiring tests (restore adopts without minting; sign-in mints once and opens the session) run on native under `cfg(test)`; `native,keyring` 301 pass, `native,pem` 308 pass, wasm32 checks clean. |
| Review fixes (stage 1–2) | From the review: sign-out now follows `auth-client.ts:1389-1445` exactly --- waits for the restore, steals the sign-in lock and (when the store is shared) the mint lock, reads the session credential before the wipe, runs the revoke and the local teardown together, installs anonymous, releases, then raises a carried revoke failure before navigating; a ceremony whose sign-in lock was stolen aborts with `Superseded` before committing. `#endSession`/`#dropSession` gained upstream's read-only early return (`auth-client.ts:1816-1835`) so read-only stores are never written through; `install` refuses to install after `dispose`. Cross-tab changes are followed with the Rust equivalent of `#restoreAgain` (`auth-client.ts:1631-1660`): the synchronous listener marks the client stale, and `get_identity` settles it under a `restore_gate` (coalescing, mismatch check included). Locks are a per-client `Arc<dyn LockManager>`. Tests: read-only store (3), dispose-vs-restore (1), peer record change (2); `native,keyring` 305 pass / `native,pem` 312 pass. |
| Review fixes (stage 3) | The Android/Kotlin password store moved to PBKDF2-HMAC-SHA256 (600k) + ChaCha20-Poly1305 (`password.rs`), with the version-1 chained-SHA-256/XOR/SHA-256-tag format still read and re-encrypted on write, atomic temp-file+rename writes and `0600` permissions on Unix. The non-browser flow bounds its answer: `effective_ttl` clamps 1--1440 minutes, every hop's expiration must be within the requested lifetime + 5 minutes of skew, `MAX_CHAIN_HOPS` (4) and a self-rooted chain are refused, the loopback body is capped at 1 MiB, a non-form content type gets 415, and the nonce comparison is constant-time (`webauth.rs`). Tests: password format/migration/tamper/permissions (5), webauth clamp/cap/self-rooted (3). |
| Review fixes (stage 4a) | The hydrate path became data-driven: `enum Restored { Session(Credential), AppDelegation(Credential) }` replaces the `native_fallback` flag and the `cfg(any(wasm-js, test))`/`unreachable!` arms, so restore has one shape on every target and the session identity is opened wherever a session credential exists (`hydrate_session`/`hydrate_app`/`forget_unusable_session`). The on-gone record half stays `wasm-js`-only by design: the storage traits' futures are not `Send` on native (their stores are synchronous underneath), so there is no executor to hand it to; the sync half (drop to anonymous, notify) runs everywhere. `spawn_background` replaces the test-only `spawn_local`. `AuthClientError::AccountMismatch` (with its own kind) replaces the `Other` mapping, and the v5 storage leftovers (`storage_keys`, two `KEY_STORAGE_*` constants, `StoredKey::CryptoKeyPair`) are removed. Native `cargo check` warnings are back to zero (was ~27). Tests: `native,keyring` 310 pass, `native,pem` 317 pass, wasm32 checks clean. |
| Review fixes (stage 4b) | The record transitions moved into `client/session/record.rs` (`end_session`, `drop_session`, `expire_session`, `clear_credentials`, `end_or_drop`), the port of `auth-client.ts:1577-1621`/`1816-1835`, with the read-only early return living there rather than being repeated. The client's methods and the session identity's gone listener now call the same functions, so a policy change cannot land in one and not the other. |
| Review fixes (stage 4b) | `ClientIdentity` (`client/identity.rs`) is the handle `get_identity`/`sign_in` return: it implements `ic_agent::Identity` by forwarding, and adds `principal()`, `is_anonymous()`, `as_arc_identity()` and `delegation_expires_at_ms()` (the rotating session's current delegation, or a fixed chain's earliest hop). `IdentityHolder::to_client_identity` builds it, so the rotation is expressible to callers without exposing the session type; the UniFFI `AuthIdentity` wraps it and exports `delegationExpiresAtMs()`. README/CHANGELOG updated (`with_identity` now takes the handle directly). |
| Next | (1) mobile/native sign-in (the provider's non-browser flow needs a platform-hosted equivalent of the loopback callback); (2) the Swift/Kotlin hand-written wrappers and example applications; for the client's identity and hand it `on_session_gone` (restore + sign-in), which also enables mint-on-return and silent re-issue; (2) `foreground_refresh` wiring through `SessionIdentity::refresh`; (3) the Swift/Kotlin hand-written wrappers and the example applications, which still call the removed v5 surface ([`examples/README.md`](../../examples/README.md)); a mobile sign-in needs a platform-hosted equivalent of the provider's non-browser flow; (5) `compat-tests/` upgraded to `@icp-sdk/auth@11` for cross-implementation storage conformance. |

