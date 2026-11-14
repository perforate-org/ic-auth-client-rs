# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.49.1] - 2026-11-14

### Changed

- Dependency version requirements are floors rather than the versions this crate
  happened to be developed against: `thiserror = "2"`, `serde = "1"`,
  `serde_json = "1"`, `base64 = "0.23"`, `bon = "3"`, `ed25519-dalek = "3"`,
  `rand = "0.10"`, `web-sys = "0.3"`, `uniffi = "0.32"` and the rest of the
  non-crypto stack. An application is no longer forced onto, say,
  `thiserror 2.0.21` --- which mattered in practice: `pocket-ic 16.1` pins
  `thiserror = 2.0.18`, so the previous requirement made the two impossible to
  use in one workspace. `ic-agent` (the pairing) and the RustCrypto generation
  it needs are relaxed to their minor (`"0.49"`, `"0.13"`, `"0.10"`), and
  `keyring` to `"4.1"` --- its test helper now triggers the platform store
  through `Entry::new` rather than the `4.2`-only `store_status`.
- `scripts/bump-ic-agent.sh` keeps the dependency floor on `ic-agent`'s minor
  and records the patch it verifies in `[package.metadata.ic-agent] tested`, so
  a follow-up patch release does not force applications onto that patch.

## [0.49.0] - 2026-11-12

### Security

- `cargo audit` runs in CI. One advisory is open and recorded in `.cargo/audit.toml`:
  RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5 timing variability). Its fix is a
  RustCrypto generation this crate cannot adopt without breaking the `ic-agent`
  identity interop, so it is carried until the `ic-agent` bump. See README
  "Security", including the note on extractable browser keys.

### Changed

- **BREAKING**: Following `@icp-sdk/auth` v11 means the client is now a *view on
  stored state* rather than a long-lived object:
  - `AuthClient::builder()`/`build()` is replaced by `AuthClient::new(options)`.
  - `login()`/`login_with_options()` are renamed to `sign_in()`; `logout()` to
    `sign_out()`.
  - `identity()` (synchronous, `Arc<dyn Identity>`) becomes
    `get_identity().await`; `principal()` becomes the synchronous
    `get_principal() -> Option<Principal>`.
  - The identity provider is a pair --- `IdentityProvider { authorize_url,
    canister_id }`, defaulting to `https://id.ai/authorize` and
    `rdmx6-jaaaa-aaaaa-aaadq-cai` --- not a bare URL.
  - `storage` + `key_type` are replaced by `credential_storage` +
    `state_storage` + `namespace`; key type is chosen by the credential store.
  - `on_success`/`on_error` callbacks are gone: `sign_in()` returns the identity
    and reports failures as `AuthClientError`.
  - `IdleManager` is no longer wired into the client: a sign-in is bounded by the
    identity provider (`max_time_to_live`/`max_time_to_idle`). The module is still
    exported for callers that want the old behaviour as a standalone utility.
- **BREAKING**: Dependencies moved to their latest stable releases:
  `ic-agent` 0.45 -> 0.49, `ic-transport-types` 0.45 -> 0.49, `ed25519-dalek`
  2 -> 3, `keyring` 3 -> 4, `uniffi` 0.31 -> 0.32, `base64` 0.22 -> 0.23,
  `getrandom` 0.3 -> 0.4, `gloo-timers` 0.3 -> 0.4, `gloo-events`/`gloo-utils`
  0.2 -> 0.3, `rand` 0.8 -> 0.10, `bon` 3.x latest. `k256`/`p256`/`pkcs8`/`sha2`
  stay on the majors `ic-agent` itself depends on so the crate has one
  cryptographic stack, and MSRV rises to 1.95.

### Added

- Non-browser sign-in with no bridge page: the `native` feature signs in
  through Internet Identity's first-party flow for non-browser clients ---
  discovery at `{auth}/.well-known/cli-auth-config`, a `127.0.0.1` loopback
  callback, the provider's `public_key`/`callback`/`nonce` fragment and its form
  POST carrying the delegation. The flow is exposed as `client::webauth` (with
  `WebAuthRunner` for callers that complete it their own way) and driven by
  `AuthClient::sign_in` when the platform has no signer transport.
- Port of the v11 sign-in model: a session delegation requested from the signer
  (`ii_session_delegation`) plus an app delegation minted from the Internet
  Identity canister (`app_prepare_delegation`/`app_get_delegation`), with an
  identity that replaces its own delegation as it ages.
- `session`, `session-pending`, `app`, `app-pending` and `ic-session-state` slots
  with `namespace` prefixing, and the credential/state store split
  (`CredentialStorage`, `StateStorage`) that upstream v9 introduced.
- `ready()`, `get_status()` (`SessionStatus`), `subscribe()`, `dispose()`,
  `request_attributes()`, and the notification-consent surface
  (`request_notification_consent`/`revoke_notification_consent`/
  `get_notification_consent_status`).
- SSO: `sso_domain` option, `get_sso_status()`/`refresh_sso_status()` with the
  Internet Identity domain check, replacing the old domain string option.
- Signer transports: ICRC-29 `postMessage` (window) and ICRC-167 browser URL
  transport (redirect, with a journal that survives the navigation).
- `scoped_keys()` and `OPENID_PROVIDER_URLS` for OpenID and SSO attribute scopes.
- Support for multiple key types in `AuthClient` (Ed25519, P-256, secp256k1) with key-type metadata in storage.
- WebCrypto P-256 key generation/import/export for `wasm-js`.
- IndexedDB-backed async storage with LocalStorage fallback and migration for `wasm-js`.
- JS/Rust storage format compatibility helpers plus Playwright-based compat tests.
- `make clean` target for removing example build artifacts, plus new Makefile check/test targets.

### Changed

- Enabled the `rust-analyzer` feature and tightened the wasm target guard.
- Updated frontend examples (auth/note handling, todo refresh on auth state change).
- Updated Internet Identity canister configs and example `dfx.json` settings; deploy Makefile targets removed in favor of `dfx deploy`.
- Bumped npm package version to `0.0.2`, adjusted dependency versions, removed package-locks, and ignored example `Cargo.lock` files.

### Deprecated

- `IdleManager`, `IdleManagerOptions` and `IdleOptions` belong to the v5 API
  only and now say so in their documentation. Upstream removed `IdleManager` in
  v9, and the v11 client has no idle surface: a session is bounded where it is
  issued (`max_time_to_idle` / `max_time_to_live` sent with `sign_in`), and an
  idle-out arrives as `SessionStatus::Expired`. The module stays until the v5
  client is removed, so nothing breaks today; migrate by subscribing to the
  client and reacting to `Expired`.

- The session identity is wired into the client (`client::auth_client`). A
  browser sign-in and a page-load restore now open the rotating
  `SessionIdentity` instead of snapshotting one app delegation: the client mints
  ahead of expiry, replaces the delegation it signs with as it ages, and reports
  a gone session by dropping to anonymous while publishing the record as ended.
  Foreground/activity events drive the refresh (`disable_browser_activity` turns
  it off, and a sign-in in flight stands it down). `get_identity` and `sign_in`
  return `Arc<dyn ic_agent::Identity>` accordingly --- build the agent with
  `with_arc_identity`.
- The session layer's tests now cover the client wiring: restore adopts a live
  app credential instead of re-minting, and a sign-in mints exactly once before
  opening the identity.

- Signing out is now atomic from the application's point of view: it waits for
  the constructor's restore, takes the same lock a ceremony takes (and steals the
  mint lock when the credential store is shared), starts the canister revoke
  before clearing local state, wipes the record and credentials regardless of
  whether the revoke succeeds, and only then reports a revoke failure. A mint
  that loses the lock sees it lost and discards its result, so it cannot write a
  credential back into a slot signing out just cleared.
- Read-only state stores are no longer written through: ending or dropping a
  session on one leaves the record and credentials for a page of the same origin
  to handle, as upstream does, instead of trapping on the platform's assert.
  Sign-in on a read-only store is rejected up front.
- A restore that finishes after `dispose` no longer installs what it found, and
  `instance`s that would keep scheduling rotation for a disposed client are
  stopped.
- A record changed by a peer client or another tab is followed: the change is
  noted without re-hydrating synchronously, and the next `get_identity` re-runs
  the restore (serialised, so two passes cannot install two identities) or
  reports a mismatch it can still see after that.
- The client's locks are one manager per client, shared by the ceremony lock,
  the mint lock and sign-out's steal (`LockManager` default).

- The password-protected native store (Android/Kotlin) now writes a stronger
  format: PBKDF2-HMAC-SHA256 (600k rounds) derives the key and ChaCha20-Poly1305
  encrypts the bundle, replacing the chained-SHA-256 pseudo-KDF, XOR keystream
  and SHA-256 tag of the old format. Files the old format wrote are still read
  and are re-encrypted on the next write, so an upgrade keeps the session. The
  file is written to a temporary sibling and renamed into place, and is `0600` on
  Unix, so a crash cannot truncate it and another local user cannot read it.
- The non-browser sign-in flow now bounds what it accepts: the requested lifetime
  is clamped to 1--1440 minutes (`effective_ttl`), every hop's expiration must sit
  within that lifetime plus a five-minute clock-drift allowance, chains longer
  than `MAX_CHAIN_HOPS` are refused, and a chain rooted at its own leaf is
  refused. The loopback server caps the form body at 1 MiB, requires a
  form-urlencoded content type when one is sent, and compares the nonce in
  constant time.

- The restore path is one code path again: what a page load found is a
  `Restored` value (`Session` credential or native app delegation) and the
  hydrate branches on it, so the test-only `cfg` and the `unreachable!` arm are
  gone and the session identity is opened wherever one exists.
- A mint that answers for an unexpected account is now
  `AuthClientError::AccountMismatch` with an `AuthClientErrorKind` of its own,
  rather than `Other` with a string.
- Leftovers of the removed v5 storage layer are gone: the `storage_keys` alias
  module, the unused `KEY_STORAGE_DELEGATION`/`KEY_STORAGE_KEY_TYPE` constants
  and the `StoredKey::CryptoKeyPair` variant the native stores only ever had to
  reject.

- `get_identity`/`sign_in` now return a `ClientIdentity` handle instead of a bare
  `Arc<dyn Identity>`: it implements `ic_agent::Identity` (so `with_identity` takes
  it directly) and answers `principal()`, `is_anonymous()` and
  `delegation_expires_at_ms()`. The last one is what makes the rotation visible to
  callers: a browser identity's delegation is replaced as it ages.
- The UniFFI `AuthIdentity` gained `delegationExpiresAtMs()` for the same reason,
  and the docs say the handle is a snapshot to re-ask for rather than cache.

- The crate version now names the `ic-agent` pairing: `ic-auth-client 0.49.x`
  is built for `ic-agent 0.49.*`, a new `ic-agent` minor is a new minor here (and
  therefore a cargo-visible breaking bump under 0.x semantics), and patch
  releases are fixes within a pairing. `scripts/check-agent-compat.sh` fails the
  build if the version, `[package.metadata.ic-agent]` and the dependency
  disagree.
- `pub use ic_agent` re-exports the agent this crate is built against. An
  identity is only usable with an agent from the same `ic-agent` instance, so
  applications should take `ic-agent` types from `ic_auth_client::ic_agent`
  rather than adding a second copy to their own `Cargo.toml`.

- Documentation: docs.rs now builds the browser surface (wasm32, `wasm-js`,
  `tracing`), which is the primary one, and the new `Docs` workflow publishes
  both surfaces for the main branch to GitHub Pages (`/wasm`, `/native`) with a
  landing page. `make doc-wasm` / `make doc-native` do the same locally;
  `make doc` is the native one. The two surfaces cannot share a build: the
  browser stores are not `Send`, which the native bounds require.

- Dependency version requirements are now floors rather than the versions this
  crate happened to be developed against: `thiserror = "2"`, `serde = "1"`,
  `serde_json = "1"`, `base64 = "0.23"`, `bon = "3"`, `ed25519-dalek = "3"`,
  `rand = "0.10"`, `web-sys = "0.3"`, `uniffi = "0.32"` and the rest of the
  non-crypto stack. An application is no longer forced onto, say,
  `thiserror 2.0.21` --- which mattered in practice: `pocket-ic 16.1` pins
  `thiserror = 2.0.18`, so the previous requirement made the two impossible to
  use in one workspace. `ic-agent` (the pairing) and the RustCrypto generation
  it needs are relaxed to their minor (`"0.49"`, `"0.13"`, `"0.10"`), and
  `keyring` to `"4.1"` --- its test helper now triggers the platform store
  through `Entry::new` rather than the `4.2`-only `store_status`.

### Removed

- **BREAKING**: the pre-v11 client. `AuthClient::builder()`,
  `AuthClientLoginOptions`, `login()`/`logout()`, `NativeAuthClient`, the
  `api` module (`InternetIdentityAuthRequest` and friends), `IdleOptions` /
  `IdleManager`, the `callback` module and the v5 storage helpers are gone: this
  crate is v11-only now. `IdleManager`'s job belongs to the identity provider
  (`max_time_to_idle` / `max_time_to_live` on `sign_in`, surfaced as
  `SessionStatus::Expired`), so there is nothing to replace it with.
- **BREAKING**: `ii-bridge/`. A non-browser sign-in no longer needs a hosted
  bridge page: Internet Identity completes the ceremony on its own page and posts
  the delegation to a loopback listener.
- **BREAKING**: the removed `dependencies` for the deleted modules (`rdev`,
  `portpicker`, unused `gloo-*`/`wasm-timer`/`serde-wasm-bindgen`,
  `percent-encoding`, `web-time`, `serde_bytes`, `serde_test`).
- **BREAKING**: the UniFFI surface was rewritten for the v11 client. `login`
  no longer takes a bridge URL (it drives the browser flow itself); `logout`
  returns a result; the secp256k1 raw-key accessors and `sign_ic_request` are
  gone in favour of `AuthIdentity::sign_arbitrary` plus
  `delegation_chain_json`.

### Documentation

- Added `docs/port/`: the specification the port follows --- protocol and flow
  contracts (`protocols/`, 9 files), storage/session contracts (`state/`, 8
  files), each citing upstream `file:line`, plus `DESIGN.md` (architecture,
  decisions, progress log).

### Fixed

- The IndexedDB credential store reads its records back again. `CryptoKeyPair` is
  a WebIDL dictionary, so `JsCast` refused the pair that came back from
  IndexedDB and every stored credential read as absent --- a page reload
  re-signed in and signing out could not revoke the session. `p256::key_pair_from_value`
  builds the pair from `privateKey`/`publicKey` when the cast refuses.
- Handle JS Ed25519 key-length variants during format detection.
- Temporarily increased the auth popup height for II 2.0.

## [0.5.0-beta.0] - 2026-01-19

### Added

- Native app implementations for `auth_client`, `idle_manager`, and `storage` modules
- Native app support via OS-level integrations (`keyring`, `chrono`, `url`)
- Public API types (`InternetIdentityAuthRequest`, `IdentityServiceResponseMessage`, `IdentityServiceResponseKind`) for external usage

### Changed

- **BREAKING**: Updated `ic-agent` dependency to **v0.45**.
- **BREAKING**: Restructured codebase with platform-specific modules (`auth_client`, `idle_manager`, `storage`)
- **BREAKING**: WASM-specific dependencies (`gloo-*`, `web-sys`) now optional behind `wasm-js` feature flag
- **BREAKING**: `AuthClient` methods `login()` and `logout()` now use `&self` instead of `&mut self`
- **BREAKING**: `web_sys::Url` used in `AuthClientLoginOptions` has been replaced with `String`. This is a specification change to prepare for future platform compatibility
- **BREAKING**: Several changes have been made to the configuration of builder methods for optional structures
- `on_success` and `on_error` can now be used with both synchronous and asynchronous closures
- Improved resource management in WASM with RAII pattern using `ActiveLogin` struct
- Replaced custom sleep utility with `gloo-timers` for better async compatibility
- Aligned native app flow with platform-agnostic interfaces

- Signing out is now atomic from the application's point of view: it waits for
  the constructor's restore, takes the same lock a ceremony takes (and steals the
  mint lock when the credential store is shared), starts the canister revoke
  before clearing local state, wipes the record and credentials regardless of
  whether the revoke succeeds, and only then reports a revoke failure. A mint
  that loses the lock sees it lost and discards its result, so it cannot write a
  credential back into a slot signing out just cleared.
- Read-only state stores are no longer written through: ending or dropping a
  session on one leaves the record and credentials for a page of the same origin
  to handle, as upstream does, instead of trapping on the platform's assert.
  Sign-in on a read-only store is rejected up front.
- A restore that finishes after `dispose` no longer installs what it found, and
  `instance`s that would keep scheduling rotation for a disposed client are
  stopped.
- A record changed by a peer client or another tab is followed: the change is
  noted without re-hydrating synchronously, and the next `get_identity` re-runs
  the restore (serialised, so two passes cannot install two identities) or
  reports a mismatch it can still see after that.
- The client's locks are one manager per client, shared by the ceremony lock,
  the mint lock and sign-out's steal (`LockManager` default).

- The password-protected native store (Android/Kotlin) now writes a stronger
  format: PBKDF2-HMAC-SHA256 (600k rounds) derives the key and ChaCha20-Poly1305
  encrypts the bundle, replacing the chained-SHA-256 pseudo-KDF, XOR keystream
  and SHA-256 tag of the old format. Files the old format wrote are still read
  and are re-encrypted on the next write, so an upgrade keeps the session. The
  file is written to a temporary sibling and renamed into place, and is `0600` on
  Unix, so a crash cannot truncate it and another local user cannot read it.
- The non-browser sign-in flow now bounds what it accepts: the requested lifetime
  is clamped to 1--1440 minutes (`effective_ttl`), every hop's expiration must sit
  within that lifetime plus a five-minute clock-drift allowance, chains longer
  than `MAX_CHAIN_HOPS` are refused, and a chain rooted at its own leaf is
  refused. The loopback server caps the form body at 1 MiB, requires a
  form-urlencoded content type when one is sent, and compares the nonce in
  constant time.

- The restore path is one code path again: what a page load found is a
  `Restored` value (`Session` credential or native app delegation) and the
  hydrate branches on it, so the test-only `cfg` and the `unreachable!` arm are
  gone and the session identity is opened wherever one exists.
- A mint that answers for an unexpected account is now
  `AuthClientError::AccountMismatch` with an `AuthClientErrorKind` of its own,
  rather than `Other` with a string.
- Leftovers of the removed v5 storage layer are gone: the `storage_keys` alias
  module, the unused `KEY_STORAGE_DELEGATION`/`KEY_STORAGE_KEY_TYPE` constants
  and the `StoredKey::CryptoKeyPair` variant the native stores only ever had to
  reject.

- The crate version now names the `ic-agent` pairing: `ic-auth-client 0.49.x`
  is built for `ic-agent 0.49.*`, a new `ic-agent` minor is a new minor here (and
  therefore a cargo-visible breaking bump under 0.x semantics), and patch
  releases are fixes within a pairing. `scripts/check-agent-compat.sh` fails the
  build if the version, `[package.metadata.ic-agent]` and the dependency
  disagree.
- `pub use ic_agent` re-exports the agent this crate is built against. An
  identity is only usable with an agent from the same `ic-agent` instance, so
  applications should take `ic-agent` types from `ic_auth_client::ic_agent`
  rather than adding a second copy to their own `Cargo.toml`.

- Documentation: docs.rs now builds the browser surface (wasm32, `wasm-js`,
  `tracing`), which is the primary one, and the new `Docs` workflow publishes
  both surfaces for the main branch to GitHub Pages (`/wasm`, `/native`) with a
  landing page. `make doc-wasm` / `make doc-native` do the same locally;
  `make doc` is the native one. The two surfaces cannot share a build: the
  browser stores are not `Send`, which the native bounds require.

### Removed

- Custom `sleep` utility module (replaced by `gloo-timers`)
- Thread-local HashMap storage for authentication resources

### Dependencies

- Added: `parking_lot`, `futures`, native-specific dependencies (`keyring`, `chrono`, `url`)
- Updated: `gloo-timers` with `futures` feature
- Made optional: WASM-specific dependencies behind feature flags

## [0.4.1] - 2025-09-13

### Refactored

- Resolved `IdleManager` initialization bug that caused web pages to freeze.

## [0.4.0] - 2025-09-12 [YANKED]

### Changed

- **Breaking**: Updated `ic-agent` dependency to **v0.44**.
- **Breaking**: Deprecate the `ed25519-consensus` crate for private keys and use `ic-ed25519` instead.
- Internal values now update correctly upon login/logout, eliminating the need for page refreshes.
- Bump MSRV from `1.56.0` to `1.85.0`.

### Refactored

- Nearly all instances of `unwrap()` have been removed and replaced with error messages via [tracing](https://crates.io/crates/tracing) crate. If debugging is required, use the `tracing` feature and [tracing-wasm](https://crates.io/crates/tracing-wasm) or similar tools depending on your environment.

## [0.4.0-alpha] - 2025-04-16

### Added

- `AuthClient` and `IdleManager` are now thread-safe.

### Changed

- **Breaking**: Updated `ic-agent` dependency to **v0.40**.
  This version is **not** compatible with previous versions.

- Signing out is now atomic from the application's point of view: it waits for
  the constructor's restore, takes the same lock a ceremony takes (and steals the
  mint lock when the credential store is shared), starts the canister revoke
  before clearing local state, wipes the record and credentials regardless of
  whether the revoke succeeds, and only then reports a revoke failure. A mint
  that loses the lock sees it lost and discards its result, so it cannot write a
  credential back into a slot signing out just cleared.
- Read-only state stores are no longer written through: ending or dropping a
  session on one leaves the record and credentials for a page of the same origin
  to handle, as upstream does, instead of trapping on the platform's assert.
  Sign-in on a read-only store is rejected up front.
- A restore that finishes after `dispose` no longer installs what it found, and
  `instance`s that would keep scheduling rotation for a disposed client are
  stopped.
- A record changed by a peer client or another tab is followed: the change is
  noted without re-hydrating synchronously, and the next `get_identity` re-runs
  the restore (serialised, so two passes cannot install two identities) or
  reports a mismatch it can still see after that.
- The client's locks are one manager per client, shared by the ceremony lock,
  the mint lock and sign-out's steal (`LockManager` default).

- The password-protected native store (Android/Kotlin) now writes a stronger
  format: PBKDF2-HMAC-SHA256 (600k rounds) derives the key and ChaCha20-Poly1305
  encrypts the bundle, replacing the chained-SHA-256 pseudo-KDF, XOR keystream
  and SHA-256 tag of the old format. Files the old format wrote are still read
  and are re-encrypted on the next write, so an upgrade keeps the session. The
  file is written to a temporary sibling and renamed into place, and is `0600` on
  Unix, so a crash cannot truncate it and another local user cannot read it.
- The non-browser sign-in flow now bounds what it accepts: the requested lifetime
  is clamped to 1--1440 minutes (`effective_ttl`), every hop's expiration must sit
  within that lifetime plus a five-minute clock-drift allowance, chains longer
  than `MAX_CHAIN_HOPS` are refused, and a chain rooted at its own leaf is
  refused. The loopback server caps the form body at 1 MiB, requires a
  form-urlencoded content type when one is sent, and compares the nonce in
  constant time.

- The restore path is one code path again: what a page load found is a
  `Restored` value (`Session` credential or native app delegation) and the
  hydrate branches on it, so the test-only `cfg` and the `unreachable!` arm are
  gone and the session identity is opened wherever one exists.
- A mint that answers for an unexpected account is now
  `AuthClientError::AccountMismatch` with an `AuthClientErrorKind` of its own,
  rather than `Other` with a string.
- Leftovers of the removed v5 storage layer are gone: the `storage_keys` alias
  module, the unused `KEY_STORAGE_DELEGATION`/`KEY_STORAGE_KEY_TYPE` constants
  and the `StoredKey::CryptoKeyPair` variant the native stores only ever had to
  reject.

- The crate version now names the `ic-agent` pairing: `ic-auth-client 0.49.x`
  is built for `ic-agent 0.49.*`, a new `ic-agent` minor is a new minor here (and
  therefore a cargo-visible breaking bump under 0.x semantics), and patch
  releases are fixes within a pairing. `scripts/check-agent-compat.sh` fails the
  build if the version, `[package.metadata.ic-agent]` and the dependency
  disagree.
- `pub use ic_agent` re-exports the agent this crate is built against. An
  identity is only usable with an agent from the same `ic-agent` instance, so
  applications should take `ic-agent` types from `ic_auth_client::ic_agent`
  rather than adding a second copy to their own `Cargo.toml`.

- Documentation: docs.rs now builds the browser surface (wasm32, `wasm-js`,
  `tracing`), which is the primary one, and the new `Docs` workflow publishes
  both surfaces for the main branch to GitHub Pages (`/wasm`, `/native`) with a
  landing page. `make doc-wasm` / `make doc-native` do the same locally;
  `make doc` is the native one. The two surfaces cannot share a build: the
  browser stores are not `Send`, which the native bounds require.

### Removed

- **Breaking**: Removed `IdentityType`.
  Use `ArcIdentity` as a replacement.

### Refactored

- **Breaking**: Reorganized some internal build patterns.
  These changes may impact specific build or integration scenarios.

## [0.3.1] - 2024-11-14

- Relaxed version specification of dependencies.
- Improved inner error handling.

## [0.3.0] - 2024-11-11

- Breaking: Updated dependency to `ic-agent` v0.39. Not compatible with previous versions.
- Using `ed25519-consensus` instead of `ring` to create `BasicIdentity`.
- Removes warning that users found unhelpful, when a message originates from other sources than the identity provider during authentication.

## [0.2.1] - 2024-09-24

- Updated dependency to `ic-agent` v0.38.

## [0.2.0] - 2024-09-11

- Breaking: `AuthClient::login()` and `AuthClient::login_with_options()` become synchronous.
