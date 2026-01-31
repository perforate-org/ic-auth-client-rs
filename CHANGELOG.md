# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

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

### Fixed

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
