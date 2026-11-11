# §10 — Mapping to the current Rust crate, required changes, and Rust-specific risks

Read-only survey of `/Users/yota/dev/ic-auth-client-rs` at `0.5.0-beta.0`
(`rust:` prefixes below). The crate is a faithful **v5** port: builder + `login()` +
callbacks + `IdleManager` + a single `storage`/`key_type` pair, and a native flow that
predates ICRC-29/167.

## 10.1 Per-flow mapping

| Upstream flow | Upstream source | Current Rust implementation | What must change / be added |
| --- | --- | --- | --- |
| Client construction | `auth-client.ts:427-587` | `AuthClientBuilder` + `AuthClient::builder()` (`rust:src/auth_client/wasm_js.rs:127,1505-1600`), options in `rust:src/option/wasm_js.rs` | Replace with `AuthClient::new(AuthClientCreateOptions)`; new option set (§1.2.2); drop `identity`, `key_type`, `idle_options`; add credential/state stores, namespace, transport, provider pair, SSO/openid/prompt/hint/resumable/agentOptions |
| State model + status | `auth-client.ts:747-759`, `slots.ts` | none (identity held in `AuthClientInner`) | **New module** `session_state` + `slots`; synchronous `StateStorage` trait; `SessionStatus` |
| Restore/hydrate | `auth-client.ts:1665-1808` | `wasm_js.rs:180-360` reads `KEY_STORAGE_KEY`/`KEY_STORAGE_DELEGATION` and builds the identity directly | Rework: session slot + app slot + state record; `SessionNotHeld`; `AccountMismatch`; `expired` vs `signed-out`; retry-after-failure init |
| `signIn` window transport | `auth-client.ts:944-1099`, signer `PostMessageTransport` | `wasm_js.rs:1140-1420` — opens `idpWindow`, URL `#authorize`, `postMessage` `kind:"authorize-client"`, listens for `authorize-ready`/`authorize-client-success`/`authorize-client-failure` (`rust:src/api.rs:14-96`) | **Replace protocol**: ICRC-29 heartbeat + JSON-RPC `ii_session_delegation`; then mint app delegation via canister; then store/commit; no `authorize-client` message |
| `signIn` redirect transport | `auth-client.ts:1112-1161`, signer `UrlTransport` | none | **New**: ICRC-167 transport + journal + `memoize`; durable-store requirement |
| Session key | `auth-client.ts:1103-1161` | one base key persisted under `KEY_STORAGE_KEY` (`wasm_js.rs:191-351`) | **New**: per-sign-in key (window) / pending slot (redirect); session key is not the base key |
| Session delegation | `session-delegation.ts` | v5 `authorize-client` response (`rust:src/api.rs:38-45`) | **New** JSON-RPC request/response + validation |
| App delegation mint | `session-minter.ts` | none (II handed a delegation in v5) | **New** canister calls `app_prepare_delegation`/`app_get_delegation`; `SessionMinter` |
| App delegation rotation | `session-identity.ts` | none | **New** `SessionIdentity` (pre-mint, single-flight, block margin) |
| Mint lock / sign-in lock | `app-lock.ts` | none | **New** lock abstraction + Web Locks binding |
| `signOut` | `auth-client.ts:1389-1452` | `logout()` (`wasm_js.rs`; `native.rs:1094`) | Async; revoke session at canister; wipe `session`+`app`; steal mint lock; `returnTo` with `assign` |
| `requestAttributes` | `auth-client.ts:1187-1244` | none | **New**: `ii-icrc3-attributes`, nonce callback, redirect journaling |
| Notification consent | `notification-consent.ts` | none | **New**: signer method + two canister methods |
| SSO | `sso.ts` | none | **New**: `normalize_sso_domain`, checker task, two canister methods, URL param |
| `subscribe`/`dispose` | `auth-client.ts:782-823` | `IdleManager` callbacks (`rust:src/idle_manager.rs`) | Replace with state subscription + browser-listener teardown; delete idle manager |
| `watchForeground`/`watchActivity` | `foreground-refresh.ts` | `IdleManager` listens to the same DOM events to *end* a session (`rust:src/idle_manager/wasm_js.rs`) | Invert the purpose: same events now *refresh*; export as `wasm-js` helpers |
| Storage | `credentials/*`, `state/*` | `AuthClientStorage` (`rust:src/storage/async_storage.rs`), `StoredKey`, `KEY_STORAGE_*` (`rust:src/storage.rs:16-27`), `js_compat` format compat | Split into two traits; new slot names; keep JS-format compat only if old data must be read |
| `OPENID_PROVIDER_URLS`, `scopedKeys` | `auth-client.ts:62-72,1921-1971` | none | **New** pure functions |
| Native browser flow | none upstream (browser-only package, `installation.mdx:29`) | `NativeAuthClient::login` — loopback `tiny_http` server, `webbrowser::open`, II native query params (`rust:src/auth_client/native.rs:1002-1075`) | **Out of scope / must be re-scoped**: no v11 equivalent. Keep as legacy or reimplement against a browser-capable host (design proposal §10.6) |
| UniFFI surface | n/a | `rust:src/uniffi_bindings.rs:25-219` (`LoginOptions`, `AuthClient`, `AuthIdentity`, `login(auth_bridge_url, …)`, `build_login_url`, `finish_login_from_payload`, `logout`) | Re-shape to the new API: async methods, `SessionStatus`/`SsoStatus` enums, new errors; the `ii-bridge` native flow stays a host concern |

## 10.2 Module layout proposal (design proposal)

Mirrors upstream file boundaries so the spec maps 1:1:

```
src/
  auth_client.rs              // facade: AuthClient + options (wasm-js)
  auth_client/                // (native legacy kept separate)
  slots.rs                    // Slots, slots_for(namespace)
  session/
    mod.rs
    session_delegation.rs     // ii_session_delegation request/response
    session_minter.rs         // app_prepare_delegation/app_get_delegation/app_revoke_session
    session_identity.rs       // rotating DelegationIdentity
    app_delegation_source.rs  // trait + SessionGone/SessionUnsupported/AccountMismatch
    app_lock.rs               // MintLock/HeldLock over Web Locks (no-op fallback)
  credentials/
    mod.rs                    // Credential, CredentialStorage trait
    idb.rs / local.rs / memory.rs / shared_memory.rs
  state/
    mod.rs                    // SessionState, StateStorage trait
    local.rs / cookie.rs / memory.rs
  transport/                  // (wasm-js) ICRC-29 + ICRC-167
    signer.rs                 // JSON-RPC client, transforms, channel lifecycle
    post_message.rs           // heartbeat + channel
    url_transport.rs          // journal + replay
  sso.rs
  notification_consent.rs
  foreground_refresh.rs
```

## 10.3 Per-file change list (concrete)

| Rust file | Verdict | Notes |
| --- | --- | --- |
| `rust:src/api.rs` | **delete/replace** | `InternetIdentityAuthRequest` (`kind:"authorize-client"`) and `IdentityServiceResponseMessage` (`authorize-ready`/`-success`/`-failure`) are the v5 wire protocol, gone in v11. Replace with JSON-RPC request/response types + the three `ii_*` method params. |
| `rust:src/auth_client/wasm_js.rs` | **rewrite** | Keep: `window.open` plumbing, event listener wiring, `web_sys` imports. Replace: login flow, storage, idle manager, callbacks. |
| `rust:src/auth_client/native.rs` | **re-scope** | Keep the loopback HTTP server as a host-side legacy flow; it cannot implement ICRC-29/167 without a browser. |
| `rust:src/idle_manager.rs`, `idle_manager/*` | **delete** | Replaced by `SessionStatus::Expired` + `watch_foreground`/`watch_activity`. |
| `rust:src/key.rs` | **reduce** | Keep `ArcIdentity`, `BaseKeyType`; delete the persisted-base-key model and `KEY_STORAGE_KEY_TYPE`. Key generation moves to the credential store (`create()`). |
| `rust:src/option.rs`, `option/*` | **rewrite** | New create/sign-in option structs; delete idle options, `on_success`/`on_error`, `timeout`, `custom_values`, `allow_pin_authentication`, `targets`. |
| `rust:src/storage.rs`, `storage/*` | **split** | `CredentialStorage` (async) + `StateStorage` (sync). Keep `js_compat` only as a migration reader. |
| `rust:src/uniffi_bindings.rs` | **rewrite** | See §10.7. |
| `rust:src/util/delegation_chain.rs` | **extend** | Already has `is_delegation_valid` and JSON (de)serialisation (`:15-89`); add `earliest_expiration`, `delegates_to`, `chain_authorises_key`, `assert_chain_reaches`. |
| `rust:src/util/callback.rs` | **delete** | Promise-based API replaces `OnSuccess`/`OnError`. |
| `rust:src/util/arc_identity.rs` | **keep** | Still the identity abstraction; `SessionIdentity` must be able to sit behind it (upstream `SessionIdentity extends DelegationIdentity`). |
| `rust:ii-bridge/` | **keep (native only)** | Out of the browser protocol layer. |

## 10.4 Rust-specific problems and proposals

### 10.4.1 Popup must open inside the click task

Upstream refuses to open a window outside a click handler
(`postMessageTransport.js:7-13,66-69`) because Chromium/Safari block it, and it takes the
channel lock **after** the window exists for the same reason (`auth-client.ts:869-876`).

**Design proposal:** `AuthClient::sign_in(&self, options) -> SignIn` where `SignIn` is a
handle created synchronously (opens the popup and hands the request to the signer), and
`SignIn: Future<Output = Result<ArcIdentity, AuthError>>`. Do **not** expose
`async fn sign_in()`: an async fn's body starts on first poll, which is too late.
Document that `sign_in` must be called from a DOM event handler in `wasm-js`.

### 10.4.2 Web Locks / BroadcastChannel / `storage` events

`web-sys` has no `navigator.locks` and no `LockManager` types. Upstream relies on them for
(a) the channel/sign-in/mint locks, (b) `SharedMemoryCredentialStorage` replication and
peer-presence detection, (c) `LocalStateStorage` worker mirroring
(`app-lock.ts`, `shared-memory-credential-storage.ts:160-227`,
`local-state-storage.ts:129-207`).

**Design proposal:** declare minimal `#[wasm_bindgen]` externs
(`navigator.locks.request/query`, `BroadcastChannel`) in a `wasm-js`-only module, and
implement every use behind traits with a documented no-op fallback — upstream itself makes
coordination optional (`app-lock.ts:1-18`). For `Send`-friendly code, the traits must not be
`Send` in `wasm-js`; gate them with `#[cfg(target_arch = "wasm32")]`.

### 10.4.3 IndexedDB and non-extractable `CryptoKeyPair`

`IdbCredentialStorage` stores a structured-cloned `CryptoKeyPair` whose private half is
non-extractable (`idb-credential-storage.ts:5-9,49-76`). The current crate already has
`StoredKey::CryptoKeyPair(web_sys::CryptoKeyPair)` (`rust:src/storage.rs:45-47`) and an
`idb` dependency, so this is feasible — but `web_sys::CryptoKeyPair` is not `Serialize`,
so it must be stored as a raw JS value through the `idb` crate's `JsValue` path, and every
read must be re-wrapped into the identity. Add a test that the private half is not
exportable (`crypto_subtle.export_key` must fail), mirroring
`tests/client/credentials/credential-storage.test.ts:55-60`.

### 10.4.4 Promise-of-request and call-order slots

The signer's `sendRequest(request | Promise<request>)` reserves the call-order slot on the
call (`signer.js:252-284`; `urlChannel.js:58-68`). A plain Rust `async fn send(req)` cannot
express this: the future's argument is evaluated before the call, which is fine, but the
*slot* must be reserved even when the request's inputs are not ready.

**Design proposal:**

```rust
pub trait Channel {
    fn reserve(&self) -> Slot;                       // synchronous, call order
    fn send_at(&self, slot: Slot, req: JsonRpcRequest) -> BoxFuture<'_, Result<JsonRpcResponse, SignerError>>;
    fn close(&self) -> BoxFuture<'_, ()>;
}
```

`AuthClient::request_attributes` then does: `let slot = channel.reserve();` → build the
nonce future → `send_at(slot, req)` after the nonce resolves (window) or from the journal
(redirect). This is the Rust equivalent of the promise-of-request contract and must be
documented as such.

### 10.4.5 The redirect load never completes its awaited request

On the navigating load, the awaited response never arrives — the page unloads
(`urlChannel.d.ts` docs; `auth-client-redirect.test.ts:102-111` fake models it by leaving
the request pending). Rust must not treat the dropped future as an error, must not leak a
timer, and must not write anything after unload. **Design proposal:** the redirect
`sign_in` future is allowed to be dropped; all journaling happens *before*
`location.assign`, and the commit path runs only on the return load when the journal
replays.

### 10.4.6 BigInt / nanoseconds on the wire

Every ns value is a **decimal string** in JSON (`session-delegation.ts:84-92`;
`signer.js:38-47,532`) and the JSON-clean transform throws on BigInt. Rust `u64`/`i64` are
fine for Candid but must be serialised as strings in JSON-RPC params and parsed from
strings in responses (reject >20 digits / ≥2^64). Never `serde_json::Number` for these.

### 10.4.7 Native / non-browser hosts

Upstream is browser-only (`installation.mdx:29`), and both transports need a DOM:
`window.open` + `postMessage`, or top-level navigation + `sessionStorage` + `history`.
The v5 native flow (`rust:src/auth_client/native.rs:1002-1028`: loopback `tiny_http`
callback + `webbrowser::open` with `redirectUri/pubkey/keyType/…` query params) is an
**II native-app protocol with no v11 counterpart**.

**Design proposal (clearly non-upstream):** keep `NativeAuthClient` as a legacy,
feature-gated flow, and do not claim v11 parity for it. If a native v11-compatible flow is
required, the closest design is a host-supplied *redirect transport*: the host opens a
system browser at the authorize URL with an ICRC-167-style fragment
(`message`/`callback`/`state`), receives the response via a universal link / loopback HTTP
callback, and feeds the JSON-RPC responses back into the same journal interface. That is a
design proposal, not upstream behaviour, and it must be marked as such in the crate docs.

### 10.4.8 UniFFI

`uniffi 0.31` supports async methods, but the exported surface is flat. Proposed:

| Current (`rust:src/uniffi_bindings.rs`) | Proposed |
| --- | --- |
| `LoginOptions { identity_provider, max_time_to_live, allow_pin_authentication, derivation_origin, window_opener_features, timeout_millis, custom_values_json }` (`:25-42`) | `SignInOptions { max_time_to_live_ns: Option<u64>, max_time_to_idle_ns: Option<u64>, return_to: Option<String> }`; provider configuration moves to a `CreateOptions` record |
| `AuthClient::new(service_name)` (`:79-81`) | `AuthClient::new(credential_storage, state_storage)` or host-provided storage objects; no service name |
| `login(auth_bridge_url, options)` (`:271-306`) | `sign_in(options)` async + `sign_out(options)` async |
| `logout()` (`:219`) | `sign_out` |
| `is_authenticated`/`principal_text` | keep, plus `status() -> SessionStatus` and `sso_status() -> Option<SsoStatus>` (uniffi enums) |
| `AuthError::Message/InvalidCustomValues/Principal/Signature/Key` | add `SessionGone`, `SessionNotHeld`, `InteractionRequired { reason }`, `NotificationsUnsupported`, `Superseded`, `Signer { code, message }` |
| callbacks (`on_success`/`on_error`) | none; async result replaces them |

A `subscribe` callback across FFI needs a listener object; propose
`#[uniffi::export(callback_interface)] trait AuthListener { fn on_change(&self); }` — a
design proposal, since upstream's `subscribe` returns an unsubscribe closure.

## 10.5 The five biggest risks (ranked)

1. **Popup-gesture + Rust future model** (§10.4.1). If `sign_in` is an `async fn`, every
   browser blocks the popup. This is the most likely "works in tests, fails in Safari"
   defect, and it shapes the public API.
2. **Redirect replay / promise-of-request** (§10.4.4, §10.4.5). Slot reservation, batching,
   divergence guards and a future that never resolves are all foreign to idiomatic Rust.
   Getting the journal wrong silently re-fetches a single-use nonce or signs against a
   different key.
3. **Web Locks / cross-tab coordination** (§10.4.2). No `web-sys` support; without it,
   multiple tabs mint N delegations and a sign-out cannot interrupt an in-flight mint.
   Upstream tolerates absence but not incorrectness.
4. **Non-extractable key storage in IndexedDB** (§10.4.3). The security property (private
   key never leaves the browser's key store) is easy to lose when bridging `web-sys` ↔
   `idb`; needs an explicit non-exportability test.
5. **Native/UniFFI scope mismatch** (§10.4.7, §10.4.8). v11 is browser-only; the existing
   native flow and `ii-bridge` cannot be "ported" — they must be kept as a separately
   documented legacy path, and the UniFFI surface re-shaped around async + enums.

Secondary: exact error-taxonomy preservation (`SessionGone` vs `InteractionRequired` vs
`SessionNotHeld` vs `Superseded`) because callers branch on it; `expired` vs `signed-out`
because UIs say different things; the stable-status-object requirement is a JS-framework
concern only and should be documented, not emulated.

## Rust port checklist

- [ ] Create the module layout in §10.2 (or an equivalent that keeps the file boundaries).
- [ ] Delete `api.rs` v5 wire types, `idle_manager`, `util/callback.rs`; rewrite
      `option*`, `auth_client/wasm_js.rs`, `uniffi_bindings.rs`.
- [ ] Provide `SignIn`-handle API so `window.open` runs in the click task.
- [ ] Add `wasm-bindgen` externs for Web Locks / BroadcastChannel with no-op fallbacks.
- [ ] Keep `CryptoKeyPair` non-extractable storage and test non-exportability.
- [ ] Introduce `Slot` reservation in the `Channel` trait; document the redirect
      never-completing-future contract.
- [ ] Serialise ns values as decimal strings everywhere on the JSON-RPC wire.
- [ ] Mark native and `ii-bridge` as legacy/non-upstream in docs; do not claim v11 parity.
- [ ] Re-shape UniFFI around async methods + enums + listener interface.
