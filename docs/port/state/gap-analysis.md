# Upstream v11.2.0 → Rust port — Gap Analysis & API Design Proposal

Target port: `/Users/yota/dev/ic-auth-client-rs`, crate `ic-auth-client` 0.5.0-beta.0.
Upstream: `/tmp/icp-js-auth`, `@icp-sdk/auth` **11.2.0**.
Companion specs: `state-storage.md`, `credential-storage.md`, `session-layer.md`,
`idle-and-foreground.md`, `subscriptions-and-status.md`, `test-inventory.md`.

**Status legend**: `implemented` = behaviour matches upstream; `partial` = some piece exists but
the upstream contract is not met; `missing` = nothing equivalent; `n/a` = browser-only facility
with no faithful native analogue (a proposal is given instead).

**Citation convention**: `up:` = upstream path relative to `/tmp/icp-js-auth`; `rs:` = path
relative to `/Users/yota/dev/ic-auth-client-rs`.

> **Note on concurrent work (2026-11-11).** The "Current Rust" column describes the **shipped v5
> layer** (`src/auth_client/*`, `src/storage*`, `src/idle_manager*`, `src/key.rs`, `src/util/*`) that
> the crate implements today. While this analysis was written, a v11 port was being created
> concurrently under `src/client/` and `src/signer/` by another workstream (files appeared at
> 21:32-21:40 local time and `src/lib.rs` gained `pub mod client;`). Those new files are **not**
> assessed here. If they land, re-check each status against them; the table remains the checklist of
> concepts that must exist, and §2 is the intended shape.

---

## 1. Master gap table

### 1.1 State layer (who is signed in)

| # | Upstream concept | Upstream ref | Current Rust | Status | Proposal |
|---|---|---|---|---|---|
| 1 | `SessionState {principal, expiration, held}` record | up:`src/client/state/state-storage.ts:12-31` | none; auth is derived from the delegation (`rs:src/auth_client/wasm_js.rs:1122-1138`, `rs:src/auth_client/native.rs:443-459`) | **missing** | Add `state` module with `SessionState` + `StateStorage` |
| 2 | `StateStorage` trait (get/set/remove/discard/subscribe/resumable/isReadOnly/ready) | up:`state-storage.ts:49-112` | none | **missing** | Trait as in §2.1 |
| 3 | `MemoryStateStorage` | up:`memory-state-storage.ts:10-75` | none | **missing** | `MemoryStateStorage` (instance-local `Mutex<HashMap>`) |
| 4 | `LocalStateStorage` (localStorage `<principal>\|<ns>`, per-origin claim) | up:`local-state-storage.ts:38-216` | none; `localStorage` is used for credentials only (`rs:src/storage/async_storage.rs:16-126`) | **missing** | `LocalStateStorage` for `wasm-js` |
| 5 | Worker mirror (`auth-client-state-db`/`ic-keyval`, value `{raw}`, BroadcastChannel `ic-session-state`) | up:`local-state-storage.ts:5-9,181-207` | none | **missing** | Mirror store + channel; `ready()` future |
| 6 | `CookieStateStorage` (domain-wide record, `held` per origin, 400-day Max-Age) | up:`cookie-state-storage.ts:59-304` | none | **missing / n/a native** | `wasm-js` only; native = file-backed store, no sharing |
| 7 | Cross-subdomain sign-in (`prompt:'none'`, `hint`, `resumable`) | up:`auth-client.ts:184-230,545-555`; up:`docs/.../v9.md:96-102` | none | **missing** | Add `prompt`/`hint`/`resumable` options + URL params |
| 8 | Slot names + namespace (`session`, `session-pending`, `app`, `app-pending`, `ic-session-state`) | up:`src/client/slots.ts:17-78` | fixed keys `identity`/`delegation`/`key-type`/`iv`, no namespace (`rs:src/storage.rs:16-35`) | **partial** | One `Slots` struct with `:` namespacing |
| 9 | State expiry / `expired` with principal | up:`auth-client.ts:746-759` | `DelegationChain::is_delegation_valid` checks expiry only (`rs:src/util/delegation_chain.rs:84-115`) | **partial** | Add status enum + lazy expiry check |
| 10 | `signed-in-elsewhere` | up:`auth-client.ts:330-331` | none | **missing** | Derived from `held == false` |
| 11 | Subscription (`subscribe`/`dispose`, status before listeners) | up:`auth-client.ts:761-815` | none; no change notification | **missing** | `subscribe`/`Subscription` + `dispose` |
| 12 | Read-only store/client (worker) | up:`auth-client.ts:1842-1844` | none | **missing** | `is_read_only()` + `ReadOnly` error |
| 13 | Redirect journal / `memoize` | up:`auth-client.ts:1338-1382`; dependency `@icp-sdk/signer` | none | **missing** | Own transport; host-owned journal (native) |
| 14 | Pending redirect key slot `session-pending` | up:`auth-client.ts:1112-1261` | none | **missing** | Slot + durable-store check |

### 1.2 Credential layer (key + delegation)

| # | Upstream concept | Upstream ref | Current Rust | Status | Proposal |
|---|---|---|---|---|---|
| 15 | `Credential { identity, chain? }` as one record | up:`credentials/credential-storage.ts:12-20` | key and chain stored separately (`rs:src/storage.rs:17-19`; written at `rs:src/auth_client/wasm_js.rs:935-1015`, `rs:src/auth_client/native.rs:500-545`) | **partial** | New `Credential` type; stores key+chain as one value |
| 16 | `CredentialStorage` trait with `shared`/`durable`/`create` | up:`credential-storage.ts:32-56` | `AuthClientStorage` get/set/remove/contains/clear (`rs:src/storage/async_storage.rs:341-389`, `rs:src/storage/sync_storage.rs:21-54`) | **partial** | New trait; keep old one private for migration |
| 17 | `IdbCredentialStorage` (DB `auth-client-db`, store `ic-keyval`, version 1, `{keyPair, chain?}`) | up:`credentials/idb-credential-storage.ts:20-82`, up:`db.ts:4-53` | `IdbStorage` with same names, version hardcoded 1, **opens a new DB per operation** (`rs:src/storage/async_storage.rs:134-191`) | **partial** | Cache connection, upgrade-clears, `terminated` + `InvalidStateError` retry |
| 18 | IDB connection recovery (force-close, retry once) | up:`db.ts:89-127` | none | **missing** | `KeyValueDb` trait + recovery logic |
| 19 | IDB migration policy (version bump clears store) | up:`db.ts:11-26` | `on_upgrade_needed` only creates the store if missing, never clears (`rs:src/storage/async_storage.rs:167-185`) | **partial** | Match upstream: clear-then-create on upgrade; document data loss |
| 20 | `LocalCredentialStorage` (prefix `ic-`, JSON `{key, chain?}`, Ed25519) | up:`credentials/local-credential-storage.ts:19-68` | `LocalStorage` with `ic-` prefix but stores raw values per key (`rs:src/storage/async_storage.rs:13,38-126`) | **partial** | New store writing one JSON record per slot |
| 21 | `MemoryCredentialStorage` (non-extractable P-256) | up:`credentials/memory-credential-storage.ts:15-41` | none | **missing** | Add |
| 22 | `SharedMemoryCredentialStorage` (BC `ic-credentials`, put/drop/ask/offer, presence locks) | up:`credentials/shared-memory-credential-storage.ts:78-303` | none | **missing** | `wasm-js` implementation of the protocol |
| 23 | Key type chosen by the store; `keyType` option removed | up:`docs/.../v9.md:53-55` | `key_type` is a client option (`rs:src/option/wasm_js.rs:16-17`, `rs:src/option/native.rs:13-14`); key types `Ed25519/Prime256v1/Secp256k1` (`rs:src/key.rs:223-246`) | **partial** | Move generation into stores; keep `key_type` only on native stores |
| 24 | Spent-credential eviction (one delegation lifetime bound) | up:`session-identity.ts:90-105` | none (chain validity checked, never evicted) | **missing** | Port `read_slot` eviction rule |
| 25 | Migration from v5 `identity`/`delegation` keys | up:`docs/.../v9.md:47-57` (upstream removes, does not migrate) | Rust migrates localStorage→IDB for the key (`rs:src/auth_client/wasm_js.rs:196-209`, `:289-445`) | **partial** | Keep as a one-time migration into the new `session` slot; document |

### 1.3 Session layer

| # | Upstream concept | Upstream ref | Current Rust | Status | Proposal |
|---|---|---|---|---|---|
| 26 | Session delegation request `ii_session_delegation` (JSON-RPC, max TTL/idle, derivation origin) | up:`session/session-delegation.ts:96-148` | Uses the old `authorize-client` popup flow (`rs:src/api.rs:10-30`, `rs:src/auth_client/wasm_js.rs:1324-1470`) | **missing** | New signer transport + `request_session_delegation` |
| 27 | `InteractionRequiredError` (code 3002, reason) | up:`session-delegation.ts:22-50` | none | **missing** | Error variant |
| 28 | `SessionMinter` Candid (`app_prepare_delegation`, `app_get_delegation`, `app_revoke_session`) | up:`session/session-minter.ts:18-55,151-198` | none | **missing** | ic-agent calls as in §2.3 |
| 29 | `assertChainReaches` (intersection of hop targets) | up:`session-minter.ts:233-277` | `DelegationChain::is_delegation_valid(checks)` does a different, weaker check (`rs:src/util/delegation_chain.rs:89-115`) | **partial** | Port `assert_chain_reaches` exactly |
| 30 | `SessionIdentity` rotating delegation (15s pre-mint, 10s block margin, used-flag, single-flight) | up:`session/session-identity.ts:227-510` | none; client holds a static key+chain (`rs:src/auth_client/wasm_js.rs:92-120`, `rs:src/auth_client/native.rs:92-118`) | **missing** | New `SessionIdentity` as in §2.4 |
| 31 | `AppDelegationSource` trait + 4-error taxonomy | up:`session/app-delegation-source.ts:12-66` | none | **missing** | `SessionError` enum |
| 32 | Web Locks (`withMintLock`, `stealMintLock`, `stealLock`) | up:`session/app-lock.ts:20-120` | none | **missing** | `LockManager` trait; wasm = `navigator.locks`; native = `Mutex` |
| 33 | `SessionGoneError` / `SessionUnsupportedError` / `AccountMismatchError` semantics | up:`app-delegation-source.ts:4-47` | none | **missing** | Error enum + end/drop/expire policy |
| 34 | `expired` published as a write (`#expireSession`) vs sign-out removal | up:`auth-client.ts:1589-1621` | `logout` deletes key+chain (`rs:src/auth_client/wasm_js.rs:1489-1500`, `rs:src/auth_client/native.rs:1103-1111`) | **partial** | Distinguish end (remove) / expire (write now) / drop (discard) |
| 35 | Restore/hydrate: state must back the chain, drop on mismatch | up:`auth-client.ts:1693-1761` | loads chain if valid, otherwise clears (`rs:src/auth_client/wasm_js.rs:779-838`, `rs:src/auth_client/native.rs:261-317`) | **partial** | Re-implement restore against the state record |
| 36 | Sign-in sequence with guarded writes + supersede checks | up:`auth-client.ts:923-1101` | popup flow writes at the end (`rs:src/auth_client/wasm_js.rs:896-933`) | **partial** | Re-sequence; add ceremony locks |
| 37 | Sign-out: revoke at canister, parallel wipe, carried failure | up:`auth-client.ts:1389-1454` | deletes local storage, no canister revoke (`rs:src/auth_client/wasm_js.rs:1475-1500`) | **partial** | Add `revoke()` and parallel wipe |
| 38 | Read-only sessions (permissions) | up:`docs/.../v10.md:11-25`; up:`session-minter.ts:26-31,220-227` | never reads/writes `permissions`; the resolved `ic-transport-types` 0.49.3 has `DelegationPermissions` (`Cargo.lock: ic-transport-types 0.49.3`) | **missing** | Carry permissions; map to `Unsupported` |
| 39 | Two-delegation model (session chain vs app chain) | up:`session-layer.md` §intro | one key + one chain only (`rs:src/auth_client/wasm_js.rs:92-118`) | **missing** | Add the `session` + `app` slots |

### 1.4 Idle / foreground

| # | Upstream concept | Upstream ref | Current Rust | Status | Proposal |
|---|---|---|---|---|---|
| 40 | No idle timer in the client | up:`docs/.../v9.md:59-70` | `IdleManager` created and default callback logs out + reloads (`rs:src/auth_client/wasm_js.rs:844-893`, `rs:src/auth_client/native.rs:319-377`, `rs:src/idle_manager.rs:76-218`) | **must change** | Remove from client; deprecate `IdleOptions` |
| 41 | Idle timeout owned by the canister (`maxTimeToIdle`) | up:`auth-client.ts:279-293` | only `max_time_to_live` exists (`rs:src/option.rs:23-24`) | **missing** | Add `max_time_to_idle` |
| 42 | `watchForeground` (visibilitychange/focus/pageshow) | up:`foreground-refresh.ts:17-47` | none | **missing** | wasm implementation |
| 43 | `watchActivity` (6 passive events, no throttle) | up:`foreground-refresh.ts:53-92` | `IdleManager` wasm listens to 6 events but resets an idle timer (`rs:src/idle_manager/wasm_js.rs:12-19`) | **partial** | New watcher; do not reuse idle timer |
| 44 | Foreground refresh → `SessionIdentity.refresh()` | up:`auth-client.ts:1460-1488` | none | **missing** | Requires #30 |
| 45 | `disableBrowserActivity` (one flag for both) | up:`auth-client.ts:104-120` | `disable_idle` means "no idle timer" (`rs:src/option.rs:61-63`) | **missing** | Add flag; keep old deprecated |
| 46 | Native activity/foreground equivalent | — | `rdev` OS listener in `rs:src/idle_manager/native.rs:21-88` | **n/a** | Host-driven `refresh_if_due()`; optional experimental native-activity feature |

### 1.5 Test & tooling

| # | Upstream concept | Upstream ref | Current Rust | Status | Proposal |
|---|---|---|---|---|---|
| 47 | Fake signer transport | up:`tests/client/fake-transport.ts` | none | **missing** | `FakeSignerTransport` |
| 48 | Fake URL transport + journal | up:`tests/client/fake-url-transport.ts` | none | **missing** | `FakeUrlTransport` |
| 49 | IDB test isolation | up:`tests/setup-idb.ts` | wasm tests use real IDB (`rs:src/storage/async_storage.rs:391-434`) | **partial** | Fresh DB name per test; `KeyValueDb` fake for logic |
| 50 | Fake Web Locks | up:`tests/client/session/app-lock.test.ts:11-72` | none | **missing** | `FakeLockManager` |
| 51 | Injected clock | up:`session-identity.test.ts:89-95` (`vi.useFakeTimers`) | `now()` calls `SystemTime`/`Date::now` directly (`rs:src/util/delegation_chain.rs:117-130`) | **missing** | `Clock` trait everywhere time matters |

---

## 2. Proposed Rust API (design proposal — not upstream behaviour)

Feature gating used below:

| Feature | Contents |
|---|---|
| `wasm-js` (default) | `LocalStateStorage`, `CookieStateStorage`, `IdbCredentialStorage`, `LocalCredentialStorage`, `SharedMemoryCredentialStorage`, Web Locks, BroadcastChannel, DOM watchers, signer transports |
| `native` | file-backed state store, keyring/pem/password credential stores, no-op watchers, host-driven login/refresh |
| `both` | `SessionState`, `StateStorage`, `Credential`, `CredentialStorage`, `SessionIdentity`, `SessionMinter` (ic-agent), status/subscription, errors |

### 2.1 State

```rust
// src/state/mod.rs
pub struct SessionState { pub principal: Principal, pub expiration_ns: u64, pub held: bool }
pub struct SessionStateWrite { pub principal: Principal, pub expiration_ns: u64 }

pub type Unsubscribe = Box<dyn FnOnce() + Send + Sync>;

pub trait StateStorage: Send + Sync {
    fn get(&self, key: &str) -> Option<SessionState>;
    fn set(&self, key: &str, state: SessionStateWrite);
    fn remove(&self, key: &str);      // sign-out: retract, including shared media
    fn discard(&self, key: &str);     // found dead: this origin only
    fn subscribe(&self, key: &str, listener: Arc<dyn Fn() + Send + Sync>) -> Unsubscribe;
    fn resumable(&self) -> bool { false }
    fn is_read_only(&self) -> bool { false }
    /// `Some(fut)` where the store loads asynchronously (worker mirror).
    fn ready(&self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> { None }
}
```

Implementations: `MemoryStateStorage` (both), `LocalStateStorage` + `CookieStateStorage`
(`wasm-js`), `FileStateStorage` (`native`, proposal: `<data_dir>/<service>/session-state.json`,
`resumable = false`, `is_read_only = false`).

### 2.2 Credentials

```rust
// src/credentials/mod.rs
pub struct Credential { pub key: Key, pub chain: Option<DelegationChain> }

#[async_trait::async_trait]
pub trait CredentialStorage: Send + Sync {
    fn shared(&self) -> bool;
    fn durable(&self) -> bool;
    async fn create(&self) -> Result<Key, StorageError>;
    async fn get(&self, slot: &str) -> Result<Option<Credential>, StorageError>;
    async fn set(&self, slot: &str, credential: &Credential) -> Result<(), StorageError>;
    async fn remove(&self, slot: &str) -> Result<(), StorageError>;
}

// src/slots.rs
pub struct Slots { pub session: String, pub session_pending: String,
                   pub app: String, pub app_pending: String, pub state: String }
impl Slots { pub fn for_namespace(ns: Option<&str>) -> Self { /* ":" separator */ } }
```

Implementations: `IdbCredentialStorage`, `LocalCredentialStorage`,
`SharedMemoryCredentialStorage`, `MemoryCredentialStorage` (`wasm-js`); native adapters over
`KeyringStorage` / `PemStorage` / `PasswordStorage` (`shared = false`, `durable = true`).

### 2.3 Session minter

```rust
pub struct SessionMinter { agent: Agent, canister_id: Principal }

impl SessionMinter {
    pub async fn create(session_key: Arc<dyn SignIdentity>, session_chain: DelegationChain,
                        canister_id: Principal, opts: Option<AgentOptions>) -> Result<Self, SessionError>;
    pub async fn mint(&self, app_pubkey_der: &[u8]) -> Result<DelegationChain, SessionError>;
    pub async fn revoke(&self) -> Result<(), SessionError>;
}
pub fn assert_chain_reaches(chain: &DelegationChain, canister_id: Principal) -> Result<(), SessionError>;
pub fn app_delegation_chain(user_key: &[u8], signed: SignedAppDelegation) -> DelegationChain;
```

Candid is in `session-layer.md` §2. `permissions` maps to `DelegationPermissions` already present
in `ic-transport-types` 0.49.3.

### 2.4 Session identity

```rust
pub enum SessionError {
    Gone, Unsupported(String), AccountMismatch, NoSuchDelegation, Retryable(Box<dyn Error>),
}

pub trait AppDelegationSource: Send + Sync {
    fn mint(&self, app_pubkey_der: &[u8]) -> BoxFuture<'_, Result<DelegationChain, SessionError>>;
}
pub trait Clock: Send + Sync { fn now_ms(&self) -> u64; }
pub trait LockManager: Send + Sync {
    fn with_mint_lock<'a>(&'a self, name: Option<&'a str>,
                          work: Box<dyn FnOnce(StealSignal) -> BoxFuture<'a, Result<Held, SessionError>> + Send + 'a>)
        -> BoxFuture<'a, Result<Held, SessionError>>;
    fn steal_mint_lock<'a>(&'a self, name: Option<&'a str>) -> BoxFuture<'a, ()>;
    fn steal_lock<'a>(&'a self, name: Option<&'a str>) -> HeldLock;
}

pub const BLOCK_MARGIN_MS: u64 = 10_000;
pub const PRE_MINT_THRESHOLD_MS: u64 = 15_000;

pub struct SessionIdentity { /* held, in_flight, used, scheduled, gone_reported, unsupported, account */ }
impl SessionIdentity {
    pub async fn create(opts: SessionIdentityOptions) -> Result<Self, SessionError>;
    pub fn principal(&self) -> Principal;
    pub fn delegation(&self) -> &DelegationChain;
    pub async fn transform_request(&self, req: &mut HttpRequest) -> Result<(), SessionError>;
    pub async fn refresh(&self) -> Result<(), SessionError>;   // "somebody is here"
    pub fn dispose(&self);
}
```

Native caveat: `SessionIdentity` is transport-agnostic once `AppDelegationSource` is injected, so
the same type serves `wasm-js` and `native`; only the source differs (signer-based vs a host
bridge that mints on the app's behalf).

### 2.5 Client options / status

```rust
pub struct AuthClientOptions {
    pub credential_storage: Arc<dyn CredentialStorage>,
    pub state_storage: Arc<dyn StateStorage>,
    pub namespace: Option<String>,
    pub identity_provider: IdentityProvider,          // { authorize_url: Url, canister_id: Principal }
    pub agent_options: Option<AgentOptions>,
    pub derivation_origin: Option<Url>,
    pub transport: TransportKind,                     // Window | Redirect
    pub prompt: Option<Prompt>,                       // Login | None
    pub hint: Option<Principal>,
    pub resumable: Option<bool>,
    pub disable_browser_activity: bool,
}

pub enum SessionStatus {
    SignedIn { principal: Principal, expires_at_ms: u64 },
    SignedInElsewhere { principal: Principal, expires_at_ms: u64 },
    Expired { principal: Principal, expires_at_ms: u64 },
    SignedOut,
}

impl AuthClient {
    pub fn get_status(&self) -> SessionStatus;            // stable object semantics
    pub fn is_authenticated(&self) -> bool;
    pub fn get_principal(&self) -> Option<Principal>;
    pub fn subscribe(&self, f: Arc<dyn Fn() + Send + Sync>) -> Unsubscribe;
    pub fn dispose(&self);
    pub async fn sign_in(&self, opts: SignInOptions) -> Result<Arc<dyn Identity>, AuthClientError>;
    pub async fn sign_out(&self, opts: SignOutOptions) -> Result<(), AuthClientError>;
    pub async fn get_identity(&self) -> Result<Arc<dyn Identity>, AuthClientError>;
    pub async fn ready(&self) -> Result<(), AuthClientError>;
}
```

### 2.6 UniFFI exposure

UniFFI cannot express a Rust enum with payloads ergonomically on all targets, and cannot expose
`Arc<dyn Trait>` callbacks without a callback interface. Proposal:

```rust
#[derive(uniffi::Enum)] pub enum SessionStatusKind { SignedIn, SignedInElsewhere, Expired, SignedOut }
#[derive(uniffi::Record)] pub struct SessionStatusRecord {
    pub kind: SessionStatusKind,
    pub principal_text: Option<String>,
    pub expires_at_ms: Option<u64>,
}
#[uniffi::export(callback_interface)] pub trait AuthListener: Send + Sync { fn on_change(&self); }
#[uniffi::export] impl AuthClient {
    pub fn status(&self) -> SessionStatusRecord;
    pub fn subscribe(&self, listener: Box<dyn AuthListener>) -> u64;  // id, released by unsubscribe
    pub fn unsubscribe(&self, id: u64);
}
```

Errors: add `AuthError::{ SessionGone, SessionNotHeld, InteractionRequired{reason}, Superseded,
ReadOnly, Unsupported }` variants (today `rs:src/uniffi_bindings.rs:44-57` only has
`Message/InvalidCustomValues/Principal/Signature/Key`).

---

## 3. Browser-only facilities → native equivalents

| Facility | Used by upstream | Faithful native equivalent? | Proposal |
|---|---|---|---|
| `localStorage` | `LocalStateStorage`, `LocalCredentialStorage` | no (no origin) | file-backed JSON under the app data dir; one install = one "origin" |
| IndexedDB + `CryptoKeyPair` | `IdbCredentialStorage`, `IdbKeyVal` | no | keyring (`KeyringStorage`) or password-encrypted file (`PasswordStorage`); keys are extractable bytes |
| Cookies + `Domain` scope | `CookieStateStorage` | no | **not-applicable**; a native install has no sibling origins. File state store, `resumable = false` |
| `BroadcastChannel` | worker mirror, `SharedMemoryCredentialStorage` | in-process only | `tokio::sync::broadcast` / callback registry; no cross-process |
| Web Locks | mint/sign-in coordination | in-process only | `Mutex` keyed by lock name; document single-process scope |
| Service/Web Worker read-only client | worker state mirror | no | **not-applicable** |
| `document.visibilitychange` / `focus` / `pageshow` | `watchForeground` | no | host app calls `refresh_if_due()` on its lifecycle events |
| DOM activity events | `watchActivity` | no | same as above; optional experimental `rdev`-based activity feature |
| `location.replace/assign` | `returnTo`, redirect flow | no | host callback (`on_navigate(url)`) or deep link |
| `postMessage` signer transport | window transport | no | native login bridge; the repo already has `build_login_url`/`finish_login_from_payload` (`rs:src/auth_client/native.rs:906-925`) and `ii-bridge/` |
| URL-transport redirect journal | redirect flow | no | host-owned state; no browser history to survive |
| `crypto.randomUUID` | request ids, presence lock names | yes (`uuid` crate) | add dependency |
| `crypto.subtle` ECDSA/Ed25519 | key generation | yes (`p256`/`ed25519-dalek`, already deps) | reuse `rs:src/key.rs` |

---

## 4. Suggested implementation order (dependency-driven)

1. **Slots + state types + `MemoryStateStorage` + status** — no browser, unblocks everything.
2. **`SessionIdentity` + `AppDelegationSource` + `SessionError` + clock + lock traits** — pure logic,
   port `session-identity.test.ts` and `app-lock.test.ts` as acceptance.
3. **`SessionMinter` + Candid + `assert_chain_reaches`** — native-testable with a fake service.
4. **Client re-architecture** (`sign_in`/`sign_out`/restore/status/subscription) on top of 1-3,
   keeping the existing login transport behind a feature/adapter so the wasm client keeps working
   during the transition.
5. **`wasm-js` stores**: `LocalStateStorage` + worker mirror, `IdbCredentialStorage` (+ recovery),
   `LocalCredentialStorage`, `SharedMemoryCredentialStorage`, `CookieStateStorage`.
6. **Watchers** + `disableBrowserActivity` + foreground refresh.
7. **Read-only sessions/permissions** and the `Unsupported` latch.
8. **Native adapters**: file state store, credential stores, `refresh_if_due`, deep-link login;
   remove `IdleManager` from the client.
9. **UniFFI**: status record, subscribe/unsubscribe, new error variants.
10. **Tests**: port the 8 pure-logic suites first, then wasm-bindgen-test suites, then redirect.

## 5. Biggest risks

| # | Risk | Why | Mitigation |
|---|---|---|---|
| 1 | Two-delegation model is a rewrite, not an extension | current client holds one key + one chain and derives auth from it; upstream has a session chain, an app chain, and a rotating identity | land the session layer behind a new type and keep the old client path until parity tests pass |
| 2 | Time semantics | state expiry = session chain's earliest expiry; 15s pre-mint / 10s block margin; scheduled rotation; "unused delegation lapses" | inject a `Clock`; port `session-identity.test.ts` with fake time as the gate |
| 3 | Cross-context state propagation | localStorage `storage` events, BroadcastChannel, IDB mirror, cookie re-checks are all browser-only and each has subtle dedupe rules | implement per-store `subscribe` exactly as specified, with canonical-string dedupe; test tab/worker scenarios in a real browser |
| 4 | IndexedDB schema/recovery in Rust | upstream relies on `idb`'s `terminated` hook and `InvalidStateError` retry; a version bump **clears** the store | wrap raw `web-sys` IDB (or the `idb` crate with a recovery layer); write a recovery test that force-closes a connection |
| 5 | Read-only sessions / permissions | the port never reads `permissions`; a read-only session must sign in and then latch `Unsupported` rather than sign out | carry `DelegationPermissions` end-to-end and port the `Unsupported` latch + `SessionUnsupportedError` semantics |

---

## Rust port checklist

- [ ] Create `src/state/` (types + memory store + wasm stores + native file store) and
      `src/credentials/` (trait + four wasm stores + native adapters).
- [ ] Create `src/slots.rs` with the five names and `:` namespacing; replace the fixed
      `identity`/`delegation`/`key-type`/`iv` constants for the new path.
- [ ] Create `src/session/` with `SessionError`, `AppDelegationSource`, `SessionMinter`,
      `SessionIdentity`, `assert_chain_reaches`, `app_delegation_chain`, `LockManager`, `Clock`.
- [ ] Re-architect `AuthClient`/`NativeAuthClient` around the state record: `get_status`,
      `subscribe`, `dispose`, `sign_in`, `sign_out`, `get_identity`, restore/expire/drop.
- [ ] Remove `IdleManager` from client construction; add `max_time_to_idle`,
      `disable_browser_activity`, `prompt`, `hint`, `resumable`.
- [ ] Add `watch_foreground` / `watch_activity` (`wasm-js`) and `refresh_if_due` (native).
- [ ] Carry `permissions` (read-only sessions) and implement the `Unsupported` latch.
- [ ] Implement IDB schema/version/upgrade-clears/recovery to upstream's contract.
- [ ] Extend UniFFI with `SessionStatusRecord`, `subscribe`/`unsubscribe`, and the new error
      variants.
- [ ] Add `test-utils` fakes (`FakeSignerTransport`, `FakeUrlTransport`, `FakeLockManager`,
      `FakeDelegationSource`, `FakeSessionService`, `FakeClock`, `KeyValueDb` fake) and port the
      pure-logic suites first.
