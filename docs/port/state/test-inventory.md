# Upstream v11.2.0 — Test Inventory & Test-Fake Strategy (for the Rust port)

Upstream: `/tmp/icp-js-auth` at `@icp-sdk/auth` **11.2.0**.
Runner: vitest 5.0.5, `environment: 'jsdom'`, `setupFiles: ['./tests/setup-idb.ts']`,
`typecheck.enabled: true` (`vitest.config.ts:1-12`).
All paths below are relative to `/tmp/icp-js-auth`.

---

## 1. Test-fake infrastructure (the key to porting without a live Identity Identity)

### 1.1 `tests/client/fake-transport.ts` (119 lines) — in-memory signer transport

An in-memory implementation of `@icp-sdk/signer`'s `Transport` / `Channel`
(`fake-transport.ts:35-119`). Replaces `PostMessageTransport` via
`vi.mock('@icp-sdk/signer/web', ...)` (`auth-client.test.ts:120-125`), so the **real** `Signer`
runs over it — no window is opened and nothing about JSON-RPC correlation is faked
(`auth-client.test.ts:116-125`).

| Behaviour | Detail |
|---|---|
| Instance tracking | static `instances[]`, `last()`, `reset()` (`:36-46`) |
| Options | captures constructor options, e.g. the authorize URL (`:48-55`) |
| Request recording | every sent request is pushed to `requests` (`:49`, `:99`) |
| Handler chain | `onRequest(handler)`; handlers are tried in registration order and the **first non-`undefined` response wins**, so tests compose independent per-method helpers (`:28-33`, `:106-112`) |
| Async handlers | awaited before dispatching (`:106-111`) |
| Notifications | a request with `id === undefined \| null` gets **no response** and hangs the signer's correlation wait, exactly like a real signer (`:100-105`) |
| Response dispatch | echoes the request's `id`; listeners are invoked synchronously after the handler (`:106-112`) |
| Close | idempotent; notifies close listeners; `send` on a closed channel throws (`:114-119`) |
| Handlers after channel | read through the shared array, so handlers registered after `establishChannel` still apply (`:61-63`) |

Tests of the fake itself: `tests/client/fake-transport.test.ts` (19 tests).

**Port analogue:** a `FakeSignerTransport` implementing a Rust `SignerTransport` trait:
`async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, Error>`, with a
`Vec<Box<dyn Fn(&JsonRpcRequest) -> Option<JsonRpcResponse>>>` handler chain, request recording,
and the same "notification never answers" rule. It lets `request_session_delegation` be tested
without any browser window.

### 1.2 `tests/client/fake-url-transport.ts` (160 lines) — redirect-flow model

Models the two moving parts `AuthClient` depends on from `UrlTransport` (`fake-url-transport.ts:22-41`):

1. **`memoize` journal**: values recorded **by call order** in a **static** journal shared across
   instances, so a value captured on one "load" replays on the next (`:77-99`). It mirrors the real
   transport's polymorphic shape: a sync producer returns synchronously, an async one returns a
   promise, and the replay preserves that (`asyncSlots`) (`:80-99`).
2. **respond vs navigate**: each instance is constructed with `respond = FakeUrlTransport.nextRespond`;
   `respond=false` records requests but never answers — the load that navigates away (`:136-153`).

Statics: `instances`, `journal`, `asyncSlots`, `nextRespond`, `reset()`, `last()`
(`:43-59`).

Tests of the fake + redirect paths: `tests/client/auth-client-redirect.test.ts` (14 tests).

**Port analogue:** a `FakeUrlTransport` with a process-static `Vec<serde_json::Value>` journal
keyed by call index, plus a `respond: bool` per instance. This is the only way to test the
two-load redirect state machine (`session-pending` slot reuse, `memoize` replay, superseded-key
detection) without real navigation.

### 1.3 `tests/setup-idb.ts` (28 lines) — IndexedDB isolation

```ts
import 'fake-indexeddb/auto';
```

Before **every** test, clears the **state mirror** database only (`:4-5`, `:17-28`):

| Thing | Value |
|---|---|
| DB name | `auth-client-state-db` |
| Store | `ic-keyval` |
| Method | native `indexedDB.open` + `transaction(store,'readwrite').objectStore(store).clear()` — deliberately **not** `IdbKeyVal`, so files that mock `idb` see only their own connections (`:13-16`) |
| Why | the default state store mirrors the sign-in into IndexedDB, which otherwise lives as long as the test file; tests clear `localStorage` between them (`:13-16`) |

Tests that need their own database use unique names per test (`db.test.ts:6-11`,
`idb-credential-storage.test.ts:13-17`).

**Port analogue:** for native tests, a `KeyValueDb` trait with an in-memory implementation, reset
between tests. For wasm tests, `fake-indexeddb` has no Rust equivalent; either run against a real
browser (wasm-bindgen-test) with a fresh DB name per test, or make the IDB layer generic over the
`idb` crate and test the logic against a memory DB.

### 1.4 Web Locks stand-in

jsdom has no Web Locks, so tests stub `navigator.locks` with a queue + stealing model
(`app-lock.test.ts:11-72`; `shared-memory-credential-storage.test.ts:17-41`; duplicated as
`stubLocks()` in `auth-client.test.ts:180-221`). Model: `request(name, opts, cb)` queues per name;
`{ steal: true }` rejects the incumbent's promise with a `DOMException('lock stolen','AbortError')`
while its callback keeps running, and the stealer becomes the holder; `query()` reports held names.

**Port analogue:** a `FakeLockManager` implementing a `LockManager` trait, with the same
steal semantics (reject incumbent, keep callback running).

### 1.5 Other mocks

| Mock | Purpose | Where |
|---|---|---|
| `session/session-minter.ts` | replaces the canister mint with a local `DelegationChain.create` rooted at a fixed account key; records `createdWith`, `count`, `revoked`, `refuse`, `refuseRevoke`, `onMint` | `auth-client.test.ts:38-87` |
| `sso.ts` (`createSsoDomainService`) | keeps the real `SsoStatusChecker` and stubs the canister methods `app_sso_domain_check` / `app_sso_domain_status` | `auth-client.test.ts:89-114` |
| `@icp-sdk/signer/web` | swaps `PostMessageTransport` for `FakeTransport`, keeps the real `UrlTransport` so the constructor's `instanceof` check works | `auth-client.test.ts:120-125` |
| `idb` (`openDB`) | wraps `openDB` to capture every connection so a test can force-close it | `db-recovery.test.ts:7-19` |
| `IdbKeyVal.prototype.get` | holds/releases a worker's IndexedDB read to test `ready()` ordering | `local-state-storage.test.ts:104-130`, `:143-170` |
| `FakeTransport` / `FakeUrlTransport` class mocks | redirect tests | `auth-client-redirect.test.ts:1-150` |

## 2. Inventory — every upstream test file

`#it` = number of `it(...)` blocks (parameterised `it.each` counts as one block). "Portable?"
judges whether the *assertions* can be reproduced in the Rust port; "Needs" names the fake.

| # | File | #it | What it asserts | Portable to Rust? | Needs |
|---|---|---|---|---|---|
| 1 | `tests/client/slots.test.ts` | 2 | `slotsFor()` names all five slots (state included) and a namespace prefixes every one at once | **yes, native** | none |
| 2 | `tests/client/state/memory-state-storage.test.ts` | 9 | memory store round-trips state, reports `held:true`, isolates instances/keys, `discard==remove`, fires subscribers only on real change and after the value is readable | **yes, native** | none |
| 3 | `tests/client/state/local-state-storage.test.ts` | 24 | localStorage format/round-trip, bigint preserved, tolerant parse, tab↔worker mirror via IDB+BroadcastChannel, read-only worker, `ready()` ordering, mirror repair on subscribe, unsubscribe stops following | partly (mirror needs IDB+BC) | fake-indexeddb, BroadcastChannel (jsdom) |
| 4 | `tests/client/state/cookie-state-storage.test.ts` | 25 | cookie attributes (incl. 400-day `Max-Age`), domain validation/probe, `held` composition vs sibling, `discard` leaves cookie, per-origin `storage` events, visibility/focus re-check, worker read-only, `resumable` | partly (cookie API browser-only) | jsdom document.cookie; real browser for exact cookie behaviour |
| 5 | `tests/client/credentials/credential-storage.test.ts` | 11 | memory store `shared=false/durable=false`, hands back same object, non-extractable key; local store `shared/durable=true`, Ed25519 JSON round-trip, prefix isolation, corrupt record ⇒ `null` | **yes** | none (local store: fake localStorage) |
| 6 | `tests/client/credentials/idb-credential-storage.test.ts` | 7 | IDB store flags, one record = key+chain, key-only record, non-extractable key, corrupt record ⇒ `null`, one `IdbKeyVal.create` for concurrent first accesses, failed open not cached | partly (IDB) | fake-indexeddb |
| 7 | `tests/client/credentials/shared-memory-credential-storage.test.ts` | 14 | flags, identity identity-preserved, replicate put/drop to a live peer, cold-start `ask`/`offer`, no peer ⇒ no wait, peer death ends wait, offer fills gaps only, key crosses as non-exportable handle, ignores foreign messages, closed store takes nothing, names isolated, no locks ⇒ alone | **design-level yes** (BC+locks) | FakeLockManager + BroadcastChannel |
| 8 | `tests/client/db.test.ts` | 3 | KV set/get/remove, `CryptoKeyPair` survives structured clone (snapshot) | partly | fake-indexeddb |
| 9 | `tests/client/db-recovery.test.ts` | 2 | force-closed connection is reopened and the operation retried once; a write after close recovers | **yes, if IDB layer abstracted** | mock `openDB` |
| 10 | `tests/client/foreground-refresh.test.ts` | 13 | `watchForeground` fires on visible/focus/pageshow, ignores hidden, unhooks, no-DOM/partial-DOM ⇒ undefined; `watchActivity` fires on all six events, every time (no throttle), ignores scroll/visibilitychange, unhooks, no DOM ⇒ undefined | **yes, wasm-bindgen-test** | synthetic DOM events |
| 11 | `tests/client/session/app-lock.test.ts` | 14 | `withMintLock` serialises, runs unserialised for `null`, passes a non-aborting signal, frees on failure, signal fires on steal and steal does not wait; `stealLock` holds until release, tells incumbent, leaves other locks, idempotent release, no-lock fallback | **yes** | FakeLockManager |
| 12 | `tests/client/session/session-minter.test.ts` | 22 | `unwrapSessionResult` mapping (Ok/NoSuchSession/NoSuchDelegation/InternalCanisterError text); `appDelegationChain` roots at user key, carries expiry/targets/permissions; `assertChainReaches` accepts II shape and refuses unrestricted/empty/other canister; `mint` retries prepare+get once on `NoSuchDelegation`, gives up after two, does not retry `NoSuchSession`; `revoke` raises canister refusal, treats gone as success | **yes, native** | fake `SessionService` (canister calls) |
| 13 | `tests/client/session/session-identity.test.ts` | 41 | 15s pre-mint / 10s block margin thresholds, single-flight mint, rotation only when used, unused lapses, refresh(), gone reported once, unsupported latched, account-mismatch refusal, key/delegation pairing, store adoption/eviction rules, lock behaviour, disposal stops scheduling | **yes, native** | fake `DelegationSource` + fake `CredentialStorage` + fake clock |
| 14 | `tests/client/auth-client.test.ts` | 143 (5 `it.each`) | the whole client: status matrix and stability, namespace isolation, prompt/hint/resumable URL params, sign-in sequence and writes, session/state/credential layout, silent reissue, restore/drop/expire/end, sign-out and revoke failure, supersede/dispose, foreground+activity refresh, subscription propagation, worker read-only, redirect-independent helpers, scopedKeys, SSO status | partly: pure logic native; URL/DOM/IDB parts wasm | FakeTransport, FakeLockManager, fake minter, jsdom |
| 15 | `tests/client/auth-client-redirect.test.ts` | 14 | redirect requires a durable store, routes through the URL transport, reuses session key across loads, journals validated `returnTo`/derivation origin/nonce, cleans up pending key, refuses a superseded pending slot | **partly** | FakeUrlTransport |
| 16 | `tests/client/auth-client-redirect-replay.test.ts` | 1 (`it.each`, 2 cases) | against the **real** `UrlTransport`: signIn and requestAttributes issued together complete on the return load with a slow nonce, in either order | **no** (real transport is a JS dependency) | real `@icp-sdk/signer/web` |
| 17 | `tests/client/fake-transport.test.ts` | 19 | the fake itself: instance tracking, request recording, notification no-dispatch, handler order, async handlers, closed channel, listener unsubscribe, close idempotence, handlers after channel | **yes** (port the fake, then these) | none |
| 18 | `tests/client/sso.test.ts` | 20 | `normalizeSsoDomain` rules; `SsoStatusChecker` checks on build, polls with backoff, final answers, abandon window, retry, builds service again, stable object, invalid never calls, refresh, disposal | **yes, native** | fake SSO service |
| 19 | `tests/client/notification-consent.test.ts` | 15 | consent JSON-RPC method, derivation origin, refusal as answer, unsupported/interaction errors, status/revoke canister results, chain-reach refusal | **yes, native** | FakeTransport |
| 20 | `tests/client/db.test.ts.snap` | — | snapshot for the `CryptoKeyPair` structured-clone test | n/a | — |
| 21 | `tests/client/setup-idb.ts` | — | (setup, not a test file) clears `auth-client-state-db`/`ic-keyval` before each test | n/a | — |

Non-`tests/client` files: none relevant to this layer.

## 3. Portability classification for the Rust port

| Class | Upstream files | Rust harness |
|---|---|---|
| **Pure/native-testable** (no browser API) | slots, memory state, credential storage (memory/local logic), app-lock, session-minter, session-identity, sso, notification-consent, fake-transport | `#[cfg(test)]` unit/integration tests on the host (`native` feature), with in-memory stores, fake clock, fake `DelegationSource`, fake `SessionService` |
| **wasm-bindgen-test only** (browser API) | local-state-storage mirror, cookie-state-storage, foreground-refresh, idb-*, db-recovery, redirect flow | `wasm_bindgen_test_configure!(run_in_browser)` tests; use synthetic `Event`s and real `document.cookie`/`localStorage`/`indexedDB` |
| **Not portable** | redirect-replay against the real `@icp-sdk/signer/web` `UrlTransport` | the Rust port owns its own transport; re-implement the equivalent replay test against the Rust URL transport |
| **Port the fake, then the test** | fake-transport, fake-url-transport, lock stand-in | `FakeSignerTransport`, `FakeUrlTransport`, `FakeLockManager` in a `test-utils` module |

## 4. Recommended Rust test-fake design (proposal)

```rust
// test-utils (cfg(any(test, feature = "test-utils")))
pub struct FakeSignerTransport { requests: Mutex<Vec<JsonRpcRequest>>, handlers: Mutex<Vec<Handler>> }
impl SignerTransport for FakeSignerTransport { async fn send(&self, req) -> Result<Response> { ... } }

pub struct FakeUrlTransport { respond: bool, journal: Arc<Mutex<Vec<Value>>>, cursor: AtomicUsize }
impl UrlTransportLike for FakeUrlTransport {
    fn memoize<T: Serialize + DeserializeOwned>(&self, produce: impl FnOnce() -> T) -> T { /* replay by index */ }
}

pub struct FakeLockManager { held: Mutex<HashMap<String, Vec<oneshot::Sender<()>>>> }
impl LockManager for FakeLockManager { /* steal rejects incumbent, keeps callback running */ }

pub struct FakeDelegationSource { mint: Box<dyn Fn(DerKey) -> Result<DelegationChain>> }
pub struct FakeSessionService { prepare: ..., get: ..., revoke: ... } // canister call shapes

pub struct FakeClock { now_ms: AtomicU64 }   // injected `Clock` trait, never `SystemTime::now()` in logic
```

Rules for testability (these are prerequisites, not nice-to-haves):

1. **Inject time.** `SessionIdentity`, `get_status()`, `is_delegation_valid` all need a `Clock`
   trait; the JS tests use `vi.useFakeTimers({ toFake: ['Date'] })` and
   `advanceTimersByTimeAsync` (`session-identity.test.ts:89-95`).
2. **Inject the mint source.** The JS tests replace the whole `SessionMinter`; Rust should take
   `Arc<dyn AppDelegationSource>`.
3. **Inject the canister calls.** `SessionMinter` should take a trait for the three methods so
   `session-minter.test.ts` can run without a replica.
4. **Inject the lock manager.** `Option<Arc<dyn LockManager>>`, `None` = no coordination.
5. **Inject the KV database.** `IdbKeyVal` logic (open/retry/upgrade) needs a `KeyValueDb` trait so
   `db-recovery.test.ts` can force-close a connection in a memory impl.

## Rust port checklist

- [ ] Build a `test-utils` module with `FakeSignerTransport`, `FakeUrlTransport`, `FakeLockManager`,
      `FakeDelegationSource`, `FakeSessionService`, `FakeClock`, `MemoryStateStorage`,
      `MemoryCredentialStorage`.
- [ ] Port the 8 pure-logic test files first (slots, memory state, credentials logic, app-lock,
      session-minter, session-identity, sso, notification-consent) — they are the acceptance
      criteria for the session layer and need no browser.
- [ ] Port the watcher tests with wasm-bindgen-test (synthetic events; assert fire/no-fire/unhook/
      no-DOM).
- [ ] Port the IDB tests as wasm-bindgen-test with a fresh DB name per test; port the recovery
      test against a `KeyValueDb` fake.
- [ ] Port the cookie tests as wasm-bindgen-test; for exact cookie attribute assertions, capture
      writes through a wrapper around `document.cookie` (the upstream test does this at
      `cookie-state-storage.test.ts:122-146`).
- [ ] Port the worker-mirror tests (tab↔worker, `ready()` ordering, mirror repair) with
      wasm-bindgen-test + `fake-indexeddb`-equivalent unavailable ⇒ run in a real browser.
- [ ] Add a Rust redirect-replay test against the Rust URL transport once it exists; the JS
      real-transport replay test is not portable.
- [ ] Keep the "notification never answers" rule in the fake transport so a missing `id` fails by
      timeout, not silently.
