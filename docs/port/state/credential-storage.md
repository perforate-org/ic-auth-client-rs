# Upstream v11.2.0 — Credential Storage Specification (for the Rust port)

Upstream: `/tmp/icp-js-auth` at `@icp-sdk/auth` **11.2.0**.
Sources: `src/client/credentials/*.ts`, `src/client/db.ts`, `src/client/slots.ts`,
`tests/client/credentials/*`, `tests/client/db*.test.ts`, `tests/setup-idb.ts`,
`docs/src/content/docs/upgrading/v9.md`.

A **credential** is the material a client acts with. A **state record** (who is signed in) is a
separate, non-secret store — see `state-storage.md`.

---

## 1. `Credential` — exact shape

`src/client/credentials/credential-storage.ts:4-20` (verbatim):

```ts
export interface Credential<T extends SignIdentity = SignIdentity> {
  identity: T;                 // the key that signs
  chain?: DelegationChain;     // absent only while a ceremony is in flight
}
```

| Field | Type | Meaning |
|---|---|---|
| `identity` | `SignIdentity` | The key. Its type is chosen by the store (§3.1) |
| `chain` | `DelegationChain?` | The delegation issued **to that key**. Absent only under the `session-pending` slot during a ceremony (`:15-19`) |

The two are one record because a delegation is issued to a key: held apart they can disagree, and
"a chain with no key to sign for it" must be unrepresentable (`:4-11`). A record with no chain is
not a usable credential; only a ceremony's own slot may hold a key alone
(`auth-client.ts:1797-1803`).

## 2. `CredentialStorage` interface

`src/client/credentials/credential-storage.ts:22-56`:

| Member | Signature | Semantics |
|---|---|---|
| `shared` | `readonly boolean` | whether another tab of this origin reads what this writes |
| `durable` | `readonly boolean` | whether what this writes survives the document teardown (redirect flow requires it) |
| `create()` | `() => Promise<T>` | a fresh identity **of this store's own key type**, not persisted |
| `get(slot)` | `(string) => Promise<Credential<T> \| null>` | `null` = nothing usable stored |
| `set(slot, credential)` | `(string, Credential<T>) => Promise<void>` | |
| `remove(slot)` | `(string) => Promise<void>` | |

Generation belongs to the store because the medium decides the key type (`:39-47`): a store that
must serialise needs a key whose private bytes are readable; a store that does not should not
have them. This prevents pairing a non-extractable key with a store that cannot hold one.

### 2.1 Slots (shared with the state layer)

`src/client/slots.ts:17-78` — one list, one assigner:

| Key | Bare name | Contents |
|---|---|---|
| `session` | `session` | session key + session delegation chain (the chain restricted to II) |
| `sessionPending` | `session-pending` | redirect ceremony's key while the page is away |
| `app` | `app` | app key + app delegation (what the agent signs with) |
| `appPending` | `app-pending` | app credential minted during a ceremony, before its session is stored |
| `state` | `ic-session-state` | the state record (not a credential slot, but named here so a namespace moves it too) |

Namespace: `slotsFor(namespace)` prefixes every name with `${namespace}:` (`slots.ts:52-78`);
the separator is a cross-origin contract.

## 3. The four implementations

### 3.1 `IdbCredentialStorage` (default)

`src/client/credentials/idb-credential-storage.ts:1-82`. Declared `shared = true`, `durable = true`
(`:21-22`). Key type: **ECDSA P-256, non-extractable** (`:49-51`).

| Thing | Exact value |
|---|---|
| DB name | `auth-client-db` (`db.ts:8`) |
| Object store | `ic-keyval` (`db.ts:9`) |
| DB version | `DB_VERSION = 1` (`db.ts:4`) |
| Object stores/indexes | **one object store, no keyPath, no indexes** — `database.createObjectStore(storeName)` (`db.ts:22`); keys are out-of-line `IDBValidKey` (`db.ts:7`) |
| Per-slot record | `{ keyPair: CryptoKeyPair, chain?: string }` (`idb-credential-storage.ts:5-9`, `:70-76`) |
| `chain` encoding | `JSON.stringify(credential.chain.toJSON())` (`:74`) |
| Corrupt/unreadable record | `get` returns `null` rather than throwing (`:58-67`) |
| DB handle caching | `#dbPromise`; cleared on failure so a later call retries (`:33-47`) |
| Concurrent first accesses | share one `IdbKeyVal.create` promise (test `idb-credential-storage.test.ts:80-96`) |
| Failed open | not cached; next call retries (test `:98-106`) |

`DBCreateOptions` (`db.ts:49-53`): `{ dbName?: string; storeName?: string; version?: number }`;
defaults `auth-client-db` / `ic-keyval` / `DB_VERSION` (`db.ts:68-78`).

### 3.2 `db.ts` — the generic KV layer, upgrade and recovery

`src/client/db.ts:59-158`:

- `IdbKeyVal.create(options)` opens eagerly so an unavailable database fails at creation
  (`:68-78`).
- `_openDbStore` (`:11-26`): `openDB(dbName, version, { upgrade, terminated })`.
  **Upgrade policy: if the store already exists it is `clear()`ed, then re-created**
  (`:17-25`). There is no record-level migration: a version bump wipes the object store. This is
  the entire "migration path" in this file.
- `terminated` hook (`:89-106`): the browser can force-close a connection; the cached promise is
  dropped so the next operation opens a fresh one.
- `_withDb` (`:108-127`): Chrome can force-close without firing `terminated`, and the next
  transaction throws `InvalidStateError`; that error is matched **by name** (a `DOMException`
  does not inherit `Error`), the connection is dropped and the action retried **once**.
- `get` normalises `undefined` to `null` (`:146-148`).
- `set/get/remove` take `IDBValidKey = string | number | Date | BufferSource | IDBValidKey[]`
  (`:7`).

Upstream v9 renamed the public storage from `IdbStorage`/`AuthClientStorage` to
`IdbCredentialStorage`/`CredentialStorage` and removed `KEY_STORAGE_KEY` /
`KEY_STORAGE_DELEGATION` (`docs/.../v9.md:47-57`). There is no in-library migration from v8
records; the DB upgrade clears the store.

### 3.3 `LocalCredentialStorage`

`src/client/credentials/local-credential-storage.ts:19-68`. `shared = true`, `durable = true`
(`:20-21`). Key type: **Ed25519** (`:29-31`) because `localStorage` holds strings and Ed25519
private bytes serialise.

| Thing | Exact value |
|---|---|
| Prefix | constructor `prefix = 'ic-'` (`:27`) |
| localStorage key | `${prefix}${slot}` — e.g. `ic-session`, `ic-app`, `ic-session-pending` |
| Record shape | `{ key: string, chain?: string }` (`:4-8`) |
| `key` | `JSON.stringify(identity.toJSON())` (`:49`) |
| `chain` | `JSON.stringify(chain.toJSON())` when present (`:50`) |
| Missing record | `null` (`:34-36`) |
| Corrupt record | `get` returns `null` rather than throwing (`:36-45`) |

Note: the record object literal includes `chain: undefined` when absent; `JSON.stringify` drops
it, so a key-only record is `{"key":"..."}`.

### 3.4 `MemoryCredentialStorage`

`src/client/credentials/memory-credential-storage.ts:15-41`. `shared = false`, `durable = false`
(`:16-17`). Key type: **ECDSA P-256, non-extractable** (`:23-26`).

- Backing store is instance-local `Map<string, Credential>` (`:19-21`), never module-global.
- Records are handed back **as given**, not round-tripped through an encoding (`:10-13`,
  `:28-30`) — that is what lets it hold a non-extractable key at all. Test asserts identity
  equality (`credential-storage.test.ts:23-33`).

### 3.5 `SharedMemoryCredentialStorage` (v11.2.0)

`src/client/credentials/shared-memory-credential-storage.ts:78-303`. `shared = true`,
`durable = false` (`:79-80`). Key type: ECDSA P-256 non-extractable (`:137-139`).

Purpose: an environment with **no durable medium** (IndexedDB and localStorage both unavailable,
or an app that decided nothing may reach disk) where every tab minting for itself is still worth
avoiding. Steady-state reads are local and immediate; the channel keeps the Maps agreeing.

#### Constants

```ts
export const DEFAULT_SHARED_MEMORY_NAME = 'ic-credentials';   // :5
```

The same string is used for **both** the `BroadcastChannel` name and the Web Locks name prefix
(`:117-123`, `:160-162`). Options: `{ name?: string }`.

#### Wire messages (`:8-36`)

| Message | Shape |
|---|---|
| `put` | `{ kind: 'put', slot: string, keyPair: CryptoKeyPair, chain?: string }` |
| `drop` | `{ kind: 'drop', slot: string }` |
| `ask` | `{ kind: 'ask' }` |
| `offer` | `{ kind: 'offer', entries: WireCredential[] }` |

`WireCredential = { slot: string, keyPair: CryptoKeyPair, chain?: string }` (`:8-12`).
`chain` is the chain's JSON, exactly as in IDB. Validation is a narrow `isMessage` switch
(`:43-58`) that accepts `ask`; `drop`/`put` with a string slot; `put` also requires `keyPair`;
`offer` requires an array of entries. Unknown kinds are ignored (test `:208-223`).

#### Replication protocol

| Step | Behaviour |
|---|---|
| Construction | `new BroadcastChannel(name)`; listener → `#receive`; `#synced = #openReplica()` (`:117-123`) |
| `set` | write own replica, `postMessage(put)` (`:150-153`) |
| `remove` | delete own replica, `postMessage(drop)` (`:155-158`) |
| `get` | `await #synced; await #applying;` then read replica (`:141-148`) — a message in hand must not read as a miss |
| `put` received | `#apply(entry, { overwrite: true })` — rebuild identity via `ECDSAKeyIdentity.fromKeyPair`, chain via `DelegationChain.fromJSON`; rebuild failure is swallowed and the slot is not held (`:256-258`, `:270-284`) |
| `drop` received | delete replica slot (`:259-261`) |
| `ask` received | enqueue: post `offer` with **all** entries, **even when empty** — the asker is waiting and "I have nothing" is an answer (`:232-245`) |
| `offer` received | apply each entry with `{ overwrite: false }` — fills gaps only, never replaces a newer local write; then resolve `#synced` (`:249-255`) |
| Ordering | all incoming work is queued on `#applying` so a put applied after the drop that followed it cannot resurrect a slot (`:97-101`, `:266-268`) |
| `close()` | closes channel and releases the presence lock (`:131-135`) — only needed when replacing a store while the page lives |

#### Presence / cold-start sync (Web Locks)

`#openReplica` (`:164-192`) and `#claimPresence` (`:194-227`):

1. If `navigator.locks` or the channel is absent → return immediately; every instance is alone
   ("waiting could only cost a load") (`:168-174`; test `:252-259`).
2. `#claimPresence` first takes a **snapshot** with `locks.query()` and collects held lock names
   starting with `${name}:alive:` except its own — snapshot before requesting, otherwise it would
   wait for a lock it holds itself (`:194-213`).
3. Then requests its own presence lock named `${name}:alive:${crypto.randomUUID()}`
   (`:92`, `:160-162`, `:218-224`), holding it for the instance's life; the browser releases it
   when the document is torn down — the signal no message could carry.
4. If peers existed, post `ask` and wait for `Promise.race([offerAnswered, allPeerLocksGranted])`
   (`:176-192`): a peer that answers ends the wait; a peer that dies ends it because its lock is
   granted at once. There is **no timeout**; a lone instance waits not at all.

#### Web-worker / Service Worker note

This store uses `BroadcastChannel` + Web Locks; it is **not** a SharedWorker. (The v11.2.0
changelog entry says "share the sign-in state with web workers" — the worker-side state store is
`LocalStateStorage`'s IndexedDB mirror, see `state-storage.md` §4.3.)

## 4. Credential lifetime rules (store-independent)

Implemented in `src/client/session/session-identity.ts:76-110` (`readSlot`) and used by the
identity:

- A credential whose chain has `msLeft <= 0` is **spent**: it is declined, and only a caller
  holding the mint lock may `remove` it (`:66-105`). This bounds a stored credential at one
  delegation lifetime with nothing having to fire (there is no dependable "browser closing"
  signal) (`:90-97`).
- A key without a chain is not a credential (`:87-88`).
- Adopting a stored credential is only allowed if its chain is rooted at the account already
  established (`:48-63`).
- Writing a credential is best-effort: a credential that cannot be written is still one this tab
  can use; the cost is other tabs mint for themselves (`session-identity.ts:171-176`).

## 5. Native equivalents (design proposal, marked)

Upstream's credential stores are browser facilities. The Rust port needs:

| Upstream | Browser facility | Native proposal |
|---|---|---|
| `IdbCredentialStorage` | IndexedDB + non-extractable `CryptoKeyPair` | Keep as `wasm-js` only. Native already has `KeyringStorage` (`src/storage/sync_storage/keyring.rs`), `PemStorage` (`pem.rs`), `PasswordStorage` (`password.rs`) — see `gap-analysis.md` |
| `LocalCredentialStorage` | `localStorage` + Ed25519 JSON | Native file/keyring with Ed25519 raw bytes (already the default native key type) |
| `MemoryCredentialStorage` | in-memory | Straightforward `Mutex<HashMap<String, Credential>>` |
| `SharedMemoryCredentialStorage` | BroadcastChannel + Web Locks | No cross-process equivalent needed for native; either in-process `Arc<Mutex<...>>` or a file-backed store. Mark `shared=false`, `durable=true` for file/keyring |

## Rust port checklist

- [ ] Add `Credential { identity: Key, chain: Option<DelegationChain> }` and a
      `CredentialStorage` trait: `fn shared(&self) -> bool`, `fn durable(&self) -> bool`,
      `async fn create(&self) -> Result<Key>`, `async fn get(&self, slot) -> Result<Option<Credential>>`,
      `async fn set(&self, slot, credential) -> Result<()>`, `async fn remove(&self, slot) -> Result<()>`.
- [ ] Keep key-type choice in the store: Ed25519 for string/file media, P-256 non-extractable for
      IDB, P-256/Ed25519 for keyring as the native feature set dictates.
- [ ] Introduce one `Slots` type with `session`, `session_pending`, `app`, `app_pending`,
      `state`, namespaced with `:`.
- [ ] Reuse/extend the existing `src/storage.rs` `StoredKey` only as an internal encoding for
      native stores; do not expose it as the credential API.
- [ ] Implement the `IdbCredentialStorage` equivalent for `wasm-js`: DB `auth-client-db`, store
      `ic-keyval`, version 1, one object store, out-of-line string keys, record
      `{ keyPair: CryptoKeyPair, chain?: string }`; upgrade clears the store; `terminated` +
      `InvalidStateError` single retry; failed open not cached.
- [ ] Implement a `SharedMemoryCredentialStorage` equivalent for `wasm-js`: BroadcastChannel
      `ic-credentials`, messages `put/drop/ask/offer`, presence locks
      `ic-credentials:alive:<uuid>`, `query()` snapshot before claiming, offer fills gaps only,
      queue incoming work in arrival order, `close()` releases the lock.
- [ ] Implement the spent-credential eviction rule (decline without lock, remove under lock).
- [ ] Native: map `CredentialStorage` onto `KeyringStorage` / `PemStorage` / `PasswordStorage`
      (durable, not shared) and a `MemoryCredentialStorage`; mark `shared=false`.
- [ ] Expose `create` on the store so `key_type` stops being a client-level option (upstream v9
      removed `keyType`; see `docs/.../v9.md:53-55`).
