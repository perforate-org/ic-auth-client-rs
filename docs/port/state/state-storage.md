# Upstream v11.2.0 — State Storage Specification (for the Rust port)

Upstream: `/tmp/icp-js-auth` at `@icp-sdk/auth` **11.2.0** (`package.json:3`).
Sources of truth: `src/client/state/*.ts`, `src/client/slots.ts`, `src/client/auth-client.ts`,
`tests/client/state/*`, `docs/src/content/docs/upgrading/v9.md`.

This file specifies the **state record** layer only — *who is signed in here and until when*.
The credential (key + delegation) layer is in `credential-storage.md`.

---

## 1. `SessionState` — exact shape

`src/client/state/state-storage.ts:12-31` (verbatim):

```ts
export interface SessionState {
  principal: Principal;      // the account principal a canister sees as caller
  expiration: bigint;        // nanoseconds since epoch, matching Delegation.expiration
  held: boolean;             // DERIVED on read, never published
}
```

| Field | Type | Persisted? | Meaning |
|---|---|---|---|
| `principal` | `Principal` | yes | Account principal (self-authenticating key of the **account key**, not the session key) |
| `expiration` | `bigint` (ns) | yes | Session expiry = **earliest delegation expiry of the session chain** (`auth-client.ts:1768-1785`) |
| `held` | `boolean` | **no** | Whether *this origin* holds a credential for that account. Derived by each store from a per-origin medium; `signed-in-elsewhere` is `held === false` |

`set()` accepts `Omit<SessionState, 'held'>`; `held` is never written
(`state-storage.ts:34`). Rationale (`state-storage.ts:21-27`): a record shared past one origin
cannot carry a per-origin fact.

A record may be **stale**: it is what this browser knows, not an authority against the network
(`state-storage.ts:44-47`). Expiry is not enforced by the store; the client interprets it.

## 2. `StateStorage` interface — exact contract

`src/client/state/state-storage.ts:49-112`:

| Member | Signature | Semantics |
|---|---|---|
| `get(key)` | `(string) => SessionState \| null` | synchronous, no await; `null` = nothing signed in within this store's reach |
| `set(key, state)` | `(string, Omit<SessionState,'held'>) => void` | writes the record and whatever the store publishes past this origin |
| `remove(key)` | `(string) => void` | sign-out: removes the record **including what reaches siblings** |
| `discard(key)` | `(string) => void` | *finding out*: removes only what this origin holds, leaves a shared record alone. Stores that publish nothing answer it with `remove` (`state-storage.ts:74-84`; implementations: `memory-state-storage.ts:30-33`, `local-state-storage.ts:94-97`) |
| `resumable?` | `readonly boolean` | absent = false; true only where the record reaches past this origin (only cookie store, `cookie-state-storage.ts:69`). Drives `resumable` query param (`auth-client.ts:553`) |
| `subscribe(key, listener)` | `(string, () => void) => () => void` | **required**; fires when the record under `key` changes, including changes made by another context. Returns unsubscribe |
| `isReadOnly?` | `readonly boolean` | absent = false; true in a worker: the client then changes nothing shared (`auth-client.ts:1842-1844`) |
| `ready?()` | `() => Promise<void>` | resolves once `get` answers with loaded state; absent = ready immediately. The client awaits it before restore (`auth-client.ts:1683`) |

Design invariant enforced by every implementation: a listener is only fired when the *answer*
actually changed since that listener was last told (raw-string compare), and it is fired only
**after** the new value is readable. See `memory-state-storage.ts:45-61`,
`local-state-storage.ts:107-115`, `cookie-state-storage.ts:218-234`.

## 3. `MemoryStateStorage`

`src/client/state/memory-state-storage.ts:10-75`.

- Backing store: `Map<string, Omit<SessionState,'held'>>` on the instance, never module-global
  (`:11`), so two clients are only shared if handed the same instance and tests do not leak.
- `get` returns `{...state, held: true}` (`:14-18`).
- Raw compare string (`:69-74`): `` `${principal.toText()}|${expiration.toString()}` ``.
- `isReadOnly`/`ready`/`resumable` absent.

## 4. `LocalStateStorage` (default store)

`src/client/state/local-state-storage.ts:38-216`.

### 4.1 Exact persistence

| Thing | Value |
|---|---|
| Medium | `globalThis.localStorage` |
| Key | the slot passed by the client, i.e. `ic-session-state` (bare) or `<namespace>:ic-session-state` |
| Value format | `` `${principal.toText()}|${expiration.toString()}` `` — **not JSON** (`:34-36`, `:82`) |
| Example | `2vxsx-fae|1893456000000000000` |
| Parse failure | any missing separator, unparseable principal or expiration ⇒ `get` returns `null`, never throws (`:61-78`; test `local-state-storage.test.ts:108-117`) |
| `held` | always `true` — the record is written by this origin and read by no other (`:71-73`) |

Why the pipe format: an expiration is a `bigint` and JSON cannot carry one (`:34-36`).

### 4.2 Worker mode (no `localStorage`)

`isReadOnly = !hasLocalStorage()` (`:45`; `hasLocalStorage` catches the throw when the browser
blocks storage, `:17-24`). In a worker:

- reads come from `#mirrored: Map<string,string|null>` (`:49`, `:176-179`);
- `set`/`remove`/`discard` throw `readOnlyError()` (`:80-97`, `:11-15`), message:
  `The sign-in state is read-only in a worker: sign in and sign out from a page of this origin.`
- `ready()` awaits the load queue, including loads queued while it waited (`:52-59`).

### 4.3 Tab → worker mirror (v11.2.0 feature)

Constants (`:5-9`):

```ts
const MIRROR_DB = { dbName: 'auth-client-state-db', storeName: 'ic-keyval' };
const MIRROR_CHANNEL = 'ic-session-state';
```

| Step | Behaviour |
|---|---|
| Tab `set`/`remove` | writes `localStorage`, fires local subscribers, then `void #mirror(key)` (`:80-92`) |
| `#mirror(key)` | `IdbKeyVal.create(MIRROR_DB)` → `db.set(key, { raw: <localStorage value or null> })` → `new BroadcastChannel('ic-session-state').postMessage(key)` → close (`:181-195`). IndexedDB value shape is exactly `{ raw: string \| null }` |
| Worker `subscribe(key)` | `#load(key)`: open mirror DB, `db.get<{raw}>(key)`, set `#mirrored`, fire (`:197-207`); loads are chained on `#loads` so a later load always lands last (`:50`, `:198`) |
| Worker `BroadcastChannel` message | message payload is **the key string itself** (`event.data === key`, `:131-138`); worker reloads, tab re-checks |
| Tab on channel message | re-checks its own raw value (a write by another store in the same tab raises no `storage` event) |
| `subscribe` in a tab | also mirrors immediately (`:120-128`), which repairs a mirror left by an older version or a closing page |
| Failure | no IndexedDB / no channel is swallowed; workers keep what they have until the next write (`:191-194`, `:202-204`) |

### 4.4 Subscription sources

`subscribe` (`:107-170`) hooks, in order:

1. local `#subscribers` set, fired on same-tab `set`/`remove` (`:172-174`);
2. `BroadcastChannel('ic-session-state')` — message === key;
3. `globalThis.addEventListener('storage')` — `event.key === key || event.key === null`
   (`null` = whole store cleared, `:140-144`);
4. if `document` exists: `document.visibilitychange` (only when `visibilityState === 'visible'`),
   `globalThis.pageshow`, `globalThis.focus` — recovery from bfcache/frozen tabs (`:146-158`).

Every source routes through `check()`, which compares the raw string and fires only on change.
Unsubscribe removes all of the above and closes the channel (`:160-169`).

## 5. `CookieStateStorage` — cross-subdomain record

`src/client/state/cookie-state-storage.ts:59-304`.

### 5.1 Constructor and exact cookie attributes

`new CookieStateStorage({ domain: string })` (`:30-41`, `:90-150`).

Domain validation, in order:

1. Loopback detection (`:24-28`): `localhost`, `*.localhost`, `127.0.0.1`, `[::1]`.
   `loopback = isLoopbackHost(domain) && (hostname undefined || isLoopbackHost(hostname))`
   (`:96-98`).
2. Host check (`:104-113`): unless loopback, require `hostname === domain` or
   `hostname.endsWith('.' + domain)`; otherwise throw
   `A cookie cannot be scoped to '<domain>' from '<hostname>': the domain has to be this host or one above it`.
3. Cookie attributes (`:115-125`):

| Attribute | Value |
|---|---|
| `Domain` | `Domain=<options.domain>` — **omitted entirely on loopback** (browsers reject `Domain=localhost`; host-only cookies span ports) |
| `Path` | `/` |
| `SameSite` | `Lax` |
| `Secure` | present only when `location.protocol === 'https:'` |
| `Max-Age` | `RECORD_MAX_AGE_SECONDS = 400*24*60*60 = 34560000` on `set` (`:18`, `:185`); `Max-Age=0` on `remove` (`:192`) |

Why 400 days (`:5-17`): it is the browser ceiling for persistent cookies (Chrome/Edge/Firefox
truncate longer); Safari caps script-written cookies at 7 days, which merely shortens the
record. The cookie lifetime is **not** the session lifetime: the record is deliberately kept
past expiry so every sibling can say *the session ended* rather than *nobody signed in*.

4. Probe (`:127-149`): if `document` exists, write `ic-cookie-probe=1` with the same attributes,
   read it back, always clean up with `Max-Age=0`. Failure throws
   `A cookie scoped to '<domain>' cannot be written from '<hostname>': the browser refused it. The domain may be a public suffix, or cookies may be disabled.`
   This is the only check that catches public suffixes (`co.uk`) and cookies disabled.

### 5.2 Cookie name / value format

| Thing | Value |
|---|---|
| Cookie name | `encodeURIComponent(key)` — for the default slot this is literally `ic-session-state` |
| Cookie value | `encodeURIComponent(`${principal.toText()}|${expiration.toString()}`)` (`:183-185`) |
| Read | split raw on `|`; `Principal.fromText`, `BigInt(expiration)`; any failure ⇒ `null` (`:152-178`) |
| Malformed unrelated cookie | `readCookie` decodes each entry name in a `try` and skips on error, so a stray `%` cannot break reads (`:290-304`; test `cookie-state-storage.test.ts:185-198`) |

### 5.3 `held` for a cookie record

The cookie is the domain's; `held` is per origin. `CookieStateStorage` composes them
(`:71-83`, `:152-178`):

```ts
readonly #local = new LocalStateStorage();   // per-origin claim, same key
get(key):
  if (isReadOnly) return #local.get(key)     // worker: only this origin's claim
  cookie = readCookie(key); if null -> null
  local  = #local.get(key)
  return { principal, expiration,
           held: local !== null && local.principal.compareTo(principal) === 'eq' }
```

`held` compares **principal identity**, not mere local-record existence: a record can outlive
the sign-in it describes, and a sibling signing in as someone else publishes a cookie this
origin holds no credential for (`:160-174`; tests `:59-88`).

Write order matters: `set` writes `#local` **first**, then the cookie, then fires (`:180-187`),
so nothing reads the cookie as held before the local claim exists.

`remove` (`:189-194`): local remove + cookie `Max-Age=0` + fire.
`discard` (`:196-207`): local remove **only**, cookie untouched + fire — a sibling may have
written the cookie a moment ago, so retracting it would tell that sibling its new session is
gone.

`isReadOnly` / `ready` delegate to the internal `LocalStateStorage` (`:80-88`).

### 5.4 Subscription sources for cookies

`subscribe` (`:209-274`), same `stateOf` compare as the local store but including `held`
(`:281-288`): `` `${principal}|${expiration}|${held}` ``.

Sources:

- worker: the internal local store's subscription (`:239-246`);
- `visibilitychange` when visible (`:248-250`);
- `storage` events from the per-origin `localStorage` claim (`event.key === key || null`)
  (`:251-258`);
- `pageshow`, `focus` (`:259-261`);
- `cookieStore.addEventListener('change')` where the Cookie Store API exists (`:263-264`).

`document.cookie` raises no event and `BroadcastChannel` does not cross origins
(`:209-217`): a sibling's sign-out is only visible by *looking*, which is why visibility/focus
re-checks exist.

## 6. Cross-subdomain sign-in — end-to-end contract

Documented in `docs/src/content/docs/upgrading/v9.md:33-35,96-102` and implemented by the
pieces above plus the client options.

1. App on `a.example.com` uses `stateStorage: new CookieStateStorage({ domain: 'example.com' })`
   and signs in. Cookie `ic-session-state` is written domain-wide; `a`'s `localStorage` holds
   the per-origin claim.
2. App on `b.example.com` with the same cookie store reads `{principal, expiration, held:false}`
   ⇒ `getStatus() === { state: 'signed-in-elsewhere', principal, expiresAtMs }`
   (`auth-client.ts:746-759`).
3. To act, `b` builds a client with `prompt: 'none'` and `hint: <principal>`
   (`auth-client.ts:184-230`); those are baked into the authorize URL as query params
   (`auth-client.ts:544-550`). `resumable` is sent as `resumable=true` when
   `options.resumable ?? stateStorage.resumable ?? false` (`auth-client.ts:553-555`), which is
   `true` for `CookieStateStorage`.
4. If Internet Identity answers the silent request with `interaction_required`, the client
   throws `InteractionRequiredError` and the app must run an interactive ceremony
   (`session-delegation.ts:22-50`).
5. `signOut()` on any origin removes the cookie ⇒ every sibling reads signed-out
   (`cookie-state-storage.ts:189-194`; v9 doc line 96).

`held:false` is what tells a sibling to acquire its own credential; `isAuthenticated()` is
false for it (`auth-client.test.ts:466-486`).

## 7. Pending-redirect keys, journal / `memoize`, and "abandoned entries"

### 7.1 Slots (see also `credential-storage.md` §2)

`src/client/slots.ts:17-50`:

| Slot | Bare name |
|---|---|
| `session` | `session` |
| `sessionPending` | `session-pending` |
| `app` | `app` |
| `appPending` | `app-pending` |
| `state` | `ic-session-state` |

Namespacing (`slots.ts:52-78`): prefix `${namespace}:` on **every** slot including `state`;
separator is a cross-origin contract because a sibling reads the state record by name.

### 7.2 Redirect flow state

`auth-client.ts:1104-1261` (`#ensureSessionKeyForRedirectFlow`):

- A redirect sign-in runs twice (outbound load and return load); both must use the same session
  key, so the outbound load writes it to the **`session-pending`** credential slot and the return
  load reads it back (`:1110-1114`).
- Refuses if `!credentialStorage.durable` (`:1125-1129`): the medium must survive the document
  teardown; a store only other tabs can read is not enough.
- The key's **public half** is journaled via `transport.memoize` (`:1140-1150`); on the return
  load the journaled value is compared to the slot (`:1152-1160`). Mismatch throws
  `This sign-in was superseded by another one in this browser`.
- Cleanup: after a successful sign-in `session-pending` is removed best-effort
  (`auth-client.ts:1080-1086`); the ceremony's app credential is promoted from `app-pending`
  to `app` and `app-pending` is removed best-effort (`auth-client.ts:1503-1517`).

### 7.3 Journal ownership (important: not in this repo)

The redirect **journal** is owned by the external dependency `@icp-sdk/signer` (`^6.1.0`,
`package.json:66`) — `UrlTransport.memoize` (`auth-client.ts:558-570`, `:1374-1382`). This repo
only depends on its contract, which the tests model:

- values are keyed by **call order**, replay across the redirect, and must be JSON-serialisable
  (`auth-client.ts:1358-1371`);
- `memoize` is polymorphic: a sync producer returns synchronously (needed in the constructor),
  an async producer returns a promise, and the replay preserves that (`fake-url-transport.ts:77-99`);
- the return URL carries `state` and `message` fragment params (`auth-client-redirect-replay.test.ts:49-58`).

There is **no sweeping of abandoned journal entries in this repository**; do not invent one.
What this repo does sweep, precisely:

| Leftover | Swept by | Where |
|---|---|---|
| `session-pending` after a completed sign-in | best-effort `remove` | `auth-client.ts:1080-1086` |
| `app-pending` after promotion | best-effort `remove` | `auth-client.ts:1515-1517` |
| spent app credential (delegation expired) | evicted under the mint lock | `session-identity.ts:90-105` |
| state mirror lagging `localStorage` | repaired on every `subscribe` (`#mirror`) | `local-state-storage.ts:120-128` |
| mirror entry after a state removal | `#mirror` writes `{ raw: null }` | `local-state-storage.ts:182-195` |

The state record itself is intentionally **not** swept when it expires: it is kept so
`expired` can name the account (`cookie-state-storage.ts:5-17`; test `:108-120`).

## 8. Encoding, size and JSON constraints

| Store | Encoding | Constraint (as implemented) |
|---|---|---|
| `LocalStateStorage` | `<principal text>|<ns decimal>` | bigint not representable in JSON ⇒ pipe string (`local-state-storage.ts:34-36`). No length check in code; `localStorage` quota applies (browser) |
| `CookieStateStorage` | `encodeURIComponent(principal|expiration)` | No explicit size check; browsers cap a cookie (~4 KB) and the payload is ~85 bytes. Cookie lifetime ceiling 400 days (`:18`) |
| Mirror IDB | structured-clone of `{ raw: string \| null }` | no JSON |
| Credentials in `localStorage` | JSON `{ key, chain? }` (`local-credential-storage.ts:4-8,47-54`) | Ed25519 only, because private bytes must serialise |
| Credentials in IDB | structured clone of `{ keyPair: CryptoKeyPair, chain?: string }` | non-extractable ECDSA key handle; chain JSON is a string |
| Redirect journal | JSON (dependency) | call-order keyed, JSON-serialisable (`auth-client.ts:1358-1371`) |
| `stateOf` compares | strings | `principal|expiration|held` (`cookie-state-storage.ts:281-288`) |

---

## Rust port checklist

- [ ] Define `SessionState { principal: Principal, expiration: u64 /* ns */, held: bool }` and a
      `StateStorage` trait with `get/set/remove/discard`, `subscribe(key, cb) -> Subscription`,
      `resumable() -> bool`, `is_read_only() -> bool`, `ready() -> Option<BoxFuture<()>>`.
      Keep `set` taking a state **without** `held`.
- [ ] Make `subscribe` mandatory and fire only on a real change, after the new value is readable;
      compare a canonical string, not structs.
- [ ] Implement `MemoryStateStorage` (instance-local, `held = true`).
- [ ] Implement `LocalStateStorage` for `wasm-js`: key `<namespace>:ic-session-state`, value
      `<principal>|<expiration_ns>`, tolerant parse to `None`.
- [ ] Implement the v11.2 worker mirror: DB `auth-client-state-db`, store `ic-keyval`, value
      `{ raw: string | null }`; BroadcastChannel name `ic-session-state` carrying the key string;
      worker read-only mode with the exact error text; `ready()` waits for queued loads.
- [ ] Implement `CookieStateStorage` for `wasm-js`: domain validation, loopback rule, exact
      attributes (`Domain` omitted on loopback, `Path=/`, `SameSite=Lax`, `Secure` iff https),
      `Max-Age=34560000`, probe cookie `ic-cookie-probe`, `held` composed from a per-origin
      claim compared by principal.
- [ ] Implement cookie subscriptions via visibility/pageshow/focus + `storage` + optional
      `cookieStore.change`; compare `principal|expiration|held`.
- [ ] Native equivalent: a file-backed state store (e.g. `<data_dir>/<service>/state.json`) that
      is `resumable = false`, `is_read_only = false`, with an in-process subscription channel;
      no cookie analogue (state is per install, not per subdomain). Mark cookie sharing as
      **not-applicable for native**.
- [ ] Add a `resumable` flag to the client config and thread it into the authorize URL as
      `resumable=true`.
- [ ] Model `prompt: 'none' | 'login'`, `hint: Principal`, `derivation_origin` as client options
      and authorize-URL params for the sibling-acquisition flow.
- [ ] Keep slot names in one `Slots` struct (`session`, `session-pending`, `app`, `app-pending`,
      `ic-session-state`) with `:` namespacing applied to all five.
- [ ] Add a `StateStatus` reader that maps a record to `signed-in` / `signed-in-elsewhere` /
      `expired` / `signed-out` and checks expiry lazily (see `subscriptions-and-status.md`).
