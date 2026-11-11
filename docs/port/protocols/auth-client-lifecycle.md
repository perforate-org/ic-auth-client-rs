# §2 — `AuthClient` lifecycle, state model, and options

Upstream v9 moved the sign-in **out of the client and into storage**
(`docs/src/content/docs/upgrading/v9.md:9-22`). A client is a cheap, disposable view.
Everything in this section follows from that: there is no long-lived identity field that
is the source of truth — `#status` is a cache of the state record, `#identity` is a
derived object.

## 2.1 Construction sequence (`auth-client.ts:427-587`)

Numbered exactly as the constructor runs; order is observable and tests pin it.

| # | Step | Line |
| --- | --- | --- |
| 1 | Store options; `credentialStorage = options.credentialStorage ?? new IdbCredentialStorage()` | `:428-429` |
| 2 | `slots = slotsFor(options.namespace)` | `:430` |
| 3 | `stateStorage = options.stateStorage ?? defaultStateStorage()` — one shared `LocalStateStorage` per page/worker | `:431,367-371` |
| 4 | **Reject a string/URL `identityProvider`** with `TypeError('identityProvider is now an object: pass { authorizeUrl, canisterId } …')` | `:437-441` |
| 5 | Default provider; **reject a half-specified pair** with `TypeError('identityProvider names authorizeUrl and canisterId together, or neither: nothing about the canister is derived from the URL')` | `:443-455` |
| 6 | `canisterId = Principal.from(provider.canisterId)`; parse `authorizeUrl` into `URL` | `:457-459` |
| 7 | If `!disableBrowserActivity`: hook `watchForeground` and `watchActivity`, both → `#refreshInForeground()` | `:460-471` |
| 8 | `#status = #readStatus()` **before** subscribing (the held answer) | `:480` |
| 9 | Subscribe to `stateStorage` under the `state` slot; on change: re-read status → maybe `#restoreAgain()` → fire listeners | `:481-501` |
| 10 | **Reject `openIdProvider` + `ssoDomain` together**: `Error('openIdProvider and ssoDomain are mutually exclusive')` | `:502-504` |
| 11 | If `openIdProvider`: set `openid` query param = provider URL | `:505-507` |
| 12 | If `ssoDomain`: normalize; set `sso` param (normalized, or the trimmed value as typed when invalid); if `derivationOrigin` set, also set `derivationOrigin` param; build `SsoStatusChecker` | `:508-537` |
| 13 | If `prompt`: set `prompt` param; if `hint`: set `hint` param (`hint.toText()`) | `:544-549` |
| 14 | If `resumable ?? stateStorage.resumable ?? false`: set `resumable=true` | `:553-555` |
| 15 | Build transport: `'redirect'` → `UrlTransport({url, callbackUrl: location.origin + location.pathname})`; else `PostMessageTransport({url, windowOpenerFeatures})` | `:557-570` |
| 16 | Build `Signer({ transport, derivationOrigin: this.memoize(() => options.derivationOrigin?.toString()) })` | `:572-582` |
| 17 | Start `#init()` **eagerly, not awaited** | `:586` |

### 2.1.1 Authorize-URL assembly (order matters; later `set` wins on collision)

The URL passed to the transport is `authorizeUrl` plus, in this order:

| Param | Condition | Value | Line |
| --- | --- | --- | --- |
| `openid` | `openIdProvider` set | `OPENID_PROVIDER_URLS[provider]` | `:505-507` |
| `sso` | `ssoDomain` set | normalized domain, or `options.ssoDomain.trim()` if invalid | `:517-520` |
| `derivationOrigin` | `ssoDomain` **and** `derivationOrigin` set | `derivationOrigin.toString()` | `:523-528` |
| `prompt` | `prompt` set | `'none' \| 'login'` | `:544-546` |
| `hint` | `hint` set | `hint.toText()` | `:547-549` |
| `resumable` | `resumable ?? stateStorage.resumable ?? false` | `'true'` (never `'false'`) | `:553-555` |

> Why `derivationOrigin` rides on the URL only with `sso`: the SSO ceremony starts before
> a delegation is requested, so the signer channel carries the derivation origin too late
> (`:521-523`). For every other request the derivation origin is added by the signer's
> ICRC-95 transform (`signer-protocol.md` §9.3).

`callbackUrl` for the redirect transport is `location.origin + location.pathname` — query
and fragment deliberately dropped (`:564`), because the return load must be the same route.

## 2.2 The state model: five slots, two stores

`slots.ts:17-50` defines one namespace, applied by `slotsFor(namespace)` (`:73-78`):

| Slot key | Bare name | Holds | Written by | Read by |
| --- | --- | --- | --- | --- |
| `session` | `session` | session key + session delegation chain (`CredentialStorage`) | sign-in commit `:1773`; restore seeds | `#restoreSession` `:1796`, `#consent` `:1324` |
| `sessionPending` | `session-pending` | ceremony key with **no chain**, redirect flow only | `:1146` | `:1141,1152`; removed `:1082` |
| `app` | `app` | app key + app delegation chain — what every tab acts with | `#promoteAppCredential` `:1514`; `SessionIdentity` `:175` | `SessionIdentity` reads `:410-417` |
| `appPending` | `app-pending` | credential a ceremony minted, until the session is stored | `:1057`; removed `:1517` | promoted only (`:1509-1518`) |
| `state` | `ic-session-state` | `{principal, expiration}` — who is signed in and until when (`StateStorage`) | `#persistSession` `:1784-1787`, `#expireSession` `:1616-1619` | `#readStatus` `:748` |

Namespace separator is `':'` (`slots.ts:58`); a namespace prefixes **all five**
(`:74-77`). The `state` slot is namespaced too, on purpose: two clients must not share an
answer to "who is signed in" while holding separate keys (`slots.ts:42-49`).

Why `sessionPending`/`appPending` are separate names (`slots.ts:21-40`): a cancelled
ceremony must not take a working session with it, and a ceremony must not change what
other tabs of the origin act with before it succeeds.

### 2.2.1 `SessionStatus` derivation — `#readStatus()` (`auth-client.ts:747-759`)

```
record = stateStorage.get(stateSlot)
if record == null                      -> { state: 'signed-out' }
expiresAtMs = Number(record.expiration / 1_000_000n)   // ns -> ms, truncating
if Date.now() >= expiresAtMs           -> { state: 'expired', principal, expiresAtMs }
else record.held                       -> { state: 'signed-in', principal, expiresAtMs }
else                                   -> { state: 'signed-in-elsewhere', principal, expiresAtMs }
```

`held` is **derived on read and never published** (`state-storage.ts:17-26`): a cookie
record reaches siblings that hold no credential, and each origin composes `held` itself
(`cookie-state-storage.ts:169-174`). `LocalStateStorage` always reports `held: true`
(`local-state-storage.ts:68-74`) because the record is written by this origin and read by
no other.

`getStatus()` (`:688-705`) is the only place expiry is evaluated lazily:

- returns the **same object** until something changes (important for
  `useSyncExternalStore`; `:688-696`);
- if `state != 'signed-out'` and `Date.now() >= expiresAtMs`, rebuild **once** as
  `expired`, keeping `principal` and `expiresAtMs` (`:698-703`);
- no write happens on expiry — the record stays, so every tab/sibling reads `expired`.

`isAuthenticated()` is exactly `getStatus().state === 'signed-in'` (`:653-655`);
`getPrincipal()` is `status.state === 'signed-in' ? status.principal : undefined`
(`:678-681`). These three can never disagree — a stated invariant (`:657-677`).

### 2.2.2 Allowed state transitions

```
signed-out ──signIn commits #persistSession──▶ signed-in
signed-in  ──time passes (lazy getStatus)──▶ expired
signed-in  ──mint refused, record unchanged (#expireSession)──▶ expired
signed-in  ──signOut (#endSession: state removed)──▶ signed-out
signed-in  ──restore finds no credential (#dropSession: discard)──▶ signed-out
signed-in-elsewhere ──silent signIn (prompt:'none') commits──▶ signed-in
signed-in-elsewhere ──signOut──▶ signed-out
expired    ──signIn──▶ signed-in
```

`#endSession` (`:1816-1820`) = `stateStorage.remove(state)` + `#clearCredentials()`;
`#dropSession` (`:1831-1835`) = `stateStorage.discard(state)` + `#clearCredentials()`. The
difference is deliberate: **sign-out retracts the shared record**, *finding out* does not
(`state-storage.ts:54-66`, `auth-client.ts:1822-1835`).

`#clearCredentials()` removes `session` and `app` in parallel with `allSettled`, then
throws the first failure (`:1856-1863`). The `session-pending` slot is **not** cleared —
an abandoned ceremony may still return for it (`:1846-1848`).

## 2.3 `#init()` / restore / hydrate

`#init()` (`:1665-1676`) memoises `#restore()`; **a rejection clears the memo** so a later
call retries instead of replaying a network failure (`:1659-1675`). `ready()` simply
returns `#init()` (`:610-612`) and is only needed where the state store loads
asynchronously (worker) (`:589-608`).

`#restore()` (`:1680-1688`): set `#restoring = true` → `await stateStorage.ready?.()` →
`#hydrate()` → clear flag.

`#hydrate()` (`:1693-1762`), in order:

1. `restored = await #restoreSession()`.
2. No key/chain → if status is `signed-in`, `#dropSession()`; install `AnonymousIdentity`;
   return (`:1697-1706`).
3. State record absent → `#endSession()`, install anonymous, return (`:1713-1719`).
4. Key cannot sign → install anonymous, return (`:1721-1724`).
5. `#openSession(key, chain)`; on `AccountMismatchError` → `#dropSession()`, install
   anonymous (`:1726-1738`). Any other error propagates.
6. If disposed while in flight → `identity.dispose()`, install nothing (`:1740-1745`).
7. Re-read state; if absent or its principal ≠ the identity's principal → dispose the
   identity, install anonymous, `#dropSession()` (`:1752-1760`).
8. Otherwise `#installIdentity(identity)` (`:1761`).

`#restoreSession()` (`:1795-1808`): read `session` slot; absent → `null`; chain absent or
`!isDelegationValid(chain)` → `#clearCredentials()` (unless read-only) and `null` — the
**state record is kept**, so it reads as `expired` rather than `signed-out`
(`:1799-1805`).

`#restoreAgain()` (`:1631-1657`) coalesces a burst: if a restore is queued, return;
otherwise chain onto `#initPromise` and run one more `#restore()`. It fires from the state
subscription only when `#interactions === 0 && !#restoring && !#disposed` (`:496-498`).

## 2.4 `getIdentity()` (`:617-648`)

1. `await #init()`.
2. `await #committing?.catch(() => undefined)` — a ceremony writing the record/identity is
   allowed to finish so a subscriber asking for the identity waits for it (`:621`).
3. If `#readStatus().state` is `signed-in` **or** `signed-in-elsewhere`, the client is not
   disposed, and `#identity` is still `AnonymousIdentity` → **throw
   `SessionNotHeldError`** (`:639-646`).
4. Return `#identity`.

> Rationale (`:623-638`): returning anonymous while the record says signed in would send
> calls out unauthenticated. An expired record is exempt (nothing to acquire), and a
> disposed client is exempt (it was told to stop).

## 2.5 `subscribe()` and `dispose()`

`subscribe(listener)` (`:782-790`) adds to `#listeners`, returns an unsubscribe. Fired by
the client **after** `#status` is refreshed, so a listener reading `getStatus()` sees what
it was told about (`:481-500,782-785`). It covers:

- the state record changing for any reason (own write excluded while restoring/ceremony,
  `:487-498`);
- the SSO status changing (`sso.ts:360-364` → `auth-client.ts:530-536`);
- a peer client on the page, another tab, or a sibling subdomain.

It does **not** fire for an app delegation rotating under a held identity (`:776-778`).

`dispose()` (`:798-823`) is synchronous and releases, in order: SSO checker; `#disposed =
true`; `#identity.dispose()` if it is a `SessionIdentity`; fire `signer.closeChannel()` if
interactions are in flight; release the channel lock; unhook foreground/activity/state
listeners. It is **not** sign-out: nothing shared is written (`:804-811`).

## 2.6 Worker (read-only) mode — v11.2.0

`LocalStateStorage` cannot read `localStorage` in a worker, so it is **read-only** there
(`local-state-storage.ts:44-45`): `set`/`remove` throw `readOnlyError()`
(`:11-15,80-92`). A tab mirrors every write/subscription into IndexedDB
(`auth-client-state-db` / `ic-keyval`, `:6`) and announces the key on a `BroadcastChannel`
named `ic-session-state` (`:9,181-207`); a worker loads the mirror and fires `ready()`
once subscribed keys have landed (`:52-59,197-207`). `AuthClient` then changes nothing
shared: `#isReadOnly` short-circuits `signIn`/`signOut` (`:924,1390`) and the teardown
methods (`:1615,1817,1832`), and a session it finds unusable is left for a page to end
(`:1837-1844`).

## Rust port checklist

- [ ] Implement the five slots (`session`, `session-pending`, `app`, `app-pending`,
      `ic-session-state`) with the `:` namespace prefix; a namespaced client must move all
      five.
- [ ] `getStatus` must return the same value until a change (cheap to clone a small enum
      in Rust; the *stable-object* requirement is a JS-framework concern — note it in docs).
- [ ] Derive `SessionStatus` from the state record only; expiry is evaluated on read and
      writes nothing. `expired` keeps `principal`/`expires_at_ms`.
- [ ] `isAuthenticated` = `status == SignedIn`; `getPrincipal` = `Some` only for
      `SignedIn`; assert these in tests.
- [ ] Implement `init()` memoisation with **retry after failure**, eager start in the
      constructor, and `ready()` as the same future.
- [ ] Implement `getIdentity()`'s `SessionNotHeld` guard (record live + anonymous +
      not disposed).
- [ ] Implement `subscribe`/`dispose`; `dispose` must cancel the identity's scheduled
      refresh and must not write shared state.
- [ ] Model the state store as a synchronous `StateStorage` trait
      (`get/set/remove/discard/subscribe`, `resumable`, `is_read_only`, `ready`) and the
      credential store as async with `shared`/`durable`.
- [ ] Worker read-only support is browser-only; mark as a `wasm-js` feature with a
      design proposal (`rust-port-mapping.md` §10.6) rather than a `Send`-safe abstraction.
