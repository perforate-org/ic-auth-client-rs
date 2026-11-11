# Upstream v11.2.0 — Subscriptions & Status Specification (for the Rust port)

Upstream: `/tmp/icp-js-auth` at `@icp-sdk/auth` **11.2.0**.
Sources: `src/client/auth-client.ts`, `src/client/state/*`, `docs/src/content/docs/upgrading/v9.md:29-43`,
`docs/src/content/docs/upgrading/v11.md`, `tests/client/auth-client.test.ts`,
`tests/client/state/*`.

---

## 1. `SessionStatus` — exact shape

`src/client/auth-client.ts:324-332` (verbatim):

```ts
export type SessionStatus =
  | { state: 'signed-in';            principal: Principal; expiresAtMs: number }
  | { state: 'signed-in-elsewhere';  principal: Principal; expiresAtMs: number }
  | { state: 'expired';              principal: Principal; expiresAtMs: number }
  | { state: 'signed-out' };
```

| State | Meaning (v9 doc `:33`) | `isAuthenticated()` | `getPrincipal()` |
|---|---|---|---|
| `signed-in` | this origin holds a credential and can act as the user | `true` | the principal |
| `signed-in-elsewhere` | someone is signed in on this domain while this origin holds nothing for them yet | `false` | `undefined` |
| `expired` | the session ended (ran out or provider ended it) and still names whose it was | `false` | `undefined` |
| `signed-out` | nobody is | `false` | `undefined` |

`expiresAtMs` is `Number(record.expiration / 1_000_000n)` (`auth-client.ts:752`). It is present in
**every** state where a record exists, so an application can name the account and count down
without reading the store (`auth-client.ts:317-322`; tests `auth-client.test.ts:402-465`).

`getPrincipal()` returns `status.state === 'signed-in' ? status.principal : undefined`
(`auth-client.ts:676-686`). The narrowness is deliberate: `if (getPrincipal())` must mean "calls
made as it will be accepted", so an expired record or a record this origin holds nothing for
answers `undefined` (`:659-675`).

`isAuthenticated()` is exactly `getStatus().state === 'signed-in'` (`auth-client.ts:653-655`), so
the two can never disagree (test `auth-client.test.ts:1182-1200`).

## 2. `getStatus()` — synchronous, stable, lazily expiring

`auth-client.ts:688-705`:

- Reads a **held** `#status` object, not the store, on every call.
- The **same object** is returned until something actually changes. A page renders on this and a
  framework comparing by identity (`useSyncExternalStore`) must not see a change on every render;
  returning the held one also avoids a `Principal.fromText` per call (`:690-697`).
- Expiry is the one transition with **no write behind it**, so it is the one thing checked here:
  `if (state !== 'signed-out' && Date.now() >= expiresAtMs)` rebuild the answer once as `expired`
  with the same principal and expiry (`:698-704`).

Tests: same object until change (`auth-client.test.ts:1893-1911`), flips to `expired` without a
write and holds that answer (`:1912-1931`), carries `expiresAtMs` in every record-bearing state
(`:402-445`), `signed-in-elsewhere` for a record with `held:false` (`:367-401`, `:466-486`).

`#readStatus()` (`auth-client.ts:746-759`) is the store→status mapping:

```
record = stateStorage.get(stateSlot)
if record === null -> { state: 'signed-out' }
expiresAtMs = Number(record.expiration / 1e6)
if Date.now() >= expiresAtMs -> { state: 'expired', principal, expiresAtMs }
return record.held ? signed-in : signed-in-elsewhere
```

## 3. Status transitions

| From | To | Trigger | Where the client acts |
|---|---|---|---|
| `signed-out` | `signed-in` | `signIn()` completed (record + credentials written) | `#persistSession` writes the record; `#openSession` installs identity (`auth-client.ts:1064-1070`) |
| `signed-out` | `signed-in` | page load restoring a session | `#hydrate` (`auth-client.ts:1693-1761`) |
| `signed-out` | `signed-in-elsewhere` | a shared (cookie) record appears, this origin holds no credential | `held:false` composed by `CookieStateStorage.get` (`cookie-state-storage.ts:152-178`) |
| `signed-in` | `signed-in-elsewhere` | this origin `discard`s its claim (chain found dead, sibling may have replaced the sign-in) | `#dropSession` → `stateStorage.discard` (`auth-client.ts:1831-1835`, `:1589-1602`) |
| `signed-in` | `expired` | session expiry passes (lazy, no write) | `getStatus` (`auth-client.ts:698-704`) |
| `signed-in` | `expired` | a mint is refused with `SessionGoneError` and the record still names this session | `#endOrDrop` → `#expireSession` (`auth-client.ts:1589-1621`) |
| `signed-in-elsewhere` | `signed-in` | this origin acquires its own credential (silent `prompt:'none'` sign-in, or restore/mint) | `signIn` / `#hydrate` |
| any | `signed-out` | `signOut()` removes the record (`stateStorage.remove`) | `#endSession` (`auth-client.ts:1816-1821`) |
| any | `signed-out` | the record is removed elsewhere (another tab / sibling sign-out) | state subscription → `#readStatus` |
| `expired` | `signed-in` | a new sign-in writes a new record | `signIn` |

`#expireSession` writes the record with `expiration = BigInt(Date.now()) * 1_000_000n` and clears
credentials (`auth-client.ts:1614-1621`). It is a **write**, not a removal, so every tab and sibling
reads `expired` and can name the account. Signing out is the act that removes the record
(`:1604-1613`; test `auth-client.test.ts:2158-2184`).

`#endOrDrop` refuses to publish `expired` when the record moved on (different principal or
expiration): someone else owns the sign-in now, so this origin converges to them via `discard`
instead of retracting what they published (`auth-client.ts:1589-1602`;
test `auth-client.test.ts:2214-2245`).

## 4. `subscribe(listener)` / `dispose()`

### 4.1 `subscribe`

`auth-client.ts:761-791`:

- `subscribe(listener: () => void): () => void`; adds to `#listeners`, returns an unsubscribe.
- Fired **by the client**, not by the store, because the answer has to be up to date before a
  listener asks for it; a store announcing first would let a listener read a status one change
  behind (`:783-786`).
- It says *that something changed*, not *what*; a listener reads `getStatus()` (or
  `getSsoStatus()`) (`:771-779`).
- It also fires for the **SSO status** of a client built with `ssoDomain` (v11:
  `docs/.../v11.md:57-62`; listener wired at `auth-client.ts:536-542`).
- It does **not** fire for app-delegation rotation: a rotation is deliberately invisible, and
  nothing about who is signed in changes when it happens (`:776-779`).

Firing order inside the state subscription (`auth-client.ts:480-501`), which is the contract that
matters:

1. `#status = #readStatus()` — the held answer first;
2. `#restoreAgain()` if `#interactions === 0 && !#restoring && !#disposed` — then the restore, so a
   listener that awaits `getIdentity()` waits for the identity of the sign-in it was told about
   (`:488-500`; v10.0.1 changelog entry; tests `auth-client.test.ts:1960-1994`);
3. then every listener (`:500`).

### 4.2 What causes a subscription to fire

| Source | Mechanism | Where |
|---|---|---|
| same-tab write by this client | store's `#fire` on `set`/`remove` | `memory-state-storage.ts:63-65`, `local-state-storage.ts:172-174`, `cookie-state-storage.ts:276-278` |
| another tab of this origin | `storage` event (`key === key` or `key === null`) | `local-state-storage.ts:140-144`, `cookie-state-storage.ts:251-258` |
| a worker, or a tab hearing a worker's mirror | `BroadcastChannel('ic-session-state')` carrying the key string | `local-state-storage.ts:129-138`, `:181-195` |
| another client on the same page sharing a `MemoryStateStorage` | the store's own listener set | `memory-state-storage.ts:45-61` |
| a sibling subdomain's cookie write/removal | re-check on `visibilitychange` (visible), `pageshow`, `focus`, or `cookieStore.change` | `cookie-state-storage.ts:209-274` |
| this origin dropping its claim (only `held` changed) | `discard` fires; `stateOf` includes `held` | `cookie-state-storage.ts:228-234`, `:281-288` |
| SSO answer arriving | `SsoStatusChecker` invokes the client's listener set | `auth-client.ts:536-542` |

Every store deduplicates: a source fires a listener only if the canonical string changed since
that listener was last told (`state-storage.md` §2). Tests: `local-state-storage.test.ts:63-106`,
`cookie-state-storage.test.ts:208-255`, `memory-state-storage.test.ts:62-109`.

### 4.3 `dispose()`

`auth-client.ts:793-815` — releases what the client hooked, and **does not sign out**:

| Released | Detail |
|---|---|
| SSO checker | `#sso?.dispose()` (`:799`) |
| `#disposed = true` | so an in-flight restore installs nothing (`:800-803`, `:1742-1746`) |
| the `SessionIdentity` | `dispose()` cancels its scheduled refresh (`:804`; `session-identity.ts:382-386`) |
| the signer channel | `closeChannel()` only if this client had an interaction (`:806-808`) |
| locks | `#channelLock.release()` (`:809-810`) |
| browser watchers | foreground + activity unwatch (`:811-814`) |
| state subscription | `#unwatchState?.()` (`:815`) |

Disposing means "stop using this client", not "sign out": another instance may be acting on the
same slots (`:797-802`). `docs/.../v9.md:11-27` makes `dispose()` the required teardown for every
client created per page/component; skipping it leaks listeners.

Tests: `disposing releases the locks it holds rather than taking any`
(`auth-client.test.ts:1653-1668`), `installs nothing when disposed while the restore is in flight`
(`:2058-2079`), `releases the identity it replaces, so a discarded one stops minting`
(`:637-652`).

## 5. Identity consistency around the status

`getIdentity()` (`auth-client.ts:617-647`) awaits `#init()` and any in-flight `#committing`
ceremony, then:

- if the status is `signed-in` **or** `signed-in-elsewhere`, the client is not disposed, and the
  held identity is still `AnonymousIdentity` ⇒ throw `SessionNotHeldError` (`:631-647`).
  Returning an anonymous identity here is the dangerous answer: calls would go out unauthenticated
  while `isAuthenticated()` and the record both say someone is signed in. Failing by name is what
  lets a caller acquire one.
- An expired record has nothing to acquire, so the anonymous identity is returned instead
  (`:644-647`; test `auth-client.test.ts:2199-2213`).

`SessionNotHeldError` (`auth-client.ts:333-351`): `A sign-in exists for this domain, but this
origin holds no credential for it`.

## 6. Read-only clients (workers)

A worker's state store reports `isReadOnly === true` (`local-state-storage.ts:45`,
`cookie-state-storage.ts:80-83`). The client then:

- changes nothing shared: `#endSession`, `#dropSession`, `#expireSession` return early
  (`auth-client.ts:1817`, `:1832`, `:1615`; `:1804` guards the credential clear);
- `signIn` / `signOut` throw `readOnlyError()` (`auth-client.ts:924`, `:1390`);
- still reads status and restores a session once `stateStorage.ready()` resolves
  (`auth-client.ts:1683`; test `auth-client.test.ts:2372-2396`);
- reports an unusable session by leaving it for a page of the origin to end.

## Rust port checklist

- [ ] Define `SessionStatus { SignedIn { principal, expires_at_ms }, SignedInElsewhere { .. },
      Expired { .. }, SignedOut }` with a stable identity for `get_status()` (return a cached
      clone/`Arc`, not a freshly built value).
- [ ] Implement lazy expiry in `get_status()`: if a record exists and `now >= expires_at_ms`,
      return `Expired` with the same principal/expiry; rebuild only on the flip.
- [ ] Derive `is_authenticated()` and `get_principal()` from `get_status()` only; keep them
      mutually consistent.
- [ ] Implement `subscribe(listener) -> Subscription` and `dispose()`; fire status **before**
      listeners, restore **before** listeners that ask for an identity, and never fire for
      delegation rotation.
- [ ] Keep `#interactions`, `#restoring`, `#disposed` guards so a client's own ceremony/restore
      writes are not reported back as news.
- [ ] Implement `SessionNotHeldError` for `get_identity()` when a live record exists but this
      origin holds no credential; return the anonymous identity for an expired record.
- [ ] Map state-store notifications (`storage`/BroadcastChannel/cookie re-checks) into one
      "record changed" callback; dedupe by canonical string before notifying.
- [ ] Read-only mode: `is_read_only()` on the store suppresses every shared mutation and makes
      `sign_in`/`sign_out` return a `ReadOnly` error with the upstream message.
- [ ] Expose status transitions through uniffi as a flat enum + optional principal/expiry fields
      (Swift/Kotlin cannot pattern-match a Rust enum; see `gap-analysis.md`).
