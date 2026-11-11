# Upstream v11.2.0 — Session Layer Specification (for the Rust port)

Upstream: `/tmp/icp-js-auth` at `@icp-sdk/auth` **11.2.0**.
Sources: `src/client/session/*.ts`, `src/client/auth-client.ts`, `src/client/slots.ts`,
`tests/client/session/*`, `docs/src/content/docs/upgrading/v9.md`, `v10.md`.

The session layer has **two delegations**, and they must not be confused:

| | Session delegation | App delegation |
|---|---|---|
| Issued by | the identity provider (Internet Identity) over the signer transport | the Internet Identity **canister** |
| Issued to | the session key (kept in the `session` slot) | the app key (kept in the `app` slot) |
| Restricted to | the II canister only (`targets`) | unrestricted (targets absent) |
| Lifetime | what the user consented to (`maxTimeToLive`, `maxTimeToIdle`) | short; replaced as it ages |
| Used for | signing the mint/revoke calls | signing the application's canister calls |
| Kept as | `Credential { identity, chain }` in `session` | `Credential { identity, chain }` in `app` |

The **account principal** is `Principal.selfAuthenticating(accountKey)`, where `accountKey` is the
root public key of the app delegation (`session-identity.ts:44-46`, `auth-client.ts:1778-1783`).
The session chain is rooted at the session's own key, not the account's
(`session-identity.ts:258-266`).

---

## 1. Requesting a session delegation

`src/client/session/session-delegation.ts:96-148`.

### Constants

| Constant | Value | Where |
|---|---|---|
| JSON-RPC method | `ii_session_delegation` | `:12` |
| ICRC-25 user-action code meaning "a ceremony is needed" | `3002` | `:20` |

### Request (`:71-94`)

```jsonc
{
  "jsonrpc": "2.0",
  "id": "<crypto.randomUUID()>",
  "method": "ii_session_delegation",
  "params": {
    "sessionPublicKey": "<base64 DER>",
    // optional, only when the caller set them; bigint nanoseconds as decimal strings
    "maxTimeToLive": "<ns decimal string>",
    "maxTimeToIdle": "<ns decimal string>",
    // optional
    "icrc95DerivationOrigin": "<derivation origin>"
  }
}
```

The request is handed to `signer.sendRequest` **on the call, before any await**, as a promise of
the request, so it keeps call order with the signer even while params resolve
(`:107-113`).

### Response (`:52-58`, `:130-147`)

```jsonc
{
  "publicKey": "<base64 DER root>",
  "signerDelegation": [
    {
      "delegation": { "pubkey": "<base64>", "expiration": "<ns decimal string>", "targets": ["<principal>"] },
      "signature": "<base64>"
    }
  ]
}
```

- `signerDelegation` must be non-empty; an empty list would build a chain whose earliest expiry
  is 0 and read as "expired at the epoch" (`:60-69`).
- Chain is built with `DelegationChain.fromDelegations(...)`, root = `fromBase64(result.publicKey)`
  (`:137-147`).
- The returned chain is **restricted to the II canister**, so it is not something the app can call
  its own canisters with (`:96-102`).

### Errors

| Condition | Thrown |
|---|---|
| `error.code === 3002` | `InteractionRequiredError(message, reason?)` where `reason` is `String(error.data.reason)` when present (`:119-126`) |
| any other JSON-RPC error | plain `Error(response.error.message)` (`:127`) |
| missing `publicKey`, or missing/empty `signerDelegation` | `Error('Invalid session response: missing publicKey, or missing or empty signerDelegation')` (`:130-135`) |

`InteractionRequiredError` (`:22-50`) is *not a failure*: it says a ceremony is needed. `reason`
is a plain string (`login_required`, `account_selection_required`, …) deliberately not a union, so
an unknown value does not fail (`:36-43`). It is the only dependable evidence that a shared
record is stale rather than replaced (`:22-31`).

## 2. `SessionMinter` — minting app delegations from the II canister

`src/client/session/session-minter.ts`.

### Candid interface (verbatim from `:18-55`)

```candid
type SessionKey = vec nat8;
type Timestamp = nat64;
type AppSessionError = variant {
  NoSuchSession;
  NoSuchDelegation;
  InternalCanisterError : text;
};
type CandidDelegation = record {
  pubkey : SessionKey;
  expiration : Timestamp;
  targets : opt vec principal;
  permissions : opt text;
};
service : {
  app_prepare_delegation : (record { session_key : SessionKey }) ->
    (variant { Ok : record { user_key : SessionKey; expiration : Timestamp }; Err : AppSessionError });
  app_get_delegation : (record { session_key : SessionKey; expiration : Timestamp }) ->
    (variant { Ok : record { delegation : CandidDelegation; signature : SessionKey }; Err : AppSessionError }) query;
  app_revoke_session : () -> (variant { Ok : null; Err : AppSessionError });
}
```

### Construction (`:115-149`)

`SessionMinterOptions { sessionKey: SignIdentity, sessionChain: DelegationChain,
canisterId: Principal, agentOptions?: Omit<HttpAgentOptions,'identity'> }`.

- `assertChainReaches(sessionChain, canisterId)` runs first (`:142`).
- The agent is built with `identity: DelegationIdentity.fromDelegation(sessionKey, sessionChain)`
  placed **last**, so no agent option can replace the session (`:143-147`).
- Calls go to `canisterId` (`:148`).

### `mint(appPublicKey)` — two calls, one retry (`:151-198`)

1. `app_prepare_delegation({ session_key: appPublicKey })` → `{ user_key, expiration }`.
2. `app_get_delegation({ session_key: appPublicKey, expiration: <exactly what prepare returned> })`
   → `{ delegation, signature }`. A different expiration is a different signature (`:189-195`).
3. Build the one-hop chain with `appDelegationChain(user_key, signed)` (`:205-231`):
   `DelegationChain.fromDelegations([{ delegation: Delegation(pubkey, expiration, targets[0],
   permissions[0]), signature }], userKey)`.

Retry policy (`:161-168`): if and only if the failure is `NoSuchDelegationError`, run the **whole
pair again** (prepare + get) exactly once. A third attempt is not made.

### `revoke()` (`:180-182`)

`app_revoke_session()`; unwrap. Idempotent at the canister: an already-gone session is `Ok`.
A failed write is raised, not dropped — an app that told a user it signed them out of their apps
should be able to find out that it did not (`:170-179`).

### Result unwrapping (`:98-113`)

| Canister result | Thrown |
|---|---|
| `Ok(v)` | `v` |
| `Err(NoSuchSession)` | `SessionGoneError` |
| `Err(NoSuchDelegation)` | `NoSuchDelegationError` (not exported; message `Internet Identity signed no delegation for this key and expiration`) |
| `Err(InternalCanisterError(text))` | `Error('Internet Identity could not mint a delegation: <text>')` — keeps the canister's explanation, never `[object Object]` |
| anything else | retryable failure |

### `assertChainReaches(chain, canisterId)` (`:233-277`)

Refuses a chain that is not a session for `canisterId`. Effective restriction is the
**intersection** of hops that name targets (`:233-248`):

1. no hop names any canister → error `... but no hop of this one names any canister`;
2. any restricting hop names nothing (`targets: []`) → error `... but a hop of this one names nothing`;
3. any target differs from `canisterId` → error `... but this one also names <others>`.

It accepts the shape II issues: an unrestricted hop to the provider's key plus a hop naming the
canister (`session-minter.test.ts:136-141`).

## 3. `AppDelegationSource` and the error taxonomy

`src/client/session/app-delegation-source.ts`.

```ts
interface AppDelegationSource { mint(appPublicKey: DerEncodedPublicKey): Promise<DelegationChain>; }
```

The identity decides **when** to mint; the source decides **how** (`:49-66`).

| Error | Class meaning | Who reacts |
|---|---|---|
| `SessionGoneError` | canister has no session behind the caller: revoked, expired, pruned, never one | the only **terminal** outcome; ends the session (`:4-17`) |
| `SessionUnsupportedError` | session exists but this library cannot act for it (e.g. read-only permissions) | latch and stop; do **not** retract the record (`:19-33`) |
| `AccountMismatchError` | mint answered for an unexpected account; session healthy, pairing wrong | drop this origin's claim, do not retry (`:35-47`) |
| `NoSuchDelegationError` | canister signed nothing for the prepared expiration | retry prepare+get once (`session-minter.ts:83-96`) |
| anything else | transport/canister failure | retryable; leaves the session alone |

Helpers (`:68-86`): `sameKey(a,b)`, `delegatesTo(chain)` (leaf pubkey), `chainAuthorisesKey(chain,
keyDer)` (leaf bytes equal key bytes).

## 4. `SessionIdentity` — the self-rotating identity

`src/client/session/session-identity.ts:227-510`. It extends `DelegationIdentity` so existing
consumers accept it (`:227-241`).

### 4.1 Constants

| Constant | Value | Meaning | Where |
|---|---|---|---|
| `BLOCK_MARGIN_MS` | `10_000` | minimum life needed to hand a delegation to a caller (covers request flight time) | `:14-19` |
| `PRE_MINT_THRESHOLD_MS` | `15_000` | when a replacement is minted; covers one mint only | `:21-28` |
| session bound | `sessionExpiresAtMs` | `earliestExpiryMs(sessionChain)`; nothing is minted past it | `:194-195`, `:180-182` |

The threshold ratio matters: minting early discards the rest of a delegation's life, so an active
session consumes lifetime at `ttl / (ttl - threshold)` and every second of threshold costs update
calls on every active session. A refresh is **scheduled** for that moment rather than waiting for
a request inside the window (`:21-28`).

### 4.2 State held

| Field | Type | Purpose |
|---|---|---|
| `#held.current` | `{ identity, chain }?` | current credential; replaced under the object so `sign` sees it (`:249-250`, `:307-330`) |
| `#inFlight` | `Promise<Held>?` | one mint at a time; concurrent requests share it (`:252`, `:433-438`) |
| `#currentWasUsed` | `boolean` | whether the credential earned the next rotation (`:253`, `:481-485`) |
| `#scheduled` | `setTimeout` handle | scheduled rotation (`:254`, `:487-502`) |
| `#reportedGone` | `boolean` | `onSessionGone` fires at most once (`:255`, `:504-509`) |
| `#unsupported` | `SessionUnsupportedError?` | latched: asking again returns the same answer (`:256`, `:440-479`) |
| `#account` | `Principal` | account every credential must be rooted at (`:247-248`, `:329`) |
| `#sessionExpiresAtMs` | `number` | upper bound on minting (`:246`) |

### 4.3 Lifecycle / state machine

```
                 create()                         first transformRequest / refresh()
  no credential ────────► credential (locked read-or-mint) ────────────► serving
       │                        │                                          │
       │                        │ mint fails SessionGone                  │ msLeft <= threshold
       │                        ▼                                          ▼
       │                  onSessionGone()                          mint behind current (if
       │                  throw SessionGoneError                   > BLOCK_MARGIN), else await mint
       │                        │                                          │
       │                        │ SessionUnsupported                       │ rotation scheduled at
       │                        ▼                                          │ msLeft - threshold
       │                  latch + dispose()                                 ▼
       │                  throw same error                          adopt → schedule again
       │
       └─ session already past BLOCK_MARGIN → onSessionGone() + throw
```

`SessionIdentity.create(options)` (`:278-305`):

1. `if (!sessionHasLifeLeft(sessionExpiresAtMs)) { onSessionGone(); throw new SessionGoneError('The session has expired'); }`
2. `acquireCredential({ storage, slot, source, lockName, verify: isForAccount(candidate,
   expectedAccount), adopt: expectedAccount !== undefined, onGone: onSessionGone })`
3. account key = `credential.chain.publicKey`; construct identity; `#adopt(credential)`.

`expectedAccount` absent ⇒ `adopt: false` ⇒ it **mints** rather than trusting the slot, because a
caller that cannot name the account has nothing to check against, and a mint is the only thing
that establishes one (`:290-297`).

`refresh()` (`:345-365`): calls `#refreshIfDue()` then sets `#currentWasUsed = true` — being here
counts as use exactly as signing does, so a session does not end under a user who is reading
rather than clicking (`:345-359`).

`dispose()` (`:382-386`): clears the scheduled refresh. It does not clear storage or report gone.

`#refreshIfDue` (`:367-380`): return if current has `> PRE_MINT_THRESHOLD`; if no current, read
the stored credential (without evicting) and adopt it when it has `> threshold`; otherwise
`#mint().catch(() => undefined)`.

`transformRequest` (`:336-343`): `await #usable()`, mark used, then delegate to
`DelegationIdentity.fromDelegation(identity, chain).transformRequest(request)` — sign and attach
happen in one act, so an in-flight request carries a matching pair (`:236-239`).

`#usable` (`:419-431`):

| Current credential life left | Action |
|---|---|
| `> PRE_MINT_THRESHOLD_MS` | use it |
| `(BLOCK_MARGIN, PRE_MINT_THRESHOLD]` | use it **and** start a background mint |
| `<= BLOCK_MARGIN_MS` | await a mint (replacing) |

`#mint` / `#mintOnce` (`:433-479`):

- single-flight via `#inFlight` (concurrent requests = one mint; test `:117-121`);
- latched `#unsupported` re-thrown immediately, rotation dropped;
- `!sessionHasLifeLeft` ⇒ `#reportGone()` + `SessionGoneError('The session has expired')` — a
  delegation lasts `min(ttl, what remains of session)`, so refreshing on delegation alone would
  mint forever against an almost-finished session (`:447-453`);
- `acquireCredential` with `verify = isForThisSession`, `adopt: true`;
- on `SessionUnsupportedError` latch + `dispose()` (`:468-476`);
- on success `#adopt`.

`#adopt` (`:481-485`): set current, reset `#currentWasUsed = false`, `#schedule(chain)`.

`#schedule` (`:487-502`): `delay = msLeft - PRE_MINT_THRESHOLD`; if `<= 0` no timer; timer fires
`if (#currentWasUsed) void #mint()`. So **an unused delegation lapses instead of refreshing**
(test `:161-171`). `unref()` where available so Node is not held open (`:500-502`).

`#reportGone` (`:504-509`): once only; `dispose()`; `onSessionGone()`.

### 4.4 Locked read-or-mint: `acquireCredential`

`session-identity.ts:112-178` — the one place an app credential is minted and written.

```
withMintLock(lockName, async (stolen) => {
  stored = readSlot({ evictSpent: true, verify })        // read *inside* the lock
  if (adopt && stored && msLeft(stored.chain) > PRE_MINT_THRESHOLD) return stored
  identity = await storage.create()
  chain = await source.mint(identity.getPublicKey().toDer())   // SessionGone → onGone + rethrow
  credential = { identity, chain }
  if (verify && !verify(credential)) throw AccountMismatchError
  if (stolen.aborted) { onGone(); throw SessionGoneError('The session ended while this mint was in flight') }
  await storage.set(slot, credential).catch(() => undefined)   // best-effort
  return credential
})
```

The lock alone would only serialise; the read inside it is what **suppresses** duplicate mints, so
the floor is one mint per origin rather than one per tab (`:112-124`). The steal check happens
after calls return and before anything is written, because a sign-out elsewhere may have cleared
the slot while the mint was in flight (`:162-169`).

`lockNameFor(storage, slot)` (`:184-188`): `storage.shared ? slot : null` — a store no other tab
reads has nothing to coordinate.

`readSlot` (`:76-110`): `storage.get(slot).catch(() => null)`; no chain ⇒ undefined; `msLeft <= 0`
⇒ spent, remove **only if** `evictSpent` (only the lock holder may); then `verify` if given.
A lock-free read declines a spent record rather than evicting it, so it cannot delete a credential
another tab minted between read and removal (`:65-75`, `:100-104`).

### 4.5 Account verification

`isForAccount(held, expected)` (`:48-63`): both ends of the chain —

1. `chainAuthorisesKey(chain, identity.getPublicKey().toDer())` — leaf must be the stored key;
2. `accountOf(chain) === expected` — `Principal.selfAuthenticating(new Uint8Array(chain.publicKey))`.

`expected` absent only where the caller has no account to name; a read that cannot check it does
not adopt (`:55-63`).

## 5. Web Locks coordination (`app-lock.ts`)

`src/client/session/app-lock.ts`. Coordination may only ever **suppress** work, never be required
for it (`:4-11`).

| Function | Behaviour |
|---|---|
| `withMintLock(name, mint)` (`:20-39`) | `name === null` or no `navigator.locks` ⇒ run immediately with a never-aborting signal. Otherwise `locks.request(name, () => mint(stolen.signal))`; a steal rejects this promise and is converted into `stolen.abort()` rather than surfaced |
| `stealMintLock(name)` (`:49-56`) | `locks.request(name, { steal: true }, () => undefined)`, granted and released at once. What sign-out does: the user's sign-out must not queue behind a canister call in another tab |
| `HeldLock` (`:65-76`) | `{ stolen: AbortSignal, release(): void }` — held across a span (a ceremony), not one call |
| `stealLock(name)` (`:93-120`) | Takes the lock away and holds it until `release()`. A steal arrives as `AbortError`; only that is reported as a steal (a frame going away is not a steal) |

Lock names used by the client (`auth-client.ts:46-57`):

| Name | Value | Scope |
|---|---|---|
| signer channel | `ic-auth-signer-channel` | per **origin**, not namespaced: an origin has one signer window |
| sign-in | `${stateSlot}:sign-in` — e.g. `ic-session-state:sign-in`, `one:ic-session-state:sign-in` | per namespace |
| mint | the app slot (`app` / `<ns>:app`) when `credentialStorage.shared`, else none | per namespace |

## 6. `AuthClient` session orchestration

### 6.1 `signIn` — exact order (`auth-client.ts:923-1101`)

1. Refuse in a read-only store (`readOnlyError()`, `:924`).
2. `#beginInteraction()` — count up **before any await**; it stands the foreground refresh down
   (`:937-942`, `:926-936`).
3. `#runSignIn`:
   1. `returnTo` journaled (validated same-origin href only) (`:944-956`).
   2. session key acquisition starts on the call:
      window flow = `credentialStorage.create()` (`:1103-1105`);
      redirect flow = `#ensureSessionKeyForRedirectFlow` (`:1112-1261`).
   3. `requestSessionDelegation(signer, promise-of-params)` — window opens within the call
      (`:978-991`).
   4. `#takeChannelLock()` (`:993`), then `stealLock(signInLockFor(stateSlot))` (`:1003`).
   5. `await #init()` — never interleave with the constructor's restore (`:1019`).
   6. await key, require `'sign' in key` (`:1022-1030`), await session chain, and verify
      `chainAuthorisesKey(sessionChain, key.getPublicKey().toDer())` (`:1032-1040`).
   7. Build minter; `credentialStorage.create()` for the app key; `minter.mint(appKey DER)`
      **inside the ceremony** so the returned identity already holds a delegation
      (`:1050-1053`).
   8. Write app credential to `appPending` (guarded) (`:1057-1059`).
   9. Commit, in order: `#persistSession` (session slot + state record), `#promoteAppCredential`
      (app slot, remove appPending), `#openSession(...)` + `#installIdentity` (`:1064-1070`).
   10. Best-effort remove `session-pending` if the redirect flow used it (`:1080-1086`).
   11. `location.replace(returnTo)` last, after the sign-in is stored (`:1091-1094`).
   12. `signInLock.release()` in `finally` (`:1097-1099`).

Every shared write goes through `guarded()` which calls `#assertCurrent(signInLock)` before the
write: one check before the first write is not enough, because a sign-out can land between any two
writes and this flow would put them all back (`:1006-1013`, `:904-921`).

`#assertCurrent` (`:904-921`): disposed ⇒ `SupersededError('This client was disposed while
signing in')`; channel lock stolen ⇒ `SupersededError('Another signer interaction took the
channel')`; sign-in lock stolen ⇒ `SupersededError()`.

### 6.2 `signOut` (`auth-client.ts:1389-1454`)

1. Refuse in a read-only store (`:1390`).
2. `await #init()` (`:1393`).
3. `stealLock(signInLockFor(stateSlot))` (`:1399`).
4. Read the session credential **before** clearing (the revoke call is made as the session)
   (`:1403`).
5. `stealMintLock(credentialStorage.shared ? appSlot : null)` (`:1409`).
6. Run **in parallel**: revoke at the canister (failures carried, not thrown) and `#endSession()`
   (`:1415-1430`).
7. Install `AnonymousIdentity` (`:1428`).
8. Release the lock; re-raise a carried revoke failure **after** the wipe and before navigation
   (`:1432-1439`).
9. `returnTo` validated same-origin then `location.assign` (`:1441-1453`).

`#endSession` (`:1816-1821`): `stateStorage.remove(stateSlot)` then `#clearCredentials()`.
`#clearCredentials` (`:1856-1863`): remove **both** `session` and `app` slots via
`Promise.allSettled`, rethrow the first failure. It deliberately does not touch the ceremony's
pending slots: a sign-out cannot tell an abandoned key from a live one (`:1845-1855`).

### 6.3 Restore (`auth-client.ts:1665-1761`)

`#init()` memoizes one restore promise; a rejection clears it so a later call retries
(`:1653-1676`). `#restore` marks `#restoring = true`, awaits `stateStorage.ready?.()`, then
`#hydrate` (`:1680-1689`).

`#hydrate` (`:1693-1761`), in order:

1. `#restoreSession()` (`:1795-1812`): `credentialStorage.get(sessionSlot)`; `null` ⇒ `null`;
   missing chain or `!isDelegationValid(chain)` ⇒ if not read-only `#clearCredentials()` (the state
   record stays, so it reads as `expired`), return `null`.
2. No key/chain: if status is `signed-in` ⇒ `#dropSession()` (record that reaches past this origin
   belongs to whoever published it); install `AnonymousIdentity` (`:1697-1710`).
3. `stateStorage.get(stateSlot) === null` ⇒ `#endSession()` (chain without a state record is a
   sign-in that has ended) + anonymous (`:1711-1721`).
4. Key cannot sign ⇒ anonymous (`:1723-1726`).
5. `#openSession(key, chain)` (which may mint; expected account = state principal):
   `AccountMismatchError` ⇒ `#dropSession()` + anonymous; any other error propagates
   (`:1727-1741`).
6. Disposed while in flight ⇒ `identity.dispose()`, install nothing (`:1742-1746`).
7. State re-read: `state === null || state.principal !== identity.getPrincipal()` ⇒ dispose,
   anonymous, `#dropSession()` (`:1750-1760`).
8. Otherwise install the identity (`:1761`).

`#restoreAgain` (`:1631-1648`) is invoked by the state subscription: coalesced (`#restoreQueued`),
queued behind the current `#initPromise`, one further pass for a burst.

### 6.4 Session-gone / session-ended handling

`#openSession` (`:1541-1578`) passes `onSessionGone: () => { void #endOrDrop(held, !opening); ...
install AnonymousIdentity }` where `held` is the state record captured when the session was opened
and `opening` is true only for the mint a ceremony's own session is opened with (`:1560-1570`).

`#endOrDrop(held, ended)` (`:1589-1602`): if the current record is unchanged (same principal **and**
same expiration) then `ended ? #expireSession(principal) : #endSession()`; otherwise
`#dropSession()` — someone else owns the sign-in now and this origin converges to them instead of
retracting what they published.

`#expireSession(principal)` (`:1614-1621`): not in a read-only store; writes the state record with
`expiration = BigInt(Date.now()) * 1_000_000n` (so it reads `expired` and still names the account)
and clears credentials. Signing out removes the record instead — that is the user asking to leave,
not a session running its course (`:1604-1613`).

`#dropSession` (`:1831-1835`): `stateStorage.discard(stateSlot)` + clear credentials.

### 6.5 `#persistSession` — what exactly is recorded (`:1768-1785`)

1. `credentialStorage.set(sessionSlot, { identity, chain })`.
2. Compute `earliest` = min delegation expiration over the **session chain**.
3. `stateStorage.set(stateSlot, { principal: Principal.selfAuthenticating(accountKey),
   expiration: earliest })` where `accountKey = appChain.publicKey` (the mint's reported account
   key, not the session chain root) (`:1064`, `:1778-1783`).

### 6.6 Read-only sessions (v10)

- `docs/.../v10.md:11-25`: core v6 supports read-only delegations, so a read-only session signs in
  instead of throwing.
- The read-only **permission** travels in the Candid `permissions: opt text` of the app delegation
  (`session-minter.ts:26-31`, `:220-227`; test `session-minter.test.ts:108-114`: a session with
  `permissions: ['queries']` produces a chain with `permissions === 'queries'`).
- If a session cannot be acted for, the minter raises `SessionUnsupportedError`, which
  `SessionIdentity` latches: rotation stops, the error reaches the caller, and the record is left
  alone because the sign-in is alive (`session-identity.ts:440-446`, `:468-476`;
  `app-delegation-source.ts:19-33`).
- In a **worker**, the state store is read-only and the client changes nothing shared: a session it
  finds unusable is left for a page of the origin to end (`auth-client.ts:1842-1844`, `:1615`,
  `:1817`, `:1832`; tests `auth-client.test.ts:2424-2471`).

## 7. Concurrency summary

| Race | Mechanism | Where |
|---|---|---|
| Two tabs mint simultaneously | mint lock + read inside lock | `session-identity.ts:112-178`, `app-lock.ts:20-39` |
| Two `signIn` calls on one client | channel lock stolen; earlier gets `SupersededError` | `auth-client.ts:904-921`, `:993-1004` |
| Sign-out during a mint | `stealMintLock` + `stolen.aborted` check before write | `auth-client.ts:1409`, `session-identity.ts:162-169` |
| Sign-out during a ceremony | `stealLock(sign-in)` + `guarded()` before every write | `auth-client.ts:1003-1013` |
| Burst of state changes | `#restoreAgain` coalescing | `auth-client.ts:1631-1648` |
| Concurrent requests during rotation | `#inFlight` single-flight | `session-identity.ts:433-438` |
| Foreground refresh during a ceremony | `#interactions > 0` stands it down | `auth-client.ts:1460-1468` |

## Rust port checklist

- [ ] Split `DelegationSource` (trait `mint(app_pubkey_der) -> Result<DelegationChain>`) from the
      rotating identity, and model the four error kinds as a `SessionError` enum
      (`Gone`, `Unsupported`, `AccountMismatch`, `Retryable`/`NoSuchDelegation`).
- [ ] Implement `SessionMinter` with the Candid interface above (ic-agent `call` with
      `Principal` argument record + variant return; `app_get_delegation` as a query).
      `assert_chain_reaches` before creating the actor.
- [ ] Implement `SessionIdentity` as a `DelegationIdentity`-like wrapper with:
      `BLOCK_MARGIN = 10s`, `PRE_MINT_THRESHOLD = 15s`, single-flight mint, scheduled rotation,
      `used` flag so an unused delegation lapses, latched `Unsupported`, once-only `on_session_gone`.
- [ ] Port `read_slot` / `acquire_credential` exactly: read inside the lock, evict only under the
      lock, best-effort write, post-call steal check.
- [ ] Port the account check: leaf key equals stored key AND
      `Principal::self_authenticating(chain.public_key) == expected`.
- [ ] Implement the `sign_in` sequence (session key → session chain → mint → persist session →
      promote app → open identity) with a "current" check before every shared write.
- [ ] Implement `sign_out`: read session → revoke (parallel with wipe, failure carried) → remove
      state + both credentials → release locks → raise revoke failure.
- [ ] Implement restore: `ready()` → session slot → validate chain → state record must exist and
      name the same principal → open session (adopt/mint) → drop/expire/end as above.
- [ ] Implement `expired` as a *write* of `{principal, expiration = now}` (not a removal) and
      `discard` as a per-origin-only removal; never `remove` on a shared store when the session
      was merely found dead.
- [ ] Web Locks: `wasm-js` uses `navigator.locks` (`with_mint_lock`, `steal_mint_lock`,
      `steal_lock`); native proposal: an in-process `Mutex` keyed by slot (single process) and
      document that cross-process coordination is out of scope.
- [ ] Read-only session support: carry `permissions` through the app chain; map "cannot act" to
      `Unsupported` and latch it.
- [ ] Gate the whole layer on `wasm-js` for the transport/signer parts; native needs a
      `NativeLogin`/deep-link equivalent for `requestSessionDelegation` (the current native client
      already has `build_login_url` / `finish_login_from_payload`, see `gap-analysis.md`).
