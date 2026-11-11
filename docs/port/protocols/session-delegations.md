# §8 — Session acquisition, app delegations, and minting without ceremony

This is the layer v5 did not have: in v9+ the client does **not** hold a long-lived
delegation handed to it by II. It holds a short-lived **session** (key + chain restricted
to the II canister) and mints short-lived **app delegations** from that session by calling
the II canister. `docs/src/content/docs/upgrading/v9.md:92-98` and
`CHANGELOG.md` 9.0.0 (features: *mint app delegations from the Internet Identity canister*,
*an identity that replaces its own delegation as it ages*, *acquire a session without a
ceremony*).

## 8.1 Two-level delegation model

```
account key (II-side; never leaves II)
  └── session chain  ── delegated to the client's session key, restricted to II canister
        └── app delegation ── delegated to the app key, rooted at the account key
              └── what an HttpAgent signs with (DelegationIdentity)
```

| Level | Obtained from | Lifetime | Stored where | Used for |
| --- | --- | --- | --- | --- |
| session chain | signer `ii_session_delegation` (`session-delegation.ts:12`) | `maxTimeToLive`/`maxTimeToIdle`, provider default 30 d / 7 d idle (`upgrading/v9.md:63`) | `session` slot (`auth-client.ts:1773`) | signing canister calls **as the session** (mint, revoke, consent) |
| app delegation | II canister `app_prepare_delegation` + `app_get_delegation` (`session-minter.ts:33-52`) | bounded by both the mint and the remaining session (`session-identity.ts:447-453`) | `app` slot, `app-pending` during a ceremony | signing the application's canister calls |

The session chain is deliberately useless for application calls: it is restricted to II
(`session-delegation.ts:98-102`), and `assertChainReaches` refuses a chain that is
unrestricted, names nothing, or names any other canister
(`session-minter.ts:249-277`).

## 8.2 `SessionMinter` — the canister side (`session/session-minter.ts`)

### 8.2.1 Candid (`session-minter.ts:18-55`)

```candid
type SessionKey = vec nat8;
type Timestamp  = nat64;
type AppSessionError = variant {
  NoSuchSession;
  NoSuchDelegation;
  InternalCanisterError : text;
};
type CandidDelegation = record {
  pubkey      : SessionKey;
  expiration  : Timestamp;
  targets     : opt vec principal;
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

Written out inline because the package carries no II declarations (`:13-17`).

### 8.2.2 Construction (`:140-149`)

`assertChainReaches(sessionChain, canisterId)` → `HttpAgent` with `...agentOptions` and
**last** `identity: DelegationIdentity.fromDelegation(sessionKey, sessionChain)` so no
agent option can replace the session the calls rest on.

### 8.2.3 `mint(appPublicKey)` (`:161-199`)

```
mint = mintOnce; if NoSuchDelegationError -> mintOnce once more; anything else rethrows
mintOnce:
  prepared = unwrap(app_prepare_delegation({session_key: appPublicKey}))
  signed   = unwrap(app_get_delegation({session_key: appPublicKey,
                                        expiration: prepared.expiration}))   // exactly what was prepared
  return appDelegationChain(prepared.user_key, signed)
```

- The retry exists because the pair is two calls and only the first is an update: an
  expiration the canister will not sign for means the session moved on, and the answer is
  to prepare again — **not** to sign in again (`:151-160`). Attempted exactly twice
  (`:161-168`).
- `appDelegationChain` (`:205-231`) builds a **one-hop** chain rooted at `prepared.user_key`
  with the signed delegation (including `targets`/`permissions`, so read-only sessions work
  — `upgrading/v10.md:19-25`).

### 8.2.4 Error mapping (`unwrapSessionResult`, `:103-113`)

| Candid | Rust-equivalent outcome |
| --- | --- |
| `Ok` | value |
| `Err.NoSuchSession` | **`SessionGoneError`** — the one terminal outcome |
| `Err.NoSuchDelegation` | `NoSuchDelegationError` (internal; retried once) |
| `Err.InternalCanisterError(text)` | `Error('Internet Identity could not mint a delegation: <text>')` |

`SessionGoneError` is the *only* outcome that may end a session; a transport error or an
internal canister error leaves the session alone and is worth retrying
(`app-delegation-source.ts:4-11`).

### 8.2.5 `revoke()` (`:180-182`)

`app_revoke_session()`; idempotent at the canister (already gone = `Ok`); a canister
failure is raised, not swallowed (`:170-179`).

## 8.3 `SessionIdentity` — the self-rotating identity (`session/session-identity.ts`)

An `Identity` whose credential is replaced as it ages. It `extends DelegationIdentity` so
existing consumers accept it (`:241`), but signs through a mutable `#held.current`
(`:307-330`) so the object an agent holds for hours stays valid.

### 8.3.1 Constants and derived values

| Constant | Value | Why | Line |
| --- | --- | --- | --- |
| `BLOCK_MARGIN_MS` | `10_000` | a delegation must outlive a request's flight time, or the replica rejects it | `:19` |
| `PRE_MINT_THRESHOLD_MS` | `15_000` | when a replacement is minted; covers one mint only | `:21-28` |

`expiresAtMs(chain)` = **earliest** delegation expiration / 1e6 (`:33-40`);
`accountOf(chain)` = `Principal.selfAuthenticating(chain.publicKey)` (`:45-46`).

### 8.3.2 The account key problem

The session chain is rooted at the **session's own key**, and the state carries the
account's **principal** (a hash of the account key), not the key. So an account key can
only come from (a) a credential the store already holds or (b) a mint — a caller with
neither must wait for the mint before an identity exists at all (`:258-276`).

`SessionIdentity.create` (`:278-305`):

1. `if (!sessionHasLifeLeft(sessionExpiresAtMs))` → `onSessionGone()` + throw
   `SessionGoneError('The session has expired')` (`:281-284`).
2. `acquireCredential({storage, slot, source, lockName: lockNameFor(storage, slot),
   verify: candidate => isForAccount(candidate, expectedAccount),
   adopt: expectedAccount !== undefined, onGone})` (`:286-297`).
3. Construct with `accountKey = credential.chain.publicKey`, adopt the credential
   (`:299-304`).

### 8.3.3 `acquireCredential` — one writer for the app slot (`:125-178`)

```
withMintLock(lockName, async stolen => {
  stored = readSlot({storage, slot, evictSpent: true, verify})
  if (adopt && stored && msLeft(stored.chain) > PRE_MINT_THRESHOLD_MS) return stored
  identity = await storage.create()
  chain = await source.mint(identity.getPublicKey().toDer())     // on SessionGoneError: onGone(); rethrow
  credential = {identity, chain}
  if (verify && !verify(credential)) throw new AccountMismatchError()
  if (stolen.aborted) { onGone(); throw SessionGoneError('The session ended while this mint was in flight') }
  await storage.set(slot, credential).catch(() => undefined)     // a failed write is not fatal
  return credential
})
```

- The **read inside the lock** is what turns serialising into suppressing: N tabs waking
  together make one mint, not N (`:112-124`).
- `lockNameFor` returns `storage.shared ? slot : null` — no lock where no other tab can
  read the store (`:185-188`).
- `readSlot` (`:76-110`): no chain → `undefined`; `msLeft <= 0` → evict only if
  `evictSpent` (a lock-free read must not delete what a peer just minted, `:66-75,96-105`);
  `verify` rejects a credential not rooted at the expected account.

### 8.3.4 Rotation state machine

```
#usable()  (:419-431)
  current && left > 15s           -> return current
  current && left > 10s           -> start #mint() in background, return current
  otherwise                       -> await #mint()

#mint()  (:433-438)   single-flight (#inFlight)
#mintOnce()  (:440-479)
  if #unsupported                 -> throw it (latched)
  if !sessionHasLifeLeft          -> #reportGone(); throw SessionGoneError
  credential = acquireCredential(..., verify: isForThisSession, adopt: true, onGone: #reportGone)
  on SessionUnsupportedError      -> latch + dispose; rethrow
  #adopt(credential)
#adopt()  (:481-485)  set #held.current; #currentWasUsed = false; #schedule(chain)
#schedule()  (:487-502)  delay = msLeft - 15s; if <= 0 return;
                         setTimeout: if #currentWasUsed then #mint(); unref()
```

- `#currentWasUsed` is set by `transformRequest` (`:336-343`) **and** by `refresh()`
  (`:360-365`): presence counts as use, so a session bounded by how long it goes unminted
  does not end under a user who is reading (`:344-359`). An unused delegation is allowed to
  lapse — no refresh for a tab nobody is using (`:492-497`).
- `#reportGone()` fires `onSessionGone` **once**, disposes the timer, and never retries
  (`:504-509`); `SessionGoneError` is reported only for `NoSuchSession`
  (`:440-453,466`).
- `SessionUnsupportedError` is latched: retrying would return the same answer forever, and
  the record must be left alone because the sign-in is alive (`:440-445,468-475`;
  `app-delegation-source.ts:19-33`).

### 8.3.5 `refresh()` — "mint when a tab comes back" (`:360-380`)

```
refresh(): #refreshIfDue(); #currentWasUsed = true
#refreshIfDue():
  if current && msLeft > 15s            -> return
  if !current: stored = #readStored(); if stored && msLeft > 15s -> adopt; return
  await #mint().catch(() => undefined)  // silent
```

It is **never a no-op in effect**: even a healthy credential is marked used, earning the
next rotation (`:344-359`).

### 8.3.6 Client-side wiring

- `#refreshInForeground` (`auth-client.ts:1460-1468`) ignores while `#interactions > 0` or
  a refresh is in flight (one at a time; `mousemove` fires dozens of times per second,
  `:396-399`).
- `#refreshIfDue` (`:1470-1489`) waits for `#init()` first (a `pageshow`/pointer before
  restore would find anonymous and waste the moment), re-checks `#interactions`, then
  `identity.refresh().catch(() => undefined)`.
- Hooks (`foreground-refresh.ts`): `visibilitychange` when `visible`, `focus`, `pageshow`
  (`:17-47`); activity events `pointerdown, mousedown, mousemove, keydown, touchstart,
  wheel` with `{passive:true}` (`:53,72-92`). Both return `undefined` and hook nothing where
  there is no DOM (`:21-29,73-79`).
- Disabled wholesale by `disableBrowserActivity` (`auth-client.ts:460-471`).
- `dispose()`/`#installIdentity()` dispose the previous `SessionIdentity`, stopping its
  scheduled refresh (`auth-client.ts:798-804,859-863`).

Tests: mint on page-load restore before any request (`auth-client.test.ts:1755-1782`),
mint when the tab comes back (`:1783-1802`), mint when the user acts (`:1803-1827`), one
mint for a burst of activity (`:1995-2027`), no refresh for a ceremony's identity
(`:2028-2057`), a healthy tab costs nothing (`:2124-2136`), hooks nothing when disabled
(`:2137-2157`); full rotation matrix in `session-identity.test.ts:97-778`.

## 8.4 App locks (`session/app-lock.ts`) — Web Locks, optional by design

| Function | Behaviour | Line |
| --- | --- | --- |
| `withMintLock(name, mint)` | `navigator.locks.request(name, () => mint(signal))`; a stolen lock rejects this tab's request → `signal.abort()`; no lock manager or `name === null` → run immediately with a never-firing signal | `:20-39` |
| `stealMintLock(name)` | `locks.request(name, {steal:true}, () => undefined)` — granted and released at once | `:49-56` |
| `stealLock(name)` | holds the lock until `release()`, exposes `stolen: AbortSignal`; only an `AbortError` from `request` counts as a steal | `:93-120` |

Coordination may only ever **suppress** work, never be required for it (`:1-18,78-92`).
Names used by the client: `ic-auth-signer-channel` (`auth-client.ts:54`),
`${stateSlot}:sign-in` (`:57`), and the app slot name for the mint lock
(`session-identity.ts:185-188`).

## 8.5 Acquiring a session without a ceremony (sibling subdomains, `prompt:'none'`)

The mechanism is three pieces that already exist above; the *protocol* is just the
authorize URL plus a normal sign-in:

1. **A state store that reaches siblings**: `CookieStateStorage({domain})`
   (`state/cookie-state-storage.ts:59-304`), `resumable = true` (`:61-69`), so the client
   sets `resumable=true` on the authorize URL (`auth-client.ts:553-555`). A sibling reads
   the record as `signed-in-elsewhere` (`held:false`, `:152-178`) and holds no credential.
2. **A client configured for a silent re-issue**: `prompt: 'none'` + `hint: <principal the
   state names>` (`auth-client.ts:199-230,544-549`). II answers from a session it already
   holds for the app and returns without rendering, or denies with code `3002`
   (`session-delegation.ts:14-32`).
3. **`getIdentity()` refuses to pretend**: with a live record and no credential it throws
   `SessionNotHeldError` (`auth-client.ts:639-646`), which is where the silent
   `signIn()` belongs (`upgrading/v9.md:102`).

The denial is the only dependable evidence that a shared record is **stale rather than
replaced** (`session-delegation.ts:22-31`); `InteractionRequiredError.reason` is
`login_required` (no session held) or `account_selection_required` (several, none named)
(`:36-43`), and it is a plain `string` on purpose (`:38-42`).

Tests: silent acquisition without a ceremony (`auth-client.test.ts:885-909`), `prompt`/
`hint` params (`:830-843,878-883`), `resumable` (`:845-876`), denied silent request mapped
to `InteractionRequiredError` (`:534-554`), any other denial is an ordinary error
(`:555-574`), `getIdentity` refusing for a record this origin cannot act on (`:2277-2301`),
`signed-in-elsewhere` status (`:466-487`).

## 8.6 Client-side session teardown / expiry rules (ties §2 and §8 together)

| Trigger | Action | Line |
| --- | --- | --- |
| sign-out | `#endSession` (state removed) + `#clearCredentials` | `auth-client.ts:1816-1820` |
| mint refused `NoSuchSession` while the record still names this session | `#expireSession(principal)` — state kept, expiry = now, credentials cleared | `:1589-1621` |
| mint refused but the record moved on (another account/expiry) | `#dropSession()` — discard this origin's claim only | `:1589-1601,1831-1835` |
| restore finds no usable chain | `#clearCredentials`, keep state (reads as `expired`) | `:1795-1808` |
| restore finds no state record | `#endSession` | `:1713-1719` |
| restore finds an account mismatch | `#dropSession` | `:1726-1738` |
| record changed under the client | `#restoreAgain()` (coalesced) | `:481-501,1631-1657` |

`#endOrDrop` compares account **and** expiration to decide whether the record still names
the session this origin was operating under (`:1589-1601`).

## Rust port checklist

- [ ] Implement the two-level model: session credential + app credential in separate slots;
      never hand an application the session chain.
- [ ] Inline Candid for `app_prepare_delegation` / `app_get_delegation` / `app_revoke_session`;
      build the agent as a `DelegationIdentity` of session key + session chain.
- [ ] Port `mint` with the exactly-once retry on `NoSuchDelegation`; map `NoSuchSession` →
      `SessionGoneError`; keep other failures retryable.
- [ ] Port `assertChainReaches` (targets intersection, empty-target hop refused, no
      unrestricted chain).
- [ ] Implement `SessionIdentity` with: 10 s block margin, 15 s pre-mint threshold,
      single-flight mint, read-inside-lock adoption, `current_was_used` gating, latched
      unsupported error, report-gone-once, and a `refresh()` that counts as use.
- [ ] Implement `AppDelegationSource` as a trait so timing can be tested without a replica.
- [ ] Implement the lock abstraction: a `MintLock`/`HeldLock` pair backed by Web Locks where
      available and a no-op fallback; keep "coordination may only suppress" as a documented
      invariant.
- [ ] Wire `watch_foreground`/`watch_activity` (or accept a host callback) to
      `identity.refresh()` with the interaction guard.
- [ ] Implement `prompt`/`hint`/`resumable` URL params and the
      `SessionNotHeld`/`InteractionRequired` split; expose `InteractionRequiredError.reason`.
- [ ] Implement the teardown matrix in §8.6 with `expire` (state kept) vs `end` (state
      removed) vs `drop` (claim discarded) as three distinct operations.
