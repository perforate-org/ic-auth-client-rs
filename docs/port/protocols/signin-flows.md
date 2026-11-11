# §3 — Sign-in flow (window + redirect), and §4 — Sign-out

The sign-in is a **signer interaction** over a transport (ICRC-29 `postMessage` or
ICRC-167 URL navigation) plus **canister calls** that mint and later revoke app
delegations. The transport layer is `@icp-sdk/signer@6.1.0`; its wire formats are in
[`signer-protocol.md`](signer-protocol.md). This section is the `AuthClient` choreography
on top of it.

## 3.1 `signIn()` — entry, interaction counting, and the two locks

```ts
async signIn(options?: AuthClientSignInOptions): Promise<Identity>   // auth-client.ts:923
```

1. `if (#isReadOnly) throw readOnlyError()` (`:924`).
2. `#beginInteraction()` — increments `#interactions` **before the first await** (`:936`);
   `finally { #endInteraction() }` (`:939-941`).
   - This count is also what stands the foreground refresh down, so the ceremony's own
     background/foreground round trip cannot spend a mint on the identity it is replacing
     (`:925-935,1461,1486`).
3. `#runSignIn(options)`.

Locks:

| Lock | Name | Taken | Purpose | Source |
| --- | --- | --- | --- | --- |
| Channel lock | `ic-auth-signer-channel` | `#takeChannelLock()` **after** the request is handed to the signer (`:993`) | one signer interaction per origin; a steal closes the channel so waiters fail instead of hanging | `:54,877-893` |
| Sign-in lock | `${stateSlot}:sign-in` | `stealLock(...)` after the window is open (`:1003`) | one sign-in per namespace; `signOut` steals it too | `:57,1003,1398` |

Both are **stolen, not queued** (`app-lock.ts:78-120`): the newer intent wins and the
loser throws `SupersededError` before writing (`:903-921`). Neither may be requested
before the popup exists, because a lock request ahead of `window.open` was enough for
Chromium to refuse the popup (`:869-876,925-935`).

## 3.2 `#runSignIn` — exact order (`auth-client.ts:944-1099`)

| # | Action | Line |
| --- | --- | --- |
| 1 | `returnTo = memoize(() => sameOriginTarget(raw)?.href ?? null)` — only when the caller gave one; the **validated href or null** is journaled, never the raw value | `:953-955` |
| 2 | Start session-key acquisition **eagerly** (see 3.2.1) and attach a no-op rejection handler | `:962-973` |
| 3 | Hand the delegation request to the signer **on the call**: `requestSessionDelegation(signer, sessionKeyPromise.then(…))`; params = `{sessionPublicKey, maxTimeToLive?, maxTimeToIdle?, derivationOrigin?}` | `:978-991` |
| 4 | `#takeChannelLock()` | `:993` |
| 5 | `signInLock = stealLock(signInLockFor(stateSlot))` | `:1003` |
| 6 | Build `guarded(write)` = `#assertCurrent(signInLock)` then `write()` | `:1009-1012` |
| 7 | `await #init()` — constructor restore finishes before this flow writes | `:1019` |
| 8 | `{key, pending} = await sessionKeyPromise`; require `'sign' in key` else `Error('A session needs a key that can sign')` | `:1021-1029` |
| 9 | `sessionChain = await sessionChainPromise`; **verify** `chainAuthorisesKey(sessionChain, key.getPublicKey().toDer())` else `Error('The session chain does not delegate to the key it was requested for')` | `:1031-1039` |
| 10 | `minter = await #minterFor(key, sessionChain)` (canister call setup) | `:1050,1520-1527` |
| 11 | `appKey = await credentialStorage.create()`; `appChain = await minter.mint(appKey.getPublicKey().toDer())` — **mint inside the ceremony** so the first request does not wait | `:1051-1052` |
| 12 | `guarded(write app-pending)` | `:1056-1058` |
| 13 | commit, guarded at each step: (a) `#persistSession(key, chain, appChain.publicKey)`; (b) `#promoteAppCredential(appKey, appChain)`; (c) `#installIdentity(await #openSession(key, chain, minter))` | `:1063-1076` |
| 14 | `if (pending) credentialStorage.remove(sessionPending)` — best effort, failure ignored | `:1080-1086` |
| 15 | `target = await returnTo`; `if (typeof target === 'string') location.replace(target)` — **after** the sign-in is stored | `:1092-1093` |
| 16 | `finally signInLock.release()` | `:1096-1098` |

`#persistSession` (`:1768-1789`) writes the `session` slot and then the state record:
`expiration` = **earliest delegation expiration in the chain** (ns), `principal` =
`Principal.selfAuthenticating(appChain.publicKey)` — the account the **mint** reported, not
the session chain's root (`:1781-1788`).

`#promoteAppCredential` (`:1509-1518`) **overwrites** `app` (never clear-then-write, so
the origin is never credential-less) and then removes `app-pending` best-effort.

### 3.2.1 Session-key acquisition

Window transport (`#ensureSessionKeyForWindowFlow`, `:1103-1105`): a fresh
`credentialStorage.create()` per sign-in; nothing persisted.

Redirect transport (`#ensureSessionKeyForRedirectFlow`, `:1112-1161`):

1. **Refuse before navigating** if `!credentialStorage.durable`:
   `Error('A redirect sign-in needs a credential store that survives the navigation, and this one does not. Use a durable store or the window transport.')` (`:1125-1129`).
   `shared` is not enough — a peer answering only works while a peer is open
   (`:1118-1124`; tests `auth-client-redirect.test.ts:165-198`).
2. Inside `transport.memoize(...)`: read `session-pending`; if present use it, else
   `create()` and write it; journal **the key's public half as base64**
   (`:1139-1149,1878-1880`).
3. On the return load, `memoize` replays that string instead of running the producer;
   read the pending slot and require `publicKeyOf(key) === startedWith`, else
   `Error('This sign-in was superseded by another one in this browser')`
   (`:1151-1159`).
4. Return `{ key, pending: true }` so the caller cleans the pending slot on success.

## 3.3 Redirect (ICRC-167) vs window (ICRC-29) selection

`options.transport` (`auth-client.ts:160-182`):

| | `'window'` (default) | `'redirect'` |
| --- | --- | --- |
| Transport class | `PostMessageTransport({url, windowOpenerFeatures})` | `UrlTransport({url, callbackUrl})` |
| Where | `auth-client.ts:566-569` | `:559-565` |
| Requires user gesture | yes (popup) | no |
| Page unloads per step | no | **yes** |
| Key persistence | none | `session-pending` slot, `durable` store required |
| Flow re-runs on return | no | yes — call `signIn`/`requestAttributes` **on page load** (`:174-178`) |
| Journal | none (`memoize` is passthrough) | `UrlTransport` call-order journal (`signer-protocol.md` §9.5) |
| Callback | signer window origin | `location.origin + location.pathname`; must be in the origin's `/.well-known/ii-auth-callbacks` allow-list (`:167-171`) |
| Timeouts | ICRC-29 heartbeat: establish 120 s, pending 300 s, disconnect 2 s, poll 300 ms | `flowTimeout` 600 s (`urlTransport.js:72`) |

Both transports enforce **secure context** (`https`, or `http` on loopback) at
construction; details in `signer-protocol.md` §9.4/§9.5.

`#urlTransport` is set only in redirect mode (`:570`), and is the switch for every
redirect-only path: `#ensureSessionKeyForRedirectFlow`, nonce journaling, `memoize`
(`:1376-1381`).

## 3.4 The JSON-RPC requests a sign-in sends

The session request (built in `session/session-delegation.ts:78-94`):

```json
{
  "jsonrpc": "2.0",
  "id": "<crypto.randomUUID()>",
  "method": "ii_session_delegation",
  "params": {
    "sessionPublicKey": "<base64 DER>",
    "maxTimeToLive": "3600000000000",      // string, ns, only when caller set it
    "maxTimeToIdle": "600000000000",       // string, ns, only when caller set it
    "icrc95DerivationOrigin": "https://…"  // only when derivationOrigin set
  }
}
```

- Method name constant `SESSION_DELEGATION_METHOD = 'ii_session_delegation'`
  (`session-delegation.ts:12`) — "named for its provider because a JSON-RPC method travels
  over a transport shared with other signers" (`:8-11`).
- `targets` is **never** sent by the auth client: the session chain is restricted to II
  and what the app may call is decided by app delegations (`:98-102`;
  test `auth-client.test.ts:1012-1031`).
- `maxTimeToLive`/`maxTimeToIdle` are **omitted, not defaulted**, when unset, so the
  provider's policy applies (`:983-987`; tests `:1033-1055`).
- `icrc95DerivationOrigin` here comes from `this.#options.derivationOrigin` **directly**
  (`:988`), which is `undefined` on the redirect return load. The value still reaches the
  request because the `Signer`'s memoized ICRC-95 transform adds it to **every** request
  (`:581`, `signer.js:131-139`). A Rust port must therefore keep both paths: the explicit
  param for the window flow, and the journaled transform for the return leg.

Success result (`session-delegation.ts:52-58,130-147`):

```json
{ "publicKey": "<base64 DER of the chain root>",
  "signerDelegation": [
    { "delegation": { "pubkey": "<b64>", "expiration": "<decimal ns string>",
                      "targets": ["rdmx6-…"], "permissions": "…" },
      "signature": "<b64>" } ] }
```

Validation before use:

- `looksLikeResult` requires `publicKey` string, `signerDelegation` array, and
  `length > 0` — an empty list would build a chain whose earliest expiry is 0
  (`session-delegation.ts:60-69`);
- error `code === 3002` → `InteractionRequiredError(message, data.reason)`
  (`:20,115-127`); any other error → `Error(message)`;
- the signer package independently validates the returned chain (leaf key, target scope,
  lifetime) — see `signer-protocol.md` §9.3.

## 3.5 `returnTo` validation (sign-in)

`sameOriginTarget(returnTo)` (`auth-client.ts:1891-1905`):

1. `new URL(returnTo, window.location.href)` — relative targets resolve against the
   current page; a parse failure → `undefined`.
2. Require `protocol ∈ {http:, https:}` **and** `target.origin === window.location.origin`.
3. Return the parsed `URL` (so callers navigate to `target.href`, never the raw string).

Anything else is **ignored, not refused** — a `returnTo` is a convenience, and failing the
sign-in over it would be worse (`:1882-1889`). Sign-in navigates with
`location.replace(target)` (replaces history; `:1088-1093`). Tests pin: same-origin
relative resolves and is replaced (`auth-client.test.ts:675-710`); cross-origin,
protocol-relative and `javascript:` are ignored (`:712-739`); no `returnTo` → no
navigation (`:741-759`); in redirect mode the validated href (or `null`) is journaled
(`auth-client-redirect.test.ts:235-264`).

## 3.6 Supersede / abort semantics

`#assertCurrent(signInLock)` (`:903-921`), called by `guarded()` **before every shared
write**:

- `#disposed` → `SupersededError('This client was disposed while signing in')`;
- channel lock stolen → `SupersededError('Another signer interaction took the channel')`;
- sign-in lock stolen → `SupersededError()` (default message).

A steal also closes the signer channel from the incumbent's side, turning "wait forever"
into "fail" (`:884-890`). `dispose()` releases the locks rather than taking any
(`:812-816`). Tests: `auth-client.test.ts:1574-1738`, `:1619-1667` (disposed client writes
nothing), `:1653-1667` (dispose releases, does not take).

## 3.7 `requestAttributes` interaction with `signIn`

Both take the **channel lock only** (`:1191-1193`), and `#beginInteraction`/`#endInteraction`
are shared, so a concurrent `signIn` + `requestAttributes` is **one** signer interaction
sharing one channel, and the channel closes only when the last request settles
(`:418-423`, `signer.js:323-335`). Tests: `auth-client.test.ts:2707-2790`.

## 3.8 `signOut()` (`auth-client.ts:1389-1452`)

| # | Action | Line |
| --- | --- | --- |
| 1 | `if (#isReadOnly) throw readOnlyError()` | `:1390` |
| 2 | `await #init()` — a hydration racing the deletion could repopulate the identity | `:1391-1393` |
| 3 | `signOutLock = stealLock(signInLockFor(stateSlot))` — the same lock a ceremony moves; **no channel lock** (a revoke is an agent call) | `:1395-1398` |
| 4 | Read `session` credential **before** clearing (the revoke is made as the session) | `:1400-1402` |
| 5 | `await stealMintLock(credentialStorage.shared ? appSlot : null)` — take the mint lock away rather than queue: a sign-out must not wait on another tab's canister call, and a mint that finishes after the wipe must not write | `:1404-1409` |
| 6 | Start `revoke(session.identity, session.chain)` in parallel with the wipe; a failure is **carried, not thrown yet** | `:1411-1424` |
| 7 | `cleared = #endSession()` (remove state, clear `session` + `app`) and `#installIdentity(new AnonymousIdentity())` | `:1425-1427` |
| 8 | `await Promise.all([revoked, cleared])`; release sign-in lock | `:1429-1431` |
| 9 | **Raise the carried revoke failure** after the wipe, before navigation | `:1433-1438` |
| 10 | If `returnTo`: `target = sameOriginTarget(returnTo)`; `window.location.assign(target.href)` — **assign**, not replace (sign-in uses replace) | `:1440-1451` |

`#revoke` (`:1492-1500`) builds a `SessionMinter` from the session and calls
`minter.revoke()` → `app_revoke_session` on the II canister (`session-minter.ts:180-182`).
Idempotent at the canister (`:170-179`); a canister refusal is raised, not swallowed
(`:1433-1438`; test `auth-client.test.ts:1472-1499`).

Tests: sign-out clears both credentials (`:1740-1754`), clears state storage
(`:2302-2314`), ends the session at the canister (`:1421-1435`), takes the mint lock away
(`:1516-1572`), and a sign-out is not undone by the sign-in it interrupted
(`:1574-1617`).

### 3.8.1 `returnTo` on sign-out

Same validator (`sameOriginTarget`, `:1447-1449`), but the sink is `location.assign`.
Tests: same-origin navigates (`auth-client.test.ts:761-772`), history is not rewritten
with `pushState` (`:777-789`), cross-origin / protocol-relative / `javascript:` never
reach the sink (`:791-812`). The comment at `:1441-1446` states the security property:
*the validated `href` is what reaches the sink, so neither an open redirect nor a
`javascript:` execution can be built from it.*

### 3.8.2 Idle-logout reload ordering

v5 had `IdleManager` + `onIdle`; v9 removed it (`upgrading/v9.md:59-72`). The ordering bug
"reload before teardown" was fixed in v8.0.2 (`CHANGELOG.md`, 8.0.2: *await session
teardown before the idle-logout reload*). In v11 there is **no reload inside the library**:
an idle-out arrives as `SessionStatus::expired`, and the application decides what to
render/reload (`upgrading/v9.md:65-72`). A Rust port must not reintroduce a reload.

## Rust port checklist

- [ ] `sign_in(options)` must open the popup **synchronously** in the caller's task and
      return a future — the first `await` may not precede `window.open`.
- [ ] Implement the two locks (channel, sign-in) as stealable, and make `assert_current`
      run before **every** shared write, not once.
- [ ] Session key: window = fresh per sign-in; redirect = durable-store requirement,
      `session-pending` write, journaled public key, supersede check on return.
- [ ] Send `ii_session_delegation` with `sessionPublicKey` base64 DER, string-encoded ns
      `maxTimeToLive`/`maxTimeToIdle` **only when set**, `icrc95DerivationOrigin` only when
      set, never `targets`.
- [ ] Validate the returned chain: non-empty `signerDelegation`, leaf key equals the
      requested key, and build the `DelegationChain` with `fromDelegations`.
- [ ] Map JSON-RPC `3002` to `InteractionRequired { reason }`; other errors to a generic
      signer error carrying code+message.
- [ ] Mint the app delegation inside `sign_in`; write `app-pending` then `session`+state
      then promote `app`; clear `session-pending` best-effort; then navigate.
- [ ] `returnTo`: parse relative to the current URL, require http(s) + same origin, ignore
      otherwise; sign-in `replace`, sign-out `assign`.
- [ ] `sign_out`: read session, steal mint lock only when the store is `shared`, run
      revoke and wipe in parallel, raise the revoke error after the wipe, then navigate.
- [ ] Delete `IdleManager`; represent idle-out as `Expired` and never reload from the
      library.
