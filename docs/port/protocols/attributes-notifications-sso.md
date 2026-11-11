# §5 — `requestAttributes`, §6 — Notification consent, §7 — SSO

## §5 `requestAttributes({ keys, nonce })` (`auth-client.ts:1187-1244`)

### 5.1 Signature and nonce semantics (v8 breaking change)

```ts
requestAttributes(params: {
  keys: string[];
  nonce: () => Promise<Uint8Array>;   // a CALLBACK, not a value
}): Promise<SignedAttributes>;        // { data: Uint8Array; signature: Uint8Array }
```

v8 changed `nonce` from `Uint8Array | Promise<Uint8Array>` to a **callback**
(`docs/src/content/docs/upgrading/v8.md:9-28`). Reasons, both observable:

1. **Redirect journaling.** In `'redirect'` mode the produced nonce is journaled (base64,
   because the journal is JSON) and reused on the return load, so the signer signs the
   same single-use bytes rather than a freshly fetched nonce
   (`auth-client.ts:1206-1210`; `upgrading/v8.md:26-28`).
2. **Popup timing.** In `'window'` mode the identity provider window opens while the
   nonce is still resolving; the signer keeps the channel open while the request waits for
   its nonce (`auth-client.ts:1173-1178`).

Passing `nonce: () => Promise.resolve(alreadyFetched)` re-runs nothing but defeats the
journaling guarantee (`upgrading/v8.md:26`).

### 5.2 Flow (`#runRequestAttributes`, `auth-client.ts:1202-1244`)

| # | Action | Line |
| --- | --- | --- |
| 1 | `#beginInteraction()` / `finally #endInteraction()` (channel lock only, shared with `signIn`) | `:1191-1199` |
| 2 | Nonce: redirect → `urlTransport.memoize(async () => toBase64(await params.nonce()))`; window → `params.nonce().then(toBase64)` | `:1208-1210` |
| 3 | `signer.sendRequest(nonce.then(value => ({jsonrpc:'2.0', id: randomUUID(), method:'ii-icrc3-attributes', params:{keys, nonce: value}})))` — handed over **on the call**, so the channel opens and the slot is taken while the nonce resolves | `:1216-1223` |
| 4 | `#takeChannelLock()` | `:1224` |
| 5 | `await response`; `'error' in response` → `throw new Error(response.error.message)` | `:1225-1229` |
| 6 | Require `result.data` and `result.signature` to be strings, else `Error('Invalid response: missing data or signature')` | `:1231-1234` |
| 7 | `fromBase64` both; a decode failure → `Error('Invalid response: data or signature is not valid base64', {cause})` | `:1236-1243` |

Wire message:

```json
{
  "jsonrpc": "2.0",
  "id": "<crypto.randomUUID()>",
  "method": "ii-icrc3-attributes",
  "params": { "keys": ["email", "name"], "nonce": "<base64 of the 32-byte nonce>" }
}
```

`id` inclusion is mandatory: the signer correlates by `id`, and the URL transport rejects
requests without one (`urlChannel.js:74-78`).

### 5.3 Tests that pin the behaviour

| Assertion | Test |
| --- | --- |
| method/keys/base64 nonce; result decoded to bytes | `auth-client.test.ts:2523-2541` |
| provided nonce used verbatim | `:2542-2552` |
| distinct nonces → distinct base64 | `:2553-2569` |
| signer error message propagated | `:2570-2581` |
| missing `data` or `signature` rejected | `:2582-2591` |
| promise-returning callback forwarded | `:2592-2606` |
| **channel opens before the nonce resolves** | `:2607-2632` |
| nonce rejection propagated | `:2634-2641` |
| redirect: nonce memoized as base64 at journal slot 1, derivation origin at slot 0 | `auth-client-redirect.test.ts:375-392` |
| redirect: nonce **not** re-fetched on the return load | `:394-416`; `auth-client-redirect-replay.test.ts:108-156` |

## Rust port checklist (§5)

- [ ] Take `nonce: impl FnOnce() -> impl Future<Output = Result<Vec<u8>>>` (a callback),
      never a pre-fetched value; document why.
- [ ] Redirect: journal the base64 nonce at the next call-order slot before sending.
- [ ] Window: hand the request (as a future) to the signer before awaiting the nonce.
- [ ] Send `ii-icrc3-attributes` with a fresh UUID `id`; decode `{data, signature}` from
      base64; map error responses to a signer error; validate both fields exist.

---

## §6 Notification consent (v11.1)

Introduced in 11.1.0 (`CHANGELOG.md`, *ask for, read and withdraw notification consent*).
Three operations on `AuthClient`, plus one free function and one service class:

| Operation | Ceremony? | Transport | Canister | Source |
| --- | --- | --- | --- | --- |
| `requestNotificationConsent()` | yes (opens II) | signer `sendRequest` | – | `auth-client.ts:1265-1277` |
| `getNotificationConsentStatus()` | no | – | `app_notification_consent_status` (query) | `:1305-1307` |
| `revokeNotificationConsent()` | no | – | `app_revoke_notification_consent` (update) | `:1288-1290` |
| `requestNotificationConsent(signer, derivationOrigin?)` (free fn) | – | signer | – | `notification-consent.ts:63-91` |
| `NotificationConsent.create/status/revoke` | – | agent | both canister methods | `:158-214` |

### 6.1 The signer request (`ii_notification_consent`)

```json
{
  "jsonrpc": "2.0",
  "id": "<crypto.randomUUID()>",
  "method": "ii_notification_consent",
  "params": {}                                   // or { "icrc95DerivationOrigin": "https://…" }
}
```

- Method constant `NOTIFICATION_CONSENT_METHOD = 'ii_notification_consent'`
  (`notification-consent.ts:15`).
- `params` is **always an object**: `{}` when there is no derivation origin, never absent
  (`:71-74`; test `notification-consent.test.ts:65-71`).
- The derivation origin is `options.derivationOrigin?.toString()` from the client
  (`auth-client.ts:1271`; test `:73-81`).

Error mapping (`notification-consent.ts:76-84`):

| JSON-RPC code | Meaning | Result |
| --- | --- | --- |
| `-32601` (`METHOD_NOT_FOUND_CODE`, `:21`) | this II does not notify at all | `NotificationsUnsupportedError` |
| `3002` (`INTERACTION_REQUIRED_CODE`, `:18`) | request asked not to render (`prompt:'none'`) | `InteractionRequiredError` |
| anything else | – | `Error(response.error.message)` |

Success: `result.granted` must be a boolean, else `Error('Invalid response: missing granted')`
(`:86-90`). A **refusal is an answer**: `{granted:false}` resolves, it does not throw
(`:48-55`; test `:83-87`).

`AuthClient.requestNotificationConsent` (`:1265-1277`) takes the **channel lock** (not the
sign-in lock) because it opens the signer channel and writes nothing shared, then calls
the free function.

### 6.2 The canister calls (as the session, not as the app)

`NotificationConsent.create` (`:172-183`):

1. `assertChainReaches(sessionChain, canisterId)` — the session chain must be restricted
   to exactly this II canister (`session-minter.ts:249-277`).
2. Build `HttpAgent` with `...agentOptions` then **last** `identity:
   DelegationIdentity.fromDelegation(sessionKey, sessionChain)` so no agent option can
   replace the session (`:175-179`).

IDL, written inline because the package carries no II declarations (`:107-125`):

```candid
type ConsentError = variant { NoSuchSession; InternalCanisterError : text };
type Status = record { is_granted : bool };

service : {
  app_notification_consent_status : () -> (variant { Ok : Status; Err : ConsentError }) query;
  app_revoke_notification_consent : () -> (variant { Ok : null; Err : ConsentError });
}
```

Result mapping (`unwrap`, `:131-138`):

| Candid | Outcome |
| --- | --- |
| `Ok` | value |
| `Err.NoSuchSession` | `SessionGoneError` |
| `Err.InternalCanisterError(text)` | `Error('<failed><: text?>')` where `<failed>` is the call-specific prefix (`'Internet Identity could not report this notification consent'` / `'… could not withdraw this notification consent'`) |

`status()` is a **query** → uncertified; it reports consent only, not whether a
notification would actually reach the device (`:185-197`). `revoke()` is idempotent at the
canister and a failed write is raised (`:199-213`).

### 6.3 The client's session guard (`#consent`, `auth-client.ts:1316-1335`)

1. `await #init()` — the constructor restore must have put the credential where this reads.
2. Read `session` slot; if absent, or `chain === undefined`, or `!isDelegationValid(chain)`
   → **`SessionGoneError`** (`:1324-1327`). The chain check matters because `#init()`
   resolves once, so a session that expired while the page stayed open is still in the slot
   (`:1321-1323`).
3. `NotificationConsent.create({sessionKey, sessionChain, canisterId, agentOptions})`.

Tests: status/revoke refuse without a live session, including a session that ran out while
the page stayed open (`auth-client.test.ts:2644-2705`).

### 6.4 Derivation origin handling — summary

| Path | How the derivation origin travels |
| --- | --- |
| consent ceremony | explicit `params.icrc95DerivationOrigin` in `ii_notification_consent` (`notification-consent.ts:73`) |
| consent status/revoke | **not needed**: the canister authorises by the session principal the call signs with (`:165-171`) |

## Rust port checklist (§6)

- [ ] Add the three `AuthClient` methods plus `NotificationsUnsupportedError` and
      `NotificationConsentStatus`.
- [ ] Send `ii_notification_consent` with an object `params` (empty object when unset),
      map `-32601`/`3002`/other errors as in §6.1, require a boolean `granted`.
- [ ] Implement `NotificationConsent` over `ic-agent`: inline Candid for
      `app_notification_consent_status` (query) and `app_revoke_notification_consent`
      (update); map `NoSuchSession` → `SessionGoneError`.
- [ ] Assert the session chain is restricted to the II canister before building the agent
      (port `assertChainReaches`).
- [ ] Guard status/revoke with the session-present + `is_delegation_valid` check and throw
      `SessionGoneError`.

---

## §7 SSO (v9 one-click, v10 unchanged, v11 rewritten)

History: v9 added `ssoDomain` + `isValidSsoDomain` (`upgrading/v9.md:104`);
v11 **removed** `isValidSsoDomain` and made the check client state
(`docs/src/content/docs/upgrading/v11.md:9-46`, `CHANGELOG.md` 11.0.0 breaking note).

### 7.1 Option and validation

`AuthClientCreateOptions.ssoDomain?: string` (`auth-client.ts:239-271`), mutually exclusive
with `openIdProvider` (`:502-504`).

`normalizeSsoDomain(domain)` (`sso.ts:68-111`) — port this function verbatim:

1. Trim; empty → `Error('ssoDomain cannot be empty')` (`:69-72`).
2. Detect and **reject a scheme** (`:73-74,91`), then parse `new URL('https://' + rest)`.
   Parse failure → `Error('ssoDomain "<quoted>" is not a domain')` (`:76-80`).
3. Reject `userinfo`, `pathname !== '/'`, `?`, `#` (`:92-95`).
4. **Loopback** host (`localhost`, `127.0.0.1`, `*.localhost`; `:26-28`):
   - may carry a port; a typed port must be non-empty and equal the parsed port
     (`localhost:443` is rejected because `URL` drops the default port) (`:97-101`).
   Non-loopback: a typed port is rejected with
   `'a port, which only loopback hosts may carry'` (`:97-98`).
5. Length: authority > 255 → `'more than 255 characters'` (`:6,102-103`).
6. DNS rules for non-loopback (`dnsNameProblems`, `:31-53`): ≥ 2 labels; no empty label;
   label ≤ 63; only `[a-z0-9-]`; no leading/trailing `-`; no `--` in positions 3–4 unless
   `xn--`; name ≤ 253.
7. Returns `url.host` — lowercased and IDNA-encoded (`:110`).
8. Every problem is collected and reported together (`listed`, `:55-57,107-109`); values in
   messages are JSON-quoted and cut to 100 chars + `…` (`:12-19`).

Accept/reject table (from `tests/client/sso.test.ts:12-68`):

| Input | Output |
| --- | --- |
| `dfinity.org` / `  DFINITY.org  ` | `dfinity.org` |
| `zürich.example` | `xn--zrich-kva.example` |
| `localhost:11107`, `127.0.0.1`, `app.localhost:8000` | accepted |
| `sso-2.dfinity.org`, `xn--zrich-kva.example`, 253-char name | accepted |
| `''`, `dfinity`, `https://dfinity.org`, `dfinity.org/sso`, `dfinity.org?x=1`, `dfinity.org#x`, `user:pw@dfinity.org`, `sso.dfinity.org:8443`, `dfinity.org:443`, `dfinity.org:`, `localhost:`, `localhost:443`, `.org`, `dfinity..org`, `-dfinity.org`, `dfinity-.org`, `df_inity.org`, 64-char label, `ab--cd.org`, >253-char name, `dfinity .org`, >255-char authority | rejected |

### 7.2 Constructor wiring (`auth-client.ts:508-537`)

1. Try `normalizeSsoDomain`; a throw becomes `{invalid: message}` — **the constructor does
   not throw** (`:509-514`; v11 breaking change).
2. Set the `sso` query param to the normalized domain, or, when invalid, to
   `options.ssoDomain.trim()` **as typed** (`:515-520`). Internet Identity explains the
   error on its own screen, and `signIn()` proceeds in every SSO state
   (`:716-722`; test `auth-client.test.ts:2940-2963`).
3. If `derivationOrigin` is set, also set `derivationOrigin` on the authorize URL
   (`:521-528`; tests `:945-957`).
4. Build `SsoStatusChecker(domain, () => createSsoDomainService({canisterId, agentOptions}), onChange)`
   where `onChange` fires the client's listeners (`:529-536`).

### 7.3 `getSsoStatus()` / `refreshSsoStatus()`

```ts
getSsoStatus(): SsoStatus | undefined     // undefined for a client built without ssoDomain
refreshSsoStatus(): void                  // no-op for invalid domain or no ssoDomain
```

`getSsoStatus` returns the checker's current status object (`auth-client.ts:728-730`);
`refreshSsoStatus` calls `checker.refresh()` (`:742-744`). Both are synchronous, and the
status object is stable until it changes (`sso.ts:274-277,360-364`).

`SsoStatusChecker` (`sso.ts:241-365`):

| Aspect | Behaviour | Line |
| --- | --- | --- |
| initial | `checking` for a valid domain and `#start(0)` immediately; `invalid{reason}` forever for an invalid one (never calls) | `:264-272` |
| start | bump run counter, clear timer, schedule `#check(run)` | `:294-301` |
| check | `app_sso_domain_check(domain)` (update); a failure is swallowed — the status reads still run and a never-started check is restarted after the abandon window | `:307-320` |
| poll | `app_sso_domain_status(domain)` (query) with exponential backoff `500 ms → 2 s` | `:182-183,322-346` |
| final | `Available` / `Unavailable` stops polling | `:333-336` |
| pending | `Pending` keeps `checking`; after `SSO_RECHECK_AFTER_MS = 120_000` a fresh `app_sso_domain_check` is started | `:189,337-342` |
| read failure | retried at the next interval | `:329-331,343-346` |
| refresh | sets `checking` then re-checks; no-op for invalid or disposed | `:280-284` |
| dispose | bump run, clear timer; a late answer is dropped | `:287-292,303-305` |
| change | fires `onChange` only when `sameStatus` says different (deep compare of all fields) | `:215-230,360-364` |
| service build | built once, retried if the build failed | `:348-358` |

Status mapping from Candid (`fromCandid`, `:195-213`):

| Candid `app_sso_domain_status` | `SsoStatus` |
| --- | --- |
| `Available { name: [] \| [text] }` | `{state:'available'}` or `{state:'available', name}` |
| `Pending` | `undefined` → stays `checking` |
| `Unavailable { retry_after: [] \| [nat64 ns], reason: [] \| [text] }` | `{state:'unavailable', retryAfter?: Date, reason?}` |

### 7.4 Canister interface (`sso.ts:134-160`)

```candid
type Timestamp = nat64;
type Status = variant {
  Available   : record { name : opt text };
  Pending;
  Unavailable : record { retry_after : opt Timestamp; reason : opt text };
};
service : {
  app_sso_domain_check  : (text) -> ();            // update
  app_sso_domain_status : (text) -> (Status) query;
}
```

`createSsoDomainService` (`:166-179`) builds an `HttpAgent` as **anonymous** (`identity:
new AnonymousIdentity()` last), because the check runs before anyone has signed in
(`:162-165`), using the same `identityProvider.canisterId` and `agentOptions` the client
mints with (`upgrading/v11.md:66-68`).

### 7.5 The SSO sign-in flow itself

There is **no SSO-specific protocol in the auth client**. The domain is baked into the
authorize URL as `sso=…` (plus `derivationOrigin` when configured) and the normal
`signIn()` runs; II resolves the domain and renders its own provider. Consequences a Rust
port must preserve:

- `signIn()` must not gate on `SsoStatus` — it proceeds in `invalid`, `checking`,
  `available` and `unavailable` (`auth-client.test.ts:2940-2963`).
- `subscribe()` fires for SSO status changes as well as sign-in changes
  (`upgrading/v11.md:60-62`; test `auth-client.test.ts:2902-2911`).
- A local II without the two methods leaves the status at `checking` forever
  (`upgrading/v11.md:64-68`).
- Attribute keys can be scoped to the organization with
  `scopedKeys({ ssoDomain, keys })` → `sso:<normalized-domain>:<key>`
  (`auth-client.ts:1944-1964`; default keys `['name','email']`, `verified_email` not
  available for SSO, `:72`).

## Rust port checklist (§7)

- [ ] Port `normalize_sso_domain` with the full rule set and the aggregated error message
      (quote+truncate to 100 chars, list every problem).
- [ ] `ssoDomain` is optional, mutually exclusive with `open_id_provider`, and a malformed
      value must **not** fail construction: store `SsoStatus::Invalid { reason }`.
- [ ] Set `sso` (normalized or trimmed-as-typed) and, only with `ssoDomain`,
      `derivationOrigin` on the authorize URL.
- [ ] Implement `SsoStatusChecker` as an async task with the 500 ms→2 s backoff, 120 s
      abandon window, `retryAfter`, `refresh`, `dispose`, stable-value change detection.
- [ ] Inline Candid for `app_sso_domain_check` / `app_sso_domain_status`; call as anonymous
      with `agentOptions` and the configured `canisterId`.
- [ ] `get_sso_status() -> Option<SsoStatus>` and `refresh_sso_status()`; `subscribe` must
      fire for SSO changes; `sign_in` must never gate on SSO state.
- [ ] Port `scoped_keys` for the `sso:` prefix with domain normalization.
