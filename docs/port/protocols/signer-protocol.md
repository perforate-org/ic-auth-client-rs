# §9 — The `@icp-sdk/signer` dependency (protocol layer the Rust port must reimplement)

`@icp-sdk/auth` delegates **all** signer communication to `@icp-sdk/signer@6.1.0`
(`package.json:38`; imports at `auth-client.ts:14-15`,
`session/session-delegation.ts:4`, `notification-consent.ts:5`). The auth client only ever
uses three things from it:

```ts
new Signer({ transport, derivationOrigin })   // auth-client.ts:572-582
signer.sendRequest(request | Promise<request>) // :1216, session-delegation.ts:109, notification-consent.ts:67
signer.closeChannel()                          // :813,887
```

It does **not** use `Signer`'s typed helpers (`getAccounts`, `requestDelegation`,
`requestPermissions`, …). A Rust port therefore needs: a `Transport` abstraction, a
`Channel` abstraction with call-order semantics, a JSON-RPC 2.0 send/correlate layer, and
the two web transports. The typed helpers are optional.

Package exports (`package/lib/esm/index.d.ts`, `web/index.d.ts`):
`Signer`, `SignerError`, `SignerOptions`, `SignerRequestTransformFn`, `SupportedStandard`,
`PermissionScope`, `PermissionState`, `Channel`, `Transport` from the root;
`PostMessageTransport`, `UrlTransport`, `PostMessageChannel`, `UrlChannel`, `UrlFlow`,
`HeartbeatClient`, `HeartbeatServer`, and their error/option types from `/web`.

## 9.1 `Transport` / `Channel` contracts

```ts
// lib/esm/transport.d.ts:1-36
export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}
export type JsonRpcResponse =
  | { jsonrpc: '2.0'; id: string | number | null; result: unknown }
  | { jsonrpc: '2.0'; id: string | number | null; error: JsonRpcError };
export interface Channel {
  closed: boolean;
  addEventListener(event: 'close', listener: () => void): () => void;
  addEventListener(event: 'response', listener: (r: JsonRpcResponse) => void): () => void;
  send(request: JsonRpcRequest | Promise<JsonRpcRequest>): Promise<void>;
  close(): Promise<void>;
}
export interface Transport { establishChannel(): Promise<Channel>; }
```

Runtime guards (`lib/esm/transport.js:1-10`): a request is `{jsonrpc:'2.0', method:string}`;
a response is `{jsonrpc:'2.0', id: string|number}` with **either** `result` or `error`.

**The call-order contract.** `Channel.send` accepts a *promise* of a request: the slot is
reserved on the call, the request is transmitted when it resolves. `Signer.sendRequest`
opens the channel on the call and transforms/queues the request when its input resolves
(`signer.js:252-400`). This is what makes redirect replay deterministic: concurrent
requests whose inputs (e.g. a nonce) resolve in a different order on the return load still
replay into the slots they were sent from.

## 9.2 `Signer` core (`lib/esm/signer.js:174-652`)

Defaults (`:186-192`): `autoCloseTransportChannel: true`, `closeTransportChannelAfter: 200`
ms, `crypto: globalThis.crypto`.

Error codes it defines: `GENERIC_ERROR = 1000` (`:3`), `NETWORK_ERROR = 4000` (`:4`).
`SignerError` carries `code` and `data` (`:144-154`).

`sendRequest` behaviour (`:252-400`), in order:

1. `opening = openChannel()` **starts on the call** (`:253`). `openChannel` reuses a live
   channel, awaits an in-flight establishment, and wraps transport failures in
   `SignerError(NETWORK_ERROR)` (`:218-237`).
2. A promise-of-request that rejects is passed through **as the caller's error**, not
   reported as a network failure (`:256-263,268-275,386-388`).
3. Registers `response` and `close` listeners; a close before a response rejects with
   `SignerError(4000, 'Channel was closed before a response was received')` (`:337-345`).
4. Applies transforms (see §9.3), takes `id` from the transformed request.
5. Invalid `error` shapes are normalised to `{code:1000, message:'Invalid error response from signer'}`
   (`:309-319`).
6. `autoCloseTransportChannel`: only when `#pendingRequestCount === 0` is a close scheduled
   after `closeTransportChannelAfter` (`:323-335`). This is what keeps
   `Promise.all([signIn, requestAttributes])` on one channel.

Notifications: a request with `id === undefined | null` is send-and-forget and never
resolves from a response (`:277-284`); the URL transport rejects notifications outright
(`urlChannel.js:74-78`).

`#rpc` (`:607-644`): builds `{id: randomUUID(), jsonrpc:'2.0', method, params}` → throws
`SignerError(response.error)` on error → decodes `result` or throws
`SignerError(1000, 'Invalid result from signer: …')`.

### 9.2.1 Methods, params, results (all JSON-RPC 2.0)

| Method | Params | Result | Decoding / validation | Source |
| --- | --- | --- | --- | --- |
| `icrc25_supported_standards` | none | `{supportedStandards:[{name,url}]}` | require array of `{name,url}` strings | `signer.js:406-426` |
| `icrc25_request_permissions` | `{scopes:[PermissionScope]}` | `{scopes:[{scope:{method,…},state}]}` | `state ∈ denied\|ask_on_use\|granted` | `:433-455` |
| `icrc25_permissions` | none | `{scopes:[{scope,state}]}` | as above | `:460-480` |
| `icrc27_accounts` | none | `{accounts:[{owner:string, subaccount?:base64}]}` | `owner` → `Principal.fromText`, `subaccount` → base64 bytes | `:488-511` |
| `icrc34_delegation` | `{publicKey: base64 DER, targets?: string[], maxTimeToLive?: string ns}` | `{publicKey, signerDelegation:[{delegation:{pubkey,expiration,targets?,permissions?}, signature}]}` | see §9.2.2 | `:525-564` |
| `icrc49_call_canister` | `{canisterId, sender, method, arg: base64, nonce?: base64}` | `{contentMap: base64, certificate: base64}` | base64 decode both | `:579-600` |
| `icrc29_status` | — (transport heartbeat, not a `Signer` method) | `'pending' \| 'ready'` | see §9.4 | `web/heartbeat/*` |

Auth-client-private methods that travel over the **same** channel (defined in
`@icp-sdk/auth`, not in the signer package):

| Method | Params | Result | Source |
| --- | --- | --- | --- |
| `ii_session_delegation` | `{sessionPublicKey, maxTimeToLive?, maxTimeToIdle?, icrc95DerivationOrigin?}` | `{publicKey, signerDelegation}` | `session-delegation.ts:12,78-94` |
| `ii-icrc3-attributes` | `{keys: string[], nonce: base64}` | `{data: base64, signature: base64}` | `auth-client.ts:1216-1223` |
| `ii_notification_consent` | `{}` or `{icrc95DerivationOrigin}` | `{granted: boolean}` | `notification-consent.ts:15,67-74` |

> Naming convention, explicitly stated upstream: provider-scoped methods are prefixed
> because a JSON-RPC method travels over a transport shared with other signers, unlike a
> canister method (`session-delegation.ts:8-11`, `notification-consent.ts:10-14`).

### 9.2.2 Returned-delegation validation (`signer.js:49-115`)

The signer is *not fully trusted*; the client re-checks what it asked for:

1. `assertLeafKey` — the **last** delegation's `pubkey` must equal the requested
   `publicKey.toDer()`; else `'Returned delegation chain does not terminate at the requested public key'`
   (`:49-55`).
2. `assertTargetScope` — only when `targets` was requested: the effective scope
   (intersection of scoped hops) must be non-empty and a subset of the requested targets;
   an unscoped chain fails (`:60-84`).
3. `assertLifetime` — only when `maxTimeToLive` was requested: the chain's **earliest**
   expiration must be ≤ `Date.now()*1e6 + maxTimeToLive + 5 min` skew (`:90-105`).
4. Expirations are parsed from **decimal strings only**, ≤ 20 digits, < 2^64
   (`toExpiration`, `:38-47`) — a JSON number would already have lost precision.

## 9.3 Transforms and ICRC-95 derivation origin

`Signer` applies transforms in order, then a JSON-clean transform last
(`signer.js:181-185,649-651`):

| Transform | Effect | Source |
| --- | --- | --- |
| caller `transforms` | arbitrary request rewrite | `signer.d.ts:24-30` |
| `icrc95DerivationOriginTransform(derivationOrigin)` | adds `params.icrc95DerivationOrigin = derivationOrigin` to **every** request | `:131-139` |
| `jsonCleanTransform` | `JSON.parse(JSON.stringify(request))` — strips `undefined`, turns `NaN/Infinity` in arrays into `null`, **throws on BigInt** | `:125` |

The auth client passes `derivationOrigin: this.memoize(() => options.derivationOrigin?.toString())`
(`auth-client.ts:572-582`) so that the value survives the redirect (journaled at slot 0 in
redirect mode; passthrough in window mode). A `BigInt` anywhere in params would therefore
throw — which is why every ns value on the wire is a **string**
(`session-delegation.ts:84-92`, `signer.js:532`).

## 9.4 ICRC-29 window `postMessage` transport (`PostMessageTransport`)

Constructor (`web/postMessageTransport.js:29-58`):

| Option | Default | Line |
| --- | --- | --- |
| `url` | required; must be **secure context**: `https:` or host `127.0.0.1` or `*.localhost` | `:30-43` |
| `windowOpenerFeatures` | `''` | `:45` |
| `window` | `globalThis.window` | `:46` |
| `establishTimeout` | `120000` ms | `:47` |
| `pendingTimeout` | `300000` ms | `:48` |
| `disconnectTimeout` | `2000` ms | `:49` |
| `statusPollingRate` | `300` ms | `:50` |
| `crypto` | `globalThis.crypto` | `:51` |
| `manageFocus` | `true` | `:52` |
| `closeOnEstablishTimeout` / `closeOnPendingTimeout` | `true` / `true` | `:53-54` |
| `detectNonClickEstablishment` | `true` | `:55` |

A non-secure URL throws `PostMessageTransportError('Invalid signer RPC url')` (`:41-43`).

`establishChannel()` (`:66-111`):

1. If `detectNonClickEstablishment && !withinClick` → reject
   `'Signer window should not be opened outside of click handler, see: …'` (`:67-69`).
   `withinClick` is maintained by a **module-level** capture/bubble `click` listener pair
   on `window` (`:7-13`) — i.e. the popup must be opened inside the click task.
2. `window.open(url, `${new URL(url).origin}-signer-window`, windowOpenerFeatures)`; a null
   result → `'Signer window could not be opened'` (`:70-80`). The window **name** is the
   signer's origin + `-signer-window`, so reopening reuses the same tab.
3. Start `HeartbeatClient`; on establish resolve a `PostMessageChannel` with the
   **verified** origin and current status (`:81-110`); on establish timeout / pending
   timeout close the window and reject; on disconnect `channel.close()`; on status change
   `channel.changeStatus(status)`.

### 9.4.1 Heartbeat handshake (ICRC-29)

`HeartbeatClient` (`web/heartbeat/client.js:2-115`):

- **Establish**: every `statusPollingRate` ms post `{jsonrpc:'2.0', id, method:'icrc29_status'}`
  to the signer window with target origin `'*'` (`:112-114`). The first response whose `id`
  is one of ours **and** whose `result` is `'pending'` or `'ready'` establishes the channel
  with `(event.origin, result)` (`:26-38,95-111`). The listener requires
  `event.source === signerWindow` (`:102`).
- **Maintain**: poll continuously; a response to a pending id within `disconnectTimeout`
  resets the timeout; a status change fires `onStatusChange` (`:48-94`). Timeout is
  `pendingTimeout` while status is `'pending'`, else `disconnectTimeout` (`:70-76`).
- **Server side** (for a Rust signer/II implementation, `web/heartbeat/server.js:2-81`):
  respond to `icrc29_status` requests with `{jsonrpc:'2.0', id, result: status}` to
  `event.origin` (`:66-80`); `status` defaults `'ready'`; an optional
  `allowedOrigin`; when `window.opener` exists it proactively sends
  `{id:'wake-up-client', result:status}` to resume a slept page (`:37-39`).

### 9.4.2 `PostMessageChannel` (`web/postMessageChannel.js:12-111`)

- `closed` = own flag **or** `signerWindow.closed` (`:26-28`).
- `response` listener accepts a message only if
  `event.source === signerWindow && event.origin === signerOrigin && isJsonRpcResponse(event.data)`
  (`:37-45`). This is the origin/source check a Rust port must reproduce exactly.
- `send`: if status is `'pending'`, queue; else `signerWindow.postMessage(request, signerOrigin)`
  and, when `manageFocus`, `signerWindow.focus()` (`:59-80`).
- `changeStatus('ready')` flushes the queue (`:101-110`).
- `close`: closes the window, refocuses the opener, notifies close listeners (`:82-95`).

## 9.5 ICRC-167 URL (redirect) transport (`UrlTransport` + `UrlFlow` + `UrlChannel`)

`UrlTransport` (`web/urlTransport.js:51-86`):

| Option | Default | Line |
| --- | --- | --- |
| `url` | required; secure-context URL | `:54-56` |
| `callbackUrl` | required; absolute; **must not contain a fragment** | `:57-66` |
| `storage` | `sessionStorage` | `:70` |
| `storageKey` | `` `icrc167:flow:${callbackUrl}` `` | `:71` |
| `flowTimeout` | `600000` ms | `:72` |
| `location` / `history` / `crypto` / `now` | globals | `:73-76` |

`isSecureContextUrl` (`urlFlow.js:15-23`): `https:` anywhere, or `http:` only on a loopback
host (`localhost`, `*.localhost`, `[::1]`, `127/8`). Re-checked **at the navigation sink**
(`urlFlow.js:263-268`) because the target URL may have been restored from storage.

### 9.5.1 The journal (`StoredFlow`, `urlFlow.js:70-282`)

Persisted JSON at `storageKey` (`:271-281`):

```json
{
  "createdAt": 1760000000000,
  "url": "https://id.ai/icrc-167",
  "results": { "0": <value>, "1": <JsonRpcResponse> },
  "asyncSlots": [1],
  "requestKeys": { "1": "{\"method\":\"…\",\"params\":…}" },
  "pending": { "state": "<uuid>", "requests": [{ "index": 1, "id": "<uuid>" }] }
}
```

Rules:

1. **Fresh vs return** (`:94-137`): a load continues the stored flow only when
   `!expired && hash has message && stored.pending && state === stored.pending.state`.
   Otherwise it starts fresh (`results = {}`), ignoring any leftover journal. An expired
   journal (`now - createdAt > flowTimeout`) is removed (`:95-98`).
2. **Strip the response fragment** whenever `message` is present, matching or not, via
   `history.replaceState(null, '', pathname + search)` (`:103-108`) — the fragment may
   carry a delegation.
3. On a return, fold each returned response into `results[index]` by matching
   `response.id` against `stored.pending.requests` (`:122-130`); the message is a single
   object or an array (`:123`).
4. `next()` reserves a call-order slot (`:139-141`); slots are shared by **requests and
   `memoize` steps**.
5. `memoize(produce)` (`:180-225`): replay returns the journaled value (a promise if the
   slot was async, `:194`); otherwise run `produce`, record, `persist`. A `memoize` step
   landing on a slot that held a **request** throws
   `'URL transport replay diverged: a memoize step is at a slot that held a request before the redirect. …'`
   (`:186-190`).
6. `request(index, request, key)` buffers for the next redirect and records the content
   fingerprint (`:163-167`).
7. `hold()` (`:172-179`) keeps the flush from navigating while a step is still in flight —
   so a concurrently produced nonce is journaled before the page leaves.
8. **Batch + navigate** (`:226-270`): a macrotask (`setTimeout 0`) after the first buffered
   request flushes **all** buffered requests as one JSON-RPC batch:
   - new `state = randomUUID()`;
   - persist `pending = {state, requests:[{index, id}]}`;
   - `message = JSON.stringify(requests.length === 1 ? requests[0] : requests)`;
   - `fragment = URLSearchParams({message, callback: callbackUrl, state})`;
   - `location.assign(`${url}#${fragment}``)`, after re-checking the secure context.
   One redirect per **batch**, so concurrently issued requests cost one round trip
   (`README.md` of the signer package, "Requests issued concurrently are coalesced").

### 9.5.2 `UrlChannel` (`urlChannel.js:22-110`)

- `send` takes `index = flow.next()` **on the call**, then, for a promise request, holds
  the flow until it resolves (`:58-68`).
- Notifications (`id == null`) are rejected: `'The URL transport requires a request id; notifications are not supported'`
  (`:74-78`).
- Fingerprint `requestKey = JSON.stringify({method, params: params ?? null})` (`:3`).
- **Replay** when the journal has a result at this index (`:80-95`): the recorded key must
  equal this call's key, else
  `'URL transport replay diverged: the request at this step differs from the one sent before the redirect. …'`.
  The replayed response is re-stamped with **this** call's id (`:87-88`) and delivered on a
  microtask (`:89-94`); `send` resolves without navigating.
- Otherwise buffer for the next redirect (`:96-97`).

### 9.5.3 The replay contract (what a caller must do)

From `signer.d.ts`/`urlTransport.d.ts` docs and `upgrading/v8.md:30-68`:

1. Run the flow code **on the load of the flow's route**; a fresh visit starts it, the
   signer's return replays it.
2. Issue the same requests and `memoize` steps in the **same order on every load**; branch
   only on values recovered from earlier results.
3. Route every value a request depends on (a nonce, a return URL) through `memoize`.
4. There is **no resume or cleanup call**; a completed journal is inert to the next flow,
   and `flowTimeout` is the backstop.

## 9.6 What the auth client relies on — summary for the Rust port

| Reliance | Where | Rust must implement |
| --- | --- | --- |
| Transport chosen at construction, `instanceof UrlTransport` selects redirect paths | `auth-client.ts:557-570` | an enum/trait with a `is_redirect()` predicate |
| `sendRequest` opens the channel **on the call** | `signer.js:253` | reserve/establish before any await |
| Request may be a promise, keeping call order | `signer.js:252-284` | a slot-reserving API, not `async fn` alone |
| Channel shared by concurrent requests; closes after the last | `signer.js:323-335` | pending-request counter + deferred close |
| Close before response → error | `signer.js:337-345` | typed `ChannelClosed` error |
| Transforms: ICRC-95 param on every request; JSON-clean last | `signer.js:181-185` | serde-based request builder; **never** emit BigInt |
| `closeChannel()` used by `dispose` and by a channel steal | `auth-client.ts:813,887` | transport close |
| Redirect `memoize` used by the client for derivation origin, session key, nonce, `returnTo` | `auth-client.ts:581,955,1140,1208-1210` | journal API on the redirect transport |

## Rust port checklist

- [ ] Define `JsonRpcRequest`/`JsonRpcResponse` as serde types with `#[serde(untagged)]`
      or explicit result/error enums; keep `id` a `String` (UUID) and allow `null`.
- [ ] Implement `Transport`/`Channel` traits; `send` must accept a request that is not yet
      materialised (reserve the call-order slot at call time — see design proposal in
      `rust-port-mapping.md` §10.5).
- [ ] Implement `Signer`-equivalent: channel reuse, pending-request counter, deferred close
      (200 ms), `SignerError {code,message,data}`, 1000/4000 codes, close-before-response
      error.
- [ ] Apply the ICRC-95 derivation-origin transform to **every** request and JSON-clean
      last (serde_json round trip is equivalent; reject non-JSON values at the type level).
- [ ] Window transport: secure-context check, `window.open` with window name
      `${origin}-signer-window`, ICRC-29 heartbeat (120 s / 300 s / 2 s / 300 ms), source+
      origin filtering, pending queue, focus management, click-handler detection.
- [ ] Redirect transport: secure-context check, callback validation (absolute, no
      fragment), journal format in §9.5.1, fresh-vs-return rule, fragment stripping,
      call-order slots shared with `memoize`, content-fingerprint divergence guard,
      batching + single redirect, `flowTimeout` 600 s.
- [ ] Do **not** port the typed signer helpers (`icrc27_accounts`, `icrc34_delegation`,
      `icrc49_call_canister`) unless a downstream consumer needs them; the auth flows use
      raw `sendRequest` only.
