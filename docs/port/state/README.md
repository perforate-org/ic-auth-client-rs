# Upstream v11.2.0 — State / Credential / Session / Idle specification for the Rust port

This directory is the implementation-ready specification of the **state, credential, session and
idle layer** of `@icp-sdk/auth` **11.2.0**, written for the Rust port in
`/Users/yota/dev/ic-auth-client-rs` (crate `ic-auth-client` 0.5.0-beta.0).

- Upstream source: `/tmp/icp-js-auth`, tag `11.2.0`, commit
  `bb45d65b364c795344e6fbbfae807387e657b917` ("chore: release 11.2.0 (#216)", 2026-11-09).
- Rust source inspected read-only: `src/` at the time of writing; no build was run and no file
  outside `.build/upstream-v11/state/` was modified.
- A concurrent v11 implementation appeared under `src/client/` and `src/signer/` while these
  documents were written; it is not assessed here (see the note at the top of
  [`gap-analysis.md`](gap-analysis.md)).
- Every behaviour statement cites `file:line` in one of the two repos. Where the upstream code
  relies on a browser API the port cannot use, the closest Rust design is given and explicitly
  marked **design proposal**.

## Reading order

| File | Contents |
|---|---|
| [`state-storage.md`](state-storage.md) | `SessionState`, `StateStorage`, memory/local/cookie stores, worker mirror, exact formats, cross-subdomain sharing, redirect pending keys/journal, encoding limits |
| [`credential-storage.md`](credential-storage.md) | `Credential`, `CredentialStorage`, local/IDB/memory/shared-memory stores, exact IndexedDB schema/version/migration/recovery, `DEFAULT_SHARED_MEMORY_NAME` and the BroadcastChannel/Web Locks protocol, credential lifetime rules |
| [`session-layer.md`](session-layer.md) | session delegation request, `SessionMinter` Candid, error taxonomy, `SessionIdentity` rotation state machine, thresholds, account verification, Web Locks, `AuthClient` sign-in/sign-out/restore/expire/drop, read-only sessions |
| [`idle-and-foreground.md`](idle-and-foreground.md) | why `IdleManager` is gone, `watchForeground`/`watchActivity` exact events, foreground refresh, throttling, interaction with the current Rust `IdleManager` and what must change |
| [`subscriptions-and-status.md`](subscriptions-and-status.md) | `SessionStatus` values/transitions, `getStatus` stability, `subscribe`/`dispose`, how storage/`storage`/BroadcastChannel/cookie changes propagate |
| [`test-inventory.md`](test-inventory.md) | every upstream vitest file with a one-line assertion summary, portability classification, and the fake infrastructure (`fake-transport.ts`, `fake-url-transport.ts`, `setup-idb.ts`, lock stand-in) needed to test the port without a live Internet Identity |
| [`gap-analysis.md`](gap-analysis.md) | 51-row mapping upstream concept → current Rust module/line → status → proposal; proposed Rust API with feature gating and UniFFI; browser-only facility → native equivalent table; implementation order; 5 biggest risks |

Every file ends with a **Rust port checklist** of concrete, checkable work items.

## Constants quick reference (verified against the sources)

| Constant | Value | Source |
|---|---|---|
| state slot (bare) | `ic-session-state` | `src/client/slots.ts:49` |
| credential slots | `session`, `session-pending`, `app`, `app-pending` | `src/client/slots.ts:17-50` |
| namespace separator | `:` | `src/client/slots.ts:58` |
| state localStorage value | `<principal>|<expiration_ns>` (pipe, not JSON) | `src/client/state/local-state-storage.ts:82` |
| cookie attributes | `Domain=<domain>; Path=/; SameSite=Lax[; Secure]`, `Max-Age=34560000` (`400*24*60*60`) | `src/client/state/cookie-state-storage.ts:18,115-125,185` |
| cookie probe | `ic-cookie-probe` | `src/client/state/cookie-state-storage.ts:133` |
| worker state mirror | DB `auth-client-state-db`, store `ic-keyval`, value `{ raw: string \| null }`, BroadcastChannel `ic-session-state` | `src/client/state/local-state-storage.ts:5-9,181-195` |
| credential IndexedDB | DB `auth-client-db`, store `ic-keyval`, `DB_VERSION = 1`, record `{ keyPair, chain? }` | `src/client/db.ts:4-9`, `src/client/credentials/idb-credential-storage.ts:5-9` |
| localStorage credential | key `ic-<slot>`, value `{"key": "...", "chain": "..."}` | `src/client/credentials/local-credential-storage.ts:27,47-54` |
| shared-memory name | `ic-credentials` (`BroadcastChannel` + lock prefix) | `src/client/credentials/shared-memory-credential-storage.ts:5` |
| session delegation method | `ii_session_delegation`; interaction-required code `3002` | `src/client/session/session-delegation.ts:12,20` |
| mint constants | `BLOCK_MARGIN_MS = 10_000`, `PRE_MINT_THRESHOLD_MS = 15_000` | `src/client/session/session-identity.ts:19,28` |
| II canister methods | `app_prepare_delegation`, `app_get_delegation` (query), `app_revoke_session` | `src/client/session/session-minter.ts:32-54` |
| lock names | `ic-auth-signer-channel`, `<stateSlot>:sign-in`, app slot for mint | `src/client/auth-client.ts:54-57`, `src/client/session/session-identity.ts:184-188` |
| foreground events | `visibilitychange` (visible only), `focus`, `pageshow` | `src/client/foreground-refresh.ts:31-46` |
| activity events | `pointerdown, mousedown, mousemove, keydown, touchstart, wheel` (passive) | `src/client/foreground-refresh.ts:53,83-85` |
| status values | `signed-in`, `signed-in-elsewhere`, `expired`, `signed-out` | `src/client/auth-client.ts:324-332` |

## How to verify a claim

```bash
# upstream
cd /tmp/icp-js-auth && git log -1 --oneline && sed -n '324,332p' src/client/auth-client.ts
# rust (read-only)
cd /Users/yota/dev/ic-auth-client-rs && sed -n '1122,1138p' src/auth_client/wasm_js.rs
```

## Out of scope

Deliberately not specified here (other workstreams own them): the ICRC-29/167 signer transport
itself, `sso.ts` / `notification-consent.ts` details beyond their interaction with status and
subscriptions, the UI-facing `quick-start` docs, and the `ii-bridge/` native login bridge.
