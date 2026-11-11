# Protocol / flow layer of `@icp-sdk/auth` v11.2.0 — Rust-port specification

This directory specifies the **protocol and flow layer** that the Rust crate
`ic-auth-client` 0.5.0-beta.0 (currently a port of upstream **v5**) must reproduce to
behave like upstream **v11.2.0**.

## Sources and pinning

| Source | Revision / version | Location used |
| --- | --- | --- |
| Repo B, upstream JS | `bb45d65` — `chore: release 11.2.0` (tag `11.2.0`, 2026-11-09) | `/tmp/icp-js-auth` |
| `@icp-sdk/signer` (direct dep, `^6.1.0`) | **6.1.0** tarball from npm | `/tmp/signer-pkg/package/` |
| `@icp-sdk/core` (peer dep, `^6.1.1`) | **6.1.1** tarball from npm | `/tmp/signer-pkg/core/package/` |
| Repo A, Rust port | `0.5.0-beta.0` | `/Users/yota/dev/ic-auth-client-rs` (read-only here) |

Every claim below cites `file:line`. Upstream paths are relative to `/tmp/icp-js-auth`.
Signer/core paths are relative to the extracted tarballs (`package/lib/esm/...`); they
are **not vendored in the repo** (`/tmp/icp-js-auth/node_modules` is absent), so they
were read from the npm tarball at the version `package.json:38` pins (`^6.1.0`).

Versions inspected from `package.json:2-3,38-41`:
`@icp-sdk/auth@11.2.0`, deps `@icp-sdk/signer ^6.1.0`, `idb ^8.0.4`, peer
`@icp-sdk/core ^6`.

## Reading order

| File | Covers | Upstream surface |
| --- | --- | --- |
| [`api-surface.md`](api-surface.md) | §1 full public API with TS signatures; Rust diff table | `src/client/index.ts`, `src/client/auth-client.ts` |
| [`auth-client-lifecycle.md`](auth-client-lifecycle.md) | §2 constructor/options/defaults, `ready`, `getIdentity`, `isAuthenticated`, `getPrincipal`, `getStatus`, `subscribe`, `dispose`; state model, slots, storage contracts | `auth-client.ts`, `slots.ts`, `state/*`, `credentials/*` |
| [`signin-flows.md`](signin-flows.md) | §3 `signIn` window + redirect transports, wire messages, locking, timeouts, `returnTo`; §4 `signOut` | `auth-client.ts`, `session/session-delegation.ts` |
| [`signer-protocol.md`](signer-protocol.md) | §9 `@icp-sdk/signer` internals: JSON-RPC, ICRC-25/27/34/49 methods, ICRC-29 postMessage + heartbeat, ICRC-167 URL transport + journal | signer 6.1.0 |
| [`attributes-notifications-sso.md`](attributes-notifications-sso.md) | §5 `requestAttributes`; §6 notification consent; §7 SSO | `auth-client.ts`, `notification-consent.ts`, `sso.ts` |
| [`session-delegations.md`](session-delegations.md) | §8 session acquisition without ceremony, app delegations, `SessionMinter`, `SessionIdentity`, locks, errors, mint-on-return | `session/*` |
| [`rust-port-mapping.md`](rust-port-mapping.md) | §10 per-flow mapping to current Rust modules, required changes, Rust-specific risks and design proposals | `/Users/yota/dev/ic-auth-client-rs/src` |
| [`acceptance-tests.md`](acceptance-tests.md) | §11 upstream tests → acceptance criteria for the Rust port | `tests/client/*` |

## Conventions

- **MUST / SHOULD / MAY** are used in the RFC sense. A MUST is observable upstream
  behaviour that a test pins.
- `file:line` always refers to the *upstream* repo unless prefixed with `rust:`.
- **Design proposal** marks something the Rust port cannot copy 1:1 because upstream
  relies on a browser API with no Rust equivalent; the proposed shape is not upstream
  behaviour and must not be cited as such.
- Every section ends with a **Rust port checklist**.
- Base64 in this document is **standard** base64 (`btoa`/`atob` semantics), *not*
  base64url: `src/client/base64.ts:7-28`.
- Nanoseconds are `u64`/`bigint`; milliseconds are `f64`/`number`. Every timestamp that
  crosses a wire boundary is nanoseconds since the Unix epoch.

## Headline changes a v5-equivalent Rust port must absorb

1. **No builder, no `login()`**: `new AuthClient(options)` + `await signIn()`; the
   client is a *view* on stored state, construct/dispose per page
   (`docs/src/content/docs/upgrading/v9.md:11-22`).
2. **Identity provider is a pair** `{ authorizeUrl, canisterId }`, default
   `https://id.ai/authorize` + `rdmx6-jaaaa-aaaaa-aaadq-cai`
   (`src/client/auth-client.ts:59-60,132-138`).
3. **No `IdleManager`**; the session is bounded by the provider and by
   `maxTimeToLive`/`maxTimeToIdle` on `signIn` (`upgrading/v9.md:59-72`).
4. **The client mints its own app delegations** from the II canister, so the protocol
   layer includes canister calls, not only `postMessage` (`session/session-minter.ts`).
5. **Two transports**: `'window'` (ICRC-29 `postMessage`, default) and `'redirect'`
   (ICRC-167 URL transport) (`auth-client.ts:160-182`).
6. **Notifications consent (v11.1)** and **SSO domain status (v11.0)** are new client
   state surfaces (`notification-consent.ts`, `sso.ts`).
