# Porting notes: `@icp-sdk/auth` v11.2.0 → Rust

This directory is the specification the Rust port of
[`@icp-sdk/auth`](https://github.com/dfinity/icp-js-auth) follows. It exists so
that every behaviour in `src/client/` and `src/signer/` can be traced back to the
JavaScript it reproduces, with `file:line` references into the upstream
repository at the pinned versions:

| Upstream | Version | Commit |
| -------- | ------- | ------ |
| `dfinity/icp-js-auth` | `@icp-sdk/auth` 11.2.0 | `bb45d65` |
| `dfinity/icp-js-signer` | `@icp-sdk/signer` 6.1.0 | `163695b` |
| `@icp-sdk/core` | 6.1.1 | — |

## Reading order

| File | What it covers |
| ---- | -------------- |
| [`DESIGN.md`](DESIGN.md) | Architecture, module layout, decisions, phase plan, progress log |
| [`protocols/README.md`](protocols/README.md) | Index of the protocol/flow specs, conventions, headline v5→v11 changes |
| [`protocols/api-surface.md`](protocols/api-surface.md) | Every upstream export with full TypeScript signature, plus the Rust diff table |
| [`protocols/auth-client-lifecycle.md`](protocols/auth-client-lifecycle.md) | Constructor, options, state model, slots, restore, subscribe/dispose, worker mode |
| [`protocols/signin-flows.md`](protocols/signin-flows.md) | `signIn` (window and redirect transports), `signOut` |
| [`protocols/signer-protocol.md`](protocols/signer-protocol.md) | ICRC-25 JSON-RPC, ICRC-29 postMessage channel and heartbeat, ICRC-167 URL transport and journal |
| [`protocols/attributes-notifications-sso.md`](protocols/attributes-notifications-sso.md) | `requestAttributes`, notification consent, SSO domain status |
| [`protocols/session-delegations.md`](protocols/session-delegations.md) | The two-level delegation model, app-delegation minter, rotating identity, locks |
| [`protocols/rust-port-mapping.md`](protocols/rust-port-mapping.md) | Per-flow mapping onto the Rust crate, risks, design proposals |
| [`protocols/acceptance-tests.md`](protocols/acceptance-tests.md) | Upstream tests → acceptance criteria for the Rust port |
| [`state/README.md`](state/README.md) | Index of the storage/session specs and the constants each store uses |
| [`state/state-storage.md`](state/state-storage.md) | `SessionState`/`StateStorage`, the local/cookie/memory stores, the worker mirror |
| [`state/credential-storage.md`](state/credential-storage.md) | `Credential`/`CredentialStorage`, the four stores, IndexedDB schema and recovery |
| [`state/session-layer.md`](state/session-layer.md) | The `SessionIdentity` state machine, the minter's Candid interface, locks |
| [`state/idle-and-foreground.md`](state/idle-and-foreground.md) | Why `IdleManager` is gone, the watcher events, refresh throttling |
| [`state/subscriptions-and-status.md`](state/subscriptions-and-status.md) | Status values and transitions, subscribe/dispose, how changes propagate |
| [`state/test-inventory.md`](state/test-inventory.md) | All upstream vitest files, portability classes, the fakes worth porting |
| [`state/gap-analysis.md`](state/gap-analysis.md) | Upstream concept → Rust module, status, and the proposed Rust API |

## Conventions used by the specs

- `file:line` refers to the upstream repository unless prefixed with `rust:`.
- **Design proposal** marks behaviour that cannot be copied 1:1 because upstream
  relies on a browser API with no Rust equivalent; it is not upstream behaviour.
- Binary values on the signer wire are **standard padded base64**; hex appears
  only in the storage compatibility format.
- Every nanosecond value that crosses a wire boundary is a **decimal string**.

## Known deviations from upstream (documented, deliberate)

1. `ic-agent`'s `Identity::sign` is synchronous, so the port cannot hold
   non-extractable WebCrypto keys. The IndexedDB credential store generates
   **extractable** P-256 keys: JavaScript reads what Rust wrote, while a
   credential written by JavaScript's non-extractable key reads as absent here
   (the user signs in again).
2. `HttpAgentOptions` is not a plain data struct in Rust, so the create options
   carry a `host` (and a delegation-source factory for tests) instead of
   `agentOptions`.
3. `signIn` is split into a synchronous `begin_sign_in` (which opens the popup
   inside the caller's user gesture) and the awaitable that runs the ceremony.
4. The native feature has no upstream counterpart. A non-browser client does not
   speak the signer protocol: it signs in through Internet Identity's own
   non-browser flow (discovery at `/.well-known/cli-auth-config`, loopback
   callback, form POST) --- see [`crate::client::webauth`](../../src/client/webauth.rs)
   and the platform matrix in `DESIGN.md`. No bridge page is involved. The flow
   yields one delegation chain rather than the browser flow's session chain, so
   the two-level session model and its rotation remain browser-only, and
   browser-only facilities (cookies, Web Workers, Web Locks, notifications)
   degrade as documented in `DESIGN.md`.
