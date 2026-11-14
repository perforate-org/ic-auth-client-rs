# Native sign-in over ICRC-167 — design proposal

**Status:** proposed, 2026-11-14. Not upstream behaviour: `@icp-sdk/auth` has no
non-browser entry point, so this is a Rust-only extension. Upstream references
below are to `@icp-sdk/auth` 11.2.0 / `@icp-sdk/signer` 6.1.0 (see
[README.md](README.md)); protocol references are to the ICRC-167 draft at
`cd5ef7d2`.

## 0. Decision

Native desktop sign-in gets a second path, **ICRC-167 URL transport against a
relay page the application hosts on its own origin**. The existing
[`webauth`](../../src/client/webauth.rs) flow (Internet Identity's non-browser
CLI flow) stays as the fallback for applications without a domain. The browser
(`wasm-js`) surface does not change.

Why:

- It removes the "CLI access" toggle. `webauth` with `derivation_origin` needs
  the user to enable CLI access for that identity in Internet Identity's
  settings (`README.md`, "Native applications").
- It restores the v11 model on native: the signer returns an **II-scoped session
  delegation**, the client mints the app delegation through the canister, and
  `SessionIdentity` can rotate. `webauth` can only hand out one relying-party
  chain with no rotation.
- It keeps the principal. With the relay page on the app's own origin, the
  relying-party origin *is* the derivation origin, so the principal matches the
  one the browser sign-in produces.
- Attributes and notification consent become reachable on native (they are
  `Unsupported` today because the client has no signer transport).

## 1. Evidence from the probe

Measured 2026-11-14 against `https://id.ai/authorize` with
[`probes/icrc167/`](../../probes/icrc167/README.md) (real Internet Identity,
Cloudflare-tunnelled origin). The probe is the regression fixture for this
design; re-run it when II changes.

| Probe | Request | Result |
| --- | --- | --- |
| E1 | `icrc34_delegation` | Accepted. Two-hop chain (canister-signed -> browser key, browser-signed -> asked key). Leaf = asked key. Leaf expiry came back as the 30-day maximum, not the requested 8 hours. |
| **E2** | **`ii_session_delegation`** | **Accepted. Two-hop chain, both hops `targets: ["rdmx6-jaaaa-aaaaa-aaadq-cai"]`, both expiring in exactly the requested 8 hours, leaf = asked key.** This is the request the v11 browser sign-in sends. |
| E3 | `icrc34_delegation` + `targets: [II canister]` | Accepted, but `targets` was **ignored** (unscoped chain, same root as E1). No fallback design on this. |
| — | JSON-RPC **batch** (delegation + `icrc27_accounts`) | **Not answered.** II stopped on its terminal "Authentication successful" page and never drove the callback. One JSON-RPC message per navigation; sequential round-trips are fine (every other probe ran as its own navigation). |
| E4 | `icrc34_delegation` + `icrc95DerivationOrigin: https://example.com` | **Rejected** with II's "Unverified origin --- It seems like the request could not be processed." II fetches `<derivation>/.well-known/ii-alternative-origins` and only lets an origin derive as another when that document names the relying party. |
| E5 | same-origin derivation | No-op, root identical to E1, as expected. |

Consequences that shape the design:

1. The v11 ceremony works unchanged over this transport: sign-in sends exactly
   one signer request (`ii_session_delegation`, `auth_client.rs:710`), and the
   response matches `signer::protocol::parse_session_delegation`.
2. The transport must do **one navigation per `send`**. Batches must never be
   used. (The browser `UrlTransport` already behaves this way; see
   `rust:session_key_for_sign_in`'s "the flow runs twice" comment.)
3. Derivation is validated, so a shared relay domain cannot silently impersonate
   an app, and an app-domain relay page needs no
   `/.well-known/ii-alternative-origins` at all.

## 2. Constraints imposed by ICRC-167

- The **callback** must be an absolute URL on the relying party origin, declared
  byte-for-byte in `<origin>/.well-known/ii-auth-callbacks` (`application/json`,
  CORS-readable, no redirects, `no-store`, <= 8 KiB, same-origin entries only,
  no fragments). II fails closed on any violation.
- Messages and responses travel in the **fragment**, never in the query, so
  neither the signer's nor the app's server sees them.
- **Deep links** are allowed only when the OS verifies domain ownership
  (Universal Links on Apple, App Links on Android). **Custom URI schemes are
  forbidden** --- their registration is not verified, so any app could claim
  them and intercept a delegation.
- **Desktop has no reliable browser-to-app hand-off.** The standard's prescribed
  pattern is a web page the application controls that runs the flow as an
  ordinary relying party and relays the result to the application over a local
  channel such as a loopback HTTP server (RFC 8252 §7.3).
- A batch is one navigation; a multi-step interaction is several sequential
  navigations. II keeps ICRC-25 permission scopes keyed by relying-party origin,
  so later round-trips do not re-prompt.

## 3. Architecture

```
AuthClient::sign_in (native, desktop)
  |
  |  transport = NativeUrlTransport        (new, src/client/transport/native_url.rs)
  v
Signer (unchanged)  -- ii_session_delegation -->
  |
  v
NativeUrlTransport::send
  1. state := random 32 B, token := random 32 B, journal := {state, request, token}
  2. bind 127.0.0.1:0, open https://<app>/auth/#signer=<url>&message=<json>&state=<s>&port=<p>&token=<t>
  3. browser page -> https://id.ai/authorize#message=...&callback=https://<app>/auth/callback&state=<s>
  4. II -> https://<app>/auth/callback#message=...&state=<s>
  5. page POSTs {state, message} to http://127.0.0.1:<p>/icrc167 (Bearer token)
  6. transport validates state + ids, journals the response, returns it
  |
  v
Signer validates the chain (existing code) -> app delegation mint (existing canister path)
  -> session / state / app slots -> SessionIdentity
```

Building blocks:

| Piece | Where | Notes |
| --- | --- | --- |
| `NativeUrlTransport` | `src/client/transport/native_url.rs` | Implements the existing `Transport`/`Channel` traits; no new protocol layer. Desktop-only (`cfg(target_os = ...)` + `native`). |
| Relay page | `relay/` (new, static) | Three files: `/auth/index.html` (initiator), `/auth/callback.html` (response), `/.well-known/ii-auth-callbacks`. The app deploys them on its own origin; the crate ships the template and a `serve` example. No secrets ever reach the page: it carries a public key and receives a chain. |
| Loopback relay | inside `NativeUrlTransport` | `tiny_http` server on `127.0.0.1:0`, one-shot, token-authenticated, 10 minute deadline. Reuse the `BrowserOpener` seam from `webauth` (`webbrowser` crate). |
| Pending flow | process memory only | `{state, message, token, deadline}` per navigation. A native process is not unloaded the way a page is, so nothing has to survive a reload; a crash abandons the attempt and the caller retries. Persisting it is a later refinement (see §10). |
| `CallbackBroker` | trait next to the transport | `async fn authenticate(&self, url) -> Result<CallbackUrl>`; the desktop default is the loopback relay. Mobile implements it with `ASWebAuthenticationSession` / Custom Tabs, which receive the https callback directly and need no page (see §6). |
| Signer / ceremony | unchanged | `sign_in`'s signer path is reused verbatim; `sign_out` gains the canister revoke it already has on wasm. |

### Relay page contract

The pages are stateless apart from `sessionStorage`:

1. `/auth/` reads `#signer`, `#message`, `#state`, `#callback`, `#port`,
   `#token`, strips the fragment, and refuses a request that is not one
   JSON-RPC object, a signer that is not HTTPS (or loopback), or a callback that
   is not on its own origin. It stores `{port, token}` under one
   `sessionStorage` key and `location.replace`s to
   `<signer>#message=<message>&callback=<callback>&state=<state>`.
2. `/auth/callback` reads `#message` + `#state`, strips the fragment, POSTs
   `{state, message}` to `http://127.0.0.1:<port>/icrc167` with
   `Authorization: Bearer <token>`, and then **long-polls**
   `GET /icrc167/poll` with the same token. Each step has its own random
   `state`; the listener is the authority on which one is in flight (an
   unmatched state is answered `409`), so the page keeps no state chain.
3. The poll answers `{"next":{"signer","message","state","callback"}}` when the
   application has another request for this ceremony (an attribute request, a
   notification consent), and `{"done":true}` when none arrives within the
   application's idle window. On `next` the page navigates the **same tab**
   again; on `done` it removes the attempt and shows "return to the
   application".
4. A load of `/auth/callback` **without** `message` is not a response (II's
   signer-initiated navigation): the page shows the app instead.
5. The listener answers the browser's Private Network Access preflight
   (`Access-Control-Allow-Private-Network: true`), because the relay page is a
   public origin calling a loopback port.
6. **Safari cannot make the cross-scheme POST.** It blocks an https page from
   reading `http://127.0.0.1` (mixed content; Chrome and Firefox treat
   loopback as trustworthy), so the callback page falls back to a *navigation*:
   it `location.replace`s to `http://127.0.0.1:<port>/icrc167/handoff#state=…&message=…&token=…`,
   where the listener serves a page (`src/client/transport/handoff.html`,
   embedded with `include_str!`, token in the fragment, no credentials on the
   GET) that POSTs to its own origin and long-polls for the next step. That
   page is the same protocol with the same-tab continuation, just served from
   loopback; the fetched page is never cached. Verified in Safari 27.2 (two
   steps, one tab).

A page deployed before the hand-off protocol still works: its callback fetch
fails on Safari, so the ceremony stops there and the application times out; on
Chrome and Firefox the fetch succeeds and nothing changes. A page deployed
before the polling protocol answers one request and stays on "done": the
application's idle window expires and the next request opens a fresh tab, which
is the pre-phase-5 behaviour, and also covers a tab the user closed mid
ceremony.

## 4. Public API

Opt-in, native only, additive:

```rust
// client/options.rs
pub struct NativeRelayOptions {
    /// Bare origin that hosts the relay page, e.g. "https://app.example".
    /// The page lives at `<relay_origin>/auth/`, the callback at
    /// `<relay_origin>/auth/callback`, the allow-list at the origin root.
    pub relay_origin: String,
    /// Optional override for a page served from a sub-path.
    pub relay_page: Option<String>,
    /// Optional override for the callback path.
    pub relay_callback: Option<String>,
    /// Whole-navigation deadline; defaults to 600 s.
    pub timeout_ms: Option<u64>,
}

pub struct AuthClientCreateOptions {
    // ... existing fields ...
    /// Native desktop only: sign in over ICRC-167 through this relay page.
    /// Without it the client keeps using the non-browser (CLI) flow.
    pub native_relay: Option<NativeRelayOptions>,
}
```

`NativeRelayOptions` has a `bon` builder, and the field is additive: existing
callers using `..Default::default()` or the builder are unaffected; a struct
literal that names every field has to add `..Default::default()`.

Dispatch: `default_transport` returns `Some(NativeUrlTransport::new(..)?)` when
`native_relay` is set (and `None` otherwise), so the existing
`transport.is_none()` -> `webauth` branch keeps answering for applications
without a relay, and the signer path answers for those with one. No `sign_in`
signature change.

Validation is the transport's, surfaced as `AuthClientError::InvalidOptions`:
insecure or non-bare origins, fragment-bearing signer URLs, unsafe paths, and
the `native_relay` + `TransportMode::Redirect` combination (the redirect mode's
return-load replay has no page journal on native) are all refused at
`AuthClient::new`.

`AuthClient::with_transport` stays the injection point for tests and for mobile
brokers, and it overrides the relay.

UniFFI/mobile: the relay is fixed at client creation and the generated
constructors do not carry it yet, so the UniFFI surface keeps using the
non-browser flow. Mobile delivery (ASWebAuthenticationSession / App Links) is
phase 6, with its own constructor and `CallbackBroker` implementation.

## 5. Rotation and lifecycle on native

The rotation machinery is already platform-neutral: `SessionIdentity` owns the
scheduler seam, the block margin (`BLOCK_MARGIN_MS`, 10 s), the pre-mint
threshold (`PRE_MINT_THRESHOLD_MS`, 15 s), `prepare()` (the asynchronous half of
`ic-agent`'s synchronous `sign`) and `refresh()` (the "somebody is here" hint).
Native even has its own `Scheduler` (a detached thread), and
`foreground_refresh` already documents the native contract: the host calls
`SessionIdentity::refresh()` on window focus / app resume.

Three gaps keep rotation from running on native today:

1. `webauth` installs a plain identity, so there is no `SessionIdentity` to
   rotate. ICRC-167 sign-in goes through `open_session`, which fixes this.
2. Minting an app delegation performs canister calls through `ic_agent` (async
   `reqwest`), which needs a **Tokio reactor**. Native's `mint_blocking` uses
   `futures::executor::block_on` on a bare thread and cannot drive them; the
   path has never run on native because webauth never creates a session
   identity.
3. Signing does not mark the credential used: `current_was_used` is set only by
   `prepare()` and `refresh()`. A session whose app signs without any user
   activity therefore stops rotating after the first mint. wasm hides this
   behind the DOM activity watchers; native has none.

**Decision: rotation works by default through a platform-default `Executor`,
not through a required constructor argument.**

| Role | wasm today | native (this design) |
| --- | --- | --- |
| executor (where a mint future runs) | `spawn_local` (ambient) | crate-owned thread: `current_thread` Tokio runtime + `LocalSet` |
| scheduler (when) | `setTimeout` | detached thread (already implemented) |
| "somebody is here" | DOM watchers wired by the crate | host calls `ClientIdentity::refresh()` on focus/resume (documented today) |
| signing counts as use | missing | set `current_was_used` in the `Identity` implementation (fixes wasm too) |
| on-demand safety net | `prepare()` at bring-up | `get_identity()` / `ready()` call `session.prepare()` |

The seam is an `Executor` trait: `spawn(task)` where `task` is an `FnOnce` that
**builds** the future on the executor's thread. Storage futures are `!Send`, so
only an `Arc<SessionIdentity>` (which *is* `Send + Sync` on native) may cross
the thread boundary; the future is created and polled on the executor's thread.
`SessionIdentityOptions.executor: Option<Arc<dyn Executor>>` lets a test or an
advanced host override the default. `AuthClientCreateOptions` grows no fields,
so applications configure nothing.

Cost: the native feature gains a direct `tokio` dependency (`rt`, `time`, `net`;
reqwest already compiles Tokio, so the incremental cost is the runtime feature
and one thread per process, shared by every session).

**Implemented (phase 4):** `platform::{Executor, ExecutorTask, spawn}` with
`WasmExecutor` (`spawn_local`) and `NativeExecutor` (one worker thread running a
`current_thread` runtime and a `LocalSet`); `SessionIdentity` spawns its mints
through it; `held_for_signing` marks the credential used, so signing keeps the
rotation alive; `get_identity()` prepares the session on demand; and the
session-gone record transition now runs on native too, through the same
executor.

Consequences:

- The session-gone record half (`auth_client.rs`'s `spawn_background`) can now
  run on native too --- the executor is exactly the missing piece --- so the
  on-gone listener records `expired` / drops the credential as wasm does.
- `sign_out` takes the browser shape: read the session credential, revoke the
  app session through the canister, end the session, install anonymous.
  `webauth` keeps its local-only sign-out.
- If a target cannot run the default executor, the crate still functions:
  `get_identity()` prepares on demand and the host calls `refresh()`; background
  pre-mint is an optimisation, not a requirement.

## 6. Platform matrix

| Platform | Transport | Sign-in | Notes |
| --- | --- | --- | --- |
| Browser (`wasm-js`) | ICRC-29 window / ICRC-167 redirect | unchanged | Not touched. |
| Desktop with `native_relay` | ICRC-167 via relay page | new | Primary native path. Chrome/Edge/Firefox report over loopback fetch; Safari hands off by navigating to a listener-served page (§3, item 6). |
| Desktop without `native_relay` | `webauth` (II CLI flow) | unchanged | Fallback; needs the user's CLI-access toggle when deriving. |
| iOS / macOS app | ICRC-167 via `ASWebAuthenticationSession` (`Callback.https` + associated domains) | stage 5 | Direct deep link, no relay page or loopback. |
| Android | ICRC-167 via Custom Tabs + App Links | stage 5 | Same shape as iOS. |

Mobile therefore does **not** need the relay page: it implements
`CallbackBroker` directly. The relay page exists only because desktop browsers
have no verified hand-off.

## 7. Security model

- **No secrets in the relay.** The page carries the session public key and
  receives a delegation chain. The private key never leaves the native process,
  so a compromised page or a logged URL leaks nothing usable. This is stricter
  than the browser path, where the session key lives in browser storage.
- **Loopback is token-gated.** The token is 32 random bytes, carried only in the
  fragment (never sent to either server), required as a bearer header, and the
  listener binds `127.0.0.1` with one request accepted before it closes. A local
  process that guesses the port still needs the token.
- **State is single-use.** 32 random bytes, persisted in the journal, matched
  byte-for-byte on the callback, cleared when the result is accepted. The
  journal expires after the flow timeout and is not replayed.
- **Response validation** stays where it is: `parse_session_delegation` checks
  the leaf key, IDs are correlated, and the chain validation happens before
  anything is stored. The relay cannot widen scope; the signer decides it.
- **Allow-list + derivation are II's checks**, not ours: the app origin must
  serve `/.well-known/ii-auth-callbacks`, and (only when a shared domain is used)
  the derivation origin must name the relay origin in
  `/.well-known/ii-alternative-origins`.
- **No custom schemes**, per the standard. The relay page is ordinary https.
- **Fragment hygiene**: both pages strip the fragment with
  `history.replaceState` before doing anything else.

## 8. Testing strategy

1. **Rust unit tests** for the relay state machine with a fake broker: one
   navigation per request, state/ID checks, journal expiry, duplicate callback,
   missing/extra fields, token mismatch, timeout.
2. **Protocol regression**: keep `probes/icrc167` as the executable contract
   (`node --test` + headless-Chrome self-test against the fake signer). Its
   findings table (§1) is the expected behaviour of id.ai.
3. **Native integration test** (not CI): `examples/icrc167-relay` starts the
   transport against `probes/icrc167/serve.mjs --fake-signer`, with a scripted
   page poster standing in for the browser; assert the transport returns the
   canned chain and that a second `send` opens a second navigation.
4. **Manual checklist against real II** (documented, run at release): sign in
   through the relay page, assert the principal equals the browser sign-in's,
   mint a delegation, revoke on sign-out, restart and restore.

## 9. Phases

| Phase | Deliverable | Acceptance |
| --- | --- | --- |
| 1 | `NativeUrlTransport` + loopback relay + journal + unit tests (fake broker) | one navigation per `send`; state/ID/token/expiry covered |
| 2 | `NativeRelayOptions`, `default_transport` wiring, UniFFI record | `sign_in` reaches the transport; without options it still uses `webauth` |
| 3 | Relay page template (`relay/`) + `examples/icrc167-relay` + docs | end-to-end against fake signer in a headless browser |
| 4 | Rotation on native: `Executor` seam with platform defaults, `current_was_used` fix in the `Identity` implementation, `prepare()` in `get_identity`, `ClientIdentity::refresh()` passthrough, native `sign_out` revoke | native rotates like wasm (default executor), an app that calls `refresh()` keeps it alive, revoke on sign-out |
| 5 | Multi-step loopback protocol (attributes, notification consent) + browser-compatibility hand-off | two round-trips through one browser tab, in Chrome, Firefox and Safari |
| 6 | Mobile `CallbackBroker` (Swift/Kotlin over UniFFI) | device flow with `ASWebAuthenticationSession` / Custom Tabs |

Phases 1--5 are implemented: the transport, the `native_relay` option, the
deployable pages in [`relay/`](../../relay/README.md) with a headless-browser
self-test (`relay/selftest.py`, 7 checks, including the Safari hand-off) and
[`examples/rust/native-icrc167`](../../examples/rust/native-icrc167/README.md),
native rotation through a platform executor (§5), and the long-poll continuation
that keeps one browser tab for a multi-step ceremony (§3). Browser behaviour was
measured on 2026-11-15: Chrome 157 (self-test), Firefox 158.0.1 (loopback fetch
works, two steps in one tab), Safari 27.2 (fetch blocked as mixed content; the
hand-off page completes the same two steps). Phase 6 (mobile delivery) is next.

## 10. Decisions and remaining questions

Resolved:

- **Relay page distribution**: the application deploys the template on its own
  origin. A shared domain is rejected: it changes the relying-party origin (and
  therefore the principal unless every app publishes
  `/.well-known/ii-alternative-origins` for it) and makes Internet Identity's
  consent screen name a domain the user has no reason to recognise.
- **Rotation**: platform-default `Executor` (wasm `spawn_local`, native
  dedicated thread + `current_thread` Tokio runtime + `LocalSet`), overlappable
  per session for tests and advanced hosts. On-demand `prepare()` and
  host-driven `refresh()` remain the fallback contract. See §5.
- **Pending flow storage**: memory only in v1 (a native process is not unloaded
  like a page). If crash recovery is ever wanted, use a dedicated state-storage
  key holding a **token hash** and a short TTL; never the bearer token itself.

Remaining:

- **Relay page reference copy**: ship only the template + docs, or also a
  deployable example under `examples/`? The template is two static files, so the
  example is cheap; the docs must still say "deploy on your own origin".
- **Windows first run**: a loopback listener can trigger a firewall prompt; the
  README should describe what an app author will see.
- **Mobile API**: whether `CallbackBroker` is implemented in Swift/Kotlin and
  handed in over UniFFI, or the crate owns a small platform module (the former
  keeps this crate platform-neutral).
- **`return_to`**: `webauth` has no equivalent; the native transport should
  ignore it rather than error, and the relay page can simply show a "return to
  the application" state.
