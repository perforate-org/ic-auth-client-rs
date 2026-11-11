# Upstream v11.2.0 — Idle / Foreground / Activity Specification (for the Rust port)

Upstream: `/tmp/icp-js-auth` at `@icp-sdk/auth` **11.2.0**.
Sources: `src/client/foreground-refresh.ts`, `src/client/auth-client.ts`,
`src/client/session/session-identity.ts`, `tests/client/foreground-refresh.test.ts`,
`tests/client/auth-client.test.ts`, `docs/src/content/docs/upgrading/v9.md:59-70`.
Rust comparison: `src/idle_manager/*.rs`, `src/auth_client/{wasm_js,native}.rs`, `src/option.rs`.

---

## 1. The headline change: the idle manager is gone (v9)

`docs/.../v9.md:59-70`:

> `IdleManager` has been removed along with everything that configured it: `idleOptions`,
> `onIdle`, `idleTimeout`, `captureScroll` and `disableIdle`. A timer watching the mouse in one tab
> was only ever a guess at whether the user was still there, and it could not end a session that
> other tabs, or other subdomains, were still using.
>
> The session is now bounded where it is issued. The identity provider ends it once it has gone
> unused for `maxTimeToIdle`, and it cannot outlive `maxTimeToLive`; both are sign-in options, and
> both are optional. Leaving them unset means the provider's own defaults, currently seven days of
> idleness and thirty days in total.

Consequences for the port:

- There is **no idle timer in v11**. `watchActivity` / `watchForeground` do the *opposite* of the
  old idle manager: their callbacks are used to **keep a session alive** (refresh the app
  delegation) when a human is present, not to end it when they are absent.
- An idle-out is observed as an `expired` status when the state record's expiry passes, or as a
  `SessionGoneError` when a mint is refused (`session-layer.md` §6.4).
- `maxTimeToIdle` / `maxTimeToLive` are **sign-in options** (nanoseconds) sent to the provider
  (`auth-client.ts:279-293`, `:984-988`); the client invents no bounds of its own
  (`auth-client.test.ts:653-665`).

## 2. `watchForeground` — exact behaviour

`src/client/foreground-refresh.ts:17-47`.

| Aspect | Value |
|---|---|
| Events | `document.visibilitychange` (fires only when `document.visibilityState === 'visible'`), `globalThis.focus`, `globalThis.pageshow` |
| Guards | returns `undefined` (hooks nothing) unless `document`, `document.addEventListener`, `document.removeEventListener`, `globalThis.addEventListener`, `globalThis.removeEventListener` are all present — a partial DOM polyfill must not throw (`:21-29`) |
| Debounce/throttle | **none** in the watcher |
| Return | unsubscribe function, or `undefined` when nothing was hooked |
| Why focus | catches two visible windows side by side, where moving between them is not a visibility change (`:36-38`) |
| Why pageshow | catches a page restored from the back-forward cache, which resumes with timers that never ran (`:37-38`) |
| Why at all | a backgrounded tab has its timers throttled, so a scheduled refresh may not run and the delegation lapses; returning to the tab happens a second or two before the next click — room enough to mint (`:9-13`) |

Whether a mint is actually due is **not decided here** (`:12`, `:60-63`).

Tests (`foreground-refresh.test.ts:13-77`): fires on visible, ignores hidden, fires on focus and
pageshow, stops after unhook, hooks nothing with no `document`, hooks nothing with a `document`
that has no event methods.

## 3. `watchActivity` — exact behaviour

`src/client/foreground-refresh.ts:49-92`.

Event list, verbatim (`:53`):

```ts
const ACTIVITY_EVENTS = ['pointerdown', 'mousedown', 'mousemove', 'keydown', 'touchstart', 'wheel'];
```

| Aspect | Value |
|---|---|
| Listener options | `{ passive: true }` — these never `preventDefault`, and saying so keeps `mousemove`/`wheel` off the scroll-start path (`:81-85`) |
| Debounce/throttle | **none** in the watcher; every event calls back. Test explicitly asserts three events → three calls, "leaving the throttle to the identity" (`foreground-refresh.test.ts:93-103`) |
| Guards | `document` + `addEventListener`/`removeEventListener` present, else `undefined` (`:73-79`) |
| Unsubscribe | removes every event listener (`:87-91`) |
| Why `pointerdown` | covers mouse, finger and pen in one — the only press event a phone reliably produces (`:49-52`) |
| What it means | "this page is in front of a person right now", from the activity direction (`:55-63`) |

Tests (`foreground-refresh.test.ts:79-137`): each of the six events fires; every event fires (no
throttle); `scroll` and `visibilitychange` do **not** fire; unhook stops; no DOM ⇒ `undefined`;
partial DOM ⇒ `undefined`.

## 4. How `AuthClient` wires the watchers

`auth-client.ts:460-471` (constructor):

```ts
if (!options.disableBrowserActivity) {
  const refresh = () => { void this.#refreshInForeground(); };
  this.#unwatchForeground = watchForeground(refresh);
  this.#unwatchActivity  = watchActivity(refresh);
}
```

- Both watchers call the **same** `refresh` — "the page arriving and the user using it are the
  same claim — somebody is here — so both trigger the same refresh and one option governs both"
  (`:464-465`).
- `disableBrowserActivity` (`auth-client.ts:104-120`) turns **all** of them off together. Default
  `false`. Setting it makes requests the only thing that says the session is in use — including to
  the identity provider, which ends a session nothing has minted from for long enough.
- The **state subscription is hooked regardless** of `disableBrowserActivity`, because it is not a
  refresh: a client answering for a sign-in the record no longer names is wrong rather than stale
  (`auth-client.ts:473-479`).

`#refreshInForeground` (`auth-client.ts:1460-1468`):

```
if (#interactions > 0 || #refreshingInForeground) return;
#refreshingInForeground = true;
try { await #refreshIfDue(); } finally { #refreshingInForeground = false; }
```

- `#interactions > 0` stands it down during a ceremony: a ceremony backgrounds the tab and
  foregrounds it again on its way back, so without this the return would refresh an identity the
  sign-in is in the middle of replacing (`auth-client.ts:937-942`).
- `#refreshingInForeground` coalesces a burst of `mousemove` events: one at a time is enough, and
  the next event finds a fresher answer than the one in flight (`auth-client.ts:397-401`).

`#refreshIfDue` (`auth-client.ts:1470-1488`):

1. `await #init()` — waited for, not raced: a `pageshow`/pointer arriving before restore would find
   an anonymous identity and spend the moment (`:1471-1479`); a restore failure is swallowed here
   (nothing is waiting on this path) (`:1480-1485`).
2. Re-check `#interactions > 0` (a ceremony can start while the restore resolves) (`:1486`).
3. `if (identity instanceof SessionIdentity) await identity.refresh().catch(() => undefined)` —
   silent by design (`:1487-1488`, `:1456-1459`).

### Throttling actually lives in the identity

`SessionIdentity.refresh()` (`session-identity.ts:345-365`) → `#refreshIfDue`
(`:367-380`): if the current credential has more than `PRE_MINT_THRESHOLD_MS = 15s` left, it does
nothing. So a resting hand costs at most one mint per refresh interval (`foreground-refresh.ts:58-63`).
`refresh()` also marks the credential **used**, which earns it the next scheduled rotation — that is
what keeps a session alive for a user who is reading rather than clicking (`:345-359`).

Tests (`auth-client.test.ts`):

| Test | Assertion | Line |
|---|---|---|
| `mints when the tab comes back, if one is due` | foreground event triggers a mint when due | `:1783-1802` |
| `mints when the user does something, if one is due` | activity event does the same | `:1803-1827` |
| `mints once for a burst of activity, not once per event` | coalescing | `:1995-2027` |
| `does not refresh the identity a ceremony is in the middle of replacing` | `#interactions` guard | `:2028-2057` |
| `costs nothing to glance at a tab whose delegation is healthy` | no mint when > threshold | `:2124-2136` |
| `hooks nothing when foreground refresh is turned off` | `disableBrowserActivity` | `:2137-2157` |

## 5. Current Rust implementation and what must change

### 5.1 Current `IdleManager` (v5-era model)

| Piece | Location | Behaviour |
|---|---|---|
| Public API | `src/idle_manager.rs:76-218` | `IdleManager::new(options)`, `reset_timer()`, `register_callback(fn)`, `exit()`; `IdleManagerOptions { on_idle, idle_timeout: Option<u32>, capture_scroll: Option<bool>, scroll_debounce: Option<u32> }` |
| Defaults | `idle_manager.rs:89-94` | `DEFAULT_IDLE_TIMEOUT = 10 * 60 * 1000` ms; `DEFAULT_SCROLL_DEBOUNCE = 100` ms |
| wasm events | `src/idle_manager/wasm_js.rs:12-19` | `["load", "mousedown", "mousemove", "keydown", "touchstart", "wheel"]` on `window`; optional `scroll` with debounce (`:126-143`) |
| wasm timeout | `wasm_js.rs:112-124`, `:140-160` | every event resets a `setTimeout`; on fire it runs the callbacks |
| native | `src/idle_manager/native.rs:21-88` | `rdev::listen` OS-level events + `futures_timer::Delay`; runs callbacks on timeout |
| Client wiring | `src/auth_client/wasm_js.rs:844-858`, `:870-893`, `:1088-1107`; `src/auth_client/native.rs:319-337`, `:365-377`, `:600-618` | created when a chain or identity exists and `disable_idle != true`; default callback = `logout()` (wasm additionally reloads the page, `wasm_js.rs:880-892`) |
| Options | `src/option.rs:59-68` | `IdleOptions { disable_idle, disable_default_idle_callback, idle_manager_options }` |
| Accessor | `src/auth_client/wasm_js.rs:865`, `src/auth_client/native.rs:461` | `idle_manager()` |

This model is the one upstream v9 deleted. It ends the local session on absence and cannot account
for other tabs or subdomains.

### 5.2 Required change (mapping table)

| Upstream v11 concept | Current Rust | Status | Required port action |
|---|---|---|---|
| No idle timer in the client | `IdleManager` created in both clients | **must change** | Remove `IdleManager` from `AuthClient`/`NativeAuthClient` construction; deprecate `IdleOptions`; keep the module only as a legacy/opt-in utility (or drop it in a major) |
| Idle timeout owned by the canister (`maxTimeToIdle`) | `IdleManagerOptions.idle_timeout` | **must change** | Add `max_time_to_idle: Option<u64>` to `AuthClientLoginOptions` and send it in the sign-in request (currently only `max_time_to_live` exists, `src/option.rs:23-24`) |
| `expired` observed from the state record | `is_authenticated()` checks `is_delegation_valid` (`wasm_js.rs:1122-1138`, `native.rs:443-459`) | **partial** | Read status from a state record, not from the delegation; add an `expired` status that still names the principal (`subscriptions-and-status.md`) |
| `watchForeground` | none | **missing** | `wasm-js`: `document.visibilitychange` + `window.focus` + `window.pageshow`; native: window focus events where a window exists, else no-op |
| `watchActivity` | `IdleManager` wasm event list overlaps | **partial** | Add a separate `watch_activity` that only *refreshes*; do not reuse the idle timer. Event list should be `pointerdown, mousedown, mousemove, keydown, touchstart, wheel` (add `pointerdown`, drop `load`) |
| Foreground refresh calls `SessionIdentity.refresh()` | none | **missing** | Needs the rotating `SessionIdentity` (`session-layer.md`) before this can exist |
| `disableBrowserActivity` option | `disable_idle` (different meaning) | **missing** | Add a single flag that disables both watchers; keep `disable_idle` deprecated |
| Coalescing (`#refreshingInForeground`) | none | **missing** | An `AtomicBool`/`Mutex<bool>` guard around the refresh future |
| Stand-down during a ceremony (`#interactions`) | none | **missing** | Counter incremented before the first await of login/sign-in |
| Throttle by pre-mint threshold | none | **missing** | In the rotating identity (15s threshold) |

### 5.3 Native equivalent (design proposal, clearly marked)

Native has no DOM. Options, in order of preference:

1. **No-op + explicit refresh API** (recommended): `watch_foreground` / `watch_activity` are
   `wasm-js`-only; native exposes `AuthClient::refresh_if_due()` for the host app to call on its own
   lifecycle events (window focus, user action, app resume). This matches upstream's
   "nothing is hooked where there is no DOM" rule (`foreground-refresh.ts:21-29`).
2. Reuse `IdleManager`'s native `rdev` listener **only** to emit activity signals (never to log
   out), behind an optional `native-activity` feature. This is heavier and platform-specific;
   mark it experimental.
3. A desktop idle query (`CGEventSourceSecondsSinceLastEventType`, `GetLastInputInfo`, X11 idle)
   is *not* a faithful equivalent of "the page is in front of a person" and should not be the
   default.

The idle **timeout** for native must be the canister's `max_time_to_idle`, not a local timer; a
native session that expires is observed the same way (mint refused / state expiry).

---

## Rust port checklist

- [ ] Delete the `IdleManager` from client construction; add a deprecation path for `IdleOptions`.
- [ ] Add `watch_foreground(cb) -> Option<Unsubscribe>` for `wasm-js`: visibilitychange (visible
      only), focus, pageshow; hook nothing when the DOM APIs are absent.
- [ ] Add `watch_activity(cb) -> Option<Unsubscribe>` for `wasm-js`: the six passive events above;
      no debounce/throttle in the watcher.
- [ ] Add `disable_browser_activity: bool` client option gating both watchers.
- [ ] Wire both watchers to one `refresh_in_foreground()` with an in-flight guard and a
      ceremony counter (`interactions > 0` ⇒ stand down).
- [ ] Implement `SessionIdentity::refresh()` semantics: mint only when
      `ms_left <= 15s`, mark used, swallow errors on this path.
- [ ] Add `max_time_to_idle` (and keep `max_time_to_live`) to login/sign-in options and the
      authorize request; remove any client-invented session bounds.
- [ ] Map session end to an `expired` status (record kept, principal named) and to
      `SessionGoneError` from a refused mint; remove "idle callback logs out" behaviour.
- [ ] Native: no DOM watchers by default; expose `refresh_if_due()` and document the lifecycle
      events the host app should call it on.
- [ ] Port `foreground-refresh.test.ts` as wasm-bindgen-test for the watchers (dispatch synthetic
      events; assert fire/no-fire/unhook/no-DOM).
- [ ] Port the client-level tests: mints on return/activity when due, one mint per burst, no mint
      when healthy, stand-down during a ceremony, hooks nothing when disabled.
