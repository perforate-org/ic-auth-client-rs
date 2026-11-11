# Examples

**Status: these examples target the pre-v11 (`0.5.x`) API and are being ported.**

The crate is now v11-only: the old `AuthClient::builder()`/`login()` surface,
`NativeAuthClient` and `IdleManager` were removed (see the `Removed` section of
the [changelog](../CHANGELOG.md)). The example applications below still call that
removed API, so they do not build against the current crate:

| Example | What it needs for the port |
| ------- | -------------------------- |
| `rust/leptos` | `AuthClient::new(options)`, `sign_in`/`sign_out`, `SessionStatus` + `subscribe` instead of `IdleManager` |
| `rust/dioxus` | same as `leptos` |
| `rust/tauri` | same, plus the native sign-in now uses Internet Identity's non-browser flow (no `ii-bridge`) |
| `rust/bevy` | same as `tauri`; drop its local `ii-bridge/` copy |
| `rust/gpui` | same as `tauri`; drop its local `ii-bridge/` copy |
| `swift/AuthSessionUI` | the Swift package's hand-written `AuthSession` still drives the removed bridge flow |

They are not built by this repository's CI (`make check-*` / `make test-*` cover
the crate), so they do not block the crate's verification. Porting them is
tracked as follow-up work; the current API they should call is documented in the
[root README](../README.md) and the crate documentation.

`ii-bridge/` at the repository root has been deleted: the v11 client signs in on
native through Internet Identity's own non-browser flow
(discovery at `/.well-known/cli-auth-config`, loopback callback, form POST), so a
hosted bridge page is no longer needed. The copies under
`examples/rust/{bevy,gpui}/ii-bridge/` are leftovers from the v5 examples.
