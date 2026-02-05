# @perforate/ic-auth-bridge

Helpers for bridging Internet Identity (II) auth from a browser window to a native
callback endpoint. Designed for native apps using
[`ic-auth-client`](https://crates.io/crates/ic-auth-client).

## Install

```sh
npm install @perforate/ic-auth-bridge
```

## Usage

```ts
import {
  parseParams,
  createAuthClient,
  startLogin,
} from "@perforate/ic-auth-bridge";

// In your II popup/window (opened by your native app)
const params = parseParams(window.location.href);
const client = await createAuthClient(params);
startLogin(client, params.redirectUri);
```

The helper will attempt to POST a JSON payload to `redirectUri`. If the POST
fails, it falls back to redirecting with a `payload` query parameter.

### Success and error hooks

You can optionally receive success/error callbacks in the popup to update UI.

```ts
startLogin(client, params.redirectUri, undefined, {
  onSuccess: () => {
    // e.g. show "You can close this tab" message
  },
  onError: (error) => {
    console.error("Login failed", error);
  },
});
```

### End-to-end flow

1. Your native app calls `NativeAuthClient.login`.
2. It opens a popup/window to Internet Identity.
3. In that window, run the code above to complete auth.
4. The helper posts the result back to the native app callback.

### Minimal integration checklist

- The native app provides the popup URL (from `NativeAuthClient.login`).
- The popup page loads `@perforate/ic-auth-bridge` and runs the snippet.
- The callback endpoint in your native app is ready to receive the POST.

### Error handling

`startLogin` reports errors through the same callback. If a POST fails, the
helper falls back to redirecting with a `payload` query parameter.

## License

This project is licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT License](./LICENSE-MIT) at your option.
