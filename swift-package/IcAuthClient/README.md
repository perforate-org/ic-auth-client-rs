# IcAuthClient (Swift Package)

Swift Package Manager wrapper for the UniFFI-generated Swift bindings of
`ic-auth-client`. This package includes:

- `IcAuthClient` Swift target (generated bindings + hand-written helpers).
- `IcAuthClientFFI` binary target (xcframework built from Rust).

## Usage

### Add as a Swift Package

This repository is a Swift Package. Add it by URL and import `IcAuthClient`:

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/perforate-org/ic-auth-client-rs.git", from: "X.Y.Z")
]
```

```swift
// target dependencies
dependencies: [
    .product(name: "IcAuthClient", package: "IcAuthClient")
]
```

### Basic Usage

Basic usage (macOS / iOS):

```swift
import IcAuthClient

let client = try AuthClient(serviceName: "my-app")

let options = LoginOptions(
    identityProvider: nil,
    maxTimeToLive: nil,
    allowPinAuthentication: nil,
    derivationOrigin: nil,
    windowOpenerFeatures: nil,
    timeoutMillis: nil,
    customValuesJson: nil
)

let loginUrl = try client.buildLoginUrl(
    authBridgeUrl: "https://<ii-bridge-canister>.ic0.app",
    redirectUri: "myapp://auth",
    options: options
)
```

On iOS/macOS, `AuthSession` opens the default browser.
`AuthSession` is `@MainActor`, so call it on the main thread:

```swift
let session = AuthSession(client: client)
session.login(
    authBridgeUrl: "https://<ii-bridge-canister>.ic0.app",
    redirectUri: "myapp://auth",
    options: options
) { result in
    // handle result
}
```

Keep the `AuthSession` instance alive until the login completes, since it holds
pending state internally.

Forward the callback URL back to the session
so it can finish the login:

```swift
// e.g. in a SwiftUI view
.onOpenURL { url in
    session.handleCallbackUrl(url)
}
```

`handleCallbackUrl(_:)` returns `true` if the URL was handled and the login
completed, otherwise `false`.

On macOS, if you use an `NSApplicationDelegate`, also forward URLs from
`application(_:open:)` to the same handler:

```swift
final class AppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            session.handleCallbackUrl(url)
        }
    }
}
```

Make sure the URL scheme in `redirectUri` is registered by your app
(Info.plist `CFBundleURLTypes`). The scheme can be any custom value (for example
`myapp://auth`), but it must match your app’s registered URL schemes exactly.
If it isn’t registered, the browser can’t redirect back to your app and the
login will fail.

In the browser, you may also see console warnings about CORS or `fetch` failing
for the custom scheme; the bridge falls back to a redirect with a `payload`
query parameter, so the redirect must be allowed for the flow to complete.

## Desktop-only login

`AuthClient.login(authBridgeUrl:options:)` starts a desktop login flow using
a local callback server. This is supported on macOS/Linux/Windows and is not
available on iOS (the Swift API is marked unavailable on iOS and will fail to
compile). On iOS/macOS app targets, prefer `AuthSession`.

## LoginOptions notes

- `maxTimeToLive` is in nanoseconds.
- `timeoutMillis` is in milliseconds.
- `windowOpenerFeatures` applies to desktop browser flows.
- `customValuesJson` must be a JSON object string.

## IcpKit delegated identity

The package includes helpers to bridge to IcpKit:

```swift
let delegated = try client.icpDelegatedIdentity()
```

This parses the delegation chain JSON from the underlying identity and returns
an `ICPDelegatedIdentity`.

## Notes

- The default key type for Swift `init(serviceName:)` is `Secp256k1`.
  You can check the runtime value with `baseKeyType()`.

- For local development, you can mock `Keychain` before creating the client.
  On Apple platforms this is an alias of `enableKeyringMock()`:

```swift
import IcAuthClient

enableKeychainMock() // for local development
let client = try AuthClient(serviceName: "my-app")
```

## Development

### Requirements

- macOS 13+ / iOS 16+
- Xcode 15+ (Swift tools 5.9)

### Build the xcframework

From the repo root:

```sh
swift-package/IcAuthClient/build_all.sh
```

This does:

1. `./uniffi/generate_swift.sh` to generate Swift bindings.
2. `sync_uniffi_swift.sh` to sync generated Swift into `Sources/IcAuthClient`.
3. `build_xcframework.sh` to build `IcAuthClientFFI.xcframework`.

### Run tests

```sh
cd swift-package/IcAuthClient
swift test
```

The integration test uses keyring storage and clears the test service
name before and after the run.

- If you need to regenerate bindings or rebuild the xcframework, use
  `build_all.sh`.
