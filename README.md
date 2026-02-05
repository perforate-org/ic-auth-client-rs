# ic-auth-client

Port of [@icp-sdk/auth](https://www.npmjs.com/package/@icp-sdk/auth) for the Rust programming language.

This is a crate for developers who build the frontend of applications for Internet Computer using Rust as the primary language.

## Version compatibility for `ic-agent`

The table below shows the compatible versions of `ic-auth-client` for `ic-agent` versions.

| `ic-agent` version | `ic-auth-client` version |
| ------------------ | ------------------------ |
| 0.45.\*            | 0.5.\*                   |
| 0.44.\*            | 0.4.\*                   |
| 0.39.\*            | 0.3.\*                   |
| 0.37.\* or 0.38.\* | 0.1.\* or 0.2.\*         |

## Quick Start

### Web frontend (browser/WebView)

```rust
use ic_auth_client::AuthClient;
```

To get started with auth client, run

```rust
let mut auth_client = AuthClient::builder()
    // any configurations
    .build()
    .await;
```

The auth_client can log in with

```rust
use ic_auth_client::AuthClientLoginOptions;

let options = AuthClientLoginOptions::builder()
    .max_time_to_live(7 * 24 * 60 * 60 * 1000_000_000) // 7 days
    .on_success(|auth_success| {
        // handle success
    })
    .build();

auth_client.login_with_options(options);
```

It opens an [Internet Identity](https://identity.internetcomputer.org) window, saves your delegation to localStorage, and then sets you up with an identity.

Then, you can use that identity to make authenticated calls using the `ic-agent::Agent`.

```rust
let identity = auth_client.identity();

let agent = Agent::builder()
    .with_url(url)
    .with_identity(identity)
    .build()?;
```

---

### Native frontend (non-WebView)

When using Internet Identity in a native frontend that is not a WebView, there are a few differences.

- Using OS-specific APIs instead of WebAPIs via JavaScript.
- Internet Identity issues different credentials for each website, so a website is required for authentication requests.

#### Setup

1. Set `default-features` to `false` and enable the `native` feature and one of `keyring` or `pem`.

```toml
ic-auth-client = { version = "*.*.*", default-features = false, features = ["keyring", "native"] }
```

2. Use "native" constructors.

```rust
use ic_auth_client::NativeAuthClient as AuthClient;

// You need a unique service name that will be used by the OS-native secure store
let auth_client = AuthClient::new("your-app")?;
```

#### Internet Identity flow for native apps

1. Your native app calls `NativeAuthClient::login`, which returns a URL to open in the system browser.
2. That browser page must run a small bridge script that completes II auth and posts the result back to the native callback URL.
3. The native app receives the payload and finishes the login.

For step 2, use [`@perforate/ic-auth-bridge`](https://www.npmjs.com/package/@perforate/ic-auth-bridge) or start from the packaged template in [`ii-bridge/`](https://github.com/perforate-org/ic-auth-client-rs/) (or see the [Bevy](https://bevy.org/) example at [`examples/bevy/`](https://github.com/perforate-org/ic-auth-client-rs/) and copy it into your app or canister frontend. The template already wires the bridge, so you only need to host it and point `NativeAuthClient::login` at it.

## License

This project is licensed under [Apache License, Version 2.0](./LICENSE-APACHE).
