# AuthClient + Bevy Example

This workspace demonstrates how to integrate the Rust
[`ic-auth-client`](https://github.com/wiyota/ic-auth-client-rs/) crate with a
native Bevy application. The gameplay logic borrows pieces of
[bevy-tetris](https://github.com/corbamico/bevy-tetris), adapted specifically
for this Internet Identity example.

## Prerequisites

- [Rust](https://www.rust-lang.org/)
- [IC SDK](https://github.com/dfinity/sdk)
- [Node.js](https://nodejs.org/ja/)

## Running Locally

1. Start a local replica and deploy the example canisters from the repo root:
   ```bash
   dfx start --background
   dfx deploy
   ```
2. Build the Internet Identity integration assets (only needed when they
   change):
   ```bash
   npm install
   ```
3. Launch the Bevy client:
   ```bash
   cargo run
   ```
   The game window will display a login overlay. Clicking “LOGIN” opens
   Internet Identity; after authenticating, the game transitions into play.

### Storage backend

- Keyring (default):
  ```bash
  cargo run -p frontend --features storage-keyring
  ```
- PEM (file-based):
  ```bash
  IC_AUTH_CLIENT_STORAGE=pem \
    IC_AUTH_CLIENT_PEM_DIR=/path/to/pem-store \
    cargo run -p frontend --no-default-features --features storage-pem
  ```
  If `IC_AUTH_CLIENT_PEM_DIR` is not set, the example uses `./pem` relative to
  `examples/bevy/crates/frontend`.
  If both storage features are enabled, `IC_AUTH_CLIENT_STORAGE` selects the
  backend (`keyring` or `pem`).

## Troubleshooting

- Enable verbose logs via `RUST_LOG="frontend=debug,ic_auth_client=trace"` to
  observe every login callback and backend request.
- Keep the browser dev tools open on the II popup to catch serialization or
  postMessage errors during the login flow.

## License

### bevy-tetris

- GPLv3, Copyright by corbamico@163.com
- Assets `digital7mono.ttf`: TrueType Fonts — DIGITAL-7 version 1.02 (by
  Sizenko Alexander, Style-7)

### Scope and compliance notes

- This example includes GPLv3-licensed code adapted from bevy-tetris; as a
  result, this example is distributed under GPLv3. See `LICENSE` and
  `NOTICE.md`.
- When distributing binaries, provide the corresponding source code and the
  GPLv3 license text alongside the distribution.
