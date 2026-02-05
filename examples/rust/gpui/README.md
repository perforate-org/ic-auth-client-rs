# AuthClient + gpui Todo Example

This example uses `gpui` and `gpui-component` to build a simple Todo app backed
by the Internet Computer.

## Requirements

- Rust toolchain
- `dfx` running locally for the backend/II bridge canisters
- Node.js (needed to build `ii-bridge`)

## Running Locally

1. Start a local replica and deploy the example canisters from `examples/gpui`:
   ```bash
   dfx start --background
   dfx deploy
   ```
2. Build the Internet Identity bridge assets (only needed when they change):
   ```bash
   npm --prefix ../../ii-bridge install
   npm --prefix ../../ii-bridge run build
   ```
3. Launch the gpui client:
   ```bash
   cargo run -p frontend
   ```
   The app window will show a login button. Clicking “Log in with II” opens
   Internet Identity; after authenticating, your Todo list is loaded.

## Notes

- Backend canister stores per-user todos and filters by caller.
- Enable verbose logs via `RUST_LOG="frontend=debug,ic_auth_client=trace"` when
  troubleshooting login callbacks.
