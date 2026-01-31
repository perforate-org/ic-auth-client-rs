# AuthClient + gpui Todo Example

This example uses `gpui` and `gpui-component` to build a simple Todo app backed
by the Internet Computer.

## Requirements

- Rust toolchain
- `dfx` running locally for the backend/II integration canisters
- Node.js (needed to build `ii-integration`)

## Running Locally

1. Start a local replica and deploy the example canisters from `examples/gpui`:
   ```bash
   dfx start --background
   dfx deploy
   ```
2. Build the Internet Identity integration assets (only needed when they change):
   ```bash
   npm --prefix ../../ii-integration install
   npm --prefix ../../ii-integration run build
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
