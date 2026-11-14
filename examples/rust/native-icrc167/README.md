# native-icrc167

A minimal native sign-in over the ICRC-167 relay pages in
[`relay/`](../../../relay/README.md).

1. Deploy `relay/` on the application's public HTTPS origin and replace the
   placeholder in `relay/.well-known/ii-auth-callbacks` with that origin.
2. Run against Internet Identity:

   ```bash
   IC_AUTH_RELAY_ORIGIN=https://app.example cargo run
   ```

   The signed-in principal is the same one the application's web sign-in gets,
   because the relay origin is the relying-party origin.

3. Persist the sign-in across restarts by pointing `IC_AUTH_STATE_DIR` at a
   directory (the credentials go to the OS keyring); set `IC_AUTH_SIGN_OUT=1` to
   revoke the app session on the way out.

`IC_AUTH_SIGNER_URL` overrides the signer URL, for a testnet or a local fake
signer. It is not needed against Internet Identity.

Without `native_relay` the crate falls back to the identity provider's
non-browser flow, which needs no domain but asks the user to enable CLI access.
