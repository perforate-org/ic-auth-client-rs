//! Signing a native application in over ICRC-167 through its own relay page.
//!
//! The pages live in [`relay/`](../../../relay/README.md); deploy them on the
//! application's public HTTPS origin first. Then:
//!
//! ```text
//! IC_AUTH_RELAY_ORIGIN=https://app.example cargo run
//! ```
//!
//! Against the local fake signer from the probe (no Internet Identity):
//!
//! ```text
//! node probes/icrc167/serve.mjs --port 8787 --fake-signer --public-origin http://127.0.0.1:8787
//! IC_AUTH_RELAY_ORIGIN=http://127.0.0.1:8787 \
//! IC_AUTH_SIGNER_URL=http://127.0.0.1:8787/fake-signer \
//! IC_AUTH_STATE_DIR=/tmp/native-icrc167 \
//! cargo run
//! ```
//!
//! (The probe's `serve.mjs` serves the probe pages, not `relay/`; point
//! `IC_AUTH_RELAY_ORIGIN` at a host serving `relay/` for a real run.)

use std::sync::Arc;

use ic_auth_client::client::{
    AuthClient, AuthClientCreateOptions, IdentityProvider, NativeCredentialStorage,
    NativeRelayOptions, NativeStateStorage,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay_origin = std::env::var("IC_AUTH_RELAY_ORIGIN").map_err(|_| {
        "set IC_AUTH_RELAY_ORIGIN to the public origin hosting relay/ (e.g. https://app.example)"
    })?;
    let state_directory =
        std::env::var("IC_AUTH_STATE_DIR").unwrap_or_else(|_| "native-icrc167-state".to_string());

    let mut options = AuthClientCreateOptions {
        credential_storage: Some(Arc::new(NativeCredentialStorage::keyring(
            "native-icrc167-example",
        ))),
        state_storage: Some(Arc::new(NativeStateStorage::new(&state_directory)?)),
        native_relay: Some(NativeRelayOptions {
            relay_origin,
            ..Default::default()
        }),
        ..Default::default()
    };

    // A local signer (the probe's fake one) answers on a different URL.
    if let Ok(signer) = std::env::var("IC_AUTH_SIGNER_URL") {
        options.identity_provider = Some(IdentityProvider {
            authorize_url: signer,
            ..IdentityProvider::default()
        });
    }

    let client = AuthClient::new(options)?;
    if client.is_authenticated() {
        println!("restoring the stored sign-in");
    }

    let identity = client.sign_in(Default::default()).await?;
    println!("signed in as {}", identity.principal());
    if let Some(expires) = identity.delegation_expires_at_ms() {
        println!("the delegation expires at {expires} ms since the Unix epoch");
    }

    if std::env::var("IC_AUTH_SIGN_OUT").is_ok() {
        client.sign_out(Default::default()).await?;
        println!("signed out");
    }
    Ok(())
}
