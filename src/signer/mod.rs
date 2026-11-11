//! The signer protocol (port of `@icp-sdk/signer` 6.1.0).
//!
//! `@icp-sdk/auth` v11.2.0 delegates every signer interaction to
//! `@icp-sdk/signer`: it constructs one `Signer` with a `Transport`, issues
//! JSON-RPC requests over the channel the transport establishes, and closes the
//! channel when the ceremony ends (`auth-client.ts:572-582,813,887,1216`;
//! `session/session-delegation.ts:109`; `notification-consent.ts:67`). This
//! module is that layer, on top of the transport seam in
//! [`crate::client::transport`].
//!
//! # What is here
//!
//! - [`Signer`] --- one client for one signer: channel caching, request
//!   correlation and result decoding.
//! - The three methods the auth client sends: `ii_session_delegation`,
//!   `ii-icrc3-attributes` and `ii_notification_consent`, with their exact
//!   params encoding and result validation.
//! - The ICRC-25/29 method name constants upstream uses elsewhere
//!   (`icrc25_*`, `icrc27_accounts`, `icrc34_delegation`, `icrc49_call_canister`,
//!   `icrc29_status`), so the names never have to be guessed twice.
//! - `test_utils` --- a fake transport/channel pair, for this crate's tests
//!   and the hidden `wasm-compat-test` feature.
//!
//! # What is deliberately not here
//!
//! Upstream's typed convenience helpers (`getSupportedStandards`,
//! `requestPermissions`, `getAccounts`, `requestDelegation`, `callCanister`) are
//! not ported: the auth client never calls them, and upstream itself notes the
//! auth flows use raw `sendRequest` only. There is likewise no implicit
//! permission handshake --- `Signer` sends nothing before the caller's request.
//! The ICRC-29 `icrc29_status` heartbeat lives in the window transport's channel
//! establishment, not in this layer.
//!
//! # Wire formats worth pinning
//!
//! - Binary values (DER public keys, signatures, nonces, attributes) are
//!   **standard padded base64** (`signer.ts:16-35`, `@icp-sdk/auth`
//!   `base64.ts`). Hex is only this crate's *storage* compatibility format.
//! - Every nanosecond value (delegation expirations, TTLs) is a **decimal
//!   string**: a JSON number that large has already lost precision.
//! - The derivation origin travels as **`icrc95DerivationOrigin`** in
//!   `params`, on every request when the signer was built with one
//!   (`signer.ts:125-139`).

mod client;
mod protocol;

#[cfg(any(test, feature = "wasm-compat-test"))]
pub mod test_utils;

pub use client::{AttributeRequest, SessionDelegationParams, Signer, SignerOptions};
pub use protocol::{
    ATTRIBUTES_METHOD, ICRC25_PERMISSIONS_METHOD, ICRC25_REQUEST_PERMISSIONS_METHOD,
    ICRC25_SUPPORTED_STANDARDS_METHOD, ICRC27_ACCOUNTS_METHOD, ICRC29_STATUS_METHOD,
    ICRC34_DELEGATION_METHOD, ICRC49_CALL_CANISTER_METHOD, NOTIFICATION_CONSENT_METHOD,
    SESSION_DELEGATION_METHOD,
};
