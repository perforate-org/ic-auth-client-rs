//! App delegations minted from the Internet Identity canister.
//!
//! Port of upstream `src/client/session/`. The session layer is what v9
//! introduced: a sign-in is a session rooted at the identity provider, from
//! which this client mints the app delegation it signs requests with.
//!
//! ```text
//! account key (II-side; never leaves II)
//!   └── session chain  ── delegated to the client's session key, restricted to II
//!         └── app delegation ── delegated to the app key, rooted at the account key
//!               └── what an HttpAgent signs with
//! ```
//!
//! - [`identity`] --- an identity that replaces its own delegation as it ages
//! - [`minter`] --- mints app delegations from the Internet Identity canister
//! - [`delegation`] --- requests a session delegation from the signer
//! - [`app_lock`] --- the cross-tab locks a ceremony and a mint take
//! - [`app_delegation_source`] --- where a session's app delegations come from
//!
//! # The seam
//!
//! The session layer is transport-agnostic once an
//! [`AppDelegationSource`](app_delegation_source::AppDelegationSource) is
//! injected: the identity decides *when* to mint, the source decides *how*. The
//! same identity serves `wasm-js` and `native`; only the source differs.

pub mod app_delegation_source;
pub mod app_lock;
pub mod delegation;
pub mod identity;
pub mod minter;
pub(crate) mod record;

#[cfg(test)]
pub(crate) mod test_support;

pub use app_delegation_source::{
    AccountMismatchError, AppDelegationSource, Held, NoSuchDelegationError, SessionError,
    SessionGoneError, SessionUnsupportedError, account_of, chain_authorises_key, delegates_to,
    earliest_expiration_ns, expires_at_ms, is_for_account, ms_left, same_key,
};
#[cfg(feature = "native")]
pub use app_lock::InProcessLockManager;
#[cfg(feature = "wasm-js")]
pub use app_lock::WebLocks;
pub use app_lock::{
    HeldLock, LockManager, MintWork, NoopLockManager, StealSignal, default_lock_manager,
    steal_lock, steal_mint_lock, with_mint_lock,
};
pub use identity::{
    BLOCK_MARGIN_MS, Clock, CredentialPredicate, PRE_MINT_THRESHOLD_MS, PlatformScheduler,
    ScheduledTask, Scheduler, SessionIdentity, SessionIdentityCreateOptions,
    SessionIdentityOptions, SystemClock, default_clock, default_scheduler,
};
pub use minter::{
    AppResult, AppSessionError, CandidDelegation, GetDelegationArgs, PrepareDelegationArgs,
    PreparedDelegation, SessionMinter, SessionService, SignedAppDelegation, app_delegation_chain,
    assert_chain_reaches, unwrap_session_result,
};

/// The canister methods this crate calls on Internet Identity.
///
/// Port of the small hand-written Candid interface upstream carries in
/// `session/session-minter.ts:18-45` rather than generating the whole
/// Internet Identity interface for three methods.
pub(crate) const II_SESSION_PREPARE_METHOD: &str = "app_prepare_delegation";
/// The canister method that signs an app delegation for a prepared session.
pub(crate) const II_SESSION_GET_DELEGATION_METHOD: &str = "app_get_delegation";
/// The canister method that revokes this session.
pub(crate) const II_SESSION_REVOKE_METHOD: &str = "app_revoke_session";
