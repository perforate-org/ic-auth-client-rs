//! The record transitions a client makes when a sign-in ends.
//!
//! Port of upstream `#endSession`, `#dropSession`, `#expireSession` and
//! `#endOrDrop` (`auth-client.ts:1577-1621`, `1816-1835`). They live together
//! because they are one policy --- what to publish, what to remove, and what a
//! read-only store gets --- and because two callers need them: the client
//! (`sign_out`, a restore that finds nothing usable) and the session identity's
//! gone listener. Keeping them in one place is what stops the two from drifting.
//!
//! Every function here is a no-op on a read-only store: that store publishes
//! nothing, and writing through it traps on the platform's assert.

use crate::client::credentials::SharedCredentialStorage;
#[cfg(any(feature = "wasm-js", test))]
use crate::client::now::now_ns;
use crate::client::slots::Slots;
use crate::client::state::SharedStateStorage;
#[cfg(any(feature = "wasm-js", test))]
use crate::client::state::StoredSessionState;

/// Removes the record and the credentials: what signing out does.
pub(crate) async fn end_session(
    state: &SharedStateStorage,
    credentials: &SharedCredentialStorage,
    slots: &Slots,
) {
    if state.is_read_only() {
        return;
    }
    state.remove(&slots.state);
    clear_credentials(credentials, slots).await;
}

/// Removes this origin's claim on the record and its credentials: what finding
/// out the session is gone does. A shared record written by a sibling is left
/// alone.
pub(crate) async fn drop_session(
    state: &SharedStateStorage,
    credentials: &SharedCredentialStorage,
    slots: &Slots,
) {
    if state.is_read_only() {
        return;
    }
    state.discard(&slots.state);
    clear_credentials(credentials, slots).await;
}

/// Publishes the sign-in as over rather than as never having happened.
///
/// A session that ran out or was revoked ended on its own, and an application
/// says so differently: "your session ended, sign back in" names the account it
/// ended for, which a removed record cannot.
#[cfg(any(feature = "wasm-js", test))]
pub(crate) async fn expire_session(
    state: &SharedStateStorage,
    credentials: &SharedCredentialStorage,
    slots: &Slots,
    principal: ic_agent::export::Principal,
) {
    if state.is_read_only() {
        return;
    }
    state.set(
        &slots.state,
        StoredSessionState {
            principal,
            expiration_ns: now_ns(),
        },
    );
    clear_credentials(credentials, slots).await;
}

/// Ends a sign-in whose session turned out gone, or only this origin's claim on
/// it.
///
/// Port of upstream `#endOrDrop` (`auth-client.ts:1585-1601`): if the record
/// still names the session the identity was opened over, it is published as over
/// when that session was ever used, and removed when it never was; if the record
/// has moved on, someone else owns the sign-in and this origin only drops its
/// own claim.
#[cfg(any(feature = "wasm-js", test))]
pub(crate) async fn end_or_drop(
    state: SharedStateStorage,
    credentials: SharedCredentialStorage,
    slots: std::sync::Arc<Slots>,
    held: Option<StoredSessionState>,
    ended: bool,
) {
    if state.is_read_only() {
        return;
    }
    let unchanged = held.is_some_and(|held| {
        state.get(&slots.state).is_some_and(|now| {
            now.principal == held.principal && now.expiration_ns == held.expiration_ns
        })
    });

    if !unchanged {
        drop_session(&state, &credentials, &slots).await;
    } else if ended {
        let principal = held.map(|held| held.principal);
        match principal {
            Some(principal) => expire_session(&state, &credentials, &slots, principal).await,
            None => drop_session(&state, &credentials, &slots).await,
        }
    } else {
        end_session(&state, &credentials, &slots).await;
    }
}

/// Removes the `session` and `app` credentials.
///
/// The `session-pending` slot is deliberately kept: an abandoned ceremony may
/// still return for it (`auth-client.ts:1846-1848`).
pub(crate) async fn clear_credentials(credentials: &SharedCredentialStorage, slots: &Slots) {
    let session = credentials.remove(&slots.session).await;
    let app = credentials.remove(&slots.app).await;
    // Both are attempted; the first failure is what upstream reports.
    let _ = match session {
        Ok(()) => app,
        Err(error) => Err(error),
    };
}
