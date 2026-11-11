//! Requests a session delegation from the signer.
//!
//! Port of upstream `session/session-delegation.ts`. The method is named for its
//! provider because a JSON-RPC method travels over a transport shared with other
//! signers, unlike a canister method.
//!
//! What comes back is a chain restricted to the Internet Identity canister, so
//! it is not something an application can call its own canisters with. It is
//! what app delegations are minted from.
//!
//! # Interaction required
//!
//! Internet Identity denies a `prompt: 'none'` request with JSON-RPC code `3002`,
//! in ICRC-25's 3xxx user-action range. That denial is not a failure: it says a
//! ceremony is needed, so the caller signs in interactively rather than
//! retrying. It is also the only dependable evidence that a shared record is
//! stale rather than replaced, which is what lets an origin retract a record it
//! did not write.
//!
//! This module maps that refusal onto [`AuthClientError::InteractionRequired`],
//! keeping the provider's own `reason` (`login_required`,
//! `account_selection_required`, …) as a plain string so a value this crate does
//! not know is not a reason to fail.

use serde_json::Value;

use crate::client::error::AuthClientError;
use crate::client::transport::SignerError;
use crate::delegation_chain::DelegationChain;
use crate::signer::Signer;

/// The JSON-RPC method Internet Identity answers with a session rather than a
/// long-lived delegation.
pub use crate::signer::SESSION_DELEGATION_METHOD;

/// The JSON-RPC code for "a ceremony is needed", which a silent re-issue
/// reports.
pub const INTERACTION_REQUIRED_CODE: i64 = SignerError::CODE_INTERACTION_REQUIRED;

/// The parameters of a session-delegation request.
///
/// Port of `SessionDelegationParams` (`session-delegation.ts:63-68`), with the
/// same optional bounds: an unset bound is omitted so the provider's own default
/// applies rather than a number this crate invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDelegationParams<'a> {
    /// The session's DER-encoded public key the chain must delegate to.
    pub session_public_key: &'a [u8],
    /// The requested maximum lifetime, in nanoseconds.
    pub max_time_to_live: Option<u64>,
    /// The requested maximum idle time, in nanoseconds.
    pub max_time_to_idle: Option<u64>,
    /// The ICRC-95 derivation origin for this request.
    pub derivation_origin: Option<&'a str>,
}

/// Asks the identity provider for a session, and returns the chain it signed.
///
/// A `3002` refusal becomes [`AuthClientError::InteractionRequired`] with the
/// provider's reason; every other failure stays a
/// [`AuthClientError::Signer`], which is what lets a caller tell "a ceremony is
/// needed" apart from a transport or protocol failure.
pub async fn request_session_delegation(
    signer: &Signer,
    params: SessionDelegationParams<'_>,
) -> Result<DelegationChain, AuthClientError> {
    let request = crate::signer::SessionDelegationParams {
        session_public_key: params.session_public_key,
        max_time_to_live: params.max_time_to_live,
        max_time_to_idle: params.max_time_to_idle,
        derivation_origin: params.derivation_origin,
    };
    signer
        .request_session_delegation(request)
        .await
        .map_err(map_signer_error)
}

/// Maps a signer failure onto the client's error vocabulary.
///
/// Only the `3002` refusal is re-shaped: it is the one outcome a caller acts on
/// differently, and the code carries the only thing it can act on. Dropping it
/// would leave "interaction required" indistinguishable from a transport failure
/// except by matching a message this crate does not define.
pub fn map_signer_error(error: SignerError) -> AuthClientError {
    if error.is_interaction_required() {
        AuthClientError::InteractionRequired {
            reason: interaction_required_reason(&error),
        }
    } else {
        AuthClientError::Signer(error)
    }
}

/// The reason Internet Identity gave for needing interaction, where it gave one.
///
/// `login_required` where it holds no session, `account_selection_required`
/// where it holds more than one and the request named none. A caller may word
/// its prompt from this and does not have to branch on it, so it is deliberately
/// a string rather than a union — a value this crate does not know is not a
/// reason to fail.
pub fn interaction_required_reason(error: &SignerError) -> Option<String> {
    match error {
        SignerError::Refused { data, .. } => data.as_ref().and_then(|data| {
            data.get("reason").map(|reason| match reason {
                Value::String(reason) => reason.clone(),
                other => other.to_string(),
            })
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::signer::{Signer, SignerOptions};

    fn refused(code: i64, data: Option<Value>) -> SignerError {
        SignerError::Refused {
            code,
            message: "the signer refused".to_string(),
            data,
        }
    }

    #[test]
    fn interaction_required_maps_from_3002_and_keeps_the_reason() {
        let error = map_signer_error(refused(
            INTERACTION_REQUIRED_CODE,
            Some(json!({ "reason": "login_required" })),
        ));
        assert!(matches!(
            error,
            AuthClientError::InteractionRequired { reason: Some(ref reason) }
                if reason == "login_required"
        ));
        assert_eq!(
            error.kind(),
            crate::client::error::AuthClientErrorKind::InteractionRequired
        );
    }

    #[test]
    fn interaction_required_without_a_reason_still_maps() {
        let error = map_signer_error(refused(INTERACTION_REQUIRED_CODE, None));
        assert!(matches!(
            error,
            AuthClientError::InteractionRequired { reason: None }
        ));
    }

    #[test]
    fn a_non_string_reason_is_stringified_rather_than_dropped() {
        let error = map_signer_error(refused(
            INTERACTION_REQUIRED_CODE,
            Some(json!({ "reason": 7 })),
        ));
        assert!(matches!(
            error,
            AuthClientError::InteractionRequired { reason: Some(ref reason) }
                if reason == "7"
        ));
    }

    #[test]
    fn any_other_denial_stays_an_ordinary_signer_error() {
        let error = map_signer_error(refused(-32000, Some(json!({ "reason": "nope" }))));
        assert_eq!(
            error.kind(),
            crate::client::error::AuthClientErrorKind::Signer
        );
    }

    #[test]
    fn a_transport_failure_stays_an_ordinary_signer_error() {
        let error = map_signer_error(SignerError::Timeout);
        assert_eq!(
            error.kind(),
            crate::client::error::AuthClientErrorKind::Signer
        );
    }

    #[test]
    fn the_wrapper_maps_a_3002_refusal_from_the_wire() {
        let transport = crate::signer::test_utils::FakeTransport::new();
        transport.on_error(
            SESSION_DELEGATION_METHOD,
            INTERACTION_REQUIRED_CODE,
            "interaction required",
            Some(json!({ "reason": "login_required" })),
        );
        let signer = Signer::new(SignerOptions {
            transport: transport.shared(),
            derivation_origin: None,
        });

        let error = futures::executor::block_on(request_session_delegation(
            &signer,
            SessionDelegationParams {
                session_public_key: &[1, 2, 3],
                max_time_to_live: None,
                max_time_to_idle: None,
                derivation_origin: None,
            },
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            AuthClientError::InteractionRequired { reason: Some(ref reason) }
                if reason == "login_required"
        ));
        // The request went out as the documented method.
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, SESSION_DELEGATION_METHOD);
        assert_eq!(SESSION_DELEGATION_METHOD, "ii_session_delegation");
    }
}
