//! Where a session's app delegations come from, and the errors they can fail
//! with.
//!
//! Port of upstream `session/app-delegation-source.ts`. The identity decides
//! *when* to mint; a source decides *how*. Splitting them is what lets the
//! rotation timing be tested without a replica, and what keeps the identity free
//! of any agent or canister id.
//!
//! The error taxonomy is the important part. Only [`SessionError::Gone`] may end
//! a session: a transport failure or an internal canister error leaves the
//! session alone and is worth retrying, and a session this library cannot act
//! for (a read-only one) is neither gone nor retryable, so it is latched and the
//! record is left alone.

use async_trait::async_trait;
use ic_agent::export::Principal;
use thiserror::Error;

use crate::ArcIdentity;
use crate::client::error::AuthClientError;
use crate::client::platform::PlatformBounds;
use crate::delegation_chain::DelegationChain;

/// The canister has no session behind the caller: revoked, expired, pruned, or
/// never one at all.
///
/// This is the one terminal outcome. Everything else a mint can fail with leaves
/// the session alone and is worth retrying, so only this may end a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the session behind this identity no longer exists")]
pub struct SessionGoneError;

/// The session exists but this library cannot act for it, however healthy it is.
///
/// The third outcome, and the reason it is not either of the others: the session
/// is neither gone nor worth retrying. Retrying returns the same answer forever,
/// and reporting it as gone would retract a record for a sign-in that is alive,
/// signing every tab on the domain out of it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("this session cannot be acted for: {0}")]
pub struct SessionUnsupportedError(pub String);

/// A mint answered for an account the caller was not expecting.
///
/// The session is healthy and the mint succeeded; it is the pairing that is
/// wrong. So it is neither gone nor retryable — asking again returns the same
/// account — and the caller's own record is what has to give way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the minted delegation is not for the account this origin acts as")]
pub struct AccountMismatchError;

/// The canister signed nothing for the key and expiration that were prepared.
///
/// Its own error because the remedy is its own: prepare again and use what comes
/// back. Signing in afresh is not it — the session is live, or the call would
/// have been refused for being no session at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("Internet Identity signed no delegation for this key and expiration")]
pub struct NoSuchDelegationError;

/// Everything a session operation can fail with.
///
/// Port of the four error classes in `app-delegation-source.ts` plus the
/// retryable bucket upstream leaves as a plain `Error`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The session behind this identity no longer exists. The only terminal
    /// outcome.
    #[error(transparent)]
    Gone(#[from] SessionGoneError),

    /// The session is alive but cannot be acted for.
    #[error(transparent)]
    Unsupported(#[from] SessionUnsupportedError),

    /// A mint answered for an account the caller was not expecting.
    #[error(transparent)]
    AccountMismatch(#[from] AccountMismatchError),

    /// The canister signed nothing for the expiration that was prepared.
    #[error(transparent)]
    NoSuchDelegation(#[from] NoSuchDelegationError),

    /// A transport or canister failure that leaves the session alone and may be
    /// worth retrying.
    #[error("{0}")]
    Retryable(String),

    /// The session chain is not a session for the canister being called.
    #[error("invalid session chain: {0}")]
    InvalidChain(String),
}

impl SessionError {
    /// Whether this is the one terminal outcome.
    pub fn is_gone(&self) -> bool {
        matches!(self, SessionError::Gone(_))
    }

    /// Whether the session exists but cannot be acted for.
    pub fn is_unsupported(&self) -> bool {
        matches!(self, SessionError::Unsupported(_))
    }

    /// Whether a mint answered for an unexpected account.
    pub fn is_account_mismatch(&self) -> bool {
        matches!(self, SessionError::AccountMismatch(_))
    }

    /// Whether the canister signed nothing for the prepared expiration.
    pub fn is_no_such_delegation(&self) -> bool {
        matches!(self, SessionError::NoSuchDelegation(_))
    }
}

impl From<SessionError> for AuthClientError {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Gone(_) => AuthClientError::SessionGone,
            // The static message is what `kind()` is for; the detailed one is
            // carried by the session error the caller saw first.
            SessionError::Unsupported(_) => {
                AuthClientError::Unsupported("this session cannot be acted for")
            }
            SessionError::AccountMismatch(_) => AuthClientError::AccountMismatch,
            SessionError::NoSuchDelegation(_) => {
                AuthClientError::Agent(NoSuchDelegationError.to_string())
            }
            SessionError::Retryable(message) => AuthClientError::Agent(message),
            SessionError::InvalidChain(message) => AuthClientError::InvalidOptions(message),
        }
    }
}

/// A credential that is certainly whole: a key and the delegation that
/// authorises it.
///
/// Only a ceremony's slot holds a key alone; an app slot read for use holds
/// both halves, and held apart the two can disagree.
#[derive(Clone)]
pub struct Held {
    /// The key that signs.
    pub identity: ArcIdentity,
    /// The delegation issued to that key.
    pub chain: DelegationChain,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held")
            .field("identity", &self.identity)
            .field("expires_at_ms", &expires_at_ms(&self.chain))
            .finish()
    }
}

impl Held {
    /// The DER-encoded public key of this credential's identity.
    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        self.identity.public_key()
    }

    /// Whether this credential is rooted at `expected`, where one is named.
    pub fn is_for_account(&self, expected: Option<Principal>) -> bool {
        is_for_account(
            &self.chain,
            self.public_key_der().as_deref().unwrap_or_default(),
            expected,
        )
    }
}

/// Where [`SessionIdentity`](super::identity::SessionIdentity) gets an app
/// delegation from.
///
/// The identity decides *when* to mint; this decides *how*. Implemented by
/// [`SessionMinter`](super::minter::SessionMinter) over the Internet Identity
/// canister, and by a host bridge on a platform that mints on the app's behalf.
#[async_trait(?Send)]
pub trait AppDelegationSource: PlatformBounds {
    /// Mints a delegation from the session to `app_public_key`.
    ///
    /// Three outcomes. [`SessionError::Gone`] where the session no longer
    /// exists, [`SessionError::Unsupported`] where it exists but this library
    /// cannot act for it, and anything else where the attempt may be worth
    /// repeating.
    async fn mint(&self, app_public_key: &[u8]) -> Result<DelegationChain, SessionError>;
}

/// Whether two DER-encoded keys are the same bytes.
pub fn same_key(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(left, right)| left == right)
}

/// The leaf of a chain: the key it authorises.
pub fn delegates_to(chain: &DelegationChain) -> Option<&[u8]> {
    chain
        .delegations
        .last()
        .map(|signed| signed.delegation.pubkey.as_slice())
}

/// Whether a chain's leaf authorises `key_der` — the key that would sign with
/// it.
///
/// A chain paired with a key it does not authorise signs nothing the replica will
/// accept, and fails with a signature error that points at neither half. Every
/// place that holds both halves checks this.
pub fn chain_authorises_key(chain: &DelegationChain, key_der: &[u8]) -> bool {
    delegates_to(chain).is_some_and(|leaf| same_key(leaf, key_der))
}

/// The account a chain is rooted at: the self-authenticating principal of its
/// root key.
pub fn account_of(chain: &DelegationChain) -> Principal {
    Principal::self_authenticating(&chain.public_key)
}

/// Whether a chain may be used for `expected`.
///
/// Two checks at opposite ends of the chain. The leaf must be the key stored
/// beside it, which is true of any whole record whoever it belongs to. And the
/// root must be the account the caller names — a credential left by another
/// account would otherwise decide who this identity is, and requests would go
/// out as that account and succeed until its delegation expired.
///
/// `expected` is absent only where the caller has no account to name, which is
/// why a read that cannot check it does not adopt.
pub fn is_for_account(
    chain: &DelegationChain,
    key_der: &[u8],
    expected: Option<Principal>,
) -> bool {
    if !chain_authorises_key(chain, key_der) {
        return false;
    }
    match expected {
        Some(expected) => account_of(chain) == expected,
        None => true,
    }
}

/// The earliest delegation expiration in a chain, in nanoseconds since the
/// epoch.
///
/// `None` for a chain with no hops, which authorises nothing.
pub fn earliest_expiration_ns(chain: &DelegationChain) -> Option<u64> {
    chain
        .delegations
        .iter()
        .map(|signed| signed.delegation.expiration)
        .min()
}

/// When a chain expires, in milliseconds since the epoch.
///
/// Zero for a chain with no hops: an empty chain reads as a session that expired
/// at the epoch rather than as a bad answer.
pub fn expires_at_ms(chain: &DelegationChain) -> u64 {
    earliest_expiration_ns(chain).unwrap_or(0) / 1_000_000
}

/// How long a chain has left, in milliseconds, at `now_ms`.
///
/// Signed, because the interesting comparison is `<= 0`.
pub fn ms_left(chain: &DelegationChain, now_ms: u64) -> i64 {
    expires_at_ms(chain) as i64 - now_ms as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_agent::identity::{Delegation, SignedDelegation};

    fn chain(root: &[u8], hops: &[(Vec<u8>, u64, Option<Vec<Principal>>)]) -> DelegationChain {
        DelegationChain::new(
            hops.iter()
                .map(|(pubkey, expiration, targets)| SignedDelegation {
                    delegation: Delegation {
                        pubkey: pubkey.clone(),
                        expiration: *expiration,
                        targets: targets.clone(),
                        permissions: None,
                    },
                    signature: vec![1],
                })
                .collect(),
            root.to_vec(),
        )
    }

    fn principal(byte: u8) -> Principal {
        Principal::from_slice(&[byte; 29])
    }

    #[test]
    fn same_key_compares_bytes() {
        assert!(same_key(&[1, 2, 3], &[1, 2, 3]));
        assert!(!same_key(&[1, 2, 3], &[1, 2]));
        assert!(!same_key(&[1, 2, 3], &[1, 2, 4]));
        assert!(same_key(&[], &[]));
    }

    #[test]
    fn leaf_and_root_are_read_from_the_right_ends() {
        let root = vec![9u8; 44];
        let leaf = vec![7u8; 44];
        let chain = chain(
            &root,
            &[(vec![8u8; 44], 10, None), (leaf.clone(), 20, None)],
        );

        assert_eq!(delegates_to(&chain), Some(leaf.as_slice()));
        assert_eq!(chain.public_key, root);
        assert!(chain_authorises_key(&chain, &leaf));
        assert!(!chain_authorises_key(&chain, &[7u8; 43]));
        assert_eq!(account_of(&chain), Principal::self_authenticating(&root));
    }

    #[test]
    fn an_empty_chain_authorises_nothing() {
        let chain = chain(&[9u8; 44], &[]);
        assert_eq!(delegates_to(&chain), None);
        assert!(!chain_authorises_key(&chain, &[]));
        assert_eq!(expires_at_ms(&chain), 0);
    }

    #[test]
    fn is_for_account_checks_both_ends() {
        let root = vec![9u8; 44];
        let leaf = vec![7u8; 44];
        let chain = chain(&root, &[(leaf.clone(), 10, None)]);
        let account = Principal::self_authenticating(&root);

        assert!(is_for_account(&chain, &leaf, Some(account)));
        assert!(!is_for_account(&chain, &leaf, Some(principal(1))));
        // No account named: only the leaf is checked.
        assert!(is_for_account(&chain, &leaf, None));
        // Leaf that does not match the stored key: refused whatever the account.
        assert!(!is_for_account(&chain, &[8u8; 44], Some(account)));
        assert!(!is_for_account(&chain, &[8u8; 44], None));
    }

    #[test]
    fn expiry_is_the_earliest_hop() {
        let chain = chain(
            &[9u8; 44],
            &[
                (vec![1u8; 44], 5_000_000_000, None),
                (vec![2u8; 44], 2_000_000_000, None),
            ],
        );
        assert_eq!(earliest_expiration_ns(&chain), Some(2_000_000_000));
        assert_eq!(expires_at_ms(&chain), 2_000);
        assert_eq!(ms_left(&chain, 1_000), 1_000);
        assert_eq!(ms_left(&chain, 2_500), -500);
        assert!(ms_left(&chain, 3_000) <= 0);
    }

    #[test]
    fn errors_map_onto_the_client_error_vocabulary() {
        assert!(matches!(
            AuthClientError::from(SessionError::Gone(SessionGoneError)),
            AuthClientError::SessionGone
        ));
        assert!(matches!(
            AuthClientError::from(SessionError::Unsupported(SessionUnsupportedError(
                "queries only".into()
            ))),
            AuthClientError::Unsupported(_)
        ));
        assert!(matches!(
            AuthClientError::from(SessionError::Retryable("blip".into())),
            AuthClientError::Agent(_)
        ));
        assert!(matches!(
            AuthClientError::from(SessionError::InvalidChain("bad".into())),
            AuthClientError::InvalidOptions(_)
        ));
        assert!(SessionError::Gone(SessionGoneError).is_gone());
        assert!(SessionError::AccountMismatch(AccountMismatchError).is_account_mismatch());
        assert!(SessionError::NoSuchDelegation(NoSuchDelegationError).is_no_such_delegation());
    }
}
