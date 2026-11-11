//! The error type shared by the v11-shaped client.
//!
//! Upstream throws a set of named error classes; Rust represents them as
//! variants of one enum, with [`AuthClientError::kind`] giving the same
//! discrimination a JavaScript caller would use with `instanceof`.

use thiserror::Error;

use crate::client::transport::SignerError;

/// The category of an [`AuthClientError`].
///
/// Named after the upstream error classes so that a JavaScript caller's
/// `instanceof` check has a one-to-one Rust counterpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthClientErrorKind {
    /// The options passed to the constructor or to a method are not usable.
    InvalidOptions,
    /// A storage medium failed.
    Storage,
    /// The signer (identity provider) failed or refused.
    Signer,
    /// An agent / canister call failed.
    Agent,
    /// A later sign-in or sign-out took over from this one.
    Superseded,
    /// A sign-in exists for this domain, but this origin holds no credential
    /// for it.
    SessionNotHeld,
    /// The session behind this identity no longer exists.
    SessionGone,
    /// A mint answered for an unexpected account.
    AccountMismatch,
    /// The signer needs user interaction and was asked for none.
    InteractionRequired,
    /// This Internet Identity does not send notifications.
    NotificationsUnsupported,
    /// The platform cannot do what was asked (for example a browser-only
    /// facility on the native feature).
    Unsupported,
    /// A platform (JavaScript) exception carried through unchanged.
    Platform,
    /// Anything else.
    Other,
}

/// The error type of the v11-shaped client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthClientError {
    /// The options passed to the constructor or to a method are not usable.
    #[error("invalid options: {0}")]
    InvalidOptions(String),

    /// A storage medium failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// The signer (identity provider) failed or refused.
    #[error(transparent)]
    Signer(#[from] SignerError),

    /// An agent / canister call failed.
    #[error("agent error: {0}")]
    Agent(String),

    /// A later sign-in or sign-out took over from this one.
    #[error("superseded: {0}")]
    Superseded(String),

    /// A sign-in exists for this domain, but this origin holds no credential
    /// for it.
    #[error("a sign-in exists for this domain, but this origin holds no credential for it")]
    SessionNotHeld,

    /// The session behind this identity no longer exists.
    #[error("the session behind this identity no longer exists")]
    SessionGone,

    /// A mint answered for an account this origin was not expecting: the
    /// credential it read belongs to a sign-in that has moved on.
    #[error("the minted delegation is not for the account this origin acts as")]
    AccountMismatch,

    /// The signer needs user interaction and was asked for none.
    #[error("interaction required{}", reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())]
    InteractionRequired {
        /// The provider's own explanation, when it gave one.
        reason: Option<String>,
    },

    /// This Internet Identity does not send notifications.
    #[error("this Internet Identity does not send notifications")]
    NotificationsUnsupported,

    /// The platform cannot do what was asked.
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),

    /// A platform (JavaScript) exception carried through unchanged.
    #[error("platform error: {0}")]
    Platform(String),

    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl AuthClientError {
    /// The category of this error, for callers that branch on it.
    pub fn kind(&self) -> AuthClientErrorKind {
        match self {
            AuthClientError::InvalidOptions(_) => AuthClientErrorKind::InvalidOptions,
            AuthClientError::Storage(_) => AuthClientErrorKind::Storage,
            AuthClientError::Signer(_) => AuthClientErrorKind::Signer,
            AuthClientError::Agent(_) => AuthClientErrorKind::Agent,
            AuthClientError::Superseded(_) => AuthClientErrorKind::Superseded,
            AuthClientError::SessionNotHeld => AuthClientErrorKind::SessionNotHeld,
            AuthClientError::SessionGone => AuthClientErrorKind::SessionGone,
            AuthClientError::AccountMismatch => AuthClientErrorKind::AccountMismatch,
            AuthClientError::InteractionRequired { .. } => AuthClientErrorKind::InteractionRequired,
            AuthClientError::NotificationsUnsupported => {
                AuthClientErrorKind::NotificationsUnsupported
            }
            AuthClientError::Unsupported(_) => AuthClientErrorKind::Unsupported,
            AuthClientError::Platform(_) => AuthClientErrorKind::Platform,
            AuthClientError::Other(_) => AuthClientErrorKind::Other,
        }
    }
}

impl From<crate::storage::StorageError> for AuthClientError {
    fn from(error: crate::storage::StorageError) -> Self {
        AuthClientError::Storage(error.to_string())
    }
}
