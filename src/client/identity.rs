//! The identity a client answers with.
//!
//! A sign-in is more than one key and one delegation: in a browser the client
//! replaces the delegation it signs with as that delegation ages. What callers
//! hold is therefore a handle to the client's answer, not a snapshot of it ---
//! hand it to an agent and signing follows the rotation.

use std::sync::Arc;

use ic_agent::agent::EnvelopeContent;
use ic_agent::export::Principal;
use ic_agent::identity::{Delegation, Identity, SenderInfo, Signature, SignedDelegation};

use crate::client::session::identity::SessionIdentity;

/// The identity a client answers with.
///
/// Implements [`Identity`], so an agent can be given it directly
/// (`with_identity`). It also answers the questions a caller needs before
/// trusting it: which principal it signs as, whether that is anonymous, and when
/// the delegation behind it expires.
#[derive(Clone)]
pub struct ClientIdentity {
    identity: Arc<dyn Identity>,
    /// The rotating session behind it, where this target has one.
    session: Option<Arc<SessionIdentity>>,
}

impl ClientIdentity {
    pub(crate) fn new(identity: Arc<dyn Identity>, session: Option<Arc<SessionIdentity>>) -> Self {
        Self { identity, session }
    }

    /// An identity that is not a rotating session.
    pub(crate) fn plain(identity: Arc<dyn Identity>) -> Self {
        Self::new(identity, None)
    }

    /// The identity as a trait object, for code that wants the vtable rather
    /// than the handle.
    pub fn as_arc_identity(&self) -> Arc<dyn Identity> {
        self.identity.clone()
    }

    /// The principal this identity signs as.
    pub fn principal(&self) -> Principal {
        self.identity
            .sender()
            .unwrap_or_else(|_| Principal::anonymous())
    }

    /// Whether this client is answering anonymously (nothing is signed in).
    pub fn is_anonymous(&self) -> bool {
        self.principal() == Principal::anonymous()
    }

    /// When the delegation this identity signs with expires, in milliseconds
    /// since the Unix epoch.
    ///
    /// The rotating session reports when the delegation it currently holds
    /// expires; a fixed identity reports its chain's earliest hop. `None` where
    /// the identity carries no delegation at all (a root key, say).
    pub fn delegation_expires_at_ms(&self) -> Option<u64> {
        if let Some(session) = &self.session {
            let expires = session.delegation_expires_at_ms();
            if expires != 0 {
                return Some(expires);
            }
        }
        self.identity
            .delegation_chain()
            .iter()
            .map(|signed| signed.delegation.expiration)
            .min()
            .map(|expiration_ns| expiration_ns / 1_000_000)
    }
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("principal", &self.principal())
            .field("expires_at_ms", &self.delegation_expires_at_ms())
            .finish()
    }
}

impl Identity for ClientIdentity {
    fn sender(&self) -> Result<Principal, String> {
        self.identity.sender()
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        self.identity.public_key()
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.identity.sign(content)
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.identity.sign_delegation(content)
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        self.identity.sign_arbitrary(content)
    }

    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        self.identity.delegation_chain()
    }

    fn sender_info(&self) -> Option<SenderInfo> {
        self.identity.sender_info()
    }
}
