//! UniFFI bindings for the native client (Swift and Kotlin consumers).
//!
//! The exported surface is the v11 client, blocking: a foreign caller cannot
//! await a Rust future, so every asynchronous operation is driven to completion
//! with `futures::executor::block_on` on the calling thread.
//!
//! Sign-in uses the identity provider's non-browser flow
//! ([`crate::client::webauth`]): the system browser opens, the provider hands the
//! delegation to a loopback listener, and this call returns once it has landed.
//! That is a desktop flow (macOS, Linux, Windows); on iOS and Android it returns
//! [`AuthError::Unsupported`] until a platform-hosted equivalent lands, because
//! the provider only accepts a `127.0.0.1` HTTP callback.

use std::sync::Arc;

use futures::executor::block_on;
use ic_agent::identity::Identity;

use crate::client::{
    AuthClient as Client, AuthClientCreateOptions, AuthClientError, ClientIdentity, SessionStatus,
    SignInOptions, SignOutOptions,
};

#[cfg(feature = "keyring")]
#[uniffi::export]
/// Enable a mock keyring backend for local development.
///
/// Call this before creating an `AuthClient` to avoid touching the OS keyring.
pub fn enable_keyring_mock() {
    // `keyring` 4 initialises its platform store lazily on the first `Entry::new`
    // call and installs it as the `keyring-core` default store. Force that
    // initialisation first, then replace the default store with the in-memory
    // mock so entries created afterwards stay off the real OS keychain.
    let _ = keyring::Entry::store_status();
    keyring_core::set_default_store(
        keyring_core::mock::Store::new().expect("failed to create mock credential store"),
    );
}

/// Errors exposed by the UniFFI bindings.
#[derive(Debug, Clone, uniffi::Error, thiserror::Error)]
pub enum AuthError {
    /// The options handed to a call are not usable.
    #[error("invalid options: {0}")]
    InvalidOptions(String),
    /// A storage medium failed.
    #[error("storage error: {0}")]
    Storage(String),
    /// The signer (identity provider) failed or refused.
    #[error("signer error: {0}")]
    Signer(String),
    /// An agent or canister call failed.
    #[error("agent error: {0}")]
    Agent(String),
    /// A sign-in exists for this domain, but this client holds no credential.
    #[error("session not held")]
    SessionNotHeld,
    /// The session behind the identity no longer exists.
    #[error("session gone")]
    SessionGone,
    /// A later sign-in or sign-out took over from this one.
    #[error("superseded: {0}")]
    Superseded(String),
    /// The platform cannot do what was asked.
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
    /// Anything else.
    #[error("{0}")]
    Message(String),
}

impl From<AuthClientError> for AuthError {
    fn from(error: AuthClientError) -> Self {
        match error {
            AuthClientError::InvalidOptions(message) => AuthError::InvalidOptions(message),
            AuthClientError::Storage(message) => AuthError::Storage(message),
            AuthClientError::Signer(error) => AuthError::Signer(error.to_string()),
            AuthClientError::Agent(message) => AuthError::Agent(message),
            AuthClientError::SessionNotHeld => AuthError::SessionNotHeld,
            AuthClientError::SessionGone => AuthError::SessionGone,
            AuthClientError::Superseded(message) => AuthError::Superseded(message),
            AuthClientError::Unsupported(reason) => AuthError::Unsupported(reason.to_string()),
            other => AuthError::Message(other.to_string()),
        }
    }
}

/// Options for [`AuthClient::login`].
#[derive(uniffi::Record, Clone, Default)]
pub struct LoginOptions {
    /// The identity provider's authorize URL (defaults to `https://id.ai/authorize`).
    pub identity_provider: Option<String>,
    /// The canister that mints and revokes this application's delegations.
    pub canister_id: Option<String>,
    /// The origin of the application whose principal to sign in as.
    ///
    /// This is the provider's `domain` parameter: signing in "as an app" makes
    /// the principal match the one the same user has in that app's web UI.
    /// Requires the user to have enabled CLI access for their identity, and
    /// omitting it signs in as the provider's generic CLI identity instead.
    pub derivation_origin: Option<String>,
    /// Maximum session lifetime in nanoseconds (sent as the provider's `ttl`).
    pub max_time_to_live: Option<u64>,
    /// Maximum idle time in nanoseconds. No equivalent in the non-browser flow.
    pub max_time_to_idle: Option<u64>,
}

/// The client's answer about its sign-in, as a plain record.
#[derive(uniffi::Record, Clone, Default)]
pub struct SessionStatusRecord {
    /// One of `signed-in`, `signed-in-elsewhere`, `expired`, `signed-out`.
    pub state: String,
    /// The account's principal, where the status names one.
    pub principal: Option<String>,
    /// When the sign-in ends (or ended), in milliseconds since the Unix epoch.
    pub expires_at_ms: Option<u64>,
}

impl From<SessionStatus> for SessionStatusRecord {
    fn from(status: SessionStatus) -> Self {
        Self {
            state: status.state().to_string(),
            principal: status.principal().map(|principal| principal.to_text()),
            expires_at_ms: status.expires_at_ms(),
        }
    }
}

/// A native authentication client.
#[derive(uniffi::Object)]
pub struct AuthClient {
    inner: Client,
}

impl AuthClient {
    fn from_parts(
        credential_storage: crate::client::credentials::SharedCredentialStorage,
        state_directory: Option<String>,
    ) -> Result<Arc<Self>, AuthError> {
        let state_storage: crate::client::state::SharedStateStorage = match state_directory {
            Some(directory) => Arc::new(
                crate::client::state::native::NativeStateStorage::new(directory)
                    .map_err(AuthError::from)?,
            ),
            None => Arc::new(crate::client::state::MemoryStateStorage::new()),
        };
        let options = AuthClientCreateOptions {
            credential_storage: Some(credential_storage),
            state_storage: Some(state_storage),
            ..Default::default()
        };
        let inner = Client::new(options).map_err(AuthError::from)?;
        Ok(Arc::new(Self { inner }))
    }
}

#[cfg(feature = "keyring")]
#[uniffi::export]
impl AuthClient {
    /// Creates a client whose credentials live in the OS keyring.
    ///
    /// `state_directory` is where the sign-in state is kept, so that a restart
    /// still knows who is signed in. Omitting it keeps the state in memory.
    #[uniffi::constructor]
    pub fn new(
        service_name: String,
        state_directory: Option<String>,
    ) -> Result<Arc<Self>, AuthError> {
        Self::from_parts(
            Arc::new(
                crate::client::credentials::native::NativeCredentialStorage::keyring(service_name),
            ),
            state_directory,
        )
    }
}

#[cfg(feature = "android-password")]
#[uniffi::export]
impl AuthClient {
    /// Creates a client whose credentials live in a password-encrypted file.
    ///
    /// For Android/Kotlin consumers where the OS keyring is unavailable, or
    /// where a password-protected file is preferred.
    #[uniffi::constructor(name = "newWithPassword")]
    pub fn new_with_password(
        service_name: String,
        storage_directory: String,
        password: String,
        state_directory: Option<String>,
    ) -> Result<Arc<Self>, AuthError> {
        Self::from_parts(
            Arc::new(
                crate::client::credentials::native::NativeCredentialStorage::password(
                    service_name,
                    storage_directory,
                    password,
                ),
            ),
            state_directory,
        )
    }
}

#[cfg(feature = "pem")]
#[uniffi::export]
impl AuthClient {
    /// Creates a client whose credentials live in a PEM file.
    #[uniffi::constructor(name = "newWithPem")]
    pub fn new_with_pem(
        directory: String,
        state_directory: Option<String>,
    ) -> Result<Arc<Self>, AuthError> {
        Self::from_parts(
            Arc::new(crate::client::credentials::native::NativeCredentialStorage::pem(directory)),
            state_directory,
        )
    }
}

#[uniffi::export]
impl AuthClient {
    /// Signs in, blocking until the browser flow completes.
    ///
    /// Desktop only: the identity provider's non-browser flow hands the
    /// delegation to a `127.0.0.1` listener, which a mobile app cannot complete
    /// without a platform-hosted equivalent.
    pub fn login(&self, options: LoginOptions) -> Result<Arc<AuthIdentity>, AuthError> {
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            let identity = self.build_options(options).and_then(|options| {
                block_on(self.inner.sign_in(options)).map_err(AuthError::from)
            })?;
            Ok(Arc::new(AuthIdentity::from_identity(identity)))
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = options;
            Err(AuthError::Unsupported(
                "sign-in from a mobile app needs a platform-hosted equivalent of the \
                 provider's non-browser flow, which is not implemented yet"
                    .to_string(),
            ))
        }
    }

    /// Signs out, ending the session at the identity provider where possible.
    pub fn logout(&self) -> Result<(), AuthError> {
        block_on(self.inner.sign_out(SignOutOptions::default())).map_err(AuthError::from)
    }

    /// Whether this client is signed in.
    pub fn is_authenticated(&self) -> bool {
        self.inner.is_authenticated()
    }

    /// The signed-in account's principal, where there is one.
    pub fn principal_text(&self) -> Option<String> {
        self.inner
            .get_principal()
            .map(|principal| principal.to_text())
    }

    /// The client's answer about its sign-in.
    pub fn status(&self) -> SessionStatusRecord {
        self.inner.get_status().into()
    }

    /// The identity requests are signed with.
    ///
    /// In a browser this is the session identity, whose delegation the client
    /// replaces as it ages; this handle is a snapshot of it, so a long-lived
    /// foreign object should ask again rather than cache it.
    pub fn identity(&self) -> Result<Arc<AuthIdentity>, AuthError> {
        let identity = block_on(self.inner.get_identity()).map_err(AuthError::from)?;
        Ok(Arc::new(AuthIdentity::from_identity(identity)))
    }
}

impl AuthClient {
    fn build_options(&self, options: LoginOptions) -> Result<SignInOptions, AuthError> {
        // The provider pair is applied through the create options; a caller that
        // changes it here would be changing a client-level setting per call, so
        // this validates that nothing was asked for that is not supported.
        if options.identity_provider.is_some() || options.canister_id.is_some() {
            return Err(AuthError::InvalidOptions(
                "identity_provider and canister_id are create-time settings; pass them to the \
                 client constructor instead"
                    .to_string(),
            ));
        }
        let _ = options.max_time_to_idle;
        Ok(SignInOptions::builder()
            .maybe_max_time_to_live(options.max_time_to_live)
            .build())
    }
}

/// A concrete identity, suitable for signing requests.
#[derive(uniffi::Object)]
pub struct AuthIdentity {
    identity: ClientIdentity,
}

impl AuthIdentity {
    fn from_identity(identity: ClientIdentity) -> Self {
        Self { identity }
    }
}

#[uniffi::export]
impl AuthIdentity {
    /// The principal this identity signs as.
    pub fn principal_text(&self) -> Result<String, AuthError> {
        self.identity
            .sender()
            .map(|principal| principal.to_text())
            .map_err(AuthError::Message)
    }

    /// The DER-encoded public key this identity presents.
    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        self.identity.public_key()
    }

    /// Signs `message` with this identity.
    pub fn sign_arbitrary(&self, message: Vec<u8>) -> Result<Vec<u8>, AuthError> {
        let signature = self
            .identity
            .sign_arbitrary(&message)
            .map_err(AuthError::Message)?;
        signature
            .signature
            .ok_or_else(|| AuthError::Message("signature missing".to_string()))
    }

    /// When the delegation this identity signs with expires, in milliseconds
    /// since the Unix epoch.
    ///
    /// A browser identity's delegation is replaced as it ages, so this is a
    /// snapshot: a foreign object that holds the identity for a long time should
    /// ask the client for it again rather than trust an old answer.
    pub fn delegation_expires_at_ms(&self) -> Option<u64> {
        self.identity.delegation_expires_at_ms()
    }

    /// The delegation chain this identity presents, as JSON.
    pub fn delegation_chain_json(&self) -> Option<String> {
        let delegations = self.identity.delegation_chain();
        if delegations.is_empty() {
            return None;
        }
        let public_key = self.identity.public_key().unwrap_or_default();
        let chain = crate::delegation_chain::DelegationChain::new(delegations, public_key);
        Some(chain.to_js_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_records_say_what_the_client_says() {
        let record: SessionStatusRecord = SessionStatus::SignedOut.into();
        assert_eq!(record.state, "signed-out");
        assert_eq!(record.principal, None);
        assert_eq!(record.expires_at_ms, None);

        let principal = ic_agent::export::Principal::self_authenticating([1u8; 29]);
        let record: SessionStatusRecord = SessionStatus::SignedIn {
            principal,
            expires_at_ms: 42,
        }
        .into();
        assert_eq!(record.state, "signed-in");
        assert_eq!(record.principal, Some(principal.to_text()));
        assert_eq!(record.expires_at_ms, Some(42));
    }

    #[test]
    fn client_errors_map_onto_the_exported_enum() {
        assert!(matches!(
            AuthError::from(AuthClientError::SessionNotHeld),
            AuthError::SessionNotHeld
        ));
        assert!(matches!(
            AuthError::from(AuthClientError::Unsupported("x")),
            AuthError::Unsupported(_)
        ));
        assert!(matches!(
            AuthError::from(AuthClientError::InvalidOptions("y".to_string())),
            AuthError::InvalidOptions(_)
        ));
    }
}
