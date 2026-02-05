//! UniFFI bindings for the native auth client.

use crate::{AuthClientLoginOptions, NativeAuthClient};
#[cfg(feature = "keyring")]
use crate::{
    NativeAuthClientCreateOptions, key::BaseKeyType, storage::sync_storage::KeyringStorage,
};
use ic_agent::identity::Identity;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use serde_json::Map;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

#[cfg(feature = "keyring")]
#[uniffi::export]
/// Enable a mock keyring backend for local development.
///
/// Call this before creating an `AuthClient` to avoid touching the OS keyring.
pub fn enable_keyring_mock() {
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
}

#[derive(uniffi::Record, Clone, Default)]
/// Options for building login URLs and starting login flows.
pub struct LoginOptions {
    /// Custom identity provider URL (defaults to Internet Identity if `None`).
    pub identity_provider: Option<String>,
    /// Maximum session TTL in nanoseconds.
    pub max_time_to_live: Option<u64>,
    /// Allow PIN-based authentication when supported.
    pub allow_pin_authentication: Option<bool>,
    /// Derivation origin to use for the session.
    pub derivation_origin: Option<String>,
    /// Browser window features (desktop only).
    pub window_opener_features: Option<String>,
    /// Request timeout in milliseconds.
    pub timeout_millis: Option<u64>,
    /// Custom values JSON to pass through to the identity provider.
    pub custom_values_json: Option<String>,
}

#[derive(uniffi::Enum, Debug, Clone)]
/// Errors exposed by the UniFFI bindings.
pub enum AuthError {
    /// A generic error message.
    Message(String),
    /// Invalid JSON in `custom_values_json`.
    InvalidCustomValues(String),
    /// Failed to derive or serialize a principal.
    Principal(String),
    /// Signature creation failed.
    Signature(String),
    /// Key retrieval or parsing failed.
    Key(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Message(message) => write!(f, "{}", message),
            AuthError::InvalidCustomValues(message) => write!(f, "{}", message),
            AuthError::Principal(message) => write!(f, "{}", message),
            AuthError::Signature(message) => write!(f, "{}", message),
            AuthError::Key(message) => write!(f, "{}", message),
        }
    }
}

#[derive(uniffi::Object)]
/// High-level authentication client for native platforms.
pub struct AuthClient {
    inner: NativeAuthClient,
}

#[uniffi::export]
impl AuthClient {
    #[uniffi::constructor]
    /// Create a new client using the provided service name.
    pub fn new(service_name: String) -> Result<Arc<Self>, AuthError> {
        #[cfg(feature = "keyring")]
        {
            #[cfg(feature = "swift")]
            let options = NativeAuthClientCreateOptions::builder()
                .storage(KeyringStorage::new(service_name))
                .key_type(BaseKeyType::Secp256k1)
                .build();
            #[cfg(not(feature = "swift"))]
            let options = NativeAuthClientCreateOptions::builder()
                .storage(KeyringStorage::new(service_name))
                .build();
            NativeAuthClient::new_with_options(options)
                .map(|inner| Arc::new(AuthClient { inner }))
                .map_err(|e| AuthError::Message(e.to_string()))
        }
        #[cfg(not(feature = "keyring"))]
        {
            NativeAuthClient::new(service_name)
                .map(|inner| Arc::new(AuthClient { inner }))
                .map_err(|e| AuthError::Message(e.to_string()))
        }
    }

    pub fn build_login_url(
        &self,
        auth_bridge_url: String,
        redirect_uri: String,
        options: LoginOptions,
    ) -> Result<String, AuthError> {
        let mut opts = AuthClientLoginOptions {
            identity_provider: options.identity_provider,
            max_time_to_live: options.max_time_to_live,
            allow_pin_authentication: options.allow_pin_authentication,
            derivation_origin: options.derivation_origin,
            window_opener_features: options.window_opener_features,
            timeout: options.timeout_millis.map(Duration::from_millis),
            ..Default::default()
        };

        if let Some(custom_json) = options.custom_values_json {
            let map: Map<String, serde_json::Value> = serde_json::from_str(&custom_json)
                .map_err(|e| AuthError::InvalidCustomValues(e.to_string()))?;
            opts.custom_values = Some(map);
        }

        self.inner
            .build_login_url(auth_bridge_url, &redirect_uri, opts)
            .map_err(|e| AuthError::Message(e.to_string()))
    }

    pub fn finish_login_from_payload(&self, payload: String) -> Result<(), AuthError> {
        self.inner
            .finish_login_from_payload(&payload)
            .map_err(|e| AuthError::Message(e.to_string()))
    }

    pub fn is_authenticated(&self) -> bool {
        self.inner.is_authenticated()
    }

    /// Return the authenticated principal as a text string.
    pub fn principal_text(&self) -> Result<String, AuthError> {
        self.inner
            .principal()
            .map(|principal| principal.to_text())
            .map_err(AuthError::Principal)
    }

    /// Return the base key type used by the client, if known.
    pub fn base_key_type(&self) -> Option<String> {
        self.inner.base_key_type().map(|k| k.to_string())
    }

    /// Return the uncompressed secp256k1 public key for the current identity.
    pub fn secp256k1_uncompressed_public_key(&self) -> Result<Vec<u8>, AuthError> {
        self.inner
            .secp256k1_uncompressed_public_key()
            .map_err(AuthError::Key)
    }

    /// Return the secp256k1 private key for the current identity.
    pub fn secp256k1_private_key(&self) -> Result<Vec<u8>, AuthError> {
        self.inner.secp256k1_private_key().map_err(AuthError::Key)
    }

    /// Return the delegation chain as JSON, if present.
    pub fn delegation_chain_json(&self) -> Option<String> {
        self.inner.delegation_chain_json()
    }

    /// Sign an Internet Computer request using the current identity.
    pub fn sign_ic_request(&self, message: Vec<u8>, domain: String) -> Result<Vec<u8>, AuthError> {
        let private_key = self.inner.secp256k1_private_key().map_err(AuthError::Key)?;
        sign_ic_request_with_key(&private_key, &message, &domain).map_err(AuthError::Signature)
    }

    /// Return the underlying identity for direct cryptographic operations.
    pub fn identity(&self) -> Arc<AuthIdentity> {
        Arc::new(AuthIdentity {
            inner: self.inner.identity(),
        })
    }

    /// Clear any stored credentials.
    pub fn logout(&self) {
        self.inner.logout();
    }
}

fn sign_ic_request_with_key(
    private_key: &[u8],
    message: &[u8],
    domain: &str,
) -> Result<Vec<u8>, String> {
    let hash = sha256(domain_separated_data(domain, message));
    let key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| "secp256k1 private key must be 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_bytes.into())
        .map_err(|e| format!("invalid secp256k1 key: {e}"))?;
    let signature: Signature = signing_key
        .sign_prehash(&hash)
        .map_err(|e| format!("signing failed: {e}"))?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(signature.to_bytes().to_vec())
}

fn domain_separated_data(domain: &str, message: &[u8]) -> Vec<u8> {
    let mut out = leb128_encode_u64(domain.len() as u64);
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(message);
    out
}

fn sha256(data: Vec<u8>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().into()
}

fn leb128_encode_u64(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

#[uniffi::export]
impl AuthClient {
    /// Start a desktop login flow using a local callback server.
    ///
    /// This is only supported on macOS, Linux, and Windows.
    pub fn login(&self, auth_bridge_url: String, options: LoginOptions) -> Result<(), AuthError> {
        let mut opts = AuthClientLoginOptions {
            identity_provider: options.identity_provider,
            max_time_to_live: options.max_time_to_live,
            allow_pin_authentication: options.allow_pin_authentication,
            derivation_origin: options.derivation_origin,
            window_opener_features: options.window_opener_features,
            timeout: options.timeout_millis.map(Duration::from_millis),
            ..Default::default()
        };

        if let Some(custom_json) = options.custom_values_json {
            let map: Map<String, serde_json::Value> = serde_json::from_str(&custom_json)
                .map_err(|e| AuthError::InvalidCustomValues(e.to_string()))?;
            opts.custom_values = Some(map);
        }

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            self.inner.login(auth_bridge_url, opts);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err(AuthError::Message(
                "login is only supported on desktop targets; use AuthSession on iOS".to_string(),
            ))
        }
    }
}

#[derive(uniffi::Object)]
/// A concrete identity instance associated with an `AuthClient`.
pub struct AuthIdentity {
    inner: Arc<dyn Identity>,
}

#[uniffi::export]
impl AuthIdentity {
    /// Return the identity principal as text.
    pub fn principal_text(&self) -> Result<String, AuthError> {
        self.inner
            .sender()
            .map(|principal| principal.to_text())
            .map_err(AuthError::Principal)
    }

    /// Return the DER-encoded public key for the identity, if available.
    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        self.inner.public_key()
    }

    /// Sign an arbitrary message with the identity.
    pub fn sign_arbitrary(&self, message: Vec<u8>) -> Result<Vec<u8>, AuthError> {
        let signature = self
            .inner
            .sign_arbitrary(&message)
            .map_err(AuthError::Signature)?;
        signature
            .signature
            .ok_or_else(|| AuthError::Signature("Signature missing".to_string()))
    }

    /// Return the delegation chain as JSON, if present.
    pub fn delegation_chain_json(&self) -> Option<String> {
        let delegations = self.inner.delegation_chain();
        if delegations.is_empty() {
            return None;
        }
        let public_key = self.inner.public_key().unwrap_or_default();
        let chain = crate::util::delegation_chain::DelegationChain::new(delegations, public_key);
        Some(chain.to_json())
    }
}
