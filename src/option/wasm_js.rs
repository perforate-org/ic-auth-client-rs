//! Browser based authentication client configuration and options.

use crate::{
    ArcIdentity, IdleOptions, key::BaseKeyType, storage::async_storage::AuthClientStorage,
};

/// Options for creating a new [`AuthClient`].
#[derive(Default, bon::Builder)]
pub struct AuthClientCreateOptions {
    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub identity: Option<ArcIdentity>,
    /// Optional storage with get, set, and remove methods. If not provided, `IdbStorage` (or
    /// `LocalStorage` as a fallback) will be used.
    #[builder(into)]
    pub storage: Option<Box<dyn AuthClientStorage>>,
    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub key_type: Option<BaseKeyType>,
    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub idle_options: Option<IdleOptions>,
}
