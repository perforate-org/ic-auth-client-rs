#[cfg(feature = "keyring")]
use crate::storage::sync_storage::KeyringStorage;
#[cfg(feature = "pem")]
use crate::storage::{StorageError, sync_storage::PemStorage};
use crate::{
    ArcIdentity, AuthClientError,
    api::AuthResponseSuccess,
    idle_manager::{IdleManager, IdleManagerOptions},
    key::{BaseKeyType, Key, KeyWithRaw},
    option::{AuthClientLoginOptions, IdleOptions, native::NativeAuthClientCreateOptions},
    storage::{
        KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, KEY_STORAGE_KEY_TYPE, StoredKey,
        sync_storage::AuthClientStorage,
    },
    util::{callback::OnSuccess, delegation_chain::DelegationChain},
};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use futures::{channel::oneshot, executor::block_on};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity, SignedDelegation},
};
use k256::SecretKey as K256SecretKey;
use p256::SecretKey as P256SecretKey;
use parking_lot::Mutex;
use serde_json::Number;
use std::{fmt, sync::Arc, thread, time::Duration};
#[cfg(feature = "pem")]
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use tiny_http::{Response, Server};
use url::Url;

/// Errors that can occur during the login process.
///
/// This enum represents all the possible error conditions that may arise
/// when attempting to authenticate a user through the Internet Identity
/// authentication flow.
#[derive(Debug, thiserror::Error)]
pub enum NativeLoginError {
    /// No free ports are available on the local machine to start the callback server.
    #[error("No free ports available")]
    NoFreePort,
    /// An error occurred while starting or running the local HTTP server.
    #[error("Server error: {0}")]
    ServerError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Failed to parse a URL during the authentication process.
    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
    /// Failed to open the user's default web browser for authentication.
    #[error("Failed to open browser: {0}")]
    BrowserOpenError(String),
    /// The server timed out while waiting for the authentication callback.
    #[error("Server receive timed out")]
    ServerTimeout,
    /// The server thread handling the authentication callback panicked.
    #[error("Server thread panicked")]
    ServerThreadPanicked,
    /// Failed to receive the delegation response through the internal message channel.
    #[error("Failed to receive delegation")]
    OneshotRecvError,
    /// Failed to deserialize the JSON response from the identity provider.
    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    /// An error occurred while processing the delegation chain.
    #[error("Delegation error: {0}")]
    DelegationError(#[from] DelegationError),
    /// The authentication callback was missing required delegation or error parameters.
    #[error("Missing delegation or error parameter in redirect")]
    MissingDelegationOrError,
    /// The callback server received a request to an unexpected URL path.
    #[error("Unexpected request path: {0}")]
    UnexpectedRequestPath(String),
    /// A custom error occurred during authentication.
    #[error("Custom error: {0}")]
    Custom(String),
}

enum CallbackResult {
    Success(AuthResponseSuccess),
    Error(NativeLoginError),
}

pub(super) struct AuthClientInner {
    pub identity: Arc<Mutex<ArcIdentity>>,
    pub key: Key,
    pub storage: Mutex<Box<dyn AuthClientStorage>>,
    pub chain: Arc<Mutex<Option<DelegationChain>>>,
    pub idle_manager: Mutex<Option<IdleManager>>,
    pub idle_options: Option<IdleOptions>,
}

impl fmt::Debug for AuthClientInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthClientInner")
            .field("key", &self.key)
            .field("idle_options", &self.idle_options)
            .finish()
    }
}

/// The tool for managing authentication and identity.
///
/// It maintains the state of the user's identity and provides methods for authentication.
#[derive(Clone, Debug)]
pub struct NativeAuthClient(Arc<AuthClientInner>);

impl NativeAuthClient {
    /// Creates a new [`AuthClient`] with default options.
    #[cfg(feature = "keyring")]
    pub fn new<T: AsRef<str>>(service_name: T) -> Result<Self, AuthClientError> {
        let options = NativeAuthClientCreateOptions::builder()
            .storage(KeyringStorage::new(service_name.as_ref()))
            .build();
        Self::new_with_options(options)
    }

    /// Creates a new [`AuthClient`] using the first PEM file found inside the provided directory.
    #[cfg(feature = "pem")]
    pub fn new_with_pem_directory<T, P>(
        service_name: T,
        directory: P,
    ) -> Result<Self, AuthClientError>
    where
        T: Into<String>,
        P: Into<PathBuf>,
    {
        let service_name = service_name.into();
        let directory = directory.into();

        let mut storage_dir = directory.clone();
        storage_dir.push(format!(
            "ic-auth-client-{}",
            sanitize_service_name(&service_name)
        ));

        let mut storage = PemStorage::new(storage_dir);

        let key_exists = storage.get(KEY_STORAGE_KEY)?.is_some();

        if !key_exists {
            if let Some(pem_path) = find_pem_file_in_directory(&directory)? {
                storage.import_private_key_from_pem_file(pem_path)?;
            }
        }

        let options = NativeAuthClientCreateOptions::builder()
            .storage(storage)
            .build();
        Self::new_with_options(options)
    }

    /// Creates a new key if one is not found in storage, otherwise loads the existing key.
    fn create_or_load_key(
        identity: Option<ArcIdentity>,
        storage: &mut dyn AuthClientStorage,
        key_type: Option<BaseKeyType>,
    ) -> Result<Key, AuthClientError> {
        match identity {
            Some(identity) => Ok(Key::Identity(identity)),
            None => {
                let stored_key_type = match storage.get(KEY_STORAGE_KEY_TYPE) {
                    Ok(Some(stored)) => {
                        let value = stored.encode();
                        value.parse::<BaseKeyType>().ok()
                    }
                    Ok(None) => None,
                    Err(e) => return Err(e.into()),
                };

                match storage.get(KEY_STORAGE_KEY) {
                    Ok(Some(stored_key)) => {
                        let private_key = stored_key.decode().map_err(|e| {
                            DelegationError::IdentityError(format!(
                                "Failed to decode private key: {}",
                                e
                            ))
                        })?;
                        let key_with_raw = if let Some(stored_key_type) = stored_key_type {
                            KeyWithRaw::new_with_type(stored_key_type, private_key)?
                        } else if private_key.len() == 32 {
                            KeyWithRaw::new_with_type(BaseKeyType::Ed25519, private_key)?
                        } else {
                            KeyWithRaw::new_with_type(BaseKeyType::Prime256v1, private_key.clone())
                                .or_else(|_| {
                                    KeyWithRaw::new_with_type(BaseKeyType::Secp256k1, private_key)
                                })?
                        };

                        if stored_key_type.is_none() {
                            let _ = storage.set(
                                KEY_STORAGE_KEY_TYPE,
                                StoredKey::String(key_with_raw.key_type().to_string()),
                            );
                        }

                        Ok(Key::WithRaw(key_with_raw))
                    }
                    Ok(None) => {
                        let key_type = key_type.unwrap_or_default();
                        let private_key = Self::generate_key_material(key_type)?;
                        storage.set(KEY_STORAGE_KEY, StoredKey::Raw(private_key.clone()))?;
                        storage.set(
                            KEY_STORAGE_KEY_TYPE,
                            StoredKey::String(key_type.to_string()),
                        )?;
                        Ok(Key::WithRaw(KeyWithRaw::new_with_type(
                            key_type,
                            private_key,
                        )?))
                    }
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    fn generate_key_material(
        key_type: BaseKeyType,
    ) -> Result<Vec<u8>, crate::storage::DecodeError> {
        match key_type {
            BaseKeyType::Ed25519 => {
                let mut rng = rand::rngs::OsRng;
                let private_key = SigningKey::generate(&mut rng).to_bytes();
                Ok(private_key.to_vec())
            }
            BaseKeyType::Prime256v1 => {
                let mut rng = rand::rngs::OsRng;
                let secret = P256SecretKey::random(&mut rng);
                let der = secret.to_sec1_der().map_err(|e| {
                    crate::storage::DecodeError::Key(format!("Prime256v1 key encoding error: {e}"))
                })?;
                let bytes: Vec<u8> = der.to_vec();
                Ok(bytes)
            }
            BaseKeyType::Secp256k1 => {
                let mut rng = rand::rngs::OsRng;
                let secret = K256SecretKey::random(&mut rng);
                let der = secret.to_sec1_der().map_err(|e| {
                    crate::storage::DecodeError::Key(format!("Secp256k1 key encoding error: {e}"))
                })?;
                let bytes: Vec<u8> = der.to_vec();
                Ok(bytes)
            }
        }
    }

    /// Extracts delegation data from a delegation chain if it is valid.
    fn get_delegation_data(
        chain: &Option<DelegationChain>,
    ) -> Option<(Vec<u8>, Vec<SignedDelegation>)> {
        if let Some(chain_inner) = chain.as_ref() {
            if chain_inner.is_delegation_valid(None) {
                let public_key = chain_inner.public_key.clone();
                let delegations = chain_inner.delegations.clone();
                Some((public_key, delegations))
            } else {
                None
            }
        } else {
            Some((Vec::new(), Vec::new()))
        }
    }

    /// Loads a delegation chain from storage and updates the identity if the chain is valid.
    fn load_delegation_chain(
        storage: &mut dyn AuthClientStorage,
        key: &Key,
    ) -> (Option<DelegationChain>, ArcIdentity) {
        let mut identity = ArcIdentity::from(key.clone());
        let mut chain: Option<DelegationChain> = None;

        match storage.get(KEY_STORAGE_DELEGATION) {
            Ok(Some(chain_stored)) => {
                let chain_stored = chain_stored.encode();
                let chain_result = DelegationChain::from_json(&chain_stored);
                chain = Some(chain_result);

                let delegation_data = Self::get_delegation_data(&chain);

                match delegation_data {
                    Some((public_key, delegations)) => {
                        if !public_key.is_empty() {
                            identity =
                                ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                                    public_key,
                                    Box::new(key.as_arc_identity()),
                                    delegations,
                                )));
                        }
                    }
                    None => {
                        #[cfg(feature = "tracing")]
                        info!("Found invalid delegation chain in storage - clearing credentials");
                        let _ = Self::delete_storage_native(storage);
                        identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
                        chain = None;
                    }
                }
            }
            Ok(None) => (),
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Failed to load delegation chain from storage: {}", _e);
            }
        }
        (chain, identity)
    }

    /// Creates an idle manager if idle detection is not disabled.
    fn create_idle_manager(
        idle_options: &Option<IdleOptions>,
        chain: &Option<DelegationChain>,
        identity_is_some: bool,
    ) -> Option<IdleManager> {
        if !idle_options
            .as_ref()
            .and_then(|o| o.disable_idle)
            .unwrap_or(false)
            && (chain.is_some() || identity_is_some)
        {
            let idle_manager_options: Option<IdleManagerOptions> = idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            Some(IdleManager::new(idle_manager_options))
        } else {
            None
        }
    }

    /// Creates a new [`AuthClient`] with the provided options.
    pub fn new_with_options(
        options: NativeAuthClientCreateOptions,
    ) -> Result<Self, AuthClientError> {
        let identity = options.identity.clone();
        let options_identity_is_some = identity.is_some();
        let mut storage = options.storage;

        let key = Self::create_or_load_key(identity, storage.as_mut(), options.key_type)?;

        let (chain, identity) = Self::load_delegation_chain(storage.as_mut(), &key);

        let idle_manager =
            Self::create_idle_manager(&options.idle_options, &chain, options_identity_is_some);

        Ok(Self(Arc::new(AuthClientInner {
            identity: Arc::new(Mutex::new(identity)),
            key,
            storage: Mutex::new(storage),
            chain: Arc::new(Mutex::new(chain)),
            idle_manager: Mutex::new(idle_manager),
            idle_options: options.idle_options,
        })))
    }

    /// Registers the default idle callback, which logs the user out on idle.
    fn register_default_idle_callback_native(&self) {
        if let Some(options) = self.0.idle_options.as_ref() {
            if options.disable_default_idle_callback.unwrap_or_default() {
                return;
            }

            if options.idle_manager_options.on_idle.lock().is_empty() {
                if let Some(idle_manager) = self.0.idle_manager.lock().as_ref() {
                    let client = self.clone();
                    let callback = move || {
                        client.logout();
                    };
                    idle_manager.register_callback(callback);
                }
            }
        }
    }

    /// Returns the identity of the user.
    pub fn identity(&self) -> Arc<dyn Identity> {
        self.0.identity.lock().as_arc_identity()
    }

    /// Returns the principal of the user.
    pub fn principal(&self) -> Result<Principal, String> {
        self.identity().sender()
    }

    /// Checks if the user is authenticated.
    pub fn is_authenticated(&self) -> bool {
        let is_not_anonymous = self
            .identity()
            .sender()
            .map(|s| s != Principal::anonymous())
            .unwrap_or(false);

        let is_valid_chain = self
            .0
            .chain
            .lock()
            .as_ref()
            .is_some_and(|c| c.is_delegation_valid(None));

        is_not_anonymous && is_valid_chain
    }

    /// Returns the idle manager if it exists.
    pub fn idle_manager(&self) -> Option<IdleManager> {
        self.0.idle_manager.lock().clone()
    }

    /// Handles a successful authentication response.
    fn handle_success(
        &self,
        message: AuthResponseSuccess,
        on_success: Option<OnSuccess>,
    ) -> Result<(), DelegationError> {
        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        let delegation_chain = DelegationChain {
            delegations: delegations.clone(),
            public_key: user_public_key.clone(),
        };

        self.update_storage_with_delegation(&delegation_chain);
        self.update_identity_with_delegation(
            &delegation_chain,
            user_public_key.clone(),
            delegations.clone(),
        );

        self.verify_and_fix_authentication(
            &user_public_key,
            &delegations,
            &delegation_chain.to_json(),
        );

        self.maybe_create_idle_manager();

        if let Some(on_success_cb) = on_success {
            on_success_cb.0.lock()(message.clone());
        }

        Ok(())
    }

    /// Stores the delegation chain and key in storage.
    fn update_storage_with_delegation(&self, delegation_chain: &DelegationChain) {
        if let Key::WithRaw(key) = &self.0.key {
            if let Err(_e) = self
                .0
                .storage
                .lock()
                .set(KEY_STORAGE_KEY, StoredKey::Raw(key.raw_key().to_vec()))
            {
                #[cfg(feature = "tracing")]
                error!("Failed to store key: {}", _e);
            }
            if let Err(_e) = self.0.storage.lock().set(
                KEY_STORAGE_KEY_TYPE,
                StoredKey::String(key.key_type().to_string()),
            ) {
                #[cfg(feature = "tracing")]
                error!("Failed to store key type: {}", _e);
            }
        }

        let chain_json = delegation_chain.to_json();
        if let Err(_e) = self.0.storage.lock().set(
            KEY_STORAGE_DELEGATION,
            StoredKey::String(chain_json.clone()),
        ) {
            #[cfg(feature = "tracing")]
            error!("Failed to store delegation: {}", _e);
        }
    }

    /// Updates the in-memory identity with the new delegation.
    fn update_identity_with_delegation(
        &self,
        delegation_chain: &DelegationChain,
        user_public_key: Vec<u8>,
        delegations: Vec<SignedDelegation>,
    ) {
        *self.0.chain.lock() = Some(delegation_chain.clone());
        *self.0.identity.lock() =
            ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                user_public_key,
                Box::new(self.0.key.as_arc_identity()),
                delegations,
            )));
    }

    /// Verifies that the user is authenticated and attempts to fix the state if not.
    fn verify_and_fix_authentication(
        &self,
        user_public_key: &[u8],
        delegations: &[SignedDelegation],
        chain_json: &str,
    ) {
        if self.is_authenticated() {
            return;
        }

        #[cfg(feature = "tracing")]
        warn!("CRITICAL: is_authenticated() returned false after successful login");

        let _is_not_anonymous = self
            .identity()
            .sender()
            .map(|s| s != Principal::anonymous())
            .unwrap_or(false);
        let _has_chain = self.0.chain.lock().is_some();
        #[cfg(feature = "tracing")]
        debug!(
            "is_authenticated(): is_not_anonymous={}, has_chain={}",
            _is_not_anonymous, _has_chain
        );

        *self.0.chain.lock() = Some(DelegationChain::from_json(chain_json));

        let is_auth_retry = self.is_authenticated();
        #[cfg(feature = "tracing")]
        debug!("After fix attempt: is_authenticated() = {}", is_auth_retry);

        if !is_auth_retry {
            if let Ok(_principal) = self.identity().sender() {
                #[cfg(feature = "tracing")]
                debug!("Current principal: {}", _principal);
            }

            *self.0.identity.lock() =
                ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                    user_public_key.to_vec(),
                    Box::new(self.0.key.as_arc_identity()),
                    delegations.to_vec(),
                )));

            let _final_auth_check = self.is_authenticated();
            #[cfg(feature = "tracing")]
            debug!("Final check: is_authenticated() = {}", _final_auth_check);
        }
    }

    /// Creates an idle manager if one does not exist and idle detection is not disabled.
    fn maybe_create_idle_manager(&self) {
        let disable_idle = self
            .0
            .idle_options
            .as_ref()
            .and_then(|o| o.disable_idle)
            .unwrap_or(false);

        if self.0.idle_manager.lock().is_none() && !disable_idle {
            let idle_manager_options = self
                .0
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            let new_idle_manager = IdleManager::new(idle_manager_options);
            *self.0.idle_manager.lock() = Some(new_idle_manager);

            if self.0.idle_manager.lock().is_some() {
                self.register_default_idle_callback_native();
            }
        }
    }

    /// Handles the redirect from the identity provider.
    fn handle_get_redirect(request: tiny_http::Request, tx: oneshot::Sender<CallbackResult>) {
        let url = match Url::parse(&format!("http://localhost{}", request.url())) {
            Ok(url) => url,
            Err(e) => {
                Self::respond_with_html_error(
                    request,
                    tx,
                    NativeLoginError::UrlParseError(e),
                    "Login window closed or redirect failed.",
                );
                return;
            }
        };

        let payload = url
            .query_pairs()
            .find(|(key, _)| key == "payload")
            .map(|(_, value)| value.into_owned());

        let Some(payload_value) = payload else {
            Self::respond_with_html_error(
                request,
                tx,
                NativeLoginError::MissingDelegationOrError,
                "Missing authentication payload.",
            );
            return;
        };

        let mut json = match Self::deserialize_payload(&payload_value) {
            Ok(json) => json,
            Err(err) => {
                let message = match err {
                    NativeLoginError::JsonError(_) => "Failed to parse authentication payload.",
                    _ => "Invalid authentication payload.",
                };
                Self::respond_with_html_error(request, tx, err, message);
                return;
            }
        };

        if let Err(err) = Self::normalize_delegations(&mut json) {
            Self::respond_with_html_error(request, tx, err, "Invalid authentication payload.");
            return;
        }

        Self::respond_with_callback(request, tx, Self::process_auth_payload(json, true));
    }

    /// Handles incoming POST requests with authentication data.
    fn handle_post_callback(request: tiny_http::Request, tx: oneshot::Sender<CallbackResult>) {
        let mut request = request;
        let mut content = String::new();
        if let Err(e) = request.as_reader().read_to_string(&mut content) {
            let _ = tx.send(CallbackResult::Error(NativeLoginError::ServerError(
                Box::new(e),
            )));
            let _ = request.respond(Self::cors_response("Error reading request body", 500));
            return;
        }

        let mut json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(json) => json,
            Err(e) => {
                let _ = tx.send(CallbackResult::Error(NativeLoginError::JsonError(e)));
                let _ = request.respond(Self::cors_response("Error parsing JSON body", 400));
                return;
            }
        };

        if let Err(err) = Self::normalize_delegations(&mut json) {
            let _ = tx.send(CallbackResult::Error(err));
            let _ = request.respond(Self::cors_response("Invalid authentication payload", 400));
            return;
        }

        Self::respond_with_callback(request, tx, Self::process_auth_payload(json, false));
    }

    fn process_auth_payload(
        json: serde_json::Value,
        render_html: bool,
    ) -> (Response<std::io::Cursor<Vec<u8>>>, CallbackResult) {
        let response_type = json["type"].as_str();

        match response_type {
            Some("success") => {
                match serde_json::from_value::<AuthResponseSuccess>(json["data"].clone()) {
                    Ok(success_data) => {
                        let response = if render_html {
                            Self::html_response(
                                "<h1>Login successful</h1><p>You can close this window.</p>",
                                200,
                            )
                        } else {
                            Self::cors_response("OK", 200)
                        };
                        (response, CallbackResult::Success(success_data))
                    }
                    Err(e) => {
                        let response = if render_html {
                            Self::html_response(
                                "<h1>Login failed</h1><p>Invalid success payload.</p>",
                                400,
                            )
                        } else {
                            Self::cors_response("Error parsing success data", 400)
                        };
                        (
                            response,
                            CallbackResult::Error(NativeLoginError::JsonError(e)),
                        )
                    }
                }
            }
            Some("error") => {
                let error_message = json["data"].as_str().unwrap_or("Unknown error").to_string();
                let response = if render_html {
                    Self::html_response(
                        &format!("<h1>Login failed</h1><p>{}</p>", error_message),
                        400,
                    )
                } else {
                    Self::cors_response("Error", 200)
                };
                (
                    response,
                    CallbackResult::Error(NativeLoginError::Custom(error_message)),
                )
            }
            _ => {
                let response = if render_html {
                    Self::html_response("<h1>Login failed</h1><p>Invalid response type.</p>", 400)
                } else {
                    Self::cors_response("Invalid response type", 400)
                };
                (
                    response,
                    CallbackResult::Error(NativeLoginError::Custom(
                        "Invalid response type".to_string(),
                    )),
                )
            }
        }
    }

    fn respond_with_html_error(
        request: tiny_http::Request,
        tx: oneshot::Sender<CallbackResult>,
        error: NativeLoginError,
        message: &str,
    ) {
        let _ = tx.send(CallbackResult::Error(error));
        let body = format!("<h1>Login failed</h1><p>{}</p>", message);
        let _ = request.respond(Self::html_response(&body, 400));
    }

    fn respond_with_callback(
        request: tiny_http::Request,
        tx: oneshot::Sender<CallbackResult>,
        outcome: (Response<std::io::Cursor<Vec<u8>>>, CallbackResult),
    ) {
        let (response, callback_result) = outcome;
        let _ = tx.send(callback_result);
        let _ = request.respond(response);
    }

    fn html_response(body: &str, status_code: u16) -> Response<std::io::Cursor<Vec<u8>>> {
        Response::from_string(body)
            .with_status_code(status_code)
            .with_header(
                tiny_http::Header::from_bytes(b"Content-Type", b"text/html; charset=utf-8")
                    .unwrap(),
            )
    }

    fn cors_response(body: &str, status_code: u16) -> Response<std::io::Cursor<Vec<u8>>> {
        let mut response = Response::from_string(body).with_status_code(status_code);
        response = response.with_header(
            tiny_http::Header::from_bytes(b"Access-Control-Allow-Origin", b"*").unwrap(),
        );
        response = response.with_header(
            tiny_http::Header::from_bytes(b"Access-Control-Allow-Headers", b"Content-Type")
                .unwrap(),
        );
        response = response.with_header(
            tiny_http::Header::from_bytes(b"Access-Control-Allow-Methods", b"POST, OPTIONS")
                .unwrap(),
        );
        response.with_header(
            tiny_http::Header::from_bytes(b"Access-Control-Allow-Private-Network", b"true")
                .unwrap(),
        )
    }

    fn deserialize_payload(payload: &str) -> Result<serde_json::Value, NativeLoginError> {
        let decoded_payload = BASE64_STANDARD
            .decode(payload.as_bytes())
            .map_err(|e| NativeLoginError::Custom(format!("Invalid payload encoding: {}", e)))?;
        let mut json = serde_json::from_slice(&decoded_payload)?;
        Self::normalize_delegations(&mut json)?;
        Ok(json)
    }

    fn normalize_delegations(json: &mut serde_json::Value) -> Result<(), NativeLoginError> {
        let Some(data) = json.get_mut("data") else {
            return Ok(());
        };

        let Some(delegations) = data.get_mut("delegations").and_then(|d| d.as_array_mut()) else {
            return Ok(());
        };

        for delegation in delegations.iter_mut() {
            let Some(expiration_value) = delegation
                .get_mut("delegation")
                .and_then(|d| d.get_mut("expiration"))
            else {
                continue;
            };

            if let Some(exp_str) = expiration_value.as_str() {
                let parsed = exp_str.parse::<u64>().map_err(|e| {
                    NativeLoginError::Custom(format!("Invalid delegation expiration: {}", e))
                })?;
                *expiration_value = serde_json::Value::Number(Number::from(parsed));
            }
        }

        Ok(())
    }

    /// Finishes the login process after the delegation has been received.
    async fn finish_login(
        &self,
        rx: oneshot::Receiver<CallbackResult>,
        on_success: Option<OnSuccess>,
    ) -> Result<(), NativeLoginError> {
        let callback_result = rx.await.map_err(|_| NativeLoginError::OneshotRecvError)?;

        match callback_result {
            CallbackResult::Success(auth_success) => {
                match self.handle_success(auth_success, on_success) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(NativeLoginError::DelegationError(e)),
                }
            }
            CallbackResult::Error(e) => Err(e),
        }
    }

    /// Logs the user in by opening a browser window to the identity provider.
    pub fn login<T: AsRef<str> + Send + 'static>(
        &self,
        ii_url: T,
        options: AuthClientLoginOptions,
    ) {
        let client = self.clone();
        let ii_url = ii_url.as_ref().to_string();

        thread::spawn(move || {
            let on_error = options.on_error.clone();
            if let Err(e) = block_on(client.login_task(ii_url, options)) {
                if let Some(on_error) = on_error {
                    on_error.0.lock()(Some(e.to_string()));
                }
            }
        });
    }

    fn start_http_server(server: Server, tx: oneshot::Sender<CallbackResult>, timeout: Duration) {
        thread::spawn(move || {
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < timeout {
                let request = match server.recv_timeout(Duration::from_millis(500)) {
                    Ok(Some(request)) => request,
                    Ok(None) => continue,
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        error!("Server error while receiving request: {}", e);
                        let _ = tx.send(CallbackResult::Error(NativeLoginError::ServerError(
                            Box::new(e),
                        )));
                        return;
                    }
                };

                if request.method() == &tiny_http::Method::Options
                    && request.url().starts_with("/auth-callback")
                {
                    let response = Self::cors_response("", 204);
                    if let Err(_e) = request.respond(response) {
                        #[cfg(feature = "tracing")]
                        error!("Failed to respond to OPTIONS request: {}", _e);
                    }
                    continue;
                }

                let handler: Option<fn(tiny_http::Request, oneshot::Sender<CallbackResult>)> =
                    if request.method() == &tiny_http::Method::Post
                        && request.url().starts_with("/auth-callback")
                    {
                        Some(Self::handle_post_callback)
                    } else if request.method() == &tiny_http::Method::Get
                        && request.url().starts_with("/auth-callback")
                    {
                        Some(Self::handle_get_redirect)
                    } else {
                        None
                    };

                if let Some(handler_fn) = handler {
                    handler_fn(request, tx);
                    return;
                }

                // Fallback for any other request.
                let response = Response::from_string("").with_status_code(204);
                if let Err(_e) = request.respond(response) {
                    #[cfg(feature = "tracing")]
                    error!("Failed to respond to unexpected request: {}", _e);
                }
            }

            let _ = tx.send(CallbackResult::Error(NativeLoginError::ServerTimeout));
        });
    }

    async fn login_task<T: AsRef<str>>(
        &self,
        ii_url: T,
        options: AuthClientLoginOptions,
    ) -> Result<(), NativeLoginError> {
        let port = portpicker::pick_unused_port().ok_or(NativeLoginError::NoFreePort)?;
        let redirect_uri = format!("http://127.0.0.1:{}/auth-callback", port);

        let server = Server::http(format!("127.0.0.1:{}", port))?;
        let (tx, rx) = oneshot::channel::<CallbackResult>();

        let public_key_hex = hex::encode(self.0.key.public_key().unwrap());
        let key_type = match &self.0.key {
            Key::WithRaw(key) => Some(key.key_type()),
            Key::Identity(identity) => BaseKeyType::from_identity(identity),
        };

        let mut url = Url::parse(ii_url.as_ref()).map_err(NativeLoginError::UrlParseError)?;
        Self::set_query_params(&mut url, &options, &redirect_uri, &public_key_hex, key_type);

        webbrowser::open(url.as_str())
            .map_err(|e| NativeLoginError::BrowserOpenError(e.to_string()))?;

        let timeout = options.timeout.unwrap_or(Duration::from_secs(300));
        Self::start_http_server(server, tx, timeout);

        self.finish_login(rx, options.on_success).await
    }

    /// Sets the query parameters for the identity provider URL.
    fn set_query_params(
        url: &mut Url,
        options: &AuthClientLoginOptions,
        redirect_uri: &str,
        public_key_hex: &str,
        key_type: Option<BaseKeyType>,
    ) {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs
            .append_pair("redirectUri", redirect_uri)
            .append_pair("pubkey", public_key_hex);
        if let Some(key_type) = key_type {
            query_pairs.append_pair("keyType", &key_type.to_string());
        }

        if let Some(ref identity_provider) = options.identity_provider {
            query_pairs.append_pair("identityProvider", identity_provider);
        }

        if let Some(ref max_time_to_live) = options.max_time_to_live {
            query_pairs.append_pair("maxTimeToLive", &max_time_to_live.to_string());
        }

        if let Some(ref allow_pin_authentication) = options.allow_pin_authentication {
            query_pairs.append_pair(
                "allowPinAuthentication",
                &allow_pin_authentication.to_string(),
            );
        }

        if let Some(ref derivation_origin) = options.derivation_origin {
            query_pairs.append_pair("derivationOrigin", derivation_origin);
        }

        if let Some(ref window_opener_features) = options.window_opener_features {
            query_pairs.append_pair("windowOpenerFeatures", window_opener_features);
        }

        if let Some(ref custom_values) = options.custom_values {
            if let Ok(json) = serde_json::to_string(custom_values) {
                query_pairs.append_pair("customValues", &json);
            }
        }
    }

    /// Core logout logic that clears identity and storage.
    fn logout_core(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: &mut dyn AuthClientStorage,
        chain: Arc<Mutex<Option<DelegationChain>>>,
    ) {
        if let Err(_e) = Self::delete_storage_native(storage) {
            #[cfg(feature = "tracing")]
            error!("Failed to delete storage: {}", _e);
        }

        // Reset this auth client to a non-authenticated state.
        *identity.lock() = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        chain.lock().take();
    }

    /// Log the user out.
    pub fn logout(&self) {
        if let Some(idle_manager) = self.0.idle_manager.lock().take() {
            drop(idle_manager);
        }

        let mut storage_lock = self.0.storage.lock();
        let storage_ref: &mut dyn AuthClientStorage = &mut **storage_lock;
        Self::logout_core(self.0.identity.clone(), storage_ref, self.0.chain.clone());
    }

    /// Deletes the key and delegation from storage.
    fn delete_storage_native(
        storage: &mut dyn AuthClientStorage,
    ) -> Result<(), crate::storage::StorageError> {
        storage.remove(KEY_STORAGE_KEY)?;
        storage.remove(KEY_STORAGE_DELEGATION)?;
        storage.remove(KEY_STORAGE_KEY_TYPE)?;
        Ok(())
    }
}

#[cfg(feature = "pem")]
fn sanitize_service_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(feature = "pem")]
fn find_pem_file_in_directory(directory: &Path) -> Result<Option<PathBuf>, AuthClientError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AuthClientError::Storage(StorageError::File(e.to_string()))),
    };

    for entry in entries {
        let entry =
            entry.map_err(|e| AuthClientError::Storage(StorageError::File(e.to_string())))?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.eq_ignore_ascii_case("pem") {
                    return Ok(Some(path));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn has_header(response: &Response<std::io::Cursor<Vec<u8>>>, key: &str, value: &str) -> bool {
        response.headers().iter().any(|header| {
            let header_name: &str = header.field.as_str().as_ref();
            let header_value: &str = header.value.as_str();
            header_name.eq_ignore_ascii_case(key) && header_value.eq_ignore_ascii_case(value)
        })
    }

    #[test]
    fn cors_response_exposes_private_network_headers() {
        let response = NativeAuthClient::cors_response("", 204);
        assert_eq!(response.status_code().0, 204);
        assert!(has_header(
            &response,
            "Access-Control-Allow-Private-Network",
            "true"
        ));
        assert!(has_header(&response, "Access-Control-Allow-Origin", "*"));
    }

    #[test]
    fn process_auth_payload_returns_success_and_cors_headers() {
        let payload = json!({
            "type": "success",
            "data": {
                "delegations": [],
                "userPublicKey": [],
                "authnMethod": "native"
            }
        });
        let (response, callback) = NativeAuthClient::process_auth_payload(payload, false);
        assert_eq!(response.status_code().0, 200);
        assert!(has_header(&response, "Access-Control-Allow-Origin", "*"));
        assert!(has_header(
            &response,
            "Access-Control-Allow-Private-Network",
            "true"
        ));

        match callback {
            CallbackResult::Success(data) => assert_eq!(data.authn_method, "native"),
            CallbackResult::Error(err) => panic!("unexpected error: {:?}", err),
        }
    }

    #[test]
    fn process_auth_payload_renders_html_when_requested() {
        let payload = json!({
            "type": "success",
            "data": {
                "delegations": [],
                "userPublicKey": [],
                "authnMethod": "redirect"
            }
        });
        let (response, callback) = NativeAuthClient::process_auth_payload(payload, true);
        assert_eq!(response.status_code().0, 200);
        assert!(has_header(
            &response,
            "Content-Type",
            "text/html; charset=utf-8"
        ));
        assert!(matches!(callback, CallbackResult::Success(_)));
    }

    #[test]
    fn process_auth_payload_handles_remote_errors() {
        let payload = json!({
            "type": "error",
            "data": "Browser closed"
        });
        let (response, callback) = NativeAuthClient::process_auth_payload(payload, false);
        assert_eq!(response.status_code().0, 200);
        match callback {
            CallbackResult::Error(NativeLoginError::Custom(message)) => {
                assert_eq!(message, "Browser closed");
            }
            _ => panic!("expected custom error"),
        }
    }

    #[test]
    fn deserialize_payload_decodes_base64_json() {
        let payload = json!({
            "type": "success",
            "data": {
                "delegations": [],
                "userPublicKey": [],
                "authnMethod": "redirect"
            }
        })
        .to_string();
        let encoded = BASE64_STANDARD.encode(payload.as_bytes());
        let json = NativeAuthClient::deserialize_payload(&encoded).expect("decode payload");
        assert_eq!(json["type"], "success");
    }

    #[test]
    fn normalize_delegations_handles_string_expiration() {
        let mut json = json!({
            "type": "success",
            "data": {
                "delegations": [{
                    "delegation": {
                        "expiration": "1763421459179717000",
                        "pubkey": [],
                        "targets": []
                    },
                    "signature": []
                }],
                "userPublicKey": [],
                "authnMethod": "native"
            }
        });

        NativeAuthClient::normalize_delegations(&mut json).expect("normalize");

        assert!(json["data"]["delegations"][0]["delegation"]["expiration"].is_number());
    }
}
