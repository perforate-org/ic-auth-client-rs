use crate::storage::async_storage::IdbStorage;
use crate::{
    ArcIdentity, AuthClientError,
    api::{
        AuthResponseSuccess, IdentityServiceResponseKind, IdentityServiceResponseMessage,
        InternetIdentityAuthRequest,
    },
    idle_manager::{IdleManager, IdleManagerOptions},
    key::{BaseKeyType, Key, KeyWithRaw},
    option::{AuthClientLoginOptions, IdleOptions, wasm_js::AuthClientCreateOptions},
    storage::{
        KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, KEY_STORAGE_KEY_TYPE, KEY_VECTOR, StoredKey,
        async_storage::{AuthClientStorage, LocalStorage},
    },
    util::{callback::OnSuccess, delegation_chain::DelegationChain},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::{
    future::{AbortHandle, Abortable},
    lock::Mutex as FutureMutex,
};
use gloo_events::EventListener;
use gloo_utils::{format::JsValueSerdeExt, window};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity, SignedDelegation},
};
use k256::SecretKey as K256SecretKey;
use p256::SecretKey as P256SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::from_value;
use std::{cell::RefCell, fmt, sync::Arc, time::Duration};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    CryptoKey, CryptoKeyPair, Location, MessageEvent, SubtleCrypto,
    js_sys::{Array, Object, Reflect},
    wasm_bindgen::{JsCast, JsValue},
};

const IDENTITY_PROVIDER_DEFAULT: &str = "https://identity.internetcomputer.org";
const IDENTITY_PROVIDER_ENDPOINT: &str = "#authorize";

const INTERRUPT_CHECK_INTERVAL: Duration = Duration::from_millis(500);
/// The error message when a user interrupts the authentication process.
pub const ERROR_USER_INTERRUPT: &str = "UserInterrupt";

thread_local! {
    static ACTIVE_LOGIN: RefCell<Option<ActiveLogin>> = const { RefCell::new(None) };
}

#[derive(Deserialize)]
struct EcJwkExport {
    kty: Option<String>,
    crv: Option<String>,
    d: Option<String>,
}

#[derive(Serialize)]
struct EcJwkImport {
    kty: &'static str,
    crv: &'static str,
    x: String,
    y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    ext: bool,
    key_ops: Vec<String>,
}

/// Holds the resources for an active login process.
/// When this struct is dropped, it automatically cleans up all associated resources.
#[derive(Debug)]
struct ActiveLogin {
    idp_window: web_sys::Window,
    _message_handler: EventListener,
    interruption_check_abort_handle: AbortHandle,
}

impl Drop for ActiveLogin {
    fn drop(&mut self) {
        // Abort the interruption check task.
        self.interruption_check_abort_handle.abort();
        // Close the IdP window, ignoring errors if it's already closed.
        let _ = self.idp_window.close();
        // The message_handler (EventListener) is automatically dropped, removing the listener.
    }
}

pub(super) struct AuthClientInner {
    pub identity: Arc<Mutex<ArcIdentity>>,
    pub key: Key,
    pub storage: FutureMutex<Box<dyn AuthClientStorage>>,
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

impl Drop for AuthClientInner {
    fn drop(&mut self) {
        ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
    }
}

/// The tool for managing authentication and identity.
///
/// It maintains the state of the user's identity and provides methods for authentication.
#[derive(Clone, Debug)]
pub struct AuthClient(Arc<AuthClientInner>);

impl AuthClient {
    /// Default time to live for the session in nanoseconds (8 hours).
    const DEFAULT_TIME_TO_LIVE: u64 = 8 * 60 * 60 * 1_000_000_000;

    /// Create a new [`AuthClientBuilder`] for building an AuthClient.
    pub fn builder() -> AuthClientBuilder {
        AuthClientBuilder::new()
    }

    /// Creates a new [`AuthClient`] with default options.
    pub async fn new() -> Result<Self, AuthClientError> {
        Self::new_with_options(AuthClientCreateOptions::default()).await
    }

    /// Creates a new [`AuthClient`] with the provided options.
    pub async fn new_with_options(
        options: AuthClientCreateOptions,
    ) -> Result<Self, AuthClientError> {
        let AuthClientCreateOptions {
            identity,
            storage,
            key_type,
            idle_options,
        } = options;

        let mut storage: Box<dyn AuthClientStorage> = if let Some(storage) = storage {
            storage
        } else {
            {
                match IdbStorage::new().await {
                    Ok(storage) => storage.into(),
                    Err(_e) => {
                        #[cfg(feature = "tracing")]
                        error!("Failed to initialize IndexedDB storage: {}", _e);
                        Box::new(LocalStorage::new())
                    }
                }
            }
        };
        let options_identity_is_some = identity.is_some();

        let key = Self::create_or_load_key(identity, storage.as_mut(), key_type).await?;

        let (chain, identity) = Self::load_delegation_chain(storage.as_mut(), &key).await;

        let idle_manager =
            Self::create_idle_manager(&idle_options, &chain, options_identity_is_some);

        Ok(Self(Arc::new(AuthClientInner {
            identity: Arc::new(Mutex::new(identity)),
            key,
            storage: FutureMutex::new(storage),
            chain: Arc::new(Mutex::new(chain)),
            idle_manager: Mutex::new(idle_manager),
            idle_options,
        })))
    }

    /// Creates a new key if one is not found in storage, otherwise loads the existing key.
    /// Supports both JS and Rust storage formats, and migrates from LocalStorage if needed.
    async fn create_or_load_key(
        identity: Option<ArcIdentity>,
        storage: &mut dyn AuthClientStorage,
        key_type: Option<BaseKeyType>,
    ) -> Result<Key, AuthClientError> {
        match identity {
            Some(identity) => Ok(Key::Identity(identity)),
            None => {
                // Check for existing key in primary storage (IndexedDB)
                if let Ok(Some(stored_key)) = storage.get(KEY_STORAGE_KEY).await {
                    return Self::load_key_from_stored(stored_key, storage, key_type).await;
                }

                // Attempt to migrate from LocalStorage
                let mut local_storage = LocalStorage::new();
                if let Ok(Some(local_key)) = local_storage.get(KEY_STORAGE_KEY).await {
                    #[cfg(feature = "tracing")]
                    info!("Found identity in LocalStorage, migrating to IndexedDB...");

                    let key = Self::migrate_key_from_local_storage(
                        &local_key,
                        &mut local_storage,
                        storage,
                    )
                    .await?;

                    #[cfg(feature = "tracing")]
                    info!("Migration from LocalStorage completed successfully");

                    return Ok(key);
                }

                // No existing key found, generate new one in JS-compatible format
                Self::generate_and_store_new_key(storage, key_type).await
            }
        }
    }

    /// Load a key from stored data, detecting format automatically (JS or Rust).
    async fn load_key_from_stored(
        stored_key: StoredKey,
        storage: &mut dyn AuthClientStorage,
        key_type: Option<BaseKeyType>,
    ) -> Result<Key, AuthClientError> {
        use crate::storage::js_compat::{
            IdentityFormat, deserialize_ed25519_from_js, detect_identity_format,
        };

        if let StoredKey::CryptoKeyPair(pair) = stored_key {
            let sec1_der = Self::p256_sec1_der_from_crypto_key_pair(&pair).await?;
            let key = KeyWithRaw::new_with_type(BaseKeyType::Prime256v1, sec1_der)?;
            return Ok(Key::WithRaw(key));
        }

        let stored_str = stored_key.encode();
        let format = detect_identity_format(&stored_str);

        match format {
            IdentityFormat::JsEd25519 => {
                // JS Ed25519 format: JSON array of hex strings
                let signing_key = deserialize_ed25519_from_js(&stored_str)?;
                let key = KeyWithRaw::new(signing_key.to_bytes());
                Ok(Key::WithRaw(key))
            }
            IdentityFormat::RustEd25519 => {
                let bytes = stored_key.decode()?;
                let key = KeyWithRaw::new_with_type(BaseKeyType::Ed25519, bytes)?;
                Ok(Key::WithRaw(key))
            }
            IdentityFormat::RustPrime256v1 => {
                let bytes = stored_key.decode()?;
                let key = KeyWithRaw::new_with_type(BaseKeyType::Prime256v1, bytes)?;
                if let Ok(pair) = Self::import_p256_keypair_from_sec1_der(key.raw_key()).await {
                    let _ = storage
                        .set(KEY_STORAGE_KEY, StoredKey::CryptoKeyPair(pair))
                        .await;
                }
                Ok(Key::WithRaw(key))
            }
            IdentityFormat::RustSecp256k1 => {
                let bytes = stored_key.decode()?;
                let key = KeyWithRaw::new_with_type(BaseKeyType::Secp256k1, bytes)?;
                Ok(Key::WithRaw(key))
            }
            IdentityFormat::Unknown => {
                // Fallback: try to decode with stored key type or provided key type
                let stored_key_type = Self::load_key_type(storage).await;
                let bytes = stored_key.decode()?;

                let key_type = stored_key_type.or(key_type).unwrap_or_default();
                let key = KeyWithRaw::new_with_type(key_type, bytes)?;
                Ok(Key::WithRaw(key))
            }
        }
    }

    /// Load key type from storage.
    async fn load_key_type(storage: &mut dyn AuthClientStorage) -> Option<BaseKeyType> {
        match storage.get(KEY_STORAGE_KEY_TYPE).await {
            Ok(Some(stored)) => {
                let value = stored.encode();
                value.parse::<BaseKeyType>().ok()
            }
            _ => None,
        }
    }

    /// Migrate key and delegation from LocalStorage to primary storage.
    async fn migrate_key_from_local_storage(
        local_key: &StoredKey,
        local_storage: &mut LocalStorage,
        target_storage: &mut dyn AuthClientStorage,
    ) -> Result<Key, AuthClientError> {
        use crate::storage::js_compat::{
            IdentityFormat, deserialize_ed25519_from_js, detect_identity_format,
            serialize_ed25519_to_js,
        };

        let stored_str = local_key.encode();
        let format = detect_identity_format(&stored_str);

        let key = match format {
            IdentityFormat::JsEd25519 => {
                // JS format - keep as-is for interoperability
                let signing_key = deserialize_ed25519_from_js(&stored_str)?;
                let key = KeyWithRaw::new(signing_key.to_bytes());

                // Store in JS format in IndexedDB
                target_storage
                    .set(KEY_STORAGE_KEY, StoredKey::String(stored_str))
                    .await?;
                target_storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String("Ed25519".to_string()),
                    )
                    .await?;

                key
            }
            IdentityFormat::RustEd25519 => {
                // Rust format - convert to JS format for interoperability
                let bytes = local_key.decode()?;
                let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                    crate::storage::DecodeError::Ed25519("Invalid Ed25519 key length".to_string())
                })?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let js_format = serialize_ed25519_to_js(&signing_key);

                let key = KeyWithRaw::new(seed);

                target_storage
                    .set(KEY_STORAGE_KEY, StoredKey::String(js_format))
                    .await?;
                target_storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String("Ed25519".to_string()),
                    )
                    .await?;

                key
            }
            IdentityFormat::RustPrime256v1 => {
                let bytes = local_key.decode()?;
                let key_type = BaseKeyType::Prime256v1;
                let key = KeyWithRaw::new_with_type(key_type, bytes.clone())?;

                let stored = match Self::import_p256_keypair_from_sec1_der(&bytes).await {
                    Ok(pair) => StoredKey::CryptoKeyPair(pair),
                    Err(_) => StoredKey::Raw(bytes.clone()),
                };

                if let Err(_e) = target_storage.set(KEY_STORAGE_KEY, stored).await {
                    #[cfg(feature = "tracing")]
                    error!("Failed to store CryptoKeyPair: {}", _e);
                    target_storage
                        .set(KEY_STORAGE_KEY, StoredKey::Raw(bytes.clone()))
                        .await?;
                }
                target_storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String(key_type.to_string()),
                    )
                    .await?;

                key
            }
            IdentityFormat::RustSecp256k1 => {
                // secp256k1 - store as-is (no JS equivalent)
                let bytes = local_key.decode()?;
                let key_type = BaseKeyType::Secp256k1;
                let key = KeyWithRaw::new_with_type(key_type, bytes.clone())?;

                target_storage
                    .set(KEY_STORAGE_KEY, StoredKey::Raw(bytes))
                    .await?;
                target_storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String(key_type.to_string()),
                    )
                    .await?;

                key
            }
            IdentityFormat::Unknown => {
                // Try to decode with stored key type
                let stored_key_type = Self::load_key_type(local_storage).await;
                let bytes = local_key.decode()?;
                let key_type = stored_key_type.unwrap_or_default();

                // For Ed25519, convert to JS format
                if key_type == BaseKeyType::Ed25519 && bytes.len() == 32 {
                    let seed: [u8; 32] = bytes.try_into().unwrap();
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                    let js_format = serialize_ed25519_to_js(&signing_key);

                    target_storage
                        .set(KEY_STORAGE_KEY, StoredKey::String(js_format))
                        .await?;
                } else if key_type == BaseKeyType::Prime256v1 {
                    let stored = match Self::import_p256_keypair_from_sec1_der(&bytes).await {
                        Ok(pair) => StoredKey::CryptoKeyPair(pair),
                        Err(_) => StoredKey::Raw(bytes.clone()),
                    };
                    if let Err(_e) = target_storage.set(KEY_STORAGE_KEY, stored).await {
                        #[cfg(feature = "tracing")]
                        error!("Failed to store CryptoKeyPair: {}", _e);
                        target_storage
                            .set(KEY_STORAGE_KEY, StoredKey::Raw(bytes.clone()))
                            .await?;
                    }
                } else {
                    target_storage
                        .set(KEY_STORAGE_KEY, StoredKey::Raw(bytes.clone()))
                        .await?;
                }

                target_storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String(key_type.to_string()),
                    )
                    .await?;

                KeyWithRaw::new_with_type(key_type, local_key.decode()?)?
            }
        };

        // Migrate delegation chain if present
        if let Ok(Some(local_delegation)) = local_storage.get(KEY_STORAGE_DELEGATION).await {
            let delegation_str = local_delegation.encode();
            // Store as-is - both formats can be read with from_any_json
            target_storage
                .set(KEY_STORAGE_DELEGATION, StoredKey::String(delegation_str))
                .await?;
            let _ = local_storage.remove(KEY_STORAGE_DELEGATION).await;
        }

        // Clean up LocalStorage
        let _ = local_storage.remove(KEY_STORAGE_KEY).await;
        let _ = local_storage.remove(KEY_STORAGE_KEY_TYPE).await;
        let _ = local_storage.remove(KEY_VECTOR).await;

        Ok(Key::WithRaw(key))
    }

    /// Generate a new key and store it in JS-compatible format.
    async fn generate_and_store_new_key(
        storage: &mut dyn AuthClientStorage,
        key_type: Option<BaseKeyType>,
    ) -> Result<Key, AuthClientError> {
        use crate::storage::js_compat::serialize_ed25519_to_js;

        let key_type = key_type.unwrap_or_default();

        match key_type {
            BaseKeyType::Ed25519 => {
                // Generate and store in JS-compatible format
                let mut rng = rand::thread_rng();
                let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
                let js_format = serialize_ed25519_to_js(&signing_key);

                storage
                    .set(KEY_STORAGE_KEY, StoredKey::String(js_format))
                    .await?;
                storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String("Ed25519".to_string()),
                    )
                    .await?;

                Ok(Key::WithRaw(KeyWithRaw::new(signing_key.to_bytes())))
            }
            BaseKeyType::Prime256v1 => {
                let (key_pair, sec1_der) = Self::generate_p256_crypto_key_pair().await?;
                if let Err(_e) = storage
                    .set(KEY_STORAGE_KEY, StoredKey::CryptoKeyPair(key_pair))
                    .await
                {
                    #[cfg(feature = "tracing")]
                    error!("Failed to store CryptoKeyPair: {}", _e);
                    storage
                        .set(KEY_STORAGE_KEY, StoredKey::Raw(sec1_der.clone()))
                        .await?;
                }
                storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String(key_type.to_string()),
                    )
                    .await?;
                Ok(Key::WithRaw(KeyWithRaw::new_with_type(key_type, sec1_der)?))
            }
            BaseKeyType::Secp256k1 => {
                // Secp256k1 - no JS equivalent, store as raw
                let private_key = Self::generate_key_material(key_type)?;
                storage
                    .set(KEY_STORAGE_KEY, StoredKey::Raw(private_key.clone()))
                    .await?;
                storage
                    .set(
                        KEY_STORAGE_KEY_TYPE,
                        StoredKey::String(key_type.to_string()),
                    )
                    .await?;
                Ok(Key::WithRaw(KeyWithRaw::new_with_type(
                    key_type,
                    private_key,
                )?))
            }
        }
    }

    fn generate_key_material(
        key_type: BaseKeyType,
    ) -> Result<Vec<u8>, crate::storage::DecodeError> {
        match key_type {
            BaseKeyType::Ed25519 => {
                let mut rng = rand::thread_rng();
                let private_key = ed25519_dalek::SigningKey::generate(&mut rng).to_bytes();
                Ok(private_key.to_vec())
            }
            BaseKeyType::Prime256v1 => {
                let mut rng = rand::thread_rng();
                let secret = P256SecretKey::random(&mut rng);
                let der = secret.to_sec1_der().map_err(|e| {
                    crate::storage::DecodeError::Key(format!("Prime256v1 key encoding error: {e}"))
                })?;
                let bytes: Vec<u8> = der.to_vec();
                Ok(bytes)
            }
            BaseKeyType::Secp256k1 => {
                let mut rng = rand::thread_rng();
                let secret = K256SecretKey::random(&mut rng);
                let der = secret.to_sec1_der().map_err(|e| {
                    crate::storage::DecodeError::Key(format!("Secp256k1 key encoding error: {e}"))
                })?;
                let bytes: Vec<u8> = der.to_vec();
                Ok(bytes)
            }
        }
    }

    fn js_error_message(error: &JsValue) -> String {
        error
            .as_string()
            .unwrap_or_else(|| format!("WebCrypto error: {error:?}"))
    }

    fn subtle_crypto() -> Result<SubtleCrypto, crate::storage::DecodeError> {
        let crypto = window()
            .crypto()
            .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        Ok(crypto.subtle())
    }

    fn ec_keygen_params() -> Result<Object, crate::storage::DecodeError> {
        let params = Object::new();
        Reflect::set(
            &params,
            &JsValue::from_str("name"),
            &JsValue::from_str("ECDSA"),
        )
        .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        Reflect::set(
            &params,
            &JsValue::from_str("namedCurve"),
            &JsValue::from_str("P-256"),
        )
        .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        Ok(params)
    }

    async fn export_p256_jwk(key: &CryptoKey) -> Result<EcJwkExport, crate::storage::DecodeError> {
        let subtle = Self::subtle_crypto()?;
        let promise = subtle
            .export_key("jwk", key)
            .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        let value = JsFuture::from(promise)
            .await
            .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        from_value::<EcJwkExport>(value).map_err(|e| {
            crate::storage::DecodeError::Key(format!("Failed to deserialize JWK: {e}"))
        })
    }

    fn p256_secret_key_from_jwk(
        jwk: &EcJwkExport,
    ) -> Result<P256SecretKey, crate::storage::DecodeError> {
        if let Some(kty) = &jwk.kty {
            if kty != "EC" {
                return Err(crate::storage::DecodeError::Key(format!(
                    "Unexpected JWK kty: {kty}"
                )));
            }
        }
        if let Some(crv) = &jwk.crv {
            if crv != "P-256" {
                return Err(crate::storage::DecodeError::Key(format!(
                    "Unexpected JWK crv: {crv}"
                )));
            }
        }
        let d = jwk.d.as_ref().ok_or_else(|| {
            crate::storage::DecodeError::Key("JWK missing private key material".to_string())
        })?;
        let d_bytes = URL_SAFE_NO_PAD
            .decode(d)
            .map_err(crate::storage::DecodeError::Base64)?;
        let secret = P256SecretKey::from_slice(&d_bytes).map_err(|e| {
            crate::storage::DecodeError::Key(format!("Prime256v1 key decode error: {e}"))
        })?;
        Ok(secret)
    }

    fn p256_sec1_der_from_secret(
        secret: &P256SecretKey,
    ) -> Result<Vec<u8>, crate::storage::DecodeError> {
        let der = secret.to_sec1_der().map_err(|e| {
            crate::storage::DecodeError::Key(format!("Prime256v1 key encoding error: {e}"))
        })?;
        Ok(der.to_vec())
    }

    async fn p256_sec1_der_from_crypto_key_pair(
        pair: &CryptoKeyPair,
    ) -> Result<Vec<u8>, crate::storage::DecodeError> {
        let private_key = pair.get_private_key();
        let jwk = Self::export_p256_jwk(&private_key).await?;
        let secret = Self::p256_secret_key_from_jwk(&jwk)?;
        Self::p256_sec1_der_from_secret(&secret)
    }

    fn crypto_keypair_from_js_value(
        value: JsValue,
    ) -> Result<CryptoKeyPair, crate::storage::DecodeError> {
        if let Ok(pair) = value.clone().dyn_into::<CryptoKeyPair>() {
            return Ok(pair);
        }
        if value.is_object() {
            let private_key = Reflect::get(&value, &JsValue::from_str("privateKey"))
                .ok()
                .and_then(|val| val.dyn_into::<CryptoKey>().ok());
            let public_key = Reflect::get(&value, &JsValue::from_str("publicKey"))
                .ok()
                .and_then(|val| val.dyn_into::<CryptoKey>().ok());
            if let (Some(private_key), Some(public_key)) = (private_key, public_key) {
                return Ok(CryptoKeyPair::new(&private_key, &public_key));
            }
        }
        Err(crate::storage::DecodeError::Key(format!(
            "Failed to cast CryptoKeyPair: {:?}",
            value
        )))
    }

    async fn generate_p256_crypto_key_pair()
    -> Result<(CryptoKeyPair, Vec<u8>), crate::storage::DecodeError> {
        let subtle = Self::subtle_crypto()?;
        let params = Self::ec_keygen_params()?;
        let usages = Array::new();
        usages.push(&JsValue::from_str("sign"));
        usages.push(&JsValue::from_str("verify"));
        let promise = subtle
            .generate_key_with_object(&params, true, &usages.into())
            .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        let value = JsFuture::from(promise)
            .await
            .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?;
        let pair = Self::crypto_keypair_from_js_value(value)?;
        let sec1_der = Self::p256_sec1_der_from_crypto_key_pair(&pair).await?;
        Ok((pair, sec1_der))
    }

    async fn import_p256_keypair_from_sec1_der(
        sec1_der: &[u8],
    ) -> Result<CryptoKeyPair, crate::storage::DecodeError> {
        let secret = P256SecretKey::from_sec1_der(sec1_der).map_err(|e| {
            crate::storage::DecodeError::Key(format!("Prime256v1 key decode error: {e}"))
        })?;
        let public_key = secret.public_key();
        let encoded = public_key.to_encoded_point(false);
        let encoded_bytes = encoded.as_bytes();
        if encoded_bytes.len() != 65 || encoded_bytes[0] != 4 {
            return Err(crate::storage::DecodeError::Key(
                "Invalid P-256 public key encoding".to_string(),
            ));
        }

        let x = URL_SAFE_NO_PAD.encode(&encoded_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&encoded_bytes[33..65]);
        let d = URL_SAFE_NO_PAD.encode(secret.to_bytes().as_slice());

        let private_jwk = EcJwkImport {
            kty: "EC",
            crv: "P-256",
            x: x.clone(),
            y: y.clone(),
            d: Some(d),
            ext: true,
            key_ops: vec!["sign".to_string()],
        };
        let public_jwk = EcJwkImport {
            kty: "EC",
            crv: "P-256",
            x,
            y,
            d: None,
            ext: true,
            key_ops: vec!["verify".to_string()],
        };

        let subtle = Self::subtle_crypto()?;
        let params = Self::ec_keygen_params()?;

        let private_value = serde_wasm_bindgen::to_value(&private_jwk).map_err(|e| {
            crate::storage::DecodeError::Key(format!("Failed to serialize JWK: {e}"))
        })?;
        let public_value = serde_wasm_bindgen::to_value(&public_jwk).map_err(|e| {
            crate::storage::DecodeError::Key(format!("Failed to serialize JWK: {e}"))
        })?;

        let private_obj: Object = private_value.dyn_into().map_err(|e| {
            crate::storage::DecodeError::Key(format!("Invalid JWK object: {:?}", e))
        })?;
        let public_obj: Object = public_value.dyn_into().map_err(|e| {
            crate::storage::DecodeError::Key(format!("Invalid JWK object: {:?}", e))
        })?;

        let private_usages = Array::new();
        private_usages.push(&JsValue::from_str("sign"));
        let public_usages = Array::new();
        public_usages.push(&JsValue::from_str("verify"));

        let private_key = JsFuture::from(
            subtle
                .import_key_with_object("jwk", &private_obj, &params, true, &private_usages.into())
                .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?,
        )
        .await
        .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?
        .dyn_into::<CryptoKey>()
        .map_err(|e| crate::storage::DecodeError::Key(format!("Invalid CryptoKey: {:?}", e)))?;

        let public_key = JsFuture::from(
            subtle
                .import_key_with_object("jwk", &public_obj, &params, true, &public_usages.into())
                .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?,
        )
        .await
        .map_err(|e| crate::storage::DecodeError::Key(Self::js_error_message(&e)))?
        .dyn_into::<CryptoKey>()
        .map_err(|e| crate::storage::DecodeError::Key(format!("Invalid CryptoKey: {:?}", e)))?;

        Ok(CryptoKeyPair::new(&private_key, &public_key))
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
    /// Supports both JS and Rust JSON formats automatically.
    async fn load_delegation_chain(
        storage: &mut dyn AuthClientStorage,
        key: &Key,
    ) -> (Option<DelegationChain>, ArcIdentity) {
        let mut identity = ArcIdentity::from(key);
        let mut chain: Option<DelegationChain> = None;

        match storage.get(KEY_STORAGE_DELEGATION).await {
            Ok(Some(chain_stored)) => {
                let chain_json = chain_stored.encode();

                // Use from_any_json to support both JS and Rust formats
                let chain_result = DelegationChain::from_any_json(&chain_json);

                match chain_result {
                    Ok(loaded_chain) => {
                        let delegation_data =
                            Self::get_delegation_data(&Some(loaded_chain.clone()));

                        match delegation_data {
                            Some((public_key, delegations)) => {
                                if !public_key.is_empty() {
                                    identity = ArcIdentity::Delegated(Arc::new(
                                        DelegatedIdentity::new_unchecked(
                                            public_key,
                                            Box::new(key.as_arc_identity()),
                                            delegations,
                                        ),
                                    ));
                                }
                                chain = Some(loaded_chain);
                            }
                            None => {
                                #[cfg(feature = "tracing")]
                                info!(
                                    "Found invalid delegation chain in storage - clearing credentials"
                                );
                                if let Err(_e) = Self::delete_storage(storage).await {
                                    #[cfg(feature = "tracing")]
                                    error!("Failed to delete storage: {}", _e);
                                }
                                identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
                            }
                        }
                    }
                    Err(_e) => {
                        #[cfg(feature = "tracing")]
                        error!("Failed to parse delegation chain: {}", _e);
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

    /// Returns the idle manager if it exists.
    pub fn idle_manager(&self) -> Option<IdleManager> {
        self.0.idle_manager.lock().clone()
    }

    /// Registers the default idle callback.
    fn register_default_idle_callback(&self) {
        if let Some(options) = self.0.idle_options.as_ref() {
            if options.disable_default_idle_callback.unwrap_or_default() {
                return;
            }

            if options.idle_manager_options.on_idle.lock().is_empty() {
                if let Some(idle_manager) = self.0.idle_manager.lock().as_ref() {
                    let client = self.clone();
                    let callback = move || {
                        let client = client.clone();
                        spawn_local(async move {
                            client.logout(None).await;
                            match window().location().reload() {
                                Ok(_) => (),
                                Err(_e) => {
                                    #[cfg(feature = "tracing")]
                                    error!("Failed to reload page: {_e:?}");
                                }
                            };
                        });
                    };
                    idle_manager.register_callback(callback);
                }
            }
        }
    }

    /// Handles a successful authentication response.
    async fn handle_success(
        &self,
        message: AuthResponseSuccess,
        on_success: Option<OnSuccess>,
    ) -> Result<(), DelegationError> {
        // Take and drop the ActiveLogin struct, which handles all resource cleanup.
        let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        let delegation_chain = DelegationChain {
            delegations: delegations.clone(),
            public_key: user_public_key.clone(),
        };

        self.update_storage_with_delegation(&delegation_chain).await;
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

    /// Stores the delegation chain and key in storage using JS-compatible formats.
    async fn update_storage_with_delegation(&self, delegation_chain: &DelegationChain) {
        use crate::storage::js_compat::serialize_ed25519_to_js;

        if let Key::WithRaw(key) = &self.0.key {
            // Store key in JS-compatible format for Ed25519
            let (stored_key, fallback_raw) = match key.key_type() {
                BaseKeyType::Ed25519 => {
                    let raw = key.raw_key();
                    if raw.len() == 32 {
                        let seed: [u8; 32] = raw.try_into().unwrap();
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                        (
                            StoredKey::String(serialize_ed25519_to_js(&signing_key)),
                            None,
                        )
                    } else {
                        (StoredKey::Raw(raw.to_vec()), None)
                    }
                }
                BaseKeyType::Prime256v1 => {
                    match Self::import_p256_keypair_from_sec1_der(key.raw_key()).await {
                        Ok(pair) => (StoredKey::CryptoKeyPair(pair), Some(key.raw_key().to_vec())),
                        Err(_) => (StoredKey::Raw(key.raw_key().to_vec()), None),
                    }
                }
                BaseKeyType::Secp256k1 => (StoredKey::Raw(key.raw_key().to_vec()), None),
            };

            if let Err(_e) = self
                .0
                .storage
                .lock()
                .await
                .set(KEY_STORAGE_KEY, stored_key)
                .await
            {
                #[cfg(feature = "tracing")]
                error!("Failed to store key: {}", _e);
                if let Some(raw) = fallback_raw {
                    let _ = self
                        .0
                        .storage
                        .lock()
                        .await
                        .set(KEY_STORAGE_KEY, StoredKey::Raw(raw))
                        .await;
                }
            }
            if let Err(_e) = self
                .0
                .storage
                .lock()
                .await
                .set(
                    KEY_STORAGE_KEY_TYPE,
                    StoredKey::String(key.key_type().to_string()),
                )
                .await
            {
                #[cfg(feature = "tracing")]
                error!("Failed to store key type: {}", _e);
            }
        }

        // Store delegation chain in JS-compatible format
        let chain_json = delegation_chain.to_js_json();
        if let Err(_e) = self
            .0
            .storage
            .lock()
            .await
            .set(
                KEY_STORAGE_DELEGATION,
                StoredKey::String(chain_json.clone()),
            )
            .await
        {
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
                self.register_default_idle_callback();
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

    /// Logs the user in with default options.
    pub fn login(&self) {
        self.login_with_options(AuthClientLoginOptions::default());
    }

    /// Logs the user in with the provided options.
    pub fn login_with_options(&self, options: AuthClientLoginOptions) {
        ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

        let identity_provider_url = match Self::create_idp_url(&options) {
            Some(url) => url,
            None => return,
        };

        let idp_window = match Self::open_idp_window(&identity_provider_url, &options) {
            Some(window) => window,
            None => return,
        };

        let abort_handle = Self::spawn_interruption_check(&idp_window, &options);

        let _message_handler =
            self.get_event_handler(idp_window.clone(), identity_provider_url, options);

        let active_login = ActiveLogin {
            idp_window,
            _message_handler,
            interruption_check_abort_handle: abort_handle,
        };

        ACTIVE_LOGIN.with(|cell| *cell.borrow_mut() = Some(active_login));
    }

    /// Creates the identity provider URL.
    fn create_idp_url(options: &AuthClientLoginOptions) -> Option<web_sys::Url> {
        let identity_provider_url = match options.identity_provider {
            Some(ref url) => url as &str,
            None => IDENTITY_PROVIDER_DEFAULT,
        };

        match web_sys::Url::new(identity_provider_url) {
            Ok(url) => {
                url.set_hash(IDENTITY_PROVIDER_ENDPOINT);
                Some(url)
            }
            Err(_err) => {
                #[cfg(feature = "tracing")]
                {
                    use wasm_bindgen::convert::TryFromJsValue;
                    match String::try_from_js_value(_err) {
                        Ok(msg) => error!("Failed to create URL: {}", msg),
                        Err(_) => error!("Failed to create URL"),
                    };
                }
                None
            }
        }
    }

    /// Opens the identity provider window.
    fn open_idp_window(
        url: &web_sys::Url,
        options: &AuthClientLoginOptions,
    ) -> Option<web_sys::Window> {
        match window().open_with_url_and_target_and_features(
            &url.href(),
            "idpWindow",
            options.window_opener_features.as_deref().unwrap_or(""),
        ) {
            Ok(Some(window_handle)) => Some(window_handle),
            Ok(None) => {
                let error_message = "Failed to open IdP window. Check popup blocker.".to_string();
                if let Some(cb) = &options.on_error {
                    cb.0.lock()(Some(error_message.clone()));
                }
                None
            }
            Err(e) => {
                let error_message = format!("Error opening IdP window: {:?}", e);
                if let Some(cb) = &options.on_error {
                    cb.0.lock()(Some(error_message.clone()));
                }
                None
            }
        }
    }

    /// Spawns a task to check for user interruption.
    fn spawn_interruption_check(
        idp_window: &web_sys::Window,
        options: &AuthClientLoginOptions,
    ) -> AbortHandle {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let interruption_check_task = {
            let idp_window_clone = idp_window.clone();
            let on_error_clone = options.on_error.clone();

            async move {
                gloo_timers::future::sleep(Duration::from_secs(1)).await;
                loop {
                    if idp_window_clone.closed().unwrap_or(true) {
                        let error_message = ERROR_USER_INTERRUPT.to_string();
                        if let Some(on_error) = on_error_clone {
                            on_error.0.lock()(Some(error_message.clone()));
                        }
                        let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
                        break;
                    }
                    gloo_timers::future::sleep(INTERRUPT_CHECK_INTERVAL).await;
                }
            }
        };

        let abortable_task = Abortable::new(interruption_check_task, abort_registration);
        spawn_local(async {
            let _ = abortable_task.await;
        });

        abort_handle
    }

    /// Returns an event handler for the login process.
    fn get_event_handler(
        &self,
        idp_window: web_sys::Window,
        identity_provider_url: web_sys::Url,
        options: AuthClientLoginOptions,
    ) -> EventListener {
        let client = self.clone();

        let callback = move |event: &web_sys::Event| {
            let event = match event.dyn_ref::<MessageEvent>() {
                Some(event) => event,
                None => return,
            };

            if event.origin() != identity_provider_url.origin() {
                return;
            }

            let message = from_value::<IdentityServiceResponseMessage>(event.data())
                .map_err(|e| e.to_string());

            let max_time_to_live = options
                .max_time_to_live
                .unwrap_or(Self::DEFAULT_TIME_TO_LIVE);

            let handle_error_wrapper = |error: String| {
                #[cfg(feature = "tracing")]
                error!("AuthClient login failed in event handler: {}", &error);
                let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
                if let Some(on_error_cb) = options.clone().on_error {
                    on_error_cb.0.lock()(Some(error.clone()));
                }
            };

            match message.and_then(|m| m.kind()) {
                Ok(kind) => match kind {
                    IdentityServiceResponseKind::Ready => {
                        client.handle_ready_response(
                            &idp_window,
                            &identity_provider_url,
                            &options,
                            max_time_to_live,
                            &handle_error_wrapper,
                        );
                    }
                    IdentityServiceResponseKind::AuthSuccess(response) => {
                        client.handle_auth_success_response(response, &options);
                    }
                    IdentityServiceResponseKind::AuthFailure(error_message) => {
                        handle_error_wrapper(error_message);
                    }
                },
                Err(e) => {
                    handle_error_wrapper(e);
                }
            }
        };

        EventListener::new(&window(), "message", callback)
    }

    /// Handles the `Ready` message from the identity provider.
    fn handle_ready_response(
        &self,
        idp_window: &web_sys::Window,
        identity_provider_url: &web_sys::Url,
        options: &AuthClientLoginOptions,
        max_time_to_live: u64,
        handle_error_wrapper: &dyn Fn(String),
    ) {
        use web_sys::js_sys::{Reflect, Uint8Array};

        let request = InternetIdentityAuthRequest {
            kind: "authorize-client".to_string(),
            session_public_key: self.0.key.public_key().expect("Failed to get public key"),
            max_time_to_live: Some(max_time_to_live),
            allow_pin_authentication: options.allow_pin_authentication,
            derivation_origin: options.derivation_origin.clone(),
        };
        let request_js_value = match JsValue::from_serde(&request) {
            Ok(value) => value,
            Err(err) => {
                handle_error_wrapper(format!("Failed to serialize request: {}", err));
                return;
            }
        };

        let session_public_key_js = Uint8Array::from(&request.session_public_key[..]).into();
        if Reflect::set(
            &request_js_value,
            &JsValue::from_str("sessionPublicKey"),
            &session_public_key_js,
        )
        .is_err()
        {
            handle_error_wrapper("Failed to set sessionPublicKey on request".to_string());
            return;
        }

        if let Some(custom_values) = options.custom_values.clone() {
            Self::set_custom_values(&request_js_value, custom_values, handle_error_wrapper);
        }

        if idp_window
            .post_message(&request_js_value, &identity_provider_url.origin())
            .is_err()
        {
            handle_error_wrapper("Failed to post message to IdP window".to_string());
        }
    }

    /// Sets custom values on the request object.
    fn set_custom_values(
        request_js_value: &JsValue,
        custom_values: serde_json::Map<String, serde_json::Value>,
        handle_error_wrapper: &dyn Fn(String),
    ) {
        for (k, v) in custom_values.into_iter() {
            match JsValue::from_serde(&v) {
                Ok(value) => {
                    if web_sys::js_sys::Reflect::set(
                        request_js_value,
                        &JsValue::from_str(&k),
                        &value,
                    )
                    .is_err()
                    {
                        handle_error_wrapper(format!("Failed to set custom value '{}'", k));
                    }
                }
                Err(err) => {
                    handle_error_wrapper(format!(
                        "Failed to serialize custom value '{}': {}",
                        k, err
                    ));
                }
            }
        }
    }

    /// Handles the `AuthResponseSuccess` message from the identity provider.
    fn handle_auth_success_response(
        &self,
        response: AuthResponseSuccess,
        options: &AuthClientLoginOptions,
    ) {
        let client_clone = self.clone();
        let on_success = options.on_success.clone();
        let on_error = options.on_error.clone();
        spawn_local(async move {
            if let Err(e) = client_clone.handle_success(response, on_success).await {
                #[cfg(feature = "tracing")]
                error!("Error during handle_success: {}", e);
                if let Some(on_error_cb) = on_error {
                    on_error_cb.0.lock()(Some(format!(
                        "Error processing successful login: {:?}",
                        e
                    )));
                }
            }
        });
    }

    /// Logs out the user and clears the stored identity.
    async fn logout_core(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: &mut dyn AuthClientStorage,
        chain: Arc<Mutex<Option<DelegationChain>>>,
        return_to: Option<Location>,
    ) {
        if let Err(_e) = Self::delete_storage(storage).await {
            #[cfg(feature = "tracing")]
            error!("Failed to delete storage: {}", _e);
        }

        // Reset this auth client to a non-authenticated state.
        *identity.lock() = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        chain.lock().take();

        if let Some(location) = return_to {
            Self::redirect_user(location);
        }
    }

    /// Handles redirecting the user after logout.
    fn redirect_user(location: Location) {
        let href = match location.href() {
            Ok(href) => href,
            Err(_) => {
                #[cfg(feature = "tracing")]
                error!("Could not get href from return_to location");
                return;
            }
        };

        let history_redirect_success = window()
            .history()
            .and_then(|history| history.push_state_with_url(&JsValue::null(), "", Some(&href)))
            .is_ok();

        if history_redirect_success {
            return;
        }

        // Fallback to assigning location.href
        if window().location().set_href(&href).is_err() {
            #[cfg(feature = "tracing")]
            error!("Failed to set href during logout");
        }
    }

    /// Log the user out.
    /// If a return URL is provided, the user will be redirected to that URL after logging out.
    pub async fn logout(&self, return_to: Option<Location>) {
        if let Some(idle_manager) = self.0.idle_manager.lock().take() {
            drop(idle_manager);
        }

        let mut storage_lock = self.0.storage.lock().await;
        let storage_ref: &mut dyn AuthClientStorage = &mut **storage_lock;
        Self::logout_core(
            self.0.identity.clone(),
            storage_ref,
            self.0.chain.clone(),
            return_to,
        )
        .await;
    }

    /// Deletes the stored keys from the provided storage.
    async fn delete_storage(
        storage: &mut dyn AuthClientStorage,
    ) -> Result<(), crate::storage::StorageError> {
        storage.remove(KEY_STORAGE_KEY).await?;
        storage.remove(KEY_STORAGE_DELEGATION).await?;
        storage.remove(KEY_STORAGE_KEY_TYPE).await?;
        storage.remove(KEY_VECTOR).await?;
        Ok(())
    }
}

/// Builder for the [`AuthClient`].
#[derive(Default)]
pub struct AuthClientBuilder {
    identity: Option<ArcIdentity>,
    storage: Option<Box<dyn AuthClientStorage>>,
    key_type: Option<BaseKeyType>,
    idle_options: Option<IdleOptions>,
}

impl AuthClientBuilder {
    /// Creates a new [`AuthClientBuilder`].
    fn new() -> Self {
        Self::default()
    }

    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub fn identity(mut self, identity: ArcIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Optional storage with get, set, and remove methods. Defaults to IndexedDB with a
    /// `LocalStorage` fallback.
    pub fn storage<S>(mut self, storage: S) -> Self
    where
        S: AuthClientStorage + 'static,
    {
        self.storage = Some(Box::new(storage));
        self
    }

    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub fn key_type(mut self, key_type: BaseKeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub fn idle_options(mut self, idle_options: IdleOptions) -> Self {
        self.idle_options = Some(idle_options);
        self
    }

    // --- Methods to configure IdleOptions directly on the builder ---

    /// Helper to get mutable access to idle_options, creating default if None.
    fn idle_options_mut(&mut self) -> &mut IdleOptions {
        self.idle_options.get_or_insert_with(IdleOptions::default)
    }

    /// If set to `true`, disables the idle timeout functionality.
    pub fn disable_idle(mut self, disable_idle: bool) -> Self {
        self.idle_options_mut().disable_idle = Some(disable_idle);
        self
    }

    /// If set to `true`, disables the default idle timeout callback.
    pub fn disable_default_idle_callback(mut self, disable_default_idle_callback: bool) -> Self {
        self.idle_options_mut().disable_default_idle_callback = Some(disable_default_idle_callback);
        self
    }

    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub fn idle_manager_options(mut self, idle_manager_options: IdleManagerOptions) -> Self {
        self.idle_options_mut().idle_manager_options = idle_manager_options;
        self
    }

    /// Sets a callback to be executed when the system becomes idle.
    ///
    /// It is possible to set multiple callbacks.
    pub fn on_idle<F>(mut self, on_idle: F) -> Self
    where
        F: FnMut() + Send + 'static,
    {
        let options = self.idle_options_mut();
        options
            .idle_manager_options
            .on_idle
            .lock()
            .push(Box::new(on_idle));
        self
    }

    /// The duration of inactivity after which the system is considered idle.
    pub fn idle_timeout(mut self, idle_timeout: u32) -> Self {
        self.idle_options_mut().idle_manager_options.idle_timeout = Some(idle_timeout);
        self
    }

    /// A delay for debouncing scroll events.
    pub fn scroll_debounce(mut self, scroll_debounce: u32) -> Self {
        self.idle_options_mut().idle_manager_options.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(mut self, capture_scroll: bool) -> Self {
        self.idle_options_mut().idle_manager_options.capture_scroll = Some(capture_scroll);
        self
    }

    /// Builds a new [`AuthClient`].
    pub async fn build(self) -> Result<AuthClient, AuthClientError> {
        let options = AuthClientCreateOptions {
            identity: self.identity,
            storage: self.storage,
            key_type: self.key_type,
            idle_options: self.idle_options,
        };

        AuthClient::new_with_options(options).await
    }
}

#[cfg(feature = "wasm-compat-test")]
mod compat_exports {
    use super::*;
    use wasm_bindgen::prelude::*;

    fn to_js_error<E: std::fmt::Display>(err: E) -> JsValue {
        JsValue::from_str(&err.to_string())
    }

    fn parse_key_type(label: Option<String>) -> Option<BaseKeyType> {
        match label.as_deref() {
            Some("Ed25519") => Some(BaseKeyType::Ed25519),
            Some("ECDSA") | Some("Prime256v1") | Some("P-256") | Some("p256") => {
                Some(BaseKeyType::Prime256v1)
            }
            Some("Secp256k1") => Some(BaseKeyType::Secp256k1),
            _ => None,
        }
    }

    fn key_principal_text(key: &Key) -> Result<String, JsValue> {
        let identity: ArcIdentity = key.into();
        let principal = identity.as_arc_identity().sender().map_err(to_js_error)?;
        Ok(principal.to_text())
    }

    /// Clears auth-related keys from IndexedDB storage.
    #[wasm_bindgen]
    pub async fn compat_clear_storage() -> Result<(), JsValue> {
        let mut storage = IdbStorage::new().await.map_err(to_js_error)?;
        storage.remove(KEY_STORAGE_KEY).await.map_err(to_js_error)?;
        storage
            .remove(KEY_STORAGE_DELEGATION)
            .await
            .map_err(to_js_error)?;
        storage
            .remove(KEY_STORAGE_KEY_TYPE)
            .await
            .map_err(to_js_error)?;
        storage.remove(KEY_VECTOR).await.map_err(to_js_error)?;
        Ok(())
    }

    /// Generates and stores a key in Rust, returning the principal text.
    #[wasm_bindgen]
    pub async fn compat_rust_write_key(key_type: String) -> Result<String, JsValue> {
        let mut storage = IdbStorage::new().await.map_err(to_js_error)?;
        let key_type = parse_key_type(Some(key_type));
        let key = AuthClient::generate_and_store_new_key(&mut storage, key_type)
            .await
            .map_err(to_js_error)?;
        key_principal_text(&key)
    }

    /// Loads a stored key via Rust and returns its principal text.
    #[wasm_bindgen]
    pub async fn compat_rust_read_key_principal(
        key_type: Option<String>,
    ) -> Result<String, JsValue> {
        let mut storage = IdbStorage::new().await.map_err(to_js_error)?;
        let stored_key = storage
            .get(KEY_STORAGE_KEY)
            .await
            .map_err(to_js_error)?
            .ok_or_else(|| JsValue::from_str("Stored key not found"))?;
        let key_type = parse_key_type(key_type);
        let key = AuthClient::load_key_from_stored(stored_key, &mut storage, key_type)
            .await
            .map_err(to_js_error)?;
        key_principal_text(&key)
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_idle_options_builder() {
        let options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .idle_manager_options(
                IdleManagerOptions::builder()
                    .on_idle(|| {})
                    .idle_timeout(1000)
                    .scroll_debounce(500)
                    .capture_scroll(true)
                    .build(),
            )
            .build();
        assert_eq!(options.disable_idle, Some(true));
        assert_eq!(options.disable_default_idle_callback, Some(true));
        assert_eq!(options.idle_manager_options.on_idle.lock().len(), 1);
        assert_eq!(options.idle_manager_options.idle_timeout, Some(1000));
        assert_eq!(options.idle_manager_options.scroll_debounce, Some(500));
        assert_eq!(options.idle_manager_options.capture_scroll, Some(true));
    }

    #[test]
    fn test_base_key_type_default() {
        assert_eq!(BaseKeyType::default(), BaseKeyType::Ed25519);
    }

    #[test]
    fn test_auth_client_login_options_builder() {
        let custom_values = vec![("key".to_string(), "value".into())]
            .into_iter()
            .collect();

        let options = AuthClientLoginOptions::builder()
            .allow_pin_authentication(true)
            .custom_values(custom_values)
            .on_error(|_| {})
            .on_success(|_| {})
            .build();

        assert_eq!(options.allow_pin_authentication, Some(true));
        assert!(options.on_error.is_some());
        assert!(options.on_success.is_some());
        assert!(options.custom_values.is_some());
    }

    #[wasm_bindgen_test]
    async fn test_auth_client_builder() {
        let mut rng = rand::thread_rng();
        let private_key = ed25519_dalek::SigningKey::generate(&mut rng).to_bytes();
        let identity = ArcIdentity::Ed25519(Arc::new(
            ic_agent::identity::BasicIdentity::from_raw_key(&private_key),
        ));

        let idle_options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .idle_manager_options(
                IdleManagerOptions::builder()
                    .on_idle(|| {})
                    .idle_timeout(1000)
                    .scroll_debounce(500)
                    .capture_scroll(true)
                    .build(),
            )
            .build();

        let auth_client = AuthClient::builder()
            .identity(identity.clone())
            .idle_options(idle_options)
            .build()
            .await
            .unwrap();

        assert!(!auth_client.is_authenticated());
        assert_eq!(
            auth_client.identity().sender().unwrap(),
            identity.as_arc_identity().sender().unwrap()
        ); // Check if identity was set
    }
}
