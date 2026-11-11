//! P-256 keys and the WebCrypto handles that carry them.
//!
//! The browser stores hold a P-256 key because IndexedDB can keep a key whose
//! private half a page cannot read, and because JS v11's `ECDSAKeyIdentity` is
//! the identity type those stores generate. Rust signs with `p256` itself, so
//! what it needs from WebCrypto is only the handle a record carries: it imports
//! its own key material as an **extractable** `CryptoKeyPair` and keeps the
//! private bytes for signing. That is a deliberate departure from upstream,
//! which generates a non-extractable pair: a Rust process has no WebCrypto
//! signing identity, so it must be able to read its own key back after a reload.
//!
//! Key material is carried as the **32-byte scalar**, which is what a JWK's `d`
//! field holds and what a store's secret registry keeps. The SEC1 DER form only
//! appears inside the native store's record encoding, where the key type is
//! Ed25519 in practice.
//!
//! The consequence for interop is one-directional. A record Rust wrote is
//! readable by JS v11 (`ECDSAKeyIdentity.fromKeyPair` only needs the public
//! half, which is always exportable). A record JS v11 wrote holds a
//! non-extractable private key, which Rust cannot export, so
//! [`secret_from_key_pair`] answers `None` and the store reports the slot as
//! empty rather than guessing.

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{CryptoKey, CryptoKeyPair};

use crate::ArcIdentity;
use crate::client::credentials::wasm;
use crate::client::error::AuthClientError;

/// The curve both sides name in a JWK.
const P256_CURVE: &str = "P-256";

fn storage_error(message: impl std::fmt::Display) -> AuthClientError {
    AuthClientError::Storage(message.to_string())
}

/// Generates a P-256 key: the identity Rust signs with, and its 32-byte scalar.
pub(crate) fn generate() -> Result<(ArcIdentity, Vec<u8>), AuthClientError> {
    let secret = crate::key::random_p256_secret_key();
    let scalar = secret.to_bytes().to_vec();
    let identity = identity_from_scalar(&scalar)?;
    Ok((identity, scalar))
}

/// The identity for a raw 32-byte P-256 scalar, as a JWK carries it.
pub(crate) fn identity_from_scalar(scalar: &[u8]) -> Result<ArcIdentity, AuthClientError> {
    let key = SecretKey::from_slice(scalar)
        .map_err(|error| storage_error(format!("P-256 scalar decoding: {error}")))?;
    Ok(ArcIdentity::from(
        ic_agent::identity::Prime256v1Identity::from_private_key(key),
    ))
}

fn secret_key(scalar: &[u8]) -> Result<SecretKey, AuthClientError> {
    SecretKey::from_slice(scalar)
        .map_err(|error| storage_error(format!("P-256 scalar decoding: {error}")))
}

/// The JWK for a scalar: the fields a JS `CryptoKey` import needs.
pub(crate) fn jwk_from_secret(scalar: &[u8]) -> Result<JsValue, AuthClientError> {
    let key = secret_key(scalar)?;
    let public = key.public_key().to_encoded_point(false);
    let encoded = public.as_bytes();
    if encoded.len() != 65 {
        return Err(storage_error(
            "P-256 public key is not an uncompressed point",
        ));
    }
    let jwk: JsValue = wasm::object().into();
    wasm::set_prop(&jwk, "kty", &JsValue::from_str("EC"))
        .map_err(|error| storage_error(wasm::display(&error)))?;
    wasm::set_prop(&jwk, "crv", &JsValue::from_str(P256_CURVE))
        .map_err(|error| storage_error(wasm::display(&error)))?;
    wasm::set_prop(
        &jwk,
        "x",
        &JsValue::from_str(&BASE64_URL_SAFE_NO_PAD.encode(&encoded[1..33])),
    )
    .map_err(|error| storage_error(wasm::display(&error)))?;
    wasm::set_prop(
        &jwk,
        "y",
        &JsValue::from_str(&BASE64_URL_SAFE_NO_PAD.encode(&encoded[33..65])),
    )
    .map_err(|error| storage_error(wasm::display(&error)))?;
    wasm::set_prop(
        &jwk,
        "d",
        &JsValue::from_str(&BASE64_URL_SAFE_NO_PAD.encode(key.to_bytes())),
    )
    .map_err(|error| storage_error(wasm::display(&error)))?;
    Ok(jwk)
}

/// The private scalar in a JWK, when it carries one.
pub(crate) fn secret_from_jwk(jwk: &JsValue) -> Option<Vec<u8>> {
    let encoded = wasm::get_string(jwk, "d")?;
    let secret = BASE64_URL_SAFE_NO_PAD.decode(encoded).ok()?;
    (secret.len() == 32).then_some(secret)
}

fn ecdsa_algorithm() -> Result<JsValue, AuthClientError> {
    let algorithm: JsValue = wasm::object().into();
    wasm::set_prop(&algorithm, "name", &JsValue::from_str("ECDSA"))
        .map_err(|error| storage_error(wasm::display(&error)))?;
    wasm::set_prop(&algorithm, "namedCurve", &JsValue::from_str(P256_CURVE))
        .map_err(|error| storage_error(wasm::display(&error)))?;
    Ok(algorithm)
}

async fn import_jwk(
    jwk: JsValue,
    usages: Vec<&str>,
    extractable: bool,
) -> Result<CryptoKey, AuthClientError> {
    let subtle = wasm::subtle()
        .ok_or_else(|| storage_error("WebCrypto is not available in this context"))?;
    let algorithm: web_sys::js_sys::Object = ecdsa_algorithm()?
        .dyn_into()
        .map_err(|_| storage_error("the ECDSA algorithm is not an object"))?;
    let jwk: web_sys::js_sys::Object = jwk
        .dyn_into()
        .map_err(|_| storage_error("the JWK is not an object"))?;
    let usages = wasm::array(usages.into_iter().map(JsValue::from_str).collect());
    let promise = subtle
        .import_key_with_object("jwk", &jwk, &algorithm, extractable, &usages)
        .map_err(|error| storage_error(wasm::display(&error)))?;
    wasm::await_promise(promise.into())
        .await
        .map_err(|error| storage_error(wasm::display(&error)))?
        .dyn_into()
        .map_err(|_| storage_error("importKey did not answer with a CryptoKey"))
}

/// Imports a scalar as an extractable WebCrypto key pair.
pub(crate) async fn key_pair_from_secret(scalar: &[u8]) -> Result<CryptoKeyPair, AuthClientError> {
    let jwk = jwk_from_secret(scalar)?;
    let private = import_jwk(jwk.clone(), vec!["sign"], true).await?;

    // A public key is imported without `d`: the same curve and point, no
    // private half.
    let public_jwk: web_sys::js_sys::Object = jwk
        .dyn_into()
        .map_err(|_| storage_error("the JWK is not an object"))?;
    let _ = web_sys::js_sys::Reflect::delete_property(&public_jwk, &JsValue::from_str("d"));
    let public = import_jwk(public_jwk.into(), vec!["verify"], true).await?;

    Ok(CryptoKeyPair::new(&private, &public))
}

/// The private scalar behind a key pair, when the browser lets it be read.
///
/// `None` is the JS→Rust interop limit: a pair JS v11 generated is
/// non-extractable, and `exportKey` refuses it.
pub(crate) async fn secret_from_key_pair(
    key_pair: &CryptoKeyPair,
) -> Result<Option<Vec<u8>>, AuthClientError> {
    let Some(subtle) = wasm::subtle() else {
        return Ok(None);
    };
    let promise = subtle
        .export_key("jwk", &key_pair.get_private_key())
        .map_err(|error| storage_error(wasm::display(&error)))?;
    match wasm::await_promise(promise.into()).await {
        Ok(jwk) => Ok(secret_from_jwk(&jwk)),
        // InvalidAccessError: the key is not extractable.
        Err(_) => Ok(None),
    }
}
