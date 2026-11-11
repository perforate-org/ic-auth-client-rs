//! ICRC-25 JSON-RPC methods, payloads and response validation.
//!
//! The wire vocabulary of a signer conversation: the method names, the exact
//! shape of the params objects, and the decoding of the results into the types
//! this crate uses. Port of the wire parts of `@icp-sdk/signer` 6.1.0
//! (`signer.ts:38-188`, `:525-564`) plus the Internet Identity methods that
//! `@icp-sdk/auth` v11.2.0 sends over the same channel
//! (`session/session-delegation.ts:12`, `auth-client.ts:1216`,
//! `notification-consent.ts:15`).
//!
//! Three rules from upstream are load-bearing here and are easy to lose in a
//! port:
//!
//! 1. **Every nanosecond value is a decimal string.** A JSON number that large
//!    has already lost precision in JavaScript, so the signer refuses it and so
//!    does [`to_expiration`].
//! 2. **Binary is standard, padded base64** --- not hex and not base64url. Hex
//!    appears only in this crate's *storage* compatibility format
//!    ([`crate::storage::js_compat`]), which is a different wire.
//! 3. **The signer is not fully trusted.** A returned delegation chain is
//!    re-checked against what was asked for (leaf key, target scope, lifetime);
//!    only the leaf-key mismatch is also enforced on-chain.

use std::collections::HashSet;

use ic_agent::export::Principal;
use ic_agent::identity::{Delegation, DelegationPermissions, SignedDelegation};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::client::base64::{from_base64, to_base64};
use crate::client::options::{NotificationConsentStatus, SignedAttributes};
use crate::client::transport::{JsonRpcId, JsonRpcRequest, SignerError};
use crate::delegation_chain::DelegationChain;

/// `ii_session_delegation` --- Internet Identity's session delegation method.
///
/// Defined by `@icp-sdk/auth`, not by the signer package, and prefixed by its
/// provider because a JSON-RPC method name travels over a transport shared with
/// other signers (`session/session-delegation.ts:8-12`).
pub const SESSION_DELEGATION_METHOD: &str = "ii_session_delegation";

/// `ii-icrc3-attributes` --- Internet Identity's signed-attributes method.
///
/// `@icp-sdk/auth` sends this literal (`auth-client.ts:1220`).
pub const ATTRIBUTES_METHOD: &str = "ii-icrc3-attributes";

/// `ii_notification_consent` --- Internet Identity's notification-consent
/// method (`notification-consent.ts:10-15`).
pub const NOTIFICATION_CONSENT_METHOD: &str = "ii_notification_consent";

/// `icrc25_supported_standards` --- ICRC-25 capability query
/// (`signer.ts:553`).
pub const ICRC25_SUPPORTED_STANDARDS_METHOD: &str = "icrc25_supported_standards";

/// `icrc25_request_permissions` --- ICRC-25 permission request
/// (`signer.ts:583`).
///
/// Upstream's `Signer` sends this only from its typed `requestPermissions`
/// helper, which the auth client never calls: there is **no implicit permission
/// handshake** before a request.
pub const ICRC25_REQUEST_PERMISSIONS_METHOD: &str = "icrc25_request_permissions";

/// `icrc25_permissions` --- ICRC-25 permission query (`signer.ts:611`).
pub const ICRC25_PERMISSIONS_METHOD: &str = "icrc25_permissions";

/// `icrc27_accounts` --- ICRC-27 account request (`signer.ts:488-511`).
pub const ICRC27_ACCOUNTS_METHOD: &str = "icrc27_accounts";

/// `icrc34_delegation` --- ICRC-34 delegation request (`signer.ts:525-564`).
pub const ICRC34_DELEGATION_METHOD: &str = "icrc34_delegation";

/// `icrc49_call_canister` --- ICRC-49 canister call request
/// (`signer.ts:579-600`).
pub const ICRC49_CALL_CANISTER_METHOD: &str = "icrc49_call_canister";

/// `icrc29_status` --- the ICRC-29 heartbeat method.
///
/// Used by the window transport's handshake (`web/heartbeat/client.ts`), not by
/// [`Signer`](crate::signer::Signer) itself: a request is only sent once a
/// channel exists, and the channel is established by the transport.
pub const ICRC29_STATUS_METHOD: &str = "icrc29_status";

/// How far the client's clock may trail the signer's before a delegation that
/// honoured `maxTimeToLive` exactly is wrongly rejected.
///
/// Five minutes, matching upstream's `skewNs` (`signer.ts:97`), absorbs clock
/// drift plus the request's flight time.
pub(crate) const LIFETIME_SKEW_NS: u64 = 5 * 60 * 1_000_000_000;

/// A fresh JSON-RPC request id, as a version-4 UUID string.
///
/// Upstream uses `crypto.randomUUID()` (`signer.ts:612`, and literals in
/// `@icp-sdk/auth`). The id must be unique per channel so responses can be
/// correlated (ICRC-167 additionally rejects id-less requests).
pub(crate) fn new_request_id() -> JsonRpcId {
    use rand::Rng as _;

    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    // RFC 4122 version 4 and the RFC 4122 variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    JsonRpcId::String(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// A request with a fresh id.
pub(crate) fn request(method: &str, params: Option<Value>) -> JsonRpcRequest {
    JsonRpcRequest::new(new_request_id(), method, params)
}

/// The params of an `ii_session_delegation` request.
///
/// Port of `sessionDelegationRequest` (`session-delegation.ts:78-94`): the
/// public key is base64 DER, the two time bounds are decimal strings and each
/// is present only when asked for, and the derivation origin travels under the
/// ICRC-95 key name.
pub(crate) fn session_delegation_params(
    session_public_key: &[u8],
    max_time_to_live: Option<u64>,
    max_time_to_idle: Option<u64>,
    derivation_origin: Option<&str>,
) -> Value {
    let mut params = Map::new();
    params.insert(
        "sessionPublicKey".to_string(),
        Value::String(to_base64(session_public_key)),
    );
    if let Some(max_time_to_live) = max_time_to_live {
        params.insert(
            "maxTimeToLive".to_string(),
            Value::String(max_time_to_live.to_string()),
        );
    }
    if let Some(max_time_to_idle) = max_time_to_idle {
        params.insert(
            "maxTimeToIdle".to_string(),
            Value::String(max_time_to_idle.to_string()),
        );
    }
    if let Some(derivation_origin) = derivation_origin {
        params.insert(
            "icrc95DerivationOrigin".to_string(),
            Value::String(derivation_origin.to_string()),
        );
    }
    Value::Object(params)
}

/// The params of an `ii-icrc3-attributes` request.
///
/// Port of `auth-client.ts:1216-1223`: the keys verbatim and the 32-byte nonce
/// as standard base64.
pub(crate) fn attributes_params(keys: &[String], nonce: &[u8]) -> Value {
    let mut params = Map::new();
    params.insert(
        "keys".to_string(),
        Value::Array(keys.iter().cloned().map(Value::String).collect()),
    );
    params.insert("nonce".to_string(), Value::String(to_base64(nonce)));
    Value::Object(params)
}

/// The params of an `ii_notification_consent` request.
///
/// Port of `notification-consent.ts:71-74`: an object **always** (empty when
/// there is nothing to say), never an absent `params`.
pub(crate) fn notification_consent_params(derivation_origin: Option<&str>) -> Value {
    let mut params = Map::new();
    if let Some(derivation_origin) = derivation_origin {
        params.insert(
            "icrc95DerivationOrigin".to_string(),
            Value::String(derivation_origin.to_string()),
        );
    }
    Value::Object(params)
}

/// Applies upstream's ICRC-95 derivation-origin transform.
///
/// Port of `icrc95DerivationOriginTransform` (`signer.ts:131-139`): when the
/// signer was built with a derivation origin, **every** request carries
/// `params.icrc95DerivationOrigin`, overwriting a value the request itself set
/// (the transform runs after the request is built, `signer.ts:181-185`). An
/// empty origin is treated as absent, which is what JavaScript's truthiness
/// check at `signer.ts:290` does.
pub(crate) fn with_derivation_origin(
    params: Option<Value>,
    derivation_origin: Option<&str>,
) -> Option<Value> {
    let Some(derivation_origin) = derivation_origin.filter(|origin| !origin.is_empty()) else {
        return params;
    };
    let mut params = match params {
        Some(Value::Object(params)) => params,
        // Upstream spreads `request.params`; spreading a non-object yields an
        // empty object. None of this crate's requests take that branch.
        _ => Map::new(),
    };
    params.insert(
        "icrc95DerivationOrigin".to_string(),
        Value::String(derivation_origin.to_string()),
    );
    Some(Value::Object(params))
}

/// A delegation chain as the signer returns it (`signer.ts:525-564`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionDelegationResult {
    public_key: String,
    signer_delegation: Vec<SignedDelegationResult>,
}

/// One hop of a returned chain.
#[derive(Debug, Deserialize)]
struct SignedDelegationResult {
    delegation: DelegationResult,
    signature: String,
}

/// The ICRC-34 delegation fields, camelCased exactly as upstream reads them.
#[derive(Debug, Deserialize)]
struct DelegationResult {
    pubkey: String,
    /// Kept as a raw value so that a JSON number is rejected rather than
    /// silently rounded: see [`to_expiration`].
    expiration: Value,
    #[serde(default)]
    targets: Option<Vec<String>>,
    #[serde(default)]
    permissions: Option<String>,
}

/// Decodes a returned session delegation and re-checks it against the request.
///
/// `expected_leaf` is the DER session public key that was requested;
/// `max_time_to_live` is the bound that was requested, where `None` means the
/// provider's default applies and the lifetime is not re-checked. The chain is
/// rejected when it does not terminate at that key (`assertLeafKey`) or when its
/// earliest expiration exceeds the requested lifetime (`assertLifetime`).
///
/// Target scope is not checked here because `ii_session_delegation` requests no
/// targets; [`validate_delegation_chain`] applies that rule for callers that do.
pub(crate) fn parse_session_delegation(
    result: Value,
    expected_leaf: &[u8],
    max_time_to_live: Option<u64>,
    now_ns: u64,
) -> Result<DelegationChain, SignerError> {
    let result: SessionDelegationResult = serde_json::from_value(result)
        .map_err(|error| invalid_delegation(format!("unreadable session delegation: {error}")))?;

    // Upstream's `looksLikeResult` (`session-delegation.ts:49-60`): a string
    // public key and a non-empty list. An empty list would build a chain whose
    // earliest expiry is 0, i.e. a session that expired at the epoch.
    if result.public_key.is_empty() || result.signer_delegation.is_empty() {
        return Err(invalid_delegation(
            "session response is missing publicKey, or signerDelegation is empty",
        ));
    }

    let public_key = decode_base64("publicKey", &result.public_key)?;
    let mut delegations = Vec::with_capacity(result.signer_delegation.len());
    for (index, signed) in result.signer_delegation.into_iter().enumerate() {
        let pubkey = decode_base64(
            &format!("signerDelegation[{index}].delegation.pubkey"),
            &signed.delegation.pubkey,
        )?;
        let expiration = to_expiration(&signed.delegation.expiration)?;
        let targets = match signed.delegation.targets {
            Some(targets) => {
                let mut parsed = Vec::with_capacity(targets.len());
                for target in targets {
                    parsed.push(Principal::from_text(&target).map_err(|error| {
                        invalid_delegation(format!(
                            "signerDelegation[{index}].delegation.targets contains \
                             {target:?}, which is not a principal: {error}"
                        ))
                    })?);
                }
                Some(parsed)
            }
            None => None,
        };
        let permissions = parse_permissions(index, signed.delegation.permissions)?;
        let signature = decode_base64(
            &format!("signerDelegation[{index}].signature"),
            &signed.signature,
        )?;
        delegations.push(SignedDelegation {
            delegation: Delegation {
                pubkey,
                expiration,
                targets,
                permissions,
            },
            signature,
        });
    }

    let chain = DelegationChain::new(delegations, public_key);
    validate_delegation_chain(&chain, expected_leaf, None, max_time_to_live, now_ns)?;
    Ok(chain)
}

/// Parses an untrusted expiration.
///
/// Port of `toExpiration` (`signer.ts:38-47`): a decimal **string** of at most
/// 20 digits that fits a `u64`. A number is already precision-lost by the time
/// it is parsed, so it is refused rather than rounded.
fn to_expiration(value: &Value) -> Result<u64, SignerError> {
    let Some(text) = value.as_str() else {
        return Err(invalid_delegation("Invalid delegation expiration"));
    };
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_delegation("Invalid delegation expiration"));
    }
    text.parse::<u64>()
        .map_err(|_| invalid_delegation("Invalid delegation expiration"))
}

/// Maps the wire string for a delegation's permissions.
///
/// Upstream reads the field with `asString` and hands it to `Delegation`
/// unchanged. This crate's chain type can only represent the two values it
/// knows, so an unknown one is refused rather than silently widened.
fn parse_permissions(
    index: usize,
    permissions: Option<String>,
) -> Result<Option<DelegationPermissions>, SignerError> {
    match permissions.as_deref() {
        None => Ok(None),
        Some("queries") => Ok(Some(DelegationPermissions::Queries)),
        Some("all") => Ok(Some(DelegationPermissions::All)),
        Some(other) => Err(invalid_delegation(format!(
            "signerDelegation[{index}].delegation.permissions is {other:?}, \
             which this crate does not understand"
        ))),
    }
}

/// Re-checks a returned chain against what was requested.
///
/// Port of upstream's `validateDelegationChain` (`signer.ts:108-115`). The
/// leaf-key check is fail-closed on-chain (a wrong terminal key makes the
/// signatures invalid); target-scope and lifetime over-grants are **not**, so
/// they must be refused here.
///
/// - `expected_leaf` --- the DER public key the chain must terminate at.
/// - `requested_targets` --- the canister scope that was requested, or `None`
///   when the request placed no scope.
/// - `max_time_to_live` --- the requested lifetime in nanoseconds, or `None`.
/// - `now_ns` --- the current time in nanoseconds; a parameter rather than a
///   clock read so the rules can be tested exactly.
pub(crate) fn validate_delegation_chain(
    chain: &DelegationChain,
    expected_leaf: &[u8],
    requested_targets: Option<&[Principal]>,
    max_time_to_live: Option<u64>,
    now_ns: u64,
) -> Result<(), SignerError> {
    assert_leaf_key(chain, expected_leaf)?;
    assert_target_scope(&chain.delegations, requested_targets)?;
    assert_lifetime(&chain.delegations, max_time_to_live, now_ns)?;
    Ok(())
}

/// The chain must terminate at exactly the requested key (`signer.ts:49-55`).
fn assert_leaf_key(chain: &DelegationChain, expected_leaf: &[u8]) -> Result<(), SignerError> {
    match chain.delegations.last() {
        Some(last) if last.delegation.pubkey.as_slice() == expected_leaf => Ok(()),
        _ => Err(invalid_delegation(
            "returned delegation chain does not terminate at the requested public key",
        )),
    }
}

/// The chain's effective scope must be no broader than the requested one.
///
/// Port of `assertTargetScope` (`signer.ts:60-84`): a canister is permitted by
/// the chain only when every scoped hop permits it, so the effective scope is
/// the intersection of the scoped hops, and a chain with no scoped hop at all is
/// unrestricted --- broader than any scoped request.
///
/// Upstream's prose says the effective scope must also be non-empty, but the
/// code does not check that and an empty intersection is the narrowest possible
/// scope; this port follows the code.
fn assert_target_scope(
    delegations: &[SignedDelegation],
    requested: Option<&[Principal]>,
) -> Result<(), SignerError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let requested: HashSet<String> = requested.iter().map(|target| target.to_text()).collect();

    let mut effective: Option<HashSet<String>> = None;
    let mut scoped_hops = 0usize;
    for signed in delegations {
        let Some(hop_targets) = signed.delegation.targets.as_ref() else {
            continue;
        };
        scoped_hops += 1;
        let hop: HashSet<String> = hop_targets.iter().map(|target| target.to_text()).collect();
        effective = Some(match effective {
            None => hop,
            Some(effective) => effective.intersection(&hop).cloned().collect(),
        });
    }

    if scoped_hops == 0 {
        return Err(invalid_delegation(
            "returned delegation is unscoped but scoped targets were requested",
        ));
    }

    for target in effective.unwrap_or_default() {
        if !requested.contains(&target) {
            return Err(invalid_delegation(
                "returned delegation targets are broader than requested",
            ));
        }
    }
    Ok(())
}

/// The chain's lifetime must not exceed the requested one.
///
/// Port of `assertLifetime` (`signer.ts:90-105`): the chain is usable only
/// while every hop is unexpired, so its lifetime is the earliest hop
/// expiration, and a hop expiring later than that grants no additional time.
fn assert_lifetime(
    delegations: &[SignedDelegation],
    max_time_to_live: Option<u64>,
    now_ns: u64,
) -> Result<(), SignerError> {
    let (Some(max_time_to_live), Some(first)) = (max_time_to_live, delegations.first()) else {
        return Ok(());
    };
    let earliest = delegations
        .iter()
        .fold(first.delegation.expiration, |earliest, signed| {
            earliest.min(signed.delegation.expiration)
        });
    // Saturating rather than wrapping: a nonsensically large bound must not
    // turn into a small one and reject a chain it should accept.
    let max_expiration = now_ns
        .saturating_add(max_time_to_live)
        .saturating_add(LIFETIME_SKEW_NS);
    if earliest > max_expiration {
        return Err(invalid_delegation(
            "returned delegation expires later than the requested maxTimeToLive",
        ));
    }
    Ok(())
}

/// The result of an `ii-icrc3-attributes` request.
#[derive(Debug, Deserialize)]
struct AttributesResult {
    data: String,
    signature: String,
}

/// Decodes the signed attributes (`auth-client.ts:1231-1243`).
pub(crate) fn parse_attributes(result: Value) -> Result<SignedAttributes, SignerError> {
    let result: AttributesResult = serde_json::from_value(result)
        .map_err(|error| protocol(format!("invalid attributes response: {error}")))?;
    Ok(SignedAttributes {
        data: decode_base64_protocol("data", &result.data)?,
        signature: decode_base64_protocol("signature", &result.signature)?,
    })
}

/// The result of an `ii_notification_consent` request.
#[derive(Debug, Deserialize)]
struct NotificationConsentResult {
    granted: bool,
}

/// Decodes a consent decision (`notification-consent.ts:86-90`).
///
/// A refusal is an answer --- `{granted: false}` decodes fine and is not an
/// error.
pub(crate) fn parse_notification_consent(
    result: Value,
) -> Result<NotificationConsentStatus, SignerError> {
    let result: NotificationConsentResult = serde_json::from_value(result)
        .map_err(|error| protocol(format!("invalid notification consent response: {error}")))?;
    Ok(NotificationConsentStatus {
        granted: result.granted,
    })
}

/// A malformed delegation, or one that grants more than was asked for.
fn invalid_delegation(message: impl Into<String>) -> SignerError {
    SignerError::InvalidDelegation(message.into())
}

/// A response of the right type but the wrong shape.
fn protocol(message: impl Into<String>) -> SignerError {
    SignerError::Protocol(message.into())
}

/// Decodes base64 inside a delegation response, naming the field on failure.
fn decode_base64(field: &str, encoded: &str) -> Result<Vec<u8>, SignerError> {
    from_base64(encoded)
        .map_err(|error| invalid_delegation(format!("{field} is not valid base64: {error}")))
}

/// Decodes base64 inside a plain result, naming the field on failure.
fn decode_base64_protocol(field: &str, encoded: &str) -> Result<Vec<u8>, SignerError> {
    from_base64(encoded).map_err(|error| protocol(format!("{field} is not valid base64: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "0b9e3a1c-1111-4111-8111-111111111111";

    fn request_json(method: &str, params: Value) -> String {
        let request = JsonRpcRequest::new(JsonRpcId::String(ID.to_string()), method, Some(params));
        serde_json::to_string(&request).expect("a request serialises")
    }

    // --- request encoding goldens -------------------------------------------

    #[test]
    fn session_delegation_params_are_exact() {
        // Object keys come out in alphabetical order because `serde_json`'s map
        // is ordered; object order is not significant on the wire and the
        // values, names, types and omissions are exact.
        let params = session_delegation_params(
            &[1, 2, 3],
            Some(1_800_000_000_000),
            Some(604_800_000_000_000),
            Some("https://rp.example"),
        );
        assert_eq!(
            request_json(SESSION_DELEGATION_METHOD, params),
            concat!(
                r#"{"jsonrpc":"2.0","id":"0b9e3a1c-1111-4111-8111-111111111111","#,
                r#""method":"ii_session_delegation","params":{"#,
                r#""icrc95DerivationOrigin":"https://rp.example","#,
                r#""maxTimeToIdle":"604800000000000","#,
                r#""maxTimeToLive":"1800000000000","#,
                r#""sessionPublicKey":"AQID"}}"#,
            )
        );
    }

    #[test]
    fn session_delegation_omits_unset_bounds_and_origin() {
        let params = session_delegation_params(&[1, 2, 3], None, None, None);
        assert_eq!(
            request_json(SESSION_DELEGATION_METHOD, params),
            concat!(
                r#"{"jsonrpc":"2.0","id":"0b9e3a1c-1111-4111-8111-111111111111","#,
                r#""method":"ii_session_delegation","params":{"sessionPublicKey":"AQID"}}"#,
            )
        );
    }

    #[test]
    fn nanosecond_bounds_are_decimal_strings_not_numbers() {
        let params = session_delegation_params(&[], Some(1), None, None);
        // A JSON number of that size would already be imprecise in JavaScript.
        assert_eq!(params["maxTimeToLive"], json!("1"));
        assert!(params["maxTimeToLive"].is_string());
    }

    #[test]
    fn attributes_params_are_exact() {
        let params = attributes_params(&["email".to_string(), "name".to_string()], &[9, 8, 7]);
        assert_eq!(
            request_json(ATTRIBUTES_METHOD, params),
            concat!(
                r#"{"jsonrpc":"2.0","id":"0b9e3a1c-1111-4111-8111-111111111111","#,
                r#""method":"ii-icrc3-attributes","params":{"#,
                r#""keys":["email","name"],"nonce":"CQgH"}}"#,
            )
        );
    }

    #[test]
    fn notification_consent_params_are_always_an_object() {
        assert_eq!(notification_consent_params(None), json!({}));
        assert_eq!(
            request_json(
                NOTIFICATION_CONSENT_METHOD,
                notification_consent_params(None)
            ),
            concat!(
                r#"{"jsonrpc":"2.0","id":"0b9e3a1c-1111-4111-8111-111111111111","#,
                r#""method":"ii_notification_consent","params":{}}"#,
            )
        );
        assert_eq!(
            notification_consent_params(Some("https://rp.example")),
            json!({ "icrc95DerivationOrigin": "https://rp.example" })
        );
    }

    #[test]
    fn derivation_origin_transform_overwrites_the_requests_own_value() {
        let params = attributes_params(&["email".to_string()], &[1]);
        let transformed = with_derivation_origin(Some(params), Some("https://option.example"))
            .expect("params stay present");
        assert_eq!(
            transformed["icrc95DerivationOrigin"],
            json!("https://option.example")
        );

        // An empty option is JavaScript-falsy upstream, so no transform runs.
        let params = attributes_params(&["email".to_string()], &[1]);
        assert_eq!(
            with_derivation_origin(Some(params.clone()), Some("")),
            Some(params)
        );
    }

    #[test]
    fn request_ids_are_uuid_v4_strings() {
        let JsonRpcId::String(id) = new_request_id() else {
            panic!("ids are strings, like `crypto.randomUUID()`");
        };
        assert_eq!(id.len(), 36, "{id}");
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        assert_eq!(&id[14..15], "4", "{id} is not version 4");
        assert_eq!(&id[18..19], "-");
        assert_eq!(&id[23..24], "-");
        assert!(
            matches!(&id[19..20], "8" | "9" | "a" | "b"),
            "{id} does not carry the RFC 4122 variant"
        );
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    // --- expiration parsing --------------------------------------------------

    #[test]
    fn decimal_string_expiration_is_accepted_and_bounded_to_u64() {
        assert_eq!(to_expiration(&json!("0")).unwrap(), 0);
        assert_eq!(to_expiration(&json!("0001")).unwrap(), 1);
        assert_eq!(
            to_expiration(&json!("18446744073709551615")).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn malformed_expirations_are_rejected() {
        for value in [
            json!(0),
            json!(1.5),
            json!(null),
            json!(""),
            json!("12a"),
            json!("-1"),
            json!("1 "),
            json!(" 1"),
            json!("+1"),
            // 2^64: 20 digits, but out of range.
            json!("18446744073709551616"),
            // 21 digits.
            json!("123456789012345678901"),
            json!("0x10"),
        ] {
            let error = to_expiration(&value).expect_err("must be rejected");
            assert!(
                matches!(error, SignerError::InvalidDelegation(_)),
                "{value} was not rejected as a delegation"
            );
        }
    }

    // --- delegation response parsing and validation ------------------------

    fn delegation_response(pubkey: &str, expiration: Value, targets: Value) -> Value {
        json!({
            "publicKey": "AQID",
            "signerDelegation": [{
                "delegation": {
                    "pubkey": pubkey,
                    "expiration": expiration,
                    "targets": targets,
                },
                "signature": "BwgJ",
            }],
        })
    }

    #[test]
    fn a_valid_chain_is_decoded() {
        let chain = parse_session_delegation(
            delegation_response("BAUG", json!("1900000000000000000"), json!(["aaaaa-aa"])),
            &[4, 5, 6],
            None,
            0,
        )
        .expect("a scoped chain to the requested leaf is accepted");

        assert_eq!(chain.public_key, vec![1, 2, 3]);
        assert_eq!(chain.delegations.len(), 1);
        assert_eq!(chain.delegations[0].delegation.pubkey, vec![4, 5, 6]);
        assert_eq!(
            chain.delegations[0].delegation.expiration,
            1_900_000_000_000_000_000
        );
        assert_eq!(
            chain.delegations[0].delegation.targets,
            Some(vec![Principal::from_text("aaaaa-aa").unwrap()])
        );
        assert_eq!(chain.delegations[0].delegation.permissions, None);
        assert_eq!(chain.delegations[0].signature, vec![7, 8, 9]);
    }

    #[test]
    fn permissions_are_decoded() {
        for (wire, expected) in [
            (Some("queries"), Some(DelegationPermissions::Queries)),
            (Some("all"), Some(DelegationPermissions::All)),
            (None, None),
        ] {
            assert_eq!(
                parse_permissions(0, wire.map(str::to_string)).unwrap(),
                expected
            );
        }
        assert!(parse_permissions(0, Some("something-else".to_string())).is_err());
    }

    #[test]
    fn a_chain_that_does_not_terminate_at_the_requested_key_is_rejected() {
        let error = parse_session_delegation(
            delegation_response("BAUG", json!("1900000000000000000"), json!(null)),
            &[9, 9, 9],
            None,
            0,
        )
        .expect_err("a wrong leaf key must be refused");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));
    }

    #[test]
    fn a_chain_without_hops_is_rejected() {
        let result = json!({ "publicKey": "AQID", "signerDelegation": [] });
        let error = parse_session_delegation(result, &[4, 5, 6], None, 0)
            .expect_err("an empty chain must be refused");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));
    }

    #[test]
    fn a_chain_without_a_public_key_is_rejected() {
        let result = json!({
            "publicKey": "",
            "signerDelegation": [{
                "delegation": { "pubkey": "BAUG", "expiration": "1" },
                "signature": "BwgJ",
            }],
        });
        let error = parse_session_delegation(result, &[4, 5, 6], None, 0)
            .expect_err("an empty publicKey must be refused");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));
    }

    #[test]
    fn malformed_binary_fields_are_rejected() {
        for result in [
            json!({
                "publicKey": "not base64!",
                "signerDelegation": [{
                    "delegation": { "pubkey": "BAUG", "expiration": "1" },
                    "signature": "BwgJ",
                }],
            }),
            json!({
                "publicKey": "AQID",
                "signerDelegation": [{
                    "delegation": { "pubkey": "not base64!", "expiration": "1" },
                    "signature": "BwgJ",
                }],
            }),
            json!({
                "publicKey": "AQID",
                "signerDelegation": [{
                    "delegation": { "pubkey": "BAUG", "expiration": "1" },
                    "signature": "not base64!",
                }],
            }),
            json!({
                "publicKey": "AQID",
                "signerDelegation": [{
                    "delegation": { "pubkey": "BAUG", "expiration": "1", "targets": ["nonsense"] },
                    "signature": "BwgJ",
                }],
            }),
        ] {
            let error = parse_session_delegation(result.clone(), &[4, 5, 6], None, 0)
                .expect_err("malformed fields must be refused");
            assert!(
                matches!(error, SignerError::InvalidDelegation(_)),
                "{result}"
            );
        }
    }

    #[test]
    fn a_malformed_expiration_in_a_response_is_rejected() {
        for expiration in [
            json!(1_900_000_000_000_000_000i64),
            json!("1e18"),
            json!(""),
        ] {
            let error = parse_session_delegation(
                delegation_response("BAUG", expiration.clone(), json!(null)),
                &[4, 5, 6],
                None,
                0,
            )
            .expect_err("a non-decimal-string expiration must be refused");
            assert!(
                matches!(error, SignerError::InvalidDelegation(_)),
                "{expiration}"
            );
        }
    }

    #[test]
    fn a_lifetime_longer_than_requested_is_rejected() {
        let now = 1_800_000_000_000_000_000;
        let expiration = 1_900_000_000_000_000_000u64;
        let result = delegation_response("BAUG", json!(expiration.to_string()), json!(null));

        // Asking for a minute cannot yield a chain a century out.
        let error = parse_session_delegation(result.clone(), &[4, 5, 6], Some(60_000_000_000), now)
            .expect_err("an over-long lifetime must be refused");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));

        // An unset bound is not checked (the provider's default applies).
        parse_session_delegation(result.clone(), &[4, 5, 6], None, now)
            .expect("no requested bound means no lifetime check");

        // A generous bound that still covers the chain passes.
        parse_session_delegation(
            result,
            &[4, 5, 6],
            Some(1_900_000_000_000_000_000 - now),
            now,
        )
        .expect("a chain inside the requested lifetime is accepted");
    }

    // --- target-scope rules, on chains built directly ----------------------

    fn principal(text: &str) -> Principal {
        Principal::from_text(text).expect("a valid principal")
    }

    fn signed(pubkey: &[u8], targets: Option<Vec<Principal>>) -> SignedDelegation {
        SignedDelegation {
            delegation: Delegation {
                pubkey: pubkey.to_vec(),
                expiration: 10,
                targets,
                permissions: None,
            },
            signature: vec![],
        }
    }

    fn chain(delegations: Vec<SignedDelegation>) -> DelegationChain {
        DelegationChain::new(delegations, vec![1, 2, 3])
    }

    fn leaf() -> Vec<u8> {
        vec![4, 5, 6]
    }

    #[test]
    fn a_scoped_chain_inside_the_requested_scope_is_accepted() {
        let chain = chain(vec![signed(&leaf(), Some(vec![principal("aaaaa-aa")]))]);
        validate_delegation_chain(&chain, &leaf(), Some(&[principal("aaaaa-aa")]), None, 0)
            .expect("an identical scope is not broader");
    }

    #[test]
    fn a_chain_with_a_broader_scope_is_rejected() {
        let chain = chain(vec![signed(
            &leaf(),
            Some(vec![
                principal("aaaaa-aa"),
                principal("rdmx6-jaaaa-aaaaa-aaadq-cai"),
            ]),
        )]);
        let error =
            validate_delegation_chain(&chain, &leaf(), Some(&[principal("aaaaa-aa")]), None, 0)
                .expect_err("a broader scope must be refused");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));
    }

    #[test]
    fn a_chain_with_no_scoped_hop_is_rejected_when_a_scope_was_requested() {
        let chain = chain(vec![signed(&leaf(), None)]);
        let error =
            validate_delegation_chain(&chain, &leaf(), Some(&[principal("aaaaa-aa")]), None, 0)
                .expect_err("an unrestricted chain is broader than a scoped request");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));
    }

    #[test]
    fn a_multi_hop_scope_is_intersected() {
        // Hop 1 permits {management, II}; hop 2 permits {management}. The
        // effective scope is {management}.
        let chain = chain(vec![
            signed(
                &[7, 7, 7],
                Some(vec![
                    principal("aaaaa-aa"),
                    principal("rdmx6-jaaaa-aaaaa-aaadq-cai"),
                ]),
            ),
            signed(&leaf(), Some(vec![principal("aaaaa-aa")])),
        ]);
        validate_delegation_chain(&chain, &leaf(), Some(&[principal("aaaaa-aa")]), None, 0)
            .expect("the intersection is inside the requested scope");
        let error = validate_delegation_chain(
            &chain,
            &leaf(),
            Some(&[principal("rdmx6-jaaaa-aaaaa-aaadq-cai")]),
            None,
            0,
        )
        .expect_err("the effective scope is not what was requested");
        assert!(matches!(error, SignerError::InvalidDelegation(_)));
    }

    #[test]
    fn the_earliest_expiration_is_the_chains_lifetime() {
        let now = 1_000_000_000_000;
        let mut early = signed(&[7, 7, 7], None);
        early.delegation.expiration = 2_000_000_000_000;
        let mut late = signed(&leaf(), None);
        late.delegation.expiration = 5_000_000_000_000;
        let chain = chain(vec![early, late]);

        // The leaf expires much later, but the chain is unusable after hop 0.
        validate_delegation_chain(&chain, &leaf(), None, Some(600_000_000_000), now)
            .expect_err("the earliest hop is the chain lifetime");
        validate_delegation_chain(&chain, &leaf(), None, Some(1_200_000_000_000), now)
            .expect("a bound above the earliest hop is fine");
    }

    #[test]
    fn the_five_minute_skew_absorbs_clock_drift() {
        let mut hop = signed(&leaf(), None);
        hop.delegation.expiration = 100_000_000_000; // now + 100 s
        let chain = chain(vec![hop]);
        // Requested a 60 s lifetime one second ago; the signer answered with
        // 100 s, which is inside the skew margin.
        validate_delegation_chain(&chain, &leaf(), None, Some(60_000_000_000), 1_000_000_000)
            .expect("skew must absorb the difference");
    }

    // --- attributes and consent decoding -----------------------------------

    #[test]
    fn attributes_are_decoded_from_base64() {
        let attributes = parse_attributes(json!({ "data": "AQID", "signature": "BAUG" })).unwrap();
        assert_eq!(attributes.data, vec![1, 2, 3]);
        assert_eq!(attributes.signature, vec![4, 5, 6]);
    }

    #[test]
    fn malformed_attributes_are_rejected() {
        for result in [
            json!({ "data": "AQID" }),
            json!({ "signature": "AQID" }),
            json!({ "data": 1, "signature": "AQID" }),
            json!({ "data": "not base64!", "signature": "AQID" }),
            json!(null),
        ] {
            let error = parse_attributes(result.clone()).unwrap_err();
            assert!(matches!(error, SignerError::Protocol(_)), "{result}");
        }
    }

    #[test]
    fn notification_consent_decodes_a_boolean_and_a_refusal_is_an_answer() {
        assert!(
            parse_notification_consent(json!({ "granted": true }))
                .unwrap()
                .granted
        );
        assert!(
            !parse_notification_consent(json!({ "granted": false }))
                .unwrap()
                .granted
        );
    }

    #[test]
    fn malformed_notification_consent_is_rejected() {
        for result in [json!({}), json!({ "granted": "yes" }), json!(null)] {
            let error = parse_notification_consent(result.clone()).unwrap_err();
            assert!(matches!(error, SignerError::Protocol(_)), "{result}");
        }
    }
}
