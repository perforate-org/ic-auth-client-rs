//! JS compatibility module for storage format conversion.
//!
//! This module provides serialization and deserialization functions that are compatible
//! with the JavaScript `icp-js-auth` library, enabling seamless data sharing between
//! Rust and JavaScript implementations.

use crate::storage::DecodeError;
use base64::prelude::*;
use ed25519_dalek::SigningKey;

/// Ed25519 DER public key prefix as hex string (OID 1.3.101.112)
const ED25519_DER_PREFIX_HEX: &str = "302a300506032b6570032100";

/// Detected format of stored identity data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFormat {
    /// JS Ed25519: JSON array `["<pubkey_der_hex>", "<secret_hex>"]`
    JsEd25519,
    /// Rust Ed25519: 32 raw bytes (Base64 encoded in string form)
    RustEd25519,
    /// Rust P-256: SEC1 DER format
    RustPrime256v1,
    /// Rust secp256k1: SEC1 DER format
    RustSecp256k1,
    /// Unknown format
    Unknown,
}

/// Detected format of stored delegation chain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationFormat {
    /// JS format: camelCase keys, hex-encoded binary data
    Js,
    /// Rust format: snake_case keys, byte arrays
    Rust,
    /// Unknown format
    Unknown,
}

/// Detect the format of a stored identity key
pub fn detect_identity_format(stored: &str) -> IdentityFormat {
    // Try JS Ed25519 format: JSON array of 2 hex strings
    if let Ok(arr) = serde_json::from_str::<[String; 2]>(stored) {
        if arr[0].starts_with(ED25519_DER_PREFIX_HEX) {
            // JS stores only the 32-byte seed (64 hex chars) while Rust stores seed+pub (128 hex chars).
            if arr[1].len() == 64 || arr[1].len() == 128 {
                return IdentityFormat::JsEd25519;
            }
        }
    }

    // Try Rust Base64 format
    if let Ok(bytes) = base64::prelude::BASE64_STANDARD_NO_PAD.decode(stored) {
        if bytes.len() == 32 {
            return IdentityFormat::RustEd25519;
        }
        // Could be P-256 or secp256k1 DER
        if bytes.len() > 32 {
            if p256::SecretKey::from_sec1_der(&bytes).is_ok() {
                return IdentityFormat::RustPrime256v1;
            }
            if k256::SecretKey::from_sec1_der(&bytes).is_ok() {
                return IdentityFormat::RustSecp256k1;
            }
        }
    }

    IdentityFormat::Unknown
}

/// Detect the format of a stored delegation chain
pub fn detect_delegation_format(json: &str) -> DelegationFormat {
    // Check for JS format (camelCase "publicKey")
    if json.contains("\"publicKey\"") && !json.contains("\"public_key\"") {
        return DelegationFormat::Js;
    }
    // Check for Rust format (snake_case "public_key")
    if json.contains("\"public_key\"") {
        return DelegationFormat::Rust;
    }
    DelegationFormat::Unknown
}

// ============================================================================
// JS Ed25519 Identity Format
// ============================================================================

/// Serialize Ed25519 key to JS-compatible format.
///
/// JS format: `["<public_key_der_hex>", "<secret_key_hex>"]`
/// - Public key: DER-encoded (44 bytes as hex = 88 chars)
/// - Secret key: seed (32 bytes) + public key (32 bytes) = 64 bytes as hex = 128 chars
pub fn serialize_ed25519_to_js(signing_key: &SigningKey) -> String {
    let public_key = signing_key.verifying_key();

    // Public key: DER prefix + raw bytes (as hex)
    let public_hex = format!(
        "{}{}",
        ED25519_DER_PREFIX_HEX,
        hex::encode(public_key.as_bytes())
    );

    // Secret: seed (32 bytes) + public key (32 bytes) = 64 bytes (as hex)
    let mut secret_bytes = Vec::with_capacity(64);
    secret_bytes.extend_from_slice(&signing_key.to_bytes());
    secret_bytes.extend_from_slice(public_key.as_bytes());
    let secret_hex = hex::encode(&secret_bytes);

    serde_json::to_string(&[public_hex, secret_hex]).expect("Failed to serialize Ed25519 to JS")
}

/// Deserialize Ed25519 key from JS format.
///
/// JS format: `["<public_key_der_hex>", "<secret_key_hex>"]`
pub fn deserialize_ed25519_from_js(json: &str) -> Result<SigningKey, DecodeError> {
    let arr: [String; 2] = serde_json::from_str(json)
        .map_err(|e| DecodeError::Key(format!("Invalid JS Ed25519 JSON: {}", e)))?;

    let secret_bytes = hex::decode(&arr[1])
        .map_err(|e| DecodeError::Key(format!("Invalid hex in JS Ed25519 secret: {}", e)))?;

    if secret_bytes.len() < 32 {
        return Err(DecodeError::Key(format!(
            "JS Ed25519 secret too short: {} bytes",
            secret_bytes.len()
        )));
    }

    let seed: [u8; 32] = secret_bytes[0..32]
        .try_into()
        .map_err(|_| DecodeError::Ed25519("Invalid seed length".to_string()))?;

    Ok(SigningKey::from_bytes(&seed))
}

// ============================================================================
// JS Delegation Chain Format
// ============================================================================

use ic_agent::{export::Principal, identity::SignedDelegation};
use serde::{Deserialize, Serialize};

/// JS-compatible delegation chain format.
///
/// Matches the JSON structure used by `icp-js-auth`:
/// ```json
/// {
///   "delegations": [...],
///   "publicKey": "<hex>"
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsDelegationChain {
    /// The signed delegations in the chain.
    pub delegations: Vec<JsSignedDelegation>,
    /// The public key associated with the chain (hex-encoded).
    pub public_key: String,
}

/// A signed delegation in JS-compatible format.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsSignedDelegation {
    /// The delegation details.
    pub delegation: JsDelegation,
    /// The signature (hex-encoded).
    pub signature: String,
}

/// A delegation in JS-compatible format.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsDelegation {
    /// The public key this delegation is for (hex-encoded).
    pub pubkey: String,
    /// The expiration time as a hex-encoded BigInt (nanoseconds since epoch).
    pub expiration: String,
    /// Optional target canister principals (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
}

impl JsDelegationChain {
    /// Convert from internal DelegationChain to JS-compatible format.
    pub fn from_delegation_chain(chain: &crate::util::delegation_chain::DelegationChain) -> Self {
        JsDelegationChain {
            delegations: chain
                .delegations
                .iter()
                .map(|d| JsSignedDelegation {
                    delegation: JsDelegation {
                        pubkey: hex::encode(&d.delegation.pubkey),
                        expiration: format!("{:x}", d.delegation.expiration),
                        targets: d
                            .delegation
                            .targets
                            .as_ref()
                            .map(|t| t.iter().map(|p| hex::encode(p.as_slice())).collect()),
                    },
                    signature: hex::encode(&d.signature),
                })
                .collect(),
            public_key: hex::encode(&chain.public_key),
        }
    }

    /// Convert to internal DelegationChain from JS-compatible format.
    pub fn to_delegation_chain(
        &self,
    ) -> Result<crate::util::delegation_chain::DelegationChain, DecodeError> {
        let delegations: Result<Vec<SignedDelegation>, DecodeError> = self
            .delegations
            .iter()
            .map(|d| {
                let pubkey = hex::decode(&d.delegation.pubkey).map_err(|e| {
                    DecodeError::Key(format!("Invalid hex in delegation pubkey: {}", e))
                })?;

                let expiration = u64::from_str_radix(&d.delegation.expiration, 16)
                    .map_err(|e| DecodeError::Key(format!("Invalid expiration hex: {}", e)))?;

                let targets = d.delegation.targets.as_ref().map(|t| {
                    t.iter()
                        .filter_map(|p| {
                            hex::decode(p)
                                .ok()
                                .and_then(|b| Principal::try_from_slice(b.as_slice()).ok())
                        })
                        .collect()
                });

                let signature = hex::decode(&d.signature).map_err(|e| {
                    DecodeError::Key(format!("Invalid hex in delegation signature: {}", e))
                })?;

                Ok(SignedDelegation {
                    delegation: ic_agent::identity::Delegation {
                        pubkey,
                        expiration,
                        targets,
                    },
                    signature,
                })
            })
            .collect();

        let public_key = hex::decode(&self.public_key)
            .map_err(|e| DecodeError::Key(format!("Invalid hex in public_key: {}", e)))?;

        Ok(crate::util::delegation_chain::DelegationChain {
            delegations: delegations?,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_js_roundtrip() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        let js_json = serialize_ed25519_to_js(&signing_key);
        let restored = deserialize_ed25519_from_js(&js_json).unwrap();

        assert_eq!(signing_key.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_detect_js_ed25519_format() {
        // Sample JS format from icp-js-auth tests
        let js_format = r#"["302a300506032b6570032100d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809","4bbff6b476463558d7be318aa342d1a97778d70833038680187950e9e02486c0d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809"]"#;

        assert_eq!(detect_identity_format(js_format), IdentityFormat::JsEd25519);
    }

    #[test]
    fn test_deserialize_js_ed25519() {
        // Sample from JS tests
        let js_format = r#"["302a300506032b6570032100d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809","4bbff6b476463558d7be318aa342d1a97778d70833038680187950e9e02486c0d1fa89134802051c8b5d4e53c08b87381b87097bca4c4f348611eb8ce6c91809"]"#;

        let signing_key = deserialize_ed25519_from_js(js_format).unwrap();

        // Verify the seed matches expected
        let expected_seed =
            hex::decode("4bbff6b476463558d7be318aa342d1a97778d70833038680187950e9e02486c0")
                .unwrap();
        assert_eq!(signing_key.to_bytes().as_slice(), expected_seed.as_slice());
    }

    #[test]
    fn test_detect_delegation_format() {
        let js_format = r#"{"delegations":[],"publicKey":"abc123"}"#;
        let rust_format = r#"{"delegations":[],"public_key":[1,2,3]}"#;

        assert_eq!(detect_delegation_format(js_format), DelegationFormat::Js);
        assert_eq!(
            detect_delegation_format(rust_format),
            DelegationFormat::Rust
        );
    }
}
