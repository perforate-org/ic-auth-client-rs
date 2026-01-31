//! Delegation chain utilities for managing signed delegations in the Internet Computer.
//!
//! This module provides the [`DelegationChain`] struct which represents a chain of cryptographic
//! delegations that can be serialized to JSON and used with delegation-based identities.
//! The chain includes validation functionality to check expiration times and scope restrictions.

use ic_agent::{export::Principal, identity::SignedDelegation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A chain of delegations.
///
/// This is the struct to serialize and pass to a DelegationIdentity. It does not keep any private keys.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DelegationChain {
    /// The delegations in the chain.
    pub delegations: Vec<SignedDelegation>,
    /// The public key associated with the chain.
    pub public_key: Vec<u8>,
}

impl DelegationChain {
    /// Create a new [`DelegationChain`].
    pub fn new(delegations: Vec<SignedDelegation>, public_key: Vec<u8>) -> Self {
        DelegationChain {
            delegations,
            public_key,
        }
    }

    /// Deserialize a [`DelegationChain`] from a JSON string (Rust format with snake_case).
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str(json).expect("Failed to parse delegation chain")
    }

    /// Serialize a [`DelegationChain`] to a JSON string (Rust format with snake_case).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize delegation chain")
    }

    /// Serialize a [`DelegationChain`] to JS-compatible JSON format.
    ///
    /// This format uses camelCase keys and hex-encoded binary data,
    /// compatible with the JavaScript `icp-js-auth` library.
    #[cfg(feature = "wasm-js")]
    pub fn to_js_json(&self) -> String {
        use crate::storage::js_compat::JsDelegationChain;
        let js_chain = JsDelegationChain::from_delegation_chain(self);
        serde_json::to_string(&js_chain).expect("Failed to serialize delegation chain to JS format")
    }

    /// Deserialize a [`DelegationChain`] from JS-compatible JSON format.
    ///
    /// This format uses camelCase keys and hex-encoded binary data,
    /// compatible with the JavaScript `icp-js-auth` library.
    #[cfg(feature = "wasm-js")]
    pub fn from_js_json(json: &str) -> Result<Self, crate::storage::DecodeError> {
        use crate::storage::js_compat::JsDelegationChain;
        let js_chain: JsDelegationChain = serde_json::from_str(json).map_err(|e| {
            crate::storage::DecodeError::Key(format!("Invalid JS delegation JSON: {}", e))
        })?;
        js_chain.to_delegation_chain()
    }

    /// Deserialize a [`DelegationChain`] from either JS or Rust JSON format.
    ///
    /// Automatically detects the format based on the JSON structure.
    #[cfg(feature = "wasm-js")]
    pub fn from_any_json(json: &str) -> Result<Self, crate::storage::DecodeError> {
        use crate::storage::js_compat::{DelegationFormat, detect_delegation_format};

        match detect_delegation_format(json) {
            DelegationFormat::Js => Self::from_js_json(json),
            DelegationFormat::Rust => Ok(Self::from_json(json)),
            DelegationFormat::Unknown => {
                // Try Rust format first, then JS format
                serde_json::from_str(json)
                    .map_err(|e| crate::storage::DecodeError::Key(e.to_string()))
                    .or_else(|_| Self::from_js_json(json))
            }
        }
    }

    /// Analyze a [`DelegationChain`] and validate that it's valid, ie. not expired and apply to the scope.
    ///
    /// # Arguments
    ///
    /// * `checks` - Principals to validate on the chain.
    pub fn is_delegation_valid(&self, checks: Option<Vec<Principal>>) -> bool {
        // Verify that the no delegation is expired. If any are in the chain, returns false.
        let now = now() * 1_000_000;
        if self
            .delegations
            .iter()
            .any(|signed_delegation| signed_delegation.delegation.expiration <= now)
        {
            return false;
        }

        // Check the scopes.
        if let Some(checks) = checks {
            let checks: HashSet<_> = checks.into_iter().collect();
            for signed_delegation in self.delegations.iter() {
                let delegation = &signed_delegation.delegation;
                if let Some(targets) = delegation.targets.clone() {
                    if targets.iter().all(|target| !checks.contains(target)) {
                        return false;
                    }
                }
            }
        }

        true
    }
}

fn now() -> u64 {
    #[cfg(feature = "native")]
    {
        chrono::Utc::now().timestamp_millis() as u64
    }

    #[cfg(not(feature = "native"))]
    {
        web_sys::js_sys::Date::now() as u64
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_delegation_chain() {
        let delegation_chain = DelegationChain {
            delegations: vec![],
            public_key: vec![1, 2, 3],
        };
        let json = delegation_chain.to_json();
        let delegation_chain2 = DelegationChain::from_json(&json);
        let json2 = delegation_chain2.to_json();
        assert_eq!(json, json2);
    }

    #[wasm_bindgen_test]
    fn test_is_delegation_valid() {
        let delegation_chain = DelegationChain {
            delegations: vec![],
            public_key: vec![1, 2, 3],
        };
        assert!(delegation_chain.is_delegation_valid(None));
    }

    #[wasm_bindgen_test]
    fn test_is_delegation_valid_expired() {
        let delegation_chain = DelegationChain {
            delegations: vec![SignedDelegation {
                delegation: ic_agent::identity::Delegation {
                    pubkey: vec![],
                    expiration: 0,
                    targets: None,
                },
                signature: vec![],
            }],
            public_key: vec![1, 2, 3],
        };
        assert!(!delegation_chain.is_delegation_valid(None));
    }
}
