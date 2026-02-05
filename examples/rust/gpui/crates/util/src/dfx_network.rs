use once_cell::sync::Lazy;
use std::env;

/// Global static reference to the current DFX network configuration.
/// This is lazily initialized from the environment variable `DFX_NETWORK`.
pub static DFX_NETWORK: Lazy<DfxNetwork> = Lazy::new(DfxNetwork::from_env);

/// Represents the different DFX network environments.
///
/// This enum is used to distinguish between local development and production
/// Internet Computer networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfxNetwork {
    /// Local development network
    Local,
    /// Internet Computer mainnet
    Ic,
}

impl DfxNetwork {
    pub fn from_env() -> Self {
        let network = env::var("DFX_NETWORK").unwrap_or_else(|_| "local".to_string());
        match network.as_str() {
            "local" => DfxNetwork::Local,
            "ic" => DfxNetwork::Ic,
            _ => panic!("Invalid DFX_NETWORK value"),
        }
    }
}

/// Returns true if the current DFX_NETWORK is Local.
pub fn is_local_dfx() -> bool {
    *DFX_NETWORK == DfxNetwork::Local
}
