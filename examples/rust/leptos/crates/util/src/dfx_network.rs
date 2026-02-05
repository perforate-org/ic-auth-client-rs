use once_cell::sync::Lazy;
use std::env;

pub static DFX_NETWORK: Lazy<DfxNetwork> = Lazy::new(DfxNetwork::from_env);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfxNetwork {
    Local,
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
