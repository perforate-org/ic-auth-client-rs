//! How the agents this client builds trust the host they talk to.
//!
//! An agent verifies canister responses against a root key, and `ic-agent`
//! starts from the mainnet one. A local replica (`icp network start`, a test instance)
//! signs with its own, so a host that talks to one either hands the key in
//! ([`AgentOptions::root_key`]) or asks the agent to read it from the replica's
//! `/api/v2/status` ([`AgentOptions::fetch_root_key`]).
//!
//! Fetching is opt-in, matching `ic-agent`: a build that talks to the mainnet
//! must never accept a root key from the peer it is verifying.
use std::sync::atomic::{AtomicBool, Ordering};

use ic_agent::Agent;

/// How an agent should trust the IC host it talks to.
#[derive(Clone, Debug, Default)]
pub struct AgentOptions {
    /// The host's known root key, for a replica that is not the mainnet.
    pub root_key: Option<Vec<u8>>,
    /// Read the root key from the host's `api/v2/status` on first use.
    ///
    /// Only for a local replica: against the mainnet this would trust whatever
    /// the endpoint claims. When `root_key` is set, that key is used and
    /// nothing is fetched.
    pub fetch_root_key: bool,
}

impl AgentOptions {
    /// Sets a configured root key, before the agent is first used.
    pub(crate) fn apply(&self, agent: &Agent) {
        if let Some(root_key) = &self.root_key {
            agent.set_root_key(root_key.clone());
        }
    }
}

/// Applies an [`AgentOptions`] and, when configured to, fetches the root key
/// once.
#[derive(Debug)]
pub(crate) struct AgentTrust {
    options: AgentOptions,
    fetched: AtomicBool,
}

impl AgentTrust {
    pub(crate) fn new(options: AgentOptions) -> Self {
        Self {
            options,
            fetched: AtomicBool::new(false),
        }
    }

    /// Applies the configured root key, if any. Synchronous: the agent exists
    /// before the first call.
    pub(crate) fn apply(&self, agent: &Agent) {
        self.options.apply(agent);
    }

    /// Fetches the host's root key from `api/v2/status` on first use.
    ///
    /// A no-op when no fetch was asked for, or when an explicit key was given.
    /// A failed fetch clears the flag so the next call tries again rather than
    /// leaving the agent silently on the mainnet key.
    pub(crate) async fn ensure(&self, agent: &Agent) -> Result<(), String> {
        if !self.options.fetch_root_key || self.options.root_key.is_some() {
            return Ok(());
        }
        if self.fetched.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Err(error) = agent.fetch_root_key().await {
            self.fetched.store(false, Ordering::SeqCst);
            return Err(format!(
                "could not fetch the root key from the IC host: {error}"
            ));
        }
        Ok(())
    }
}
