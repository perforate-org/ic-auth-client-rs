use anyhow::{Context, Result, anyhow};
use bevy::log::{debug, error};
use candid::{CandidType, Decode, Encode};
use ic_agent::{Agent, Identity, export::Principal};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::runtime::{Builder, Runtime};
use util::{
    canister_id::BACKEND,
    dfx_network::{DFX_NETWORK, DfxNetwork, is_local_dfx},
};

const TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct ScoreEntry {
    pub player: Principal,
    pub score: u32,
}

pub struct BackendActor {
    agent: Agent,
    runtime: Arc<Runtime>,
}

impl Clone for BackendActor {
    fn clone(&self) -> Self {
        Self {
            agent: self.agent.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

#[allow(dead_code)]
impl BackendActor {
    pub fn new<T>(identity: T) -> Self
    where
        T: Identity + 'static,
    {
        let url = match *DFX_NETWORK {
            DfxNetwork::Local => "http://localhost:4943".to_string(),
            DfxNetwork::Ic => "https://ic0.app".to_string(),
        };

        let agent = Agent::builder()
            .with_url(url)
            .with_identity(identity)
            .with_ingress_expiry(TIMEOUT)
            .build()
            .expect("Failed to create agent");

        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        if is_local_dfx() {
            runtime.block_on(agent.fetch_root_key()).unwrap();
        }

        Self {
            agent,
            runtime: Arc::new(runtime),
        }
    }

    async fn query<S, T>(&self, method: &'static str, arg: S) -> Result<T>
    where
        S: CandidType + Send + 'static,
        T: CandidType + for<'de> Deserialize<'de> + Send + 'static,
    {
        // This pattern ensures the future is Send by using a oneshot channel
        let agent = self.agent.clone();
        let backend = *BACKEND;
        let arg = Encode!(&arg).unwrap();
        let handle = self.runtime.handle().clone();

        let response = handle
            .spawn(async move {
                debug!(
                    method,
                    canister = %backend,
                    arg_bytes = arg.len(),
                    "Sending backend query"
                );
                agent.query(&backend, method).with_arg(arg).await
            })
            .await
            .context("Backend query task failed to join")?
            .map_err(|e| {
                error!(method, canister = %backend, ?e, "Backend query failed");
                anyhow!("Failed to query backend: {e}")
            })?;

        Decode!(response.as_slice(), T)
            .map_err(|e| anyhow!("Failed to decode backend response for {method}: {e}"))
    }

    async fn update<S, T>(&self, method: &'static str, arg: S) -> Result<T>
    where
        S: CandidType + Send + 'static,
        T: CandidType + for<'de> Deserialize<'de> + Send + 'static,
    {
        // Similar pattern for update calls to ensure Send
        let agent = self.agent.clone();
        let backend = *BACKEND;
        let arg = Encode!(&arg).unwrap();
        let handle = self.runtime.handle().clone();

        let response = handle
            .spawn(async move {
                debug!(
                    method,
                    canister = %backend,
                    arg_bytes = arg.len(),
                    "Sending backend update"
                );
                agent.update(&backend, method).with_arg(arg).await
            })
            .await
            .context("Backend update task failed to join")?
            .map_err(|e| {
                error!(method, canister = %backend, ?e, "Backend update failed");
                anyhow!("Failed to update backend: {e}")
            })?;

        Decode!(response.as_slice(), T)
            .map_err(|e| anyhow!("Failed to decode backend response for {method}: {e}"))
    }

    pub async fn submit_score(&self, score: u32) -> Result<ScoreEntry> {
        self.update("submit_score", score).await
    }

    pub async fn get_score(&self, player: Principal) -> Result<Option<ScoreEntry>> {
        self.query("get_score", player).await
    }

    pub async fn get_leaderboard(&self, limit: Option<u32>) -> Result<Vec<ScoreEntry>> {
        self.query("get_leaderboard", limit).await
    }
}
