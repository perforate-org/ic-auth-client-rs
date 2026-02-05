use candid::{CandidType, Decode, Encode};
use domain::note::{NoteId, NoteTitle, entity::Note};
use futures::channel::oneshot;
use ic_agent::{Agent, Identity};
use leptos::task::spawn_local;
use serde::Deserialize;
use std::time::Duration;
use util::{
    canister_id::BACKEND,
    dfx_network::{DFX_NETWORK, DfxNetwork, is_local_dfx},
};

const TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[derive(Debug, Clone)]
pub struct BackendActor {
    agent: Agent,
}

#[allow(dead_code)]
impl BackendActor {
    pub async fn new<T>(identity: T) -> Self
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

        if is_local_dfx() {
            agent.fetch_root_key().await.unwrap();
        }

        Self { agent }
    }

    async fn query<S, T>(&self, method: &'static str, arg: S) -> T
    where
        S: CandidType + Send + 'static,
        T: CandidType + for<'de> Deserialize<'de> + Send + 'static,
    {
        // This pattern ensures the future is Send by using a oneshot channel
        let agent = self.agent.clone();
        let backend = *BACKEND;
        let arg = Encode!(&arg).unwrap();

        let (tx, rx) = oneshot::channel();

        // Spawn a task that will execute the non-Send future and send the result back
        spawn_local(async move {
            let result = agent
                .query(&backend, method)
                .with_arg(arg)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to query call: canister_id: {}, method: {}, {:?}",
                        backend, method, e
                    );
                });

            let _ = tx.send(result);
        });

        // Wait for the result from the channel
        let res = rx.await.expect("Query task failed");

        Decode!(res.as_slice(), T).unwrap()
    }

    async fn update<S, T>(&self, method: &'static str, arg: S) -> T
    where
        S: CandidType + Send + 'static,
        T: CandidType + for<'de> Deserialize<'de> + Send + 'static,
    {
        // Similar pattern for update calls to ensure Send
        let agent = self.agent.clone();
        let backend = *BACKEND;
        let arg = Encode!(&arg).unwrap();

        let (tx, rx) = oneshot::channel();

        // Spawn a task that will execute the non-Send future and send the result back
        spawn_local(async move {
            let result = agent
                .update(&backend, method)
                .with_arg(arg)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to update call: canister_id: {}, method: {}, {:?}",
                        backend, method, e
                    );
                });

            let _ = tx.send(result);
        });

        // Wait for the result from the channel
        let res = rx.await.expect("Update task failed");

        Decode!(res.as_slice(), T).unwrap()
    }

    pub async fn fetch_note(&self, id: NoteId) -> Option<Note> {
        self.query("fetch_note", id).await
    }

    pub async fn fetch_note_list(&self) -> Vec<(NoteId, NoteTitle)> {
        self.query("fetch_note_list", ()).await
    }

    pub async fn post_note(&self, note: Note) {
        self.update("post_note", note).await
    }

    pub async fn delete_note(&self, id: NoteId) -> Result<(), String> {
        self.update("delete_note", id).await
    }
}
