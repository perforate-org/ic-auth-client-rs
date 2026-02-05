use anyhow::Result;
use flume::{Receiver, Sender, unbounded};
use ic_agent::{Identity, export::Principal};
use ic_auth_client::{
    AuthClientLoginOptions, NativeAuthClient as AuthClient, api::AuthResponseSuccess,
};
use std::sync::Arc;
use tracing::{debug, error, info};
use util::{canister_id::II_BRIDGE, dfx_network::is_local_dfx};

mod backend;
pub use backend::{BackendActor, TodoItem};

#[derive(Debug, Clone)]
pub enum AuthSignal {
    LoginComplete,
    LoginFailed,
}

pub struct Signal {
    rx: Receiver<AuthSignal>,
    tx: Sender<AuthSignal>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum AuthState {
    Authenticated(Principal),
    Authenticating,
    #[default]
    Unauthenticated,
}

pub struct Auth {
    pub state: AuthState,
    pub auth_client: AuthClient,
    pub identity: Arc<dyn Identity>,
    pub backend: BackendActor,
    pub identity_signal: Signal,
}

impl Auth {
    pub fn new() -> Result<Self> {
        info!("Initializing authentication client");
        let auth_client = AuthClient::new("gpui_example")?;
        let state = if auth_client.is_authenticated() {
            let principal = auth_client.principal().unwrap();
            info!(%principal, "Existing Internet Identity session detected");
            AuthState::Authenticated(principal)
        } else {
            AuthState::Unauthenticated
        };
        let identity = auth_client.identity();
        let backend = BackendActor::new(identity.clone());
        let (identity_tx, identity_rx) = unbounded();
        let identity_signal = Signal {
            rx: identity_rx,
            tx: identity_tx,
        };

        Ok(Self {
            state,
            auth_client,
            identity,
            backend,
            identity_signal,
        })
    }

    pub fn login(&mut self) -> Result<()> {
        info!("Starting Internet Identity login flow");
        self.state = AuthState::Authenticating;

        let identity_tx = self.identity_signal.tx.clone();
        let success_tx = identity_tx.clone();
        let on_success = move |res: AuthResponseSuccess| {
            info!(
                auth_method = res.authn_method,
                delegations = res.delegations.len(),
                "Login successful, waiting for state sync"
            );
            let _ = success_tx.send(AuthSignal::LoginComplete);
        };

        let on_error = move |err: Option<String>| {
            error!(?err, "Internet Identity login failed");
            let _ = identity_tx.send(AuthSignal::LoginFailed);
        };

        let options = AuthClientLoginOptions::builder()
            .on_success(on_success)
            .on_error(on_error)
            .build();

        self.auth_client.login(ii_bridge(), options);
        Ok(())
    }

    pub fn logout(&mut self) -> Result<()> {
        self.auth_client.logout();
        self.update_state();
        Ok(())
    }

    pub fn update_state(&mut self) {
        let new_identity = self.auth_client.identity().clone();
        self.state = if self.auth_client.is_authenticated() {
            let principal = self.auth_client.principal().unwrap();
            info!(%principal, "Authentication state updated");
            AuthState::Authenticated(principal)
        } else {
            info!("Authentication state changed to unauthenticated");
            AuthState::Unauthenticated
        };
        self.identity = new_identity.clone();
        self.backend = BackendActor::new(new_identity);
    }

    pub fn update_state_signal(&mut self) -> bool {
        if let Ok(signal) = self.identity_signal.rx.try_recv() {
            match signal {
                AuthSignal::LoginComplete => {
                    debug!("Received login-complete signal");
                    self.update_state();
                    return true;
                }
                AuthSignal::LoginFailed => {
                    debug!("Received login-failed signal");
                    self.state = AuthState::Unauthenticated;
                    return true;
                }
            }
        }
        false
    }

    pub fn signal_receiver(&self) -> Receiver<AuthSignal> {
        self.identity_signal.rx.clone()
    }

    pub fn is_authenticated(&self) -> bool {
        self.auth_client.is_authenticated()
    }
}

fn ii_bridge() -> String {
    if is_local_dfx() {
        return format!("http://localhost:4943/?canisterId={}", *II_BRIDGE);
    }

    format!("https://{}.ic0.app/", *II_BRIDGE)
}
