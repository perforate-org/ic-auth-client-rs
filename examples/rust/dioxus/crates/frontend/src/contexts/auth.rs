use crate::contexts::auth::backend::BackendActor;
use dioxus::prelude::*;
use ic_agent::{Identity, export::Principal};
use ic_auth_client::{
    AuthClient, AuthClientCreateOptions, AuthClientLoginOptions, IdleOptions,
    idle_manager::IdleManagerOptions,
};
use std::sync::Arc;
use util::{
    canister_id::INTERNET_IDENTITY,
    dfx_network::{DFX_NETWORK, DfxNetwork},
};
use wasm_bindgen_futures::spawn_local;

use crate::features::note::component::Backend;

pub mod backend;

const IDENTITY_PROVIDER: &str = "https://id.ai";

const AUTH_POPUP_WIDTH: u32 = 576;
// we need to temporarily increase the height so II 2.0 in "guided mode" fits the popup
// TODO: revert to 625 after II provides a fix on their end
const AUTH_POPUP_HEIGHT: u32 = 826;

#[derive(Clone)]
pub struct AuthState {
    pub is_authenticated: bool,
    pub is_initialized: bool,
    pub auth_client: Option<AuthClient>,
    pub identity: Option<Arc<dyn Identity>>,
    pub principal: Option<Principal>,
    pub backend: Option<BackendActor>,
}

impl AuthState {
    fn new() -> Self {
        Self {
            is_authenticated: false,
            is_initialized: false,
            auth_client: None,
            identity: None,
            principal: None,
            backend: None,
        }
    }

    fn update_with_client(store: AuthStore, client: AuthClient) {
        let is_authenticated = client.is_authenticated();
        let identity = client.identity();
        let principal = client.principal().ok();

        let mut store = store;
        spawn_local(async move {
            let backend = BackendActor::new(identity.clone()).await;
            store.set(AuthState {
                is_authenticated,
                is_initialized: true,
                auth_client: Some(client),
                identity: Some(identity),
                principal,
                backend: Some(backend),
            });
        });
    }

    pub fn login(store: AuthStore) {
        let Some(client) = store.read().auth_client.clone() else {
            return;
        };

        let on_success = move |_| {
            if let Some(updated_client) = store.read().auth_client.clone() {
                AuthState::update_with_client(store, updated_client);
            }
        };

        let on_error = |_| {};

        let options = AuthClientLoginOptions::builder()
            .window_opener_features(popup_center(AUTH_POPUP_WIDTH, AUTH_POPUP_HEIGHT))
            .on_success(on_success)
            .on_error(on_error);

        let options = match identity_provider() {
            Some(provider) => options.identity_provider(provider).build(),
            None => options.build(),
        };

        client.login_with_options(options);
    }

    pub fn logout(store: AuthStore) {
        let Some(client) = store.read().auth_client.clone() else {
            return;
        };

        spawn_local(async move {
            client.logout(None).await;
            if let Some(updated_client) = store.read().auth_client.clone() {
                AuthState::update_with_client(store, updated_client);
            }
        });
    }
}

pub type AuthStore = SyncSignal<AuthState>;

#[component]
pub fn AuthProvider(children: Element) -> Element {
    let auth_store = use_signal_sync(AuthState::new);
    let auth_store = use_context_provider(|| auth_store);

    let _auth_init = use_future(move || async move {
        let options = AuthClientCreateOptions::builder()
            .idle_options(
                IdleOptions::builder()
                    .idle_manager_options(
                        IdleManagerOptions::builder()
                            .idle_timeout(5 * 1000)
                            .on_idle(|| {})
                            .build(),
                    )
                    .build(),
            )
            .build();

        if let Ok(client) = AuthClient::new_with_options(options).await {
            AuthState::update_with_client(auth_store, client);
        }
    });

    let _ = use_context_provider(|| Backend::new(auth_store));

    rsx! { {children} }
}

pub fn use_auth() -> AuthStore {
    use_context::<AuthStore>()
}

pub trait AuthStoreExt {
    fn login(&self);
    fn logout(&self);
}

impl AuthStoreExt for AuthStore {
    fn login(&self) {
        AuthState::login(*self);
    }

    fn logout(&self) {
        AuthState::logout(*self);
    }
}

fn identity_provider() -> Option<String> {
    if let Some(window) = web_sys::window() {
        let is_local = *DFX_NETWORK == DfxNetwork::Local;

        if let Ok(user_agent) = window.navigator().user_agent() {
            let user_agent = user_agent.to_lowercase();
            let is_safari = user_agent.contains("safari")
                && !user_agent.contains("chrome")
                && !user_agent.contains("android");

            if is_local && is_safari {
                return Some(format!(
                    "http://localhost:4943/?canisterId={}",
                    *INTERNET_IDENTITY
                ));
            } else if is_local {
                return Some(format!("http://{}.localhost:4943", *INTERNET_IDENTITY));
            }
        }
    }

    Some(IDENTITY_PROVIDER.to_string())
}

fn popup_center(width: u32, height: u32) -> String {
    let window = web_sys::window();
    let (screen_width, screen_height) = match window {
        Some(window) => (
            window
                .inner_width()
                .ok()
                .and_then(|value| value.as_f64())
                .unwrap_or(1200.0) as u32,
            window
                .inner_height()
                .ok()
                .and_then(|value| value.as_f64())
                .unwrap_or(800.0) as u32,
        ),
        None => (1200, 800),
    };

    let left = (screen_width.saturating_sub(width)) / 2;
    let top = (screen_height.saturating_sub(height)) / 2;

    format!(
        "toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no, copyhistory=no, width={width}, height={height}, top={top}, left={left}"
    )
}
