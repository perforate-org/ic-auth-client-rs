use ic_agent::{Identity, export::Principal};
use ic_auth_client::{
    AuthClient, AuthClientCreateOptions, AuthClientLoginOptions, IdleOptions,
    idle_manager::IdleManagerOptions,
};
use leptos::{
    leptos_dom::logging::{console_log, console_warn},
    prelude::*,
    task::spawn_local,
};
use reactive_stores::Store;
use std::sync::Arc;
use util::{
    canister_id::INTERNET_IDENTITY,
    dfx_network::{DFX_NETWORK, DfxNetwork},
};

mod backend;
pub use backend::BackendActor;

const IDENTITY_PROVIDER: &str = "https://id.ai";

const AUTH_POPUP_WIDTH: u32 = 576;
// we need to temporarily increase the height so II 2.0 in "guided mode" fits the popup
// TODO: revert to 625 after II provides a fix on their end
const AUTH_POPUP_HEIGHT: u32 = 826;

// Guided upgrade flow (legacy users -> id.ai) requires:
// const IDENTITY_PROVIDER: &str = "https://id.ai/?feature_flag_guided_upgrade=true";

pub type AuthStore = Store<Auth>;

#[allow(dead_code)]
#[derive(Clone, Store)]
pub struct Auth {
    is_authenticated: bool,
    is_initialized: bool,
    auth_client: Option<AuthClient>,
    identity: Option<Arc<dyn Identity>>,
    principal: Option<Principal>,
    backend: Option<BackendActor>,
}

impl Auth {
    pub fn create_store(options: AuthClientCreateOptions) -> AuthStore {
        let store = Store::new(Auth {
            is_authenticated: false,
            is_initialized: false,
            auth_client: None,
            identity: None,
            principal: None,
            backend: None,
        });

        spawn_local(async move {
            let client = AuthClient::new_with_options(options)
                .await
                .expect("Failed to create AuthClient");
            Auth::update_with_client(store, client);
        });

        store
    }

    fn update_with_client(store: AuthStore, client: AuthClient) {
        let is_authenticated = client.is_authenticated();
        let identity = client.identity();
        let principal = client.principal().ok();

        spawn_local(async move {
            store.set(Auth {
                is_authenticated,
                is_initialized: true,
                auth_client: Some(client),
                identity: Some(identity.clone()),
                principal,
                backend: Some(BackendActor::new(identity).await),
            });
        });
    }

    pub fn login(store: AuthStore) {
        if let Some(client) = store.auth_client().get() {
            let client_clone = client.clone();
            let on_success = move |_| {
                console_log("Logged in successfully");
                if let Some(updated_client) = store.auth_client().get_untracked() {
                    Auth::update_with_client(store, updated_client);
                }
            };

            let on_error = |e| {
                if let Some(e) = e {
                    console_warn(&format!("Failed to login: {:?}", e));
                } else {
                    console_warn("Failed to login");
                }
            };

            let options = AuthClientLoginOptions::builder()
                .window_opener_features(popup_center(AUTH_POPUP_WIDTH, AUTH_POPUP_HEIGHT))
                .on_success(on_success)
                .on_error(on_error);

            let options = match identity_provider() {
                Some(provider) => options.identity_provider(provider).build(),
                None => options.build(),
            };

            client_clone.login_with_options(options); // Use the cloned client
        }
    }

    pub fn logout(store: AuthStore) {
        if let Some(client) = store.auth_client().get() {
            let client_clone = client.clone();
            spawn_local(async move {
                client_clone.logout(None).await;
                if let Some(updated_client) = store.auth_client().get_untracked() {
                    console_log("Logged off successfully");
                    Auth::update_with_client(store, updated_client);
                }
            });
        }
    }
}

fn identity_provider() -> Option<String> {
    // Check if we're in a browser context
    if let Some(window) = web_sys::window() {
        // Check if the network is local
        let is_local = *DFX_NETWORK == DfxNetwork::Local;

        // Check if browser is Safari
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
    let screen_width = window().inner_width().unwrap().as_f64().unwrap() as u32;
    let screen_height = window().inner_height().unwrap().as_f64().unwrap() as u32;

    let left = (screen_width - width) / 2;
    let top = (screen_height - height) / 2;

    format!(
        "toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no, copyhistory=no, width={width}, height={height}, top={top}, left={left}"
    )
}

#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let auth_store = Auth::create_store(
        AuthClientCreateOptions::builder()
            .idle_options(
                IdleOptions::builder()
                    .idle_manager_options(
                        IdleManagerOptions::builder()
                            .idle_timeout(5 * 1000) // 5 seconds
                            .on_idle(|| console_log("User is idle"))
                            .build(),
                    )
                    .build(),
            )
            .build(),
    );

    provide_context(auth_store);

    children()
}

/// Hook to access the Auth context.
pub fn use_auth() -> Result<AuthStore, String> {
    use_context::<AuthStore>().ok_or("Out of the Auth context".to_string())
}

/// Extension trait for Auth to provide a more ergonomic API
pub trait AuthStoreExt {
    fn login(self);
    fn logout(self);
}

impl AuthStoreExt for AuthStore {
    fn login(self) {
        Auth::login(self);
    }

    fn logout(self) {
        Auth::logout(self);
    }
}
