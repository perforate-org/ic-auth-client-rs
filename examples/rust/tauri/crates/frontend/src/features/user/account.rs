use crate::contexts::auth::{AuthStoreExt, use_auth};
use leptos::prelude::*;

#[component]
pub fn LoginButton() -> impl IntoView {
    let auth = use_auth().unwrap();

    view! {
        <button
            class="btn btn-primary btn-soft btn-sm btn-wide"
            on:click=move |_| auth.login()
        >
            "Login"
        </button>
    }
}

#[component]
pub fn LogoutButton() -> impl IntoView {
    let auth = use_auth().unwrap();
    view! {
        <button
            class="btn btn-primary btn-soft btn-sm btn-wide"
            on:click=move |_| auth.logout()
        >
            "Logout"
        </button>
    }
}
