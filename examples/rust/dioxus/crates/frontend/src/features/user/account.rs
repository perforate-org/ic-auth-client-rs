use crate::contexts::auth::{AuthStoreExt, use_auth};
use dioxus::prelude::*;

#[component]
pub fn LoginButton() -> Element {
    let auth = use_auth();
    let is_authenticated = auth.read().is_authenticated;
    let disabled = auth.read().auth_client.is_none() || is_authenticated;

    rsx! {
        button {
            class: "btn btn-primary btn-soft btn-sm btn-wide",
            disabled,
            onclick: move |_| auth.login(),
            "Login"
        }
    }
}

#[component]
pub fn LogoutButton() -> Element {
    let auth = use_auth();
    let is_authenticated = auth.read().is_authenticated;
    let disabled = auth.read().auth_client.is_none() || !is_authenticated;

    rsx! {
        button {
            class: "btn btn-primary btn-soft btn-sm btn-wide",
            disabled,
            onclick: move |_| auth.logout(),
            "Logout"
        }
    }
}
