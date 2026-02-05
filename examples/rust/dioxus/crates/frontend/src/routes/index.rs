use crate::{
    contexts::auth::use_auth,
    features::{
        note::component::NoteComponent,
        user::account::{LoginButton, LogoutButton},
    },
};
use dioxus::prelude::*;

#[component]
pub fn Route() -> Element {
    let auth = use_auth();
    let is_authenticated = auth.read().is_authenticated;
    let principal = auth
        .read()
        .principal
        .as_ref()
        .map(|value| value.to_text())
        .unwrap_or_else(|| "Unknown".to_string());

    let section_class = if is_authenticated {
        "flex flex-col gap-6 justify-center items-center w-full text-center max-w-[60rem] flex-grow"
    } else {
        "flex flex-col gap-6 justify-center items-center w-full text-center max-w-[60rem]"
    };

    rsx! {
        main { class: "flex flex-col justify-center items-center p-8 w-screen h-screen",
            h1 { class: "text-4xl font-semibold text-center cursor-default",
                "ic-auth-client for Rust Example"
            }
            section { class: section_class,
                if is_authenticated {
                    div { class: "flex flex-col gap-2 items-center",
                        p { class: "text-xs pointer-events-none text-stone-600 dark:text-stone-400",
                            "You're logged in: {principal}"
                        }
                        LogoutButton {}
                    }
                    NoteComponent {}
                } else {
                    div { class: "flex flex-col gap-2 items-center",
                        p { class: "text-xs pointer-events-none text-stone-600 dark:text-stone-400",
                            "You're NOT logged in"
                        }
                        LoginButton {}
                    }
                }
            }
        }
    }
}
