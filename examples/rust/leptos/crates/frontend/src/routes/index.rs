use crate::{
    contexts::auth::{AuthStoreFields, use_auth},
    features::{
        note::component::NoteComponent,
        user::account::{LoginButton, LogoutButton},
    },
};
use leptos::{either::Either, prelude::*};

#[component]
pub fn Route() -> impl IntoView {
    let auth = use_auth().unwrap();
    let is_authenticated = auth.is_authenticated();
    let principal = auth.principal();

    view! {
        <main class="flex flex-col justify-center items-center p-8 w-screen h-screen">
            <h1 class="text-4xl font-semibold text-center cursor-default">"ic-auth-client for Rust Example"</h1>

                <section
                    class="flex flex-col gap-6 justify-center items-center w-full text-center max-w-[60rem]"
                    class:flex-grow=move || is_authenticated.get()
                >
                    {move || {
                        if is_authenticated.get() {
                            Either::Left(
                                view! {
                                    <div class="flex flex-col gap-2 items-center">
                                        <p class="text-xs pointer-events-none text-stone-600 dark:text-stone-400">{format!("You're logged in: {}", principal.get().unwrap())}</p>
                                        <LogoutButton />
                                    </div>

                                    <NoteComponent />
                                }
                            )
                        } else {
                            Either::Right(
                                view! {
                                    <div class="flex flex-col gap-2 items-center">
                                        <p class="text-xs pointer-events-none text-stone-600 dark:text-stone-400">"You're NOT logged in"</p>
                                        <LoginButton />
                                    </div>
                                }
                            )
                        }
                    }}
                </section>
        </main>
    }
}
