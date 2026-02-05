use dioxus::prelude::*;

mod contexts;
mod features;
mod routes;

use contexts::auth::AuthProvider;
use routes::AppRouter;

fn main() {
    console_error_panic_hook::set_once();
    launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Stylesheet {href: asset!("/public/main.css")}
        AuthProvider {
            AppRouter {}
        }
    }
}
