#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Url, WebviewWindowBuilder, webview::NewWindowResponse};

fn is_idp_url(url: &Url) -> bool {
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }

    let host = match url.host_str() {
        Some(host) => host,
        None => return false,
    };

    if matches!(
        host,
        "id.ai"
            | "identity.ic0.app"
            | "identity.internetcomputer.org"
            | "identity.icp0.io"
            | "identity.internetcomputer.app"
    ) {
        return true;
    }

    if host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost") {
        return url.port_or_known_default() == Some(4943);
    }

    false
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let mut builder = WebviewWindowBuilder::from_config(
                app.handle(),
                app.config()
                    .app
                    .windows
                    .first()
                    .expect("missing window config"),
            )?;

            builder = builder.on_new_window(move |url, features| {
                if !is_idp_url(&url) {
                    return NewWindowResponse::Deny;
                }
                let _ = features;
                NewWindowResponse::Allow
            });

            builder.build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
