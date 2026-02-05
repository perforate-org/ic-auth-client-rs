use candid::Principal;
use dotenvy_macro::dotenv;
use once_cell::sync::Lazy;
use std::env;

pub static BACKEND: Lazy<Principal> = Lazy::new(|| {
    let mut canister_id = dotenv!("CANISTER_ID_BACKEND").to_string();
    if canister_id.is_empty() {
        canister_id = env::var("CANISTER_ID_BACKEND").expect("CANISTER_ID_BACKEND is must be set");
    }

    parce_principal(canister_id)
});

pub static INTERNET_IDENTITY: Lazy<Principal> = Lazy::new(|| {
    let mut canister_id = dotenv!("CANISTER_ID_INTERNET_IDENTITY").to_string();
    if canister_id.is_empty() {
        canister_id = env::var("CANISTER_ID_INTERNET_IDENTITY")
            .expect("CANISTER_ID_INTERNET_IDENTITY is must be set");
    }

    parce_principal(canister_id)
});

fn parce_principal(canister_id: String) -> Principal {
    Principal::from_text(canister_id).expect("Failed to get backend canister id")
}
