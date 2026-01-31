# Example for Dioxus

This example demonstrates how to use `ic-auth-client` in a Dioxus Web app with
frontend assets and a Rust backend canister.

## Getting Started

Both dfx and Dioxus CLI commands occupy the console while running, so you'll need to use separate terminal windows for each.

First, in one terminal, start the local PocketIC:

```bash
dfx start
```

Then, in a second terminal, deploy your canisters and start the Dioxus development server.
Tailwind watch also needs its own terminal while running, so use a third terminal for it:

```bash
dfx deploy

make tailwind-watch

dx serve --platform web -p frontend
```

## Prerequisites

- [Rust](https://www.rust-lang.org/)
- [Dioxus CLI](https://dioxuslabs.com/learn/0.7/getting_started)
- [IC SDK](https://github.com/dfinity/sdk)
