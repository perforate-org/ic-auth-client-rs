# Example for Tauri + Leptos

## Getting Started

Both dfx, trunk, and tauri dev commands occupy the console while running, so you'll need to use separate terminal windows for each.

First, in one terminal, start the local PocketIC:

```bash
dfx start
```

Then, in a second terminal, deploy your canisters and start the Trunk development server:

```bash
dfx deploy

trunk serve
```

Finally, in a third terminal, launch the Tauri app:

```bash
cargo tauri dev
```

To create a release build:

```bash
trunk build --release
cargo tauri build
```

## Prerequisites

- [Rust](https://www.rust-lang.org/)
- [Trunk](https://github.com/thedodd/trunk)
- [IC SDK](https://github.com/dfinity/sdk)
- [Tauri CLI](https://tauri.app/) (`cargo install tauri-cli`)
