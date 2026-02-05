# ii-bridge

Minimal Internet Identity login page used by the native app integration.

## Setup

```sh
npm install
```

## Development

```sh
npm run dev
```

## Build

```sh
npm run build
```

## Configuration

`src/index.ts` derives the default identity provider from env and browser:

- `CANISTER_ID_INTERNET_IDENTITY` (required for local/dev URLs)
- `DFX_NETWORK` (`ic` for mainnet, anything else for local/dev)

## Structure

- `index.html`: login page markup
- `src/index.ts`: login flow and identity provider resolution
- `assets/`: static assets (logo)

## License

This project is licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT License](./LICENSE-MIT) at your option.
