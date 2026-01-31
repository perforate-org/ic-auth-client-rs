# Storage Compatibility Tests

This directory hosts Playwright-based compatibility tests for JS (`@icp-sdk/auth`) and Rust (Wasm)
storage formats.

## Run

```shell
make build-wasm-compat
pnpm install
pnpm test:compat
```

If Playwright browsers are not installed yet:

```shell
pnpm exec playwright install
```

## Notes

- JS-generated ECDSA keys are non-extractable by default, so Rust cannot read them back.
  The test asserts this expected failure to highlight the incompatibility.
