# IcAuthClient (Android AAR)

Android/Kotlin wrapper for UniFFI-generated Kotlin bindings of `ic-auth-client`.

## Build all

From repository root:

```sh
kotlin-package/IcAuthClient/build_all.sh
```

This runs:

1. `./uniffi/generate_kotlin.sh` to generate Kotlin bindings.
2. `sync_uniffi_kotlin.sh` to sync generated Kotlin into `src/main/kotlin/generated`.
3. `build_aar.sh` to build JNI `.so` files and produce an AAR.

## Requirements

- Rust toolchain
- `cargo-ndk` (`cargo install cargo-ndk`)
- Android SDK / NDK
- Gradle (wrapper or system `gradle`)

## Output

- JNI libs: `src/main/jniLibs/<abi>/libic_auth_client.so`
- AAR: `build/outputs/aar/`

## Android password storage

Kotlin bindings expose `AuthClient.newWithPassword(serviceName, storageDir, password)`.
Pass an app-private directory such as `context.filesDir.absolutePath` for `storageDir`.

## Notes

- Default Rust features are `kotlin` (includes Android password storage). Override by setting `KOTLIN_FEATURES`.
- Example: `KOTLIN_FEATURES="kotlin" kotlin-package/IcAuthClient/build_all.sh`
