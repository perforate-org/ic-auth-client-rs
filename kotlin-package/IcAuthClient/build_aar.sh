#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/kotlin-package/IcAuthClient"
JNI_DIR="${PKG_DIR}/src/main/jniLibs"
FEATURES_DEFAULT="kotlin"
FEATURES="${KOTLIN_FEATURES:-${FEATURES_DEFAULT}}"

ABIS=(
  arm64-v8a
  armeabi-v7a
  x86_64
)

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "cargo-ndk is required. Install with: cargo install cargo-ndk"
  exit 1
fi

rm -rf "${JNI_DIR}"
mkdir -p "${JNI_DIR}"

cargo ndk \
  $(for abi in "${ABIS[@]}"; do printf -- '-t %s ' "${abi}"; done) \
  -o "${JNI_DIR}" \
  build --release --no-default-features --features "${FEATURES}"

if [[ -x "${ROOT_DIR}/gradlew" ]]; then
  (
    cd "${ROOT_DIR}"
    ./gradlew :kotlin-package:IcAuthClient:assembleRelease
  )
elif command -v gradle >/dev/null 2>&1; then
  (
    cd "${ROOT_DIR}"
    gradle :kotlin-package:IcAuthClient:assembleRelease
  )
else
  echo "Gradle is required. Add ./gradlew or install system gradle."
  exit 1
fi

echo "AAR created under: ${PKG_DIR}/build/outputs/aar"
