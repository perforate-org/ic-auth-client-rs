#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/uniffi/generated/kotlin"
FEATURES_DEFAULT="kotlin"
FEATURES="${KOTLIN_FEATURES:-${FEATURES_DEFAULT}}"

mkdir -p "${OUT_DIR}"

# Build the cdylib with UniFFI metadata.
cargo build --no-default-features --features "${FEATURES}" --release

# Locate the built dynamic library used by uniffi-bindgen for metadata extraction.
LIB_PATH="${ROOT_DIR}/target/release"
LIB_NAME="libic_auth_client"

if [[ "$(uname)" == "Darwin" ]]; then
  DYLIB="${LIB_PATH}/${LIB_NAME}.dylib"
elif [[ "$(uname)" == "Linux" ]]; then
  DYLIB="${LIB_PATH}/${LIB_NAME}.so"
else
  echo "Unsupported OS for this script."
  exit 1
fi

if [[ ! -f "${DYLIB}" ]]; then
  echo "Library not found: ${DYLIB}"
  exit 1
fi

cargo run --no-default-features --features "${FEATURES}" --bin uniffi-bindgen generate --language kotlin --out-dir "${OUT_DIR}" --library "${DYLIB}"

echo "Kotlin bindings generated at: ${OUT_DIR}"
