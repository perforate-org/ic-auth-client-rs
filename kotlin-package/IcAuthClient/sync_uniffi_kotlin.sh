#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/kotlin-package/IcAuthClient"
GEN_DIR="${ROOT_DIR}/uniffi/generated/kotlin"
OUT_DIR="${PKG_DIR}/src/main/kotlin/generated"

if [[ ! -d "${GEN_DIR}" ]]; then
  echo "Generated Kotlin bindings not found at: ${GEN_DIR}"
  echo "Run ./uniffi/generate_kotlin.sh first."
  exit 1
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

cp -R "${GEN_DIR}"/. "${OUT_DIR}/"

echo "Synced UniFFI Kotlin sources into: ${OUT_DIR}"
