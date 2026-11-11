#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/kotlin-package/IcAuthClient"

"${ROOT_DIR}/uniffi/generate_kotlin.sh"
"${PKG_DIR}/sync_uniffi_kotlin.sh"
"${PKG_DIR}/build_aar.sh"
