#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/swift-package/IcAuthClient"

"${ROOT_DIR}/uniffi/generate_swift.sh"
"${PKG_DIR}/sync_uniffi_swift.sh"
"${PKG_DIR}/build_xcframework.sh"

