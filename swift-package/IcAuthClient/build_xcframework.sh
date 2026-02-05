#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/swift-package/IcAuthClient"
OUT_DIR="${PKG_DIR}/IcAuthClientFFI.xcframework"
BUILD_DIR="${ROOT_DIR}/target/uniffi-build"
HEADERS_DIR="${BUILD_DIR}/headers"

IOS_FEATURES_DEFAULT="keyring,swift"
MAC_FEATURES_DEFAULT="keyring,swift"
IOS_FEATURES="${IOS_FEATURES:-${IOS_FEATURES_DEFAULT}}"
MAC_FEATURES="${MAC_FEATURES:-${MAC_FEATURES_DEFAULT}}"

# Targets to build. Adjust if you want fewer platforms.
IOS_DEVICE_TARGET="aarch64-apple-ios"
IOS_SIM_ARM_TARGET="aarch64-apple-ios-sim"
MAC_X86_TARGET="x86_64-apple-darwin"
MAC_ARM_TARGET="aarch64-apple-darwin"

LIB_NAME="ic_auth_client"

rm -rf "${BUILD_DIR}" "${OUT_DIR}"
mkdir -p "${BUILD_DIR}" "${HEADERS_DIR}"

cp "${ROOT_DIR}/uniffi/generated/swift/ic_auth_clientFFI.h" "${HEADERS_DIR}/"
cp "${ROOT_DIR}/uniffi/generated/swift/ic_auth_clientFFI.modulemap" "${HEADERS_DIR}/"
cat > "${HEADERS_DIR}/module.modulemap" <<'EOF'
module IcAuthClientFFI {
    header "ic_auth_clientFFI.h"
    export *
    use "Darwin"
    use "_Builtin_stdbool"
    use "_Builtin_stdint"
}
EOF

build_target() {
  local target="$1"
  local features="$2"
  if [[ "${target}" == *"apple-darwin"* ]]; then
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}" \
      cargo build --release --no-default-features --features "${features}" --target "${target}"
  else
    IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}" \
      cargo build --release --no-default-features --features "${features}" --target "${target}"
  fi
}

copy_lib() {
  local target="$1"
  local dst="$2"
  local ext
  ext="a"

  local lib_path="${ROOT_DIR}/target/${target}/release/lib${LIB_NAME}.${ext}"
  if [[ ! -f "${lib_path}" ]]; then
    echo "Missing ${lib_path}"
    exit 1
  fi
  cp "${lib_path}" "${dst}"
}

# Build and collect iOS device
build_target "${IOS_DEVICE_TARGET}" "${IOS_FEATURES}"
mkdir -p "${BUILD_DIR}/ios"
copy_lib "${IOS_DEVICE_TARGET}" "${BUILD_DIR}/ios/lib${LIB_NAME}.a"

# Build and collect iOS simulator (x86_64 + arm64)
build_target "${IOS_SIM_ARM_TARGET}" "${IOS_FEATURES}"
mkdir -p "${BUILD_DIR}/ios-sim"

cp "${ROOT_DIR}/target/${IOS_SIM_ARM_TARGET}/release/lib${LIB_NAME}.a" \
  "${BUILD_DIR}/ios-sim/lib${LIB_NAME}.a"

# Build and collect macOS (x86_64 + arm64)
build_target "${MAC_X86_TARGET}" "${MAC_FEATURES}"
build_target "${MAC_ARM_TARGET}" "${MAC_FEATURES}"
mkdir -p "${BUILD_DIR}/macos"

lipo -create \
  "${ROOT_DIR}/target/${MAC_X86_TARGET}/release/lib${LIB_NAME}.a" \
  "${ROOT_DIR}/target/${MAC_ARM_TARGET}/release/lib${LIB_NAME}.a" \
  -output "${BUILD_DIR}/macos/lib${LIB_NAME}.a"

# Create xcframework
xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/ios/lib${LIB_NAME}.a" -headers "${HEADERS_DIR}" \
  -library "${BUILD_DIR}/ios-sim/lib${LIB_NAME}.a" -headers "${HEADERS_DIR}" \
  -library "${BUILD_DIR}/macos/lib${LIB_NAME}.a" -headers "${HEADERS_DIR}" \
  -output "${OUT_DIR}"

echo "XCFramework created at: ${OUT_DIR}"
