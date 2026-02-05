#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/swift-package/IcAuthClient"
GEN_DIR="${ROOT_DIR}/uniffi/generated/swift"
OUT_DIR="${PKG_DIR}/Sources/IcAuthClient"

if [[ ! -d "${GEN_DIR}" ]]; then
  echo "Generated Swift bindings not found at: ${GEN_DIR}"
  echo "Run ./uniffi/generate_swift.sh first."
  exit 1
fi

mkdir -p "${OUT_DIR}"

# Remove only previously generated files, keep hand-written Swift.
for file in "${GEN_DIR}"/*.swift; do
  base="$(basename "${file}")"
  if [[ -f "${OUT_DIR}/${base}" ]]; then
    rm -f "${OUT_DIR}/${base}"
  fi
done

cp -v "${GEN_DIR}"/*.swift "${OUT_DIR}/"

for file in "${OUT_DIR}"/*.swift; do
  perl -0pi -e 's/#if canImport\(ic_auth_clientFFI\)\nimport ic_auth_clientFFI\n#endif/#if canImport(IcAuthClientFFI)\nimport IcAuthClientFFI\n#elseif canImport(ic_auth_clientFFI)\nimport ic_auth_clientFFI\n#endif/g' "${file}"
done

AUTH_LOGIN_AVAIL='@available(iOS, unavailable, message: "login is only supported on desktop targets; use AuthSession on iOS")'
AUTH_FILE="${OUT_DIR}/ic_auth_client.swift"
if [[ -f "${AUTH_FILE}" ]]; then
  perl -0pi -e 's/\n\s*\@available\(iOS, unavailable, message: "login is only supported on desktop targets; use AuthSession on iOS"\)\n/\n/g' "${AUTH_FILE}"
  perl -0pi -e 's/\n\s*\(iOS, unavailable, message: "login is only supported on desktop targets; use AuthSession on iOS"\)\n/\n/g' "${AUTH_FILE}"
  perl -0pi -e 's/\n    func login\(authBridgeUrl: String, options: LoginOptions\) throws /\n#if !os(iOS)\n    func login(authBridgeUrl: String, options: LoginOptions) throws \n#endif\n/g' "${AUTH_FILE}"
  perl -0pi -e 's/\nopen func login\(authBridgeUrl: String, options: LoginOptions\)throws   /\n\@available(iOS, unavailable, message: "login is only supported on desktop targets; use AuthSession on iOS")\nopen func login(authBridgeUrl: String, options: LoginOptions)throws   /g' "${AUTH_FILE}"
fi

echo "Synced UniFFI Swift sources into: ${OUT_DIR}"
