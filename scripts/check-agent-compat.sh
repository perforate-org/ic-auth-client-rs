#!/usr/bin/env bash
# Fails when the crate version and the `ic-agent` it is built against drift.
#
# The crate hands out `ic_agent::Identity` values, so its public API is only
# usable with one `ic-agent` minor. That pairing is written down twice --- in the
# crate's own version, and in the dependency --- and this script is what keeps
# both, plus `[package.metadata.ic-agent]`, in agreement.
#
# Usage: scripts/check-agent-compat.sh [--no-tree]
#   --no-tree  skip the duplicate-crate check (no `cargo`/lockfile needed)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

manifest="Cargo.toml"
[ -f "$manifest" ] || fail "no $manifest in $(pwd)"

# `<major>.<minor>` of the crate itself.
crate_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$manifest" | head -1)"
[ -n "$crate_version" ] || fail "could not read [package] version"
crate_pair="$(printf '%s' "$crate_version" | cut -d. -f1,2)"

# The pairing written down for humans and for the follow workflow.
metadata_minor="$(sed -n '/^\[package\.metadata\.ic-agent\]/,/^\[/s/^minor = "\(.*\)"/\1/p' "$manifest" | head -1)"
metadata_tested="$(sed -n '/^\[package\.metadata\.ic-agent\]/,/^\[/s/^tested = "\(.*\)"/\1/p' "$manifest" | head -1)"
[ -n "$metadata_minor" ] || fail "no [package.metadata.ic-agent] minor in $manifest"

# The dependency requirement, e.g. `0.49.3` from
# `ic-agent = { version = "0.49.3", ... }`.
dependency_version="$(sed -n 's/^ic-agent = { version = "\([^"]*\)".*/\1/p; s/^ic-agent = "\(.*\)"$/\1/p' "$manifest" | head -1)"
[ -n "$dependency_version" ] || fail "could not read the ic-agent dependency"
dependency_pair="$(printf '%s' "$dependency_version" | sed 's/^[~^=]//' | cut -d. -f1,2)"

printf 'crate:      %s (pairs with ic-agent %s)\n' "$crate_version" "$crate_pair"
printf 'dependency: ic-agent %s (pair %s)\n' "$dependency_version" "$dependency_pair"
printf 'metadata:   minor %s, tested with %s\n' "$metadata_minor" "$metadata_tested"

[ "$crate_pair" = "$metadata_minor" ] \
    || fail "the crate version ($crate_version) and [package.metadata.ic-agent] minor ($metadata_minor) disagree"
[ "$dependency_pair" = "$metadata_minor" ] \
    || fail "the ic-agent requirement ($dependency_version) does not match metadata minor ($metadata_minor)"
case "$metadata_tested" in
    "$dependency_pair".*) ;;
    *) fail "metadata says tested = $metadata_tested, which is not an ic-agent $dependency_pair release" ;;
esac

if [ "${1:-}" != "--no-tree" ]; then
    command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH"
    # The hazard is a second `ic-agent`: it is a second `Identity` trait, and the
    # identity this crate hands out does not typecheck against it. A duplicated
    # sha2/k256/p256 is common in the ecosystem and harmless --- the types that
    # cross this crate's API are `ic-agent`'s --- so it is reported, not failed.
    tree="$(cargo tree -e normal -d 2>&1)" || {
        printf '%s\n' "$tree" >&2
        fail "cargo tree failed (run cargo fetch first)"
    }
    duplicates="$(printf '%s\n' "$tree" | grep -E '^ic-agent v' || true)"
    if [ -n "$duplicates" ]; then
        printf '%s\n' "$duplicates" >&2
        fail "more than one ic-agent in the dependency graph; depend on ic_auth_client::ic_agent instead of adding your own"
    fi
    crypto="$(printf '%s\n' "$tree" | grep -E '^(k256|p256|pkcs8|sha2) v' || true)"
    if [ -n "$crypto" ]; then
        printf 'note: several versions of a crypto crate resolve (harmless without a duplicate ic-agent):\n%s\n' "$crypto"
    fi
    printf 'dependency graph: one ic-agent\n'
fi

printf 'ok: version and ic-agent pairing agree\n'
