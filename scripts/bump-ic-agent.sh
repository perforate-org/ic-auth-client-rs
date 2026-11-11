#!/usr/bin/env bash
# Moves the crate onto another `ic-agent` version.
#
# Usage: scripts/bump-ic-agent.sh <ic-agent-version> [--keep-crate-version]
#
#   <ic-agent-version>     e.g. 0.50.1, as published on crates.io
#   --keep-crate-version   only move the dependency (a patch release within the
#                          current pairing), leaving the crate version alone
#
# A new `ic-agent` minor becomes a new minor of this crate: the pairing is
# written into the version (README "Version compatibility for `ic-agent`"), so
# `ic-auth-client = "0.49"` cannot silently pull an `ic-agent` 0.50, whose
# `Identity` trait this crate would not satisfy.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

version="${1:?usage: bump-ic-agent.sh <ic-agent-version> [--keep-crate-version]}"
keep_crate_version="${2:-}"

case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "error: '$version' is not a version like 0.50.1" >&2; exit 1 ;;
esac

minor_pair="$(printf '%s' "$version" | cut -d. -f1,2)"

python3 - "$version" "$minor_pair" "$keep_crate_version" <<'PY'
import pathlib
import re
import sys

version, pair, keep = sys.argv[1], sys.argv[2], sys.argv[3]
path = pathlib.Path("Cargo.toml")
lines = path.read_text().splitlines()

out = []
in_metadata = False
moved_dependency = False
moved_metadata = False
moved_version = False

for line in lines:
    stripped = line.strip()
    if stripped.startswith("["):
        in_metadata = stripped == "[package.metadata.ic-agent]"

    # The dependency itself: `ic-agent = { version = "0.49.3", ... }`.
    if not moved_dependency and line.startswith("ic-agent = {"):
        out.append(re.sub(r'version = "[^"]*"', f'version = "{version}"', line, count=1))
        moved_dependency = True
        continue

    if in_metadata and stripped.startswith("minor ="):
        out.append(f'minor = "{pair}"')
        moved_metadata = True
        continue
    if in_metadata and stripped.startswith("tested ="):
        out.append(f'tested = "{version}"')
        continue

    # The crate's own version, after `[package]`.
    if not moved_version and line.startswith("version = "):
        if keep == "--keep-crate-version":
            out.append(line)
        else:
            out.append(f'version = "{pair}.0"')
        moved_version = True
        continue

    out.append(line)

if not moved_dependency:
    sys.exit("error: no ic-agent dependency found in Cargo.toml")
if not moved_metadata:
    sys.exit("error: no [package.metadata.ic-agent] block in Cargo.toml")
if not moved_version:
    sys.exit("error: no [package] version in Cargo.toml")

path.write_text("\n".join(out) + "\n")
PY

# The compatibility table and the changelog say the same thing to humans; keep
# them in step so the PR only needs the test outcome added to it.
python3 - "$version" "$minor_pair" "$keep_crate_version" <<'PY'
import pathlib
import re
import sys

version, pair, keep = sys.argv[1], sys.argv[2], sys.argv[3]

readme = pathlib.Path("README.md")
text = readme.read_text()
row = f"| {pair}.\\*            | {pair}.\\*                   | 11.x                     |"
if row not in text:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("| `ic-agent` version |"):
            # header, separator, then the rows
            insert_at = index + 2
            lines.insert(insert_at, row)
            break
    else:
        sys.exit("error: no compatibility table in README.md")
    readme.write_text("\n".join(lines) + "\n")

if keep != "--keep-crate-version":
    changelog = pathlib.Path("CHANGELOG.md")
    text = changelog.read_text()
    entry = f"- Compatibility: built against `ic-agent {pair}.*`.\n"
    if entry not in text:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if line.startswith("## Unreleased"):
                lines.insert(index + 1, "")
                lines.insert(index + 2, entry.rstrip("\n"))
                break
        else:
            lines[0:0] = ["## Unreleased", "", entry.rstrip("\n"), ""]
        changelog.write_text("\n".join(lines) + "\n")
PY

printf 'ic-agent -> %s (pairs with %s)\n' "$version" "$minor_pair"
[ "$keep_crate_version" = "--keep-crate-version" ] || printf 'crate version -> %s.0 (README row and CHANGELOG entry added)\n' "$minor_pair"
printf 'next: run the test matrix (CI does this too) and review the PR.\n'
