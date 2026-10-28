#!/usr/bin/env bash
# Prints the CHANGELOG.md section for a version, e.g. `scripts/release-notes.sh 0.1.0`.
# Fails if there is no such section, so a release can't go out without notes.
set -euo pipefail

version=${1:?usage: $0 <version>}
notes=$(awk -v header="## [$version]" '
  /^## \[/ { in_section = index($0, header) == 1; next }
  /^\[[^]]*\]: / { next }  # link reference definitions
  in_section
' "$(dirname "$0")/../CHANGELOG.md")

if [ -z "${notes//[[:space:]]/}" ]; then
  echo "error: no CHANGELOG.md entry for $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
