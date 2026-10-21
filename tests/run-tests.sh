#!/usr/bin/env bash
# Run the test suite with a locally installed bats (CI calls bats directly).
set -Eeuo pipefail

cd "$(dirname "$0")/.."

# Optional: a local bats-core checkout takes precedence over the system bats.
LOCAL_BATS="${LOCAL_BATS:-/c/Users/User/AppData/Local/Temp/opencode/bats-core/bin}"
if [[ -d $LOCAL_BATS ]]; then
	PATH="${LOCAL_BATS}:${PATH}"
fi

echo "==> running bats tests"
if ! command -v bats >/dev/null 2>&1; then
	echo "bats not found in PATH (install it or point LOCAL_BATS at it)" >&2
	exit 1
fi
bats tests/
