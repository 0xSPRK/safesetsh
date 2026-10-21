#!/usr/bin/env bats
# tests/helpers.bash

setup_test_env() {
	SAFESET_BIN="${SAFESET_BIN:-$(pwd)/safeset.sh}"
	SAFESET_ROOT="$(pwd)"
	TEST_TMPDIR="$(mktemp -d)"
	export SAFESET_BIN SAFESET_ROOT TEST_TMPDIR
	export SAFESET_BACKUP_ROOT="${TEST_TMPDIR}/backups"
	export SAFESET_LOG_DIR="${TEST_TMPDIR}/logs"
	export SAFESET_ETC_DIR="${TEST_TMPDIR}/etc"
	export SAFESET_RUN_DIR="${TEST_TMPDIR}/run"
	export DRY_RUN=true
	export ASSUME_YES=true
	export NO_COLOR=1
	export SAFESET_NO_SYS_CALLS=1
}

teardown() {
	rm -rf "${TEST_TMPDIR:-}"
}

# bats >= 1.11 keeps stderr separate from stdout, older versions merge both
# into $output. This helper works with both.
# shellcheck disable=SC2154 # output/stderr are provided by bats
assert_output_contains() {
	local needle="$1"
	[[ "$output" == *"$needle"* ]] && return 0
	if [[ -n "${stderr:-}" && "$stderr" == *"$needle"* ]]; then
		return 0
	fi
	echo "expected output to contain: $needle" >&2
	echo "--- output ---" >&2
	echo "$output" >&2
	if [[ -n "${stderr:-}" ]]; then
		echo "--- stderr ---" >&2
		echo "$stderr" >&2
	fi
	return 1
}
