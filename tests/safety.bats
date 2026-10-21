#!/usr/bin/env bats
# tests/safety.bats — unit tests for the safety mechanisms (backups, rollback,
# template rendering). They only need bash, so they run everywhere.

setup() {
	load 'helpers'
	setup_test_env
	export START_TS="20260101-000000"
	# shellcheck source=/dev/null
	source "$SAFESET_ROOT/lib/common.sh"
	# shellcheck source=/dev/null
	source "$SAFESET_ROOT/lib/rollback.sh"
}

@test "backup_file records created files so rollback can remove them" {
	DRY_RUN=false
	local created="${TEST_TMPDIR}/created/drop-in.conf"
	backup_file "$created"
	[ -f "${SAFESET_BACKUP_ROOT}/${START_TS}.created" ]
	grep -Fxq "$created" "${SAFESET_BACKUP_ROOT}/${START_TS}.created"
}

@test "backup_file keeps one backup per file" {
	DRY_RUN=false
	local existing="${TEST_TMPDIR}/existing.conf"
	echo "original" >"$existing"
	backup_file "$existing"
	backup_file "$existing"
	[ "$(find "$SAFESET_BACKUP_ROOT" -type f -name 'existing.conf' | wc -l)" -eq 1 ]
}

@test "dry-run does not create backups" {
	DRY_RUN=true
	local f="${TEST_TMPDIR}/dry-run.conf"
	backup_file "$f"
	[ ! -d "$SAFESET_BACKUP_ROOT" ]
}

@test "render_template substitutes admin whitelist placeholders" {
	local dest="${TEST_TMPDIR}/rendered.nft"
	render_template "$SAFESET_ROOT/configs/nftables/safeset.nft" "$dest" \
		"ADMIN4_ELEMENTS=192.0.2.10,198.51.100.7" \
		"ADMIN6_ELEMENTS=2001:db8::1"
	grep -Fq "@ADMIN4_ELEMENTS@" "$dest" && false
	grep -Fq "@ADMIN6_ELEMENTS@" "$dest" && false
	grep -Fq "192.0.2.10,198.51.100.7" "$dest"
	grep -Fq "2001:db8::1" "$dest"
}

@test "render_template leaves unknown placeholders untouched" {
	local dest="${TEST_TMPDIR}/rendered2.nft"
	render_template "$SAFESET_ROOT/configs/nftables/safeset.nft" "$dest" "ADMIN4_ELEMENTS=1.2.3.4"
	grep -Fq "@ADMIN6_ELEMENTS@" "$dest"
}

@test "rollback restores modified files and removes created ones" {
	DRY_RUN=false
	local target="${TEST_TMPDIR}/etc/ssh/sshd_config.d/99-safeset.conf"
	local created="${TEST_TMPDIR}/etc/safeset/created.conf"
	mkdir -p "$(dirname "$target")" "$(dirname "$created")"
	echo "original content" >"$target"
	echo "created content" >"$created"

	local dir="${SAFESET_BACKUP_ROOT}/${START_TS}"
	mkdir -p "${dir}$(dirname "$target")"
	echo "original content" >"${dir}${target}"
	mkdir -p "${SAFESET_BACKUP_ROOT}"
	printf '%s\n' "$created" >"${SAFESET_BACKUP_ROOT}/${START_TS}.created"

	do_rollback "$START_TS" >/dev/null

	[ "$(cat "$target")" = "original content" ]
	[ ! -e "$created" ]
}

@test "rollback without any backup fails" {
	DRY_RUN=false
	local rc=0
	# lib/common.sh defines its own `run` helper, so bats' `run` is not used
	# here; a subshell keeps `die` (which exits) inside this test.
	(do_rollback "20991231-235959") >/dev/null 2>&1 || rc=$?
	[ "$rc" -ne 0 ]
}
