#!/usr/bin/env bash
# ci/lynis-compare.sh - Lynis hardening index before/after a real safeset run.
# Not part of CI (takes minutes and mutates a throwaway container); run locally:
#   DOCKER_BIN=podman ci/lynis-compare.sh docker.io/library/debian:12-slim
set -Eeuo pipefail

IMAGE="${1:-docker.io/library/debian:12-slim}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
SRC="$(pwd -W 2>/dev/null || pwd)"

echo "==> lynis before/after report in ${IMAGE}"
"$DOCKER_BIN" pull "$IMAGE" >/dev/null 2>&1 || true

# shellcheck disable=SC2016 # the single-quoted body is intentional (runs in the container)
"$DOCKER_BIN" run --rm \
	-v "${SRC}:/safeset:rw" \
	--cap-add NET_ADMIN --cap-add SYS_ADMIN \
	"$IMAGE" bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "Acquire::ForceIPv4 true;" >/etc/apt/apt.conf.d/99force-ipv4
apt-get -o Acquire::ForceIPv4=true update -y >/dev/null
apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends lynis ca-certificates openssh-client >/dev/null

# The hardening index is printed as "Hardening index : 62/100" - take the
# first number (the score), not the maximum.
lynis_index() {
	local file="$1" line
	[ -f "$file" ] || file=/var/log/lynis/lynis.report
	[ -f "$file" ] || return 0
	line="$(grep -m1 "Hardening index" "$file" 2>/dev/null || true)"
	[ -n "$line" ] || return 0
	printf "%s" "$line" | grep -oE "[0-9]+" | head -n1 || true
}

run_lynis() {
	local out="$1"
	lynis audit system --quick --no-colors >"$out" 2>&1 || true
	if [ -s "$out" ] && grep -q "Hardening index" "$out"; then
		return 0
	fi
	if [ -f /var/log/lynis/lynis.report ]; then
		cp /var/log/lynis/lynis.report "$out" 2>/dev/null || true
	fi
}

echo "--- baseline lynis (fresh Debian) ---"
run_lynis /tmp/lynis-before.txt
before="$(lynis_index /tmp/lynis-before.txt || true)"
echo "lynis before: ${before:-n/a}"

cd /safeset
chmod +x safeset.sh
# The ssh module refuses to disable password authentication without a key
# for the operator, so the comparison run gets a throwaway key.
ssh-keygen -t ed25519 -N "" -f /tmp/lynis_key -q
echo "--- real safeset run (all default modules) ---"
./safeset.sh --yes --safe-timer 60 --create-user lynis-ci --ssh-key /tmp/lynis_key.pub
echo "--- confirm firewall connectivity ---"
./safeset.sh --confirm

echo "--- hardened lynis (after safeset) ---"
run_lynis /tmp/lynis-after.txt
after="$(lynis_index /tmp/lynis-after.txt || true)"
echo "lynis after:  ${after:-n/a}"
echo "LYNIS_BEFORE=${before:-n/a} LYNIS_AFTER=${after:-n/a}"
'
echo "==> done"
