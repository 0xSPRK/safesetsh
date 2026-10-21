#!/usr/bin/env bash
# ci/container-smoke.sh — integration smoke: dry-run, real run, idempotency,
# ssh module with an operator key, and rollback. Exits non-zero on failure.
set -Eeuo pipefail

IMAGE="${1:-docker.io/library/debian:12-slim}"
# CI ships docker; local runs may set DOCKER_BIN=podman.
DOCKER_BIN="${DOCKER_BIN:-docker}"

echo "==> integration smoke test in ${IMAGE}"
"$DOCKER_BIN" pull "$IMAGE" >/dev/null 2>&1 || true

# On Git Bash, prefer a Windows-style path for the volume mount.
SRC="$(pwd -W 2>/dev/null || pwd)"

"$DOCKER_BIN" run --rm \
	-v "${SRC}:/safeset:rw" \
	--cap-add NET_ADMIN --cap-add SYS_ADMIN \
	"$IMAGE" bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "Acquire::ForceIPv4 true;" >/etc/apt/apt.conf.d/99force-ipv4
apt-get -o Acquire::ForceIPv4=true update -y >/dev/null
apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends ca-certificates openssh-client >/dev/null
cd /safeset
chmod +x safeset.sh

echo "--- dry-run (all modules) ---"
./safeset.sh --dry-run --yes --safe-timer 10

echo "--- dry-run with flags ---"
./safeset.sh --dry-run --yes --only packages,sysctl --no-ipv6

echo "--- real hardening run ---"
./safeset.sh --yes --only packages,sysctl,filesystem,accounts,audit,firewall,fail2ban --safe-timer 60
./safeset.sh --confirm
nft list table inet safeset >/dev/null
if ! fail2ban-client --test >/dev/null 2>&1; then
	echo "fail2ban config test failed" >&2
	fail2ban-client --test || true
	exit 1
fi

echo "--- idempotency: second identical run ---"
./safeset.sh --yes --only packages,sysctl,filesystem,accounts,audit,firewall,fail2ban --safe-timer 60
./safeset.sh --confirm
nft list table inet safeset >/dev/null

echo "--- ssh module: operator user + key + drop-in validation ---"
ssh-keygen -t ed25519 -N "" -f /tmp/ci_key -q
./safeset.sh --yes --only ssh --create-user ci --ssh-key /tmp/ci_key.pub
grep -q "PasswordAuthentication no" /etc/ssh/sshd_config.d/99-safeset.conf
/usr/sbin/sshd -t -f /etc/ssh/sshd_config

echo "--- rollback (latest) ---"
./safeset.sh --rollback

echo "integration smoke OK"
'
echo "==> done"
