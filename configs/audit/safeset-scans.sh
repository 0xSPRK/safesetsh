#!/bin/bash
# Managed by safeset (safesetsh): weekly integrity / rootkit / audit scans.
# Installed to /usr/local/sbin/safeset-scans.sh and driven by
# safeset-scans.timer (weekly). Output goes to /var/log/safeset/.
set -Eeuo pipefail

LOG_DIR=/var/log/safeset
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

stamp="$(date +%Y%m%d-%H%M%S)"

if command -v rkhunter >/dev/null 2>&1; then
	rkhunter --update >/dev/null 2>&1 || true
	rkhunter --propupd --quiet >/dev/null 2>&1 || true
	rkhunter --check --sk --nocolors >>"${LOG_DIR}/rkhunter-${stamp}.log" 2>&1 || true
fi

if command -v lynis >/dev/null 2>&1; then
	lynis audit system --quick --quiet --no-colors \
		>>"${LOG_DIR}/lynis-${stamp}.log" 2>&1 || true
fi

if [[ -f /var/lib/aide/aide.db ]]; then
	aide --check >>"${LOG_DIR}/aide-${stamp}.log" 2>&1 || true
fi

# Retain the last 12 reports of each kind.
for prefix in rkhunter lynis aide; do
	find "$LOG_DIR" -maxdepth 1 -name "${prefix}-*.log" -printf '%T@ %p\n' 2>/dev/null |
		sort -rn | tail -n +13 | cut -d' ' -f2- | xargs -r rm -f --
done
