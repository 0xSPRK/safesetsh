# shellcheck shell=bash
# lib/modules/crowdsec.sh — optional CrowdSec + nftables bouncer (external repo).

# Fingerprint of the CrowdSec packagecloud signing key, verified on
# 2026-10-18 against https://packagecloud.io/crowdsec/crowdsec/gpgkey.
# Re-verify with: curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey | gpg --show-keys
CROWDSEC_KEY_FPR='6A89E3C2303A901A889971D3376ED5326E93CD0C'
CROWDSEC_KEY_URL='https://packagecloud.io/crowdsec/crowdsec/gpgkey'
CROWDSEC_KEYRING='/etc/apt/keyrings/crowdsec.asc'

gpg_key_fingerprint() {
	# gpg_key_fingerprint <keyfile> — prints the primary key fingerprint.
	local file="$1" gnupg_home
	gnupg_home="$(mktemp -d)"
	if ! GNUPGHOME="$gnupg_home" gpg --quiet --import "$file" >/dev/null 2>&1; then
		rm -rf "$gnupg_home"
		return 1
	fi
	GNUPGHOME="$gnupg_home" gpg --with-colons --fingerprint 2>/dev/null |
		awk -F: '/^fpr:/{print $10; exit}'
	rm -rf "$gnupg_home"
}

mod_crowdsec() {
	log_info "=== crowdsec: community blocklist bouncer (optional) ==="

	if ! $CROWDSEC; then
		note_skipped "crowdsec: disabled (enable with --crowdsec)"
		return 0
	fi

	if ! have_cmd gpg; then
		note_failed "crowdsec: 'gpg' is required to verify the CrowdSec repository key (apt-get install gnupg)"
		return 1
	fi

	local tmp_key
	tmp_key="$(mktemp)"

	if $DRY_RUN; then
		log_info "[dry-run] would download ${CROWDSEC_KEY_URL}, verify fingerprint ${CROWDSEC_KEY_FPR},"
		log_info "[dry-run] add the CrowdSec apt repository and install crowdsec + crowdsec-firewall-bouncer-nftables"
		rm -f "$tmp_key"
		return 0
	fi

	if ! curl --proto '=https' --tlsv1.2 -fsSL "$CROWDSEC_KEY_URL" -o "$tmp_key"; then
		rm -f "$tmp_key"
		note_failed "crowdsec: could not download the repository signing key"
		return 1
	fi

	local got
	got="$(gpg_key_fingerprint "$tmp_key" || true)"
	if [[ ${got^^} != "${CROWDSEC_KEY_FPR^^}" ]]; then
		rm -f "$tmp_key"
		note_failed "crowdsec: GPG fingerprint mismatch (got '${got}', expected '${CROWDSEC_KEY_FPR}'); refusing to add the repository"
		return 1
	fi
	log_debug "crowdsec: repository key fingerprint verified"

	mkdir -p /etc/apt/keyrings
	backup_paths_marker "$CROWDSEC_KEYRING" /etc/apt/sources.list.d/crowdsec_crowdsec.list
	install -m 0644 "$tmp_key" "$CROWDSEC_KEYRING"
	rm -f "$tmp_key"

	local codename="${OS_CODENAME:-bookworm}"
	write_file_atomic /etc/apt/sources.list.d/crowdsec_crowdsec.list 644 <<EOF
# Managed by safeset. CrowdSec repository (key verified via GPG fingerprint).
deb [signed-by=${CROWDSEC_KEYRING}] https://packagecloud.io/crowdsec/crowdsec/debian/ ${codename} main
EOF

	if ! run_soft apt-get update -o Dir::Etc::sourcelist=sources.list.d/crowdsec_crowdsec.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0; then
		note_failed "crowdsec: apt update for the CrowdSec repository failed"
		return 1
	fi

	run_soft apt-get install -y --no-install-recommends crowdsec crowdsec-firewall-bouncer-nftables ||
		{
			note_failed "crowdsec: package installation failed"
			return 1
		}

	enable_now crowdsec >/dev/null 2>&1 || note_warn "crowdsec: could not enable crowdsec.service"
	enable_now crowdsec-firewall-bouncer >/dev/null 2>&1 || note_warn "crowdsec: could not enable crowdsec-firewall-bouncer.service"

	if have_cmd cscli; then
		run_soft cscli collections install crowdsecurity/linux >/dev/null 2>&1 || true
		run_soft cscli collections install crowdsecurity/sshd >/dev/null 2>&1 || true
		note_applied "crowdsec: installed with linux+sshd collections and nftables bouncer"
	else
		note_applied "crowdsec: installed and services enabled"
	fi
	note_manual "crowdsec: register this host for the community blocklist with: cscli console enroll <TOKEN>"
	return 0
}

mod_crowdsec_help() {
	cat <<'EOF'
crowdsec  optional (--crowdsec): adds the CrowdSec apt repository with GPG
          key verification (fingerprint pinned in this script), installs
          crowdsec + crowdsec-firewall-bouncer-nftables, enables both
          services and installs the linux/sshd collections. Requires network
          access to packagecloud.io.
EOF
}
