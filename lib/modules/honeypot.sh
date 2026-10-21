# shellcheck shell=bash
# lib/modules/honeypot.sh — endlessh tarpit on the original SSH port.

mod_honeypot() {
	log_info "=== honeypot: endlessh tarpit ==="

	if ! $HONEYPOT; then
		note_skipped "honeypot: disabled (enable with --honeypot)"
		return 0
	fi

	if [[ ${SSH_PORT_EFFECTIVE} -eq 22 ]]; then
		note_skipped "honeypot: SSH still listens on port 22; refusing to start a tarpit there"
		return 0
	fi

	if ! have_cmd endlessh && ! service_exists endlessh; then
		note_skipped "honeypot: endlessh is not installed/available"
		note_manual "honeypot: install 'endlessh' and expose port 22 to it if you want the tarpit"
		return 0
	fi

	write_file_atomic /etc/endlessh/config 644 <<'EOF'
# Managed by safeset: endlessh tarpit, slowly drips an endless SSH banner.
Port 22
Delay 10000
MaxLineLength 32
MaxClients 4096
LogLevel 1
EOF

	# endlessh.service binds 0.0.0.0:22; only safe because sshd moved away.
	if service_exists endlessh; then
		if enable_now endlessh >/dev/null 2>&1; then
			note_applied "honeypot: endlessh tarpit active on port 22 (SSH is on ${SSH_PORT_EFFECTIVE})"
			if have_cmd fail2ban-client; then
				note_manual "honeypot: optionally add an endlessh jail to fail2ban to ban tarpit hits"
			fi
		else
			note_manual "honeypot: endlessh installed; start it manually: systemctl enable --now endlessh"
		fi
	fi
	return 0
}

mod_honeypot_help() {
	cat <<'EOF'
honeypot  optional (--honeypot): endlessh tarpit on port 22, only when SSH
          has been moved to another port. Keeps automated scanners busy with
          an endless banner instead of exposing real SSH there.
EOF
}
