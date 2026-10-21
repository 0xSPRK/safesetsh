# shellcheck shell=bash
# lib/modules/fail2ban.sh — intrusion banning for sshd, recidive and web.

mod_fail2ban() {
	log_info "=== fail2ban: brute-force and bot protection ==="

	if ! have_cmd fail2ban-client; then
		note_skipped "fail2ban: not installed"
		return 0
	fi

	# --- ignoreip list ------------------------------------------------------
	local ignore=''
	local ip
	for ip in "${ADMIN_IPS[@]}"; do
		ignore+="${ip} "
	done
	ignore="${ignore% }"

	install_template "${SAFESET_ROOT}/configs/fail2ban/jail.d/99-safeset.local" \
		/etc/fail2ban/jail.d/99-safeset.local 644 \
		"SSH_PORT=${SSH_PORT_EFFECTIVE}" \
		"IGNORE_IP=${ignore}"

	install_template "${SAFESET_ROOT}/configs/fail2ban/filter.d/nginx-scan.conf" \
		/etc/fail2ban/filter.d/nginx-scan.conf 644

	# --- Web jails only when a web server is actually present --------------
	if [[ -n $WEB_SERVER ]] || $WEB; then
		install_template "${SAFESET_ROOT}/configs/fail2ban/jail.d/99-safeset-web.local" \
			/etc/fail2ban/jail.d/99-safeset-web.local 644
		note_applied "fail2ban: web jails installed (nginx/apache)"
	else
		run_soft rm -f /etc/fail2ban/jail.d/99-safeset-web.local || true
		log_debug "fail2ban: no web server detected; web jails not installed"
	fi

	if $DRY_RUN; then
		note_applied "fail2ban: jails prepared (sshd, recidive${WEB_SERVER:+, web})"
		return 0
	fi

	# fail2ban refuses to load a jail whose logpath does not exist. Minimal
	# images / containers often run without syslog, so /var/log/auth.log and
	# the daemon's own log are missing until the first start.
	local lf
	for lf in /var/log/auth.log /var/log/fail2ban.log; do
		if [[ ! -e $lf ]]; then
			touch "$lf"
			chmod 640 "$lf" 2>/dev/null || true
			chown root:adm "$lf" 2>/dev/null || true
			log_debug "fail2ban: created missing ${lf} (no syslog running)"
		fi
	done

	# --- Validate config, then (re)start ------------------------------------
	if ! fail2ban-client --test >/dev/null 2>&1; then
		local err
		err="$(fail2ban-client --test 2>&1 | tail -n5 || true)"
		# fail2ban --test needs the daemon config; on fresh systems without the
		# service running it can still validate. Treat parse errors as fatal.
		if printf '%s' "$err" | grep -qiE 'ERROR|Traceback|Failed to read'; then
			note_failed "fail2ban: configuration test failed: ${err}"
			return 1
		fi
	fi

	if service_active fail2ban; then
		run_soft fail2ban-client reload >/dev/null 2>&1 || run_soft systemctl restart fail2ban || true
	else
		run_soft systemctl enable --now fail2ban || note_warn "fail2ban: could not start service"
	fi

	if service_active fail2ban; then
		note_applied "fail2ban: running with sshd + recidive jails${WEB_SERVER:+, web jails}"
	else
		note_manual "fail2ban: service is not active; check: systemctl status fail2ban"
	fi
	return 0
}

mod_fail2ban_help() {
	cat <<'EOF'
fail2ban  nftables-backed bans: [sshd] (aggressive mode), [recidive]
          (4-week bans for repeat offenders, all ports) and, when a web
          server is detected, nginx/apache jails plus a custom scanner-path
          filter. Admin IPs (--admin-ip) are whitelisted via ignoreip.
EOF
}
