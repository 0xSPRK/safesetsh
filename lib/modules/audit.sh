# shellcheck shell=bash
# lib/modules/audit.sh — auditd rules, journald, AIDE, periodic scans, chrony.

mod_audit() {
	log_info "=== audit: auditd, journald, integrity checks, time sync ==="

	# --- auditd -------------------------------------------------------------
	if env_limits_audit; then
		note_skipped "audit: auditd kernel support unavailable (container)"
	elif have_cmd auditctl && ! auditctl -s >/dev/null 2>&1; then
		note_skipped "audit: auditd cannot access kernel audit (missing CAP_AUDIT_CONTROL)"
	elif have_cmd auditctl; then
		install_template "${SAFESET_ROOT}/configs/audit/99-safeset.rules" \
			/etc/audit/rules.d/99-safeset.rules 640
		if have_cmd augenrules; then
			if ! $DRY_RUN; then
				if run_soft augenrules --load; then
					note_applied "audit: rules loaded via augenrules"
				else
					note_warn "audit: augenrules --load failed; rules will load on next auditd restart"
				fi
			else
				note_applied "audit: rules prepared (augenrules --load skipped in dry-run)"
			fi
		fi
		enable_now auditd >/dev/null 2>&1 || note_warn "audit: could not enable auditd"
	else
		note_skipped "audit: auditd not installed"
	fi

	# --- journald -----------------------------------------------------------
	if [[ -d /etc/systemd/journald.conf.d || ! $DRY_RUN ]]; then
		run_soft mkdir -p /var/log/journal || true
		write_file_atomic /etc/systemd/journald.conf.d/99-safeset.conf 644 <<'EOF'
# Managed by safeset: persistent, size-capped journal.
[Journal]
Storage=persistent
SystemMaxUse=500M
RuntimeMaxUse=100M
MaxRetentionSec=1month
Compress=yes
ForwardToSyslog=no
EOF
		if have_cmd systemctl; then
			run_soft systemctl restart systemd-journald >/dev/null 2>&1 || true
		fi
		note_applied "audit: journald persistent with size caps"
	fi

	# --- AIDE ---------------------------------------------------------------
	local -a aide_args=()
	if [[ -f /etc/aide/aide.conf ]]; then
		aide_args=(--config /etc/aide/aide.conf)
	elif [[ -f /etc/aide.conf ]]; then
		aide_args=(--config /etc/aide.conf)
	fi
	if have_cmd aide || have_cmd aideinit; then
		if ((${#aide_args[@]} == 0)) && ! have_cmd aideinit; then
			# AIDE 0.19+ no longer discovers a default config file; without
			# one the init would fail with "missing configuration".
			note_manual "audit: AIDE config missing (install aide-common); run aideinit manually later"
		elif $DRY_RUN; then
			log_info "[dry-run] would initialize AIDE database (aideinit) if missing"
		elif [[ ! -f /var/lib/aide/aide.db && ! -f /var/lib/aide/aide.db.new ]]; then
			log_info "audit: initializing AIDE database (this can take several minutes)"
			local rc=0 out=''
			if have_cmd aideinit; then
				out="$(aideinit -y -f 2>&1)" || rc=$?
			else
				out="$(aide --init "${aide_args[@]}" 2>&1)" || rc=$?
			fi
			if ((rc)); then
				local line last_line='' err_line=''
				while IFS= read -r line; do
					[[ -n $line ]] && last_line="$line"
					if [[ -z $err_line && $line =~ [Uu]nable|[Ee]rror|[Ff]ail ]]; then
						err_line="$line"
					fi
				done <<<"$out"
				printf '%s\n' "$out" >>"${SAFESET_LOG_DIR}/aide-init.log" 2>/dev/null || true
				note_warn "audit: AIDE init failed (${err_line:-$last_line}); full output: ${SAFESET_LOG_DIR}/aide-init.log"
			fi
			[[ -f /var/lib/aide/aide.db.new ]] && run_soft mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
		fi
		if [[ -f /var/lib/aide/aide.db ]]; then
			note_applied "audit: AIDE database present (weekly check via safeset-scans.timer)"
		else
			note_manual "audit: AIDE database not initialized; run: aideinit -y -f"
		fi
	else
		note_skipped "audit: AIDE not installed"
	fi

	# --- Weekly scans (rkhunter, lynis, aide) ------------------------------
	install_template "${SAFESET_ROOT}/configs/audit/safeset-scans.sh" \
		/usr/local/sbin/safeset-scans.sh 750
	install_template "${SAFESET_ROOT}/configs/audit/safeset-scans.service" \
		/etc/systemd/system/safeset-scans.service 644
	install_template "${SAFESET_ROOT}/configs/audit/safeset-scans.timer" \
		/etc/systemd/system/safeset-scans.timer 644
	if have_cmd systemctl && ! $DRY_RUN; then
		run_soft systemctl daemon-reload >/dev/null 2>&1 || true
		if enable_now safeset-scans.timer >/dev/null 2>&1; then
			note_applied "audit: weekly scans scheduled (rkhunter + lynis + aide -> /var/log/safeset)"
		else
			note_manual "audit: enable weekly scans manually: systemctl enable --now safeset-scans.timer"
		fi
	else
		note_applied "audit: weekly scan units installed (safeset-scans.timer)"
	fi

	# --- Time synchronization ----------------------------------------------
	if have_cmd chronyc || service_exists chrony; then
		if enable_now chrony >/dev/null 2>&1; then
			note_applied "audit: chrony time synchronization enabled"
		else
			note_manual "audit: enable time sync manually: systemctl enable --now chrony"
		fi
	else
		note_skipped "audit: chrony not installed"
	fi

	# --- Log directory permissions -----------------------------------------
	if ! $DRY_RUN; then
		mkdir -p "${SAFESET_LOG_DIR}"
		chmod 700 "${SAFESET_LOG_DIR}" 2>/dev/null || true
	fi

	return 0
}

mod_audit_help() {
	cat <<'EOF'
audit     auditd rules (identity, sudoers, ssh, modules, time, cron,
          mounts, logins) loaded with augenrules; persistent size-capped
          journald; AIDE database init + weekly check; weekly rkhunter and
          lynis reports in /var/log/safeset; chrony time sync. Skipped in
          containers (no kernel audit).
EOF
}
