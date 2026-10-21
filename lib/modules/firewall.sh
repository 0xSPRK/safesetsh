# shellcheck shell=bash
# lib/modules/firewall.sh — nftables host firewall (default-deny incoming).

mod_firewall() {
	log_info "=== firewall: nftables default-deny ==="

	# The packages module may have installed nftables earlier in this very
	# run; the startup probe (detect_environment) ran before that.
	detect_nft
	if env_limits_nft; then
		note_skipped "firewall: nftables not usable in this environment (no NET_ADMIN / nft missing)"
		return 0
	fi

	# --- Build the allow rules for --allow-ports --------------------------
	local -a tcp_ports=() udp_ports=()
	local entry port proto
	for entry in "${ALLOWED_PORTS[@]}"; do
		port="${entry%%/*}"
		proto="${entry##*/}"
		if [[ $proto == tcp ]]; then
			tcp_ports+=("$port")
		else
			udp_ports+=("$port")
		fi
	done

	local allow_rules=''
	if ((${#tcp_ports[@]})); then
		local tcp_list
		tcp_list="$(
			IFS=,
			echo "${tcp_ports[*]}"
		)"
		allow_rules+="		tcp dport { ${tcp_list} } ct state new accept"$'\n'
	fi
	if ((${#udp_ports[@]})); then
		local udp_list
		udp_list="$(
			IFS=,
			echo "${udp_ports[*]}"
		)"
		allow_rules+="		udp dport { ${udp_list} } accept"$'\n'
	fi
	# In dry-run / empty case the placeholder must still be replaced.
	allow_rules="${allow_rules%$'\n'}"
	if [[ -z $allow_rules ]]; then
		allow_rules='		# (no extra service ports allowed)'
	fi

	local ssh_port="${SSH_PORT_EFFECTIVE}"

	# --- Admin whitelist rendered straight into the sets (survives reboot) --
	local admin4_elems='' admin6_elems=''
	local -a v4=() v6=()
	local ip
	for ip in "${ADMIN_IPS[@]}"; do
		if [[ $ip == *:* ]]; then
			v6+=("$ip")
		else
			v4+=("$ip")
		fi
	done
	if ((${#v4[@]})); then
		admin4_elems="elements = { $(
			IFS=,
			echo "${v4[*]}"
		) }"
	fi
	if ((${#v6[@]})); then
		admin6_elems="elements = { $(
			IFS=,
			echo "${v6[*]}"
		) }"
	fi

	# --- Render -------------------------------------------------------------
	local rendered apply_file
	rendered="$(mktemp)"
	render_template "${SAFESET_ROOT}/configs/nftables/safeset.nft" "$rendered" \
		"SSH_PORT=${ssh_port}" \
		"ALLOW_RULES=${allow_rules}" \
		"ADMIN4_ELEMENTS=${admin4_elems}" \
		"ADMIN6_ELEMENTS=${admin6_elems}"

	# nft 1.0.6 (Debian 12) has no "destroy table", so an existing table is
	# deleted and recreated in the same netlink batch. Validating the batch
	# (not the bare template) is essential: checking a create-only file
	# against an already existing table fails with EBUSY on every rerun.
	apply_file="$(mktemp)"
	if nft list table inet safeset >/dev/null 2>&1; then
		printf 'delete table inet safeset\n' >"$apply_file"
	fi
	cat "$rendered" >>"$apply_file"

	if ! nft --check --file "$apply_file" 2>/dev/null; then
		local err
		err="$(nft --check --file "$apply_file" 2>&1 || true)"
		rm -f "$rendered" "$apply_file"
		if $DRY_RUN; then
			# Dry-run on hosts without privileges cannot always check; warn only.
			note_warn "firewall: nft --check failed: ${err}"
		else
			die "nftables ruleset failed validation: ${err}"
		fi
	fi
	rm -f "$apply_file"

	if $DRY_RUN; then
		log_info "[dry-run] would install and apply nft ruleset (ssh=${ssh_port}, tcp={${tcp_ports[*]:-}}, udp={${udp_ports[*]:-}})"
		rm -f "$rendered"
		return 0
	fi

	# --- Save current ruleset for the safe-timer / manual rollback ---------
	mkdir -p "${SAFESET_RUN_DIR}"
	nft list ruleset >"${SAFESET_RUN_DIR}/ruleset.before" 2>/dev/null || true

	# --- Install + apply ----------------------------------------------------
	backup_paths_marker /etc/nftables.d/safeset.nft /etc/nftables.conf
	mkdir -p /etc/nftables.d
	install_template "${SAFESET_ROOT}/configs/nftables/safeset.nft" /etc/nftables.d/safeset.nft 644 \
		"SSH_PORT=${ssh_port}" \
		"ALLOW_RULES=${allow_rules}" \
		"ADMIN4_ELEMENTS=${admin4_elems}" \
		"ADMIN6_ELEMENTS=${admin6_elems}"
	rm -f "$rendered"

	# The batch was already validated above; "delete table" is needed again
	# here only because the table still exists (same content either way).
	apply_file="$(mktemp)"
	if nft list table inet safeset >/dev/null 2>&1; then
		printf 'delete table inet safeset\n' >"$apply_file"
	fi
	cat /etc/nftables.d/safeset.nft >>"$apply_file"

	if ! nft --check --file "$apply_file" 2>/dev/null; then
		local err
		err="$(nft --check --file "$apply_file" 2>&1 || true)"
		rm -f "$apply_file"
		die "installed nft ruleset failed validation: ${err}; aborting before apply"
	fi
	if ! nft -f "$apply_file"; then
		rm -f "$apply_file"
		die "failed to apply nftables ruleset; previous state saved at ${SAFESET_RUN_DIR}/ruleset.before"
	fi
	rm -f "$apply_file"

	# --- Boot persistence ---------------------------------------------------
	if [[ ! -f /etc/nftables.conf ]]; then
		write_file_atomic /etc/nftables.conf 644 <<'EOF'
#!/usr/sbin/nft -f
# Written by safeset: load the safeset table at boot.
flush ruleset
include "/etc/nftables.d/*.nft"
EOF
	else
		append_once /etc/nftables.conf 'include "/etc/nftables.d/*.nft"'
	fi
	if have_cmd systemctl; then
		run_soft systemctl enable nftables.service >/dev/null 2>&1 || note_warn "firewall: could not enable nftables.service (boot persistence may need manual activation)"
	fi

	note_applied "firewall: nftables applied (default deny in, allow out; ssh ${ssh_port}; services tcp={${tcp_ports[*]:-none}})"
	if ((${#ADMIN_IPS[@]} == 0)); then
		note_manual "firewall: no --admin-ip provided; if you lock yourself out, use console/VNC and: nft delete table inet safeset"
	fi

	# --- Safe-timer ---------------------------------------------------------
	arm_firewall_safe_timer "$SAFE_TIMER"
	return 0
}

mod_firewall_help() {
	cat <<'EOF'
firewall  nftables host firewall: default deny incoming / allow outgoing,
          only --allow-ports + SSH open; SYN/NULL/XMAS and flood protection
          with dynamic timeout sets; ICMP rate limits; IPv4+IPv6 via one
          "inet" table. Supports --safe-timer auto-rollback and --admin-ip
          whitelist. Skipped when nft/NET_ADMIN is unavailable (containers).
EOF
}
