# shellcheck shell=bash
# lib/modules/sysctl.sh — kernel/network sysctls and module blacklisting.

mod_sysctl() {
	log_info "=== sysctl: kernel & network hardening ==="

	local conf=/etc/sysctl.d/99-safeset.conf
	local modprobe_conf=/etc/modprobe.d/99-safeset-blacklist.conf

	# --- sysctl drop-in ----------------------------------------------------
	if ! env_limits_sysctl; then
		install_template "${SAFESET_ROOT}/configs/sysctl/99-safeset.conf" "$conf" 644
		# Apply per-key so a single read-only knob (common in LXC) cannot abort
		# the whole module; collect failures for the report.
		local failed=()
		local line key value
		if ! $DRY_RUN; then
			while IFS= read -r line; do
				[[ $line =~ ^[[:space:]]*# ]] && continue
				[[ $line =~ ^[[:space:]]*$ ]] && continue
				key="${line%%=*}"
				value="${line#*=}"
				key="${key%"${key##*[![:space:]]}"}" # rtrim
				key="${key#"${key%%[![:space:]]*}"}" # ltrim
				value="${value#"${value%%[![:space:]]*}"}"
				if ! sysctl -qw "$key=$value" 2>/dev/null; then
					failed+=("$key")
				fi
			done <"$conf"
		fi
		if ((${#failed[@]})); then
			note_warn "sysctl: ${#failed[@]} knob(s) not writable in this environment (${failed[*]}); they will apply after boot from ${conf}"
			note_applied "sysctl: wrote ${conf}"
		else
			note_applied "sysctl: ${conf} written and applied"
		fi
	else
		note_skipped "sysctl: not applicable in container/limited environment"
	fi

	# --- module blacklist --------------------------------------------------
	if ! env_limits_kernel_modules; then
		install_template "${SAFESET_ROOT}/configs/modprobe/99-safeset-blacklist.conf" "$modprobe_conf" 644
		((REBOOT_RECOMMENDED++)) || true
		note_applied "sysctl: kernel module blacklist written to ${modprobe_conf} (effective after reboot)"
	else
		# Still install the file so it applies if the container image is later
		# converted to a VM/LXC template, but skip depmod side effects.
		install_template "${SAFESET_ROOT}/configs/modprobe/99-safeset-blacklist.conf" "$modprobe_conf" 644
		note_skipped "sysctl: module blacklist written but not active inside container (${modprobe_conf})"
	fi

	# --- IPv6 disable (opt-out) -------------------------------------------
	if $NO_IPV6; then
		ensure_managed_block /etc/sysctl.d/99-safeset.conf "ipv6-disable" \
			"$(printf '%s\n' \
				'# Disable IPv6 entirely (requested via --no-ipv6).' \
				'net.ipv6.conf.all.disable_ipv6 = 1' \
				'net.ipv6.conf.default.disable_ipv6 = 1')"
		if ! env_limits_sysctl && ! $DRY_RUN; then
			sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
			sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
		fi
		note_applied "sysctl: IPv6 stack disabled (--no-ipv6)"
	fi

	return 0
}

mod_sysctl_help() {
	cat <<'EOF'
sysctl    kernel/network hardening via /etc/sysctl.d/99-safeset.conf
          (rp_filter, no redirects/source routing, syncookies, kptr_restrict,
          dmesg_restrict, unprivileged_bpf_disabled, yama, protected_*,
          ASLR, suid_dumpable=0, ...) and blacklisting of uncommon kernel
          modules via /etc/modprobe.d/. Skipped (partially) in containers.
EOF
}
