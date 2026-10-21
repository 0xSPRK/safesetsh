# shellcheck shell=bash
# lib/rollback.sh — restore files from a safeset backup timestamp.

list_backups() {
	[[ -d $SAFESET_BACKUP_ROOT ]] || return 0
	find "$SAFESET_BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null |
		grep -E '^[0-9]{8}-[0-9]{6}$' | sort -r
}

do_rollback() {
	local ts="${1:-}"
	if [[ -z $ts ]]; then
		ts="$(list_backups | head -n1)"
		[[ -n $ts ]] || die "no safeset backups found under ${SAFESET_BACKUP_ROOT}"
		log_info "no timestamp given; using the most recent backup: ${ts}"
	fi
	local dir="${SAFESET_BACKUP_ROOT}/${ts}"
	local marker="${SAFESET_BACKUP_ROOT}/${ts}.created"
	if [[ ! -d $dir && ! -f $marker ]]; then
		die "no backup found for timestamp '${ts}' (looked in ${dir})"
	fi

	log_info "restoring configuration files from ${dir:-$marker}"
	local pre
	pre="${SAFESET_BACKUP_ROOT}/pre-rollback-$(date +%Y%m%d-%H%M%S)"
	local f rel count=0
	while IFS= read -r f; do
		rel="${f#"$dir"}"
		if $DRY_RUN; then
			log_info "[dry-run] would restore ${rel}"
			continue
		fi
		if [[ -e $rel ]]; then
			mkdir -p "${pre}$(dirname "$rel")"
			cp -a "$rel" "${pre}${rel}" 2>/dev/null || true
		fi
		mkdir -p "$(dirname "$rel")"
		cp -a "$f" "$rel"
		count=$((count + 1))
	done < <(find "$dir" -type f 2>/dev/null)

	# Remove files this run CREATED (they did not exist before, so there is
	# nothing to restore — but leaving them would defeat the rollback).
	if [[ -f $marker ]]; then
		while IFS= read -r f; do
			[[ -n $f ]] || continue
			if $DRY_RUN; then
				log_info "[dry-run] would remove ${f} (created by that run)"
				continue
			fi
			if [[ -e $f ]]; then
				rm -f "$f"
				count=$((count + 1))
			fi
		done <"$marker"
	fi

	if $DRY_RUN; then
		log_info "[dry-run] would restore ${count} file(s) and reload services"
		return 0
	fi

	log_ok "restored ${count} file(s) from ${ts}"

	# --- Re-apply the restored state where possible -------------------------
	if have_cmd sysctl; then
		run_soft sysctl --system >/dev/null 2>&1 || true
	fi
	if [[ -f /etc/nftables.d/safeset.nft ]] && have_cmd nft; then
		run_soft nft -f /etc/nftables.d/safeset.nft || note_warn "rollback: could not re-apply the restored nft ruleset"
	fi
	if have_cmd systemctl; then
		run_soft systemctl reload ssh >/dev/null 2>&1 || true
		run_soft systemctl reload sshd >/dev/null 2>&1 || true
		run_soft systemctl restart fail2ban >/dev/null 2>&1 || true
		run_soft systemctl restart chrony >/dev/null 2>&1 || true
		run_soft systemctl reload nginx >/dev/null 2>&1 || true
		run_soft systemctl reload apache2 >/dev/null 2>&1 || true
	fi
	log_ok "services reloaded where available"
	log_info "a copy of the pre-rollback state was saved to ${pre} (if files existed)"
	return 0
}
