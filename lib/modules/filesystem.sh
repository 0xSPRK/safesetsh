# shellcheck shell=bash
# lib/modules/filesystem.sh — mount options, file permissions, banners.

FSTAB=/etc/fstab

fstab_ensure_tmpfs() {
	# fstab_ensure_tmpfs <mountpoint> <size> <opts>
	local mpoint="$1" size="$2" opts="$3"
	local line="tmpfs ${mpoint} tmpfs ${opts},size=${size} 0 0"
	if grep -qE "^[^#]*[[:space:]]${mpoint}[[:space:]]" "$FSTAB" 2>/dev/null; then
		# An entry exists (possibly a real partition): leave it alone, only remount.
		log_debug "fstab already has an entry for ${mpoint}"
		return 0
	fi
	append_once "$FSTAB" "$line"
}

remount_opts() {
	# remount_opts <mountpoint> <comma-opts>
	local mpoint="$1" opts="$2"
	if ! mountpoint -q "$mpoint" && ! findmnt -n --target "$mpoint" >/dev/null 2>&1; then
		return 1
	fi
	# Skip when the mountpoint shares the root filesystem (cannot remount /).
	local root_src mnt_src
	root_src="$(findmnt -n -o SOURCE / 2>/dev/null || echo /)"
	mnt_src="$(findmnt -n -o SOURCE --target "$mpoint" 2>/dev/null || echo '')"
	if [[ -n $mnt_src && $mnt_src == "$root_src" ]]; then
		return 2 # same device as root
	fi
	run_soft mount -o "remount,${opts}" "$mpoint"
}

set_perm() {
	# set_perm <path> <mode> [owner:group]
	local path="$1" mode="$2" own="${3:-}"
	[[ -e $path ]] || return 0
	if $DRY_RUN; then
		log_debug "[dry-run] chmod ${mode} ${path}${own:+ ${own}}"
		return 0
	fi
	chmod "$mode" "$path" 2>/dev/null || true
	if [[ -n $own ]]; then
		chown "$own" "$path" 2>/dev/null || true
	fi
}

mod_filesystem() {
	log_info "=== filesystem: mount options, permissions, banner ==="

	if env_limits_mounts; then
		note_skipped "filesystem: mount hardening skipped inside container"
	else
		local opts='nodev,nosuid,noexec,mode=1777'
		# /dev/shm is always a tmpfs; remount it (no size change).
		remount_opts /dev/shm 'nodev,nosuid,noexec'
		note_applied "filesystem: /dev/shm remounted nodev,nosuid,noexec (best effort)"

		local mpoint rc
		local tmpfs_size=2G
		for mpoint in /tmp /var/tmp; do
			rc=0
			remount_opts "$mpoint" "$opts" || rc=$?
			case $rc in
			0) note_applied "filesystem: ${mpoint} remounted nodev,nosuid,noexec" ;;
			2)
				# Same filesystem as root: add a dedicated tmpfs entry instead.
				fstab_ensure_tmpfs "$mpoint" "$tmpfs_size" 'defaults,nodev,nosuid,noexec'
				run_soft mount "$mpoint" || note_warn "filesystem: could not mount dedicated tmpfs on ${mpoint}; it will apply after reboot"
				note_applied "filesystem: ${mpoint} tmpfs (nodev,nosuid,noexec) configured in ${FSTAB}"
				;;
			*) note_warn "filesystem: could not remount ${mpoint} with hardened options" ;;
			esac
		done

		# apt hook: temporarily allow exec on /tmp during dpkg/apt runs.
		if ! $DRY_RUN && findmnt -n -o OPTIONS /tmp 2>/dev/null | grep -q noexec; then
			write_file_atomic /etc/apt/apt.conf.d/99safeset-tmp-exec 644 <<'EOF'
// Managed by safeset: apt/dpkg may need to execute from /tmp, which is
// mounted noexec. Temporarily remount exec around dpkg invocations.
DPkg::Pre-Invoke {"if mountpoint -q /tmp && grep -q ' /tmp ' /proc/mounts && grep ' /tmp ' /proc/mounts | grep -q noexec; then mount -o remount,exec /tmp 2>/dev/null || true; fi";};
DPkg::Post-Invoke {"if mountpoint -q /tmp && grep -q ' /tmp ' /proc/mounts && grep ' /tmp ' /proc/mounts | grep -q exec; then mount -o remount,noexec /tmp 2>/dev/null || true; fi";};
EOF
			note_applied "filesystem: apt hook installed for noexec /tmp"
		fi
	fi

	# --- Permissions on security-relevant files ---------------------------
	set_perm /etc/shadow 640 root:shadow
	set_perm /etc/gshadow 640 root:shadow
	set_perm /etc/passwd 644 root:root
	set_perm /etc/group 644 root:root
	set_perm /etc/sudoers 440 root:root
	set_perm /etc/sudoers.d 750 root:root
	set_perm /etc/ssh/sshd_config 600 root:root
	set_perm /root 700 root:root
	set_perm /etc/crontab 600 root:root
	local d
	for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
		set_perm "$d" 700 root:root
	done
	note_applied "filesystem: permissions tightened on critical files"

	# --- Login banner ------------------------------------------------------
	install_template "${SAFESET_ROOT}/configs/issue/issue.net" /etc/issue.net 644
	if ! $DRY_RUN; then
		cp -f /etc/issue.net /etc/issue 2>/dev/null || true
	fi
	note_applied "filesystem: login banner installed (/etc/issue.net, SSH Banner)"

	return 0
}

mod_filesystem_help() {
	cat <<'EOF'
filesystem  nodev,nosuid,noexec on /tmp, /var/tmp, /dev/shm (dedicated
            tmpfs when they live on the root fs) with an apt/dpkg noexec
            hook; tightened permissions on /etc/shadow, sudoers, cron
            directories; login banner in /etc/issue.net. Mount changes are
            skipped inside containers.
EOF
}
