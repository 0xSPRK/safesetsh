# shellcheck shell=bash
# lib/modules/ssh.sh — harden OpenSSH via drop-in, with lockout protection.

SSH_DROP_IN=/etc/ssh/sshd_config.d/99-safeset.conf

user_home_dir() {
	local user="$1" home
	home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
	[[ -n $home && -d $home ]] && printf '%s\n' "$home"
}

user_has_usable_key() {
	local user="$1" home akf
	home="$(user_home_dir "$user")" || return 1
	akf="${home}/.ssh/authorized_keys"
	[[ -s $akf ]] || return 1
	# Validate that at least one line parses as a public key.
	ssh-keygen -l -f "$akf" >/dev/null 2>&1 || return 1
	return 0
}

assert_no_self_lockout() {
	# Called before disabling password auth. Ensure at least one login path
	# with keys exists for the users that will remain allowed.
	local -a candidates=()
	[[ -n ${CREATE_USER:-} ]] && candidates+=("$CREATE_USER")
	[[ -n ${SUDO_USER:-} ]] && candidates+=("$SUDO_USER")
	candidates+=(root)

	local user
	for user in "${candidates[@]}"; do
		if user_has_usable_key "$user"; then
			log_debug "lockout check: user '${user}' has a usable authorized_keys"
			return 0
		fi
	done
	if $DRY_RUN; then
		note_warn "ssh: NONE of the candidate users (${candidates[*]}) has a valid authorized_keys; real run would abort"
		return 0
	fi
	die "refusing to disable SSH password authentication: none of [${candidates[*]}] has a valid ~/.ssh/authorized_keys. Install a key (or pass --ssh-key with --create-user) and re-run."
}

create_ssh_user() {
	local user="$1" keysrc="${2:-}"

	if ! id "$user" >/dev/null 2>&1; then
		run useradd --create-home --shell /bin/bash --groups sudo "$user"
		note_applied "ssh: created sudo user '${user}' (password locked; key-only)"
	else
		run usermod -aG sudo "$user"
		log_debug "ssh: user '${user}' already exists; ensured sudo group membership"
	fi
	# Lock the password: access is key-only.
	run_soft passwd --lock "$user" >/dev/null 2>&1 || true

	if [[ -n $keysrc ]]; then
		local pubkey="$keysrc"
		if [[ -f $keysrc ]]; then
			pubkey="$(head -n1 "$keysrc")"
		fi
		# Validate the key material before installing.
		local tmpk
		tmpk="$(mktemp)"
		printf '%s\n' "$pubkey" >"$tmpk"
		if ! ssh-keygen -l -f "$tmpk" >/dev/null 2>&1; then
			rm -f "$tmpk"
			die "invalid SSH public key given via --ssh-key"
		fi
		rm -f "$tmpk"
		local home akf
		home="$(user_home_dir "$user")"
		[[ -n $home ]] || die "cannot determine home directory for '${user}'"
		akf="${home}/.ssh/authorized_keys"
		if $DRY_RUN; then
			log_info "[dry-run] would install public key into ${akf}"
		else
			mkdir -p "${home}/.ssh"
			chmod 700 "${home}/.ssh"
			chown "${user}:${user}" "${home}/.ssh"
			if [[ -f $akf ]] && grep -qxF -- "$pubkey" "$akf"; then
				log_debug "authorized_keys for ${user} already contains the key"
			else
				backup_file "$akf"
				printf '%s\n' "$pubkey" >>"$akf"
			fi
			chmod 600 "$akf"
			chown "${user}:${user}" "$akf"
		fi
		note_applied "ssh: public key installed for '${user}'"
	else
		note_manual "ssh: user '${user}' has no --ssh-key; add one before logging out"
	fi
}

mod_ssh() {
	log_info "=== ssh: hardening via drop-in ==="

	if ! have_cmd sshd && [[ ! -x /usr/sbin/sshd ]]; then
		note_skipped "ssh: sshd not installed"
		return 0
	fi

	# --- Optional operator account ----------------------------------------
	if [[ -n ${CREATE_USER:-} ]]; then
		create_ssh_user "$CREATE_USER" "${SSH_KEY_FILE:-}"
	fi

	# --- Lockout protection ------------------------------------------------
	assert_no_self_lockout

	# --- Build drop-in -----------------------------------------------------
	local port_line='' allow_line=''
	if [[ -n ${SSH_PORT:-} ]]; then
		port_line="Port ${SSH_PORT}"
	fi
	if [[ -n ${CREATE_USER:-} ]]; then
		allow_line="AllowUsers ${CREATE_USER}"
	elif [[ -n ${ALLOW_USERS:-} ]]; then
		allow_line="AllowUsers ${ALLOW_USERS}"
	fi

	local x11='no' agent='no' tcpfwd='no'
	if $KEEP_FORWARDING; then
		x11='yes' agent='yes' tcpfwd='yes'
	fi

	local rendered
	rendered="$(mktemp)"
	render_template "${SAFESET_ROOT}/configs/ssh/99-safeset.conf" "$rendered" \
		"PORT_LINE=${port_line}" \
		"ALLOW_USERS_LINE=${allow_line}" \
		"X11_FORWARDING=${x11}" \
		"AGENT_FORWARDING=${agent}" \
		"TCP_FORWARDING=${tcpfwd}"

	# --- Install drop-in, validate, roll back on failure -------------------
	local dest="$SSH_DROP_IN"
	if $DRY_RUN; then
		log_info "[dry-run] would install ${dest} and run 'sshd -t'"
		rm -f "$rendered"
		note_applied "ssh: drop-in prepared (root login off, password auth off, modern algos)"
		return 0
	fi

	backup_file "$dest"
	mkdir -p "$(dirname "$dest")"
	chmod 755 "$(dirname "$dest")"
	cp "$rendered" "$dest"
	chmod 644 "$dest"
	rm -f "$rendered"

	# sshd -t refuses to run without the privilege-separation directory
	# (normally created by the ssh.service unit via RuntimeDirectory).
	mkdir -p /run/sshd
	chmod 755 /run/sshd

	if ! /usr/sbin/sshd -t -f /etc/ssh/sshd_config; then
		# Restore previous drop-in (if any) and abort before touching sshd.
		if [[ -f ${SAFESET_BACKUP_ROOT}/${START_TS}${dest} ]]; then
			cp -a "${SAFESET_BACKUP_ROOT}/${START_TS}${dest}" "$dest"
		else
			rm -f "$dest"
		fi
		die "sshd configuration validation failed; previous SSH config restored"
	fi
	log_debug "sshd -t: OK"

	# --- Reload (never restart: do not cut the current session) ------------
	local reloaded=0
	if have_cmd systemctl; then
		if run_soft systemctl reload ssh; then
			reloaded=1
		elif run_soft systemctl reload sshd; then
			reloaded=1
		fi
	fi
	if ((reloaded == 0)); then
		local pidfile=/run/sshd.pid
		if [[ -f $pidfile ]]; then
			run_soft kill -HUP "$(cat "$pidfile")" || true
			reloaded=1
		fi
	fi
	if ((reloaded)); then
		note_applied "ssh: drop-in installed and sshd reloaded (session preserved)"
	else
		note_manual "ssh: drop-in installed but sshd could not be reloaded (no systemd?); run: systemctl reload ssh"
	fi

	if [[ -n ${SSH_PORT:-} && ${SSH_PORT} -ne ${SSH_PORT_CURRENT} ]]; then
		note_manual "ssh: port changed ${SSH_PORT_CURRENT} -> ${SSH_PORT}; reconnect using port ${SSH_PORT} and then close old port in firewall if desired"
	fi
	if ! $KEEP_FORWARDING; then
		note_manual "ssh: X11/agent/TCP forwarding disabled (override with --keep-forwarding)"
	fi
	return 0
}

mod_ssh_help() {
	cat <<'EOF'
ssh      harden OpenSSH through /etc/ssh/sshd_config.d/99-safeset.conf:
         no root login, no password auth (lockout-protected), no empty
         passwords, modern ciphers/kex/MACs, MaxAuthTries 3, protocol 2,
         timeouts, optional port change (--ssh-port) and AllowUsers.
         Validates with sshd -t and reloads (never restarts) sshd.
EOF
}
