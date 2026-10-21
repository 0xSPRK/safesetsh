# shellcheck shell=bash
# lib/modules/accounts.sh — password policy, account hygiene, umask, su/cron.

mod_accounts() {
	log_info "=== accounts: password policy, locked system accounts, umask, su, cron ==="

	# --- Password quality (libpam-pwquality) -------------------------------
	if [[ -d /etc/security/pwquality.conf.d ]] || ! $DRY_RUN; then
		install_template "${SAFESET_ROOT}/configs/pam/pwquality-safeset.conf" \
			/etc/security/pwquality.conf.d/99-safeset.conf 644
		note_applied "accounts: password quality policy installed (minlen 14, minclass 3)"
	fi

	# --- login.defs hardening ---------------------------------------------
	if [[ -f /etc/login.defs ]]; then
		# note: managed block avoids duplicating keys on re-run
		ensure_managed_block /etc/login.defs "login-defs" \
			"$(printf '%s\n' \
				'PASS_MAX_DAYS   365' \
				'PASS_MIN_DAYS   1' \
				'PASS_WARN_AGE   7' \
				'UMASK           027' \
				'ENCRYPT_METHOD  SHA512' \
				'SHA_CRYPT_MIN_ROUNDS 65536')"
		note_applied "accounts: login.defs hardened (PASS_MAX_DAYS=365, UMASK=027, SHA512)"
	fi

	# Root password aging (CIS: max 365 days).
	if ! $DRY_RUN && id root >/dev/null 2>&1; then
		chage -M 365 -m 1 root 2>/dev/null || note_warn "accounts: could not set password aging for root"
	fi

	# --- Lock unused interactive system accounts --------------------------
	local acct
	for acct in games news uucp proxy backup list irc gnats; do
		if id "$acct" >/dev/null 2>&1; then
			run_soft usermod -L "$acct" >/dev/null 2>&1 || true
			run_soft usermod -s /usr/sbin/nologin "$acct" >/dev/null 2>&1 || true
		fi
	done
	note_applied "accounts: legacy interactive accounts locked (games/news/uucp/proxy/backup/list/irc/gnats)"

	# Lock any account with an empty password hash.
	if ! $DRY_RUN && [[ -r /etc/shadow ]]; then
		local locked=0
		while IFS=: read -r user _hash _rest; do
			if [[ -z $_hash ]]; then
				if passwd -l "$user" >/dev/null 2>&1; then
					locked=$((locked + 1))
				fi
			fi
		done </etc/shadow
		if ((locked > 0)); then
			note_applied "accounts: locked ${locked} account(s) with empty password"
		fi
	fi

	# --- Restrict su to the sudo group (pam_wheel) -------------------------
	if [[ -f /etc/pam.d/su ]]; then
		ensure_managed_block /etc/pam.d/su "pam-wheel-group" \
			"auth required pam_wheel.so use_uid group=sudo"
		note_applied "accounts: 'su' restricted to the sudo group (pam_wheel)"
	else
		note_skipped "accounts: /etc/pam.d/su not found"
	fi

	# --- umask / session timeout / core dumps -----------------------------
	write_file_atomic /etc/profile.d/safeset-umask.sh 644 <<'EOF'
# Managed by safeset: default umask and idle session timeout.
umask 027
readonly TMOUT=600
export TMOUT
EOF
	chmod 644 /etc/profile.d/safeset-umask.sh 2>/dev/null || true
	write_file_atomic /etc/profile.d/safeset-umask.csh 644 <<'EOF'
# Managed by safeset: csh variant of umask/session timeout.
umask 027
setenv TMOUT 600
EOF
	write_file_atomic /etc/security/limits.d/99-safeset.conf 644 <<'EOF'
# Managed by safeset: no core dumps for any user.
*  hard  core  0
*  soft  core  0
EOF
	note_applied "accounts: umask 027, TMOUT=600, core dumps disabled"

	# --- cron / at access control -----------------------------------------
	if [[ -d /etc/cron.d ]] || have_cmd crontab; then
		local cron_users='root'
		[[ -n ${SUDO_USER:-} ]] && cron_users+=$'\n'"${SUDO_USER}"
		[[ -n ${CREATE_USER:-} ]] && cron_users+=$'\n'"${CREATE_USER}"
		printf '%s\n' "$cron_users" | write_file_atomic /etc/cron.allow 600
		run_soft rm -f /etc/cron.deny || true
		note_applied "accounts: cron restricted via /etc/cron.allow"
	fi
	if have_cmd at || [[ -d /var/spool/cron/atjobs ]]; then
		local at_users='root'
		[[ -n ${SUDO_USER:-} ]] && at_users+=$'\n'"${SUDO_USER}"
		printf '%s\n' "$at_users" | write_file_atomic /etc/at.allow 600
		run_soft rm -f /etc/at.deny || true
		note_applied "accounts: at restricted via /etc/at.allow"
	fi

	# --- sudoers drop-in ---------------------------------------------------
	if [[ -d /etc/sudoers.d ]]; then
		install_template "${SAFESET_ROOT}/configs/login/99-safeset-sudoers.conf" \
			/etc/sudoers.d/99-safeset 440
		if ! $DRY_RUN && have_cmd visudo; then
			if ! visudo -c -f /etc/sudoers >/dev/null 2>&1; then
				note_failed "accounts: sudoers validation failed; removing drop-in"
				rm -f /etc/sudoers.d/99-safeset
			else
				note_applied "accounts: sudoers hardening drop-in installed"
			fi
		fi
	fi

	return 0
}

mod_accounts_help() {
	cat <<'EOF'
accounts  password policy via libpam-pwquality (minlen 14, minclass 3),
          login.defs hardening, root password aging, locking of legacy
          interactive accounts and empty-password accounts, su restricted to
          the sudo group, umask 027, TMOUT=600, core dumps disabled, cron/at
          allow-lists and a sudoers drop-in (with visudo validation).
EOF
}
