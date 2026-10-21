# shellcheck shell=bash
# lib/modules/packages.sh — apt updates, unattended-upgrades, bloat removal,
# installation of the hardening toolset.

mod_packages() {
	log_info "=== packages: updates, auto-upgrades, hardening toolset ==="

	export DEBIAN_FRONTEND=noninteractive

	run apt-get update -y
	run apt-get full-upgrade -y --allow-downgrades

	# --- Packages to remove if present (legacy / risky services) -----------
	local -a remove_pkgs=()
	local -a candidates=(
		telnet telnet-ssl rsh-client rsh-server talk ntalk
		xinetd openbsd-inetd tftp tftp-hpa
		avahi-daemon cups cups-client cups-bsd
		nis yp-tools ypbind ftp ftpbsd
	)
	local pkg
	for pkg in "${candidates[@]}"; do
		if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
			remove_pkgs+=("$pkg")
		fi
	done
	if ((${#remove_pkgs[@]})); then
		run apt-get purge -y "${remove_pkgs[@]}"
		note_applied "packages: purged legacy/risky packages (${remove_pkgs[*]})"
	else
		log_debug "no legacy packages to purge"
	fi
	run apt-get autoremove -y --purge
	run apt-get autoclean -y

	# --- Core hardening toolset -------------------------------------------
	local -a install_pkgs=(
		nftables iptables fail2ban
		auditd apparmor apparmor-utils
		chrony needrestart debsums apt-listchanges
		aide aide-common rkhunter lynis
		unattended-upgrades
		libpam-pwquality libpam-modules login
		sudo openssh-server
		ca-certificates
	)
	run apt-get install -y --no-install-recommends "${install_pkgs[@]}"

	# endlessh is optional (honeypot module); install only when requested.
	if $HONEYPOT; then
		if apt-cache show endlessh >/dev/null 2>&1; then
			run apt-get install -y --no-install-recommends endlessh
		else
			note_warn "packages: 'endlessh' not available in ${OS_ID} ${OS_CODENAME} repositories"
		fi
	fi

	# --- unattended-upgrades ----------------------------------------------
	write_file_atomic /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
	local reboot_line='//Unattended-Upgrade::Automatic-Reboot "false";'
	if $AUTO_REBOOT; then
		reboot_line='//Unattended-Upgrade::Automatic-Reboot "true";'
		reboot_line+=$'\n'"//Unattended-Upgrade::Automatic-Reboot-Time \"04:00\";"
	fi
	ensure_managed_block /etc/apt/apt.conf.d/50unattended-upgrades "safeset-autoreboot" \
		"${reboot_line}"
	note_applied "packages: unattended security updates enabled (auto-reboot: ${AUTO_REBOOT})"

	# needrestart: don't pop interactive dialogs during upgrades.
	write_file_atomic /etc/needrestart.conf.d/50-safeset.conf 644 <<'EOF'
# Managed by safeset: non-interactive needrestart during unattended upgrades.
$nrconf{verbosity} = 0;
$nrconf{restart} = 'l';
EOF

	# apt-listchanges: non-interactive news display.
	write_file_atomic /etc/apt/listchanges.conf.d/50-safeset.conf 644 <<'EOF'
[apt]
frontend=none
always=false
confirm=false
EOF

	note_applied "packages: hardening toolset installed"
	return 0
}

mod_packages_help() {
	cat <<'EOF'
packages  apt update/full-upgrade, unattended-upgrades for security,
          removal of legacy services (telnet/rsh/avahi/cups/...),
          installation of the hardening toolset (nftables, fail2ban,
          auditd, apparmor, chrony, aide, rkhunter, lynis, ...)
EOF
}
