# shellcheck shell=bash
# lib/detect.sh — OS, virtualization, service and environment detection.
# Sourced by safeset.sh.

OS_ID=''
OS_VERSION_ID=''
OS_CODENAME=''
VIRT='none'
IS_CONTAINER=0
HAS_SYSTEMD=0
HAS_NFT=0
SSH_PORT_CURRENT=22
WEB_SERVER='' # nginx | apache2 | ''

detect_os() {
	if [[ ! -r /etc/os-release ]]; then
		die "/etc/os-release not found; cannot detect operating system"
	fi
	# shellcheck disable=SC1091
	. /etc/os-release
	OS_ID="${ID:-}"
	OS_VERSION_ID="${VERSION_ID:-}"
	OS_CODENAME="${VERSION_CODENAME:-}"

	if [[ $OS_ID != debian ]]; then
		die "unsupported distribution: '${OS_ID:-unknown}' (only Debian 12 bookworm and 13 trixie are supported)"
	fi
	case "$OS_VERSION_ID" in
	12 | 12.*) ;; # bookworm
	13 | 13.*) ;; # trixie
	*)
		die "unsupported Debian version '${OS_VERSION_ID:-unknown}' (supported: 12 bookworm, 13 trixie)"
		;;
	esac
	log_debug "detected Debian ${OS_VERSION_ID} (${OS_CODENAME})"
}

detect_virt() {
	if have_cmd systemd-detect-virt; then
		VIRT="$(systemd-detect-virt 2>/dev/null || echo none)"
		if systemd-detect-virt --container >/dev/null 2>&1; then
			IS_CONTAINER=1
		fi
	fi
	if ((!IS_CONTAINER)); then
		# Fallbacks for images without systemd-detect-virt (slim containers).
		if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
			IS_CONTAINER=1
			[[ $VIRT == none || -z $VIRT ]] && VIRT=container
		elif [[ -r /proc/1/cgroup ]] && grep -qE '(docker|podman|libpod|containerd|lxc|kubepods)' /proc/1/cgroup 2>/dev/null; then
			IS_CONTAINER=1
			[[ $VIRT == none || -z $VIRT ]] && VIRT=container
		fi
	fi
	if [[ -d /run/systemd/system ]] && have_cmd systemctl; then
		HAS_SYSTEMD=1
	fi
	log_debug "virt=${VIRT} container=${IS_CONTAINER} systemd=${HAS_SYSTEMD}"
}

detect_nft() {
	if have_cmd nft; then
		# A NET_ADMIN-less container usually cannot list/create rulesets.
		if nft list ruleset >/dev/null 2>&1; then
			HAS_NFT=1
		fi
	fi
}

detect_ssh_port() {
	SSH_PORT_CURRENT=22
	local port='' f
	local -a confs=()
	if [[ -x /usr/sbin/sshd ]]; then
		port="$(/usr/sbin/sshd -T 2>/dev/null | awk 'tolower($1)=="port" {print $2; exit}')" || port=''
	fi
	if [[ -z $port ]]; then
		if [[ -r /etc/ssh/sshd_config ]]; then
			confs+=(/etc/ssh/sshd_config)
		fi
		for f in /etc/ssh/sshd_config.d/*.conf; do
			if [[ -r $f ]]; then
				confs+=("$f")
			fi
		done
		if ((${#confs[@]} > 0)); then
			port="$(awk 'tolower($1)=="port" {print $2; exit}' "${confs[@]}" 2>/dev/null | tail -n1)" || port=''
		fi
	fi
	if [[ $port =~ ^[0-9]+$ ]]; then
		SSH_PORT_CURRENT="$port"
	fi
	log_debug "current ssh port: ${SSH_PORT_CURRENT}"
}

detect_web() {
	WEB_SERVER=''
	if have_cmd nginx && [[ -d /etc/nginx ]]; then
		WEB_SERVER=nginx
	elif have_cmd apache2 && [[ -d /etc/apache2 ]]; then
		WEB_SERVER=apache2
	fi
	log_debug "web server: ${WEB_SERVER:-none}"
}

detect_environment() {
	detect_os
	detect_virt
	detect_nft
	detect_ssh_port
	detect_web
}

# True when a hardening knob is not applicable to this environment.
env_limits_sysctl() {
	# In containers /proc/sys is usually read-only or namespaced per knob.
	((IS_CONTAINER))
}

env_limits_kernel_modules() {
	((IS_CONTAINER))
}

env_limits_audit() {
	# auditd needs kernel audit support (not available in unprivileged containers).
	((IS_CONTAINER))
}

env_limits_mounts() {
	((IS_CONTAINER))
}

env_limits_nft() {
	((HAS_NFT == 0))
}
