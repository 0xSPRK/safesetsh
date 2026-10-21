#!/usr/bin/env bash
# safeset.sh — baseline hardening for fresh Debian 12/13 servers.
# https://github.com/0xSPRK/safesetsh  (MIT)
#
# What it is: a single, modular, idempotent script that reduces the attack
# surface of a freshly installed Debian server (CIS Level 1 oriented) and
# configures defenses against mass scanners, brute force and bots.
#
# What it is NOT: it does not "close all vulnerabilities". It does not patch
# your applications, does not replace a WAF, an IDS/IPS or central monitoring,
# and does not protect against a determined attacker who already has valid
# credentials or a kernel/zero-day exploit.

set -Eeuo pipefail

# Variables below are consumed by the sourced modules in lib/, which shellcheck
# cannot see from this file.
# shellcheck disable=SC2034
SAFESET_VERSION='0.1.0'
SAFESET_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SAFESET_ROOT SAFESET_VERSION

# --------------------------------------------------------------------------
# Defaults (overridable via flags or safeset.conf)
# --------------------------------------------------------------------------
DRY_RUN=false
VERBOSE=false
ASSUME_YES=false
# shellcheck disable=SC2034
AUTO_REBOOT=false
# shellcheck disable=SC2034
NO_IPV6=false
WEB=false
# shellcheck disable=SC2034
CROWDSEC=false
# shellcheck disable=SC2034
HONEYPOT=false
# shellcheck disable=SC2034
KEEP_FORWARDING=false
ROLLBACK=false
ROLLBACK_TS=''
CONFIRM_ONLY=false
SHOW_HELP=false
SHOW_VERSION=false
LIST_MODULES=false
SSH_PORT=''
CREATE_USER=''
SSH_KEY_FILE=''
# shellcheck disable=SC2034
ALLOW_USERS=''
ALLOW_PORTS_RAW=''
SAFE_TIMER=300
# shellcheck disable=SC2034
# shellcheck disable=SC2034
SSH_PORT_EFFECTIVE=22
# shellcheck disable=SC2034
REBOOT_RECOMMENDED=0
START_TS="$(date +%Y%m%d-%H%M%S)"

declare -a ADMIN_IPS=()
declare -a ALLOWED_PORTS=()
declare -a SELECTED_MODULES=()

MODULES_ALL=(packages sysctl filesystem accounts audit firewall fail2ban ssh web crowdsec honeypot)

declare -a ONLY_MODULES=()
declare -a SKIP_MODULES=()

# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------
usage() {
	cat <<EOF
safeset.sh ${SAFESET_VERSION} — Debian 12/13 baseline hardening (attack-surface reduction)

USAGE
  sudo ./safeset.sh [OPTIONS]
  sudo ./safeset.sh --rollback [TIMESTAMP]

MODES
  --dry-run                 show what would be done, change nothing
  --yes                     non-interactive (no prompts)
  --verbose                 verbose/debug output
  --only <list>             run only these modules (comma separated)
  --skip <list>             skip these modules
  --list-modules            list modules and exit
  --confirm                 confirm firewall connectivity (cancels safe-timer)
  --rollback [TIMESTAMP]    restore files from a backup (default: latest)
  --help                    this help
  --version                 print version

SSH / ACCESS
  --ssh-port <port>         change the SSH port
  --create-user <name>      create a sudo user for key-only login
  --ssh-key <file|key>      public key to install for --create-user
  --allow-users <list>      explicit AllowUsers list for sshd
  --keep-forwarding         keep X11/agent/TCP forwarding (default: disabled)

FIREWALL
  --allow-ports <list>      extra inbound ports, e.g. 80,443 or 8080/tcp
  --admin-ip <ip|cidr>      whitelist an operator IP (repeatable)
  --safe-timer <seconds>    auto-rollback firewall if not confirmed (0=off, default 300)
  --no-ipv6                 disable the IPv6 stack
  --crowdsec                install CrowdSec + nftables bouncer (external repo)
  --honeypot                endlessh tarpit on port 22 (only if SSH moved)

MISC
  --reboot-automatically    allow unattended-upgrades to reboot the host
  --web                     force the web module even without detected server
  --config <file>           load settings from a safeset.conf file
  --no-color                disable colored output

MODULES
$(for m in "${MODULES_ALL[@]}"; do printf '  %-10s\n' "$m"; done)

SAFETY
  Keep a second SSH session open and console/VNC access. Test on staging first.
EOF
}

list_modules() {
	local m
	for m in "${MODULES_ALL[@]}"; do
		local fn="mod_${m}_help"
		if declare -F "$fn" >/dev/null 2>&1; then
			"$fn"
		else
			printf '%s\n' "$m"
		fi
	done
}

die_usage() {
	printf 'error: %s\n\n' "$*" >&2
	usage >&2
	exit 2
}

# --------------------------------------------------------------------------
# Config file (KEY=VALUE only — no arbitrary code execution)
# --------------------------------------------------------------------------
load_config_file() {
	local file="$1"
	[[ -r $file ]] || die "config file '${file}' is not readable"
	local line key value
	while IFS= read -r line || [[ -n $line ]]; do
		line="${line#"${line%%[![:space:]]*}"}"
		[[ -z $line || $line == \#* ]] && continue
		[[ $line == *=* ]] || die "invalid line in ${file}: ${line}"
		key="${line%%=*}"
		value="${line#*=}"
		key="${key//[[:space:]]/}"
		value="${value%\"}"
		value="${value#\"}"
		value="${value%\'}"
		value="${value#\'}"
		case "$key" in
		SSH_PORT) SSH_PORT="$value" ;;
		CREATE_USER) CREATE_USER="$value" ;;
		SSH_KEY) SSH_KEY_FILE="$value" ;;
		ALLOW_USERS) ALLOW_USERS="$value" ;;
		ALLOW_PORTS) ALLOW_PORTS_RAW="$value" ;;
		ADMIN_IPS)
			IFS=',' read -ra _ips <<<"$value"
			ADMIN_IPS+=("${_ips[@]}")
			;;
		SAFE_TIMER) SAFE_TIMER="$value" ;;
		AUTO_REBOOT) AUTO_REBOOT="$(config_bool "$value")" ;;
		NO_IPV6) NO_IPV6="$(config_bool "$value")" ;;
		WEB) WEB="$(config_bool "$value")" ;;
		CROWDSEC) CROWDSEC="$(config_bool "$value")" ;;
		HONEYPOT) HONEYPOT="$(config_bool "$value")" ;;
		KEEP_FORWARDING) KEEP_FORWARDING="$(config_bool "$value")" ;;
		*) die "unknown key '${key}' in ${file}" ;;
		esac
	done <"$file"
	log_debug "loaded configuration from ${file}"
}

# Normalise a config-file boolean to the "true"/"false" commands the rest of
# the script expects. Accepts true/yes/on/1 and false/no/off/0.
config_bool() {
	local v="${1,,}"
	case "$v" in
	true | yes | on | 1) printf 'true' ;;
	false | no | off | 0 | '') printf 'false' ;;
	*) die "invalid boolean value: ${1}" ;;
	esac
}

# Find the config file that applies: --config wins, then ./safeset.conf, then
# /etc/safeset/safeset.conf. Parsed before the command line so that explicit
# flags always override the file.
resolve_config_file() {
	local prev='' a
	for a in "$@"; do
		if [[ $prev == '--config' ]]; then
			printf '%s' "$a"
			return 0
		fi
		prev="$a"
	done
	if [[ -r ${SAFESET_ROOT}/safeset.conf ]]; then
		printf '%s' "${SAFESET_ROOT}/safeset.conf"
		return 0
	fi
	if [[ -r ${SAFESET_ETC_DIR}/safeset.conf ]]; then
		printf '%s' "${SAFESET_ETC_DIR}/safeset.conf"
		return 0
	fi
	return 0
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
add_modules() {
	# add_modules <target-array-name> <comma-list>
	local -n arr="$1"
	local list="$2" item
	IFS=',' read -ra _items <<<"$list"
	for item in "${_items[@]}"; do
		item="${item// /}"
		[[ -z $item ]] && continue
		local known=0 m
		for m in "${MODULES_ALL[@]}"; do
			[[ $m == "$item" ]] && known=1
		done
		((known)) || die_usage "unknown module: '${item}'"
		arr+=("$item")
	done
}

parse_args() {
	while (($#)); do
		case "$1" in
		--dry-run) DRY_RUN=true ;;
		--yes | -y) ASSUME_YES=true ;;
		--verbose | -v) VERBOSE=true ;;
		--no-color) NO_COLOR=1 ;;
		--reboot-automatically | --auto-reboot)
			# shellcheck disable=SC2034
			AUTO_REBOOT=true
			;;
		--no-ipv6) NO_IPV6=true ;;
		--web) WEB=true ;;
		--crowdsec)
			# shellcheck disable=SC2034
			CROWDSEC=true
			;;
		--honeypot) HONEYPOT=true ;;
		--keep-forwarding)
			# shellcheck disable=SC2034
			KEEP_FORWARDING=true
			;;
		--confirm) CONFIRM_ONLY=true ;;
		--help | -h) SHOW_HELP=true ;;
		--version) SHOW_VERSION=true ;;
		--list-modules) LIST_MODULES=true ;;
		--rollback)
			ROLLBACK=true
			if [[ ${2:-} =~ ^[0-9]{8}-[0-9]{6}$ ]]; then
				ROLLBACK_TS="$2"
				shift
			fi
			;;
		--ssh-port)
			[[ -n ${2:-} ]] || die_usage "--ssh-port requires a port number"
			if [[ ! $2 =~ ^[0-9]+$ ]] || (($2 < 1 || $2 > 65535)); then
				die_usage "invalid --ssh-port: $2"
			fi
			SSH_PORT="$2"
			shift
			;;
		--create-user)
			[[ -n ${2:-} ]] || die_usage "--create-user requires a name"
			[[ $2 =~ ^[a-z_][a-z0-9_-]*$ ]] || die_usage "invalid user name: $2"
			CREATE_USER="$2"
			shift
			;;
		--ssh-key)
			[[ -n ${2:-} ]] || die_usage "--ssh-key requires a file or key"
			SSH_KEY_FILE="$2"
			shift
			;;
		--allow-users)
			[[ -n ${2:-} ]] || die_usage "--allow-users requires a list"
			# shellcheck disable=SC2034
			ALLOW_USERS="$2"
			shift
			;;
		--allow-ports)
			[[ -n ${2:-} ]] || die_usage "--allow-ports requires a list"
			ALLOW_PORTS_RAW="$2"
			shift
			;;
		--admin-ip)
			[[ -n ${2:-} ]] || die_usage "--admin-ip requires an address"
			ADMIN_IPS+=("$2")
			shift
			;;
		--safe-timer)
			[[ ${2:-} =~ ^[0-9]+$ ]] || die_usage "--safe-timer requires seconds"
			SAFE_TIMER="$2"
			shift
			;;
		--only)
			[[ -n ${2:-} ]] || die_usage "--only requires a module list"
			add_modules ONLY_MODULES "$2"
			shift
			;;
		--skip)
			[[ -n ${2:-} ]] || die_usage "--skip requires a module list"
			add_modules SKIP_MODULES "$2"
			shift
			;;
		--config)
			# The file was already resolved and loaded before parse_args ran
			# (see resolve_config_file), so here the flag is only consumed.
			[[ -n ${2:-} ]] || die_usage "--config requires a file"
			shift
			;;
		*) die_usage "unknown option: $1" ;;
		esac
		shift
	done
}

module_is_selected() {
	local m="$1" x
	if ((${#ONLY_MODULES[@]})); then
		for x in "${ONLY_MODULES[@]}"; do
			[[ $x == "$m" ]] && return 0
		done
		return 1
	fi
	for x in "${SKIP_MODULES[@]}"; do
		[[ $x == "$m" ]] && return 1
	done
	return 0
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
require_root() {
	if $DRY_RUN; then
		# Dry-run simulates every step and never mutates the system.
		if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
			log_warn "dry-run without root: some probes (nftables, sshd) may be skipped"
		fi
		return 0
	fi
	if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
		die "safeset.sh must run as root (try: sudo $0 $*)"
	fi
}

preflight_warnings() {
	printf '%s\n' "${C_BOLD}Before continuing:${C_RESET}"
	printf '  * keep a SECOND SSH session open and have console/VNC access\n'
	printf '  * test on staging first; verify access after each module\n'
	printf '  * backups go to %s/<timestamp>/\n' "${SAFESET_BACKUP_ROOT}"
	if [[ ${SSH_PORT} != "" ]] && [[ ${SSH_PORT} != "${SSH_PORT_CURRENT}" ]]; then
		printf '  * SSH will move %s -> %s (firewall opens the new port first)\n' \
			"${SSH_PORT_CURRENT}" "${SSH_PORT}"
	fi
	printf '\n'
	if $ASSUME_YES; then
		return 0
	fi
	if [[ -t 0 ]]; then
		confirm "Proceed with hardening?" 60 || die "aborted by operator"
	else
		log_warn "stdin is not a TTY; proceeding non-interactively (use --yes to silence this)"
	fi
}

preflight_checks() {
	if $NO_IPV6 && $HONEYPOT; then
		log_warn "--no-ipv6 with --honeypot: endlessh will bind IPv4/IPv6 depending on its build"
	fi
	if [[ -n ${SSH_KEY_FILE} && -z ${CREATE_USER} ]]; then
		die "--ssh-key requires --create-user"
	fi
	if [[ ${SSH_PORT} =~ ^[0-9]+$ ]]; then
		if ! $DRY_RUN && have_cmd ss && ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${SSH_PORT}$"; then
			die "port ${SSH_PORT} is already in use on this host"
		fi
	fi
}

# Validate option values right after the command line has been parsed (the
# config file is already loaded at this point), so a typo is reported
# immediately instead of after the root check.
validate_options() {
	local ip part
	local -a parts=()
	for ip in "${ADMIN_IPS[@]}"; do
		[[ -n $ip ]] || continue
		IFS=',' read -ra parts <<<"$ip"
		for part in "${parts[@]}"; do
			[[ -n $part ]] || continue
			is_valid_ip_or_cidr "$part" || die "invalid --admin-ip: ${part}"
		done
	done
	if [[ -n ${SSH_KEY_FILE} && -z ${CREATE_USER} ]]; then
		die "--ssh-key requires --create-user"
	fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
	# Function definitions are loaded first: argument validation uses helpers
	# from lib/ (is_valid_ip_or_cidr) and must run before any privilege check.
	# shellcheck source=lib/common.sh
	. "${SAFESET_ROOT}/lib/common.sh"
	# shellcheck source=lib/detect.sh
	. "${SAFESET_ROOT}/lib/detect.sh"
	# shellcheck source=lib/rollback.sh
	. "${SAFESET_ROOT}/lib/rollback.sh"

	local modfile
	shopt -s nullglob
	for modfile in "${SAFESET_ROOT}"/lib/modules/*.sh; do
		# shellcheck disable=SC1090
		. "$modfile"
	done
	shopt -u nullglob

	# Config file is loaded BEFORE the command line, so explicit flags always
	# win over the file. Only KEY=VALUE pairs are read — never shell code.
	local cfg_file
	cfg_file="$(resolve_config_file "$@")"
	if [[ -n $cfg_file ]]; then
		load_config_file "$cfg_file"
	fi

	parse_args "$@"

	if $SHOW_VERSION; then
		printf 'safeset.sh %s\n' "$SAFESET_VERSION"
		exit 0
	fi
	if $SHOW_HELP; then
		usage
		exit 0
	fi

	# Fail fast on invalid input — before asking for root.
	validate_options

	if $LIST_MODULES; then
		list_modules
		exit 0
	fi

	require_root "$@"

	detect_environment

	log_init

	if $CONFIRM_ONLY; then
		mark_firewall_confirmed
		exit 0
	fi

	if $ROLLBACK; then
		log_info "safeset.sh ${SAFESET_VERSION} — rollback mode"
		do_rollback "$ROLLBACK_TS"
		exit 0
	fi

	# The config file was already loaded (before the command line) in main().

	# Normalize ports and IPs.
	if [[ -n $ALLOW_PORTS_RAW ]]; then
		while IFS= read -r p; do ALLOWED_PORTS+=("$p"); done < <(normalize_ports "$ALLOW_PORTS_RAW")
	fi
	# Auto-open web ports when the web module will run against a real server.
	if [[ -n $WEB_SERVER ]] || $WEB; then
		local has_http=0 hp
		for hp in "${ALLOWED_PORTS[@]}"; do
			[[ $hp == 80/tcp || $hp == 443/tcp ]] && has_http=1
		done
		if ((has_http == 0)); then
			ALLOWED_PORTS+=("80/tcp" "443/tcp")
			log_info "web module active: opening 80/tcp and 443/tcp"
		fi
	fi

	local ip
	for ip in "${ADMIN_IPS[@]}"; do
		is_valid_ip_or_cidr "$ip" || die "invalid --admin-ip: ${ip}"
	done
	# A repeatable --admin-ip may also be a comma list.
	local -a expanded=()
	for ip in "${ADMIN_IPS[@]}"; do
		if [[ $ip == *,* ]]; then
			IFS=',' read -ra _parts <<<"$ip"
			expanded+=("${_parts[@]}")
		else
			expanded+=("$ip")
		fi
	done
	ADMIN_IPS=("${expanded[@]}")

	# shellcheck disable=SC2034 # consumed by sourced modules (ssh/firewall/fail2ban)
	if [[ -n $SSH_PORT ]]; then
		SSH_PORT_EFFECTIVE="$SSH_PORT"
	else
		SSH_PORT_EFFECTIVE="$SSH_PORT_CURRENT"
	fi

	for m in "${MODULES_ALL[@]}"; do
		module_is_selected "$m" && SELECTED_MODULES+=("$m")
	done

	log_info "safeset.sh ${SAFESET_VERSION} on Debian ${OS_VERSION_ID} (${OS_CODENAME}), virt=${VIRT}"
	if ((IS_CONTAINER)); then
		log_warn "container detected: kernel/module/mount/audit hardening will be skipped or partial"
	fi
	log_info "modules: ${SELECTED_MODULES[*]}"
	$DRY_RUN && log_warn "DRY RUN: no changes will be made"

	preflight_checks
	preflight_warnings

	local m
	for m in "${SELECTED_MODULES[@]}"; do
		log_info "--- module: ${m} ---"
		"mod_${m}"
	done

	# Firewall safe-timer confirmation (only when a ruleset was actually applied).
	if module_is_selected firewall && ! $DRY_RUN; then
		if [[ -f ${SAFESET_RUN_DIR}/confirmed ]]; then
			: # already confirmed this boot
		elif $ASSUME_YES; then
			log_warn "non-interactive run: firewall safe-timer stays armed."
			log_warn "verify connectivity now, then run: safeset.sh --confirm"
			note_manual "firewall: confirm access within ${SAFE_TIMER}s via 'safeset.sh --confirm' or the ruleset rolls back"
		elif confirm "Is your network access still working?" "$SAFE_TIMER"; then
			mark_firewall_confirmed
		fi
	elif module_is_selected firewall && $DRY_RUN && ((SAFE_TIMER > 0)); then
		log_info "dry-run: firewall safe-timer would be armed for ${SAFE_TIMER}s"
	fi

	print_report

	if ((${#REPORT_FAILED[@]})); then
		exit 1
	fi
	exit 0
}

main "$@"
