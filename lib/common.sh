# shellcheck shell=bash
# lib/common.sh — logging, dry-run execution, backups, managed blocks, report.
# Sourced by safeset.sh. Depends on globals set in safeset.sh:
#   DRY_RUN, VERBOSE, ASSUME_YES, START_TS, and option variables.

: "${SAFESET_BACKUP_ROOT:=/var/backups/safeset}"
: "${SAFESET_LOG_DIR:=/var/log/safeset}"
: "${SAFESET_ETC_DIR:=/etc/safeset}"
: "${SAFESET_RUN_DIR:=/run/safeset}"

# ---------------------------------------------------------------------------
# Colors / output
# ---------------------------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
	C_RESET=$'\033[0m'
	C_RED=$'\033[31m'
	C_GREEN=$'\033[32m'
	C_YELLOW=$'\033[33m'
	C_BLUE=$'\033[34m'
	C_BOLD=$'\033[1m'
	C_DIM=$'\033[2m'
else
	C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_BOLD='' C_DIM=''
fi

_log_to_file() {
	local line="$1"
	if [[ -n ${SAFESET_LOG_FILE:-} && -w ${SAFESET_LOG_FILE%/*} ]]; then
		printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >>"${SAFESET_LOG_FILE}" 2>/dev/null || true
	fi
}

log_init() {
	if $DRY_RUN; then
		SAFESET_LOG_FILE=''
		return 0
	fi
	mkdir -p "${SAFESET_LOG_DIR}" "${SAFESET_BACKUP_ROOT}" "${SAFESET_ETC_DIR}" "${SAFESET_RUN_DIR}" 2>/dev/null || true
	SAFESET_LOG_FILE="${SAFESET_LOG_DIR}/safeset.log"
	touch "${SAFESET_LOG_FILE}" 2>/dev/null || SAFESET_LOG_FILE=''
}

log_info() {
	printf '%s[INFO]%s %s\n' "${C_BLUE}" "${C_RESET}" "$*"
	_log_to_file "INFO  $*"
}
log_ok() {
	printf '%s[ OK ]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"
	_log_to_file "OK    $*"
}
log_warn() {
	printf '%s[WARN]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2
	_log_to_file "WARN  $*"
}
log_error() {
	printf '%s[ERR ]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2
	_log_to_file "ERROR $*"
}
log_skip() {
	printf '%s[SKIP]%s %s\n' "${C_DIM}" "${C_RESET}" "$*"
	_log_to_file "SKIP  $*"
}
log_debug() {
	if $VERBOSE; then
		printf '%s[DBG ]%s %s\n' "${C_DIM}" "${C_RESET}" "$*"
		_log_to_file "DEBUG $*"
	fi
}

die() {
	log_error "$*"
	exit 1
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
declare -ga REPORT_APPLIED=()
declare -ga REPORT_SKIPPED=()
declare -ga REPORT_MANUAL=()
declare -ga REPORT_WARN=()
declare -ga REPORT_FAILED=()

note_applied() {
	REPORT_APPLIED+=("$1")
	log_ok "$1"
}
note_skipped() {
	REPORT_SKIPPED+=("$1")
	log_skip "$1"
}
note_manual() {
	REPORT_MANUAL+=("$1")
	log_warn "MANUAL ACTION: $1"
}
note_warn() {
	REPORT_WARN+=("$1")
	log_warn "$1"
}
note_failed() {
	REPORT_FAILED+=("$1")
	log_error "$1"
}

print_report() {
	printf '\n%s==================== SAFESSET REPORT ====================%s\n' "${C_BOLD}" "${C_RESET}"
	local item
	if ((${#REPORT_APPLIED[@]})); then
		printf '%sApplied:%s\n' "${C_GREEN}" "${C_RESET}"
		for item in "${REPORT_APPLIED[@]}"; do printf '  + %s\n' "$item"; done
	fi
	if ((${#REPORT_SKIPPED[@]})); then
		printf '%sSkipped (not applicable / disabled):%s\n' "${C_DIM}" "${C_RESET}"
		for item in "${REPORT_SKIPPED[@]}"; do printf '  - %s\n' "$item"; done
	fi
	if ((${#REPORT_MANUAL[@]})); then
		printf '%sRequires manual action:%s\n' "${C_YELLOW}" "${C_RESET}"
		for item in "${REPORT_MANUAL[@]}"; do printf '  ! %s\n' "$item"; done
	fi
	if ((${#REPORT_WARN[@]})); then
		printf '%sWarnings:%s\n' "${C_YELLOW}" "${C_RESET}"
		for item in "${REPORT_WARN[@]}"; do printf '  ~ %s\n' "$item"; done
	fi
	if ((${#REPORT_FAILED[@]})); then
		printf '%sFailed:%s\n' "${C_RED}" "${C_RESET}"
		for item in "${REPORT_FAILED[@]}"; do printf '  x %s\n' "$item"; done
	fi
	printf '%s=========================================================%s\n' "${C_BOLD}" "${C_RESET}"
	if ((REBOOT_RECOMMENDED)); then
		printf '%sReboot is recommended to finish applying kernel/module changes.%s\n' "${C_YELLOW}" "${C_RESET}"
	fi
}

# ---------------------------------------------------------------------------
# Command execution (dry-run aware)
# ---------------------------------------------------------------------------
run() {
	if $DRY_RUN; then
		log_info "[dry-run] $*"
		return 0
	fi
	log_debug "+ $*"
	"$@"
}

# Run a command; on failure log a warning and return its status without
# aborting the caller (used where failure is expected, e.g. container limits).
run_soft() {
	if $DRY_RUN; then
		log_info "[dry-run] $*"
		return 0
	fi
	local rc=0
	log_debug "+ $*"
	"$@" || rc=$?
	return "$rc"
}

# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
declare -gA _SAFESET_BACKED=()

backup_file() {
	local f="$1"
	# The subscript is quoted: an unquoted path would be evaluated as an
	# arithmetic expression by some bash builds ("arithmetic syntax error").
	if [[ -n ${_SAFESET_BACKED["$f"]:-} ]]; then
		return 0
	fi
	_SAFESET_BACKED["$f"]=1
	if [[ ! -e $f ]]; then
		# Remember files CREATED by this run so --rollback can remove them
		# again (restoring only pre-existing files would keep hardening
		# drop-ins in place after a rollback).
		if ! $DRY_RUN; then
			mkdir -p "${SAFESET_BACKUP_ROOT}" 2>/dev/null || true
			printf '%s\n' "$f" >>"${SAFESET_BACKUP_ROOT}/${START_TS}.created" 2>/dev/null || true
		fi
		return 0
	fi
	if $DRY_RUN; then
		log_debug "[dry-run] would back up $f"
		return 0
	fi
	local dest="${SAFESET_BACKUP_ROOT}/${START_TS}${f}"
	mkdir -p "$(dirname "$dest")"
	cp -a "$f" "$dest"
	log_debug "backed up $f -> ${dest}"
}

backup_paths_marker() {
	# Record which files this run touched, for --report and auditing.
	$DRY_RUN && return 0
	printf '%s\n' "$@" >>"${SAFESET_BACKUP_ROOT}/${START_TS}.files" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------
write_file_atomic() {
	# write_file_atomic <dest> <mode> <content via stdin>
	local dest="$1" mode="${2:-644}"
	local tmp
	tmp="$(mktemp)" || die "mktemp failed"
	cat >"$tmp"
	if $DRY_RUN; then
		log_info "[dry-run] would write ${dest} (mode ${mode})"
		rm -f "$tmp"
		return 0
	fi
	mkdir -p "$(dirname "$dest")"
	local need=1
	if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
		need=0
	fi
	if ((need)); then
		backup_file "$dest"
		chmod "$mode" "$tmp"
		mv -f "$tmp" "$dest"
		log_debug "wrote $dest"
	else
		rm -f "$tmp"
		log_debug "$dest already up to date"
	fi
	return 0
}

# Idempotent: append a line only when the file does not contain it.
append_once() {
	local file="$1" line="$2"
	if [[ -f $file ]] && grep -qxF -- "$line" "$file" 2>/dev/null; then
		log_debug "$file already contains: $line"
		return 0
	fi
	if $DRY_RUN; then
		log_info "[dry-run] would append to ${file}: $line"
		return 0
	fi
	backup_file "$file"
	mkdir -p "$(dirname "$file")"
	printf '%s\n' "$line" >>"$file"
	log_debug "appended to $file: $line"
}

# Manage a block delimited by markers:
#   # >>> safeset managed: <tag> >>>
#   ...content...
#   # <<< safeset managed: <tag> <<<
# Replaces the block if present, appends otherwise. Idempotent.
ensure_managed_block() {
	local file="$1" tag="$2" content="$3"
	local begin="# >>> safeset managed: ${tag} >>>"
	local end="# <<< safeset managed: ${tag} <<<"
	local new_content
	new_content="${begin}"$'\n'"${content}"$'\n'"${end}"

	if [[ -f $file ]] && grep -qF -- "$begin" "$file"; then
		local existing
		existing="$(awk -v b="$begin" -v e="$end" '
      $0 == b {inb=1; next}
      $0 == e {inb=0; next}
      inb {print}
    ' "$file")"
		if [[ "$existing" == "$content" ]]; then
			log_debug "$file managed block '${tag}' already up to date"
			return 0
		fi
		if $DRY_RUN; then
			log_info "[dry-run] would update managed block '${tag}' in ${file}"
			return 0
		fi
		backup_file "$file"
		local tmp
		tmp="$(mktemp)"
		awk -v b="$begin" -v e="$end" -v repl="$new_content" '
      $0 == b {inb=1; print repl; next}
      $0 == e {inb=0; next}
      !inb {print}
    ' "$file" >"$tmp"
		mv -f "$tmp" "$file"
		log_debug "updated managed block '${tag}' in $file"
		return 0
	fi

	if $DRY_RUN; then
		log_info "[dry-run] would add managed block '${tag}' to ${file}"
		return 0
	fi
	backup_file "$file"
	mkdir -p "$(dirname "$file")"
	{
		[[ -f $file && -s $file ]] && printf '\n'
		printf '%s\n' "$new_content"
	} >>"$file"
	log_debug "added managed block '${tag}' to $file"
}

# Render @KEY@ placeholders from KEY=VAL arguments.
render_template() {
	# render_template <src> <dest> KEY=VAL...
	local src="$1" dest="$2"
	shift 2
	local content
	content="$(cat "$src")"
	local kv key val
	for kv in "$@"; do
		key="${kv%%=*}"
		val="${kv#*=}"
		# Escape sed replacement specials in val: \ & |
		val="${val//\\/\\\\}"
		val="${val//&/\\&}"
		val="${val//|/\\|}"
		content="${content//@$key@/$val}"
	done
	printf '%s\n' "$content" >"$dest"
}

# Install a rendered template (with @KEY@ placeholders) to destination.
install_template() {
	# install_template <src> <dest> [mode] [KEY=VAL...]
	local src="$1" dest="$2" mode="${3:-644}"
	shift 3 || shift 2
	local tmp
	tmp="$(mktemp)" || die "mktemp failed"
	if (($#)); then
		render_template "$src" "$tmp" "$@"
	else
		cat "$src" >"$tmp"
	fi
	if $DRY_RUN; then
		log_info "[dry-run] would install template ${src} -> ${dest} (mode ${mode})"
		rm -f "$tmp"
		return 0
	fi
	mkdir -p "$(dirname "$dest")"
	if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
		rm -f "$tmp"
		log_debug "$dest already up to date"
		return 0
	fi
	backup_file "$dest"
	chmod "$mode" "$tmp"
	mv -f "$tmp" "$dest"
	log_debug "installed $dest from $src"
}

# ---------------------------------------------------------------------------
# Confirmation / safe-timer
# ---------------------------------------------------------------------------
confirm() {
	# confirm <prompt> [timeout_seconds] — returns 0 when user confirms.
	local prompt="$1" timeout="${2:-0}"
	if $ASSUME_YES; then
		return 1
	fi
	if [[ ! -t 0 ]]; then
		return 1
	fi
	local answer
	if ((timeout > 0)); then
		if ! read -r -t "$timeout" -p "${prompt} [y/N, auto-continue in ${timeout}s] " answer; then
			printf '\n'
			return 1
		fi
	else
		read -r -p "${prompt} [y/N] " answer || return 1
	fi
	[[ $answer == y || $answer == Y || $answer == yes ]]
}

firewall_confirmed() {
	[[ -f ${SAFESET_RUN_DIR}/confirmed ]]
}

mark_firewall_confirmed() {
	$DRY_RUN && return 0
	mkdir -p "${SAFESET_RUN_DIR}"
	touch "${SAFESET_RUN_DIR}/confirmed"
	log_info "firewall connectivity confirmed; safe-timer cancelled"
}

# Arm a rollback watchdog: if not confirmed within N seconds, restore the
# saved pre-change nftables ruleset. Detached so it survives script exit.
arm_firewall_safe_timer() {
	local secs="$1"
	((secs > 0)) || return 0
	if $DRY_RUN; then
		log_info "[dry-run] would arm firewall safe-timer (${secs}s, auto-rollback without confirmation)"
		return 0
	fi
	local saved="${SAFESET_RUN_DIR}/ruleset.before"
	if [[ ! -f $saved ]]; then
		log_warn "safe-timer: no saved ruleset at ${saved}; timer not armed"
		return 0
	fi
	mkdir -p "${SAFESET_RUN_DIR}"
	rm -f "${SAFESET_RUN_DIR}/confirmed"
	nohup bash -c "
    sleep '${secs}'
    if [[ -f '${SAFESET_RUN_DIR}/confirmed' ]]; then
      exit 0
    fi
    if [[ -f '${saved}' ]]; then
      {
        echo 'flush ruleset'
        cat '${saved}'
      } > '${SAFESET_RUN_DIR}/ruleset.restore'
      if nft -f '${SAFESET_RUN_DIR}/ruleset.restore' 2>/dev/null; then
        echo \"safeset: safe-timer fired, nftables ruleset rolled back\" | logger -t safeset || true
      fi
    fi
  " >/dev/null 2>&1 &
	disown || true
	log_warn "safe-timer armed: firewall rules will be ROLLED BACK in ${secs}s unless confirmed."
	log_warn "Confirm with: safeset.sh --confirm  (or press Enter at the prompt)"
}

# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------
service_exists() { [[ -f /lib/systemd/system/$1.service || -f /etc/systemd/system/$1.service || -f /usr/lib/systemd/system/$1.service ]]; }
service_active() { have_cmd systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }
service_enabled() { have_cmd systemctl && systemctl is-enabled --quiet "$1" 2>/dev/null; }

enable_now() {
	local svc="$1"
	if ! have_cmd systemctl; then
		log_warn "systemctl not available; cannot enable ${svc}"
		return 1
	fi
	run systemctl enable --now "$svc"
}

# Validate a comma-separated list of TCP ports: 80,443 or 8080/tcp
# Prints normalized space-separated port numbers.
normalize_ports() {
	local input="$1" out=() p port proto
	IFS=',' read -ra _ports <<<"$input"
	for p in "${_ports[@]}"; do
		p="${p// /}"
		[[ -z $p ]] && continue
		proto=tcp
		if [[ $p == */* ]]; then
			port="${p%%/*}"
			proto="${p##*/}"
		else
			port="$p"
		fi
		if [[ ! $port =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
			die "invalid port: '$p'"
		fi
		if [[ $proto != tcp && $proto != udp ]]; then
			die "invalid protocol in '$p' (expected tcp or udp)"
		fi
		out+=("${port}/${proto}")
	done
	((${#out[@]})) || die "empty port list"
	printf '%s\n' "${out[@]}"
}

is_valid_ip_or_cidr() {
	local ip="$1" addr prefix o
	local -a _o=()
	if [[ $ip == */* ]]; then
		addr="${ip%%/*}"
		prefix="${ip##*/}"
		[[ $prefix =~ ^[0-9]+$ ]] || return 1
		if [[ $addr == *:* ]]; then
			((prefix >= 0 && prefix <= 128)) || return 1
		else
			((prefix >= 0 && prefix <= 32)) || return 1
		fi
	else
		addr="$ip"
	fi
	if [[ $addr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		IFS=. read -ra _o <<<"$addr"
		for o in "${_o[@]}"; do
			((o <= 255)) || return 1
		done
		return 0
	fi
	[[ $addr =~ ^[0-9a-fA-F:]+$ && $addr == *:* ]]
}
