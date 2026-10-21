# shellcheck shell=bash
# lib/modules/web.sh — nginx / apache hardening drop-ins.

nginx_insert_server_include() {
	# Insert the safeset snippet include right after each "server {" line.
	local file="$1"
	local inc='    include /etc/nginx/snippets/safeset-server.conf;'
	if grep -qF 'safeset-server.conf' "$file" 2>/dev/null; then
		log_debug "nginx: ${file} already includes the safeset snippet"
		return 0
	fi
	if $DRY_RUN; then
		log_info "[dry-run] would add safeset include to ${file}"
		return 0
	fi
	backup_file "$file"
	local tmp
	tmp="$(mktemp)"
	awk -v inc="$inc" '
    { print }
    /^[[:space:]]*server[[:space:]]*\{/ { print inc }
  ' "$file" >"$tmp"
	mv -f "$tmp" "$file"
	log_debug "nginx: include added to ${file}"
}

mod_web() {
	log_info "=== web: server hardening ==="

	if [[ -z $WEB_SERVER ]] && ! $WEB; then
		note_skipped "web: no nginx/apache detected and --web not given"
		return 0
	fi

	local did=0

	# --- nginx --------------------------------------------------------------
	if [[ $WEB_SERVER == nginx || $WEB ]]; then
		if [[ -d /etc/nginx ]]; then
			install_template "${SAFESET_ROOT}/configs/web/nginx-http-safeset.conf" \
				/etc/nginx/conf.d/99-safeset.conf 644
			install_template "${SAFESET_ROOT}/configs/web/nginx-safeset-server.conf" \
				/etc/nginx/snippets/safeset-server.conf 644

			local site
			shopt -s nullglob
			for site in /etc/nginx/sites-enabled/*; do
				[[ -f $site ]] || continue
				nginx_insert_server_include "$site"
			done
			shopt -u nullglob

			if ! $DRY_RUN; then
				if nginx -t >/dev/null 2>&1; then
					run_soft systemctl reload nginx >/dev/null 2>&1 || true
					note_applied "web: nginx hardened (headers, rate limits, scanner 444) and reloaded"
				else
					local err
					err="$(nginx -t 2>&1 | tail -n3)"
					note_failed "web: nginx config test failed: ${err}"
					note_manual "web: fix nginx config; safeset backups are in ${SAFESET_BACKUP_ROOT}/${START_TS}/etc/nginx"
					return 1
				fi
			else
				note_applied "web: nginx drop-ins prepared"
			fi
			did=1
		fi
	fi

	# --- apache -------------------------------------------------------------
	if [[ $WEB_SERVER == apache2 || $WEB ]]; then
		if [[ -d /etc/apache2 ]]; then
			install_template "${SAFESET_ROOT}/configs/web/apache-safeset-security.conf" \
				/etc/apache2/conf-available/safeset-security.conf 644
			if have_cmd a2enconf; then
				run_soft a2enconf -q safeset-security >/dev/null 2>&1 || run_soft a2enconf safeset-security >/dev/null 2>&1 || true
			fi
			if ! $DRY_RUN; then
				if apache2ctl configtest >/dev/null 2>&1; then
					run_soft systemctl reload apache2 >/dev/null 2>&1 || true
					note_applied "web: apache hardened (headers, 403 scanner paths) and reloaded"
				else
					local aerr
					aerr="$(apache2ctl configtest 2>&1 | tail -n3)"
					note_failed "web: apache config test failed: ${aerr}"
					return 1
				fi
			else
				note_applied "web: apache conf prepared"
			fi
			did=1
		fi
	fi

	if ((did == 0)); then
		note_skipped "web: no web server configuration directory found"
	fi
	return 0
}

mod_web_help() {
	cat <<'EOF'
web       nginx/apache hardening using drop-ins only: hide server version,
          security headers (HSTS, X-Content-Type-Options, X-Frame-Options,
          Referrer-Policy, CSP placeholder, Permissions-Policy), no TRACE,
          body/time limits, rate limiting zones, 444/403 for scanner paths
          and bad user agents (also feeding fail2ban). Validates config
          (nginx -t / apache2ctl configtest) before reload.
EOF
}
