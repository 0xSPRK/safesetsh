# safesetsh

**`safeset.sh` — one-shot baseline hardening for Debian 12 (bookworm) and Debian 13 (trixie).**
Attack-surface reduction for internet-facing hosts: closes the usual SSH/brute-force/scanner
surface, applies CIS-style kernel and account hardening, and refuses to lock you out while
doing it.

> **Read this before you run it.** Hardening a live server can lock you out. Keep a second SSH
> session open, have console/VNC access, and test on staging first. The script is not a
> substitute for reading what it changes — every change is printed, logged and backed up.

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Options](#options)
- [Modules](#modules)
- [Safety model](#safety-model)
- [Rollback](#rollback)
- [Verification (CI + local)](#verification-ci--local)
- [What is verified, and what is not](#what-is-verified-and-what-is-not)
- [Layout](#layout)

## What it does

| Area | Summary |
| --- | --- |
| Packages | Core hardening toolset (nftables, fail2ban, auditd, AIDE, rkhunter, Lynis, chrony, apparmor, unattended-upgrades, …) |
| sysctl | CIS-style network kernel hardening (syn cookies, redirects off, source routing, accept redirects, rp_filter, IPv6 hardening) |
| Filesystem | `nodev,nosuid,noexec` on `/tmp` and `/var/tmp`, stricter permissions on sensitive files, login banner |
| Accounts | Password quality (`pwquality`), `login.defs` ageing, `umask 027`, locked system accounts, `su` restricted to sudo group, `cron.allow`, sudoers drop-in |
| Audit | auditd rules, persistent size-capped journald, AIDE database + weekly integrity check, weekly rkhunter/Lynis reports, chrony time sync |
| Firewall | nftables `inet safeset` table, default-deny inbound, scan-pattern drops, per-source rate limiting, SSH rate limit, operator whitelist |
| Fail2ban | sshd jail (brute force) + optional web jail, log file bootstrap, systemd timer |
| SSH | Drop-in `99-safeset.conf`: key-only auth, no root login, no password auth, reduced ciphers/MACs/KEX, no forwarding, `MaxAuthTries`/`LoginGraceTime` tightened, optional port change |
| Web | nginx/Apache hardening snippets (headers, TLS, server tokens) when a web server is detected |
| CrowdSec | Opt-in (`--crowdsec`): CrowdSec + nftables bouncer from the upstream package repository, GPG-verified |
| Honeypot | Opt-in (`--honeypot`): endlessh tarpit on port 22 (only meaningful after the SSH port was moved) |

The script is a **baseline**, not a silver bullet. It reduces the surface that automated
scanners and credential-stuffing bots look for; it cannot protect a host that is already
compromised, and it does not replace monitoring, patching, or backups.

## Quick start

```bash
git clone https://github.com/0xSPRK/safesetsh.git
cd safesetsh

# 1. See exactly what would happen (no changes at all)
sudo ./safeset.sh --dry-run

# 2. Hardening run on a staging host
sudo ./safeset.sh --yes --admin-ip 203.0.113.10 --safe-timer 300

# 3. From a second terminal, verify you can still log in, then:
sudo ./safeset.sh --confirm
```

Recommended for a real host:

```bash
sudo ./safeset.sh --create-user ops --ssh-key ~/.ssh/id_ed25519.pub \
                  --admin-ip 203.0.113.10 \
                  --allow-ports 80,443 \
                  --safe-timer 300
```

`--safe-timer` is the important part: the firewall ruleset is armed with a watchdog. If you
do not confirm connectivity with `--confirm` (or the interactive prompt) within the timeout,
the **previous nftables ruleset is restored automatically**.

## Options

```
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
```

Notes:

- `--dry-run` works without root; it only warns when a privileged probe cannot run.
- The firewall opens the **new** SSH port before the old one is dropped, so a port change
  does not cut an active session.
- `--admin-ip` is the operator whitelist inside the nftables `admin4`/`admin6` sets. If you
  give no address, the ruleset still applies — a lockout then needs console access
  (`nft delete table inet safeset`).
- A config file may be used instead of flags: `KEY=VALUE` pairs only, no shell evaluation
  (see `load_config_file` in `safeset.sh`). Keys mirror the flags
  (`SSH_PORT`, `ADMIN_IPS`, `ALLOW_PORTS`, `SAFE_TIMER`, `NO_IPV6`, `WEB`, `CROWDSEC`,
  `HONEYPOT`, `KEEP_FORWARDING`, `AUTO_REBOOT`).
- **Config file lookup order**: `--config <file>` → `./safeset.conf` → `/etc/safeset/safeset.conf`
  (the first readable file wins). The file is parsed *before* the command line, so an explicit
  flag always overrides the value from the file. Boolean keys accept `true/yes/on/1` and
  `false/no/off/0`; an unknown key or a non-boolean value aborts the run.
- Invalid input is rejected **before** the root check: a bad `--admin-ip` (including a
  comma-separated list) or `--ssh-key` without `--create-user` fails immediately, so a
  misconfigured run never half-applies anything.
- All paths are overridable through the environment: `SAFESET_BACKUP_ROOT`,
  `SAFESET_LOG_DIR`, `SAFESET_ETC_DIR`, `SAFESET_RUN_DIR`.

## Modules

`safeset.sh --list-modules` prints the same list with per-module notes.

Default order: `packages → sysctl → filesystem → accounts → audit → firewall → fail2ban →
ssh → web`. `crowdsec` and `honeypot` are opt-in.

- `packages` — apt install of the hardening toolset, `needrestart` handling, apt cache cleanup.
- `sysctl` — writes `/etc/sysctl.d/99-safeset.conf` and applies it immediately.
- `filesystem` — remounts `/tmp` and `/var/tmp` with `nodev,nosuid,noexec`, tightens
  permissions on `/etc/passwd`, `/etc/shadow`, `/root`, cron directories, installs
  `/etc/issue.net` + SSH banner.
- `accounts` — `/etc/security/pwquality.conf.d`, `login.defs` (PASS_MAX_DAYS, UMASK, SHA512),
  locks unused system accounts, `pam_wheel` for `su`, `umask 027`, `TMOUT=600`, core dumps
  off, `/etc/cron.allow`, sudoers drop-in.
- `audit` — `/etc/audit/rules.d/99-safeset.rules` + `augenrules --load`, journald drop-in,
  AIDE database, `safeset-scans.service/.timer` (weekly rkhunter + Lynis + AIDE reports in
  `/var/log/safeset`), chrony.
- `firewall` — nftables `inet safeset` table: default-deny input, established/related
  accept, ICMP handling, malformed-packet drops, per-source throttle sets, per-source SSH
  rate limiting, operator whitelist sets, `forward` policy drop, `output` accept.
- `fail2ban` — `jail.d/99-safeset.local` (sshd), optional `99-safeset-web.local`, log file
  bootstrap (`/var/log/auth.log`), systemd timer.
- `ssh` — `/etc/ssh/sshd_config.d/99-safeset.conf`; validates with `sshd -t` **before**
  installing, restores the previous drop-in if validation fails, reloads (never restarts)
  `sshd`; optional user creation with an authorized key.
- `web` — nginx/Apache hardening snippets; only touches config when a web server is detected
  (or `--web` is given).
- `crowdsec` — `--crowdsec` only. Installs CrowdSec from the upstream packagecloud
  repository after verifying the repository GPG key fingerprint
  (`6A89E3C2303A901A889971D3376ED5326E93CD0C`), then the nftables bouncer.
- `honeypot` — `--honeypot` only. endlessh tarpit; warns if the SSH port was not moved.

## Safety model

1. **Dry-run first.** `--dry-run` prints every action and touches nothing.
2. **Backups.** Every file the script modifies is copied to
   `/var/backups/safeset/<timestamp>/…` before it is changed. Files the script *creates* are
   recorded as well, so a rollback removes them again instead of leaving them behind.
3. **Self-lockout protection.** Before password authentication is disabled the script
   verifies that a usable key-based login path exists (`assert_no_self_lockout`).
4. **Config validation.** `sshd -t` and `nft --check` run against the *exact* file that is
   about to be installed. A failing check aborts that module instead of installing a broken
   configuration.
5. **Firewall safe-timer.** `--safe-timer <seconds>` (default 300) arms a detached watchdog.
   Without a `--confirm`, the pre-change nftables ruleset is restored automatically.
6. **Atomic writes.** Configuration files are written to a temporary file and moved into
   place, so a crash cannot leave a half-written config.

## Rollback

```bash
sudo ./safeset.sh --rollback              # latest backup
sudo ./safeset.sh --rollback 20261019-184016   # a specific run
```

Rollback restores every modified file from the backup set, removes files that the run
created, and reloads the services it can. A copy of the pre-rollback state is kept in
`/var/backups/safeset/pre-rollback-<timestamp>/` so a rollback can itself be rolled back.

## Verification (CI + local)

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull request:

- `shellcheck -x -S style` over all shell files — must be clean.
- `shfmt -d` (default flags) over all shell files — must be clean.
- `bats` unit tests in `debian:12-slim` and `debian:13-slim` containers.
- An integration job that runs the real script inside `debian:12`/`debian:13` containers:
  dry-run, a real hardening run, idempotency (second identical run), `nft list table inet
  safeset`, `fail2ban-client --test`, the SSH module with a generated key plus `sshd -t`,
  and finally `--rollback`.

Locally (needs Docker or Podman):

```bash
DOCKER_BIN=podman bash ci/container-smoke.sh docker.io/library/debian:12-slim
DOCKER_BIN=podman bash ci/container-smoke.sh docker.io/library/debian:13-slim
DOCKER_BIN=podman bash ci/lynis-compare.sh  docker.io/library/debian:12-slim
```

`ci/lynis-compare.sh` runs a Lynis audit before and after a real hardening run and prints
`LYNIS_BEFORE=<n> LYNIS_AFTER=<n>`.

## What is verified, and what is not

Honest status of the claims in this repository:

**Verified by automated tests in this repository**

- `shellcheck -x -S style`: no findings.
- `shfmt -d`: no diff.
- `bats` unit tests (19): argument parsing, module selection, config-file handling,
  help/version output, and the safety primitives (backup bookkeeping, template rendering,
  rollback of modified and created files).
- Integration smoke test (Debian 12 and 13 containers): full dry-run, full real run,
  idempotent second run, nftables table present, fail2ban config valid, SSH drop-in valid
  (`sshd -t`), rollback restores the system.
- nftables ruleset: validated by `nft --check` against the kernel before it is applied
  (Debian 12, nft 1.0.6, and Debian 13).

**Verified manually, not covered by an automated test**

- Lynis hardening index before/after. Last measured run (2026-10-21, `debian:12-slim`):
  **58 → 73**. Re-run `ci/lynis-compare.sh` to get the numbers for your environment.
- Behaviour of the SSH module against a real `sshd` service (the container test validates
  the configuration with `sshd -t`, it does not log in over a real network).

**Not verified / known limitations**

- The CrowdSec and honeypot modules install third-party components from the network; they
  are opt-in and were not exercised by the automated test suite.
- Kernel-level hardening (module blacklisting, mount hardening, auditd rules) is skipped or
  partial inside containers — the script detects this and says so in its report.
- AIDE database initialisation needs `CAP_SETPCAP`/`CAP_SETFCAP` and therefore fails inside
  restricted containers; on a real host it works. The script reports this as a manual action
  instead of failing silently.
- No claim is made about compliance with any certification. The configuration follows
  common CIS Debian Level 1 guidance, but this project is not audited.

## Layout

```
safeset.sh              entry point: argument parsing, preflight, module loop, report
lib/common.sh           logging, file helpers, backups, templates, safe-timer
lib/detect.sh           OS/virtualisation/container/nft detection
lib/rollback.sh         restore logic
lib/modules/*.sh        one file per module (mod_<name> + mod_<name>_help)
configs/                every file the script installs (sysctl, nftables, ssh, audit, …)
tests/                  bats unit tests
ci/                     container smoke test and Lynis before/after comparison
.github/workflows/      CI: shellcheck, shfmt, bats, integration smoke
```

## License

MIT — see [LICENSE](LICENSE).
