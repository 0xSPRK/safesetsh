# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-21

Initial public release.

### Added

- `safeset.sh` entry point with argument parsing, preflight checks, module loop and a
  final report (applied / skipped / manual actions / warnings).
- Modules: `packages`, `sysctl`, `filesystem`, `accounts`, `audit`, `firewall`, `fail2ban`,
  `ssh`, `web`, plus opt-in `crowdsec` and `honeypot`.
- Safety mechanisms:
  - `--dry-run` mode that changes nothing and works without root.
  - Timestamped backups of every modified file under `/var/backups/safeset/<timestamp>/`,
    including a record of files created by the run so `--rollback` removes them again.
  - `--rollback [TIMESTAMP]` restores the previous state and reloads services.
  - Firewall `--safe-timer` watchdog that restores the previous nftables ruleset when
    connectivity is not confirmed in time; `--confirm` cancels it.
  - Self-lockout protection before password authentication is disabled.
  - `sshd -t` and `nft --check` validation of the exact file that is installed.
  - Atomic file writes.
- nftables ruleset (`inet safeset`): default-deny inbound, malformed-packet drops, per-source
  throttle sets, per-source SSH rate limiting, operator whitelist sets, forward policy drop.
- SSH drop-in `99-safeset.conf` (key-only auth, no root login, reduced ciphers/MACs/KEX, no
  forwarding, tightened timeouts) with optional operator user creation.
- Fail2ban jails for sshd (and web servers when detected), auditd rules, AIDE database
  bootstrap, persistent journald limits, weekly rkhunter/Lynis/AIDE reports, chrony.
- CI (`.github/workflows/ci.yml`): shellcheck, shfmt, `bats` unit tests on Debian 12/13 and
  an integration job that runs the script end to end in `debian:12`/`debian:13` containers
  (dry-run, real run, idempotency, nftables table, fail2ban config, SSH drop-in, rollback).
  Last local measurement: Lynis hardening index **58 → 73** in `debian:12-slim`.
- `ci/container-smoke.sh` and `ci/lynis-compare.sh` for local verification, both runnable
  with Docker or Podman (`DOCKER_BIN=podman`).
- Test suite: `tests/argument_parsing.bats` (option handling, config file parsing) and
  `tests/safety.bats` (backup bookkeeping, template rendering, rollback of modified and created
  files), 19 tests in total, running on bats 1.8 (Debian 12) and bats 1.11 (Debian 13).
- Documentation: `README.md` (English), `README.ru.md` (Russian), `SECURITY.md`.

### Fixed

- The config file is now parsed **before** the command line, so an explicit flag always wins
  over the value from the file. The file is looked up as `--config <file>` → `./safeset.conf`
  → `/etc/safeset/safeset.conf`.
- Config file booleans are normalised (`true/yes/on/1`, `false/no/off/0`); an unknown key or a
  non-boolean value aborts the run instead of silently keeping the default.
- Invalid input is rejected before the root check: a malformed `--admin-ip` (including a
  comma-separated list) or `--ssh-key` without `--create-user` now fails immediately.
- The backup and report arrays are declared as globals, so `backup_file` and `print_report`
  work when the library is sourced from inside a function.
- nftables rulesets are now replaced atomically with a `delete table` + create batch; the
  `destroy table` syntax used before does not exist in nft 1.0.6 (Debian 12) and aborted the
  firewall module.- The ruleset is validated as the exact batch that is applied, so a second run (idempotency)
  no longer fails with `EBUSY` against the already existing table.
- Operator whitelist addresses are rendered into the nftables sets instead of being added
  with a separate `nft add element` call, so they survive a reboot and a table reload.
- The safe-timer now restores the pre-change ruleset with a `flush ruleset` + re-apply batch
  instead of re-applying a listing, which did not remove the newly created table.
- `--list-modules`, `--help` and `--version` work without root; `--dry-run` no longer
  requires root.
- Container detection also works on images without `systemd-detect-virt`
  (`/run/.containerenv`, `/.dockerenv`, cgroup hints), so kernel-level hardening is skipped
  instead of failing in containers.
- AIDE initialisation uses the distro config explicitly and reports the real failure reason
  (and its full output in `/var/log/safeset/aide-init.log`) instead of a bare error.
- `aide-common` is installed alongside `aide`, so `/etc/aide/aide.conf` and `aideinit` exist.
- Dynamic nftables sets no longer carry the `counter` flag: the kernel rejects
  `dynset add` combined with a `limit` expression on such sets (`EOPNOTSUPP`).

### Known limitations

- Kernel audit, module blacklisting and mount hardening are skipped or partial in containers.
- CrowdSec and endlessh are installed from the network and are not exercised by the test
  suite.
- AIDE database creation needs `CAP_SETPCAP`/`CAP_SETFCAP` and therefore fails in restricted
  containers.
- No certification compliance is claimed.
