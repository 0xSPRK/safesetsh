# Security Policy

## Reporting a vulnerability

Please report security issues privately, not through a public GitHub issue.

- GitHub: use **Security → Report a vulnerability** on the repository
  (https://github.com/0xSPRK/safesetsh/security/advisories/new), or
- open an issue in https://github.com/0xSPRK/safesetsh/issues if only the maintainers should
  see it and no public disclosure is needed.

Please include: the affected version, the module/option, a minimal reproduction (a dry-run
log is usually enough), and the impact you observed.

You can expect an acknowledgement within a few days. Fixes are released as a new patch
version and listed in [CHANGELOG.md](CHANGELOG.md).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## Scope

This project is a hardening script, so "vulnerabilities" mostly mean:

- the script locking an operator out of their own host,
- the script leaving the host in a weaker state than before,
- the script executing something it should not (e.g. running a config file as shell code),
- the script installing a configuration that fails to parse and breaks a service.

The following are **out of scope**:

- attacks that require administrative access to the host,
- findings from the third-party components the script installs (CrowdSec, endlessh, Lynis,
  AIDE, rkhunter) — report those to their respective projects,
- hardening gaps that the script explicitly reports as skipped or as a manual action,
- missing coverage of additional distributions (the script refuses to run on anything other
  than Debian 12/13).

## Security model of the script itself

- The script requires root and refuses to run on unsupported distributions.
- Configuration files are parsed as `KEY=VALUE` pairs only. Values are never evaluated as
  shell code.
- Third-party repositories are only used with an explicit opt-in flag (`--crowdsec`), and
  the repository key is verified against a pinned GPG fingerprint
  (`6A89E3C2303A901A889971D3376ED5326E93CD0C`).
- Configuration files are validated (`sshd -t`, `nft --check`) before they are installed, and
  a failed validation aborts the module instead of leaving a broken configuration behind.
- Every change is backed up and can be rolled back with `--rollback`.
- The firewall safe-timer restores the previous ruleset when connectivity is not confirmed.

## Hardening the host with safeset.sh

This tool changes the security posture of a machine. Before using it:

- keep a second administrative session open and have console/VNC access,
- test on a staging host first,
- review the dry-run output,
- make sure monitoring and backups are in place,
- re-run `--confirm` after each firewall change so the safe-timer does not roll back your
  ruleset.
