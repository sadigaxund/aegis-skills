# Host Secrets — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's expected-state table remains the primary fix reference.

## SSH & kernel boundaries (man pages)

- [sshd_config(5) — OpenBSD](https://man.openbsd.org/sshd_config) - upstream semantics for StrictModes-adjacent checks (host-key files refused when group/world-accessible), PermitRootLogin defaults, and first-value-wins includes.
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) - procfs access model (hidepid, per-pid files incl. environ pointers) grounding Demo C's `/proc/<pid>/environ` boundary claims.
- [systemd.exec(5) — Debian manpages](https://manpages.debian.org/bookworm/systemd/systemd.exec.5.en.html) - Environment=/EnvironmentFile=/UMask= semantics backing the inline-env finding and the UMask=0027 fix pattern.

## Database client credential files

- [PostgreSQL: The Password File (.pgpass)](https://www.postgresql.org/docs/current/libpq-pgpass.html) - confirms verbatim that libpq ignores .pgpass unless modes disallow group/world access — the silent-auth-fallback trap in Check 11.

## Standards, tools, and practice

- [OWASP Cheat Sheet Series: Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) - storage-class decision framework behind the secret-manager adoption checklist in Remediation 5.
- [CWE-732: Incorrect Permission Assignment](https://cwe.mitre.org/data/definitions/732.html) - the class entry mapping this module's frontmatter; explicit-modes-over-umask is its named mitigation.
- [age (GitHub)](https://github.com/FiloSottile/age) - upstream home of the wrap-before-upload tool used in backup-encryption starters.
- [SOPS (GitHub)](https://github.com/getsops/sops) - encrypted-secrets-in-repo pattern named as the small-team alternative to a full manager.

Nothing here replaces the redaction rule: evidence leaves the host as counts,
modes, and first-four-characters previews only; these links corroborate.
