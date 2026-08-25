# Logging & Monitoring — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's Remediation section remains the primary fix reference.

## Kernel audit subsystem (man pages)

- [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) - normative rule syntax and the exact `-e 2` semantics ("can only be changed by rebooting") backing the immutability caveat and baseline ruleset.
- [auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html) - authoritative values for max_log_file_action, space_left/admin_space_left actions, and num_logs behind the survival-knobs tradeoffs.

## journald & rsyslog

- [journald.conf(5) — Debian manpages](https://manpages.debian.org/bookworm/systemd/journald.conf.5.en.html) - canonical Storage= auto/persistent/volatile semantics ("auto behaves like persistent if /var/log/journal exists"), SystemMaxUse defaults, ForwardToSyslog behavior.
- [rsyslog documentation (official home)](https://docs.rsyslog.com/doc/) - omfwd/omrelp/imfile module parameters and TLS-forwarding tutorials cited by Remediation F5; upstream moved docs here from www.rsyslog.com/doc in Feb 2026.

## File integrity monitoring

- [AIDE project home](https://aide.github.io/) - config-rule model, init/update/check workflow, and distro packaging for the FIM layer; confirms the 1999 origin used in the primer's history.

## Standards & practice

- [OWASP Cheat Sheet Series: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) - event-coverage checklist and what-to-log guidance mirroring SKILL.md Section 5 at application level.
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html) - the weakness class behind the frontmatter mapping; centralized logging is its named mitigation.
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - source of the per-distro L1/L2 logging-and-auditing sections the baseline watch sets derive from.

Nothing here replaces the in-repo evidence rules: cite runtime state (`journalctl --list-boots`, `auditctl -l`, db mtime) per SKILL.md first; these links corroborate.
