# Linux Baseline Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's Remediation section remains the primary fix reference.

## Man pages (sshd, sudo, PAM)

- [sshd_config(5) — Debian manpages](https://manpages.debian.org/bookworm/openssh-server/sshd_config.5.en.html) - authoritative directive semantics (PermitRootLogin, AuthenticationMethods, first-value-wins includes) backing the SSH judgement table.
- [sudoers(5)](https://man7.org/linux/man-pages/man5/sudoers.5.html) - normative grammar for grants, tags (NOPASSWD), Defaults, and timestamp behavior cited in the sudo-delegation checks.
- [pam.conf(5)](https://man7.org/linux/man-pages/man5/pam.conf.5.html) - how PAM stacks and control flags work, grounding the faillock/pwquality wiring discussion.

## Kernel documentation (sysctl)

- [Kernel sysctl docs: /proc/sys/kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html) - official semantics of kptr_restrict, dmesg_restrict, randomize_va_space, perf_event_paranoid, unprivileged_bpf_disabled.
- [IP sysctl docs](https://docs.kernel.org/networking/ip-sysctl.html) - vendor-grade definitions for redirects, rp_filter, syncookies, somaxconn, fin_timeout used in the network table.

## Standards & abuse references

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - the per-distro consensus baselines (Ubuntu/RHEL/Debian/etc., Level 1 vs 2 Server) that SKILL.md aligns its rubrics with.
- [GTFOBins](https://gtfobins.github.io/) - catalogued shell-escape techniques for sudo-granted interpreters/editors/archivers, the reason scoped grants matter.
- [libpwquality (GitHub)](https://github.com/libpwquality/libpwquality) - upstream home of pwquality.conf option semantics (minlen, minclass, dictcheck).
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html) - the category entry mapping this module's OWASP A05 lineage; notes why CWE prefers behavior-specific descendants.

Nothing here replaces the in-repo evidence rules: cite effective-state command
output (`sshd -T`, `sysctl -n KEY`) per SKILL.md first; these links corroborate.
