# Service Sandboxing & Containment — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's Remediation section remains the primary fix reference.

## systemd sandboxing

- [systemd.exec(5) — Debian manpages mirror](https://manpages.debian.org/bookworm/systemd/systemd.exec.5.en.html) - normative reference for every directive audited here (`User=`, `DynamicUser=`, `ProtectSystem=`, `SystemCallFilter=`, `CapabilityBoundingSet=`, breakage-prone interactions); used because upstream freedesktop.org man hosting blocked automated fetches this session.

## Kernel primitives

- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) - canonical semantics for every CAP_* named in add-back decisions, including why CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH are treated as near-root.
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) - kernel-level explanation of strict vs BPF-filter modes, allow-list rationale, and the no-new-privs requirement underpinning SystemCallFilter.

## Container runtime

- [Docker Engine security](https://docs.docker.com/engine/security/) - vendor statement of the four review areas, the "only trusted users should control the daemon" rule behind the docker.sock finding, and default capability dropping.

## Mandatory access control

- [SELinux userspace (GitHub)](https://github.com/SELinuxProject/selinux) - upstream project home for the policy toolchain (audit2allow workflow context); used because selinuxproject.org was unreachable during fetch verification.
- [AppArmor](https://apparmor.net/) - project documentation hub covering profiles, aa-complain/aa-enforce progression, and distribution ports backing the MAC presence/mode checks.

Nothing here replaces the in-repo evidence rules: judge effective state
(`systemd-analyze security`, `getenforce`/`aa-status`, `docker inspect`) per
SKILL.md first; these links corroborate.
