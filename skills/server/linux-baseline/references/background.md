# Linux Baseline Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind accounts/sudo, sshd, PAM, sysctl, filesystem permissions, boot/disk,
and time-sync checks; SKILL.md carries the exact commands, judgement tables, and
remediation blocks.

## How this class emerged

The Linux baseline inherits its weaknesses from Unix itself. The original design
assumed a machine shared by trusted colleagues: one all-powerful `root` account,
world-readable system files, services launched by hand. Every control that exists
today — `su`, then `sudo` (written in the early 1980s for university computing),
then pluggable authentication (PAM appeared in Solaris in the mid-1990s and was
adopted by Linux-PAM) — is a patch over that assumption, layered on decades later.

Three historical waves shaped what we now audit:

- **Remote login went mainstream.** Telnet and rsh sent passwords in cleartext;
  after a documented password-sniffing incident in 1995, SSH was written to
  replace them, and the OpenSSH project (1999) made encrypted remote access free.
  But SSH also standardized something new: an *encrypted door to every account*,
  reachable from anywhere. When botnets industrialized internet-wide scanning in
  the 2000s and 2010s, port 22 with `PasswordAuthentication yes` became the most
  reliably abused door in computing — attackers simply replay username/password
  pairs harvested elsewhere until one fits.
- **The kernel grew self-protection slowly.** Address-space layout randomization
  (the `randomize_va_space` knob) reached general availability in the mid-2000s;
  restrictions on reading kernel pointers (`kptr_restrict`), blocking unprivileged
  `dmesg`, limiting `ptrace` (Yama), and disabling unprivileged BPF all landed in
  successive kernel releases through the 2010s. None of these are on-by-default
  everywhere, and older LTS kernels ship without several of them — which is why
  the sysctl section reads live values instead of trusting file text.
- **Consensus baselines were codified.** Vendor hardening guides and community
  benchmarks (most prominently the CIS Benchmarks, maintained per-distro at
  Level 1 and Level 2 Server profiles) turned scattered folklore into checklists.
  Cloud platforms complicated the picture again: convenience-driven image builds
  re-enabled password SSH (`ssh_pwauth: true`) and seeded admin accounts unless
  operators deliberately overrode them.

The recurring lesson of all three waves: **defaults are decisions someone else
made**, usually optimized for "it works on first boot," not for "it survives an
internet-connected adversary." Baseline auditing is the discipline of reviewing
those decisions one by one.

## Anatomy: one weak config, one compromised host

A minimal generic weak configuration needs only four values. Picture a small web
server built from a stock cloud image:

```
# /etc/ssh/sshd_config (effective state)
PermitRootLogin yes          # root may log in directly over the network
PasswordAuthentication yes   # ...using passwords

# /etc/sudoers.d/deploy
deploy ALL=(ALL) NOPASSWD:ALL    # the app user silently becomes root

# /etc/sysctl.conf              # nothing here: kernel defaults throughout
```

Walkthrough of how this fails:

1. Mass scanners fingerprint port 22 continuously and feed candidate
   username/password pairs into it. With password auth on and root permitted,
   the highest-value identity (`root`) accepts guesses directly.
2. One reused-or-guessed credential later, the attacker has a *root shell* —
   no local foothold, no intermediate account to lock out, no per-user trail.
3. Even when the entry point is instead a web-app bug landing as the unprivileged
   `deploy` user, the `NOPASSWD:ALL` grant means one silent `sudo -n` command
   converts it to root; the attacker drops an SSH key into `/root/.ssh/`
   authorized_keys for persistence.
4. Because the kernel runs factory defaults, the attacker's toolkit can read
   kernel pointers from `/proc/kallsyms` (defeating address randomization),
   watch other processes via unrestricted `ptrace`, and stage binaries in an
   executable `/dev/shm` — each removing friction from privilege escalation.
5. Finally, with no synchronized clock, every timestamp the defenders might
   later correlate is wrong, so the investigation starts blinded.

No exploit code appears anywhere in that chain. Each step is a *configuration
value*, which is why this class of findings is called misconfiguration rather
than vulnerability.

## Why naive fixes fail

- **Editing the wrong file.** Modern distros split sshd and sysctl configuration
  across drop-in directories (`sshd_config.d/`, `sysctl.d/`), and for sshd the
  *first value obtained wins*. A fix appended to the main file can be silently
  overridden by a lower-numbered drop-in. Always verify effective state
  (`sshd -T`, `sysctl -n KEY`).
- **Locking out before unlocking.** Setting `PasswordAuthentication no` before
  distributing and testing keys bricks remote administration. The safe order is:
  populate the allow-group, prove key login from a second terminal, validate
  syntax (`sshd -t`), then reload.
- **Blanket sysctl flips that break real roles.** Forcing `ip_forward=0` kills
  Docker/Kubernetes NAT on container hosts; strict reverse-path filtering breaks
  BGP/policy-routed multihomed machines; `unprivileged_bpf_disabled=1` silently
  kills eBPF observability agents. Role context decides the value.
- **faillock without exemptions.** Lockout policy applied to automation
  identities with rotating credentials locks the robot out on schedule.
- **chmod 777 as a repair.** Widening permissions to make an error disappear
  converts a functional bug into a world-writable artifact finding.
- **Trusting package defaults as "hardened".** Some modern defaults are already
  good (SYN cookies on, protected symlinks); others are not. Only comparing
  *live* values against the target tables separates the two.
- **Fixing the live host but not the image.** Cloud-init rebuilds revert manual
  edits; if the repo's user-data sets `ssh_pwauth: true`, the durable fix lives
  there.

## Common misconceptions

1. "`PermitRootLogin prohibit-password` is basically fine." It removes the
   password path but still gives brute force the highest-value target and skips
   per-user attribution; `no` plus a named admin group is the auditable shape.
2. "Password authentication is acceptable with a strong password." The threat is
   not one attacker guessing your one password; it is millions of bots spraying
   billions of previously leaked pairs — strength only changes the odds slightly.
3. "`NOPASSWD` just saves typing for my deploy script." Grants to interpreters,
   editors, `su`, or archivers are full-root equivalents via well-documented
   shell-escape techniques (GTFOBins catalogs them).
4. "Modern distros are secure by default, so sysctls are done." A few are; many
   information-leak and privesc-surface knobs still ship open. Verify with
   `sysctl -n`, never with assumptions.
5. "This box runs containers, so the OS baseline doesn't apply." The *host*
   holds the SSH daemon, the sudo grants, the kernel sysctls, and the SUID
   inventory; containers inherit everything you failed to constrain there.
6. "An empty password is only dangerous over the network." Any local user can
   `su` into an empty-password account with an empty string — instant identity
   theft from any foothold.
7. "Time sync is cosmetic." Every log correlation, certificate validation window,
   and forensic timeline depends on it; unsynchronized clocks blind every other
   module's evidence.

## How professionals think about it today

Modern practice reads the host as four defensive layers and maps every check to
one of them. The taxonomy below mirrors SKILL.md's own sections:

| Layer | Domain | Typical gap | Defining control |
|---|---|---|---|
| Perimeter identity | SSH daemon | root + password login exposed | key-only, explicit `AuthenticationMethods`, allow-groups |
| Local privilege boundary | Accounts, sudo, PAM | UID-0 duplicates, broad `NOPASSWD`, no lockout | unique UID-0, scoped grants, `pam_faillock`, quality/expiry |
| Containment | Sysctl, filesystem, mounts | pointer leaks, executable `/dev/shm`, planted SUID | kptr/dmesg/ptrace limits, sticky+nosuid mounts, provenance checks |
| Forensics | Time sync, core dumps, boot | unsynced clock, cores holding secrets | healthy NTP, `Storage=none`, bootloader protection |

Severity follows chains, not isolated values: a Medium gap (weak sysctls)
becomes Critical once the adjacent entry point (exposed password SSH) exists,
and amplifier findings inherit their weight from what they enable.

## Read next

In `../SKILL.md`: **Scope & Objectives** (seven domains in priority order),
**Mental Model** (entry/amplifier/outcome chain table), **What To Check**
(per-domain commands and judgement tables), **Where To Look** (artifact map and
paste-ready sweep), **Patterns & Signatures** (host-side greps and rendered
cloud-init pair), **Taint Tracing Guidance** (chain classification rules),
**Exploitation & Reproduction** (read-only proofs), **Remediation** (hardened
blocks per domain, lockout-safe ordering), **Verification & Validation**
(post-fix proof list and regression notes), **Severity Assessment** (CVSS
anchors), **Common False Positives** (cloud-init ownership, container noise).

Sibling modules: `../firewall-edge/SKILL.md` (what is reachable at all — exposure
before identity), `../service-sandboxing/SKILL.md` (deeper containment for
individual services), `../updates-patching/SKILL.md` (whether known flaws in
this baseline are fixed), `../logging-monitoring/SKILL.md` (where the evidence
this module timestamps ends up), `../tls-proxy/SKILL.md` (the public front door
in front of this host), `../api-token-security/SKILL.md` (credential hygiene for
machine identities living in these same accounts).
