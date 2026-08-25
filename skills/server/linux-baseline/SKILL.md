---
name: server-linux-baseline
description: Audits Linux OS baseline hardening across accounts/sudo, sshd, PAM/password policy, kernel sysctl, filesystem permissions, boot/disk, and time sync, with exact read-only checks, hardened config blocks, and post-fix verification commands.
category_slug: BASE
cwe: [CWE-16, CWE-250, CWE-732]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit the operating-system identity and kernel baseline of one running Linux host (or its config-as-code). Seven domains, in priority order:

1. **Accounts & sudo** — UID-0 duplication, stale/unused accounts, empty passwords, sudo grant breadth, sudo brute-force throttling.
2. **SSH daemon** — effective `sshd_config` state, authentication methods, forwarding surface, key hygiene.
3. **PAM & password policy** — lockout, password quality, expiry, password hashing.
4. **Kernel & network sysctl** — anti-MITM, anti-DoS, information-disclosure and local-privesc-surface controls.
5. **Filesystem & permissions** — SUID/SGID inventory, world-writable artifacts, mount flags, cron/at gating, umask, core dumps.
6. **Boot & disk** — bootloader protection (contextual), encryption-at-rest presence, protected data mounts.
7. **Time sync** — NTP health; forensic prerequisite for every other module's evidence.

Out of scope (cross-references): firewall/exposure map → FW; TLS/proxy edge → TLS; systemd sandboxing, SELinux/AppArmor *policy authoring*, container runtime → SANDBOX; secret contents/env files → HSECRET; patch level/EOL → PATCH; audit rules/log shipping → LOGMON.

Operating rules:

- All inspection is read-only; mutating commands appear only under Remediation (Phase 6 approval). Prefer **effective-state evidence** (`sshd -T`, `sysctl -n KEY`) over config files — drop-in dirs (`sshd_config.d/`, `sysctl.d/`) make file text misleading.
- Commands needing root are tagged `[ROOT]`; without root, audit world-readable state plus the config repo. Repo-only access: judge the *rendered* config (Ansible templates, cloud-init user-data) using Patterns & Signatures. Distro variance is called out inline — never assume Ubuntu values on RHEL or Alpine; detect first (`cat /etc/os-release`).

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **privesc**: the local steps that turn a low-level account into root
- **sudo NOPASSWD:ALL**: password-free full-root command rights for an account
- **sysctl**: kernel tunables closing redirection and information-leak paths
- **SUID binary**: a program that runs as its file's owner (often root) no matter who starts it
- **sticky bit / noexec mount**: shared-directory protections against planted trojans
- **ptrace_scope**: kernel restriction on one process debugging another user's processes
- **PAM**: the pluggable login-policy layer (lockouts, password quality, expiry)
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function

## Mental Model

Attackers do not attack "the baseline" — they chain specific gaps into a path:

```
Entry point            Amplifier (this module)              Realized outcome
---------------------  -----------------------------------  --------------------------------
internet SSH :22   ──▶ PasswordAuthentication yes +       ▶ online credential stuffing →
                       PermitRootLogin yes                  direct root, no per-user trail
app RCE as svc acct ▶ sudo NOPASSWD:ALL                   ▶ instant takeover + root persistence
on-path attacker    ─▶ accept_redirects=1 /               ▶ route hijack, traffic interception,
                       accept_source_route=1                plaintext credential theft
local low-priv user ─▶ kptr_restrict=0, dmesg open,       ▶ KASLR defeated → reliable kernel-
                       ptrace_scope=0, userns open          exploit privesc to root
any foothold        ─▶ world-writable dir without sticky  ▶ planted SUID trojan = persistent
                       + executable /dev/shm                local root, evades noexec /tmp
post-exploit        ─▶ NTP unsynchronized, coredumps on   ▶ forensics blinded, secrets in cores
```

Four defensive layers map onto the check sections:

| Layer | Sections | Question it answers |
|---|---|---|
| Perimeter identity | sshd | Can an outsider become a local identity? |
| Local privilege boundary | accounts, sudo, PAM, SUID | Can that identity become root? |
| Containment | sysctl, mounts, namespaces | How much damage can a non-root foothold do? |
| Forensics | time sync, core dumps | Can we reconstruct what happened? |

Classify every finding by layer and by what it chains with — a Medium gap becomes Critical once an adjacent entry point exists (see Taint Tracing Guidance).

## What To Check

### 1. Accounts and UID-0 Inventory

Run and verify exactly one result: `root` with a legitimate shell. A second UID-0 account (`toor`, `backup`, `svc-root`) is a Critical backdoor indicator:

```bash
awk -F: '$3==0{printf "%s uid=%d shell=%s\n",$1,$3,$7}' /etc/passwd
awk -F: '($3!=0 && $4==0){print "gid0:",$1}' /etc/passwd
```

Inventory every interactive-capable account and confirm each against the asset owner's list; check lock state `[ROOT]` (field 2 of `passwd -S`: `L` locked, `P` hash set, `NP` empty password). Flag unlocked accounts unused >90 days, service accounts owning shells, and `.ssh/authorized_keys` nobody claims (cross-check HSECRET):

```bash
awk -F: '$7!~/(nologin|false|sync)$/{print $1"\tuid="$3"\thome="$6"\tshell="$7}' /etc/passwd
for u in $(cut -d: -f1 /etc/passwd); do passwd -S "$u"; done; lastlog -b 90
```

Empty-password check `[ROOT]` — any hit is a direct-login finding (locked hashes look like `!`, `!!`, `!*`; that is the *good* state):

```bash
awk -F: '($2==""){print $1" EMPTY-PASSWORD"}' /etc/shadow
```

### 2. Sudo Delegation

Validate parse integrity first, then enumerate grants and judge breadth:

```bash
visudo -c                                   # syntax errors = finding by themselves
grep -RnsE '^[^#]*(NOPASSWD|[[:space:]]ALL=\(ALL' /etc/sudoers /etc/sudoers.d/
grep -RnsE '\(ALL(:\s*ALL)?\)\s+NOPASSWD:\s+(ALL|/bin/su|/bin/bash|/bin/sh|/usr/bin/(find|python[0-9]*|perl|ruby|php|vi[m]?|less|more|tar|zip|chmod|chown))' /etc/sudoers.d/
sudo -l                                     # as your audit identity
```

Flag: `NOPASSWD: ALL` for a network-facing service account; grants to `su`, editors, interpreters, archivers (GTFOBins abuse — https://gtfobins.github.io). Accept as scoped: `NOPASSWD: /usr/bin/systemctl restart myapp.service`.

Throttle knobs (password prompts route through PAM, so faillock covers sudo once Section 4 is configured):

```bash
grep -RhE '^\s*Defaults\s' /etc/sudoers /etc/sudoers.d/ | grep -E 'timestamp_timeout|passwd_tries|use_pty'
```

Target values: `Defaults timestamp_timeout=15, passwd_tries=3, use_pty` (`use_pty` needs sudo ≥1.9).

### 3. SSH Daemon Effective Configuration

Effective state wins over file text; `Include /etc/ssh/sshd_config.d/*.conf` is processed where it appears and **the first value obtained for a keyword wins**, so an early-numbered drop-in silently overrides later main-file lines. Run `[ROOT]`:

```bash
sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|kbdinteractiveauthentication|maxauthtries|logingracetime|permitemptypasswords|clientaliveinterval|clientalivecountmax|x11forwarding|allowagentforwarding|allowtcpforwarding|allowusers|allowgroups|banner)'
```

Without root, fall back to the sweep's file-text grep (drop-ins can contradict it — say so in evidence).

Judgement table (risky column = value to flag):

| sshd_config key | Risky value | Hardened value | Why |
|---|---|---|---|
| `PermitRootLogin` | `yes`; `prohibit-password` on hosts lacking key discipline | `no` | root logins skip per-user audit and give brute force the highest-value target |
| `PasswordAuthentication` | `yes` | `no` | enables online password guessing; keys are not sprayable |
| `KbdInteractiveAuthentication` | `yes` (alias `ChallengeResponseAuthentication`, deprecated name) | `no` | second password-ish path bypassing key-only intent |
| `PubkeyAuthentication` | absent (default yes) or `no` | `yes` explicit | assert the intended mechanism |
| `AuthenticationMethods` | unset (= any single method) | `publickey` | forces key-only even if other methods reappear |
| `MaxAuthTries` | `6` default or higher | `3` | caps guessing per connection |
| `LoginGraceTime` | `120` (default) | `30` | halves window for pre-auth resource abuse |
| `PermitEmptyPasswords` | `yes` (never leave) | `no` | pairs with shadow check in §1 |
| `X11Forwarding` | `yes` (Debian default!) | `no` | forwards X authority; server has no business running X clients remotely |
| `AllowAgentForwarding` | `yes` | `no` | agent socket forwarding lets a compromised jump host reuse operator keys |
| `AllowTcpForwarding` | `yes` | `no` or `local` if tunnels required | turns any SSH account into an internal-network pivot |
| `ClientAliveInterval`/`CountMax` | `0` (never probes) | `300` / `3` | reaps dead sessions; do not confuse with `TCPKeepAlive` |
| `AllowUsers`/`AllowGroups` | unset (any valid account logs in) | explicit group e.g. `AllowGroups ssh-users` | shrinks auth surface to named identities |
| `Banner` | absent | `/etc/issue.net` | legal deterrent only — Low severity |

Protocol note: no `Protocol` directive is needed — OpenSSH ≥7.6 speaks SSH-2 only; encountering `Protocol 2` is harmless legacy, not a finding.

**Key hygiene.** Enumerate and grade keys:

```bash
find /root /home -name authorized_keys -exec sh -c 'echo "--- {}"; awk "{print \$1\" \"\$3}" "{}"' \;
for k in /root/.ssh/*.pub /home/*/.ssh/*.pub; do [ -f "$k" ] && ssh-keygen -lf "$k"; done
```

Rules: prefer ed25519 (`ssh-ed25519`); RSA only at ≥3072 bits (size shown by `ssh-keygen -lf`) — flag smaller and any `ssh-dss`; passphrase-protect interactive-use private keys (client-side read-only check: `ssh-keygen -y -P "" -f ID_FILE` printing output = unencrypted). Automation keys must carry restrictions instead of passphrases they cannot type:

```
restrict,command="/usr/local/bin/deploy-sync",from="10.0.20.0/24" ssh-ed25519 AAAA... ci-runner
```

authorized_keys(5) option set: `restrict`, `command="..."`, `from="pattern"`, `no-port-forwarding`, `no-agent-forwarding`, `no-x11-forwarding`, `no-pty`, `expiry-time="YYYYMMDDHHMM"` (OpenSSH ≥7.7). Flag bare unrestricted keys used by CI/automation.

known_hosts trust: prefer hashed entries (`HashKnownHosts yes`). Treat unexpected host-key mismatch as potential MITM — never advise deleting the line without out-of-band fingerprint verification. In repos, flag `-oStrictHostKeyChecking=no` (and blind `accept-new`) against production hosts: trust-on-first-use over an unauthenticated network is standing interception risk.

### 4. PAM Lockout, Password Quality, Expiry, Hashing

Locate the active stack first — names differ by distro (Debian/Ubuntu: `common-auth`/`common-password` includes; RHEL/Rocky: `system-auth`/`password-auth` via authselect; Alpine: minimal per-service files):

```bash
ls /etc/pam.d/; authselect current 2>/dev/null
grep -RsE 'pam_faillock|pam_tally2' /etc/pam.d/
grep -E '^\s*(deny|unlock_time|even_deny_root|users)\s*=' /etc/security/faillock.conf 2>/dev/null
```

Prefer `pam_faillock` — `pam_tally2` was removed from RHEL 8+ and Debian 11+; seeing tally2 means old stack, migrate. Target: faillock present in both `preauth` and `authfail` phases, `deny = 5`, `unlock_time = 900`. Root is exempt unless `even_deny_root`; exempt fragile automation identities explicitly via `users =`. Alpine's BusyBox login often ships neither pam_faillock nor pam_pwquality — report control *absence*, do not pretend a config value exists.

Quality and expiry:

```bash
grep -Ev '^\s*(#|$)' /etc/security/pwquality.conf
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD|UMASK)' /etc/login.defs
chage -l SOMEHUMANUSER
```

Targets: `minlen >= 14` plus `minclass = 3` (or three of dcredit/ucredit/lcredit/ocredit negative); `PASS_MAX_DAYS <= 365`, `PASS_MIN_DAYS >= 1`, `PASS_WARN_AGE >= 7` for human accounts (system/service accounts exempt — record exceptions). `login.defs` defaults apply to *new* accounts only; remediate existing users with `chage`. Hashing: accept `SHA512` or `YESCRYPT` (YESCRYPT is default on Debian 12, RHEL 9, Ubuntu 22.04; SHA512 on older) — flag `MD5`/`DES`.

Distro honesty: Alpine's minimal BusyBox login often ships neither pam_faillock nor pam_pwquality; installing them changes the audit target from "value wrong" to "control absent" — report absence, do not pretend a config value exists.

### 5. Kernel and Network Sysctl

Always read live values; file presence proves nothing:

```bash
sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled \
       kernel.randomize_va_space kernel.yama.ptrace_scope kernel.perf_event_paranoid \
       fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular fs.suid_dumpable
sysctl net.ipv4.ip_forward net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.tcp_syncookies \
       net.ipv4.tcp_max_syn_backlog net.core.somaxconn net.ipv4.tcp_fin_timeout
sysctl -a 2>/dev/null | grep -E '(accept_redirects|send_redirects|accept_source_route|rp_filter|log_martians)'
```

Network table:

| Sysctl key | Risky value | Hardened value | Why |
|---|---|---|---|
| `net.ipv4.ip_forward` | `1` on non-router | `0` — context-dependent | routers/NAT/Docker/K8s nodes legitimately need 1; verify role before flagging |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `0` | `1` (modern default) | smurf-amplification refusal |
| `net.ipv4.conf.{all,default}.accept_redirects` | `1` | `0` | ICMP redirect route injection |
| `net.ipv6.conf.{all,default}.accept_redirects` | `1` | `0` | same, IPv6 |
| `net.ipv4.conf.{all,default}.send_redirects` | `1` on non-router | `0` | stops host acting as redirect source |
| `net.{ipv4,ipv6}.conf.{all,default}.accept_source_route` | `1` | `0` | obsolete source-routed packets are pure attack surface |
| `net.ipv4.conf.{all,default}.rp_filter` | `0`/`2` | `1` strict — caveat multi-homed | drops spoofed-source packets; breaks asymmetric routing (BGP/policy-routed hosts) — document exception |
| `net.ipv4.tcp_syncookies` | `0` | `1` (default) | SYN-flood survival |
| `net.ipv4.tcp_max_syn_backlog` | `128` legacy default | `>= 1024` | absorbs SYN bursts (cross-ref DOS) |
| `net.core.somaxconn` | `128` legacy default | `>= 1024` | listen backlog ceiling for apps |
| `net.ipv4.tcp_fin_timeout` | `60` default | `<= 30` | faster orphaned-FIN reclaim |
| `net.ipv4.conf.{all,default}.log_martians` | `0` | `1` | logs spoofed/martian packets for FW correlation |

`conf.all` vs `conf.default` trap: for `accept_redirects`, per-interface values govern behavior (`all` is an aggregate guard) while `default` applies only to interfaces created *after* being set — verify one live NIC too: `sysctl net.ipv4.conf.eth0.accept_redirects`. Namespace honesty: `kernel.unprivileged_userns_clone` exists **only** on Debian/Ubuntu-patched kernels; mainline exposes `user.max_user_namespaces` instead. Restricting unprivileged userns hardens kernel surface but breaks rootless podman/toolbox/sandboxed browsers — role-dependent decision, never a silent default fix.

Kernel/self-protection table:

| Sysctl key | Risky value | Hardened value | Why |
|---|---|---|---|
| `kernel.kptr_restrict` | `0` | `2` | hides kernel pointers from unprivileged readers (defeats KASLR-leak privesc); `1` = restricted-to-CAP_SYSLOG middle ground |
| `kernel.dmesg_restrict` | `0` | `1` | blocks unprivileged dmesg (leaks addresses, module info) |
| `kernel.unprivileged_bpf_disabled` | `0` | `1` (permanent variant `2` on kernels ≥5.16) | unprivileged BPF is a recurring exploit primitive; breaks eBPF observability agents — coordinate |
| `fs.protected_symlinks` / `_hardlinks` | `0` | `1` | blocks sticky-dir symlink/hardlink attacks on /tmp-class dirs |
| `fs.protected_fifos` / `_regular` | `0` | `1` (`2` stricter) | blocks FIFO/regular-file creation races in world-writable sticky dirs |
| `kernel.randomize_va_space` | `0`/`1` | `2` | full ASLR incl. heap/stack/libraries |
| `kernel.yama.ptrace_scope` | `0` | `>= 1` (`2` typical server target) | stops arbitrary process injection/credential scraping via ptrace |
| `kernel.perf_event_paranoid` | `< 2` | `2` (`3` = fully disable user perf_event_open) | perf-based side-channel and address-leak surface |

### 6. Filesystem and Permissions

SUID/SGID inventory. Drop `-xdev` (or iterate mountpoints) when `/usr` or `/var` are separate filesystems:

```bash
find / -xdev \( -type f -o -type d \) \( -perm -4000 -o -perm -2000 \) -printf '%m %u:%g %p\n' 2>/dev/null | sort -k3
getcap -r / 2>/dev/null | grep -v '^/proc'
```

Expected-vs-unexpected judgement table:

| Path | Normal on | Action if missing/unexpected |
|---|---|---|
| `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/passwd`, `/usr/bin/chage`, `/usr/bin/gpasswd`, `/usr/bin/chsh`, `/usr/bin/chfn`, `/usr/bin/newgrp` | all distros | expected suid root |
| `/usr/bin/mount`, `/usr/bin/umount` | util-linux installs (often cap-based now) | expected; absence fine on modern |
| `/usr/bin/pkexec`, `/usr/bin/fusermount3` | desktop/systemd distros | unexpected on headless servers → investigate |
| `/usr/bin/crontab` | sgid `crontab` (Debian) / suid root (RHEL) | mode varies — compare to package DB |
| `/usr/lib/openssh/ssh-keysign`, `/sbin/unix_chkpwd` | OpenSSH/util-linux helpers | expected suid root |
| anything under `/home`, `/tmp`, `/var/tmp`, `/usr/local` | never expected | planted binary — treat as incident (see Exploitation §3) |

Verify provenance of every entry outside the table: `dpkg -S FILE` (Debian) / `rpm -qf FILE` (RHEL); "not owned by any package" = immediate escalation. Modern distros move capabilities instead of SUID (`getent` ping uses `cap_net_raw`) — `getcap` hits like `cap_setuid` deserve the same scrutiny as SUID.

World-writable artifacts and ownership gaps:

```bash
find / -xdev -type d -perm -0002 ! -perm -1000 -print      # writable dirs MISSING sticky bit
find / -xdev -type f -perm -0002 -print                    # any hit is a finding
find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -20
stat -c '%a %n' /tmp /var/tmp /dev/shm                     # expect 1777 (sticky)
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /dev/shm /tmp /var/tmp 2>/dev/null
```

Require `/dev/shm` mounted `nosuid,nodev,noexec` (and dedicated `/tmp`, `/var/tmp` partitions likewise). Single-partition cloud hosts: document residual risk; at minimum persist hardened `/dev/shm` options in fstab.

cron/at gating (allow-list model preferred), umask, homes, core dumps:

```bash
ls -l /etc/cron.allow /etc/at.allow 2>/dev/null || echo "ALLOW-LISTS-MISSING"
stat -c '%a %U:%G %n' /etc/crontab /etc/cron.d /etc/cron.daily 2>/dev/null
ls -la /var/spool/cron /var/spool/cron/atjobs 2>/dev/null   # Debian paths; RHEL: /var/spool/at
grep -E '^\s*UMASK' /etc/login.defs
grep -RhsE '^\s*umask\s+00[02]\b' /etc/profile /etc/bash.bashrc /etc/profile.d/ 2>/dev/null
stat -c '%a %U:%G %n' /home/* 2>/dev/null                   # expect <= 750 each
grep -RhE '^\s*\*\s+hard\s+core\b' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null
grep -E '^\s*(Storage|ProcessSizeMax)' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf 2>/dev/null
ulimit -c                                                   # expect 0 in a login shell
```

Flag when neither allow nor deny files exist (everyone may schedule), when deny-only model is used, or when cron dirs are group/world-writable. Targets: `UMASK 027` (077 high-sensitivity); home dirs without group/world write (and without world read on sensitive boxes); `* hard core 0`; coredump.conf `Storage=none` plus `ProcessSizeMax=0`; `fs.suid_dumpable=0` (Section 5 table block).

### 7. Boot and Disk

GRUB password is contextual: required when console/KVM/cloud-serial access is reachable; fleet behind tight IAM may carry a documented exception. LUKS absence on hosts holding regulated data is an architectural gap (severity scales with data classification; remediation is rebuild/migration, not inline change). fstab protection applies `nodev,nosuid` (+`noexec` where nothing executes) to dedicated data/removable mounts — never demand them on `/` or `/usr`.

```bash
grep -l password_pbkdf2 /boot/grub/grub.cfg /boot/grub2/grub.cfg 2>/dev/null   # GRUB pw present?
stat -c '%a %U:%G %n' /boot/grub*/grub.cfg /boot/grub2/user.cfg 2>/dev/null
lsblk -o NAME,FSTYPE,MOUNTPOINT | grep -i crypto_luks || echo "NO-LUKS-VISIBLE"
cat /etc/crypttab 2>/dev/null
awk '$3!~/^(swap|proc|sysfs|devpts|tmpfs|overlay|iso9660)$/ {print $1,$2,$3,"opts="$4}' /etc/fstab
findmnt -no TARGET,PARTLABEL,OPTIONS -t ext4,xfs,btrfs,vfat,exfat,ntfs3
```

### 8. Time Synchronization

```bash
timedatectl show -p NTPSynchronized -p NTP -p TimeUSec
systemctl is-active chronyd chrony systemd-timesyncd ntpd 2>/dev/null
chronyc sources 2>/dev/null || ntpq -p 2>/dev/null
grep -RhE '^(server|pool|NTP=|FallbackNTP)' /etc/chrony/chrony.conf /etc/chrony.conf \
      /etc/systemd/timesyncd.conf /etc/ntp.conf 2>/dev/null
```

Flag: no active sync daemon, `NTPSynchronized=no`, sources pointing at unroutable or vendor-example default addresses. Every timestamp in every other module's evidence depends on this — unsynchronized clocks make LOGMON correlation unreliable and break TLS/Kerberos time-sensitive flows.

## Where To Look

Evidence collection: `tools/sweeps/sweep-baseline.sh` captures `[BASE-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone. The paste-ready sweep below covers the same ground for interactive use.

Paste-ready audit sweep — highest-yield checks, strictly read-only, safe on production; `[ROOT]` lines need root, everything else works unprivileged:

```bash
#!/usr/bin/env bash
# Baseline sweep — READ-ONLY. [ROOT] lines need root.
echo "== OS =="; head -2 /etc/os-release; uname -r
echo "== UID-0 accounts (expect only root) =="; awk -F: '$3==0{print $1,$7}' /etc/passwd
echo "== interactive accounts =="; awk -F: '$7!~/(nologin|false|sync)$/{print $1":"$3":"$7}' /etc/passwd
echo "== empty passwords [ROOT] =="; awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || echo "need-root"
echo "== NOPASSWD sudo =="; grep -RsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo none
echo "== sshd effective [ROOT] =="; sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|maxauthtries|x11forwarding|allowtcpforwarding|allowagentforwarding|permitemptypasswords)' || grep -RhE '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthenticationMethods|MaxAuthTries|PermitEmptyPasswords|X11Forwarding|AllowTcpForwarding|AllowAgentForwarding|LoginGraceTime)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
echo "== PAM/policy =="; grep -E '^\s*(deny|unlock_time)\s*=' /etc/security/faillock.conf 2>/dev/null; grep -RsE 'pam_(faillock|tally2)' /etc/pam.d/ 2>/dev/null | head -3; grep -E '^\s*(minlen|minclass)\s*=' /etc/security/pwquality.conf 2>/dev/null; grep -E '^(PASS_MAX_DAYS|ENCRYPT_METHOD|UMASK)' /etc/login.defs
echo "== sysctls =="; sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled fs.protected_symlinks fs.protected_hardlinks fs.suid_dumpable net.ipv4.ip_forward net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv4.conf.all.send_redirects 2>&1
echo "== SUID =="; find / -xdev -type f -perm -4000 2>/dev/null
echo "== world-writable dirs w/o sticky =="; find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null
echo "== world-writable files =="; find / -xdev -type f -perm -0002 -print 2>/dev/null
echo "== tmp modes (expect 1777) =="; stat -c '%a %n' /tmp /var/tmp /dev/shm 2>/dev/null
echo "== /dev/shm opts (want nosuid,nodev,noexec) =="; findmnt -no OPTIONS /dev/shm 2>/dev/null
echo "== cron/at allow-lists =="; ls -l /etc/cron.allow /etc/at.allow 2>/dev/null || echo missing
echo "== coredumps =="; ulimit -c; grep -hE '^\s*\*\s+hard\s+core' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; grep -hE '^\s*(Storage|ProcessSizeMax)' /etc/systemd/coredump.conf 2>/dev/null
echo "== time sync =="; timedatectl show -p NTPSynchronized -p NTP 2>/dev/null || systemctl is-active systemd-timesyncd chronyd 2>/dev/null
```

Artifact map:

| Evidence | Primary path(s) | Live command |
|---|---|---|
| Accounts/groups | `/etc/passwd`, `/etc/shadow` `[ROOT]`, `/etc/group` | `awk -F:` filters above |
| sudo | `/etc/sudoers`, `/etc/sudoers.d/*` (mode 0440) | `visudo -c`, `sudo -l` |
| sshd config | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*.conf` | `sshd -T` `[ROOT]` (needs root for host keys; fallback = file text, but say so — drop-ins can contradict it) |
| Authorized keys | `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys` | `find ... -name authorized_keys` |
| PAM + policy files | `/etc/pam.d/common-*` (Deb), `/etc/pam.d/{system,password}-auth` (RHEL); `/etc/security/faillock.conf`, `/etc/security/pwquality.conf`, `/etc/login.defs`, `/etc/security/limits.conf(.d/)` | `grep -Rs pam_faillock /etc/pam.d/`, `grep deny /etc/security/faillock.conf` |
| sysctl runtime vs files | kernel state; `/etc/sysctl.conf`, `/etc/sysctl.d/*`, `/usr/lib/sysctl.d/*` (last-applied wins — trust `sysctl -n KEY`, not file text) | `sysctl KEY`; diff files vs live values |
| Mounts/crypto | `/etc/fstab`, `/proc/mounts`, `/etc/crypttab` | `findmnt`, `lsblk -o NAME,FSTYPE` |
| cron/at | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{allow,deny}`, `/etc/at.{allow,deny}` | `ls -l` |
| Core dumps / time sync / boot | `/etc/systemd/coredump.conf(.d/)`, `/etc/chrony/chrony.conf` (Deb) or `/etc/chrony.conf` (RHEL), `/etc/systemd/timesyncd.conf`, `/boot/grub/grub.cfg` or `/boot/grub2/grub.cfg` | `coredumpctl list`, `timedatectl`, `chronyc sources`, `grep password_pbkdf2` |

## Patterns & Signatures

Host-side signature greps — each should return **zero hits** on a hardened host; every hit is candidate evidence:

```bash
grep -RnsE '^\s*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)\s+yes' /etc/ssh/ 2>/dev/null
grep -RnsE '^\s*X11Forwarding\s+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
grep -RnsE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null        # judge scope per What To Check §2
grep -RnsE '^\s*umask\s+(000|002)\b' /etc/profile /etc/bash.bashrc /etc/profile.d/ 2>/dev/null
grep -RnsE '(accept_redirects|send_redirects|accept_source_route)\s*=\s*1|(randomize_va_space|yama\.ptrace_scope|kptr_restrict|dmesg_restrict)\s*=\s*0' /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null
grep -RnsE '^ENCRYPT_METHOD\s+(MD5|DES)' /etc/login.defs
```

Config-as-code sweeps (repo root; covers Ansible, cloud-init, Terraform, Dockerfile, Packer; requires ripgrep):

```bash
rg -n --hidden -g '!.git/' \
   -e '(PermitRootLogin|PasswordAuthentication):\s*(yes|"yes")' \
   -e '(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)\s+yes' \
   -e 'NOPASSWD:\s*(ALL\b|/bin/su|/bin/bash|/bin/sh)' \
   -e '/usr/bin/(find|python[0-9.]*|perl|ruby|php|vi[m]?|less|tar)\b.*NOPASSWD'
rg -n --hidden -g '!.git/' \
   -e 'chmod\s+(-R\s+)?(777|666)\b' \
   -e 'umask\s+(000|002)\b' \
   -e 'mode:\s*0?777\b'
rg -n --hidden -g '!.git/' \
   -e 'lock_passwd:\s*[Ff]alse' \
   -e 'plain_text_passwd' \
   -e 'ssh_pwauth:\s*true' \
   -e 'StrictHostKeyChecking=\s*no'
rg -n --hidden -g '!.git/' \
   -e 'net\.(ipv4|ipv6)\.conf\.(all|default)\.(accept_redirects|send_redirects|accept_source_route)\s*=\s*1' \
   -e 'kernel\.(randomize_va_space|yama\.ptrace_scope|kptr_restrict)\s*=\s*0' \
   -e '^ENCRYPT_METHOD\s+MD5'
rg -ln --hidden -g '!.git/' -e '/var/run/docker\.sock'    # chains into SANDBOX module
```

Rendered-example pair (cloud-init user-data), showing the vulnerable and fixed shapes side by side:

```yaml
# VULNERABLE — cloud-init user-data
users:
  - { name: deploy, lock_passwd: false }
ssh_pwauth: true                # PasswordAuthentication yes for the whole host
```

```yaml
# FIXED — key-only from first boot; no password path exists
users:
  - { name: deploy, lock_passwd: true, ssh_authorized_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... deploy@ci"] }
ssh_pwauth: false               # renders as PasswordAuthentication no
```

## Taint Tracing Guidance

Classify each finding as **entry**, **amplifier**, or **containment-loss**; then report chains, not isolated values. Chain table (taint origin → combines-with → attack path → ceiling severity):

| # | Origin misconfig | Chains with | Attack path | Ceiling |
|---|---|---|---|---|
| 1 | `PermitRootLogin yes` + `PasswordAuthentication yes` on :22 internet-exposed | absent faillock/fail2ban | botnet credential spray reaches root directly; no intermediate identity to lock out | Critical 9.8 |
| 2 | Broad `NOPASSWD: ALL` for web/service user | app-layer RCE (any module) | svc shell → silent root → authorized_keys persistence in `/root/.ssh`, cron implants | High 8.8 |
| 3 | `AllowAgentForwarding yes` on jump hosts | operator habit of agent reuse | compromised jump steals forwarded agent socket → lateral movement with operator's keys | High |
| 4 | `AcceptRedirects=1` (v4/v6) | attacker on-path (rogue AP/hostile LAN) | forged ICMP redirect rewrites routes → interception of plaintext protocols | Medium–High by position |
| 5 | `kptr_restrict=0` + `dmesg_restrict=0` + `ptrace_scope=0` (+ open userns) | any local foothold; public kernel exploit | KASLR leak + process injection converts unreliable bug into deterministic privesc | amplifier to Critical |
| 6 | World-writable dir w/o sticky + planted SUID | any foothold | drop SUID shell in writable PATH dir → persistent local root | High 7.7 |
| 7 | Executable `/dev/shm` | app file-write primitive | stage ELF outside hardened `/tmp`; memory-resident malware | amplifier |
| 8 | Empty-password account | any local shell access | `su ACCOUNT` with empty string = instant identity theft | High 7.9 |
| 9 | No cron/at allow-list | low-priv foothold | schedule persistence tasks without admin visibility | Low–Medium |
| 10 | NTP unsynchronized | every other module | timestamps untrustworthy → detection gaps, replay-window failures, forensic ambiguity | force multiplier |

Guidance rules:

- Position beats absolute value: identical `PasswordAuthentication yes` is Medium behind a VPN allowlist, Critical on an edge host — pull the socket map (`ss -tlnp | grep ':22'`) and FW module output before assigning. Count the chain, not the finding: rows 1, 2, 6 together mean one web-app bug yields full host compromise with persistence — say so in SUMMARY.md chains (Phase 4).
- Amplifier findings (rows 4, 5, 7) get severity from what they enable, not their own CVSS base; annotate "enabler" rather than inflating standalone scores.

## Exploitation & Reproduction

Reproductions are READ-ONLY commands demonstrating weak state; attacker paths are described, not scripted. Attach actual output to each finding.

**1. Internet-exposed root password login (Critical).**

```bash
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication)'
# permitrootlogin yes
# passwordauthentication yes
ss -tlnp | grep ':22 '        # 0.0.0.0/[::] binding = internet-reachable (confirm with FW module)
```

Attacker path: mass scanners fingerprint :22 continuously; botnets spray breached credential pairs against `root` — one hit yields a root shell with no local foothold and no per-user trail.

**2. Service-account sudo takeover (High).**

```bash
sudo -u www-data sudo -n -l    # or run as the service account
# User www-data may run the following commands: (ALL) NOPASSWD: ALL
```

Attacker path: web-app RCE lands as `www-data`; `sudo -n` succeeds silently; attacker spawns a root shell and drops an SSH key into `/root/.ssh/authorized_keys` for persistence.

**3. Planted SUID binary (High).**

```bash
find / -xdev -type f -perm -4000 -printf '%m %u:%g %TY-%Tm-%Td %p\n' 2>/dev/null | sort -k4
dpkg -S /usr/local/bin/backup-runner 2>&1    # 'no path found' = not from any package; expect -rwsr-xr-x root root
```

Attacker path: any local user executes the planted binary → EUID 0. `/usr/local` plus absent package provenance is the tell — treat as active compromise (quarantine mode-bit, preserve evidence).

**4. ICMP redirect acceptance, pointer leaks, executable shm (Medium amplifiers).**

```bash
sysctl net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects   # = 1 both
dmesg | tail -5                                # works unprivileged when dmesg_restrict=0
grep -m3 ' [tT] ' /proc/kallsyms               # resolved addresses when kptr_restrict=0
cat /proc/sys/kernel/randomize_va_space        # 0 or 1 = weakened ASLR
findmnt -no OPTIONS /dev/shm                   # lacks noexec,nosuid,nodev
```

Attacker paths: a rogue segment host sends an ICMP redirect announcing a "better" route through itself — the host installs it and connections traverse the attacker. Readable dmesg/kallsyms defeat KASLR first, converting crash-prone public kernel exploits into one-shot privesc. With any app-level file-write primitive, an ELF staged in executable `/dev/shm` runs while sidestepping hardened `/tmp`.

**5. Empty-password identity theft (High).**

```bash
sudo awk -F: '($2==""){print $1}' /etc/shadow
# backupsvc
su - backupsvc      # empty string at prompt succeeds for any local user
```

Attacker path: every local account holder instantly becomes `backupsvc` — inheriting its cron jobs, service credentials, group memberships.

## Remediation

All commands in this section are **mutating**: Phase 6 only, after approval, with rollback notes. Lockout-risk operations carry inline warnings — honor them.

### sshd hardening

```
# FIXED — /etc/ssh/sshd_config.d/99-hardening.conf
# Check no lower-numbered drop-in re-enables these; first value obtained wins.
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
AuthenticationMethods publickey
MaxAuthTries 3
LoginGraceTime 30
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no            # use 'local' only if tunnels are a stated requirement
ClientAliveInterval 300
ClientAliveCountMax 3
AllowGroups ssh-users            # populate BEFORE reload
```

Apply protocol (order matters): populate `ssh-users` and verify membership (`id`) → confirm key login from a second terminal (`ssh -i ~/.ssh/id_ed25519 host true`) → `sshd -t` → `systemctl reload sshd` (reload keeps established sessions; never restart from a session you cannot afford to lose). Confirm console/out-of-band access exists before touching sshd on any remote host.

### Accounts and sudo

```bash
usermod -L BACKDOOR_ACCT && usermod -s /usr/sbin/nologin BACKDOOR_ACCT   # duplicate UID-0: also alert/incident
passwd -l STALE_ACCT                                                     # lock unused accounts
chage -E 1 STALE_ACCT                                                    # dated retirement alternative
passwd SERVICE_ACCT                                                      # replace empty password; prefer locking + key access
chage -m 1 -M 365 -W 7 HUMAN_USER                                        # apply expiry policy to existing users
```

```
# FIXED — /etc/sudoers.d/010-hardening  (0440 root:root; edit ONLY via visudo -f)
Defaults timestamp_timeout=15
Defaults passwd_tries=3
Defaults use_pty
%sysadmins ALL=(ALL:ALL) ALL
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart myapp.service
```

Remove offending grant lines from their original files rather than layering overrides; validate with `visudo -c` before ending your session.

### PAM and password policy

```
# FIXED — /etc/security/faillock.conf
deny = 5
unlock_time = 900
# users = svc-backup           # explicit exemptions for automation identities only
# Wire-up: Debian/Ubuntu add pam_faillock.so preauth/authfail to /etc/pam.d/common-auth;
# RHEL/Rocky: authselect enable-feature with-faillock && authselect apply-changes
```

```
# FIXED — /etc/security/pwquality.conf
minlen = 14
minclass = 3
dictcheck = 1

# FIXED — /etc/login.defs (new-account defaults)
PASS_MAX_DAYS   365
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
UMASK           027
ENCRYPT_METHOD  SHA512      # keep distro default YESCRYPT where present — do not downgrade
```

### sysctl

```
# FIXED — /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0                    # DELETE this line on routers/NAT/container hosts
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.core.somaxconn = 1024
net.ipv4.tcp_fin_timeout = 30
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1       # coordinate with eBPF observability owners first
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1               # 2 where no dev/debug workflows exist
kernel.perf_event_paranoid = 2             # 3 to disable user perf_event_open entirely
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
fs.suid_dumpable = 0
```

Apply with `sysctl --system`, then sweep per-interface leftovers that predate the default settings:

```bash
for i in $(ls /sys/class/net | grep -v lo); do
  sysctl -w "net.ipv4.conf.$i.accept_redirects=0"
  sysctl -w "net.ipv4.conf.$i.send_redirects=0"
done
```

### Filesystem, mounts, cron/at, core dumps

```bash
chmod o-w /path/from/world-writable-scan      # each world-writable FILE
chmod +t /var/tmp                              # restore missing sticky
chmod u-s /usr/local/bin/SUSPECT_BINARY        # quarantine planted SUID — do NOT delete evidence
touch /etc/cron.allow /etc/at.allow && chmod 600 /etc/cron.allow /etc/at.allow && chown root:root /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny              # switch deny-model -> allow-model (populate allow files FIRST)
```

```
# FIXED — /etc/fstab line (then: mount -o remount /dev/shm && findmnt /dev/shm)
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,mode=1777 0 0
```

```
# FIXED — /etc/security/limits.d/99-core.conf
* hard core 0

# FIXED — /etc/systemd/coredump.conf
[Coredump]
Storage=none
ProcessSizeMax=0
# then: systemctl daemon-reload
```

### Time sync

```
# FIXED — /etc/chrony/chrony.conf   (Debian path; RHEL drops the chrony/ dir level)
pool 2.debian.pool.ntp.org iburst          # or: server ntp.internal.example.com iburst prefer
makestep 1.0 3
```

Enable the distro daemon: `systemctl enable --now chrony` (Alpine), `chronyd` (RHEL), or `systemd-timesyncd` (Debian minimal).

## Verification & Validation

Post-fix proof list — run each command, compare to the expected output; every fix from Remediation maps to exactly one line here:

```bash
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|authenticationmethods|pubkeyauthentication)'
# permitrootlogin no / passwordauthentication no / authenticationmethods publickey / pubkeyauthentication yes
awk -F: '$3==0{print $1}' /etc/passwd                          # root only
sudo awk -F: '($2==""){print $1}' /etc/shadow                  # (no output)
grep -RsE 'NOPASSWD:\s*ALL' /etc/sudoers /etc/sudoers.d/ && visudo -c   # no hits; parsed OK (scoped grants reviewed)
sysctl -n kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space fs.protected_symlinks fs.protected_hardlinks fs.suid_dumpable   # 2 1 2 1 1 0
sysctl -n net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects  # 0 / 0
find / -xdev -type f -perm -4000 2>/dev/null | sort > /tmp/suid-post
diff /tmp/suid-pre /tmp/suid-post                               # only intentional deltas vs pre-change baseline
findmnt -no OPTIONS /dev/shm | tr ',' '\n' | grep -E 'nosuid|nodev|noexec'        # all three present
ls -l /etc/cron.allow /etc/at.allow                             # exist, 600, root:root
timedatectl show -p NTPSynchronized                             # NTPSynchronized=yes
chronyc sources                                                 # >=1 ^* synced source
su - NOLOGIN_TEST -c true 2>&1 | grep -q nologin && echo "shell-gating OK"        # throwaway sanity check
# Session survival before releasing the window: from a SECOND terminal run `sudo -k && sudo -l`
# and a fresh key-based ssh login; only then close the original session.
```

Regression notes — what breaks when hardening is applied wrongly:

| Change | Classic breakage | Precaution |
|---|---|---|
| `AllowUsers`/`AllowGroups` typo | every SSH login refused, including admins | confirm console/out-of-band access first; keep current session open; `sshd -t`; reload not restart |
| `PasswordAuthentication no` deployed before keys distributed | password-only colleagues and break-glass automation locked out | distribute+test keys first, flip switch second |
| `kernel.unprivileged_bpf_disabled=1` | eBPF-based monitoring/tracing agents (Cilium, bcc-style profilers) silently die | coordinate with observability owners; schedule with their deploy |
| forcing `ip_forward=0` on infra roles | Docker/Kubernetes NAT breaks; containers lose egress | exempt routers/NAT/container nodes explicitly in findings |
| `rp_filter=1` on asymmetric/multi-homed hosts | BGP/VRRP/policy-routed traffic dropped | documented exception instead of blanket value |
| `fs.protected_regular=2` | legacy daemons pre-creating shared files in `/tmp` fail on write | canary one host first; drop to `1` if an app breaks, record which |
| faillock without exemptions | automation with rotating/typo-prone creds locks itself out repeatedly | use `users=` exemptions + monitor `/var/log/faillock` |
| `Storage=none` for coredumps | crash debugging loses dumps | journald still records metadata; raise `ProcessSizeMax` temporarily per-unit when triaging |

Regression hygiene: store the sweep output (Where To Look block) as the pre-change baseline; post-change diff is your regression report. Re-run the full sweep after kernel updates — new kernels occasionally reset sysctl defaults.

## Severity Assessment

Anchors with CVSS v3.1 example vectors. Adjust for exposure (internet vs internal), compensating controls, and host role; document every adjustment.

| # | Finding class | Anchor severity | Example vector (CVSS:3.1) | Score | Context modifiers |
|---|---|---|---|---|---|
| 1 | `PermitRootLogin yes` + `PasswordAuthentication yes`, SSH internet-exposed | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | VPN/allowlist-only → downgrade one tier with evidence |
| 2 | Unknown/duplicate UID-0 account or planted SUID root binary | High (treat as incident) | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.7 | C2/persistence evidence → escalate Critical, hand to IR |
| 3 | Broad `NOPASSWD: ALL` on network-facing service account | High | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | requires adjacent app RCE — note as chain enabler too |
| 4 | Empty-password account with login shell | High | `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 7.9 | UID-0 member or multi-user host → Critical |
| 5 | Missing sysctl hardening (redirects, kptr/dmesg, ASLR) internal host | Medium | `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 5.7 | edge/internet-exposed position raises tier |
| 6 | Executable `/dev/shm` (+ app write primitive) | Medium | `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` | 6.3 | amplifier — pair with taint row 7 |
| 7 | cron/at unrestricted (no allow-list) | Medium | `AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` | 6.3 | single-admin box → Low acceptable with note |
| 8 | Time sync absent/unsynchronized | Low standalone | `AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` | 3.5 | force multiplier — annotate forensic impact regardless of score |
| 9 | Missing login banner, lax `LoginGraceTime`/`MaxAuthTries` only | Low | `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` | 3.0 | never aggregate up; keep cosmetic findings honest |

Severity discipline: anchors 1–4 are reachable paths, not theoretical — verify exposure via FW module before finalizing; amplifier findings inherit narrative weight from Taint Tracing but keep their own measured CVSS.

## Common False Positives

Suppress or re-scope these before writing findings:

1. **Cloud-init owns sshd.** Cloud images rewrite SSH settings at boot (`ssh_pwauth`, `cc_ssh` module, `ssh_deletekeys`). A manual fix to `/etc/ssh/sshd_config` may be reverted on rebuild. Verify where truth lives; if user-data/image is the source, file the finding against the repo artifact, not just the live file.
2. **Silent directive ≠ risky when distro default is safe.** `PermitRootLogin` absent means OpenSSH default `prohibit-password` (key-only root) — not a finding unless effective value is `yes`. Ubuntu cloud images commonly ship `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf` with `PasswordAuthentication no`; judge `sshd -T`, never file absence.
3. **Containers are not VMs.** Docker/Podman images lack systemd, PAM, timesync daemons, and often run root by design inside a namespace. Applying this baseline *inside* a container generates noise; audit the container host here, and container-specific risks via SANDBOX.
4. **Modern kernel defaults already satisfy several sysctl targets** (`tcp_syncookies=1`, `icmp_echo_ignore_broadcasts=1`, protected_* enabled on recent kernels). Missing config files are not misconfigurations — compare live `sysctl -n` values against the tables only.
5. **`kptr_restrict=1` is partial protection, not wide-open.** Distinguish 0 (open), 1 (restricted to CAP_SYSLOG), 2 (always hidden); flagging 1 as "KASLR defeated" overstates it.
6. **Scoped NOPASSWD is legitimate.** `NOPASSWD: /usr/bin/systemctl restart myapp.service` is an accepted pattern; flag only wildcard grants and GTFOBins-abusable commands (interpreters, editors, `su`, archivers, `find`).
7. **Missing SUID on legacy binaries is progress, not anomaly.** `ping`/`mount` lose SUID in favor of file capabilities on modern distros; check `getcap` output instead of expecting the old inventory verbatim.
8. **cron.allow absent can be correct** on hosts running exclusively systemd timers — confirm which schedulers exist (`systemctl list-timers`, `/etc/cron.d/`). WSL/devcontainers/laptops are out of server scope per the engagement agreement; do not report their divergent baselines.

## References

- CIS Benchmarks — select the benchmark matching `/etc/os-release` ID and agreed profile level: CIS Ubuntu Linux LTS Benchmark (Level 1/2 Server), CIS Debian Linux Benchmark, CIS Red Hat Enterprise Linux Benchmark, CIS Rocky Linux Benchmark, CIS Amazon Linux Benchmark, CIS Alpine Linux Benchmark. https://www.cisecurity.org/cis-benchmarks
- CWE-16 Configuration, CWE-250 Execution with Unnecessary Privileges, CWE-732 Incorrect Permission Assignment for Critical Resource — https://cwe.mitre.org/data/definitions/16.html , https://cwe.mitre.org/data/definitions/250.html , https://cwe.mitre.org/data/definitions/732.html
- OpenSSH man pages: `sshd_config(5)`, `ssh_config(5)`, `authorized_keys(5)`, `sshd(8)`, `ssh-keygen(1)` — https://man.openbsd.com/sshd_config , https://man.openbsd.com/authorized_keys
- Identity/PAM man pages: `passwd(5)`, `shadow(5)`, `sudoers(5)`, `visudo(8)`, `chage(1)`, `faillock.conf(5)`, `pam.d(5)`, `pwquality.conf(5)`, `login.defs(5)`
- Resource/storage/scheduling/time man pages: `limits.conf(5)`, `coredump.conf(5)`, `systemd-coredump(8)`, `sysctl.d(5)`, `sysctl(8)`, `fstab(5)`, `crypttab(5)`, `findmnt(8)`, `crontab(1)`, `at(1)`, `timesyncd.conf(5)`, `chrony.conf(5)`
- Kernel sysctl docs: kernel knobs (kptr_restrict, dmesg_restrict, randomize_va_space, unprivileged_bpf_disabled) https://docs.kernel.org/admin-guide/sysctl/kernel.html ; IP sysctls (redirects, rp_filter, syncookies) https://docs.kernel.org/networking/ip-sysctl.html ; Yama ptrace_scope https://docs.kernel.org/admin-guide/LSM/Yama.html
- CVSS v3.1 specification (vector math used above): https://www.first.org/cvss/v3.1/specification-document
- GTFOBins sudo/SUID abuse reference: https://gtfobins.github.io/
- OpenSSH release notes (version boundaries cited: ed25519 keys, `expiry-time` ≥7.7, SSH-2-only ≥7.6): https://www.openssh.com/releasenotes.html
- systemd coredump configuration: https://www.freedesktop.org/software/systemd/man/latest/coredump.conf.html

