---
name: server-updates-patching
description: Audits Linux server patch discipline and attack-surface minimization — distro EOL posture, pending security updates, unattended-update automation, reboot debt, unused services, legacy protocols, kernel-module hardening, and host runtime currency.
category_slug: PATCH
cwe: [CWE-1104]
owasp: A06:2021 – Vulnerable and Outdated Components
---

## Scope & Objectives

Assess patch discipline and attack-surface minimization on one Linux server (or its config-as-code repo). Answer, in priority order:

1. **Distro identity & lifecycle stage** — which release is running, and is it plausibly within vendor support? Flag uncertainty honestly (Needs-Review with the exact release string), never assert an invented EOL date.
2. **Reboot debt** — does `uname -r` lag the newest installed kernel package? Installed-but-not-running fixes are dormant.
3. **Pending update inventory** — how many updates are outstanding, and how many belong to the security pocket / advisory stream.
4. **Automation** — is an unattended/automated security-update mechanism installed, configured with security origins, and *armed* (timer active)?
5. **Restart honesty** — uptime evidence for deferred kernel/libc/systemd restarts; maintenance-window posture.
6. **Surface shrinkage** — offender services (rpcbind, nfs-common, avahi-daemon, cups, postfix, xinetd, samba) and legacy protocol servers (telnet/rsh/tftp/ftp) in enabled/active/disabled/masked/purged states.
7. **Kernel-module hardening option** — uncommon filesystem blacklists (present as options with breakage caveats, not unconditional findings).
8. **Host-level runtime currency** — system python/node/php majors plausibly supported; Needs-Review when uncertain.

Out of scope (other modules): application dependency patching → supply-chain/code module; firewall/exposure rules → FW; sshd/PAM/sysctl baseline → BASE.

Operating rules:

- Every collection command here is read-only. Mutating commands appear only under Remediation.
- Commands needing root are tagged `[ROOT]`; without root, audit world-readable state plus the config repo.
- Distro variance is called out inline — detect first (`cat /etc/os-release`), never assume Debian values on RHEL or Alpine.

## Mental Model

Two clocks tick on every server:

- The **vulnerability clock**: public bugs in installed software accumulate daily regardless of what you do.
- The **fix clock**: a vendor fix only takes effect after download → install → process restart → occasionally reboot.

Patch discipline is the machinery keeping the fix clock synchronized to the vulnerability clock. It decomposes into four auditable layers:

| Layer | Question | Failure signature |
|---|---|---|
| Inventory | What is installed, what is stale? | Nobody can say how far behind the host is |
| Automation | Does anything apply security fixes without a human remembering? | Config exists but timer dead, or nothing exists at all |
| Restart honesty | Are installed fixes actually *effective*? | Kernel packages installed months ago, uptime 400 days |
| Surface shrinkage | Is unnecessary software absent or provably off? | rpcbind/cups/avahi running on a headless app node |

Corrections that prevent bad audits:

- **Version numbers lie on enterprise distros.** Red Hat and Ubuntu backport fixes into the *original* version number (openssl may stay 1.1.1 across dozens of CVE fixes on one release). Raw version comparison says "vulnerable" forever. Consult changelogs before judging.
- **Two kernels exist per host**: the one executing (`uname -r`, a snapshot from boot time) and the newest one on disk (`dpkg -l linux-image-*` / `rpm -q kernel`). They diverge between "packages updated" and "machine rebooted". That gap is reboot debt, and it silently re-arms every kernel-side fix you thought you had.
- **Service state is a pair, not a boolean.** `is-enabled` (starts at boot?) and `is-active` (running now?) are independent. Disabled-but-active units were started by hand or by another unit's dependency — find out who owns that decision.
- **Attack surface = listening services × their unpatched flaws × who can reach them.** Removing a daemon deletes all its future CVEs permanently — the only control that improves over time without effort.

## What To Check

Start with this paste-ready read-only sweep (~20 lines), then drill into each area below:

```bash
# --- READ-ONLY patching & attack-surface sweep ---------------------------------
. /etc/os-release; echo "DISTRO: $ID ${VERSION_ID:-unknown} ($PRETTY_NAME)"
echo "RUNNING-KERNEL: $(uname -r)"
command -v dpkg >/dev/null && dpkg -l 'linux-image-[0-9]*' 2>/dev/null | awk '/^ii/{print "INSTALLED-KERNEL:",$2,$3}' | sort -V | tail -n 3
command -v rpm  >/dev/null && rpm -q kernel 2>/dev/null | sort -V | tail -n 3
command -v apt  >/dev/null && { \
  echo "UPGRADABLE-TOTAL: $(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)"; \
  echo "SECURITY-ESTIMATE: $(apt-get -s dist-upgrade 2>/dev/null | grep '^Inst' | grep -c security)"; }
command -v dnf  >/dev/null && { \
  echo "DNF-UPDATE-LINES(est): $(dnf -q check-update 2>/dev/null | grep -c '\.el[0-9]\|\.fc[0-9]')"; \
  echo "SECURITY-ADVISORIES:"; dnf -q updateinfo list security 2>/dev/null | head -n 10; }
command -v apk  >/dev/null && { echo "APK-OUTDATED:"; apk version -l '<' 2>/dev/null | head -n 10; }
for s in rpcbind nfs-common avahi-daemon cups postfix xinetd smb nmb telnet.socket tftp.socket vsftpd; do
  ac=$(systemctl is-active  "$s" 2>/dev/null); en=$(systemctl is-enabled "$s" 2>/dev/null)
  [ -n "$ac$en" ] && printf '%-14s active=%-10s enabled=%s\n' "$s" "${ac:-unknown}" "${en:-unknown}"
done
echo "UPDATE-TIMERS:"; systemctl list-timers --all 2>/dev/null | grep -iE 'apt|dnf|yum|unattended' || echo "  NONE FOUND"
echo "BOOT-TIME: $(uptime -s)"
```

Interpretation notes for the sweep: `SECURITY-ESTIMATE` is a heuristic (simulation lines name the `-security` suite; package names containing "security" can inflate it). `dnf check-update` exits **100** when updates exist and prints nothing on clean hosts — do not treat exit≠0 as an error. `is-active` reports `inactive` even for unknown units, so treat `enabled=unknown` rows as "not installed".

### 1. Distro identity & lifecycle stage

Parse `/etc/os-release`; never infer from motd or hostname.

```bash
. /etc/os-release && printf '%s %s\n' "$ID" "${VERSION_ID:-rolling}"
```

| Distro family | Identification in os-release | Lifecycle reasoning guidance | Hardened state |
|---|---|---|---|
| Debian | `ID=debian`, `VERSION_ID=12` | stable → oldstable → oldoldstable as successors release; security support shrinks each step. If you cannot confirm which stage this codename occupies today → Needs-Review with codename | Current stable/oldstable with security suite enabled |
| Ubuntu | `ID=ubuntu` | LTS releases follow a ~5-year *standard support pattern* (longer via add-on plans); interim releases live months. Unconfirmed status → Needs-Review with release name | Supported LTS within standard window |
| RHEL | `ID=rhel` | Major versions carry decade-scale lifecycles with phased maintenance. Confirm currently-maintained major.minor; else Needs-Review | Maintained major.minor |
| Rocky / AlmaLinux | `ID=rocky` / `ID=almalinux` | Clone of the corresponding RHEL major's lifecycle; apply the same treatment | Maintained major.minor |
| Amazon Linux | `ID=amzn` (`VERSION_ID=2` vs `2023`) | AL2 and AL2023 have distinct lifecycles; if unsure which applies → Needs-Review | Currently maintained major |
| Alpine | `ID=alpine`, branch = VERSION_ID major.minor | Stable branches have limited lifespans tied to kernel support; unconfirmed branch → Needs-Review | Current stable branch |

Rule: **never assert an EOL date from memory.** Qualitative patterns you may cite: Ubuntu LTS ≈ five years standard support; Debian oldoldstable receives reduced/no security support once two successors ship. Anything beyond that goes to Needs-Review carrying the exact release string (e.g., "Ubuntu 18.04 — verify support window").

### 2. Running kernel vs installed kernels

```bash
uname -r                                   # kernel executing NOW
# Debian/Ubuntu — newest installed image:
dpkg -l 'linux-image-[0-9]*' | awk '/^ii/{print $2, $3}' | sort -V | tail -n 3
# RHEL/Rocky/Alma/Amazon Linux:
rpm -q kernel | sort -V | tail -n 3        # AL2023: also rpm -q kernel-core
# Reboot-required verdict (RHEL family, if present):
command -v needs-restarting >/dev/null && [ROOT] needs-restarting -r
```

If the highest-versioned installed kernel is **newer** than `uname -r` → finding "pending reboot": fixes shipped to disk are dormant in memory. On Debian/Ubuntu compare ABI strings (e.g., `5.15.0-91-generic`), not meta-package numbers.

### 3. Pending update inventory (read-only)

Debian/Ubuntu:

```bash
apt list --upgradable 2>/dev/null | tail -n +2          # total pending
apt-get -s dist-upgrade | grep '^Inst' | grep -c security   # security-pocket estimate
[ -x /usr/lib/update-notifier/apt-check ] && /usr/lib/update-notifier/apt-check --human-readable
#   → "N packages can be updated. M updates are security updates."
command -v unattended-upgrades >/dev/null && [ROOT] unattended-upgrades --dry-run --debug 2>&1 | tail -n 20
```

Caveat: `apt list` uses the cached index. A stale cache **undercounts**. Do not run `apt-get update` during a read-only audit; instead check freshness via `stat /var/lib/apt/periodic/update-success-stamp`.

RHEL-family:

```bash
dnf -q check-update                 # exit 100 = updates available; lists them
dnf -q updateinfo list security     # one row per advisory touching installed pkgs
dnf -q updateinfo summary           # counts incl. security bucket
```

Alpine:

```bash
apk version -l '<'                  # installed packages older than repo candidates
apk policy <pkg>                    # pinning/repo detail for a specific package
```

Live-patching presence (canonical names only — no third-party guesses):

```bash
command -v kpatch               >/dev/null && [ROOT] kpatch list
command -v canonical-livepatch  >/dev/null && canonical-livepatch status
```

### 4. Automated security updates armed?

Debian/Ubuntu — config files plus timers must BOTH check out:

```ini
# /etc/apt/apt.conf.d/20auto-upgrades — both keys must be "1"
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

```bash
grep -E 'Update-Package-Lists|Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades
grep -A6 'Allowed-Origins' /etc/apt/apt.conf.d/50unattended-upgrades | grep -- '-security'
systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer   # download / apply
systemctl list-timers --all | grep -iE 'apt|unattended'
```

Key fields in `50unattended-upgrades`: `Allowed-Origins` must cover `${distro_id}:${distro_codename}-security` (the whole point of the exercise); `Automatic-Reboot` + `Automatic-Reboot-Time` tradeoff; `Mail` notification hook so silence cannot hide regressions.

RHEL-family:

```bash
rpm -q dnf-automatic || rpm -q yum-cron                 # EL7 uses yum-cron
grep -E '^apply_updates' /etc/dnf/automatic.conf         # yes = install, not just download
systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null
systemctl list-timers --all | grep -iE 'dnf|yum'
```

Timer semantics: `dnf-automatic.timer` honors `apply_updates` (with `no` it only downloads); `dnf-automatic-install.timer` always installs. Exactly one should be enabled, chosen deliberately.

Alpine ships no stock unattended mechanism; if nothing provisions periodic upgrades (e.g., scripts under `/etc/periodic/`), mark Needs-Review rather than auto-failing.

### 5. Reboot honesty

```bash
uptime -s      # boot timestamp
uptime -p      # pretty duration
```

Kernel, glibc, systemd, and OpenSSL-linked daemons fully pick up fixes only at restart or reboot. Long uptime + pending kernel packages = deferred remediation, not stability. Plan maintenance windows; on fleets, stagger reboots cohort-by-cohort behind load balancers rather than big-bang.

### 6. Package minimization & offender-service trichotomy

Context first — installed-package count vs role expectation:

```bash
dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | wc -l   # Debian-family
rpm -qa | wc -l                                              # RPM-family
apk info | wc -l                                             # Alpine
```

Classic offenders on standalone app servers (each needs explicit justification to stay):

| Offender | Why it is surface | Verdict unless justified |
|---|---|---|
| rpcbind (+ nfs-common) | Portmapper historically abused for reflection/amplification; drags NFS RPC surface | remove/purge |
| avahi-daemon | mDNS discovery; zero server role | remove/purge |
| cups | Print server on a headless box; history of RCE-class bugs | remove/purge |
| postfix / exim4 | Mail daemon on hosts that need not originate mail | remove/purge (check sendmail-binary consumers first) |
| xinetd | Legacy superserver resurrecting old protocols | remove; audit `/etc/xinetd.d/*` if kept |
| samba (smb, nmb) | File-sharing surface on non-file servers | remove/purge |
| telnet / rsh / rlogin clients | Cleartext credentials by design | remove/purge (use ssh) |
| telnetd, rsh-server, tftpd/tftp-server, vsftpd/proftpd | Cleartext legacy protocol servers | INSTANT FINDING if installed or listening |

Trichotomy — check BOTH dimensions per suspect; the matrix tells you who started what:

```bash
systemctl is-active  rpcbind avahi-daemon cups postfix xinetd smb nmb 2>/dev/null
systemctl is-enabled rpcbind avahi-daemon cups postfix xinetd smb nmb 2>/dev/null
```

| active | enabled | Meaning |
|---|---|---|
| yes | yes | Conventional; justify or remove |
| no | no | Good (purged is better) |
| yes | no | Started manually or by another unit's dependency — identify the trigger before judging |
| no | yes | Dead weight that returns at reboot; disable |
| yes | masked | Someone bypassed the mask — hygiene finding |

Orphan sockets: every listener must map to an owning package; ownerless listeners (deleted binaries, hand-copied daemons) are findings. Cross-reference the firewall module's sweep for external reachability.

```bash
[ROOT] ss -tulpn | awk 'NR>1{print $5, $7}'          # local addr:port, process info
sudo readlink -f /proc/<PID>/exe                      # resolves deleted/renamed binaries
dpkg -S "$(readlink -f /proc/<PID>/exe)"              # Debian-family owner lookup
rpm -qf "$(readlink -f /proc/<PID>/exe)"              # RPM-family owner lookup
```

### 7. Host-level language runtime currency

Record system interpreters and compare qualitatively against known lifecycle patterns (python: annual feature releases, multi-year support tails; node: even-numbered LTS lines; php: annual cycles). When you cannot state the installed major.minor's support standing with confidence, mark Needs-Review with the exact version string — do not invent cutoff dates.

```bash
python3 --version 2>/dev/null
node --version 2>/dev/null
php -r 'echo PHP_VERSION, "\n";' 2>/dev/null
```

Application-level dependency patching (node_modules, virtualenvs, composer vendors, gem bundles) belongs to the supply-chain/code module — reference it, do not duplicate it here.

### 8. Kernel-module & legacy-tech surface (optional hardening)

Blacklisting uncommon filesystem drivers shrinks kernel attack surface — code that cannot load cannot be exploited. Present as hardening options WITH breakage caveats, never as unconditional findings:

```ini
# /etc/modprobe.d/fs-blacklist.conf — FIXED example
# Verify none is load-bearing BEFORE deploying:
#   vfat     → required for EFI System Partition mounts
#   squashfs → used by many container/live-media stacks (snap, some initramfs)
install cramfs    /bin/false
install freevxfs  /bin/false
install jffs2     /bin/false
install hfs       /bin/false
install hfsplus   /bin/false
```

Legacy protocol servers (telnet server, rsh/rlogin/rexec daemons, plain FTP, tftp) are instant findings wherever installed or listening — cleartext by design; replace with ssh/scp/sftp/https.

### 9. Deeper scanning (requires tools/network — clearly optional)

Run only where tooling exists and policy permits outbound reads; base forms only, no invented flags:

```bash
# RHEL-family OpenSCAP + SCAP Security Guide: enumerate profiles, then evaluate
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
[ROOT] oscap xccdf eval --profile <PROFILE_ID> \
      --results /tmp/oscap-results.xml --report /tmp/oscap-report.html \
      /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# Lynis — audit-mode framing: reads system state, writes only its own log/dat files
[ROOT] lynis audit system

# Debian — compare installed set against the Debian security tracker
debsecan --suite <CODENAME>
```

## Where To Look

Evidence collection: `tools/sweeps/sweep-patching.sh` captures `[PATCH-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

Authoritative locations, by family; verify existence before parsing:

| Location | What it proves |
|---|---|
| `/etc/os-release` | Distro identity — source it, never regex the hostname |
| `uname -r` vs `dpkg -l linux-image-*` / `rpm -q kernel` | Divergence = reboot debt |
| `/var/lib/apt/periodic/update-success-stamp` (mtime) | Last successful index refresh; stale stamp explains suspiciously clean `apt list --upgradable` |
| `/etc/apt/apt.conf.d/20auto-upgrades` | `APT::Periodic::Update-Package-Lists` and `::Unattended-Upgrade` both `"1"` |
| `/etc/apt/apt.conf.d/50unattended-upgrades` | `-security` origin present; `Automatic-Reboot{,-Time}`; `Mail` hook |
| `/var/log/unattended-upgrades/unattended-upgrades.log` | Proof the machinery actually fires (dates of past runs) |
| `/etc/dnf/automatic.conf` (EL7: `/etc/yum/yum-cron.conf`) | `apply_updates` value |
| `systemctl list-timers --all` | Armed timers — configs without timers mean automation is dead |
| `/etc/modprobe.d/*.conf` | Filesystem/module blacklist posture |
| `/etc/xinetd.d/`, `/etc/inetd.conf` | Legacy superserver entries (telnet, tftp, chargen…) |
| `[ROOT] ss -tulpn` output | Listener↔owner map feeding minimization review |
| `python3/node/php --version` outputs | Runtime currency inputs |

## Patterns & Signatures

Vulnerable/fixed pairs:

```ini
# VULNERABLE — automation present but inert (both switches off)
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";

# FIXED
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

```ini
// VULNERABLE — origins trimmed, security pocket NOT covered
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
};

// FIXED — security pocket explicitly included
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};
```

```ini
# VULNERABLE — dnf-automatic downloads but never installs
apply_updates = no

# FIXED
apply_updates = yes
```

State signatures:

| Signature | Meaning | Action |
|---|---|---|
| `uname -r` older than newest installed kernel pkg | Reboot debt; fixes dormant | Finding + window plan |
| `20auto-upgrades` missing entirely | Automation never provisioned | Finding |
| Config keys correct but timer absent/disabled | Automation armed on paper only | Finding — verify `list-timers` always |
| Service `active` while `disabled` | Out-of-band start; unknown owner process | Trace trigger, then decide |
| Service `masked` yet `active` | Mask deliberately bypassed | Hygiene finding |
| Listener on :23/:21/:69(udp)/:512–514/:873 | telnet/ftp/tftp/rsh-family/rsync exposed | Instant finding (cross-ref FW) |
| `ss -tulpn` row with no resolvable package | Orphan/hand-copied binary listening | Finding |
| `/var/log/unattended-upgrades/` empty or absent on Ubuntu | Machinery never ran | Finding |

Kernel staleness signature (annotated):

```text
$ uname -r
5.4.0-150-generic                     ← executing (boot-time snapshot)
$ dpkg -l 'linux-image-[0-9]*' | awk '/^ii/{print $3}' | sort -V | tail -n 1
5.4.0-169.186                         ← newest on disk (fixes dormant)
→ gap 150→169 = every kernel fix in between requires a reboot to matter
```

## Taint Tracing Guidance

Treat external reachability as the taint source; propagate along ownership chains:

1. **Source**: listener bound to `0.0.0.0`/`::`/external IP in `ss -tulpn`. Everything owning or feeding it inherits taint.
2. **Owner resolution**: PID → `/proc/PID/exe` (resolve symlink; catches deleted binaries) → `dpkg -S` / `rpm -qf` → package@version.
3. **Advisory join**: package appears in `apt-get -s dist-upgrade` Inst lines naming `-security`, or as a row in `dnf updateinfo list security` → tainted-by-advisory (vendor fix exists, host lacks it).
4. **Restart-gap sizing**: `uptime -s` bounds how long kernel/libc/systemd classes have been dormant; package install timestamps (`stat` on `/var/lib/dpkg/info/<pkg>.list` mtime, `rpm -q --qf '%{INSTALLTIME:date}\n' <pkg>`) bound when fixes landed on disk.
5. **Boot lineage**: `/proc/cmdline` `BOOT_IMAGE=` plus `grubby --default-kernel` (EL family) tie the running kernel to its on-disk counterpart; mismatch vs newest installed = tainted kernel class.

Record chains compactly: `host → listener/port → package@version → advisory-stream member → restart-gap`. Severity inherits from reachability at the chain's HEAD, not from the number of stale packages overall. An internet-facing tainted listener outranks fifty stale internal libraries.

## Exploitation & Reproduction

READ-ONLY demonstrations. Objective: prove exposure exists and would survive contact with an attacker; change nothing.

Demo A — prove pending security updates:

```bash
/usr/lib/update-notifier/apt-check --human-readable
# "12 packages can be updated. 4 updates are security updates."
#   → M > 0 means vendor-shipped fixes for published vulns are sitting in the repo,
#     one command away, not applied.
dnf -q updateinfo list security
# each row = advisory ID + affected package: vendor fix exists, host lacks it.
```

Interpretation discipline: report the SECURITY count, not just totals. "300 upgradable" is noise; "4 security advisories including the internet-facing service's daemon" is the finding.

Demo B — prove stale running kernel:

```bash
uname -r                                                  # 5.4.0-150-generic
dpkg -l 'linux-image-[0-9]*' | awk '/^ii/{print $2,$3}' | sort -V | tail -n 2
# newest installed: linux-image-5.4.0-169-generic
```

Explanation for the report: memory executes the 150 build; fixes shipped in builds 151–169 activate only at next boot. Any vendor-fixed kernel privilege-escalation or remote flaw disclosed meanwhile remains exploitable on this host although the package inventory claims otherwise. This is the canonical silent failure mode of patch programs — green dashboards fed by "updates installed", red reality on the wire.

Demo C — prove automation absent:

```bash
stat /etc/apt/apt.conf.d/20auto-upgrades        # No such file or directory
systemctl list-timers --all | grep -i apt       # (no output)
ls /var/log/unattended-upgrades/ 2>&1           # No such file or directory
stat /var/lib/apt/periodic/update-success-stamp 2>/dev/null   # months-old mtime, or absent
```

Missing config + missing timer + empty logs = nothing fetches or applies security fixes without a human remembering. On dnf systems: `automatic.conf` absent and no `dnf-*` timer in `list-timers` proves the same.

Attacker narrative (qualitative — no invented identifiers): adversaries mass-scan address space, fingerprint service banners, and replay publicly documented exploitation techniques against vulnerabilities vendors fixed weeks earlier. The dominant breach path for internet-facing services is precisely this n-day replay — no novel research required. Hosts without update automation sit in the disclosure-to-patch gap indefinitely, because the disclosure happens upstream whether or not the host ever hears about it. Internal hosts inherit the same risk laterally once any foothold exists anywhere on the flat network.

## Remediation

Order: automate FIRST (stops the bleeding), then drain reboot debt in planned windows, then shrink surface, then optional hardening.

### Enable unattended security updates

Debian/Ubuntu:

```bash
sudo apt-get install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades    # seeds 20auto-upgrades with "1"
```

`/etc/apt/apt.conf.d/20auto-upgrades` — FIXED:

```ini
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

`/etc/apt/apt.conf.d/50unattended-upgrades` — security origin mandatory; choose reboot behavior consciously; keep a notification hook:

```ini
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};
// Option 1 — hands-off: automatic reboots inside a scheduled window
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:30";
// Option 2 — operator-owned reboots: keep "false" and run the window checklist below
// Unattended-Upgrade::Automatic-Reboot "false";
// Notification so silence cannot hide regressions:
Unattended-Upgrade::Mail "root";
```

Tradeoff note: `Automatic-Reboot "true"` trades surprise-free uptime for hands-off freshness. On stateful database nodes prefer `"false"` plus explicit windows.

RHEL-family:

```bash
sudo dnf install -y dnf-automatic                       # EL7: sudo yum install yum-cron
sudo sed -i 's/^apply_updates *=.*/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic-install.timer
```

Enable exactly ONE timer: `dnf-automatic-install.timer` (always installs) or `dnf-automatic.timer` (honors `apply_updates`). Enabling both invites double semantics.

### Reboot planning checklist

1. Classify pending changes: kernel → reboot; libc/systemd → practically everything restarts (treat as reboot); others → targeted service restarts (EL: `needs-restarting -s` lists processes).
2. Announce and schedule the window; drain traffic (load-balancer removal, replica step-down).
3. Reboot ONE cohort; verify `uname -r` now equals the newest installed kernel; verify application health.
4. Proceed cohort-wise; previous kernels remain in the bootloader as rollback by default.
5. Fleet staggering one-liner: never simultaneous fleet-wide reboots — overlap-free cohorts sized so any single cohort's failure still meets availability targets.

### Remove-unused-services procedure — disable → mask → verify → purge later

1. **Stop + disable**: `systemctl disable --now NAME` — stops it now and removes boot autostart. Trivially reversible.
2. **Mask**: `systemctl mask NAME` — symlinks the unit to `/dev/null` so NOTHING can activate it: not other units' `Requires/Wants`, not D-Bus or socket activation, not muscle memory.
3. **Verify** across at least one reboot cycle plus a monitoring period: `is-active` fails, socket closed, application metrics unchanged.
4. **Purge afterwards**: `sudo apt purge NAME` / `sudo dnf remove NAME` — deletion is the least reversible step; doing it LAST lets the observation period reveal hidden dependents safely.

Why disable+mask precedes purge: masking gives reversible protection against ALL activation paths during observation, while purge is permanent and surfaces dependency surprises at the worst possible time if done first.

Pre-purge blast-radius check (postfix example — many apps shell out to the sendmail binary):

```bash
command -v sendmail
grep -rl sendmail /usr/local/bin /opt /etc/cron* 2>/dev/null
```

If consumers exist, migrate them to an SMTP relay or msmtp-style client BEFORE purging postfix.

### Blacklist example file

Deploy the `/etc/modprobe.d/fs-blacklist.conf` content shown under What To Check §8. Caveats to carry into the change record: vfat is load-bearing on EFI-booted hosts; squashfs breaks snap/container-live-media stacks; test on a canary with out-of-band console access before fleet rollout.

## Verification & Validation

Post-fix positives:

```bash
systemctl is-enabled apt-daily-upgrade.timer                          # → enabled
systemctl list-timers --all | grep -i apt                             # future NEXT elapse
grep -E 'Update-Package-Lists|Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades   # both "1"
grep -c -- '-security' /etc/apt/apt.conf.d/50unattended-upgrades      # ≥ 1
grep '^apply_updates' /etc/dnf/automatic.conf                         # → apply_updates = yes
```

After the first maintenance window — security counters trending zero:

```bash
/usr/lib/update-notifier/apt-check --human-readable    # "...0 updates are security updates."
dnf -q updateinfo list security                        # empty output
uname -r                                               # equals newest installed kernel (re-list and compare)
```

Negative tests (nothing broke):

- Legit package installs still work: `apt-get -s install curl` resolves cleanly; a real install of an approved package succeeds in staging.
- Application unaffected by removed services: health endpoints return 200; job queues drain; mail flows if postfix was replaced (sendmail consumers verified pre-purge).
- Masked services stay dead across one controlled reboot.

Regression watch:

- Automatic reboots caused surprise outages → schedule windows FIRST, announce via the `Mail` hook, THEN flip `Automatic-Reboot`.
- Removing postfix broke apps calling the sendmail binary → restore service immediately (reinstall postfix or deploy the planned relay swap); the pre-purge grep exists precisely to prevent this.
- Blacklisted modules broke an early-boot mount → revert the specific `install … /bin/false` line, regenerate initramfs if needed.

IaC regression greps (run at repo root):

```bash
grep -REn 'APT::Periodic::(Unattended-Upgrade|Update-Package-List)s?"\s*"0"' .
grep -REn '^apply_updates\s*=\s*no' .
grep -REin '(telnetd|rsh-server|tftp-server|xinetd|avahi-daemon|\bcups\b)' playbooks/ docker/ k8s/ 2>/dev/null
```

## Severity Assessment

Weight REACHABILITY over raw counts. Ten stale packages on an isolated host matter less than one stale internet-facing daemon.

| Anchor | Example CVSS v3.1 vector | Score | Notes |
|---|---|---|---|
| Internet-facing service with known vendor-fixed vulns unapplied >30 days (qualitative anchor) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical — High floor at minimum | N-day replay is the dominant breach path |
| Security auto-updates absent on INTERNAL host | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L` | 5.7 Medium | Gap compounds silently until exposure changes |
| Pending reboot >90 days (kernel fixes dormant) | Same medium-vector family | Medium | Evidence: `uptime -s` vs installed kernels |
| Minor drift — isolated host, few non-security updates, no exposure | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L` | 3.5 Low | Housekeeping |

Escalation multipliers: externally confirmed exposure (+), stale RUNNING kernel matching a disclosed kernel-flaw class (+), no notification channel so regressions hide (+), multiple anchors combined on one host (+). Downgrade where immutable infrastructure rebuilds continuously (see False Positives).

## Common False Positives

1. **Backported patches.** Ubuntu/RHEL ship fixed code under UNCHANGED version numbers (openssl may remain 1.1.1 across dozens of CVE fixes on one release). Naive `installed_version >= fixed_version` logic false-positives forever. Before reporting, consult `apt changelog <pkg>` or `rpm -q --changelog <pkg>` for the vendor's fix reference.
2. **Pinned/vendor-managed environments.** Appliances and vendored images often update through a separate pipeline; absence of HOST automation is by design. Verify the pipeline exists instead of filing.
3. **Read-only/immutable infra rebuilt continuously.** Patching is replaced by redeploy cadence; assess image age and rebuild frequency, not in-place patch state. "No unattended-upgrades" is expected there.
4. **Stale package index.** `apt list --upgradable` trusts the cache; a months-old `update-success-stamp` makes zeros meaningless. Check freshness before trusting clean output.
5. **Disabled-but-running services.** `is-enabled` alone saying "disabled" does not prove anything is off — only `is-active` speaks for the running state. Check both, every time.

## References

- ubuntu.com/security — Ubuntu security overview and LTS lifecycle patterns
- access.redhat.com — Red Hat Security Data and product lifecycle (root domain)
- debian.org — Debian Security Tracker and release lifecycle (root domain)
- alpinelinux.org — Alpine release branch lifecycle (root domain)
- CIS Benchmarks — CIS Distribution Independent Linux Benchmark and per-distro benchmarks (patch management, service minimization, filesystem-module blacklisting sections)
- CWE-1104: Use of Unmaintained Third Party Components
- OWASP Top 10:2021 A06 — Vulnerable and Outdated Components
- open-scap.org — OpenSCAP and SCAP Security Guide tooling (root domain)
- cisofy.com — Lynis security auditing tool (vendor root domain)
