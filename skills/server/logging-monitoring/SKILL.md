---
name: server-logging-monitoring
description: Audits Linux logging, monitoring and intrusion detection on servers — journald persistence, rsyslog coverage and rotation, auditd baseline rules, file-integrity monitoring, off-host shipping, retention and out-of-band alerting — with read-only evidence commands, hardened reference configs, and an incident-triage quickstart.
category_slug: LOGMON
cwe: [CWE-778, CWE-223]
owasp: A09:2021 – Security Logging and Monitoring Failures
---

## Scope & Objectives

Audit whether one running Linux host (or its config-as-code) produces, keeps, protects, and surfaces security telemetry. Eight domains, in priority order:

1. **Capture & persistence** — journald `Storage=` mode (volatile-only = logs die on reboot = finding), rsyslog presence and classic auth files (`/var/log/auth.log` Debian-family, `/var/log/secure` RHEL-family).
2. **Rotation & headroom** — logrotate coverage of key files, journald size caps, disk/inode headroom for `/var/log`.
3. **Event coverage** — the checklist of events that must be logged: auth, sudo, identity changes, cron edits, package ops, firewall drops, kernel, crash-loops, app-layer auth failures.
4. **Kernel-depth telemetry** — auditd installed, running, carrying a baseline ruleset (identity, sudoers, sshd_config, time-change), with rotation and space-survival policy.
5. **Integrity monitoring** — AIDE baseline + periodic check (or osquery), webroot watches, database-update discipline.
6. **Off-host shipping** — forwarding rules in rsyslog, journald→rsyslog chain, vendor agents (Datadog/Fluent Bit/Promtail) glob coverage; local-only logging = finding.
7. **Retention & permissions** — hot-retention floor, WORM/object-lock mention, auth-log ownership/modes.
8. **Response wiring** — minimum alert set landing OUT of band of the monitored host, plus an ordered incident-triage quickstart.

Out of scope (cross-references): firewall drop-logging rule design → FW; sshd/PAM/sudo policy content → BASE; certificate expiry mechanics → TLS; app-code log-injection flaws → INJECTION; secrets leaked INTO logs → HSECRET; patch level → PATCH; audit-rule authoring beyond the baseline set here stays in this module.

Operating rules:

- All inspection is read-only; mutating commands appear only under Remediation (Phase 6 approval). Commands needing root are tagged `[ROOT]`; without root, audit world-readable state plus the config repo and say which evidence is degraded.
- Repo-only access: judge the *rendered* config (Ansible templates, cloud-init user-data, baked images) using Patterns & Signatures — images frequently strip rsyslog/auditd at build time, which file text in the repo may not reveal.
- Distro variance is called out inline; detect first (`cat /etc/os-release`). Debian/Ubuntu and RHEL-family differ in file names, package names, and AIDE workflow.
- Absence-of-telemetry findings are scored by EXPOSURE (see Severity Assessment): the same gap on an internet host outranks the gap on an internal one.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **journald Storage=**: the setting deciding whether system logs survive a reboot (volatile-only means they do not)
- **auditd**: kernel-level recording of sensitive actions — identity changes, sudo use, clock shifts
- **AIDE / file-integrity monitoring**: a baseline-and-compare watch that detects modified or planted files
- **off-host shipping**: forwarding log copies off the machine before an attacker can erase them
- **retention floor**: the minimum number of days logs stay available
- **out-of-band alerting**: paging infrastructure the monitored host itself cannot silence
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function

## Mental Model

Attackers do not attack "the logs" — they exploit the fact that nobody can see them. Each missing layer converts a detectable step into a silent one:

```
Attacker action            Telemetry layer (this module)          If the layer is missing
-------------------------  -------------------------------------  ----------------------------------
SSH credential stuffing    auth.log / journald                    invisible until the box falls
sudo to root               sudo + auditd identity/scope watches    who became root stays unknown
webshell dropped in docroot AIDE webroot watch / file-integrity      backdoor lives undetected
clock tampering            auditd time-change rules                forensic timeline uncorrelatable
post-exploit cleanup       OFF-HOST shipping                       attacker erases own trail at leisure
human response             out-of-band alerting                    perfect logs nobody ever reads
```

Six defensive layers map onto the check sections:

| Layer | Sections | Question it answers |
|---|---|---|
| Capture | 1–2 | Is every security event written somewhere durable? |
| Coverage | 3 | Are the RIGHT events written? |
| Depth | 4, 6 | Does kernel-level auditd see what userspace misses? |
| Integrity | 5 | Would we notice a trojaned binary or planted file? |
| Survival | 6–7 | Do copies leave the host before an attacker can erase them? |
| Response | 8 | Does a human get paged, from infrastructure the host cannot silence? |

Two axioms drive scoring. First, **local-only logs are attacker-wipeable**: any intrusion serious enough to matter includes a cleanup phase, so evidence that lives only on the victim has near-zero forensic value. Second, **unread logs are unwritten logs**: coverage without an alerting path detects nothing. Classify every gap by layer and by what it chains with — a Medium gap on an internet-exposed host compounds into a High finding (see Taint Tracing Guidance).

## What To Check

### 1. journald Persistence and Capacity

Determine the effective storage mode — file text AND reality, because the default is conditional:

```bash
grep -RhE '^\s*(Storage|ForwardToSyslog|Compress|SystemMaxUse|SystemKeepFree|MaxRetentionSec)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
ls -ld /var/log/journal 2>/dev/null || echo "NO /var/log/journal -> volatile"
journalctl --list-boots --no-pager | tail -5
journalctl --disk-usage
```

Judgement:

- `#Storage=auto` (commented/absent) means default `auto`: journald is persistent **only if** `/var/log/journal` existed at journald start. Missing directory ⇒ everything lives in `/run/log/journal` (tmpfs) ⇒ logs die on reboot ⇒ finding.
- Explicit `Storage=volatile` or `Storage=none` in any drop-in ⇒ definite finding; also grep drop-ins, which override the main file.
- Corroborate with history: if the ops calendar shows a reboot within the retention period you'd expect, but `--list-boots` starts at the current boot, pre-reboot logs are already unrecoverable.
- Capacity: `SystemMaxUse=` unset lets journald grow toward `SystemKeepFree` defaults (10% of fs / 15% free); on small disks that crowds out other services. Note whether `ForwardToSyslog=yes` matters later (Section 9).

### 2. Classic Syslog Files (rsyslog)

```bash
systemctl is-active rsyslog 2>/dev/null || echo "rsyslog not active"
ls -l /var/log/auth.log /var/log/syslog /var/log/messages 2>/dev/null   # Debian family
ls -l /var/log/secure /var/log/messages 2>/dev/null                     # RHEL family
grep -RhE '^[^#]*(auth|authpriv)' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
dpkg -V rsyslog 2>/dev/null; rpm -V rsyslog 2>/dev/null                 # tampered/replaced config?
```

Judgement:

- Debian/Ubuntu writes auth events to `/var/log/auth.log`; RHEL/Fedora/SUSE to `/var/log/secure`. Confirm the selector line (`auth,authpriv.*` / `authpriv.*`) actually exists and targets a real action.
- Minimal hand-rolled rsyslog configs that carry only `*.info;mail.none` style lines quietly swallow authpriv detail — never assume the package defaults survived; grep for the selector every time. A replaced config shows up in `dpkg -V`/`rpm -V` output as a changed-file line.
- Modern Ubuntu cloud images ship WITHOUT rsyslog running by default. Absence alone is not a finding IF journald is persistent (Section 1) and something consumes/ships the journal (Sections 9–10). Absence PLUS volatile journal PLUS no forwarding = the no-auth-logging High anchor.

### 3. Rotation Health

```bash
ls /etc/logrotate.d/
grep -RInE 'auth\.log|/var/log/secure|syslog|messages' /etc/logrotate.d/ 2>/dev/null
find /var/log -xdev -type f -size +100M -printf '%s\t%p\n' 2>/dev/null | sort -rn | head
logrotate -d /etc/logrotate.conf 2>&1 | grep -iE 'error|considering|rotating pattern' | head -20   # [ROOT] dry-run
```

Judgement:

- Key files must rotate on size OR time with compression and a bounded count. Missing entries for growing app logs = finding (they end up as multi-GB single files that outlive disks).
- auditd rotates its OWN log via `auditd.conf` (`max_log_file_action = rotate`) — do not expect or require a logrotate entry for `/var/log/audit/`; logrotate touching audit.log can fight the daemon.
- journald caps itself via `SystemMaxUse`/`MaxRetentionSec`, not logrotate. Any `+100M` hit from the find needs an owner and a rotation plan.

### 4. Disk Headroom for Logs

```bash
df -h /var/log; df -i /var/log
du -xh --max-depth=1 /var/log 2>/dev/null | sort -rh | head -8
```

Interpretation: Use% ≤70 healthy; 70–85 plan expansion or tighter rotation this sprint; >85 urgent — most daemons misbehave before 100%, and a full `/var` wedges databases, mail, and the logging stack itself (logging stops exactly when activity spikes). Watch the Inodes column too: `IUse%` near 100 with gigabytes free is equally fatal (millions of tiny rotated files). `journalctl --vacuum-*` exists but deleting evidence to buy space trades forensics for availability — prefer caps (Remediation F1) and rotation (F-section 3 above).

### 5. Coverage Checklist — What SHOULD Be Logged

Verify each row has a live source. "Source absent" rows are findings ranked by event criticality:

| Event | Source | Where | Alert-worthy? |
|---|---|---|---|
| SSH login success/failure | sshd → syslog/journald | `/var/log/auth.log` (Deb) · `/var/log/secure` (RHEL) · journal | Failure SPIKES yes; success from new source IP yes |
| sudo usage & failures | sudo → authpriv | same auth files | Failures yes; first-use from new user yes |
| Account/group/sudoers changes | auditd watch (`-k identity`/`-k scope`) | `/var/log/audit/audit.log` via `ausearch` | Every unexpected event yes |
| sshd_config change | auditd watch (`-k sshd_config`) | audit.log | Yes |
| cron/at edits | auditd watch or AIDE | audit.log · aide report | Yes |
| Package install/remove | apt/dpkg & dnf history | `/var/log/apt/history.log`, `/var/log/dpkg.log*` · `/var/log/dnf.log`, `dnf history` | Off-hours/unexpected yes |
| Firewall drops | kernel LOG targets (rules → FW module) | `journalctl -k` · kern.log | Aggregate spikes only (rate-limited) |
| Kernel errors/oops | kernel ring → journal | `journalctl -k` | Repeats/new classes yes |
| Service crash / restart loop | systemd unit state | `journalctl -u UNIT` | ≥N restarts/15min yes |
| Web/app auth failures & 5xx | nginx/app logs | app error/auth log dir | Spikes yes |
| Time changes | auditd `-k time-change` | audit.log | Unexpected yes |
| Logging-stopped silence | collector-side freshness check | central log store | NO events from a host for >N hours (baseline-dependent) = alert; attackers strip logs first, so silence is itself a signal |
| Binary/config drift | AIDE / osquery | aide report · osqueryd log | Unexpected yes |

Two traps: (a) the auth stream can be nuked by minimal rsyslog configs (Section 2) even while sshd dutifully emits events — verify end-to-end with the test message in Verification V1; (b) firewall drop-logging may be deliberately off to save disk — that is a Low finding here, but its PRESENCE feeds the FW module's rate-limited design, so cross-check both ways.

### 6. auditd Presence and Baseline Rules

```bash
command -v auditctl && systemctl is-active auditd; systemctl is-enabled auditd 2>/dev/null
dpkg -l auditd 2>/dev/null | tail -1; rpm -q audit 2>/dev/null          # Deb pkg: auditd · RHEL pkg: audit
auditctl -s                                                             # [ROOT] runtime status incl. immutable flag
cat /etc/audit/rules.d/*.rules 2>/dev/null || cat /etc/audit/audit.rules 2>/dev/null
```

Judgement:

- Not installed / `inactive` on an internet-reachable host = finding (Medium standalone; High when auth logging is ALSO absent — nothing recorded identity changes at any layer).
- Rules file present but `auditctl -l` [ROOT] prints nothing = rules never loaded (`augenrules --load` compiles `rules.d/*.rules` into the running kernel; plain `audit.rules` is the legacy path). File text alone earns no credit — verify runtime.
- Compare on-disk rules against the baseline below. Absent ruleset signature:

```bash
# VULNERABLE — no audit telemetry:
#   dpkg -l auditd -> "no packages found"  |  rpm -q audit -> package audit is not installed
#   systemctl status auditd -> Unit auditd.service could not be found.
#   ls /etc/audit/rules.d/ -> augenrules.rules only (stock stub, zero -w/-a lines)
```

Baseline ruleset (identity, privilege boundary, sshd config, session artifacts, time tampering):

```bash
# FIXED — /etc/audit/rules.d/50-baseline.rules (order matters: '-e 2' LAST)
# identity & privilege-boundary files
-w /etc/passwd    -p wa -k identity
-w /etc/group     -p wa -k identity
-w /etc/shadow    -p wa -k identity
-w /etc/gshadow   -p wa -k identity
-w /etc/sudoers   -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd_config
# login/session artifacts
-w /var/log/lastlog    -p wa -k logins
-w /var/run/faillock/  -p wa -k logins
# time tampering (canonical four-line arch pair + localtime watch)
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# anti-tamper lock (enable ONLY after validating everything above — see caveat)
-e 2
```

Notes on the set: always pair `-F arch=b64` with `-F arch=b32` lines — on x86_64, 32-bit processes issue legacy-mode syscalls that bypass a b64-only rule. The four-line time-change pair above is the canonical CIS-style core; some baselines add the legacy 32-bit-only `stime` syscall or `clock_adjtime` for newer kernels — treat additions as optional hardening, not omissions. `-w ... -p wa` records writes and attribute changes (mode/owner/timestamp); reads stay unlogged by design. The `/etc/sudoers.d/` directory watch catches drop-in files created inside it.

**Immutability caveat:** `-e 2` locks the kernel audit subsystem until reboot — even root gets `Operation not permitted` from live `auditctl` edits. That is intentional anti-tamper (an intruder with root cannot silently strip your watches), but it converts every future rules change into a maintenance-window reboot. Warn the owner BEFORE applying, and record the lock in the runbook (see Verification regression notes).

### 7. Audit Depth — What NOT to Audit

Honest guidance: do NOT add global execve monitoring (`-S execve` without path filters). Every process launch logs — gigabytes per day on a busy host, real intrusions buried in noise, disks filled. Logins are already covered end-to-end by PAM/sshd in the auth stream (Section 5) — auditd adds session records, but the auth stream suffices for triage. Prefer targeted watches of critical paths (the Section 6 set, plus app-specific secrets/config dirs) over breadth. Summarize rather than dump:

```bash
ausearch -k identity --interpret        # [ROOT] human-readable hits for one key
aureport --summary                      # [ROOT] fleet-wide event histogram
aureport -k                             # events grouped by key
```

### 8. auditd.conf Survival Knobs

```bash
grep -E '^\s*(max_log_file|max_log_file_action|num_logs|space_left|space_left_action|admin_space_left|admin_space_left_action|action_mail_acct)' /etc/audit/auditd.conf
```

Defaults keep only ~5 × 8 MB of audit history — an hour of noise overwrites yesterday's evidence. Tradeoffs to state honestly when recommending:

- `max_log_file_action = rotate` + `num_logs = 10..20`: bounded, self-managing. `keep_logs` refuses to ever delete (disk-full risk).
- `space_left_action = email` pages at the soft threshold BUT silently does nothing without a working MTA (`action_mail_acct`, default `root`) — verify the mail path or choose `syslog`.
- `admin_space_left_action`: `halt` preserves evidence and stops a possibly-compromised machine but converts disk-full into a full outage; `suspend` keeps services up while auditd stops writing (events during suspension are an evidence hole); `single` lands between. Integrity-first assets (bastions, PKI, directory servers): `halt`. Availability-first tier-1 API hosts: `suspend` + a paging alert on the threshold.

### 9. File Integrity Monitoring

```bash
command -v aide || echo "AIDE absent"; systemctl is-active osqueryd 2>/dev/null
ls -l /var/lib/aide/aide.db* 2>/dev/null
stat -c '%y %n' /var/lib/aide/aide.db* 2>/dev/null      # db age — stale db = blind FIM
```

What a baseline buys you: detection of backdoored binaries and webshell drops that no log line ever announces. An attacker replacing `/usr/bin/passwd` or dropping `cmd.php` into a docroot triggers zero syslog events — integrity monitoring is the only layer watching content itself.

Workflow (Debian family — `aideinit` wrapper initializes and promotes the db):

```bash
sudo aideinit                       # builds /var/lib/aide/aide.db.new, moves to aide.db after confirm
sudo aide --check                   # compare against baseline
```

Workflow (RHEL family):

```bash
sudo aide --init                    # produces /var/lib/aide/aide.db.new.gz
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo aide --check
```

Schedule checks daily via cron or timer (snippet in Remediation F4) and add a webroot watch group to `/etc/aide/aide.conf` following the file's own rule pattern, e.g. define a group like `WEBROOT = p+u+g+s+m+c+sha256` and apply it as `/var/www WEBROOT` — exclude growing upload/cache dirs or every check drowns. Discipline: after EVERY legitimate package operation run `aide --update`, review the diff, promote the new database — otherwise each patch night floods false alerts and the channel gets ignored within a month. Database older than ~7 days with no matching change window = treat FIM as degraded. osquery is an acceptable alternative: fleet-managed `osqueryd` with `file_paths` monitoring and scheduled queries landing centrally; verify the fleet config actually includes the host and the docroot paths.

### 10. Remote Shipping Detection

```bash
grep -RnsE '^[[:space:]]*[^#]*(@@|@)[a-zA-Z0-9._:-]+' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
grep -RnsE 'omfwd|omrelp|imfile' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
grep -RhE '^\s*ForwardToSyslog' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
ss -tunap 2>/dev/null | grep -E ':(514|6514|2514)\b'    # [ROOT] live collector connections
```

Judgement ladder for what you find:

- Nothing anywhere AND no vendor agent (Section 11) AND no platform drain = **local-only logging = finding**: an attacker wipes local traces as standard post-exploitation hygiene, ransomware encrypts them, disk loss ends history. Everything Sections 1–8 collected becomes worthless precisely when needed.
- `@host:514` (single @) = legacy UDP forwarding: fire-and-forget, spoofable, plaintext, silent loss under load. Counts as "leaves the box" but flag transport quality.
- `@@host:514` (double @) = TCP forwarding: reliable delivery, still plaintext/sniffable.
- `action(type="omfwd" ...)` with TLS, or `omrelp` RELP targets (`:omrelp:loghost:port`) = delivery guarantee plus integrity/confidentiality — the reference posture.
- Chain check: journald forwards to rsyslog only if `ForwardToSyslog=yes` AND rsyslog runs (Sections 1–2). Without rsyslog, journald alone has NO network output; systemd-journal-remote (pull/push receivers) or a vendor agent must cover it instead — name which.

### 11. Vendor Agent Coverage

```bash
systemctl is-active datadog-agent fluent-bit promtail vector otelcol 2>/dev/null
grep -RhsE 'logs|__path__|tail|/var/log' /etc/datadog-agent/conf.d/*.yaml /etc/promtail/config.yml /etc/fluent-bit/fluent-bit.conf 2>/dev/null | head -15
```

Concept check, not brand check: the agent's file globs must include the AUTH stream (`auth.log`/`secure`) and app error/auth logs — an infrastructure agent shipping only metrics or container stdout does NOT satisfy this module even though "monitoring works." Confirm the glob pattern actually resolves to the auth files on THIS layout (distro differences again), and that the agent's own liveness is monitored — a dead shipper is a silent blind spot unless its heartbeat alerts somewhere.

### 12. Retention and Permissions

```bash
grep -E '^(weekly|monthly|rotate|maxage)' /etc/logrotate.conf
stat -c '%a %U:%G %n' /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null
find /var/log -xdev -type f -perm -0004 2>/dev/null | head    # world-readable logs
```

Retention: 30–90 days hot online retention is the common qualitative floor for incident response (most intrusions are discovered weeks after entry; shorter windows erase your own crime scene). Longer/compliance regimes archive compressed logs off-host; regulated contexts should land copies in WORM/object-lock storage (e.g., S3 Object Lock-class immutability) so retention cannot be shortened by anyone holding the bucket. Permissions: expected shapes are `640 root:adm` for `/var/log/auth.log` (Debian family) and `0600 root:root` for `/var/log/secure` (RHEL family defaults). World-readable auth logs leak usernames, key fingerprints, and command history patterns to every local account = finding. While scanning, note any log containing credentials/tokens (cross-ref HSECRET).

### 13. Incident Triage Quickstart ("Something Looks Wrong")

Ordered first-10-commands list — all read-only, run top to bottom, save output off-host as you go:

```bash
w; who -a                                   # 1. who is logged in RIGHT NOW
last -F | head -40                          # 2. recent sessions & reboots (lastb [ROOT] = failures)
ss -tunap state established                 # 3. live network map — unexpected peers, beacons
ps auxf                                     # 4. process tree — parentage anomalies (nginx spawning sh?)
pstree -alp                                 # 5. cross-check hidden parents & full cmdlines
journalctl -n 200 --no-pager                # 6. latest system events around now
grep -aE 'Accepted|Failed|session opened' /var/log/auth.log 2>/dev/null | tail -50   # 7. auth trail (or: journalctl -u ssh -n 100)
crontab -l -u root; ls -la /etc/cron.d /etc/cron.daily /var/spool/cron 2>/dev/null   # 8. persistence hooks
find /var/www /tmp /var/tmp /dev/shm -xdev -mtime -3 -type f -ls 2>/dev/null         # 9. fresh drops in writable+web paths
rpm -V cronie 2>/dev/null; dpkg -V cron 2>/dev/null                                  # 10. tampered cron binaries vs package defaults
```

Reading hints: on step 3, map every established tuple to an owner and ask "why does this talk to THAT address"; step 4/5, look for webservers/mail agents parenting shells or interpreters. Step 8: eyeball mtimes of `/etc/cron*` entries against deploy dates — anything newer than your last change window needs an owner. Caveat that belongs on the wall: attackers SCRUB these sources first — truncated `~/.bash_history`, `unset HISTFILE`, wiped wtmp, vacuumed journals are themselves suspicious signals, so absence of evidence is not evidence of absence. Pristine-looking local history on a suspect host justifies pivoting straight to auditd/off-host copies — which is exactly why Sections 4–10 exist.

## Where To Look

Evidence collection: `tools/sweeps/sweep-logging.sh` captures `[LOGMON-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone. The paste-ready sweep below covers the same ground for interactive use.

Paste-ready audit sweep — highest-yield checks, strictly read-only, safe on production; `[ROOT]` lines need root, everything else works unprivileged:

```bash
#!/usr/bin/env bash
# Logging & monitoring sweep — READ-ONLY. [ROOT] lines need root.
echo "== OS/uptime =="; head -2 /etc/os-release; uptime
echo "== journald config =="; grep -RhE '^\s*(#)?\s*(Storage|ForwardToSyslog|SystemMaxUse|MaxRetentionSec)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null
echo "== persistent journal on disk =="; ls -ld /var/log/journal 2>/dev/null || echo "MISSING -> volatile-only FINDING"
echo "== boots known to journal =="; journalctl --list-boots --no-pager 2>/dev/null | tail -3; journalctl --disk-usage 2>/dev/null
echo "== rsyslog =="; systemctl is-active rsyslog 2>/dev/null; ls -l /var/log/auth.log /var/log/secure 2>/dev/null
echo "== auth selector present? =="; grep -RhE '^[^#]*(auth|authpriv)' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5 || echo "NO selector -> FINDING"
echo "== forwarding rules =="; grep -RnsE '^[[:space:]]*[^#]*(@@|@)[a-zA-Z0-9._:-]+|omfwd|omrelp' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo "NO forwarders -> local-only FINDING"
echo "== vendor agents =="; systemctl is-active datadog-agent fluent-bit promtail otelcol 2>/dev/null
echo "== logrotate coverage =="; ls /etc/logrotate.d/ 2>/dev/null; grep -RIls 'auth\.log|secure' /etc/logrotate.d/ 2>/dev/null
echo "== log disk headroom =="; df -h /var/log | tail -1; df -i /var/log | tail -1
echo "== biggest logs =="; du -xh --max-depth=1 /var/log 2>/dev/null | sort -rh | head -5
echo "== auditd [ROOT] =="; systemctl is-active auditd 2>/dev/null; auditctl -s 2>&1 | head -3
echo "== audit rules on disk =="; grep -RhsE '^\s*(-w|-a|-e)' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | head -20 || echo "no rules -> FINDING"
echo "== FIM =="; command -v aide; systemctl is-active osqueryd 2>/dev/null; stat -c '%y %n' /var/lib/aide/aide.db* 2>/dev/null || echo "no AIDE db -> FINDING"
echo "== aide/rotation timers =="; systemctl list-timers --all --no-pager 2>/dev/null | grep -iE 'aide|logrotat'; grep -RhsE 'aide|logrotate' /etc/cron.d/ /etc/crontab 2>/dev/null | head -5
echo "== log perms spot check =="; stat -c '%a %U:%G %n' /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null
echo "== world-readable logs =="; find /var/log -xdev -type f -perm -0004 2>/dev/null | head -8
```

Artifact map:

| Evidence | Primary path(s) | Live command |
|---|---|---|
| journald config | `/etc/systemd/journald.conf`, `/etc/systemd/journald.conf.d/*.conf` (drop-ins override) | `grep Storage`, `journalctl --disk-usage` |
| Persistent store | `/var/log/journal/<machine-id>/` vs runtime `/run/log/journal/` | `ls`, `journalctl --list-boots` |
| Auth stream | `/var/log/auth.log` + `/var/log/syslog` (Deb) · `/var/log/secure` + `/var/log/messages` (RHEL) | `grep -a Accepted/Failed` |
| rsyslog config | `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf` | selector + forwarding greps above; `dpkg -V`/`rpm -V` for replaced files |
| Rotation | `/etc/logrotate.conf`, `/etc/logrotate.d/*` | `logrotate -d` [ROOT] dry-run |
| auditd runtime | kernel state (not files) | `auditctl -s`, `auditctl -l` [ROOT] |
| auditd rules | `/etc/audit/rules.d/*.rules` → compiled `/etc/audit/audit.rules`; legacy hosts use the latter directly | `cat`, compare to Section 6 baseline |
| auditd daemon policy | `/etc/audit/auditd.conf` | grep thresholds (`max_log_file*`, `space_left*`) |
| Audit events | `/var/log/audit/audit.log` | `ausearch -k KEY --interpret`, `aureport --summary` [ROOT] |
| AIDE state | `/var/lib/aide/aide.db(.new)?.gz`; config `/etc/aide/aide.conf` (Deb also under `/etc/aide/aide.conf.d/`) | `stat` db age, `aide --check` |
| osquery | `/etc/osquery/osquery.conf` | `osqueryi "select * from file_events"` style reads |
| Vendor agents | `/etc/datadog-agent/`, `/etc/fluent-bit/fluent-bit.conf`, `/etc/promtail/config.yml` | `systemctl status` + glob-grep of log sources |
| Scheduling | `systemctl list-timers`, `/etc/cron.d/`, `/etc/crontab`, `/var/spool/cron/` | list-timers grep for aide/logrotate |

## Patterns & Signatures

Config-as-code sweeps (repo root; ripgrep `-g` globs cover Ansible, cloud-init, Terraform, Dockerfile, Packer):

```bash
rg -n 'Storage\s*=\s*(volatile|none)' .                       # explicit volatility — always a finding in IaC
rg -n --glob '*.j2' --glob '*.conf' '@@|omfwd|omrelp' .       # shipping present at all?
rg -Ln 'auditd|auditctl' playbooks/ roles/ k8s/               # files with NO audit mention (-L = files WITHOUT match)
rg -n 'rm\s+-rf\s+/var/log|journalctl\s+--vacuum|unset\s+HISTFILE|history\s+-c' scripts/ ci/   # scrub patterns — AMI bake OK at build time, NEVER at boot/runtime
rg -n 'apt-get remove.*rsyslog|microdnf.*rm.*rsyslog|dnf.*remove.*audit' Dockerfile* */Dockerfile*   # slimming images that strip telemetry
rg -n '/var/log/journal' cloud-init* user-data* packer*        # does provisioning create the persistent dir at all?
rg -n 'aideinit|aide --init|osquery' .                        # FIM wired into provisioning or missing entirely
```

Shape signatures to recognize:

- `Storage=auto` default + no `/var/log/journal` created anywhere in provisioning = volatile-at-runtime even though the config file looks innocent — the most common silent gap.
- rsyslog config containing only a catch-all like `*.*;mail.none;authpriv.none -/var/log/syslog` variants WITHOUT a positive `authpriv.*` line: auth events routed to nowhere.
- `@` single-at forwarders: legacy UDP — flag transport quality even though "forwarding exists."
- logrotate wildcard entry `/var/log/*` plus app-specific entries can double-rotate the same file (state conflicts) — check overlap when both exist.
- Provisioning scripts running `journalctl --vacuum-time=1s` or clearing histories at BOOT (not bake time): either sloppy templating or deliberate trace-scrubbing — investigate ownership either way.

## Taint Tracing Guidance

"Taint" here = exposure chaining into undetectability. Trace three directions:

1. **Exposure × gap matrix.** Pull the listener inventory from the FW module, then join each internet-reachable surface against this module's gaps:

| Entry point | Logging gap | Combined outcome | Band |
|---|---|---|---|
| Internet SSH :22 + password auth (BASE) | No auth logging anywhere | Brute force → takeover with zero trail | High |
| Internet SSH :22 | Logs exist but local-only, no integrity plan | Cleanup phase erases every trace post-takeover | High |
| App RCE as service acct | No auditd identity/scope watches | Privilege escalation steps unrecorded at kernel layer | Medium→High with exposure |
| Any foothold | No AIDE/FIM | Backdoor binaries persist undetected across reboots | Medium |
| Internal-only host | Volatile journald only | Reboot-fragile history; limited blast radius | Low→Medium |

Severity RISES with exposure: identical gaps score a band higher per additional trust boundary crossed by an attacker targeting that host.

2. **Repo taint tracing.** Follow WHERE log config is generated: Ansible templates and jinja2 conditionals, cloud-init `runcmd`, Packer/AMI bake scripts. Taint sources: image-slimming steps removing rsyslog/auditd/AIDE, conditionals like `when: env != 'prod'` skipping telemetry roles, base images whose `/var/log/journal` was never created. The rendered host is ground truth — repo says intent, Sections 1–10 say reality.

3. **Telemetry data-flow tracing.** Treat each record's path as a pipeline to verify end-to-end: producer (sshd/PAM/kernel) → file (journald/auth.log) → shipper (rsyslog forwarder / vendor agent) → collector → alert channel. A break at ANY hop is a blind spot even when upstream layers pass: agent installed but glob excludes auth.log; forwarding rule present but collector firewall blocks 514; alerts wired but delivered via email relayed BY the monitored host (dies with it). Two cross-module taints corrupt everything downstream: unsynchronized clocks (BASE) break timeline correlation across hops, and secrets flowing INTO logs (HSECRET) turn your forensic asset into a liability.

## Exploitation & Reproduction

READ-ONLY demonstrations only — prove each finding from live state without changing anything.

**D1 — Prove volatile-only journald.** Config shows the default in force, disk shows no persistent store:

```
$ grep -RhE '^\s*#?\s*Storage' /etc/systemd/journald.conf
#Storage=auto                          <- default applies
$ ls -ld /var/log/journal 2>&1
ls: cannot access '/var/log/journal': No such file or directory
$ journalctl --list-boots --no-pager
 0 ... <current boot id> ...           <- exactly one boot known to the journal
```

Narrative for the report: correlate with the change calendar — the maintenance reboot of two weeks ago demonstrably happened (uptime reset), yet the journal contains NO entries before the current boot. Every log line emitted since provisioning until that reboot is unrecoverable. Repeat after any future reboot: today's evidence evaporates identically. That is the volatility finding made concrete.

**D2 — Prove no auditd.**

```
$ systemctl status auditd
Unit auditd.service could not be found.
$ auditctl -s
-bash: auditctl: command not found
$ ls /etc/audit/rules.d/ 2>&1
ls: cannot access '/etc/audit/rules.d/': No such file or directory
```

No package, no unit, no rules: account changes (`useradd`, sudoers edits, authorized_keys writes via shell) leave zero kernel-level records. Combined with D1/D3 this is the no-auth-logging anchor.

**D3 — Prove no remote shipping.**

```
$ grep -RnsE '^[[:space:]]*[^#]*(@@|@)[a-zA-Z0-9._:-]+|omfwd|omrelp' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
(no output)
$ ss -tunap 2>/dev/null | grep -E ':(514|6514|2514)\b'
(no output)
```

Empty greps plus no vendor-agent unit (Section 11) plus no platform drain: nothing leaves the box. 

**D4 — Why local-only logs are worthless (attacker narrative, qualitative).** Standard post-exploitation hygiene on ANY Linux intrusion includes trace removal: truncate or selectively delete auth/syslog files, vacuum or wipe the journal, clear shell histories, rewrite wtmp entries. An attacker with root controls every byte on the local filesystem — including the logs about them. They can edit lines out of files rather than delete whole files, leaving plausible-looking but doctored history. Therefore: hosts shipping logs nowhere are not "logged hosts," they are hosts with *optional* logs — evidence exists solely at the attacker's discretion. This narrative is the standing justification for the off-host shipping requirement (Remediation F5); demonstrate it in reports by pairing D3's empty output with D1's missing-history proof, never by wiping anything yourself.

## Remediation

### F1. Persistent, Capped journald (# FIXED)

`/etc/systemd/journald.conf.d/99-hardening.conf`:

```ini
# FIXED — persistent journal with bounded footprint
[Journal]
Storage=persistent
SystemMaxUse=1G
SystemKeepFree=2G
MaxRetentionSec=90day
ForwardToSyslog=yes
```

Activate (creates the store and re-executes journald without a reboot):

```bash
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald
```

Size the caps to the disk: `SystemMaxUse` ≈ 5–10% of `/var`, `SystemKeepFree` large enough that other services never starve.

### F2. auditd Baseline Ruleset and Enablement (# FIXED)

Deploy the Section 6 `# FIXED` ruleset verbatim as `/etc/audit/rules.d/50-baseline.rules`, then:

```bash
sudo augenrules --load                 # compile rules.d -> running kernel (no reboot needed for -w/-a lines)
sudo systemctl enable --now auditd     # Debian pkg: auditd · RHEL pkg: audit
```

Hold back `-e 2` until the watches are validated in production (Verification V2) — once loaded with `-e 2`, ANY change requires a maintenance-window reboot. Sequence: load without the lock → verify V1–V3 for one week → add `-e 2` during the next scheduled reboot window → record the lock in the runbook.

### F3. auditd.conf Space-Survival Policy

Replace the defaults in `/etc/audit/auditd.conf`:

```text
max_log_file = 256
num_logs = 10
space_left = 1024
space_left_action = email        # requires working MTA; else use syslog
action_mail_acct = root
admin_space_left = 512
admin_space_left_action = suspend   # integrity-first assets: halt (see tradeoffs, What To Check 8)
```

Verify the mail path actually delivers before trusting `email`; an unconfigured MTA turns this into silent no-op alerting.

### F4. AIDE Baseline + Daily Check Timer (# FIXED)

Initialize (distro-specific — see Section 9 workflows), then schedule checks.

Cron pattern (works everywhere):

```cron
# /etc/cron.d/aide-check — daily integrity check, results to syslog + report file
0 2 * * * root /usr/bin/aide --check --report=file:/var/log/aide/aide-check.log 2>&1 | /usr/bin/logger -t aide
```

Or a systemd timer pair (`aide-check.timer`: `OnCalendar=daily`, `Persistent=true`) invoking the same `aide --check` service. Pair BOTH with the update discipline: after any legit package operation run `sudo aide --update`, review the reported diffs, then promote `aide.db.new.gz` over `aide.db.gz` — unreviewed promotion defeats the tool, skipped promotion floods it.

### F5. Off-Host Shipping (# FIXED)

Reference shape for rsyslog forwarding to a collector (RainerScript action):

```bash
# FIXED — /etc/rsyslog.d/90-forward.conf : ship everything, TCP transport
*.* action(type="omfwd" target="logcollector.internal.example.com" port="514" protocol="tcp"
           action.resumeRetryCount="-1" queue.type="linkedList" queue.size="10000")
```

Transport hardening: plain TCP/514 guarantees delivery but is plaintext — upgrade the same `omfwd` action to TLS per the rsyslog documentation (gtls network-stream driver with certificate parameters), or prefer RELP via the `omrelp` output module for delivery-plus-integrity semantics; consult https://www.rsyslog.com/docs/ for the exact parameter set of your installed version rather than copying TLS flags blind. Ensure `ForwardToSyslog=yes` (F1) so journal records reach rsyslog, keep journald→rsyslog→collector as the chain, or cover journald directly with systemd-journal-remote push/receivers where rsyslog is absent. Ship auth AND audit streams; point auditd's own remote path (audisp remote plugin family) at the collector if audit volume justifies it. The collector must live on separate infrastructure — same-host "off-host" is D4's narrative again.

### F6. Retention and Permission Hardening

- logrotate: ensure entries for auth/syslog/app logs rotate weekly-to-daily with `rotate 12` or better compressed; fix world-readable hits with `chmod o-rwx` and correct ownership (`chown root:adm` Debian-family auth.log; RHEL-family secure stays `root:root`).
- Archive beyond hot retention off-host (compressed), and for regulated contexts land copies in WORM/object-lock storage so retention cannot be shortened post-hoc.
- Add log-partition monitoring before capacity forces evidence deletion (see F7 thresholds).

### F7. Alert Threshold Starter Set

| Event | Source | Where (alert lands) | Alert-worthy? |
|---|---|---|---|
| SSH auth failures ≥20/5min from one source | auth stream grep/agent | External monitor/SaaS | Yes — brute-force signal |
| Any new line in authorized_keys | AIDE/osquery watch + auditd | Same | Yes — always page |
| New UID-0 account or sudoers change | auditd `-k identity`/`-k scope` | Same | Yes |
| Auditd hit on any watched file | auditd → collector | Same | Yes |
| `/var/log` Use% >85% | df metric agent | Same | Yes — logging at risk |
| Unit restart loop ≥5/15min | systemd/journald agent | Same | Yes |
| Certificate expiry <7 days | TLS module check job (cross-ref) | Same | Yes |
| Unexpected AIDE diff outside change window | aide --check cron/timer | Same | Yes |

Route ALL of these through infrastructure the monitored host cannot silence: external SMTP relay, hosted monitoring SaaS, or dedicated collectors on separate failure domains. Email relayed BY the audited host (or dashboards served BY it) is a single point of failure that dies exactly when needed.

### F8. Deeper Telemetry Options (category pointers)

- osquery/eBPF-based runtime telemetry: fleet-scheduled queries plus eBPF sensors yield process/network/file-event streams beyond static auditd rules.
- Fleet-wide live-response collection tooling (Velociraptor category): remote triage collection across many hosts without per-host shell archaeology.
- Canarytoken/honeytoken deployment: planted credentials, files, or URLs that page on first touch (canary cross-ref: backup-dr canaries).

## Verification & Validation

V1. End-to-end auth logging (after F1/F5): emit `logger -p auth.info "LOGMON-TEST-$(date +%s)"`, then confirm it lands in `/var/log/auth.log` (Deb) or `/var/log/secure` (RHEL), AND in the journal (`journalctl -t logger --since -5min`), AND on the collector side if F5 shipped. A test message visible at every hop is the only proof the pipeline works — file text never is.

V2. auditd rules live (after F2): `auditctl -l` [ROOT] must list every `-w` watch and the four time-change syscall rules; diff against the rules file. Functional probe without semantic mutation: re-apply a file's own mode (`chmod $(stat -c %a /etc/passwd) /etc/passwd` — no-op chmod still updates ctime), then `ausearch -k identity --interpret --recent` shows the event. After enabling `-e 2`: `auditctl -s` reports `enabled 2`, and an attempted live edit returns Operation not permitted — that failure IS the pass condition for immutability.

V3. AIDE healthy (after F4): `aide --check` completes clean immediately after baseline init; then a deliberate canary (create one file inside a watched dir during a change window, expect exactly one diff, remove it) proves detection actually fires; db age via `stat` stays under 7 days with the update discipline running.

V4. Negative/volume sanity: after 24–48h of normal operations the alert channel shows NO pages from the F7 set (thresholds tuned so routine logins/deploys don't trip); audit volume sane via `aureport --summary` [ROOT] (identity/scope events counted in tens per day, not thousands — thousands means an over-broad rule crept in); journal growth bounded by checking `journalctl --disk-usage` twice a day apart against `SystemMaxUse`.

V5. Regression notes: (a) immutable `-e 2` WILL confuse future admins attempting live rule edits — document the lock, the unlock-by-reboot procedure, and the owning team in the runbook BEFORE enabling; (b) patch nights invalidate the AIDE db — pair `aide --update` into the same runbook step as package operations or V4's clean-channel check erodes within weeks; (c) distro upgrades can replace rsyslog/journald defaults — re-run the Where To Look sweep after major version upgrades and compare to the stored pre-change baseline.

V6. IaC regression greps (post-fix; hits must be explainable or gone):

```bash
rg -n 'Storage\s*=\s*(volatile|none)' .                       # must return nothing
rg -Ln 'auditd' roles/ playbooks/ | grep -v node_modules      # telemetry roles applied everywhere
rg -n 'omfwd|omrelp|@@' infra/                                # shipping wired in rendered configs
```

## Severity Assessment

Anchor findings to CVSS v3.1 vectors. Detection-absence framing throughout: severity RISES with exposure because an unmonitored internet host cannot bound attacker dwell time.

HIGH — No auth logging at all on an internet-exposed host (no persistent journal, no auth.log/secure, no auditd, nothing ships off-host): compromise of such a host is undetectable for its entire lifetime; treat worst-case as full host takeover going unnoticed. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.1 High).

HIGH — Logs exist locally but no remote copy AND no integrity plan (no WORM, no FIM, plaintext-or-nothing transport) on an internet host: standard post-exploitation cleanup renders every recorded event worthless; forensics start from zero. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.1 High).

MEDIUM — Volatile-only journald (Storage=volatile or auto-without-store): full forensic loss per reboot; reboot is attacker-forceable, making evidence lifetime attacker-chosen. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N (5.2 Medium).

MEDIUM — No auditd on an internet-reachable host while basic auth logging exists: identity/privilege escalation steps unrecorded at the kernel layer; detection depends wholly on userspace logs the intruder can edit. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.2 Medium).

MEDIUM — No alerting path (or alerts land in-band on the monitored host): coverage exists but nobody is paged out-of-band when it matters; detection latency unbounded. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.2 Medium).

LOW — Firewall drop-logging absent (rate-limited design lives in FW module; here only the lost visibility signal). CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N (3.1 Low).

LOW — Short retention (<30 days hot, no archive): incidents discovered late lose their own evidence window. CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N (3.3 Low).

Modifiers: stack two Mediums on the same exposed host (e.g., volatile journal + no alerting) and report the COMBINATION at High with both vectors cited; internal-only hosts justify one band lower; documented platform-delegated logging (see False Positives) can neutralize specific gaps entirely.

## Common False Positives

- Managed Kubernetes nodes: node-level logging may be delegated to platform daemons (DaemonSet shippers, API-server audit policy). Do not fail the node for missing local rsyslog IF you verify the platform drain actually captures NODE auth events (`/var/log/auth.log`, sshd) — most default pipelines ship container stdout only, which leaves node SSH brute force invisible.
- Cloud provider equivalents count as remote shipping ONLY when verified: serial-console capture plus CloudWatch/Cloud Logging/Ops Agent/Azure Monitor agents are legitimate off-host copies — but check the agent's actual source globs include auth.log/secure rather than assuming "the cloud handles logs."
- journald false alarm: `#Storage=auto` with `/var/log/journal` PRESENT (many cloud images pre-create it) is already persistent — check the directory and `--list-boots` before flagging; conversely explicit `Storage=volatile` is always real.
- rsyslog "absent" on minimal systems where journald is persistent AND forwarded by another mechanism (vendor agent, systemd-journal-remote): absence of one component is fine; absence of ALL consumers is the finding.
- auditd rules present on disk but auditd inactive, or AIDE installed with an uninitialized/year-old database: presence ≠ functioning; only runtime state (`auditctl -l`, fresh db mtime) earns a pass.
- Dev/laptop-class boxes explicitly excluded from scope: honor the documented exclusion rather than reporting noise — but get the exclusion in writing; undocumented exclusions stay findings.

## References

- auditctl(8) — rule syntax, `-e 2` immutable mode, status fields: https://man7.org/linux/man-pages/man8/auditctl.8.html
- auditd.conf(5) — space_left/admin_space_left actions, max_log_file_action values: https://man7.org/linux/man-pages/man5/auditd.conf.5.html
- aureport(8) / ausearch(8) — audit report and search tools: https://man7.org/linux/man-pages/man8/aureport.8.html · https://man7.org/linux/man-pages/man8/ausearch.8.html
- journald.conf(5) — Storage= semantics (auto/volatile/persistent/none), SystemMaxUse, ForwardToSyslog: https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html
- rsyslog documentation (omfwd/omrelp/imfile modules, TLS forwarding): https://www.rsyslog.com/docs/
- AIDE manual — config rules, init/update/check workflow: https://aide.github.io/
- CWE-778: Insufficient Logging — https://cwe.mitre.org/data/definitions/778.html
- CWE-223: Omission of Security-relevant Information — https://cwe.mitre.org/data/definitions/223.html
- OWASP Top 10:2021 A09 – Security Logging and Monitoring Failures — https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
- OWASP Cheat Sheet Series: Logging Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- CIS Benchmarks (distribution L1/L2 sections 4.x Logging and Auditing — source of the baseline watch/time-change sets): https://www.cisecurity.org/cis-benchmarks
