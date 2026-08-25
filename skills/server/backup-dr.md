---
name: server-backup-dr
description: Audits backup hygiene and disaster-recovery readiness for Linux hosts — job inventory and coverage-gap analysis, destination tiering against the 3-2-1-1-0 pattern, encryption and key-custody posture, restore documentation and drill evidence, and ransomware resilience — using read-only discovery sweeps, fill-in RTO/RPO and recovery-order worksheets, and remediation skeletons.
category_slug: DR
cwe: [CWE-16]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit one host (or its config-as-code) for whether data can actually come back after loss. Work in priority order:

1. **Backup inventory** — enumerate every scheduled capture mechanism: systemd timers, system cron, per-user crontabs, hand-rolled scripts whose names or contents mention `backup|dump|rsync|restic|borg|sync|snap`.
2. **Coverage gap analysis** — build the inventory of what EXISTS to capture (databases, app upload dirs, container volumes, TLS keys, `/etc` state, object-storage-resident data) and diff it against the paths the jobs actually reference. Unreferenced items are findings with the missed path named.
3. **Capture safety** — flag filesystem copies of RUNNING databases (corruption trap); require logical dumps (`pg_dump`, `mysqldump --single-transaction`). Hunt rsync excludes/filters that silently drop `.env` and secret sets.
4. **Destination discipline** — classify each copy's landing zone: same filesystem, second disk, NAS/LAN, offsite VPS, object storage. Score against 3-2-1 (three copies, two media, one offsite) plus the 3-2-1-1-0 addendum (one offline/immutable, zero errors on restore tests).
5. **Encryption & key custody** — determine whether stored copies are ciphertext, locate the decryption keys, and apply the key-separation rule (keys must not live ONLY beside the archives or ONLY on the backed-up host).
6. **Monitoring & verification** — failure alerting on jobs, suspicious-success detection (zero-byte/tiny outputs), checksum manifests, size-trend baseline.
7. **Recoverability evidence** — runbooks mentioning restore, drill history, defined RTO/RPO, completed recovery-order worksheet.
8. **Ransomware resilience structure** — credential-plane separation between production and backup administration, immutability/offline tiers, delete-protection windows.

Out of scope (cross-references): database engine hardening itself → DB (skills/server/db-server-hardening.md); secret contents and env-file permissions → HSECRET; log shipping and alert-pipeline plumbing → LOGMON (skills/server/logging-monitoring.md); TLS termination → TLS; firewall reachability proofs → FW.

Operating rules:

- Everything here is READ-ONLY observation: list timers, grep configs, `stat` files, read docs. Do NOT run, trigger, dry-run, or "helpfully test" any backup or restore. Do not create, move, or delete archives. If interrupted mid-audit, report exactly which sections completed and which did not — never imply a sweep happened that did not.
- Commands needing root are tagged `[ROOT]`. Without root, audit what cron spools and unit files expose world-readable and say so in findings.
- Absence of evidence is its own evidence class: "no runbook found" is not "runbook impossible". Record WHERE you searched, then ask the operator where docs live before crediting or condemning.
- Tool mentions (restic, borg, rclone, S3-compatible storage) are examples, not endorsements, unless the site already runs them.

## Mental Model

A backup is a system with four planes. A failure in ANY plane makes the other three worthless:

```
Plane         Question answered                  Classic silent failure
------------  ---------------------------------  -------------------------------------------
CAPTURE       Does a job grab ALL the real data? .env filtered out; running-DB file copy;
                                                 container volumes never referenced
DESTINATION   Does the copy survive losing       tar.gz onto the same disk; NAS writable
              the source?                        with the same admin creds; unlocked bucket
KEYS          Can the right party decrypt and    key beside the archives (attacker takes
              the wrong party not delete?        both) or key nowhere (nobody recovers)
PROOF         Has a restore ever succeeded?      jobs ran green for years; first restore
                                                 attempt is during the outage
```

Core axioms:

- A backup that has never been restored is a hypothesis, not a capability. The highest-value finding in this module is missing PROOF, not missing software.
- Any copy reachable with the same credentials or the same host access that destroys production is not a backup against that attacker — it is a second casualty. This axiom drives the offsite, offline, and immutable requirements.
- Replication is not backup: replication faithfully propagates deletions and corruption too. Only independent point-in-time copies with retained history qualify.
- RPO = maximum tolerable data loss (bounded by how fresh the newest restorable copy is). RTO = maximum tolerable downtime (how long until service is back). Both are BUSINESS answers extracted into the worksheet in Remediation — an auditor collects them, never invents them.
- Encryption defaults matter: restic and Borg encrypt client-side BY DEFAULT; plain `tar`, `rsync`, `scp`, `gsutil cp`, `aws s3 cp` store whatever bytes were sent — plaintext at rest unless wrapped first (gpg/age). Detect posture from tool identity and wrappers, not optimism.
- Same-host copies defend against `rm -rf` typos and dead disks only — near-zero value against ransomware or an intruder, which is the threat model this module prices findings against.

## What To Check

### 1. Enumerate scheduled captures

- `systemctl list-timers --all --no-pager`, then `systemctl cat <unit>.timer <unit>.service` for each suspicious hit — ExecStart names the tool and targets.
- System cron: `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*`.
- User crontabs: `crontab -l` for your user; `[ROOT] crontab -l -u USER` per interactive/service account; spools at `/var/spool/cron/crontabs` (Debian) or `/var/spool/cron` (RHEL).
- Script hunts by filename AND content under `/usr/local/sbin`, `/usr/local/bin`, `/opt`, `/root/bin`: patterns `backup|dump|rsync|restic|borg|snap|sync`.
- Container schedulers when in scope: Kubernetes `kind: CronJob` manifests and Docker host cron entries driving `docker exec ... dump`.

### 2. Build the exists-to-capture inventory, then diff

Cross-reference the DB module's listening-port inventory technique (`ss -tlnp`):

- Engines present (5432 postgres, 3306 mysql/mariadb, 6379 redis, 27017 mongo) each need a NAMED capture path — logical dump or engine-native snapshot with proven restore.
- App roots (`/srv`, `/opt/<app>`, `/var/www`): locate upload/user-content directories and `.env`-style config files.
- Container runtime: named volumes (`docker volume ls`, `/var/lib/docker/volumes`) and bind mounts from compose/manifests.
- TLS material: `/etc/letsencrypt`, `/etc/ssl/private`, any private-CA keys.
- Host config state: `/etc` itself; package manifest if jobs save one (`dpkg -l`, `rpm -qa` output files).
- Data living OFF the host: buckets/endpoints referenced in `~/.config/rclone/rclone.conf`, `.env` vars like `S3_*`/`B2_*`, cloud profiles — decide who backs THOSE up; host-local jobs usually do not.

Diff method: inventory item → which job references it? No reference = coverage-gap finding naming the exact missed path.

### 3. Judge each job's capture method

- Databases: any `cp`/`tar`/`rsync` of a live datadir (`/var/lib/postgresql`, `/var/lib/mysql`) while the service runs = corruption-trap finding. Proper shapes: `pg_dump` / `pg_dumpall -Fc`; `mysqldump --single-transaction` (consistent for InnoDB; state honestly that MyISAM tables still need lock handling); engine-appropriate equivalents for redis/mongo.
- Excludes: rsync `--exclude`/filter rules dropping `.env*`, `secrets/`, key dirs silently → restored app cannot boot.
- Output handling: single overwriting archive vs dated rotation; retention window stated anywhere? Error handling beyond default cron mail?

### 4. Classify destinations (tier scoring)

For every job, determine where output lands:

| Tier | Location | Survives |
|---|---|---|
| 0 | same filesystem/device as source (`df` device match) | nothing serious — typo/disk only |
| 1 | second disk/NAS, same host or LAN | disk loss, not ransomware-with-host-access |
| 2 | offsite VPS/object storage over encrypted channel | host + site loss (3-2-1 baseline) |
| -1 add-on | offline/disconnected copy OR immutable target (versioning + Object-Lock-style WORM, qualitative) | attacker-with-admin deleting everything online |

Record which tiers exist PER DATASET, not per host.

### 5. Encryption posture and key custody

- Identify the capture tool from artifacts: restic/Borg repository layout ⇒ client-side encryption by default (verify a passphrase/key file legitimately exists); bare `tar`/SQL/gzip/rsync-only pipelines ⇒ plaintext-at-rest candidate; `gpg`/`age`/`openssl enc` wrappers ⇒ encrypted, then audit key management instead.
- Locate decryption material: `RESTIC_PASSWORD_FILE`, `BORG_PASSPHRASE`/keyfile, age identities, gpg secret keys. Are they ONLY on the backed-up host, or ONLY beside the archives?
- Apply the key-separation rule plainly: keys must be recoverable WITHOUT the production host AND unobtainable to whoever can destroy the archives. Co-located keys mean ransomware reads your backups too; sole-copy keys nowhere mean guaranteed permanent loss. State both horns in the finding; the escrow decision belongs to the owner (ceremony template in Remediation).

### 6. Monitoring, manifests, success honesty

- Does any failure path notify? Look for webhook/curl calls, mail lines to REAL mailboxes, LOGMON-style exit-code hooks. Cron's default root-mail-that-nobody-reads counts as no alerting.
- Suspicious-success checks: zero-byte or tiny outputs passing as success; minimum-size guard present? size-trend baseline recorded anywhere?
- Checksum manifests written post-run and verified in-job (`sha256sum -c`)?
- Track last-successful-TEST (restore drill date) separately from last-successful-RUN — only the first measures capability.

### 7. Recoverability evidence

- Sweep docs/READMEs/runbooks/wiki pointers for restore/recovery/RTO/RPO mentions (commands below).
- Evidence of PAST drills: dated runbook entries, restore-test logs, tickets. Nothing found on production = High finding.
- Drill-ladder coverage: full-host rebuild > single-service restore > single-file/table point-in-time — which levels have ever been exercised?

### 8. Structure against ransomware

- Who can delete the copies? A backup target that accepts the same domain/IAM/admin identity owning production is the SAME credential plane — say so.
- Delete-protection windows: immutability locks, versioning retention, offline rotation gaps — name what exists qualitatively; absence on production datasets is a finding.
- Separate credential plane principle: backup administration must not ride the everyday prod/domain admin identity.
- **Canary/decoy coverage:** are tripwire files planted INSIDE backup targets and data shares (files that should never be touched by legitimate jobs)? A canary that gets encrypted/renamed = active attacker in the backup plane, highest-severity alert (cross-ref LOGMON alerting + DETECT).
- **Pre-encryption indicators watched?** mass-file-rename/rename-to-random-extension bursts, shadow-copy/volume-snapshot deletion analogs on Linux (snapper/LVM snapshots wiped), entropy spikes on file stores, sudden archive-creation by unusual processes — is anything watching for these (auditd rules / eBPF agent / at minimum log-based review)? Absence = detection-blind finding cross-ref LOGMON module.
- **Restore-path independence:** if the only copy lives behind the same control panel/API the attacker now administers, it does not exist. Verify at least one restore path requires OUT-OF-BAND access (provider console with separate MFA, physical media rotation).

## Where To Look

Evidence collection: `tools/sweeps/sweep-backups.sh` captures `[DRB-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

| Path | What it tells you |
|---|---|
| `systemctl list-timers --all`; `/etc/systemd/system/*.timer` + paired `.service` | timer-driven captures; ExecStart tools/targets |
| `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/` | system-level schedules |
| `/var/spool/cron/crontabs/` (Deb) or `/var/spool/cron/` (RHEL) `[ROOT]` | per-user crontabs including service accounts |
| `/usr/local/{sbin,bin}`, `/opt/*/bin`, `/root/bin` | hand-rolled backup scripts |
| `/etc/default/*`, shell rc files, `~/.config/rclone/rclone.conf` | `RESTIC_*`/`BORG_*` env, remote endpoints |
| `ss -tlnp`; `/etc/postgresql*/`, `/etc/mysql/`, `/etc/redis*`, `/etc/mongod.conf` | data stores that must appear in some job |
| `/var/lib/docker/volumes/`, compose/k8s manifests | container-state coverage |
| `/etc/letsencrypt/`, `/etc/ssl/private/` | key material needing explicit capture decisions |
| `/var/backups`, `/srv/backups*`, `/mnt/*backup*`, `/opt/backups` | local destinations: dates, sizes, device identity |
| `README*`, `docs/`, `runbooks/`, wiki links, ticket systems | restore documentation and drill history |
| `terraform/**/*.tf`, cloud modules in repo | versioning / object-lock / SSE declarations for object-storage targets |
| Job logs referenced by scripts (`/var/log/*.log`) | recent run results and output sizes (read-only tail) |

Paste-ready read-only sweep (~20 lines). Observe only; execute nothing that writes or triggers:

```bash
### BACKUP-DR read-only sweep — observe only; run nothing that writes/triggers
systemctl list-timers --all --no-pager | grep -Ei 'backup|dump|sync|snap|borg|restic'
grep -rEni 'backup|dump|rsync|restic|borg|xtrabackup|pg_dump|mysqldump' \
  /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
for u in $(awk -F: '$7!~/(nologin|false)$/{print $1}' /etc/passwd); do
  crontab -l -u "$u" 2>/dev/null | grep -Eni 'backup|dump|rsync|restic|borg' | sed "s#^#$u: #"
done
ls -la /var/spool/cron/crontabs /var/spool/cron 2>/dev/null
find /usr/local/sbin /usr/local/bin /opt /root/bin -maxdepth 3 -type f \
  \( -iname '*backup*' -o -iname '*dump*' -o -iname '*rsync*' -o -iname '*restic*' -o -iname '*borg*' \) 2>/dev/null
for s in $(find /usr/local/sbin /usr/local/bin -maxdepth 2 -type f 2>/dev/null); do
  grep -Hil 'rsync|scp |ssh |restic|borg|rclone|aws s3|gsutil|tar .*czf|pg_dump|mysqldump' "$s"
done
grep -rnE 'RESTIC_PASSWORD|BORG_PASSPHRASE|openssl enc|gpg --|age ' \
  /etc/cron* /etc/systemd/system /usr/local/sbin /usr/local/bin 2>/dev/null      # encryption-presence scan
ls -la /var/backups /srv/backups /mnt/backup* /opt/backups 2>/dev/null            # local destination inventory
df --output=source,target / /var/backups /srv/backups 2>/dev/null                 # same-device = Tier 0 finding
ss -tlnp 2>/dev/null | grep -E ':(5432|3306|6379|27017)'                          # stores to cover (cross-ref DB)
docker volume ls 2>/dev/null; ls /var/lib/docker/volumes 2>/dev/null              # container volumes
find /srv /opt /var/www -maxdepth 3 \( -name '.env' -o -type d -iname '*upload*' \) 2>/dev/null
grep -rn 'kind: CronJob' . 2>/dev/null                                            # k8s scheduled captures (repo context)
ls ~/.config/rclone/rclone.conf 2>/dev/null                                       # off-host storage endpoints exist?
grep -rEil 'restore|RTO|RPO|disaster|runbook' README* docs/ runbooks/ *.md 2>/dev/null   # recoverability docs
```

## Patterns & Signatures

Good-vs-bad signatures as seen in jobs, scripts, and configs:

| Signature | Verdict | Why |
|---|---|---|
| `0 2 * * * tar czf /backups/etc.tar.gz /etc` | BAD | same host/filesystem; no rotation, verification, or alerting |
| `cp -a /var/lib/mysql /backups/mysql-$(date +%F)` | BAD | live-datadir copy → corrupt-on-restore trap |
| `rsync -a --exclude='.env*' /srv/app nas::app` | BAD | secrets dropped silently; plaintext at rest on the NAS |
| `gsutil cp dump.sql.gz gs://prod-backups/` | BAD-PROBABLE | transit-only TLS; no client-side wrap → plaintext-at-rest candidate until proven otherwise |
| `mysqldump appdb > appdb.sql` nightly | WEAK | needs `--single-transaction` for consistent InnoDB capture; MyISAM needs lock handling |
| restic/Borg repo on sftp/s3/b2 endpoint; key escrowed off-host | GOOD | encrypted-by-default capture reaching an offsite tier |
| `gpg --encrypt -r backup-key dump.sql.gz && rclone copy ... out.age` (or age equivalent) | GOOD | ciphertext leaves the host; recipient-key custody then decides the rest |
| wrapper ends with `sha256sum -c MANIFEST.sha256` + output-size floor check + `\|\| alert.sh FAIL` hook | GOOD | integrity verify plus failure AND suspicious-success detection |
| monthly `.timer` running a restore-drill script that writes dated PASS/FAIL evidence | GOOD | converts backup from hypothesis to capability |

Master gap table:

| Gap | Detection method | Risk | Fix direction |
|---|---|---|---|
| Only copy lives on same host/filesystem | `df --output=source,target` device match between source and archive path; job writes under same root | ransomware/attacker deletes both; disk loss kills both | offsite tier via encrypted tool or wrapped uploads |
| Running DB captured by file copy | job greps: `cp\|tar\|rsync` against `/var/lib/{mysql,postgresql}` with no `pg_dump`/`mysqldump` anywhere | restore yields a corrupt cluster exactly when needed | logical dumps: `pg_dump -Fc`; `mysqldump --single-transaction` |
| `.env`/secrets excluded by filters | read exclude/filter args in each job; diff against inventory | restored app cannot boot; secrets unrecoverable | dedicated small encrypted secret-set job; cross-ref HSECRET for storage |
| Unencrypted copies on third-party storage | plain `cp`/`rsync`/`gsutil`/`aws s3 cp` without gpg/age wrap and without restic/borg | provider-side exposure; compliance blast radius | client-side encryption before upload (tool default or explicit wrap) |
| Key stored only beside archives / only on source host | locate `RESTIC_PASSWORD_FILE`, `BORG_PASSPHRASE`, age identity paths | attacker destroys both; or key lost forever | off-host + off-site escrow with two-custodian ceremony (Remediation) |
| No failure alerting | job lacks notify hook; mailto=root unread | dead backups discovered during the outage | exit-code hook → notification channel (LOGMON pattern) |
| Zero-byte/tiny "successful" backups | `ls -la` destination history; no size floor in script | silent-empty captures pass monitoring for months | minimum-size guard + size-trend baseline |
| No restore documentation/runbook | doc sweep returns empty across plausible roots | improvised recovery under outage pressure | per-service runbook skeleton (Remediation) |
| No restore drill ever on sole-backup production | no dated drill logs; operators cannot recall one | unknown RTO; dump/server version surprises mid-crisis | quarterly drill-ladder calendar entry (Remediation) |
| Container volumes/upload dirs unreferenced by jobs | volume/dir list vs job path diff | user content lost even though DB survived | extend capture set paths |
| Replication counted as backup | architecture shows mirrors only; no point-in-time history | deletion/corruption replicates faithfully | independent PIT copies with retained history |

## Taint Tracing Guidance

Trace four dependency chains per dataset. A break ANYWHERE downgrades everything downstream; name the deepest broken chain in the finding.

**Chain A — capture integrity:** scheduler entry → script/tool → source paths → output artifact. Questions: does the binary exist (`command -v`)? do source paths match the inventory? does output land where the script claims? An unset variable or wrong path here produces silent-empty backups — zero-byte successes.

**Chain B — copy survival:** source-host credentials ↔ destination write/delete credentials. Trace: same OS user? same cloud IAM principal/account? same network zone reachable from a compromised prod host? Overlap ⇒ destroying production destroys the copies. Endpoint reachable from the prod host WITHOUT separate authentication ⇒ same plane.

**Chain C — decryptability:** ciphertext artifact → key/passphrase path → custody locations. If the key resolves onto the backed-up host or the archive store, whoever holds either gets plaintext. If it resolves nowhere (departed admin, lost paper), the data is permanently gone. Trace who has EVER decrypted successfully, and when.

**Chain D — recovery order (the meta-chain):** registrar/DNS control → vault/secret store → CA/cert material → IaC/config repo → service-data restores → validation. Each step unlocks the next; a missing upstream link stalls every downstream restore regardless of archive quality. Map which artifact unlocks which step; record gaps in the ordering checklist (Remediation).

Reporting shape: `DB dataset — Chain A ok, Chain C ok, Chain B broken: NAS share writable by the prod service account ⇒ treat as no independent backup.`

## Exploitation & Reproduction

READ-ONLY demonstrations only. Nothing here writes, triggers jobs, or touches archives. Purpose: convert suspicion into evidence a report can quote.

### Demo 1 — prove same-host-only backups (Tier 0)

```
df --output=source,target / /var/backups /srv/backups 2>/dev/null
findmnt -T /backups 2>/dev/null; findmnt -T /
```

Interpretation: identical SOURCE device for `/` and the archive directory ⇒ same disk ⇒ one encryption event or `rm -rf` destroys both. Pair the job line `tar czf /backups/x.tgz /etc` with this device proof and the finding is confirmed. Nuance: NFS/CIFS mounts show different devices but may share the LAN trust zone — record the nuance rather than auto-crediting Tier 2.

### Demo 2 — prove unencrypted dumps (header heuristic)

```
file /srv/backups/app-2026-08-01.sql.gz              # expect: "gzip compressed data"
zcat /srv/backups/app-2026-08-01.sql.gz | head -40   # CREATE TABLE / INSERT visible ⇒ plaintext content
file /var/backups/prod.tar                           # POSIX tar ⇒ plaintext tree
```

Honest limits: recognizable gzip/tar/plain-SQL magic proves there is NO encryption layer around those formats. An opaque `data` verdict means high entropy — that can be legitimate encryption OR exotic compression: mark it INCONCLUSIVE and never credit encryption without tool evidence (restic/Borg repo markers from the sweep). Conversely `.gpg`/`.age` artifacts with matching magic support an encrypted claim. State the heuristic's limits in the finding.

### Demo 3 — prove restore documentation is absent

```
grep -rEil 'restore|recovery|RTO|RPO|disaster' README* docs/ runbooks/ /srv/ops 2>/dev/null
find / -xdev -maxdepth 4 \( -iname '*runbook*' -o -iname '*restore*' \) 2>/dev/null
```

Empty results across plausible roots PLUS operator confirms no wiki ⇒ High finding on production systems. Record exactly where you searched so the negative result is reproducible and fair.

### Demo 4 — tabletop walkthrough: ransomware day-1

No actions performed — walk the findings through hour-one of an incident narrative:

> Friday 23:00 an attacker with domain/admin-equivalent access deletes shares and backup jobs, then encrypts production. Monday 09:00 operations notices.

Walk each module finding through triage:

1. **Detection lag** — no failure alerting meant the wiped jobs reported nothing all weekend; effective RPO inflates from hours to days.
2. **Copy destruction** — Tier-0/NAS copies in the same credential plane were encrypted alongside production; no immutable or offline tier existed to fall back on.
3. **Key loss** — `RESTIC_PASSWORD_FILE` lived on the now-encrypted host; escrow was never arranged ⇒ even surviving archives are unreadable.
4. **Procedure vacuum** — no runbook, no drill ever ⇒ nobody knows dump↔server major-version compatibility, which DNS/TLS/app-config dependencies must reattach, or what RTO was promised.
5. **Secrets-order vacuum** — registrar/vault access undocumented ⇒ rebuild stalls at step zero even if clean media exists.

Prioritization teaching: order remediations by what unblocks day-1 first — offsite immutable copy plus out-of-band key escrow outrank manifest polish; drill evidence is what converts both from theoretical to trusted.

## Remediation

Additions only — jobs, runbooks, policy. Tool choices below are EXAMPLES, not endorsements.

### 1. Offsite encrypted job skeleton

```bash
#!/bin/sh
# /usr/local/bin/offsite-backup.sh — shape only; adapt repo endpoint, paths, schedule
set -u
umask 077
export RESTIC_REPOSITORY="sftp:backup@nas.example.internal:/srv/repos/host1"  # or b2:/s3:/rest: endpoints per restic docs
export RESTIC_PASSWORD_FILE="/etc/backup-keys/restic.pass"                    # escrowed OFF this host FIRST (see ceremony)
fail() { printf '%s\n' "$*" >&2; exit 1; }
command -v restic >/dev/null || fail "tool missing"
[ -f "$RESTIC_PASSWORD_FILE" ] || fail "key file missing"
pg_dump -Fc appdb > "/var/backups/logical/appdb-$(date +%F).dump"             # logical dump, never datadir copy
mysqldump --single-transaction appdb > "/var/backups/logical/appdb-$(date +%F).sql"
restic backup /etc /srv/app/uploads /var/lib/docker/volumes /var/backups/logical || fail "capture failed"
( cd /var/backups/logical && sha256sum ./*.dump ./*.sql > MANIFEST.sha256 ) || fail "manifest failed"
sha256sum -c /var/backups/logical/MANIFEST.sha256 || fail "integrity verify failed"
min_bytes=10485760
actual=$(du -sb /var/backups/logical | awk '{print $1}')
[ "$actual" -lt "$min_bytes" ] && fail "suspiciously small output (${actual}B)"
exit 0
# Retention: add per-tool policy after reading docs — e.g. `restic forget --keep-daily 7 --keep-weekly 4 --prune`
```

Borg alternative shapes: `borg init --encryption=repokey ssh://backup@nas.example.internal/./repo`; `borg create --stats ssh://backup@nas.example.internal/./repo::'{hostname}-{now}' /etc /srv`; `borg prune --keep-daily 7 --keep-weekly 4 <repo>`. Same key-escrow rule applies.

### 2. Alert-on-failure + suspicious-success hook

Reuse the LOGMON exit-code→notify pattern (skills/server/logging-monitoring.md):

```bash
if ! /usr/local/bin/offsite-backup.sh >>/var/log/offsite-backup.log 2>&1; then
  rc=$?
  curl -fsS -X POST -H 'Content-Type: application/json' \
       -d "{\"text\":\"[$(hostname)] BACKUP FAILED rc=$rc\"}" "$ALERT_WEBHOOK_URL" || true
fi
```

Cron one-liner form: append `|| /usr/local/bin/alert.sh "backup failed"` to the entry; ensure mailto targets a MONITORED mailbox. Success-side guard lives inside the script (size floor above); add size-trend logging (`date,size_kb >> /var/log/backup-sizes.log`) and alert on large drops against baseline.

### 3. Checksum manifest addition lines (any existing job)

```bash
( cd /srv/backup-out && sha256sum ./* > MANIFEST.sha256 )   # after capture completes
sha256sum -c /srv/backup-out/MANIFEST.sha256 || notify-failure           # verify step in-job
```

Honest note: manifests stored WITH the archives catch corruption/truncation, not a determined attacker who rewrites both — they are hygiene, not immutability.

### 4. Key ceremony / escrow (mandatory before enabling backup encryption)

- Two custodians hold shares of the passphrase/keyfile; one offline copy in physical safe, one in the organization's primary secret manager — NEVER solely on the backed-up host or beside the archives.
- Annual proof: a custodian decrypts one archive from escrow alone; log the result next to drill records.
- Document rotation; losing keys = permanent data loss, so the ceremony precedes the first encrypted run.

### 5. Restore runbook skeleton (one per service)

```markdown
# Restore Runbook — [SERVICE]
Owner: [team]   Last tested: [YYYY-MM-DD] by [who]   Result: [PASS/FAIL]
## Preconditions
- Access required: [hosts, credentials, break-glass route]
- Dependencies verified: DNS names [...], TLS cert source [...], app config/secrets store [...],
  DB server major version [X] matches dump source [Y]
## Steps
1. Restore into ISOLATED location first: [target dir/host] — never over live paths
2. Data restore commands: [exact commands, exact tool versions]
3. Reattach config/secrets/certs: [...]
4. Cut over traffic/DNS: [...]
## Validation
- [checks proving correct data and version came back]
## Abort criteria & rollback
- [...]
## Evidence log
- [drill dates, measured time vs RTO target, issues found]
```

### 6. Quarterly drill calendar entry

Create a recurring event: "Restore drill — rotate ladder level (full-host rebuild / single-service restore / single-file-or-table point-in-time); restore into isolated location; measure actual time vs RTO target; update runbook Last-tested." Quarterly for production datasets; semiannual acceptable for low-tier systems; annual-or-less is NOT adequate for sole-backup production.

### 7. Fill-in worksheets

RTO/RPO worksheet — fill with BUSINESS answers; blank rows are intentional:

```text
| Service/dataset | Business owner asked | RTO target | RPO target | Current achievable RTO (from drills) | Current achievable RPO (job schedule) | Gap action |
|-----------------|----------------------|------------|------------|--------------------------------------|---------------------------------------|------------|
|                 |                      |            |            |                                      |                                       |            |
|                 |                      |            |            |                                      |                                       |            |
|                 |                      |            |            |                                      |                                       |            |
```

Secrets-recovery ordering checklist — number what must return FIRST; complete before the next incident:

```text
[ ] 1. Registrar/DNS control          (repoint names at rebuilt infrastructure)   custodian: ________
[ ] 2. Vault/secret store             (credentials everything downstream needs)   custodian: ________
[ ] 3. CA/TLS certificate material    (termination, internal trust)               custodian: ________
[ ] 4. IaC/config-as-code repo        (infrastructure reproducibility)            custodian: ________
[ ] 5. ____________________________   (org-specific, e.g. license servers)        custodian: ________
[ ] 6. ____________________________                                               custodian: ________
Last verified end-to-end date: ____________  verified by: ____________
```

### 6. Ransomware-specific hardening additions

**Canary/decoy files inside backup planes** — planted tripwires that legitimate jobs never touch:

```bash
# Place in backup target root + data shares; names attractive to humans and ransomware alike
install -m 400 /dev/null /mnt/backup-target/payroll-master-2026.xlsx   # decoy content
install -m 400 /dev/null /srv/data/vault-keys.kdbx                     # decoy
# Alert-on-touch: auditd watch (adjust paths) -> LOGMON alert wiring
auditctl -w /mnt/backup-target/payroll-master-2026.xlsx -p rwa -k canary-backup
auditctl -w /srv/data/vault-keys.kdbx -p rwa -k canary-data
```

Any `canary-*` key hit = responder pages immediately; document the rule in the alert runbook.

**Immutability validation drill (quarterly, alongside restore drill):**

1. Attempt to delete/overwrite a locked object BEFORE its expiry — expected: provider refuses.
2. Attempt via the BACKUP job's own credentials too (the credential plane test): if the job identity CAN delete locked objects, the lock is theater — reconfigure with a retention-lock service account lacking delete.
3. Record both results in the runbook with dates.

**Pre-encryption indicator watch (minimum viable):** weekly review hook (or auditd/timer where feasible) covering: file-rename storms (`find <share> -newermt '24 hours' | wc -l` baseline-vs-spike), new high-entropy archive files in data dirs, snapshot-pool deletions, unusual `tar`/`7z` executions by non-admin UIDs. Wire spikes to the DETECT paging rubric as SEV1-candidate signals.

**Tabletop stub (30 min, twice yearly):** scenario card "Monday 08:00 — shares show `.locked` extensions, backup console session shows an unfamiliar admin." Walk: who declares, first three actions (isolate/preserve/canary-check), does anyone know the offline copy location + its passphrase custodian? Gaps found = action items feeding this module's findings.

### 7. Policy bullets to adopt

- 3-2-1-1-0 stated as the standard: three copies, two media, one offsite, one offline/immutable, zero errors on restore tests.
- Backup administration identity separated from prod/domain administration (qualitative principle).
- Delete-protection window defined: immutability lock or offline rotation gap sized against assumed attacker dwell time.
- Exclusion lists reviewed quarterly against the inventory diff; retention costs reviewed alongside (immutable storage grows monotonically).

## Verification & Validation

### Post-fix positives

- New job runs ONCE under approved change window and completes to an ALTERNATE destination: confirm the archive/snapshot is listed remotely (`restic snapshots` / `borg list` shape) and the local log shows exit 0.
- Manifest verifies inside the job log: `sha256sum -c` exits 0.
- Test-restore of ONE small dataset succeeds INTO AN ISOLATED LOCATION (single dumped table restored to a scratch instance; one config file extracted to `/tmp/restore-test`) — never over live paths. Record elapsed time toward the RTO worksheet.

### Ransomware-extension pass criteria

- Canary files exist in ≥1 backup target and ≥1 data share; auditd watches active; a test touch (authorized, during change window) fires the alert end-to-end.
- Immutability drill logged with both refusal results (external identity AND job identity) and dates.
- Pre-encryption indicator review has an owner + cadence; at least one tabletop run recorded with action items tracked to closure.

### Negative tests

- Schedule window sits off-peak (for example 02:00–04:00 local); during the approved manual run observe load read-only (`uptime`, `iostat`) and confirm production latency unaffected. Note the agreed window in the runbook so future audits know why the timer fires then.
- Confirm the alert hook does NOT fire on a green run (no false pages): check channel silence after a successful run.

### Regression notes

- Key loss = permanent data loss: the escrow ceremony (Remediation §4) must exist BEFORE the first encrypted run; the annual decrypt-from-escrow test is the regression gate.
- Immutable/locked retention grows cost monotonically — compliance-mode locks cannot be shortened early; budget review each quarter alongside retention policy.
- Dump↔server compatibility drift: pin versions in each runbook; any major-version upgrade requires re-running the drill before old dumps are trusted (PostgreSQL honesty: verify dump format vs target server version support before relying on it).
- Silent exclusion drift: new upload dirs/volumes appear uncovered unless the inventory diff is repeated quarterly.

### IaC repo greps (presence checks)

Absence in code = open question, not automatic fail — consoles may configure outside IaC:

```bash
grep -rni 'object_lock\|object_lock_configuration' terraform/ infra/   # WORM/immutability declared?
grep -rni 'versioning' terraform/ infra/                               # bucket versioning enabled?
grep -rni 'server_side_encryption\|sse_algorithm\|aws:kms' terraform/  # at-rest encryption config
grep -rni 'lifecycle\|noncurrent_version_expiration' terraform/        # retention windows declared
```

## Severity Assessment

This module uses OPERATIONAL severity — recoverability impact under realistic loss scenarios — NOT CVSS vectors. State this explicitly in reports.

| Level | Operational anchor |
|---|---|
| Critical-equivalent | The ONLY copy of production data lives on the same host AND unencrypted; OR sole-backup production systems where no restore was EVER tested |
| High | No offsite copy for production data; backups sent unencrypted to third-party storage; no failure alerting on production backup jobs |
| Medium | Drills annual-or-less; no defined RTO/RPO for production services |
| Low | Missing checksum manifests / size-trend baselines while everything else holds |

Compound rule: a Medium finding escalates one level when the same dataset also breaks Chain B (copy survival) or Chain C (key custody) tracing.

## Common False Positives

- **Managed-platform snapshots** (RDS automated backups, managed Kubernetes etcd snapshots, PaaS database point-in-time): DO credit them — but only after VERIFYING retention is actually configured (>0 days) and cross-region/cross-account copies exist where the 3-2-1 claim needs them. Defaults vary by platform and console claims require config evidence; do not credit what you did not verify.
- **Documented intentional exclusions**: dev/staging datasets deliberately outside backup scope with written rationale are not findings. Undocumented PRODUCTION exclusions are.
- **Continuous replication mistaken for backup**: replicas mirror deletions and corruption in near-real-time; short-history features (for example WAL PITR windows) mitigate partially. Teach the distinction — HA redundancy protects against hardware loss, not against "someone deleted the data" — before crediting replication as a backup tier.
- **Stale archives of decommissioned services** found in destinations: hygiene clutter worth noting, not a coverage gap — do not raise severity for them.

## References

- 3-2-1 rule lineage: US-CERT/CISA tip publications ("Data Backup Options") and UK NCSC guidance describe three-copies/two-media/one-offsite; the 3-2-1-1-0 addendum (one offline/immutable copy, zero restore-test errors) appears in modern industry practice. Cite guidance names qualitatively; no fabricated links.
- restic documentation: restic.net (client-side encryption by default, repository backends, restore workflow).
- BorgBackup documentation: borgbackup.org (encryption modes incl. repokey; `borg create`/`prune` retention patterns).
- age encryption: age-encryption.org (small explicit key model for wrap-before-upload pipelines).
- GnuPG manual: gnupg.org (symmetric/asymmetric wrapping shapes).
- CWE-16 (Configuration), cwe.mitre.org — configuration-class mapping used by this module; no speculative CWE additions.
- OWASP A05:2021 – Security Misconfiguration (frontmatter mapping).
- Product concepts referenced QUALITATIVELY — consult vendor docs for exact flags per deployed version: S3 Object Lock compliance/governance modes, PostgreSQL pg_dump/PITR semantics and version compatibility, MySQL `--single-transaction` behavior across storage engines.
