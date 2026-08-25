# Backup & Disaster Recovery — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind backup inventory and coverage gaps, the 3-2-1-1-0
tiering pattern, encryption and key custody, restore drills, and ransomware
resilience structure; SKILL.md carries the exact sweeps, worksheets, and
remediation skeletons.

## How this class emerged

Copying important records to a second place predates computers — double-entry
ledgers were stored in duplicate for exactly the reasons this module audits.
The computing era formalized rotation schemes: grandfather-father-son tape
cycles, named after mid-century accounting practice, established that copies
need *generations*, not just existence.

Modern doctrine accumulated in layers:

- **The 3-2-1 rule crystallized in the 2000s.** Three copies, two different
  media types, one offsite spread from professional photography practice into
  general guidance, echoed by government tips on data backup. It answers disk
  death and site loss — but says nothing about adversaries.
- **Ransomware rewrote the threat model.** Modern extortion operations do not
  merely encrypt production; they locate and destroy backups first, using the
  very administrative credentials IT uses daily. High-profile late-2010s and
  2020s incidents taught one lesson repeatedly: any copy reachable with the
  same credentials (or the same control panel) that destroys production is a
  second casualty, not a backup.
- **Immutability became an affordable answer.** Write-once object storage
  with retention locks (S3 Object Lock-class features, GA around 2017–2018)
  plus client-side encrypted tools (Borg/restic lineages encrypt by default;
  age arrived in 2019 as a deliberately small tool) made "one offline or
  immutable copy" practical. Industry guidance extended the rule accordingly:
  3-2-1-1-0 — three copies, two media, one offsite, one offline/immutable,
  zero errors on restore tests.
- **Proof became the metric.** The final digit encodes the oldest truth in
  the field: a backup never restored is a hypothesis, not a capability.
  Restore drills moved from nice-to-have to the definition of done.

The recurring lesson across every layer: each safeguard targets a specific
failure someone actually suffered — fire, typo, disk death, destroyed
credentials, silent corruption, untested recovery. Skipping one re-imports
that failure.

## Anatomy: four green jobs, zero recoverability

A minimal generic weak configuration needs one crontab. Picture a small
production host:

```
0 2 * * * tar czf /backups/etc.tar.gz /etc              # Tier 0: same disk
30 2 * * * cp -a /var/lib/mysql /backups/mysql          # live datadir copy
0 3 * * * restic backup /srv/app                        # encrypted... but:
#   RESTIC_PASSWORD_FILE=/root/restic.pass              # key on THIS host
#   no alerting hook, no manifest, no drill ever run
```

Walkthrough of how this fails:

1. The MySQL job copies a running data directory — files mid-write. Every
   "successful" archive is silently corrupt; restoration was never attempted,
   so nobody knows.
2. The restic job captures `/srv/app` but its exclude filters drop `.env`,
   so even a perfect restore cannot boot the app. Coverage gaps are invisible
   until needed.
3. Friday 23:00: an attacker with admin-equivalent access deletes backup jobs
   and archives (same credential plane), then encrypts production. The key
   file dies with the encrypted host — even surviving ciphertext is now
   unreadable rubble.
4. Monday 09:00 operations notices. There is no failure alerting (the wiped
   jobs reported nothing all weekend), no runbook, no drill history — nobody
   knows dump/server version compatibility, which DNS or certificate
   dependencies must reattach, or what RTO was ever promised.
5. Effective RPO inflates from hours to forever. Four jobs ran green for
   years; capability was zero the entire time.

Every plane failed quietly: capture (wrong method, filtered paths),
destination (same plane), keys (co-located), proof (never tested).

## Why naive fixes fail

- **Moving copies to a NAS writable with the same admin credentials.**
  Destination changed; credential plane did not. The attacker deletes both in
  one session. Separation must include identity, network zone, and control
  panel — not just geography.
- **Encrypting everything but storing keys beside the archives (or only on
  the backed-up host).** Both horns are fatal: co-located keys mean the
  ransomware reads your backups too; sole-copy keys lost with the host mean
  permanent loss. Key separation is a two-sided constraint needing escrow
  ceremony BEFORE the first encrypted run.
- **Adopting restic/Borg and skipping the custody decision.** The tools
  encrypt by default — which relocates the risk into passphrase management
  rather than eliminating it.
- **Testing only tiny single-file restores forever.** The drill ladder runs
  full-host rebuild > single-service > point-in-time file. A team that has
  only ever extracted one config file has proven almost nothing about RTO or
  version compatibility.
- **Counting replication or snapshots as backups.** Replication faithfully
  propagates deletions and corruption; snapshots typically share the storage
  plane they protect. Only independent point-in-time copies with retained
  history qualify.
- **Manifests as immutability theater.** Checksum manifests stored WITH the
  archives catch truncation and bit-rot — hygiene, not protection against a
  determined attacker who rewrites both.
- **Setting immutable retention without budget review.** Compliance-mode
  locks cannot be shortened early; immutable storage grows monotonically.
  Quarterly cost review rides alongside retention policy.
- **Restoring over live paths during drills.** Practice belongs in isolated
  locations; overwriting production to prove you can recover it is a
  self-inflicted outage.

## Common misconceptions

1. "Green monitoring means we can recover." Job success proves capture ran,
   nothing more. Last-successful-TEST beats last-successful-RUN every time.
2. "Cloud providers handle durability, so DR is included." Provider durability
   answers their hardware failing — not accidental deletion, credential
   compromise, or region loss under your own account. You own tiering.
3. "Encryption guarantees safety." Encryption guarantees confidentiality
   relative to key custody. Custody decides whether YOU can also decrypt.
4. "We're too small to target." Modern ransomware spreads opportunistically
   via automation; targeting is optional. Structure matters at every size.
5. "Backup admin can share domain/prod credentials." Shared identity collapses
   the credential plane; separation of administration IS the control.
6. "Snapshots are my backup tier." Same-array snapshots share fate with the
   volumes they image; treat them as operational convenience unless
   independently exported.
7. "Restore is just copying files back." Version compatibility, DNS/TLS/
   secret dependencies, and recovery ORDER (registrar → vault → certs → IaC →
   data) decide whether copied files become a working service.

## How professionals think about it today

A backup is a system with four planes — Capture, Destination, Keys, Proof —
and a failure in ANY plane makes the other three worthless. Findings map onto
SKILL.md's objectives like this:

| Plane / domain | Typical gap | Defining control |
|---|---|---|
| Inventory & coverage | unreferenced volumes, upload dirs | exists-to-capture diff naming missed paths |
| Capture safety | live-datadir copies, dropped .env | logical dumps (`pg_dump`, `--single-transaction`) |
| Destination discipline | Tier-0-only datasets | 3-2-1-1-0 scoring per dataset |
| Keys & custody | co-located or sole-copy keys | two-custodian escrow, annual decrypt proof |
| Monitoring & honesty | dead-mail alerting, zero-byte successes | exit-code hooks, size floors, manifests |
| Recoverability evidence | no runbook, no drill dates | quarterly ladder calendar, Last-tested fields |
| Ransomware structure | shared credential planes | separated backup identity, immutable tier, canaries |

Chain tracing is the reporting discipline: capture integrity, copy survival,
decryptability, recovery order — name the deepest broken chain, because that
is where remediation starts.

## Read next

In `../SKILL.md`: **Scope & Objectives** (eight priorities), **Prerequisites
& Vocabulary**, **Mental Model** (four planes table + core axioms), **What To
Check** (eight numbered sections incl. ransomware structure), **Where To
Look** (artifact table + read-only sweep), **Patterns & Signatures** (job
signature table, master gap table), **Taint Tracing Guidance** (Chains A–D),
**Exploitation & Reproduction** (Demos 1–4 incl. tabletop walkthrough),
**Remediation** (job skeleton, alert hooks, key ceremony, runbook skeleton,
worksheets), **Verification & Validation** (positives, negative tests,
regression notes), **Severity Assessment** (operational anchors), **Common
False Positives**, **References**.

Sibling modules: `../db-server-hardening/SKILL.md` (logical-dump mechanics
per engine), `../host-secrets/SKILL.md` (the secret sets your excludes keep
dropping), `../logging-monitoring/SKILL.md` (alert wiring and silence-as-
signal for backup channels), `../firewall-edge/SKILL.md` (network zones
separating backup planes), `../kubernetes-cluster/SKILL.md` (CronJob captures
and volume inventory), `../updates-patching/SKILL.md` (version-compatibility
drift between dumps and rebuilt servers).
