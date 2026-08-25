# Host Secrets — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind permission bits, the loosest-link rule, key and cert
file discipline, shell-history leakage, database credential files, the
environment-variable boundary, rotation culture, and backup hygiene; SKILL.md
carries the exact sweeps, expected-state tables, and remediation blocks.

## How this class emerged

The Unix permission model — owner/group/other, read/write/execute per file —
dates to the original early-1970s system and was designed for machines shared
by colleagues who were *supposed* to see most things. Secrecy was bolted on:
`/etc/shadow` appeared in the late 1980s precisely because `/etc/passwd` had
to stay world-readable for name lookups while password hashes could not be.
That split (public lookup file + owner-scoped secret file) is the shape every
secret-bearing file still approximates.

Four waves turned file hygiene into a security discipline of its own:

- **Encrypted remote access raised the stakes of key files.** SSH (written in
  1995 after a documented password-sniffing incident) moved authentication
  from typed passwords to private keys sitting in home directories. A 644
  `id_rsa` is now a reusable skeleton key, not a one-off password. sshd's
  `StrictModes` check has refused over-writable home directories for decades —
  evidence that permission mistakes around keys were common enough to build a
  guard against.
- **Applications started carrying their own secrets.** Config-file credentials
  (`settings.py`, `.env`, PHP configs) became standard practice as frameworks
  matured in the 2000s. By the late 2010s, mass internet-wide scanning for
  accidentally exposed `.env` files was routine background noise — the same
  file that works locally becomes an exfiltration prize when any read path
  widens.
- **Twelve-factor-style configuration pushed secrets into environment
  variables.** The influential twelve-factor methodology (2011) told
  applications to take config from the environment; operators complied, and
  database URLs with passwords landed in process environments. The boundary
  there is different from files — kernel-gated per process, but leaking
  sideways through child processes, crash dumps, and debuggers — and whole
  audits have mis-scored it in both directions.
- **Secret managers formalized custody.** Vault-class systems (mid-2010s) and
  encrypted-in-repo patterns (SOPS+age) made dynamic, auditable credential
  delivery achievable. They also introduced the bootstrap problem: some host
  must still hold one unlock capability somewhere.

The constant across all four: defaults distribute secrets for convenience,
and only deliberate path-by-path review pulls them back.

## Anatomy: one readable file, one owned estate

A minimal generic weak configuration needs three lines. Picture a small app
server:

```
-rw-r--r-- 1 svc-api svc-api 512 .env          # DATABASE_URL=postgres://api:PW@db/app
                                               # SMTP_PASSWORD=..., S3 keys...
drwxr-xr-x 2 root     root     deploy-scripts  # cron wrapper inside:
                                               #   mysqldump -uadmin -pS3cret ...
# /root/.bash_history contains both the -pS3cret line and 'export TOKEN=...'
```

Walkthrough of how this fails:

1. One web-app bug yields command execution as `svc-api`. No privilege
   escalation needed: the service account can already read its own `.env`.
2. The DSN hands over the production database with the application's grants;
   SMTP and object-storage keys enable phishing infrastructure and data theft
   under your name. Total elapsed time from foothold to full credential set:
   seconds.
3. The world-readable history and cron script replay older credentials —
   possibly rotated ones still valid because nothing tracked expiry.
4. Any nightly dump landing 644 in `/tmp` copies the dataset where every
   local account can fetch it without touching the database server at all.
5. A stray 644 `id_rsa` belonging to the deploy user converts the foothold
   into SSH lateral movement to whatever that key reaches.

Every step reuses material the host itself distributed. Defense is shrinking
the readable set until a compromised app user finds almost nothing worth
taking.

## Why naive fixes fail

- **`chmod 777 $HOME` to "fix" an access complaint.** On home directories it
  trips sshd `StrictModes`, silently breaking pubkey login for everyone while
  the client shows only `Permission denied (publickey)` — and manufactures
  exactly the exposure this module removes. Restore 750/700 chains instead.
- **Encrypting the file but not the path or the copies.** A 600 ciphertext in
  a 755 directory still leaks its existence and can be replaced if the parent
  is group-writable; unencrypted backups and editor swap files (`file~`,
  `.swp`) bypass the encryption entirely.
- **Moving everything into environment variables believing `/proc` isolation
  solves storage.** Same-UID peers, child processes, `set -x` traces, core
  dumps piped by `core_pattern`, and `systemctl show -p Environment` (any
  local user) all leak env content. Inline unit `Environment=` is world-
  queryable; the fix is `EnvironmentFile=` targets at 640, not more env.
- **Deleting a leaked secret from HEAD and calling it rotated.** Git history,
  forks, and clones retain every past version. Rotation is the only cure;
  deletion is cosmetic.
- **Relying on umask luck in deploys.** An otherwise perfect vault-fed
  pipeline that renders a file resource without an explicit mode inherits the
  invoking shell's umask — frequently producing 644. Explicit modes on every
  credential-touching file are the contract.
- **Rotating production but not CI/staging copies.** Shared credentials mean
  the weakest environment holds the strongest secret; blast radius follows
  the copy inventory, not the org chart.
- **Fixing permissions without rotating.** A credential that was ever
  readable by the wrong principal is burned whether or not you can prove
  access. Closure requires rotation, then verification, in that order.

## Common misconceptions

1. "A 600 file inside a 755 directory is fine." For reading the bytes, yes —
   file bits govern reads. But the loosest-link rule still applies: anyone who
   can write the directory can swap the file; listing reveals it; backups,
   snapshots, and editors escape the modes entirely. Judge the whole path.
2. "Env vars are safe because `/proc/<pid>/environ` denies other users." The
   kernel gate is real (tightened further by Yama ptrace scope), but sideways
   channels — inheritance, dumps, debuggers, `systemctl show` — remain. Env
   vars rate Medium sprawl for low-sensitivity config, never credential
   storage.
3. "`/etc/shadow` being 640 root:shadow is a weakness." That narrow group is
   how the system itself reads hashes legitimately; it is the reference
   SHAPE, not a finding. Copy the pattern rather than flagging the exemplar.
4. "Public certificate bundles and `.pub` halves are leaks." Trust-store PEMs
   and public SSH halves are public by design. Only the private counterparts
   matter; flagging them wastes credibility.
5. "A secret manager removes all on-disk material." The bootstrap anchor (an
   age identity, an agent token, an instance role) lives somewhere on the
   host by definition. Decide consciously where, and protect that spot.
6. "Old credentials expire automatically." Nothing expires unless something
   enforces it. Stale mtime on a cred-bearing file is a culture indicator —
   Needs-Review, corroborated against the rotation ledger, never auto-finding.
7. "Backups inherit the permissions I just fixed." Archive tools record modes
   but restores land wherever the target umask puts them, and restore resets
   mtimes hiding staleness. Post-restore permission verification is its own
   step.

## How professionals think about it today

Modern practice treats a secret at rest as living in three states — file
bytes, process environment, memory — and this module owns the first two.
Findings map onto the SKILL.md objectives like so:

| Domain | Typical gap | Defining end-state |
|---|---|---|
| Inventory & app configs | unknown credential population | complete sweep list vs rendered reality |
| Permissions | group/world-readable secret files | 600/640 owner-scoped, parents ≤750 |
| Keys & certs | 644 private keys outside key dirs | shadow-shape: owner-scoped, narrow group, no other |
| DB credential chains | DSN strings inline, pgpass/my.cnf wide | client files 600; libpq-refusal trap understood |
| Environment boundary | inline unit `Environment=` | EnvironmentFile 640 + UMask=0027 |
| Rotation posture | two-year-old verifiers, no ledger | Needs-Review flags feeding TOK-module runbooks |
| Backup hygiene | plaintext dumps beside source | ciphertext only, off-host placement |

Severity follows the chain view: one foothold plus lazy permissions equals a
lateral-movement kit. The redaction rule (first four characters plus
`…REDACTED`) applies to every phase — evidence handling is part of the
control, not report formatting.

## Read next

In `../SKILL.md`: **Scope & Objectives** (seven objectives in execution
order), **Prerequisites & Vocabulary**, **Mental Model** (three states, DAC
bits, loosest-link rule, shadow reference), **What To Check** (fifteen
numbered sections), **Where To Look** (expected-state table plus paste-ready
sweep), **Patterns & Signatures** (VULNERABLE/FIXED pairs, env verdict table),
**Taint Tracing Guidance** (source→sink with burned-secret rule),
**Exploitation & Reproduction** (Demos A–C, strictly read-only),
**Remediation** (permission end-states, rotation mandate, escrow checklist),
**Verification & Validation** (post-fix list, StrictModes regression test),
**Severity Assessment**, **Common False Positives**, **References**.

Sibling modules: `../api-token-security/SKILL.md` (the rotation runbook for
anything you find burned), `../linux-baseline/SKILL.md` (accounts, sudo, and
the shadow shape this module generalizes), `../backup-dr/SKILL.md` (where
dumps land and key-custody ceremony), `../logging-monitoring/SKILL.md`
(secrets flowing INTO logs turn forensics into liability), `../db-server-
hardening/SKILL.md` (the server side of these client-side credentials),
`../service-sandboxing/SKILL.md` (constraining which processes may read what).
