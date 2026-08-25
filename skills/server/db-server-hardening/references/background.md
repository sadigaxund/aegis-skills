# Database Server Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind network placement, pg_hba ordering and SCRAM
migration, MySQL FILE privilege chains, Redis ACLs and protected-mode traps,
MongoDB authorization posture, and Elasticsearch/OpenSearch exposure;
SKILL.md carries the exact queries, judgement tables, and hardened blocks.

## How this class emerged

Databases predate database *networking*. Early engines served terminals and
batch jobs inside one trusted machine; the TCP listeners that arrived with
client-server computing in the late 1980s–1990s (PostgreSQL's lineage,
MySQL 1995) inherited configuration files written for the single-host world.
The defaults were reasonable there — local connections are implicitly
trustworthy, setup should be frictionless — and became liabilities the moment
the same binaries accepted remote sockets:

- **Installers optimized for first boot.** PostgreSQL's `initdb` historically
  defaulted to `trust` authentication unless told otherwise; MySQL shipped
  anonymous accounts and a `test` database until `mysql_secure_installation`
  (written to clean exactly those) became standard ritual. Redis arrived in
  2009 with no authentication at all.
- **Abuse industrialized before hardening did.** From the mid-2010s onward,
  internet-wide scanners found unauthenticated Redis instances at massive
  scale and turned them into RCE via cron-file rewrites; a wave of exposed
  MongoDB instances was wiped and ransomed around the turn of 2017; exposed
  Elasticsearch clusters suffered repeated mass deletion/extortion campaigns.
  Each engine added guardrails afterward — Redis `protected-mode` in 3.2
  (2016) and ACLs in version 6 (2020), MongoDB tightening defaults — but
  guardrails only bind operators who keep them enabled.
- **Authentication formats aged.** PostgreSQL's md5 challenge scheme gave way
  to SCRAM-SHA-256 (available from PG 10, the default for new passwords since
  PG 14); MySQL moved to caching_sha2_password. Old verifiers persist until
  each user resets — migration windows where both worlds coexist are where
  audits find trouble.
- **Co-location created its own class.** Web stack and database sharing one
  host converted SQL-level powers into code-execution: MySQL's FILE privilege
  writing webshells into writable docroots, Redis snapshot rewrites landing
  cron entries. The privilege model assumed separation that deployment
  practice abandoned.

The recurring lesson: an engine is secure exactly where its defaults end.
Every listener address, auth method, and dangerous-command surface is a
decision someone made for convenience.

## Anatomy: one permissive line, one owned cluster

A minimal generic weak configuration needs two files. Picture a co-located
web + DB host:

```
# pg_hba.conf (first match wins):
host    all    all    0.0.0.0/0    md5      # matches EVERYTHING first...
local   all    all                 trust    # ...and any local shell = postgres superuser

# redis.conf:
bind 0.0.0.0                              # explicit wildcard OVERRIDES protected-mode
# requirepass unset                       # nopass default user, all commands
```

Walkthrough of how this fails:

1. A scanner finds 6379 open. `PING` answers `PONG` with zero credentials:
   full command surface on the cache, including `CONFIG SET dir` +
   snapshot writes.
2. The attacker rewrites cron spool or SSH key material through the snapshot
   mechanism and waits for consumption — unauthenticated RCE without ever
   touching the web app.
3. In parallel, the md5-everywhere hba line means one leaked or guessed
   password reaches ANY database as ANY role from anywhere; leaked verifiers
   crack offline at leisure.
4. Local `trust` converts any shell foothold (the web app's user included)
   into superuser psql sessions — no password prompt, no record of intent.
5. With connection logging off and no identity fields in log prefixes, the
   post-incident question "who did what from where" has no answer.

Every step was a configuration value. That is why this class is called
misconfiguration rather than vulnerability — and why effective-state evidence
(`ss`, `SHOW`, live ACL output) beats config-file optimism.

## Why naive fixes fail

- **Flipping `password_encryption` to scram and declaring victory.** The GUC
  affects only passwords set afterwards; existing md5 verifiers persist until
  each role re-sets. Migration shape: flip → rotate over days/weeks → only
  then move hba lines to `scram-sha-256` (the interim `md5` method accepts
  both verifier types). Skipping rotation bricks logins; skipping the final
  flip downgrades wire protection silently.
- **Editing pg_hba without a break-glass console path.** First-match-wins
  means one misplaced line locks out every admin instantly. Apply the
  `local all postgres peer` rule first, prove console login, then reload.
- **Trusting Redis `protected-mode yes` alone.** It yields to explicit
  configuration: `bind 0.0.0.0` overrides it entirely. Judge bind + ACL shape
  together, never one line.
- **Obfuscating commands instead of governing them.** `rename-command
  CONFIG ""` works but breaks tooling, hides events from monitoring, invites
  secret-in-config. ACL category denies (`-@dangerous`, plus `-@scripting`
  because EVAL lives there) are the modern shape.
- **Enabling `require_secure_transport=ON` without checking drivers.** Any
  legacy client lacking TLS support turns the enforcement switch into an app
  outage. Stage per service; watch old-path metrics for one cycle.
- **Revoking PUBLIC grants blind.** Monitoring agents, pgbouncer health
  checks, and CI jobs often rely on implicit connect/create access. Inventory
  consumers, grant named roles, then revoke — in one window.
- **Defending by firewall only while compose publishes ports.** Docker DNAT
  bypasses INPUT-chain rules; `ports: ["6379:6379"]` exposes the engine
  regardless of host firewall. Binding discipline and publish hygiene are
  separate controls.
- **Recommending MongoDB Enterprise encryption to Community builds.** Native
  at-rest encryption is EE-only; the honest Community equivalent is disk-
  level encryption (LUKS) under the data path.

## Common misconceptions

1. "It binds loopback, so it's safe." Loopback stops strangers; it does
   nothing about `local trust` lines, shared-service users, or the next
   config change that moves the bind. Exposure and authentication are
   separate layers.
2. "md5 is hashed, so it's fine." The stored verifier is offline-crackable if
   any hash source leaks, and the scheme blocks SCRAM migration while it
   persists. Superseded is superseded.
3. "Base64 connection strings are encrypted." Encoding is reversible by
   design; treat every committed DSN as burned history requiring rotation.
4. "Redis with a password equals security." A single shared `requirepass`
   gives every client identical all-command power. Named ACL users with
   key/channel patterns and denied categories are the target shape.
5. "Managed cloud databases need no hardening." Parameter groups still set
   `require_secure_transport`, `local_infile`, and friends; OS files being
   invisible changes the audit method, not the standards.
6. "Replication traffic is inherently trusted internal plumbing." Replication
   roles carry full data read; they deserve pinned peers, TLS, and dedicated
   credentials like anything else.
7. "FILE privilege is an administrator-only power anyway." Grants drift. One
   `GRANT FILE ON *.*` to an app account during a debugging session converts
   the next SQL injection into a webshell write.

## How professionals think about it today

Modern practice audits five defensive layers per engine — exposure,
authentication, privilege containment, auditability, secrets lifecycle — and
scores findings by what they chain with. The taxonomy mirrors SKILL.md's own
sections:

| Layer | Domain | Typical gap | Defining control |
|---|---|---|---|
| Exposure | placement, binding, FW path | wildcard binds, published container ports | loopback/private binds verified via `ss` |
| Authentication | hba methods, ACLs, plugins, SCRAM | trust lines, nopass Redis, auth-off Mongo | ordered hba table; ACL default-off; authorization enabled |
| Privilege containment | superusers, PUBLIC grants, FILE priv | SUPERUSER app accounts, empty secure_file_priv | DML-only roles, revoked PUBLIC, confined file I/O |
| Audit | connection logging, prefixes | unattributable logs | log_connections + %u@%d %r prefixes |
| Secrets lifecycle | verifier formats, staleness, creds on disk | md5 rows, two-year-old passwords | staged scram migration, rotation ledger |

Reachability weighting runs throughout: the same gap scores Critical when the
firewall path admits untrusted networks and drops bands when the path is dead
— recorded as defense-in-depth debt, never deleted.

## Read next

In `../SKILL.md`: **Scope & Objectives** (six priorities across four
engines), **Prerequisites & Vocabulary**, **Mental Model** (entry→amplifier→
outcome table, five layers, two structural facts), **What To Check**
(placement pass, per-engine deep passes, paste-ready sweep), **Where To
Look** (per-engine paths incl. Elasticsearch/OpenSearch), **Patterns &
Signatures** (grep/SQL/output shapes), **Taint Tracing Guidance** (exposure/
privilege/credential taints + IaC propagation), **Exploitation &
Reproduction** (E1–E5 read-only proofs with authorization gates),
**Remediation** (hardened hba/GUC/ACL/mongod blocks, account SQL),
**Verification & Validation** (negative tests, staged-rollout warnings),
**Severity Assessment** (S1–S8 anchors), **Common False Positives**, 
**References**.

Sibling modules: `../host-secrets/SKILL.md` (the client-side half of these
credentials: .pgpass/.my.cnf/DSNs), `../backup-dr/SKILL.md` (dump-job design
and restore drills), `../logging-monitoring/SKILL.md` (shipping DB logs and
audit trails), `../firewall-edge/SKILL.md` (reachability proofs that weight
every severity), `../tls-proxy/SKILL.md` (TLS termination in front of
proxied engines), `../linux-baseline/SKILL.md` (OS baseline under the
database host), `../kubernetes-cluster/SKILL.md` (containerized engines'
service exposure).
