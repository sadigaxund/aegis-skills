---
name: aegis-db-server-hardening
description: Audits database server hardening for PostgreSQL, MySQL/MariaDB, Redis, and MongoDB — network placement and binding, transport encryption, authentication configuration, role/account hygiene, and dangerous-command surface — with read-only inspection commands, hardened config blocks, and post-fix verification steps.
category_slug: DB
cwe: [CWE-16, CWE-284]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit one host's database estate (or its config-as-code) across four engines, in priority order:

1. **Placement & exposure** — which engines listen (`ss -tlnp` port map: 5432/3306/6379/27017), what address each binds, whether the firewall path actually permits strangers (reachability cross-ref → FW), co-location with the app tier, and TLS on any app↔DB hop that crosses a network.
2. **PostgreSQL deep pass** — `postgresql.conf` security-relevant GUCs, ordered `pg_hba.conf` rule audit, role hygiene (extra superusers, passwordless LOGIN roles, legacy md5 verifiers), PUBLIC default grants on schema/database.
3. **MySQL/MariaDB pass** — binding, transport enforcement, password-validation component, default-account/test-DB cleanup state, remote root, auth-plugin mix, `FILE` privilege exposure, log-file permissions, credential staleness.
4. **Redis pass** — protected-mode, bind scope, ACL/requirepass presence and shape, dangerous-command governance, RDB file permissions.
5. **MongoDB pass** — authorization enabled, bindIp scope, SCRAM mechanism posture, localhost-exception closure, at-rest encryption honesty (Enterprise feature vs disk-level alternative).
6. **Backup-adjacent surface & app-side connection hygiene** — dump-job credentials on disk (pointers), least-privilege app users, per-service user separation, connection-string secret location.

Out of scope (cross-references): firewall ruleset design and reachability proofs → FW; TLS termination/proxy edge → TLS; systemd sandboxing and container runtime → SANDBOX; secret contents in env files and key perms → HSECRET; audit rules/log shipping → LOGMON; application-level authorization logic such as row-level-security policy design → AUTHZ (skills/code/authz-access-control/SKILL.md); token lifecycle → TOK; backup job design and restore testing → BACKUP-DR (skills/server/backup-dr/SKILL.md when present).

Operating rules:

- All inspection here is read-only; mutating commands appear only under Remediation after change-window approval.
- Prefer **effective-state evidence** (`ss -tlnp`, SQL `SHOW` output) over config files — drop-in dirs (`/etc/mysql/conf.d/`, `postgresql.conf` `include_dir`) make single files misleading.
- Commands needing root are tagged `[ROOT]`. Without root, audit world-readable config plus the repo and judge rendered templates using Patterns & Signatures.
- Connecting to a database from outside the host (even read-only `PING`s) requires written authorization naming source and target; where absent, use in-host binding evidence only (Exploitation & Reproduction gates this).
- Distro variance is called out inline; detect first (`cat /etc/os-release`). Managed cloud DBs are audited differently — see Common False Positives before flagging.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **bind address**: which network interface a database listens on; loopback-only is the safe default
- **pg_hba.conf**: PostgreSQL's ordered list of who may connect from where and how
- **first-match-wins**: the first matching rule wins, so a permissive line placed above voids stricter ones below
- **SCRAM vs md5**: new versus legacy password verifier formats; old md5 hashes persist until each user resets
- **FILE privilege**: a MySQL right letting queries read and write server files
- **protected-mode**: Redis's refusal of remote commands when no password or bind is configured
- **PUBLIC grants**: rights every database role inherits unless explicitly revoked
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Attackers do not attack "the database" — they chain one misconfigured layer into full compromise:

```
Entry point                Amplifier (this module)                 Realized outcome
-------------------------  --------------------------------------  --------------------------------------
internet :6379/:27017  ──▶ no auth (protected-mode off /          ▶ unauth RCE via crontab/SSH-key
                          authorization disabled)                  write chains, ransomware wipe
any net peer           ──▶ pg_hba `trust` / broad-CIDR md5       ▶ direct superuser session, zero
                                                                     credentials or crackable hashes
app server foothold    ──▶ app DB account has SUPERUSER /        ▶ full cluster takeover, INTO OUTFILE
                          FILE / GRANT ALL                         webshell write onto web host
on-path insider        ──▶ plaintext app↔DB traffic              ▶ credentials + PII captured mid-flight
read-only repo leak    ──▶ connection strings/dump creds         ▶ silent replica of prod data exfiltrated
post-breach cleanup    ──▶ log_connections/disconnections off,   ▶ forensics blinded; attribution lost
                          no log_line_prefix identity fields
```

Five defensive layers map to the check order:

| Layer | Checks | Question it answers |
|---|---|---|
| Exposure | placement, binding, FW path | Who can open a socket to this engine? |
| Authentication | hba methods, ACLs, plugins, SCRAM | What must they prove once connected? |
| Privilege containment | superusers, PUBLIC grants, FILE priv | How much damage can an authenticated principal do? |
| Audit | connection logging, prefixes, slow-log perms | Can we reconstruct who did what? |
| Secrets lifecycle | hash formats, last-change staleness, creds on disk | Do old/leaked credentials still work? |

Classify every finding by layer and by what it chains with: a Medium gap becomes Critical once an adjacent entry point exists (Taint Tracing Guidance). Two structural facts drive PostgreSQL auditing specifically:

- **`pg_hba.conf` is first-match-wins.** A permissive line placed *above* a strict one silently voids it; always audit the file top-to-bottom as an ordered table, never grep-only.
- **GUC changes are not retroactive for secrets.** `password_encryption = 'scram-sha-256'` affects only passwords set *after* the change; existing md5 verifiers persist until each user re-sets their password (Verification & Validation covers the dual-format migration window).

## What To Check

### Placement & Exposure (Audit First)

Run this before any engine-specific pass; it decides the severity of everything after it.

1. **Map listeners to engines and bound addresses** with `ss -tlnp` [ROOT] (falls back to `netstat -tlnp`; without root the PID column is empty but addresses still show):

   | Port | Engine | Healthy binding | Finding |
   |---|---|---|---|
   | 5432 | PostgreSQL | `127.0.0.1` or private LAN IP | `0.0.0.0` / `*` / `::` |
   | 3306 | MySQL/MariaDB | `127.0.0.1` or `169.x`-free private IP; absent if `skip_networking=ON` | `0.0.0.0` / `*` |
   | 6379 | Redis | `127.0.0.1` (+`::1`) only | `0.0.0.0` / `[::]` |
   | 27017 | MongoDB | `127.0.0.1` or explicit replica-set peer IPs | `0.0.0.0`, `::`, or `0.0.0.0/::` in `bindIp` |

2. **Apply the wildcard rule.** Treat any non-loopback wildcard bind as a finding unless clustering genuinely requires it (Patroni/replication/Pacemaker) *and* the claim is verifiable — confirm a second node exists (`ss` on peers, config replication stanza, service topology doc). "We might cluster someday" is not a reason.
3. **Cross-check reachability once**: reconcile each exposed port against the host firewall/cloud SG inventory produced by FW — one line per engine in your report ("5432 reachable from app-tier CIDR 10.20.0.0/24 via nftables accept rule #14") rather than re-auditing rules here.
4. **Record co-location.** DB on the same host as the web/app tier amplifies every downstream chain: MySQL `FILE` privilege becomes webshell write (Exploitation E4), Redis RDB rewrite becomes cron hijack, dump files land beside web roots. Dedicated DB hosts shrink blast radius; containerized DB on the app host counts as co-located unless network namespaces are actually isolated (verify with `ss` inside the netns → SANDBOX/K8S modules).
5. **Require TLS on any networked hop.** Loopback-only engines may run plaintext; the moment app↔DB traffic leaves the host (dedicated DB host, sidecar mesh hop), require the engine's transport switch: PostgreSQL `ssl=on` + `hostssl` hba lines, MySQL `require_secure_transport=ON`, MongoDB `net.tls.mode: requireTLS`, Redis TLS params or an encrypting proxy (→ TLS).

### PostgreSQL Deep Pass

**Server configuration.** Locate the live file first (`sudo -u postgres psql -Atc "SHOW config_file;"` [ROOT], else distro paths in Where To Look) and audit these keys:

| Config key | Risky value | Hardened value | Engine/version note |
|---|---|---|---|
| `listen_addresses` | `'*'`, unset-with-exposure, host's public IP | `'localhost'` or specific private IPs | Applies on reload; empty string = unix-socket only |
| `ssl` | `off` | `on` | Needs server cert/key; key must be `0600 postgres:postgres` |
| `ssl_min_protocol_version` | `'TLSv1'` / `'TLSv1.1'` | `'TLSv1.2'` | GUC exists since PG 12; verify explicitly even where default is already TLSv1.2 |
| `password_encryption` | `'md5'` | `'scram-sha-256'` | GUC since PG 10 (md5/scram values); default flipped to scram in PG 14 — affects only passwords set afterwards |
| `log_connections` | `off` | `on` | Pair with `log_disconnections`; cheap, high forensic value |
| `log_disconnections` | `off` | `on` | Session duration attribution |
| `log_min_duration_statement` | `-1` (disabled) | `500`–`1000` ms threshold | Tradeoff: `0` logs everything — latency overhead and SQL literals (PII/secrets) into logs; never enable statement logging wholesale on busy PII clusters |
| `log_line_prefix` | empty or no identity fields | `'%m [%p] %q%u@%d %r '` | Without `%u@%d` (role@db) and `%r` (remote host) connection logs cannot be attributed |

**`pg_hba.conf` ordered-rules audit.** Rebuild the file as a table in report order — TYPE, DATABASE, USER, ADDRESS, METHOD — because first match wins and later lines never execute for a matched connection. Method-column verdicts:

| Method | Verdict | Reasoning |
|---|---|---|
| `trust` | **Critical** anywhere | No password at all; network-reachable `trust` = full DB by anyone who can reach the socket |
| `ident` | Critical when on `host` lines; flag on `local` too | Relies on client-host identd — spoofable, legacy; newer majors are phasing it out — plan replacement |
| `md5` (on `host` from broad CIDR) | High | Legacy hash scheme; verifier crackable offline if leaked; blocks scram migration when kept after rotation |
| `password` | Critical | Cleartext password over the wire unless inside a verified TLS tunnel — replace with `scram-sha-256` |
| `peer` | Acceptable on `local` lines | OS-user↔PG-user map; not usable for TCP |
| `cert` with `clientcert=verify-full` | Strongest for TCP | Mutual TLS; pair with `hostssl` TYPE |
| `scram-sha-256` | Target state for TCP+local auth | Requires SCRAM verifiers (see role hygiene below) |

Example of ordering defeating intent — interpret files exactly this way during audit:

```
# VULNERABLE (pg_hba.conf) — first-match-wins voids the strict line
host    all         all             10.20.8.0/24     md5      # matches FIRST for app subnet
host    all         postgres        10.20.0.0/24     scram-sha-256   # unreachable: line above already matched
local   all         all                              trust    # CRITICAL: any local shell = superuser-free-for-all
```

```
# FIXED — narrowest/most-specific rules first, deny-all last
hostssl appdb       appsvc          10.20.8.12/32    scram-sha-256
local   all         postgres                         peer
local   all         all                              scram-sha-256
host    all         all             0.0.0.0/0        reject
host    all         all             ::/0             reject
```

**Role hygiene.** Run each query read-only as a superuser (`sudo -u postgres psql`) and interpret:

```sql
-- Superusers beyond the bundled 'postgres' account:
SELECT rolname FROM pg_roles WHERE rolsuper AND rolname <> 'postgres';
-- Replication-capable roles (expected: dedicated replicator(s) only):
SELECT rolname FROM pg_roles WHERE rolreplication;
-- LOGIN roles with NO stored verifier (passwordless over password methods):
SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword IS NULL;
-- LOGIN roles still on legacy md5 verifiers:
SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword LIKE 'md5%';
```

Interpretation notes: `\du` lists role attributes (Superuser, Replication, Createrole) but **not** password state — verifier inspection requires `pg_authid`, readable by superusers only. Roles without verifiers are legitimate *only* when their hba method is `peer`/`cert` (no password involved); cross-reference the hba table before flagging. Every row in the md5 query needs a scheduled re-set (`ALTER ROLE ... PASSWORD` under change window) — flipping `password_encryption` does not convert them.

**PUBLIC default grants.** Two defaults ship open and are routinely forgotten:

```sql
-- Who can CREATE objects in schema 'public'? (pre-PG15 clusters typically: PUBLIC)
SELECT nspname, nspacl FROM pg_namespace WHERE nspname = 'public';
-- Which databases can PUBLIC connect to?
SELECT datname, datacl FROM pg_database;
```

Version nuance (state it honestly in reports): PostgreSQL 15 changed the default so `public` schema grants PUBLIC only USAGE, not CREATE — but clusters upgraded in place via `pg_upgrade` keep their pre-15 grant sets, and databases cloned from stale `template1` inherit them. Audit the actual `nspacl`, never assume by version number. Remediation pattern: `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` plus `REVOKE CONNECT ON DATABASE <appdb> FROM PUBLIC;` with explicit per-role grants (full snippet + caveats in Remediation).

Row-level security policy design (which rows a role may see) is application authorization logic — audit its presence here only as a pointer, deep pass → AUTHZ module.

### MySQL/MariaDB Pass

Locate the effective `[mysqld]` settings (`mysql -NBe "SHOW VARIABLES WHERE Variable_name IN ('bind_address','require_secure_transport','secure_file_priv','local_infile','default_authentication_plugin');"`, or grep the config tree per Where To Look) and audit:

| Config key | Risky value | Hardened value | Engine/version note |
|---|---|---|---|
| `bind-address` | `0.0.0.0` or absent on multi-homed host | `127.0.0.1` or private LAN IP; `skip_networking=ON` if socket-only is viable | Same key both engines |
| `require_secure_transport` | `OFF`/absent | `ON` | MySQL ≥5.7.5; MariaDB ≥10.5.2 (absent on older MariaDB — enforce via proxy/TLS instead) |
| `local_infile` | `ON` | `OFF` | Blocks server-pull file reads via `LOAD DATA LOCAL INFILE` chains |
| `secure_file_priv` | empty string (writes anywhere) | `/var/lib/mysql-files` (default in modern MySQL) or narrower; `NULL` disables import/export entirely | Empty value = `SELECT ... INTO OUTFILE` can write any mysqld-writable path |
| `default_authentication_plugin` / `authentication_policy` | forced `mysql_native_password` fleet-wide | `caching_sha2_password` (MySQL 8 default) | MySQL: plugin deprecated in 8.0 and disabled-by-default later; MariaDB instead defaults to `mysql_native_password` with optional `unix_socket` — judge per engine, do not copy MySQL advice onto MariaDB |
| `validate_password` component/policy | not installed | installed with policy `MEDIUM`+ | MySQL 8: component (`INSTALL COMPONENT 'file://component_validate_password'`; vars `validate_password.policy`); MariaDB: `simple_password_check`/`cracklib_password_check` plugins instead — different names, same intent |
| `general_log_file`, `slow_query_log_file` | paths under world-readable dirs; files 0644+ | dedicated log dir, files `0640 mysql:adm` or tighter | General log captures statement text incl. literals — treat as sensitive |
| `log_error` | stderr only | explicit file, `0640`, log-shipped | → LOGMON for shipping |

**Account inventory** (read-only, as admin):

```sql
-- Anonymous accounts (classic install residue):
SELECT User, Host FROM mysql.user WHERE User = '';
-- Root reachable beyond loopback:
SELECT User, Host FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost','127.0.0.1','::1');
-- Auth plugin mix (flag legacy native-password users):
SELECT User, Host, plugin FROM mysql.user;
-- Who holds the webshell-grade FILE privilege:
SELECT GRANTEE, PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'FILE';
-- Stale credentials (MySQL; see note below for MariaDB):
SELECT User, Host, password_last_changed FROM mysql.user
WHERE password_last_changed IS NOT NULL AND password_last_changed < NOW() - INTERVAL 180 DAY;
```

Interpretation: `root@'%'` or `root@<broad-host-pattern>` is a High finding even password-gated (brute-force surface). `plugin='mysql_native_password'` per user is a migration flag, not an instant breach. `password_last_changed` NULL means non-password auth (e.g. socket plugins). **MariaDB honesty:** since 10.4 credentials live in `mysql.global_priv` and `mysql.user` is a compatibility view that lacks `password_last_changed` — track rotation dates from ops changelog there rather than inventing a query.

**FILE-privilege danger (the classic chain, statically):** on a co-hosted web stack, `GRANT FILE` to the app account turns SQL injection into code execution: `SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '/var/www/html/shell.php';` writes a webshell because mysqld runs as a user that can write the webroot. `secure_file_priv` confinement plus revoking `FILE` from app accounts breaks step one of that chain. Full narrative in Exploitation E4.

### Redis Pass

Audit `/etc/redis/redis.conf` (or distro path) plus live state:

| Config key | Risky value | Hardened value | Engine/version note |
|---|---|---|---|
| `protected-mode` | `no` | `yes` | Default `yes` since Redis 3.2; NOTE: it only refuses external conns when no bind AND no auth are configured — an explicit `bind 0.0.0.0` overrides it, so protected-mode alone is never proof of safety |
| `bind` | `0.0.0.0` / absent on exposed host | `bind 127.0.0.1 ::1` | Absent directive binds all interfaces |
| `port` | reachable from untrusted nets | keep 6379 but firewall-scope, or `port 0` when unix-socket-only (`unixsocket` + perms) | `port 0` disables TCP entirely |
| `requirepass` / ACL | unset (nopass) | ACL users with passwords; `requirepass` acceptable pre-6 legacy | Redis ≥6: prefer ACLs; single shared password has no per-client scoping |
| `aclfile` | unset | `/etc/redis/users.acl` with `user default off` | Redis ≥6; mutually exclusive design with `requirepass` — pick ACLs, don't run both shapes |
| `rename-command` | present as sole control | migrate to ACL category denies | Legacy blunt control (see governance note below) |
| `dir` + `dbfilename` output perms | `dump.rdb` world/group readable | `-rw-------` owned by redis service user | Check `ls -l "$(redis-cli CONFIG GET dir ...)"` path |

**ACL review (Redis ≥6, read-only):**

```bash
redis-cli ACL LIST
redis-cli ACL GETUSER default
```

Finding signatures in output: `user default on nopass ~* &* +@all` (or missing `&` patterns on 6.0) = unauthenticated all-powerful default user. Target shape: `user default off` plus named users with key/channel patterns and minimal command categories.

**Dangerous-command governance — give both shapes honestly:** the old pattern `rename-command CONFIG ""` (empty string = disabled) or `rename-command FLUSHALL <secret-name>` predates ACLs; it still works, survives on every version, and is simple — but it breaks tooling expectations, hides commands from monitoring, invites secret-in-config, and is effectively deprecated by upstream guidance in favor of ACLs. The modern preferred shape denies categories per user: `-@dangerous` (covers FLUSHALL/FLUSHDB/SHUTDOWN/debug-class commands) and additionally `-@scripting` where Lua misuse is in threat model (note: EVAL lives in @scripting, *not* @dangerous — denying only @dangerous leaves EVAL available). Recommend ACL-first; accept rename-command as compliant-with-caveats on versions lacking ACLs.

The unauth-Redis→RCE chain (cron/authorized_keys rewrite via `CONFIG SET dir/dbfilename` + SAVE) is demonstrated cross-ref FW module demos — pointer only here; static reasoning in Exploitation E2.

### MongoDB Pass

Audit `/etc/mongod.conf` YAML and runtime:

| Config key | Risky value | Hardened value | Engine/version note |
|---|---|---|---|
| `security.authorization` | `disabled`/absent | `enabled` | Absent key on a networked mongod = no auth at all |
| `net.bindIp` | `0.0.0.0`, `::`, or includes public IP | `127.0.0.1` or comma-separated private IPs (replica peers) | YAML list form also valid |
| `net.tls.mode` | absent | `requireTLS` (+`certificateKeyFile`) | Internal member traffic too on replica sets |
| SCRAM mechanisms | both SHA-1-only allowed | restrict `authenticationMechanisms: SCRAM-SHA-256,SCRAM-SHA-1` minimum; prefer SHA-256-only once drivers permit | New users get SCRAM-SHA-256 by default when FCV ≥4.0; older users may retain SHA-1 verifiers — check `db.getUser()` mechanisms |
| `setParameter.enableLocalhostAuthBypass` | left enabled after setup | `false` once first admin user exists | Localhost exception lets a local shell create the first user — it should be a setup-time event, then closed |
| At-rest encryption | none | Enterprise `security.enableEncryption: true` (WiredTiger encrypted) **or** filesystem/disk-level encryption (LUKS) for Community | Honesty requirement: native at-rest encryption is an Enterprise feature; do not recommend enabling it on Community builds |

Verify localhost-exception posture: if `authorization: enabled` yet no users exist (`mongosh --eval 'db.getUsers()'` errors with Unauthorized), the deployment is stuck pre-setup — flag as misconfiguration either way (open instance or unusable one).

### Backup-Adjacent Surface (Pointers Only)

One line each in findings, deep pass elsewhere: dump-job credentials stored on disk (`.my.cnf [client]`, `.pgpass`, cron env, dump scripts) → BACKUP-DR module; host-level secret file permissions and plaintext connection strings in env/unit files → HSECRET module; token-shaped secrets in repos → TOK/SECRETS modules.

### Application-Side Connection Hygiene (Quick Table)

| Dimension | Bad pattern | Good pattern | Cross-ref |
|---|---|---|---|
| App DB user privilege | `SUPERUSER`, `root`, `GRANT ALL ON *.*`, owner-of-database login | Dedicated user with DML-only grants on its schemas | AUTHZ for grant-design |
| Service separation | one shared DB user for all services | per-service users (auditable, independently revocable) | LOGMON attribution |
| Secrets location | connection strings in app config/env committed to repo, docker-compose env | secret manager / root-owned 0600 deploy-time injection | SECRETS/TOK, HSECRET |
| TLS from app driver | `sslmode=disable` style settings | verify-full/verify-ca equivalents per driver | TLS module |

### Paste-Ready Read-Only Sweep

```bash
# --- DB exposure & config sweep (read-only; adjust paths if distro differs) ---
printf '%s\n' '=== TCP listeners ==='
ss -tlnp 2>/dev/null | grep -E ':(5432|3306|6379|27017)\b' || echo 'no db listeners'
printf '%s\n' '=== client CLIs present ==='
for c in psql mysql redis-cli mongosh mongo; do command -v "$c" || true; done
printf '%s\n' '=== PostgreSQL ==='
sudo -u postgres psql -Atc "SHOW config_file;" 2>/dev/null || find /etc/postgresql /var/lib/pgsql -name postgresql.conf 2>/dev/null
sudo -u postgres psql -Atc "SHOW hba_file;"    2>/dev/null || find /etc/postgresql /var/lib/pgsql -name pg_hba.conf 2>/dev/null
grep -RnsE '^\s*(listen_addresses|ssl_min_protocol_version|password_encryption|ssl|log_connections|log_disconnections|log_line_prefix)\s*=' /etc/postgresql 2>/dev/null
grep -nE '\s(trust|ident|password|md5)\s*(#.*)?$' "$(sudo -u postgres psql -Atc 'SHOW hba_file;' 2>/dev/null)" 2>/dev/null   # hba method audit one-liner
printf '%s\n' '=== MySQL/MariaDB ==='
grep -RnsE '^\s*(bind[-_]address|skip[-_]networking|require_secure_transport|local_infile|secure_file_priv|general_log|slow_query_log_file)\s*=' /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null
printf '%s\n' '=== Redis ==='
grep -nsE '^\s*(bind|protected-mode|port|requirepass|aclfile|rename-command|dir|dbfilename)' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null
ls -l /var/lib/redis/dump.rdb 2>/dev/null
printf '%s\n' '=== MongoDB ==='
grep -nsE '^\s*(bindIp|authorization|enableEncryption|mode|enableLocalhostAuthBypass):' /etc/mongod.conf /etc/mongodb.conf 2>/dev/null
```

Interpret rules: any listener row whose local address starts `0.0.0.0`, `[::]`, `*`, or the host's public IP escalates everything downstream; empty grep results usually mean keys are commented out (risky default applies — confirm via SQL/CLI effective-state before reporting).

## Where To Look

Evidence collection: `tools/sweeps/sweep-db.sh` captures `[DB-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

Config paths vary by distro and install method; detect rather than assume. Effective-state queries beat file greps wherever shown.

### PostgreSQL

- Debian/Ubuntu (per-cluster dirs): `/etc/postgresql/<major>/<cluster>/postgresql.conf`, same dir `pg_hba.conf` (and `pg_ident.conf`). Cluster list: `pg_lsclusters`.
- RHEL-family / PGDG: `/var/lib/pgsql/<major>/data/` or `/var/lib/pgsql/data/`.
- Authoritative paths regardless of distro — ask the server itself [ROOT or peer-auth as postgres]: `sudo -u postgres psql -Atc "SHOW config_file; SHOW hba_file; SHOW data_directory;"`.
- Extra settings may hide in `include_dir = 'conf.d'` / `include_if_exists` entries near the file tail — enumerate those too.
- Logs: `/var/log/postgresql/postgresql-<major>-<cluster>.log` (Debian) or `log_directory` GUC target.
- IaC: ansible `postgresql_*` templates, cloud-init, Terraform `aws_rds_cluster_parameter_group`/parameter-group bodies.

### MySQL/MariaDB

- Config chain (first-wins per option): `/etc/my.cnf`, `/etc/mysql/my.cnf`, then `!includedir` targets — typically `/etc/mysql/conf.d/*.cnf` and on Debian `/etc/mysql/mysql.conf.d/mysqld.cnf`; RHEL adds `/etc/my.cnf.d/`. Grep all of them; last-loaded wins per key.
- Authoritative runtime values: `mysql -NBe "SHOW VARIABLES WHERE Variable_name IN ('bind_address','require_secure_transport','secure_file_priv','local_infile','general_log','slow_query_log_file');"` (admin credentials required; read-only).
- Datadir (perms audit): `/var/lib/mysql` — expect `0700 mysql:mysql`.
- Per-user credential files: `~root/.my.cnf`, service accounts' `.my.cnf` → HSECRET.
- Logs: `/var/log/mysql/` (Debian) or `log_error` variable target.
- IaC: helm chart `values.yaml` (`mysql.auth`, initdb scripts), ansible `mysql_*` modules, Terraform RDS parameter groups.

### Redis

- Debian/Ubuntu: `/etc/redis/redis.conf`; RHEL/Fedora: `/etc/redis.conf`; Alpine: `/etc/redis.conf`.
- systemd units may override args: `systemctl cat redis-server redis 2>/dev/null` reveals ExecStart config path overrides and drop-ins.
- Live effective state (read-only): `redis-cli CONFIG GET bind protected-mode requirepass dir dbfilename aclfile rename-command` — unavailable if CONFIG was renamed away; fall back to files and note the gap. Version: `redis-cli INFO server | grep redis_version`.
- ACL file (if configured): value of `aclfile` key, commonly `/etc/redis/users.acl` — audit contents like a password store: `0600 redis:redis`.
- Data dir: `dir` key (commonly `/var/lib/redis`) — check `dump.rdb` perms.
- IaC: bitnami-style helm values (`auth.enabled`, `networkPolicy.enabled`), compose files publishing 6379.

### MongoDB

- Official packages: `/etc/mongod.conf`; source/brew installs vary (`/usr/local/etc/mongod.conf`, custom unit `--config` arg — confirm via `systemctl cat mongod`).
- Runtime check needs auth once enabled: `mongosh --eval 'db.adminCommand({getParameter:1, authorization:1})'`; pre-auth instances answer without creds (that itself is the finding).
- Keyfile (replica sets): `security.keyFile` path — expect `0400 mongod:mongod`.
- Logs: `/var/log/mongodb/mongod.log`.
- IaC: helm `values.yaml` (`auth.enabled`, `replicaSetKey`), compose `- MONGO_INITDB_ROOT_PASSWORD` env leaks.

### Elasticsearch / OpenSearch

- Security plugin enabled and auth ON (x-pack security / opensearch-security) — anonymous cluster access or unauth `9200` answering `GET /` with cluster metadata is the finding.
- Bound to private interface; never `0.0.0.0` on an internet-reachable box (classic exposed-ES ransomware target).
- TLS on HTTP and transport layers where the version supports it; dedicated users per service, no shared superuser-equivalent roles.

### Repo-wide locations (all engines)

Glob for rendered artifacts: `**/pg_hba.conf*`, `**/*.cnf`, `**/redis*.conf`, `**/mongod.conf`, `docker-compose*.yml`, `*.tf`, `kustomize/**`, `charts/*/values*.yaml`. Judge *rendered output*, not template intent — a Jinja default can silently differ from prod reality.

## Patterns & Signatures

Concrete grep/SQL/output shapes that separate healthy from risky state. Use verbatim in evidence collection.

```bash
# PostgreSQL: risky GUC states (commented-out lines included intentionally to spot defaults)
grep -RE '^\s*#?\s*(listen_addresses|ssl|ssl_min_protocol_version|password_encryption)\s*=' /etc/postgresql/*/*/*.conf

# PostgreSQL: hba method-column audit one-liner — trust/ident/md5/password verdicts
sudo -u postgres psql -Atc "SHOW hba_file;" | grep -vE '^\s*#' | awk '$1=="local"||$1=="host"{print NR": "$0}'

# MySQL: wildcard bind or missing transport enforcement anywhere in the include tree
grep -RnsE 'bind[-_]address\s*=\s*(0\.0\.0\.0|\*)|^\s*#?\s*require_secure_transport' /etc/mysql /etc/my.cnf*

# Redis: unauthenticated-friendly shape
grep -nE '^protected-mode no|^# ?requirepass|^bind ' /etc/redis/redis.conf

# MongoDB: auth absent from YAML
grep -qA1 '^security:' /etc/mongod.conf && grep -A1 '^security:' /etc/mongod.conf | grep -q 'authorization: enabled' || echo 'FINDING: authorization not enabled'
```

SQL signatures (PostgreSQL, superuser session):

```sql
-- Healthy answers: zero rows for all three
SELECT rolname FROM pg_roles   WHERE rolsuper AND rolname <> 'postgres';
SELECT rolname FROM pg_authid  WHERE rolcanlogin AND rolpassword IS NULL;
SELECT rolname FROM pg_authid  WHERE rolcanlogin AND rolpassword LIKE 'md5%';
-- PUBLIC schema CREATE check: nspacl must NOT contain a bare '=U...' element granting CREATE
SELECT nspname, nspacl FROM pg_namespace WHERE nspname='public';
```

Output-shape signatures:

```
# VULNERABLE — redis ACL LIST
user default on nopass ~* &* +@all                       # any local shell owns every key

# FIXED — redis ACL LIST
user default off
user svc_app on #<sha256-of-secret> ~svc_app:* &svc_app:* +@read +@write -@dangerous -@scripting

# VULNERABLE — pg_hba excerpt (method column is what matters)
host    all    all    0.0.0.0/0    md5

# FIXED
hostssl appdb  appsvc 10.20.8.12/32  scram-sha-256
```

```
# VULNERABLE — mongod.conf fragment
#security:                          # whole block commented => no auth

# FIXED
security:
  authorization: enabled
```

MySQL signature queries are in What To Check (anonymous users, remote root, FILE holders); treat any non-empty result as a finding row in the report with the exact User@Host pair quoted.

## Taint Tracing Guidance

Model each finding as source → propagation → sink; severity follows how short the path to a sink is.

**Exposure taint (network path).**

1. Source: `ss -tlnp` shows non-loopback bind on 5432/3306/6379/27017.
2. Propagation: FW module verdict — reachable-from-internet > reachable-from-VPN/office CIDR > same-VPC only > firewall-denied (dead listener).
3. Sink selection by engine auth state: no-auth engines (Redis nopass, Mongo authorization disabled, pg_hba `trust`) sink at **unauth RCE / full data takeover** (Critical); password-gated engines sink at **online brute-force + offline hash-cracking surface** (High).

**Privilege taint (post-auth path).** App-tier foothold (from web modules) → app DB credentials from config/env → account capability check: `SUPERUSER`/`rolsuper`, MySQL `FILE`+`ALL PRIVILEGES`, Redis `+@all` — each converts an app-level breach into cluster-level breach. Trace which services share one credential: shared user means the *weakest* service's compromise propagates everywhere that user's grants reach.

**Credential taint (secrets path).**

- Connection strings in repo files (`grep -rnE '(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^/\s]*:[^@\s]+@' .`) → treat as compromised history → SECRETS/TOK rotation runbooks.
- Dump-job creds on disk (`.pgpass`, `.my.cnf`, cron scripts, backup agent configs) → BACKUP-DR.
- md5 verifier leak (any `pg_authid` dump, support bundle, logical-replication snapshot) → offline crackable → rotate per Remediation even without observed misuse.

**IaC propagation table** — audit these sources because they render into the runtime states above:

| IaC artifact | Risky pattern | Renders into |
|---|---|---|
| Terraform `aws_db_instance` / Cloud SQL | `publicly_accessible = true`, `ipv4_enabled = true` | internet-routed DB endpoint |
| Ansible templates | hardcoded `listen_addresses: '*'`, absent `require_secure_transport` line | vulnerable GUC state on every apply |
| docker-compose | `ports: ["5432:5432"]` / `"6379:6379"` | DNAT bypass of host firewall (→ FW) |
| Helm values | `auth.enabled: false`, `allowExternal: true` | unauth or open NetworkPolicy state |
| k8s Service | `type: LoadBalancer`/NodePort for StatefulSet DBs | cluster-exposed listener |

## Exploitation & Reproduction

Everything here is read-only demonstration. Connecting to any database from outside the audited host requires written authorization naming source and target; where absent, stop at binding-output proof and say so plainly in the report.

### E1 — PostgreSQL `trust` method (proof from file + optional live confirmation)

File excerpt evidence [ROOT]:

```
$ grep -nE '\b(trust|ident)\b' /etc/postgresql/16/main/pg_hba.conf
84:local   all             all                                     trust
```

Interpretation: line 84 matches every local connection for every database/user first — any shell account runs `psql -U postgres` straight to superuser with zero secrets. Optional live confirmation (authorized hosts only): `psql -h 127.0.0.1 -U postgres -c "SELECT current_user;"` returning a result *without any password prompt* proves it end-to-end.

### E2 — Unauthenticated Redis reachability

Authorized external test:

```bash
$ redis-cli -h <db-host> PING
PONG
```

`PONG` without `NOAUTH` error proves unauthenticated command execution surface exists; follow-up read-only context (still authorized): `redis-cli -h <db-host> INFO server | grep redis_version`. The RCE chain itself is documented cross-ref FW module demos — statically: attacker sets a key whose value is a cron entry or SSH public key, then `CONFIG SET dir /var/spool/cron` (+ `dbfilename root`) or `/root/.ssh` (+ `authorized_keys`), then `SAVE` rewrites the RDB payload onto that path as the redis user; cron/sshd consumes it. Never execute this chain against production — file-write side effects are destructive.

Without external authorization: report the binding proof instead — `ss -tlnp | grep :6379` showing `0.0.0.0:6379` plus FW-path analysis ("no firewall drop on INPUT dport 6379") is sufficient evidence of exposure; state that live probing was not performed and why.

### E3 — MongoDB authorization disabled

Authorized only:

```bash
$ mongosh --host <db-host> --quiet --eval 'db.adminCommand({listDatabases:1}).ok'
1
```

A numeric `1` (not an Unauthorized error, code 13) from an unauthenticated client proves open instance. Note the localhost-exception variant: fresh installs accept admin-user creation from localhost only until the first user exists — an instance stuck in that state is either open (if bindIp allows remote) or broken; flag both.

### E4 — MySQL FILE privilege → webshell chain (static reasoning)

Prerequisites observed during audit (all read-only checks): co-hosted web stack (`ss` shows 80/443 and 3306 on same box), app account holds FILE (`information_schema.USER_PRIVILEGES` row), `secure_file_priv` empty/unset. Chain reasoning, step by step:

1. Attacker has SQL injection into the app (injection modules) → executes statements as the app DB user.
2. That user's FILE privilege permits server-side writes: `SELECT '<payload>' INTO OUTFILE '<path>';`.
3. Because mysqld shares the filesystem with the web root and mysqld's user can write it (world-writable upload dir or misowned docroot), step 2 lands executable content under the document root, e.g. `/var/www/html/uploads/x.php` containing `<?php system($_GET["c"]); ?>`.
4. A plain GET request executes it as the web user → host foothold → pivot back to DB with full creds from app config.

Break points, in order of preference: revoke FILE from app accounts; set `secure_file_priv=/var/lib/mysql-files`; fix webroot ownership; separate DB host. Each independently kills step 2–4.

### E5 — MySQL anonymous/remote-root enumeration (read-only SQL)

```sql
SELECT User, Host FROM mysql.user WHERE User = '';                       -- anonymous rows
SELECT User, Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
```

Non-empty results are findings themselves; interpretation: anonymous rows inherit no privileges typically but permit connection attempts and version disclosure; `root@'%'` exposes the most privileged account to network brute force.

## Remediation

Apply under change-window approval with console/break-glass access confirmed first (hba or auth changes can lock out admins → keep a local console path per BASE module). Order: exposure fixes, then auth, then privilege revokes, then logging.

### PostgreSQL

**Complete hardened `pg_hba.conf` example** (adjust CIDRs/roles; order is the security property):

```
# FIXED — pg_hba.conf (first match wins; most specific first, deny-all last)
# TYPE      DATABASE        USER          ADDRESS              METHOD
# break-glass: OS postgres admin on console/socket only
local       all             postgres                           peer
# app tier: TLS + SCRAM only, pinned to app subnet
hostssl     appdb           appsvc        10.20.8.0/24         scram-sha-256
# streaming replication from known peers only
hostssl     replication     replicator    10.20.9.11/32        scram-sha-256
hostssl     replication     replicator    10.20.9.12/32        scram-sha-256
# admin plane via bastion CIDR only
hostssl     all             dbadmin       10.20.7.0/24         scram-sha-256 clientcert=verify-full
local       all             all                                scram-sha-256
# explicit deny-all so future edits fail closed
host        all             all           0.0.0.0/0            reject
host        all             all           ::/0                 reject
```

Reload with `sudo -u postgres psql -c "SELECT pg_reload_conf();"` — hba edits need reload, not restart.

**`postgresql.conf` hardening block** (merge into main file or conf.d; keep single source of truth):

```
# FIXED — security-relevant GUCs
listen_addresses = 'localhost'            # or explicit private IPs when clustered
ssl = on
ssl_cert_file = '/etc/postgresql/16/main/server.crt'
ssl_key_file  = '/etc/postgresql/16/main/server.key'   # chmod 0600, chown postgres:postgres
ssl_min_protocol_version = 'TLSv1.2'
password_encryption = 'scram-sha-256'
log_connections = on
log_disconnections = on
log_min_duration_statement = 1000         # ms; raise if log volume/latency hurts; never 0 on PII clusters
log_line_prefix = '%m [%p] %q%u@%d %r '   # role@db + client addr => attributable logs
```

Then `SELECT pg_reload_conf();` and confirm with `SHOW` per Verification.

**Role and grant remediation SQL** (superuser session; rotate secrets via your secret manager, not inline literals in shell history):

```sql
-- 1. Convert legacy md5 verifiers: re-set each password (GUC already flipped).
--    hba may stay on 'md5' method during migration: it accepts BOTH md5 and scram
--    verifiers; flip hba lines to scram-sha-256 only after this query returns zero rows.
ALTER ROLE appsvc PASSWORD '<new-secret>';   -- repeat per row of the md5 detector query

-- 2. Drop or demote extra superusers found by the rolsuper query.
ALTER ROLE legacy_admin NOSUPERUSER NOCREATEROLE NOCREATEDB;

-- 3. Lock public-schema CREATE (pre-PG15 clusters and pg_upgrade'd ones; PG15+ new
--    clusters ship locked — verify nspacl instead of trusting version):
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
--    Also fix templates so future databases inherit the lockdown:
\c template1
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- 4. Close default-database CONNECT for PUBLIC, grant explicitly:
REVOKE CONNECT ON DATABASE appdb FROM PUBLIC;
GRANT  CONNECT ON DATABASE appdb TO appsvc;
GRANT  CONNECT ON DATABASE appdb TO dbadmin;
GRANT  USAGE ON SCHEMA public TO appsvc;
```

Caveat to state honestly: revoking PUBLIC connect breaks tooling that relied on implicit access (monitoring agents, pgbouncer health checks, CI jobs) — inventory them first and grant named roles before the revoke lands; do both in one window.

### MySQL/MariaDB

Equivalent of `mysql_secure_installation`, as auditable steps. **Every statement below requires appropriate privileges and a change window** — run inside one admin session, not piecemeal:

```sql
-- Requires appropriate privileges and change window -------------------------
-- 1. Anonymous accounts:
DELETE FROM mysql.user WHERE User = '' AND Host <> 'localhost';  -- remote anons first
DELETE FROM mysql.user WHERE User = '';                          -- then local, after app check

-- 2. Legacy test database (grants rows too):
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db LIKE 'test%';

-- 3. Remote root: prefer removing over renaming; verify no automation depends on it
DROP USER IF EXISTS 'root'@'%';

-- 4. Rotate stale/native-password accounts onto current scheme:
ALTER USER 'appsvc'@'10.20.%' IDENTIFIED WITH caching_sha2_password BY '<new-secret>';

-- 5. Least-privilege replacement for any app using root today:
CREATE USER 'svc_app'@'10.20.%' IDENTIFIED WITH caching_sha2_password BY '<secret>';
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'svc_app'@'10.20.%';
FLUSH PRIVILEGES;
```

MariaDB differences: step 4 uses its native plugin default (`IDENTIFIED BY` alone is fine); password-quality enforcement installs `INSTALL SONAME 'cracklib_password_check';` instead of the MySQL component.

Config hardening (`[mysqld]`, drop-in file such as `/etc/mysql/conf.d/99-hardening.cnf`):

```
# FIXED
[mysqld]
bind-address = 127.0.0.1                # private LAN IP when networked DB host
require_secure_transport = ON           # MariaDB >=10.5.2 else enforce at proxy/TLS layer
local_infile = OFF
secure_file_priv = /var/lib/mysql-files
general_log = 0                         # enable transiently under change control only
slow_query_log = ON
slow_query_log_file = /var/log/mysql/slow.log
log_error = /var/log/mysql/error.log
```

Restart required for `bind-address`/`secure_file_priv` changes (schedule it); others load dynamically. After enabling `require_secure_transport=ON`, verify every service account can actually negotiate TLS *before* closing the window — see negative tests.

### Redis

Hardened `redis.conf` block (keep the rest of the file; these keys replace risky ones):

```
# FIXED
bind 127.0.0.1 ::1
protected-mode yes
port 6379                      # or port 0 + unixsocket when no TCP consumer exists
aclfile /etc/redis/users.acl   # supersedes requirepass; remove requirepass to avoid drift
dir /var/lib/redis
dbfilename dump.rdb
```

`/etc/redis/users.acl` example (`0600 redis:redis`; generate secrets with `openssl rand -hex 32`, store hashed — `#<sha256>` form — rather than cleartext where tooling allows):

```
# FIXED — users.acl
user default off
user svc_app on ><generated-secret> ~svc_app:* &svc_app:* +@read +@write -@dangerous -@scripting
user metrics_ro on ><generated-secret> ~* &* +info +ping +client|id
```

Notes: `&channel` patterns need Redis ≥6.2; on 6.0/6.1 omit them. `-@scripting` is deliberate (EVAL is not in @dangerous). If stuck pre-6 without ACLs: `requirepass <secret>` plus `rename-command CONFIG ""` and `rename-command FLUSHALL ""` is the accepted legacy shape — document the obfuscation in the secret manager, plan the ACL migration.

Apply with restart (`systemctl restart redis-server`) during a window — ACL switchover disconnects existing clients lacking credentials; update app configs first.

RDB/AOF perms after first save: `chmod 600 /var/lib/redis/dump.rdb && chown redis:redis /var/lib/redis/dump.rdb` (files are created by the service user with its umask; fix once, verify after next save).

### MongoDB

Hardened `/etc/mongod.conf` fragment:

```yaml
# FIXED
net:
  port: 27017
  bindIp: 127.0.0.1                 # or comma-separated private IPs for replica peers
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongo/mongod.pem
security:
  authorization: enabled            # Community OK; native at-rest encryption below is EE-only
  # enableEncryption: true          # Enterprise only — do NOT set on Community builds;
                                    # use disk-level encryption (LUKS on the dbPath volume)
  keyFile: /etc/mongodb-keyfile     # replica sets only; 0400 mongod:mongod
setParameter:
  enableLocalhostAuthBypass: false  # only AFTER the first admin user exists
```

Setup order matters: start with `authorization: enabled`, create the first admin via localhost exception (`db.createUser({user:"siteAdmin",pwd:"<secret>",roles:["root"]})`), then add `enableLocalhostAuthBypass: false` and restart. Create per-service least-privilege users:

```javascript
use appdb
db.createUser({user:"svc_app", pwd:"<secret>", roles:[{role:"readWrite", db:"appdb"}]})
```

Community at-rest honesty for the report: recommend LUKS/dm-crypt under `storage.dbPath` (or cloud-volume encryption) as the equivalent control; name Enterprise `enableEncryption` only when licensing actually covers it.

### Application-Side Accounts

- Replace any app login that holds SUPERUSER/root-equivalent with a DML-only account (SQL patterns in the MySQL and PostgreSQL blocks above); keep one admin role per human, never shared.
- One DB user per service; when splitting a shared credential, deploy dual-user overlap briefly (both grants live) then revoke the shared one — same staged pattern as password rotation.
- Move connection strings into the secret manager/deploy-time injection path used by this org (→ SECRETS/TOK/HSECRET); grep repos per Taint Tracing and rotate anything found committed.

## Verification & Validation

Re-run the What To Check sweep first — expected deltas: listener lines now loopback/private-only; previously-missing keys present. Then engine-specific proof.

**PostgreSQL**

```bash
sudo -u postgres psql -Atc "SHOW listen_addresses; SHOW ssl; SHOW ssl_min_protocol_version; SHOW password_encryption;"
sudo -u postgres psql -c "SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword LIKE 'md5%';"   # expect: 0 rows after migration window
sudo -u postgres psql -Atc "SELECT nspacl FROM pg_namespace WHERE nspname='public';"                       # expect no PUBLIC CREATE element
grep -nE '\b(trust|ident|password)\b' "$(sudo -u postgres psql -Atc 'SHOW hba_file;')"                     # expect: no matches outside comments
```

Negative tests: from an app-tier host, `psql "host=<db> dbname=appdb user=appsvc sslmode=disable"` must fail with a `no pg_hba.conf entry ... SSL off` FATAL (proves hostssl enforcement); `psql "host=<db> ... sslmode=require"` must succeed and appear in logs as a `connection authorized` line carrying `%u@%d %r`.

**Staged-rollout warning (state it in every report):** flipping `password_encryption` changes nothing retroactively — each role keeps md5 until its password is re-set. Migration shape: enable scram GUC → rotate passwords over days/weeks → hba stays on `md5` method meanwhile because that method transparently accepts SCRAM verifiers too → flip hba lines to `scram-sha-256` only after the md5 detector query returns zero rows. Skipping the last step silently downgrades new verifiers' protection at the wire level; skipping rotation bricks logins.

**MySQL/MariaDB**

```bash
mysql -NBe "SHOW VARIABLES WHERE Variable_name IN ('bind_address','require_secure_transport','secure_file_priv','local_infile');"
mysql -NBe "SELECT User,Host FROM mysql.user WHERE User='';"                                   # expect: Empty set
mysql -NBe "SELECT User,Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');"  # expect: Empty set
ss -tlnp | grep :3306                                                                          # expect loopback/private IP only
```

Negative test (from app host): plain TCP connect without TLS against `require_secure_transport=ON` fails with `ERROR 3159 (HY000): Connections using insecure transport are prohibited while require_secure_transport=ON.`; the app's normal path must still serve requests afterward — if it errors, a driver lacks TLS support (regression note below).

**Redis**

```bash
redis-cli ACL LIST | head                        # expect: default off, named users minimal
redis-cli ACL GETUSER default                    # flags must include 'off'
ls -l /var/lib/redis/dump.rdb                    # expect -rw------- redis redis
systemctl is-active redis-server
```

Negative test: `redis-cli -h <db-host> PING` from an external authorized vantage now returns `(error) NOAUTH Authentication required.` (or connection refused once bind/firewall tightened). App regression check: exercise the app's cache path after switching it to the svc_app ACL credentials.

**MongoDB**

```bash
mongosh --host <db-host> --quiet --eval 'db.adminCommand({listDatabases:1})'   # unauth: expect MongoServerError Unauthorized (code 13)
mongosh -u siteAdmin -p '<secret>' --eval 'db.runCommand({connectionStatus:1})' # auth: expect authenticated user echoed
grep -A2 '^security:' /etc/mongod.conf                                          # authorization: enabled present
```

**Regression watchlist**

- TLS-enforcement switches (`hostssl`, `require_secure_transport`, `requireTLS`) break legacy drivers/clients lacking TLS or SNI support — stage per-service, keep old-path metrics for one cycle.
- hba reordering can lock out admins instantly — apply the break-glass `local all postgres peer` rule first, verify console login works before reloading, cross-ref BASE console-access procedure.
- Redis ACL switchover and Mongo authorization-enable both drop existing unauth clients — coordinate app deploys carrying new credentials in the same window.
- PUBLIC-grant revocations can break monitoring/pgbouncer health checks (PostgreSQL) and test suites assuming `test` database (MySQL) — inventory consumers before revoke/drop.

**IaC repo greps** (run in config-as-code repos; findings map back to runtime severities):

```bash
grep -RnsE 'publicly_accessible\s*=\s*true|ipv4_enabled\s*=\s*true' --include='*.tf' .
grep -RnsE 'listen_addresses\s*=\s*.{0,4}(0\.0\.0\.0|\*)|bind-address\s*=\s*(0\.0\.0\.0|\*)' playbooks/ roles/ templates/
grep -RnsE '(5432|3306|6379|27017)\s*:\s*(5432|3306|6379|27017)' docker-compose*.yml compose*.yaml
grep -RnsE 'auth\.enabled:\s*false|allowExternal:\s*true|nopass' charts/ values*.yaml kustomize/
grep -rnE '(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^/\s]*:[^@\s]+@' . | grep -v node_modules      # committed connection strings → SECRETS/TOK
```

## Severity Assessment

Anchors use CVSS v3.1 base vectors; the vector's Attack Vector field encodes the reachability weighting — re-score with `AV:N` only when FW-path analysis confirms untrusted-network reachability, and drop to `AV:L` for socket-only deployments. Report the vector alongside the score.

| # | Finding | Vector | Score | Band |
|---|---|---|---|---|
| S1 | Unauth Redis/MongoDB reachable from untrusted network (`PONG`/`listDatabases` without creds) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| S2 | `pg_hba.conf` `trust` (or TCP `ident`) from broad CIDR — auth bypass to full DB control | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| S3 | Engine bound non-loopback-wide + weak/default/no-auth-required state behind some credential gate (incl. `root@'%'`) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High |
| S4 | Application connects as SUPERUSER / root-equivalent / `+@all` Redis user | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.0 | High |
| S5 | Stale md5 verifiers persisting post-migration-window (offline-crackable once any hash source leaks) | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L` | 6.8 | Medium |
| S6 | Plaintext app↔DB transport across a real network hop | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` | 6.3 | Medium |
| S7 | Connection/disconnection logging absent or unattributable (no identity fields) | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` | 4.6 | Medium |
| S8 | Verbose DB errors surfaced to end clients, no other exposure | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | 3.5 | Low |

Reachability-weighted framing: S1/S2 need no credentials and no foothold — they are internet-breach vectors on their own; S3 assumes a leaked or guessed credential; S4–S6 assume an adjacent foothold already exists and score *amplification* of that foothold. A finding moves up one band when it chains with an open entry point from another module's report (web RCE + S4 = cluster takeover), and down when FW proves the path dead — never delete a binding finding for being firewalled; record it as defense-in-depth gap with reduced severity instead.

## Common False Positives

1. **Managed cloud DBs (RDS, Cloud SQL, Azure DB).** OS and config files are unreadable by design — do not report "cannot read postgresql.conf" as a finding. Audit parameter groups / flags via IaC and cloud APIs instead (`aws_rds_cluster_parameter_group`, Cloud SQL database flags for `require_secure_transport`, `local_infile`), and record the limitation explicitly in the report scope.
2. **Replica-only nodes.** Streaming-replication roles, replication-scoped hba lines, and even md5 verifiers on a dedicated `replicator` role can be platform-standard topology plumbing. Verify against the primary's config and the clustering tooling before flagging; findings still apply to the primary.
3. **Socket-only local connections.** `listen_addresses=''`, MySQL `skip_networking=ON`, or unix-socket-only Redis (`port 0`) mean no TCP listener exists — "bound to wildcard" claims from stale config files are moot when `ss -tlnp` shows nothing for that port. Verify `ss` output agrees with every binding finding before reporting.
4. **protected-mode misread.** Redis `protected-mode yes` is not proof of safety when `bind 0.0.0.0` is set explicitly — protected-mode yields to explicit configuration. Judge bind + ACL together, never protected-mode alone.
5. **Passwordless roles with non-password auth.** PostgreSQL LOGIN roles with NULL verifiers are intentional under `peer`/`cert` hba methods; cross-check the hba method column before raising the passwordless-role finding.

## References

- PostgreSQL documentation — configuration (`postgresql.conf` GUCs incl. SSL and logging parameters) and client authentication (`pg_hba.conf` methods, SCRAM migration notes): postgresql.org/docs
- MySQL reference manual — server system variables (`bind_address`, `require_secure_transport`, `secure_file_priv`), access control/account management, `LOAD DATA`/`SELECT ... INTO OUTFILE` security notes: dev.mysql.com/doc
- Redis documentation — `redis.conf` parameters, ACL syntax and categories, security guidance: redis.io/docs
- MongoDB documentation — configuration file options (`net.bindIp`, `security.authorization`, TLS), SCRAM authentication, localhost exception, WiredTiger encryption at rest (Enterprise): mongodb.com/docs
- CIS Benchmarks (confirm current edition per engine version in the CIS catalog before citing section numbers): CIS PostgreSQL Benchmark; CIS MySQL Community Server Benchmark / CIS MariaDB Benchmark; CIS Redis Benchmark; check catalog coverage for your exact MongoDB major version rather than assuming one exists
- CWE-16: Configuration; CWE-284: Improper Access Control — cwe.mitre.org
