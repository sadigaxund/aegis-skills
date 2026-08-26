---
name: aegis-host-secrets
description: Inventories and hardens secrets stored on a Linux host — env and config files, systemd environments, cron and history leakage, SSH/TLS/signing key material, database credential chains, environment-variable boundaries, rotation posture, and backup hygiene — with read-only evidence commands and exact hardened end states.
category_slug: HSECRET
cwe: [CWE-732, CWE-312]
owasp: A02:2021 – Cryptographic Failures
---

> **REDACTION RULE — applies to every phase of this module and to the final report.** When any sweep surfaces a real secret value, the report prints exactly the first four characters followed by `…REDACTED` (shape: `sk-l…REDACTED`). Never transcribe full values into reports, tickets, chat, shell transcripts, or evidence archives. All examples in this document use deliberate fakes such as `EXAMPLE_NOT_A_REAL_TOKEN`. If a command would echo a secret (e.g., `systemctl show -p Environment`), capture only hit counts or redacted previews.

## Scope & Objectives

Audit secrets and sensitive material stored **on one Linux host** (or rendered onto it from its config-as-code repo). Seven objectives, in execution order:

1. **Inventory sweep (read-only)** — locate every place credentials actually live in practice: `.env` files in app directories, config files (`application.yml`/`.properties`, `settings.py`, `config.json`, PHP `.env`), systemd `Environment=`/`EnvironmentFile=`, `/etc/<app-name>/*`, `docker-compose.yml` environment blocks plus sibling `.env`, crontab inline creds, shell rc exports, ops history files, backup scripts with embedded DB passwords.
2. **Permission audit per location** — verify owner/mode against the expected-state table; hunt group/world-readable secret files; flag group/world-writable configs; enforce 750-not-755 home dirs for service accounts.
3. **Private keys & certs on disk** — SSH host + client keys, the sshd `StrictModes` permission chain, TLS key pairs, application signing/JWT secrets in configs, GPG material.
4. **Database credential exposure chains** — DSN strings with inline passwords, `.my.cnf` client sections, `.pgpass`, replication configs, backup scripts, and where dumps land.
5. **Environment-variable reality check** — establish honestly what `/proc/<pid>/environ` does and does not expose, enumerate real leak channels, and issue a scoped verdict.
6. **Rotation posture** — detect "unchanged since forever" credential files as Needs-Review culture flags (not auto-findings).
7. **Backup & snapshot hygiene** — unencrypted copies of secret-bearing dirs, dump placement, encryption presence.

Out of scope (cross-references): token *storage design inside applications* and token-rotation mechanics → TOK module (`skills/server/api-token-security/SKILL.md`, which owns the zero-downtime rotation runbook); secrets baked into container images or build layers → supply-chain module; network exposure of the services holding these secrets → FW/TLS modules; SELinux/AppArmor label analysis beyond noting its existence → SANDBOX module.

Operating rules:

- All inspection is read-only. Mutating commands appear only under Remediation and require change-window approval.
- Commands needing root are tagged `[ROOT]`. Without root, audit what is world-readable plus the config repo, and state the coverage gap in the report — an unprivileged sweep is a lower bound, not an inventory.
- Run `cat /etc/os-release` first; Debian/Ubuntu vs RHEL paths and groups differ (`ssl-cert`, `shadow`, `ssh_keys`) and are called out inline.
- Deliverable: findings table (location | observed owner:mode | expected | severity | evidence snippet redacted per rule above) plus a separate Needs-Review list for rotation-culture indicators.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **DAC bits**: the Unix owner/group/other permission triple deciding who may read or write each file
- **loosest-link rule**: a secret's protection equals the weakest directory permission anywhere on its path
- **world-readable**: any local account can read it — the classic secret-file defect
- **process environment**: the variables a running program received; they leak via child processes, dumps, and debuggers
- **rotation**: periodically replacing credentials so old ones stop working
- **/etc/shadow shape**: root-owned, readable by one narrow system group, nothing to others — the model for every secret file
- **redaction**: reports show only the first four characters plus `…REDACTED`, never full values
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

- A secret at rest exists in three states: **file bytes**, **process environment**, and **memory**. This module owns files and environments; memory forensics belongs to incident response, not a hardening audit.
- Every disk path resolves through discretionary access control: owner / group / other bits on each directory component plus the final file. A secret's protection equals the **loosest bit along its entire path** — a 600 `.env` inside a 755 directory that lets anyone list and read it is a 600 file with theater around it. Judge paths, not files.
- The threat actor is **any principal that can execute code locally**, and above all the internet-facing service's own user: web RCE as `svc-api` converts every `svc-api`-readable credential into attacker property instantly. Design question number one for every finding is therefore *"which principals can read this?"*, never *"is it encrypted?"*.
- Boundary honesty between states: disk files are governed purely by DAC bits; `/proc/<pid>/environ` is governed by kernel checks (same-UID-or-capability, tightened further by Yama `ptrace_scope`). Do not conflate them when rating env-var risk — env vars are **not** world-readable files, but they leak sideways through inheritance into child processes, crash dumps, `ps e`/debuggers, and scripted `set -x`.
- Reference standard: `/etc/shadow` — root-owned, shared only with a narrow system group (`shadow`), zero world access. That shape (owner-scoped, group only where a service genuinely needs read, nothing to other) is the template every secret-bearing file must approximate.
- Chain view: one foothold plus lazy permissions equals a lateral-movement kit. The audit's job is to shrink the readable set so a compromised app user finds almost nothing worth stealing.

## What To Check

Execute in order. Record evidence for every check; apply the redaction rule to all output that enters the report.

### 1. Broad filename sweep
Run the paste-ready sweep block at the end of "Where To Look". Triage every hit against the expected-state table below. Acceptance: zero secret-named files carry group or other read bits.

### 2. Application config files
Identify app roots from `systemctl cat <unit>` (WorkingDirectory, ExecStart path), then inspect `/srv`, `/opt`, `/var/www`, and webroots for `.env`, `application.yml`/`application.properties`/`config.json`, Django `settings.py`, PHP `.env`. Classify keys matching `(secret|password|token|api_key|dsn|connectionstring)`. `[ROOT]` for dirs under 750. Acceptance: every credential-bearing file is 600/640 owner-scoped, its parent directory ≤750, and no literal value is committed in a tracked file.

### 3. systemd environments
List running units (`systemctl list-units --type=service --state=running`), then per unit run `systemctl cat UNIT` and grep `^Environment=` / `^EnvironmentFile=` across `/etc/systemd/system` and `/usr/lib/systemd/system`. Verify each EnvironmentFile target's mode. Know the boundary: `systemctl show -p Environment UNIT` prints values **to any local user** — inline `Environment=` lines are world-queryable, not private. Acceptance: no inline secrets; every EnvironmentFile target 640 root:<app-group> or tighter.

### 4. Cron and scheduled jobs
`[ROOT]` Read `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*` (Debian) or `/var/spool/cron/*` (RHEL), plus scripts they invoke under `/usr/local/bin`, `/etc/cron.*`. Hunt `-p`, `--password=`, `PGPASSWORD=`, `curl -H 'Authorization: ...'`, `TOKEN=` inline. Acceptance: no credentials inside any crontab entry or invoked script; creds live in 600/640 files sourced by wrappers.

### 5. Shell rc files and history leakage
For `/root` and every `/home/*`: grep rc files (`.bashrc`, `.bash_profile`, `.profile`) for `export .*=(TOKEN|SECRET|PASS|KEY)` and grep history files (`.bash_history`, `.zsh_history`, `.sh_history`) for `export`-credential shapes and password-on-command-line shapes (`mysql -pWORD`, `psql "password=..."`). Report **hit counts and line numbers only** — never the matched text. Acceptance: zero hits.

### 6. SSH host keys
`[ROOT]` `stat -c '%a %U:%G %n' /etc/ssh/ssh_host_*_key` — expect exactly 600 root:root (RHEL may show root:ssh_keys); `.pub` counterparts 644 are correct and public. A private host key readable beyond root means any local user can impersonate the host (MITM) — Critical if the box is SSH-reachable.

### 7. SSH client keys and the StrictModes chain
For `/root` and each service/human homedir with a `.ssh`: verify home dir ≤755 and **not group/world-writable**, `.ssh` 700, private keys (`id_*` minus `.pub`) 600 owned by the account, `authorized_keys` 600 owned by the account. Understand and document the trap: sshd `StrictModes yes` (default) **refuses pubkey auth** if the home dir, `.ssh`, or `authorized_keys` are group/world-writable or wrongly owned — users see only `Permission denied (publickey)` while the real reason sits in `journalctl -u ssh` as *"Authentication refused: bad ownership or modes"*. This is why well-meant `chmod 777 $HOME` fixes silently break logins.

### 8. TLS key material
Debian/Ubuntu: `/etc/ssl/private` must be 710 root:ssl-cert; contained keys 600–640 root:ssl-cert. RHEL: `/etc/pki/tls/private` keys 600 root:root (services whose master process reads them as root need nothing extra). Web/proxy masters (nginx, haproxy, apache) start as root and bind the key before dropping privileges — do not widen perms for worker users; application services needing direct read join the `ssl-cert` group instead. Hunt any `*.key`/`*.pem` private bundle outside these dirs, especially under webroots.

### 9. Signing and JWT secrets
Grep configs and source trees on disk for `jwt|signing[_-]?key|secret_key_base|SECRET_KEY` literals. Acceptance: injected via protected EnvironmentFile or a 600 mounted file; never a constant in a repo-rendered file. Runtime token-handling depth → TOK module.

### 10. GPG material
`~/.gnupg` must be 700 (gpg enforces this itself). Raw private key blobs exported into homedirs or webroots (`*.asc` with `-----BEGIN PGP PRIVATE KEY BLOCK-----`, stray `private-keys-v1.d` copies outside 700 dirs) are findings. Agent sockets under `/run/user/<uid>/gnupg` are IPC endpoints, not key material — never flag them.

### 11. Database client-side credential files
Check `~/.pgpass` (libpq refuses group/world-readable files — a 644 pgpass silently stops working, which is itself an availability bug), `~/.my.cnf [client] password=`, `/root/.mylogin.cnf` (created by mysql_config_editor), replication credentials (older MySQL `master.info`; PostgreSQL `primary_conninfo` containing `password=` in `postgresql.auto.conf`), and DSN strings (`postgres://user:pass@...`, `mysql://...`) in app configs. Host-side exposure only here; token semantics → TOK module.

### 12. Backup scripts and dump destinations
Locate scripts performing dumps (`mysqldump`, `pg_dump`, `sqlite3 .backup`, tar-of-/etc habits). For every output artifact found under `/tmp`, `/var/tmp`, `/var/backups`, `/srv`, `/root`: stat its mode and run `file <artifact>` to classify compression vs encryption (plain gzip = unencrypted; age headers or OpenSSL `Salted__` payloads = encrypted). Verify `/root` itself is 700 before judging a `/root/etc-backup.tar.gz` acceptable. One-liner principle to record in findings: *a backup living only next to what it backs up is not a backup — ship encrypted copies off-host*.

### 13. Environment-variable reality check
Empirically confirm the boundary (Demo C in Exploitation & Reproduction): attempt reading another user's `/proc/<pid>/environ` unprivileged — expect Permission denied — then note `[ROOT]` sudo reads it, so findings must name the reading principal. Enumerate leak channels present on this host: `cat /proc/sys/kernel/core_pattern` (cores piped to a world-writable path capture env images), `coredumpctl list` availability, whether any unit/script runs with `set -x` or echoes env, `ps eww` self-test. Then issue the verdict table (end of this section's guidance in Patterns & Signatures).

### 14. Rotation posture
`find` cred-bearing files with `-mtime +730` (two years untouched). This is a **culture indicator, Needs-Review — never an auto-finding**: mtime resets on restore/copy and proves nothing about rotation by itself. Cross-reference each stale file against the rotation ledger/runbook; token rotation mechanics → TOK module rotation runbook.

### 15. Backup/snapshot hygiene beyond the filesystem
From the host you cannot see cloud-snapshot encryption state — say so plainly. If a config-as-code repo is available, grep it for snapshot/volume definitions lacking encryption flags (Verification & Validation has the greps). Flag unencrypted local archives of secret-bearing directories as Medium regardless of location.

## Where To Look

Evidence collection: `tools/sweeps/sweep-secrets-host.sh` captures `[HSEC-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

Expected end-states per location. Distro variants noted inline; when Debian and RHEL differ, detect first, then judge against the matching row.

| Location | Expected owner:mode | Common bad state | Why it matters |
|---|---|---|---|
| `/etc/shadow` | 640 root:shadow (Debian); 000 root:root (RHEL) | 644, or group-writable | Reference standard shape for all secret files |
| App `.env` (`/srv/app/.env`, `/var/www/html/.env`, PHP `.env`) | 600 appuser:appgroup | 644; parent dir 755; file also committed to git | DSNs and API keys readable by every local account |
| App configs (`/etc/app-name/*.yml`, `config.json`, `settings.py`) | 640 root:appgroup | 644 with inline `SECRET_KEY`/JWT secret | Signing keys readable repo-wide on the box |
| systemd unit with `Environment="PASS=..."` | unit 644 is fine; the pattern is not | Credentials inline | `systemctl show -p Environment` exposes values to any local user |
| `EnvironmentFile=` target | 640 root:appgroup | 644; or missing while unit expects it (boot failure) | The intended fix-path home for env secrets |
| `docker-compose.yml` sibling `.env` | compose 644 ok; `.env` 600 deployer:deployer | `.env` 644 in deploy dir, tracked in git | Injects container env; host readers get everything |
| Crontab spool + `/etc/cron.d/*` | spool 600 user:crontab (Debian) / 600 user:root (RHEL); cron.d 644 root | Inline `-pPASS` in entries or invoked scripts | Root jobs replay embedded passwords nightly |
| `~/.bashrc` / `~/.profile` exports | 600-ish, owner-only write | 644 with `export TOKEN=...` | Session-wide spill to anyone who can read the dotfile |
| `~/.bash_history` and siblings | 600 owner | 644 containing `-pPASS` / `export TOKEN` lines | Replayable plaintext credentials from ops muscle memory |
| `~/.ssh/` chain | home ≤755 non-gw; `.ssh` 700; `id_*` 600; `authorized_keys` 600 | keys 644; home 777 | Key theft; StrictModes auth breakage |
| `/etc/ssh/ssh_host_*_key` | 600 root:root (RHEL: root:ssh_keys); `.pub` 644 | 640/644 private key | Host impersonation / MITM for any reader |
| `/etc/ssl/private` (+ `/etc/pki/tls/private`) | dir 710 root:ssl-cert; keys 600–640 root:ssl-cert (Debian); 600 root:root (RHEL) | dir 755; key 644 | TLS private key theft → decryption/MITM |
| `~/.pgpass` | 600 owner | 644 — libpq then refuses the file | Replication/service DB creds; silent auth fallback |
| `/root/.my.cnf` `[client]` | 600 root:root | 644 | Root MySQL password world-readable |
| Backup/dump artifacts (`/tmp`, `/var/backups`, `/srv`) | target 600, dir 700/750 | 644 `*.sql.gz` in `/tmp` | Classic exfiltration prize, no privilege needed |
| `/root` itself | 700 root:root | 755 exposing `etc-backup*.tar.gz` | Amplifies every root-homed artifact above |
| Core-dump destination (`kernel.core_pattern`) | root-only dir/path | Pipe/file into world-writable dir | Core images may embed full process environment |

Distro variance reminders: shadow group differs (`shadow` vs `root`+000), TLS dirs differ (`/etc/ssl/private` vs `/etc/pki/tls/private`), ssh host-key group differs (`root` vs `ssh_keys`). Detect with `cat /etc/os-release`, then apply the matching row — never blend them.

### Paste-ready read-only sweep

```bash
#!/usr/bin/env bash
# READ-ONLY host secret sweep. Prints metadata and hit counts ONLY — never contents.
# REDACTION RULE: do not extend this script to print file values into reports.
# Full coverage needs [ROOT]; unprivileged runs see a partial inventory — record coverage level.

echo '== [1] secret-named files readable by group or other =='
find / -xdev -type f \( -name '*.env' -o -iname '*credential*' -o -iname '*secret*' \
     -o -name '*.pem' -o -name '*.key' -o -name '.pgpass' -o -name '.my.cnf' \) \
     -perm /044 -printf '%m %u:%g %p\n' 2>/dev/null
echo '== [2] private key files missing owner-only protection =='
find / -xdev -type f \( -name 'ssh_host_*_key' -o -name 'id_rsa' -o -name 'id_ed25519' \
     -o -name 'id_ecdsa' \) ! -name '*.pub' ! -perm -go-rwx -printf '%m %u:%g %p\n' 2>/dev/null
echo '== [3] per-user SSH directory chain =='
for h in /root /home/*; do [ -d "$h" ] && \
     stat -c '%a %U:%G %n' "$h" "$h/.ssh" "$h/.ssh/authorized_keys" "$h/.ssh/id_"* 2>/dev/null; done
echo '== [4] systemd units embedding env or referencing env files =='
grep -RnsE '^[[:space:]]*(Environment|EnvironmentFile)=' /etc/systemd/system /usr/lib/systemd/system 2>/dev/null
echo '== [5] EnvironmentFile targets and their modes =='
grep -RhE '^[[:space:]]*EnvironmentFile=' /etc/systemd/system 2>/dev/null | cut -d= -f2- | tr ' ' '\n' \
     | while read -r f; do [ -f "$f" ] && stat -c '%a %U:%G %n' "$f"; done
echo '== [6] credential-shaped history lines (counts only) =='
find /root /home -maxdepth 2 -type f -name '.*history' 2>/dev/null | while read -r hf; do
  printf '%s : export=%s pwflag=%s\n' "$hf" \
    "$(grep -ciE 'export[[:space:]]+[A-Za-z_]*(PASS|TOKEN|SECRET|KEY)' "$hf")" \
    "$(grep -cE '[[:space:]]-p[^[:space:]]' "$hf")"
done
echo '== [7] pgpass / my.cnf modes =='
find /root /home -maxdepth 2 -type f \( -name '.pgpass' -o -name '.my.cnf' -o -name '.mylogin.cnf' \) \
     -exec stat -c '%a %U:%G %n' {} + 2>/dev/null
echo '== [8] TLS key material under system stores =='
stat -c '%a %U:%G %n' /etc/ssl/private /etc/pki/tls/private 2>/dev/null
find /etc/ssl/private /etc/pki/tls/private /etc/nginx/ssl -maxdepth 1 -type f -perm /077 \
     -printf '%m %u:%g %p\n' 2>/dev/null
echo '== [9] dumps/backups world-readable in shared dirs =='
find /tmp /var/tmp /var/backups /srv -xdev -maxdepth 3 -type f \
     \( -name '*.sql*' -o -name '*.dump*' -o -name '*.bak' -o -name '*.tar.gz' \) -perm -004 \
     -printf '%m %u:%g %p\n' 2>/dev/null
echo '== [10] core dump destination and /root posture =='
cat /proc/sys/kernel/core_pattern 2>/dev/null
stat -c '%a %U:%G %n' /root 2>/dev/null
```

Interpretation: sections [1], [2], [8], [9] must return **zero lines** on a clean host; section [5] must list only 0640/0600 targets; section [3] must show the full StrictModes chain (≥700-or-tighter home, 700 `.ssh`, 600 files).

## Patterns & Signatures

### File permission end-states

```bash
# VULNERABLE
-rw-r--r-- 1 app app 512  /srv/app/.env     # 644: group+other can read DSNs and API keys
drwxr-xr-x 5 app app 4096 /srv/app          # 755 parent: any user lists the dir
-rw-rw-r-- 1 app app 512  /srv/app/.env.bak # 664 + stale copy: worst of both worlds
# FIXED
-rw------- 1 app app 512  /srv/app/.env     # 600
drwxr-x--- 5 app app 4096 /srv/app          # 750
```

### docker-compose environment injection

```yaml
# VULNERABLE — literal secret in a file that is almost certainly tracked in git
services:
  api:
    environment:
      DATABASE_PASSWORD: "EXAMPLE_NOT_A_REAL_PASSWORD"
# FIXED — env_file outside git; mode 0600 deployer:deployer on the host
services:
  api:
    env_file:
      - /etc/api/api.env
```

### systemd unit environments

```ini
# VULNERABLE — inline value retrievable by ANY local user:
#   systemctl show -p Environment api.service
[Service]
Environment="DATABASE_URL=postgres://api:EXAMPLE_NOT_A_REAL_PASSWORD@db.internal/apidb"

# FIXED — value lives in /etc/api/api.env, 0640 root:api; UMask keeps created files tight
[Service]
EnvironmentFile=/etc/api/api.env
UMask=0027
```

### Django settings constant

```python
# VULNERABLE
SECRET_KEY = "EXAMPLE_NOT_A_REAL_SECRET"        # constant in tracked source

# FIXED
import os
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]    # supplied via protected EnvironmentFile
```

### Database dump invocation

```bash
# VULNERABLE — password lands in process list, shell history, AND the dump is world-readable in /tmp
mysqldump -u root -pEXAMPLE_NOT_A_REAL_PASSWORD appdb | gzip > /tmp/appdb.sql.gz

# FIXED — credentials in a 0600 defaults-extra-file; umask guards the artifact
umask 077
mysqldump --defaults-extra-file=/root/.my.app.cnf appdb | gzip > /var/backups/appdb-$(date +%F).sql.gz
```

### Signature greps (evidence collection, counts/redacted previews only)

```bash
grep -RniE '(secret|password|token|api_key)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/_-]{8}' \
     /srv /opt /etc 2>/dev/null            # literal-looking assignments in configs/source
grep -RniE 'jwt|signing[_-]?key|secret_key_base' /srv /opt /etc --include='*.yml' --include='*.py' \
     --include='*.json' --include='*.properties' 2>/dev/null   # signing material by name
grep -Rns 'BEGIN.*PRIVATE KEY' /srv /opt /var/www 2>/dev/null  # key blobs parked outside key dirs
```

### Environment-variable verdict table

| Factor | Env vars (`Environment=`/`--env-file`) | Restricted-perm file (600/640) or secret manager |
|---|---|---|
| Who can read at rest | Any local user via `systemctl show -p Environment`; same-UID peers via `ps e`/`/proc` within kernel limits | Only owner/group per DAC bits |
| Sideways leak channels | Subprocess inheritance, `set -x` traces, crash-dump env images, child-process debuggers | None beyond path/DAC weaknesses |
| Rotation | Requires restart of every inheriting process | File swap + targeted reload; manager: automatic |
| Auditability | Invisible to file sweeps; easy to sprawl | Grep-able inventory; explicit modes |
| Verdict | **Acceptable for low-sensitivity config** (feature flags, non-credential endpoints) with `UMask=0027`, no `set -x`, controlled core dumps | **Required practice for credentials** |

Docker `--env-file` shares these semantics exactly: the CLI parses the file client-side, values enter container env and are visible to anyone with Docker control (itself root-equivalent); the on-host file's DAC bits still govern pre-launch exposure.

## Taint Tracing Guidance

For hosts managed as code, trace each secret along this flow and judge the sink:

- **Sources**: variable definitions (`*.tfvars`, Ansible `group_vars`, compose `environment:` blocks), CI/CD variables echoed to disk by deploy scripts, templates embedding literals, values committed historically (git history retains every past version — see rule below).
- **Propagation**: variable → template/render step → packaged artifact → deployed file; also direct `scp`/`rsync` of `.env` during deploys. The decisive attribute riding along is the **file resource's mode** — an otherwise perfect vault-fed pipeline that renders `mode: '0644'` produces a Critical finding.
- **Sinks and judgment**: on-host files (mode decides), unit `Environment=` lines (any local user reads), container env injection (host `.env` perms decide pre-launch). A sink is compliant only when cred-bearing content lands owner-scoped (600) or group-scoped to a named service group (640) with a ≤750 parent directory.
- **Rules**: one source maps to one designated sink; forbid staging copies into `/tmp` during deploy; require explicit modes on every file/template resource that touches credentials (`copy: ... mode: '0600'`) — never rely on umask luck; treat any secret ever committed as burned.
- **Burned-secret rule (SECRETS code-module)**: deleting a credential from HEAD does not un-leak it — git history, forks, and clones retain it. Rotation is the only cure. Repo-side detection depth → `skills/code/secrets-data-exposure/SKILL.md`; rotation mechanics → TOK module runbook.
- **Worked micro-trace**: compose `.env` committed → deployed beside `docker-compose.yml` mode 644 → any local account reads DB password → chain to database host. Trace back through `git log -p -- '**/.env*'` to scope which rotations are owed.

## Exploitation & Reproduction

All demonstrations are strictly read-only. Run unprivileged first to emulate the realistic attacker (an app user or other local account); use `[ROOT]`/sudo only to compare boundaries, and note in the report that root sees strictly more than any attacker principal.

### Demo A — prove a world-readable `.env` via stat interpretation

```bash
stat -c 'mode=%a owner=%U:%G path=%n' /srv/app/.env          # [ROOT] if the file is already owner-scoped
# Interpretation: mode=0644 -> other has r-- : every local account may read.
# Emulate the attacker without reading contents:
sudo -n -u nobody sh -c 'test -r /srv/app/.env && echo PROVEN_READABLE_BY_UNPRIVILEGED || echo NOT_READABLE'
```

Report the verdict plus a redacted classification only, e.g.:

```
FINDING: /srv/app/.env mode 0644 — readable by all local accounts (verified as user nobody).
Contents include a DATABASE_URL whose password begins EXAM…REDACTED and one key beginning sk-l…REDACTED.
```

### Demo B — prove history leakage by hit count (values never printed)

```bash
f=/root/.bash_history                                        # repeat for each user's history file
grep -nE '([[:space:]]-p[^[:space:]])|(export[[:space:]]+[A-Za-z_]*(PASS|TOKEN|SECRET|KEY))' "$f" \
     | cut -d: -f1                                           # line numbers ONLY
grep -cE '([[:space:]]-p[^[:space:]])|(export[[:space:]]+[A-Za-z_]*(PASS|TOKEN|SECRET|KEY))' "$f"
```

Report format: `/root/.bash_history: 3 credential-pattern hits (lines 112, 340, 902); values withheld per redaction rule.` The count is the proof; matched text never leaves the host.

### Demo C — empirically confirm the `/proc/<pid>/environ` boundary

```bash
target_pid=$(pgrep -u postgres -o 2>/dev/null || pgrep -u www-data -o)
cat "/proc/$target_pid/environ"                              # unprivileged attempt
# Expected output: cat: /proc/<pid>/environ: Permission denied  <- boundary HOLDS for the audit user
sudo -n cat "/proc/$target_pid/environ" >/dev/null 2>&1 && echo ROOT_CAN_READ_AS_EXPECTED
```

Interpretation to record honestly: environment blocks are kernel-gated, not world-readable — modern kernels with Yama `ptrace_scope >= 1` deny even same-UID non-descendant readers. But `sudo cat` succeeds, so the audit must always name *which principals* can read (root: yes; same-UID peers: depends on ptrace scope; others: no). This asymmetry is exactly why env vars rate Medium sprawl rather than Critical exposure.

### Attacker narrative (qualitative chain)

One RCE as the web application's service user is enough: `id` shows `svc-api`; sweep sections [1] and [9] return readable `.env`, pgpass, and dump files; the `.env` yields DB DSN plus SMTP and object-storage keys; a 644 `/tmp/*.sql.gz` hands over the whole dataset without touching the database server; a stray deploy-user `id_rsa` with 644 perms converts the foothold into SSH lateral movement. Total attacker effort after the initial foothold: minutes. Defense: shrink the readable set so the compromised user finds nothing worth taking.

## Remediation

Execute under change-window approval; steps mutate state. Order matters: fix permissions before restarting anything, and rotate before considering any finding closed.

### 1. Exact permission end-states per location

```bash
# App env files
chown svc-api:svc-api /srv/app/.env && chmod 600 /srv/app/.env && chmod 750 /srv/app
# systemd relocated env file (create skeleton, populate via editor during window)
install -o root -g svc-api -m 640 /dev/null /etc/svc-api/api.env
# Service-account home dirs: 750, never 755/777
chmod 750 /home/svc-api && chown svc-api:svc-api /home/svc-api
# SSH client chain (per affected account)
chmod go-w /home/deployer && chmod 700 /home/deployer/.ssh \
     && chmod 600 /home/deployer/.ssh/id_* /home/deployer/.ssh/authorized_keys
# DB client credential files
chmod 600 /root/.my.cnf /root/.pgpass
# Verify (do not rewrite) host keys
stat -c '%a %U:%G %n' /etc/ssh/ssh_host_*_key        # expect exactly 600 root:root
# Backup landing zones
chmod 700 /var/backups && chown root:root /var/backups
stat -c '%a %n' /root                                 # must print 700 before judging /root tars acceptable
```

Never chmod 777 anything to "fix" access — on home dirs it triggers StrictModes pubkey-auth lockout (see Verification regression notes), and everywhere else it manufactures the exact exposure this module exists to remove.

### 2. Move inline env to EnvironmentFile-with-600 pattern

Replace every `Environment="SECRET=..."` line with an EnvironmentFile target created per step 1, using the FIXED unit snippet from Patterns & Signatures (`EnvironmentFile=/etc/svc-api/api.env` + `UMask=0027`). Keep old unit files as root-600 backups during rollback risk. Restart of the affected service is approval-gated.

### 3. Rotate everything that was exposed or ever committed

Mandatory, not optional. A credential readable by the wrong group is burned regardless of whether you can prove access. Git-history caveat: rewriting history does not unburn values already cloned or forked — rotation is the only cure (SECRETS code-module rule). Token/API-key rotation mechanics, overlap windows, and cutover ordering → TOK module (`server-api-token-security`) rotation runbook.

### 4. Backup encryption starters

```bash
tar -czf - /etc/svc-api | age -r RECIPIENT_PUBLIC_KEY_GOES_HERE -o "/root/etc-svcapi-$(date +%F).tar.gz.age"
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in /var/backups/appdb-2026-08-24.sql.gz \
     -out /var/backups/appdb-2026-08-24.sql.gz.enc           # passphrase via prompt or protected env
rm /var/backups/appdb-2026-08-24.sql.gz                       # keep only ciphertext at rest
```

Pair encryption with placement: artifacts 600 in a 700 directory, encrypted copies shipped off-host (off-host copy principle from What To Check §12).

### 5. Secret-manager adoption decision checklist

Adopt a manager (Vault-style dynamic secrets, a cloud secret manager, or SOPS+age encrypted-in-repo) when most boxes tick:

- [ ] More than ~20 distinct secrets, or secrets shared across multiple hosts
- [ ] Need for automatic rotation or short-lived/dynamic DB credentials
- [ ] Multi-host or multi-environment drift already causing stale-copy incidents
- [ ] Audit requirement: who read which secret, when
- [ ] Small repo-only deployment with one team → SOPS+age encrypted-in-git is adequate instead

State the tradeoff plainly in findings: **the bootstrap problem** — the host still needs one unlock capability somewhere (an age identity file, a Vault Agent token, an IAM instance role). Decide consciously where that anchor lives; never store it inside the same repo or plaintext file it protects. Do not turn remediation into a product migration in the same change window.

## Verification & Validation

### Post-fix verification list

1. Re-run the full paste-ready sweep: sections [1], [2], [8], [9] return zero lines; section [5] lists only 0640/0600 targets; section [3] shows the intact StrictModes chain.
2. Spot-check `stat` output for every row in the Where To Look table against its expected owner:mode.
3. Approval-gated service restart reading the relocated secret: inside an approved window run `systemctl restart svc-api`, then confirm `systemctl is-active svc-api` and scan `journalctl -u svc-api --since -5m` for EnvironmentFile parse errors or missing-variable failures.
4. Negative tests (functionality intact): `curl -fsS http://127.0.0.1:<port>/healthz` returns 200; one DB-touching read-only app command succeeds (e.g., the framework's check/dry-run task); the nightly cron's next scheduled run logs success.
5. StrictModes regression test from an affected account: `ssh -o BatchMode=yes -o StrictHostKeyChecking=no localhost true && echo AUTH_OK`. On `Permission denied (publickey)`, find the culprit with `journalctl -u ssh --since -10min | grep -i 'bad ownership or modes'` — it names the offending directory.
6. Repo-side IaC greps (config-as-code hosts):

```bash
grep -rniE '(pass(word)?|secret|token|api[_-]?key)[[:space:]]*[:=]' \
     --include='*.yml' --include='*.tfvars' --include='.env*' .   # plaintext-looking vars
git ls-files | grep -E '(^|/)\.env($|\.)'                          # env files tracked in git
git log --oneline -- '**/.env*' '**/*tfvars*'                      # history depth to rotate against
grep -rniE 'snapshot|volume.*[[:space:]]+' --include='*.tf' . | grep -vi encrypted  # unflagged snapshots
```

### Regression notes

- **StrictModes breakage**: well-meant `chmod -R 777 /home` "fixes" an access complaint and silently breaks pubkey auth for every user; the client shows only Permission denied while the cause sits in the journal. Restore 750/700 chains, never world-writable homes.
- **CI deploy access**: when a deployer needs to read a service secret, design group-scoped access — `chown root:svc-api api.env && chmod 640 api.env && usermod -aG svc-api deployer` — never world-open the file.
- **Restore resets mtime**: files restored from backup carry fresh mtimes, hiding stale-credential rotation flags; anchor rotation on the ledger/runbook, not on `-mtime` alone.

## Severity Assessment

Score each finding on observed state, then re-rate after chaining with known entry points (FW/TLS modules). Disclose the chaining assumption in the report: local vectors assume an unprivileged foothold such as web RCE as the service user.

| Scenario | Band | CVSS v3.1 vector |
|---|---|---|
| World-readable production DB credentials or private keys (SSH host / TLS / signing) on an internet-reachable host | Critical (~9.6) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| Secrets readable by the exposed app's user beyond its needs (over-broad group); plaintext credentials in ops history | High (~7.3) | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` |
| Env-var sprawl without a manager; unencrypted local backups of secret-bearing config dirs | Medium (~5.5) | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Missing rotation-culture indicators only (stale mtimes on cred-bearing files, no ledger) | Low (~1.8) | `CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N` |

Needs-Review class: rotation-posture items are never auto-findings — mtime proves nothing about rotation by itself; they become Low findings only once corroborated (e.g., the same credential predates two documented policy cycles). Upgrade any band by one level when the exposed material is shared across hosts (blast radius multiplies).

## Common False Positives

1. **Test/dev-only credentials clearly scoped to throwaway environments** — dummy values like `EXAMPLE_NOT_A_REAL_PASSWORD` in a compose stack bound to loopback on an ephemeral box. Still inventory-list them (they rot into prod), but downgrade to Informational/Low after verifying scope: loopback binds, no prod data, disposable host. Escalate immediately if the stack touches real data or is reachable beyond localhost.
2. **Container-image-internal secrets** (`ENV` in Dockerfiles, secrets in image layers, registry-baked configs) — different lifecycle and detection surface; supply-chain module owns them. Only the host-side `.env` feeding `docker run --env-file` belongs to this module.
3. **Distro-managed certificate bundles** — `/etc/ssl/certs/*.pem` at 644 is public trust-store material by design, not an application secret; likewise `*.pub` SSH halves and `known_hosts` (host fingerprints, not credentials — informational note only).
4. **Intentionally grouped key access** — TLS keys at 640 root:ssl-cert with services legitimately in the group are correct design; verify actual group membership necessity before flagging over-exposure.

## References

Man pages:

- `sshd_config(5)` — StrictModes, AuthorizedKeysFile semantics — https://man.openbsd.org/sshd_config
- `ssh(1)` — client behavior and BatchMode verification — https://man.openbsd.org/ssh
- `ssh-keygen(1)` — key generation and formats — https://man.openbsd.org/ssh-keygen
- `proc(5)` — `/proc/<pid>/environ` access rules — https://man7.org/linux/man-pages/man5/proc.5.html
- `find(1)` — `-perm /044`, `-perm -go-rwx` semantics — https://man7.org/linux/man-pages/man1/find.1.html
- `chmod(1)` / `chown(1)` — mode and ownership end-states — https://man7.org/linux/man-pages/man1/chmod.1.html , https://man7.org/linux/man-pages/man1/chown.1.html
- `stat(1)` — evidence formatting — https://man7.org/linux/man-pages/man1/stat.1.html
- `coredumpctl(1)` — core listing/retrieval gating — https://www.freedesktop.org/software/systemd/man/latest/coredumpctl.html

Standards and cheat sheets:

- CWE-732: Incorrect Permission Assignment for Critical Resource — https://cwe.mitre.org/data/definitions/732.html
- CWE-312: Cleartext Storage of Sensitive Information — https://cwe.mitre.org/data/definitions/312.html
- OWASP Cheat Sheet Series — Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

Practice documentation:

- systemd.exec(5) — `Environment=`, `EnvironmentFile=`, `UMask=` — https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- PostgreSQL — libpq `.pgpass` file and permission requirement — https://www.postgresql.org/docs/current/libpq-pgpass.html
- MySQL — `mysql_config_editor` (.mylogin.cnf alternative to `[client] password=`) — https://dev.mysql.com/doc/refman/8.0/en/mysql-config-editor.html
- age — modern file encryption used in backup starter — https://github.com/FiloSottile/age
- SOPS — encrypted-secrets-in-repo pattern named in Remediation — https://github.com/getsops/sops
