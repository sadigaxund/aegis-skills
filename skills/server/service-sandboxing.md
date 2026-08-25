---
name: server-service-sandboxing
description: Audit Linux service and process containment covering root-running units, systemd sandboxing directives, MAC system status, container escape surfaces, and root-writable cron chains.
category_slug: SANDBOX
cwe: [CWE-250, CWE-269]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit containment of long-running services and scheduled jobs on a single Linux host or its config-as-code repository. Determine:

1. Which services execute with root identity or with identities that are shared, reusable, or login-capable.
2. Whether systemd units apply the sandboxing directives that cost nothing at design time and remove entire exploit classes (CWE-250: Execution with Unnecessary Privileges).
3. Whether SELinux or AppArmor is present, and in which mode.
4. Whether container runtime configuration grants host-equivalent power (docker.sock mounts, `--privileged`, `--network host`, `--pid host`, added capabilities).
5. Whether root-owned cron/timer scripts can be modified by unprivileged principals.

Constraints for the executing agent:

- Run only non-mutating commands: read files, list processes, inspect units, query container metadata. Do not edit unit files, do not restart services, do not enter containers.
- Service restarts require orchestrator-approved change windows. Propose them; never perform them during the audit.
- This module audits presence, mode, and configuration of containment. Deep SELinux/AppArmor policy authoring and k8s pod security review are specialist follow-ups flagged in Remediation, not performed here.

## Mental Model

Containment is layered. Each layer removes a capability an attacker would otherwise inherit from the service process they compromised. Read findings top-down: an attacker who lands inside the process holds everything not explicitly revoked below it.

```
attacker input
   |
   v
[L1 identity]      User=/Group=/DynamicUser=          -> whose privileges does my code run as
[L2 privilege]     NoNewPrivileges= / caps / Ambient   -> what can I escalate to
[L3 filesystem]    ProtectSystem/ProtectHome/Private*  -> what files can I read/write
[L4 kernel iface]  SystemCallFilter=/Restrict*/Lock*   -> what kernel operations can I invoke
[L5 network]       IPAddressAllow/Deny/PrivateNetwork  -> where can I connect
[L6 policy]        SELinux / AppArmor / seccomp        -> independent backstop rules
```

Key intuitions to carry through the audit:

- A directive that is absent means the attacker inherits the default: all of it. systemd defaults are permissive; hardening is opt-in per unit.
- Identity (L1) dominates every other layer. `systemd-analyze security` will score a root-running unit badly no matter how many other directives exist, because file and capability restrictions are trivially weaker when the process may become root.
- Containment failures compound. One missing directive is usually Medium; the same missing directive on a unit that also runs as root and faces the internet is part of a Critical chain.
- Container boundaries are not containment by themselves. A container that mounts `/var/run/docker.sock` or runs privileged delegates control of the host kernel's container runtime to whatever executes inside it.

## What To Check

### 1. Service-user inventory

Enumerate identity for every enabled unit and every running process:

```bash
systemctl list-unit-files --type=service --state=enabled --no-legend
systemctl show -p User -p Group -p DynamicUser <unit>.service
ps aux                       # USER column: anything running as root needs justification
ps -eo user,comm --no-headers | sort | uniq -c | sort -rn   # processes per account
```

Flag each of the following as a finding:

- A third-party/app service with no `User=` (implicit root). `User=root` or an empty `User=` means the whole unit executes as uid 0.
- A login-capable service account: shell in `/etc/passwd` is not `nologin`, `false`, or equivalent (`awk -F: '$7 !~ /(nologin|false)/ {print $1, $3, $7}' /etc/passwd`). Interactive shells on service accounts make credential theft immediately exploitable.
- The shared-service-user antipattern: two unrelated services (web app and database, web app and queue worker) running under one account. Any code-execution bug in either yields the other's files, credentials, and sockets in a single hop — a lateral-movement gift (CWE-250). Evidence: same USER column for different binaries, or one `/etc/passwd` entry referenced by multiple units.
- Missing per-service accounts entirely (everything under a generic `www-data`, `nobody`, or a personal deploy user).

Container-vs-host UID context, kept brief: UIDs are numeric; a container process showing uid 0 is the host's real uid 0 unless user namespace remapping (`dockerd userns-remap`) is active, so "root in container" equals "root on host" for volume and kernel purposes. Numeric collisions between image users and host-mounted volume owners cause both permission failures and accidental access grants — record mounted-volume owner UIDs when containers run with volumes.

### 2. systemd sandboxing directives (core)

Read the effective unit plus drop-ins with `systemctl cat <unit>.service`. Then evaluate the directive-by-directive table below against each app-facing unit. Absence of a row's directive is itself a finding candidate; severity depends on exposure (see Severity Assessment).

| Directive | Value | Effect | Breakage risk |
|---|---|---|---|
| `User=` / `Group=` | dedicated account, e.g. `webapp` | Runs the process as a non-root identity; bounds L1 blast radius | App must be able to read its own files; chown state dirs first |
| `DynamicUser=` | `yes` | systemd mints an ephemeral unique UID per start; no /etc/passwd entry needed; pair with `StateDirectory=`/`RuntimeDirectory=` for persistent paths | Incompatible with ownership patterns that outlive restarts outside State/Runtime dirs (long-lived socket files owned by old UID); some apps stat their own username |
| `NoNewPrivileges=` | `true` | Kernel blocks gaining privileges via setuid/setgid/file capabilities for the whole tree | Breaks helpers that genuinely rely on setuid binaries (rare in app stacks) |
| `ProtectSystem=` | `true` / `full` / `strict` | Mounts filesystem read-only: `true` = `/usr`, `/boot`, `/efi`; `full` = those plus `/etc`; `strict` = entire hierarchy except `/dev`, `/proc`, `/sys` | `strict` requires explicit `ReadWritePaths=`/`StateDirectory=` for any writable path; apps that self-update or write into `/etc` fail |
| `ProtectHome=` | `true` / `read-only` | Makes `/home`, `/root`, `/run/user` invisible or read-only to the unit | Only breaks apps legitimately reading home dirs (deploy checkouts under /home) |
| `PrivateTmp=` | `true` | Unit gets a private `/tmp` and `/var/tmp` namespace | Two services can no longer exchange files via shared /tmp handshakes; debugging tools must enter the namespace to see the files |
| `PrivateDevices=` | `true` | Only pseudodevices (`/dev/null`, `/dev/zero`, `/dev/random`, ...) visible; no physical devices | Direct device access (GPU, serial, TPM) fails |
| `ProtectKernelTunables=` | `true` | `/proc/sys`, `/sys` made read-only | Apps tuning sysctl at runtime fail |
| `ProtectKernelModules=` | `true` | Module autoloading denied (`CAP_SYS_MODULE` dropped) | Rarely needed by apps; breaks services inserting modules on demand |
| `ProtectKernelLogs=` | `true` | `/dev/kmsg` access removed | Logging agents reading kmsg break |
| `ProtectControlGroups=` | `true` | `/sys/fs/cgroup` read-only | Container/cgroup-manipulating tooling inside the unit breaks |
| `RestrictAddressFamilies=` | `AF_UNIX AF_INET AF_INET6` | Socket creation restricted to listed families; all others fail | Honest caveat: AF_NETLINK is used by Go runtimes and monitoring agents for interface/route enumeration; omitting it breaks source-address discovery, so geo/IP allowlist features that first query local interfaces fail at startup |
| `RestrictNamespaces=` | `true` | Blocks all `unshare`/`clone` namespace creation | Breaks in-process sandboxing (browser renderers, bubblewrap-style wrappers), nested container tooling |
| `RestrictSUIDSGID=` | `true` | Denies creating setuid/setgid files | Almost none for apps; breaks build tooling that packs archives preserving bits |
| `LockPersonality=` | `true` | Locks the `personality()` syscall so ASLR cannot be disabled at runtime | Essentially zero |
| `MemoryDenyWriteExecute=` | `true` | Kernel denies simultaneously writable+executable memory mappings | BREAKS JITs: Node/V8, JVM (older HotSpot), Chromium/Electron, LuaJIT, some regex engines; identify JIT use by bundled V8/libjvm presence or SIGSEGV on PROT_WRITE\|PROT_EXEC mmap; see Remediation exemption pattern |
| `SystemCallFilter=` | `@system-service` | seccomp allowlist of ~300 typical userspace syscalls; deny-all else | Obscure syscalls (io_uring setup on older allowlists, exotic ioctls) return EPERM; diagnose via journal seccomp lines + `ausyscall N`; list sets with `systemd-analyze syscall-filter` |
| `SystemCallArchitectures=` | `native` | Blocks foreign-ABI syscall invocation | None for single-arch apps |
| `CapabilityBoundingSet=` | empty (drop all), then add back minimal | Caps the maximum capability set ever obtainable, even after exec of setuid binaries | Empty set breaks ping-raw-sockets, time setting, etc.; add back only what is needed |
| `AmbientCapabilities=` | e.g. `CAP_NET_BIND_SERVICE` | Grants specific caps to the non-root User= across execve (alternative to root+setcap file capabilities) | Over-granting recreates the risk; grant the narrowest cap |
| `IPAddressAllow=` / `IPAddressDeny=` | `IPAddressDeny=any` + allows for needed ranges | Kernel-enforced egress/ingress ACL per cgroup — application-layer egress control without touching app code | Dynamic outbound targets (CDN APIs without fixed ranges) break; localhost resolver must be allowed explicitly |
| `TaskMax=` | e.g. `256` | Caps tasks (threads+processes) in the unit's cgroup | Thread-pool-heavy apps (high-concurrency JVMs) need headroom |
| `LimitNOFILE=` | e.g. `65535` | Raises fd limit for high-fanout servers | Too low causes EMFILE under load; too high wastes kernel memory per task |
| `UMask=` | `0027` | New files group-readable, not world-readable; prevents secret-bearing files leaking world-read | Apps relying on world-readable drops (static file servers writing to served dir) need explicit chmod discipline |
| `PrivateNetwork=` | `true` | Fresh network namespace with only loopback | Inbound serving needs slirp4netns/port plumbing; appropriate mainly for batch workers and sandboxed jobs |

Supporting pair for `ProtectSystem=strict`: declare writable exceptions explicitly:

```ini
# FIXED — strict filesystem with explicit exceptions
[Service]
ProtectSystem=strict
StateDirectory=webapp
ReadWritePaths=/srv/webapp/uploads
```

### 3. Analysis tooling workflow

Run the built-in scoring tool per unit:

```bash
systemd-analyze security nginx.service        # prints per-directive verdicts + overall score
systemd-analyze security                      # all units, worst offenders sorted last
systemd-analyze syscall-filter                # enumerate @allowlist sets for SystemCallFilter=
```

Interpretation: output lists each sandboxing question answered SAFE (directive present) or EXPOSED (absent), each weighted; the final line gives an aggregate `Overall exposure level for X.service: <score> NAME` where 0.0 is fully contained and 10.0 runs unrestricted as root. Prioritize CRITICAL-weighted EXPOSED lines — they are almost always `User=` missing (root execution) and missing filesystem isolation — before cosmetic ones.

Find overrides and understand what is actually in force:

```bash
systemctl cat <unit>.service          # base file + concatenated drop-ins
ls -l /etc/systemd/system/<unit>.service.d/   # override.conf pattern lives here
```

The safe change workflow (for the remediation phase, restart gated on approval):

1. Create `/etc/systemd/system/<unit>.service.d/override.conf` containing only changed keys under their original sections.
2. Validate parseability: `systemd-analyze verify /etc/systemd/system/<unit>.service`.
3. `systemctl daemon-reload` (safe, no service disruption).
4. Request orchestrator approval for `systemctl restart <unit>` — restart causes downtime and must never run unapproved during audit.
5. After approved restart: verify liveness (`systemctl is-active`, health endpoint) and re-score (`systemd-analyze security <unit>`).

### 4. MAC systems: SELinux and AppArmor

Detect which MAC system is active and its mode:

```bash
getenforce                 # Enforcing | Permissive | Disabled (SELinux)
sestatus                   # full SELinux status incl. policy name and booleans
aa-status                  # AppArmor: profiles loaded vs enforced vs complain
```

SELinux findings:

- `Disabled`: finding. Containment relies solely on discretionary controls.
- `Permissive`: finding WITH CONTEXT. Violations are logged but not blocked. Do not recommend flipping to Enforcing blindly — misconfigured policy breaks boot and services. Outline the targeted-policy workflow instead: collect denials with `ausearch -m avc -ts recent`, generate narrow local modules with `audit2allow -M <name>`, review generated `.te` rules before loading, iterate until clean, then switch enforcing. Never disable SELinux to fix an app.
- `Enforcing`: check whether app domains actually run confined (`ps -eZ | grep <unit>` shows `unconfined_service_t` = effectively unconfined).

AppArmor findings:

- No profiles loaded for the audited binaries: finding.
- Profiles in complain mode: staging state; violations logged, not blocked. Progression path is `aa-complain` during tuning, then `aa-enforce`.

Honesty about depth: this module audits presence/mode/coverage only. Authoring or repairing policy modules is specialist follow-up work.

### 5. seccomp outside systemd

For Docker/container workloads:

```bash
docker info | grep -i seccomp
docker inspect <c> --format '{{json .HostConfig.SecurityOpt}}'
```

Default profile sanity: the engine's default seccomp profile blocks dangerous syscalls while permitting normal workloads — treat it as baseline. Findings: `seccomp=unconfined` anywhere, or a custom profile that is a copy of the default with `defaultAction` widened to `SCMP_ACT_ALLOW`. Custom profiles are supplied via `--security-opt seccomp=/path/profile.json`.

### 6. Container runtime checks

- docker.sock exposure (THE classic finding): any container mounting `/var/run/docker.sock` holds a host-root-equivalent grant. Detect:
  ```bash
  docker ps -q | xargs docker inspect --format '{{.Name}}{{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' | grep docker.sock
  grep -l docker.sock /proc/[0-9]*/mountinfo 2>/dev/null   # works without docker CLI
  ```
- `--privileged` hunt: `docker ps -q | xargs docker inspect --format '{{.Name}} priv={{.HostConfig.Privileged}}'`
- Root-in-container default: images without a `USER` directive run as uid 0. Check `docker inspect --format '{{.Config.User}}'` (empty = root) and Dockerfile `USER` lines in-repo.
- `--cap-add` audit: `docker ps -q | xargs docker inspect --format '{{.Name}} {{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}}'` — review every added cap; `SYS_ADMIN` and `DAC_READ_SEARCH` are near-equivalents of privileged.
- Host networking: `--network host` removes network isolation; the container binds host ports directly and sees host-loopback services (metadata services, databases).
- Host PID: `--pid host` lets the container see and signal every host process, and weakens /proc-based secrets hygiene.
- Rootfs writability: prefer `read_only: true` rootfs plus explicit `tmpfs` mounts for scratch paths.
- Image trust surface is a supply-chain concern — cross-reference the supply-chain module for registry pinning, digest pinning, and base-image provenance.
- Kubernetes equivalents (pod `securityContext`, `hostPath`, privileged pods) belong to the configuration-hardening code module; do not duplicate here.

### 7. Cron, timers, and root-run scripts

Enumerate schedulers:

```bash
grep -rn . /etc/crontab /etc/cron.d/ 2>/dev/null
ls -l /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
crontab -l -u root 2>/dev/null; ls -l /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-timers --all --no-pager      # map timer -> service unit, then check its User=
```

For every command/script path executed as root, chain it with a permissions check: if the script (or any file it sources, or any directory in its path, or the binary it invokes) is writable by an unprivileged principal, cron becomes a privilege-escalation primitive. The mechanical check:

```bash
grep -rhoE '/[A-Za-z0-9_./-]{3,}' /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null \
  | sort -u | while read -r f; do [ -f "$f" ] && stat -c '%a %U:%G %n' "$f"; done
find /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly} /usr/local/sbin /opt \
  -xdev -type f -perm /go+w -exec stat -c '%a %U:%G %n' {} \; 2>/dev/null
```

Interpretation: `stat` output where owner is `root` but group-write or other-write is set (e.g., `%a` contains a 2, 3, 6, or 7 in the group/other digits) marks an escalation chain when any scheduled job executes that path as root. Also flag scripts writable by the service account identified in step 1 — a compromised web app that can rewrite a root-cron script owns the host on the next tick.

## Where To Look

Evidence collection: `tools/sweeps/sweep-sandbox.sh` captures `[SBX-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

| Surface | Host paths / commands | Config-as-code analogues |
|---|---|---|
| Unit files | `/usr/lib/systemd/system/`, `/etc/systemd/system/`, drop-ins `/etc/systemd/system/<unit>.service.d/*.conf`; authoritative view: `systemctl cat <unit>` | `deploy/systemd/*.service`, packaging specs in repo |
| Run-as identity | `/etc/passwd` (shell, UID), `getent passwd <user>`, `ps -eo user,comm` | user creation in provision scripts (`useradd ... -s /usr/sbin/nologin`) |
| Effective sandbox | `systemd-analyze security <unit>`; `/proc/<pid>/status` (Cap*, Seccomp lines) | CI checks running `systemd-analyze verify` |
| Schedulers | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/var/spool/cron[/crontabs]/`, `systemctl list-timers` | cron manifests, k8s CronJob defs (other module) |
| MAC status | `getenforce`, `sestatus`, `/sys/fs/selinux/enforce`; `aa-status`, `/etc/apparmor.d/` | VM image build recipes |
| Containers | `docker inspect <c>` fields `HostConfig.{Privileged,CapAdd,CapDrop,PidMode,NetworkMode,SecurityOpt}`, `.Mounts`, `.Config.User`; `/var/run/docker.sock` consumers via `/proc/[0-9]*/mountinfo` | `docker-compose*.yml`, Dockerfiles, `docker run` wrappers in scripts |
| Writable-script chains | `stat -c '%a %U:%G %n'` on every root-executed script path plus parent dirs (`namei -l <path>` shows the whole chain) | repo file modes for deployed scripts |

Also inspect parent-directory writability, not only file bits: a root-owned `0705` script inside a group-writable directory can be replaced via rename. Use `namei -l /path/to/script` to print traversal permissions in one shot.

## Patterns & Signatures

Unit file running as root with zero containment:

```ini
# VULNERABLE
[Service]
Type=simple
User=root
WorkingDirectory=/opt/app
Environment=NODE_ENV=production
ExecStart=/usr/bin/node /opt/app/server.js
```

The same service contained:

```ini
# FIXED
[Service]
Type=simple
User=webapp
Group=webapp
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
CapabilityBoundingSet=
UMask=0027
ExecStart=/usr/bin/node /opt/app/server.js
```

Shared-service-user signature — one account, unrelated binaries:

```
$ ps -eo user,args | grep -E 'server.js|postgres' | grep -v grep
svc_all  /usr/bin/node /opt/app/server.js
svc_all  postgres: checkpointer
```

Both processes under `svc_all`: web-app compromise reads the database's files and sockets directly.

Container escape-grant signature:

```yaml
# VULNERABLE
services:
  ci-runner:
    image: builder:latest
    privileged: true
    network_mode: host
    pid: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

Corresponding live-host evidence from `docker inspect`:

```
/ci-runner priv=true net=host pid=host mnt=/var/run/docker.sock->/var/run/docker.sock
```

Root-writable-cron chain signature:

```
$ grep -r backup /etc/cron.d/
30 2 * * * root /usr/local/bin/backup.sh
$ ls -l /usr/local/bin/backup.sh
-rwxrwxr-x 1 root webdev 812 Mar 03 02:11 /usr/local/bin/backup.sh
```

Group `webdev` write bit on a root-executed script = escalation chain.

DynamicUser done right:

```ini
# FIXED — no static account needed at all
[Service]
DynamicUser=yes
StateDirectory=metrics-agent
RuntimeDirectory=metrics-agent
ExecStart=/usr/local/bin/metrics-agent --state /var/lib/metrics-agent
```

## Taint Tracing Guidance

Trace attacker-controlled data to each containment sink to argue real impact, not theoretical presence:

- HTTP request body/headers → web-app process memory. If a parser or deserializer bug yields code execution, the payload executes with exactly the unit's identity and sandbox set. Taint path: internet listener (`ss -tlnp` on 80/443 owned by unit) → process → its User= and directive set. Missing directives convert an app-level bug (Medium) into host compromise.
- Repository write access → deployed cron script. Anyone with push rights to the repo that deploys `/usr/local/bin/*.sh`, or write access on the host file itself, taints the next root cron execution. Trace: who can write the path (`stat`, group membership via `id <user>`) → scheduler entry owner (`grep /etc/cron*`).
- Untrusted dependencies executed inside containers (npm/pip postinstall scripts, CI test runs) → mounted docker.sock. Any code running in the sock-mounted container reaches the Docker API; trace from package manifests' lifecycle scripts through CI job definitions to the runner container's mounts.
- Environment variables in units (`Environment=`/`EnvironmentFile=`) hold credentials readable by the very identity that is over-shared; under the shared-UID antipattern one service's compromise harvests the other's `EnvironmentFile`. Trace: `systemctl cat` for `EnvironmentFile=` paths, then stat those files against every account on the box.
- Host-mounted volumes into containers carry host UIDs; a container writing as uid 0 to a bind mount taints host-owned paths. Check `.Mounts` source ownership versus `.Config.User`.

## Exploitation & Reproduction

All demonstrations in this section are read-only. Prove reachability by inspection; never execute payloads.

### Demo 1: docker.sock chain (narrative + non-invasive verification)

Chain narrative, for impact framing only: a client with access to the mounted socket calls the Docker API to create a container with `HostConfig.Binds=["/:/host"]` and `Privileged=true`, starts it, and reads/writes the entire host filesystem from inside it — equivalent to host root without ever touching SELinux or sudo. No exploit is run here.

Verification without exploitation:

```bash
# Which containers mount the socket?
docker ps --format '{{.Names}}' | while read -r c; do
  docker inspect "$c" --format '{{.Name}} {{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}'
done | grep docker.sock

# Socket consumers visible purely from procfs (no docker CLI needed):
grep -l docker.sock /proc/[0-9]*/mountinfo 2>/dev/null   # each hit = one PID whose namespace can reach the socket
```

Report format: list container names/PIDs, whether the consuming workload accepts untrusted input (CI runners, dynamic-build executors), and note that the finding stands even if the current image is trusted — the grant attaches to the socket, not the image.

### Demo 2: writable-root-cron-script proof via ls -l interpretation

Given the signature above:

```
-rwxrwxr-x 1 root webdev 812 Mar 03 02:11 /usr/local/bin/backup.sh
```

Read the mode string left to right: owner `root` has rwx; group `webdev` has rwx (the fifth character pair `rwx` starting at position 5 — digits `775`); others have read+execute. Therefore any member of group `webdev` may replace the script's contents. Because `/etc/cron.d/job` schedules it as `root`, whatever content a `webdev` member writes executes as root at the next scheduled tick. Corroborate membership non-destructively:

```bash
getent group webdev
stat -c '%a %U:%G %n' /usr/local/bin/backup.sh
namei -l /usr/local/bin/backup.sh        # confirms no writable parent dir blocks the rename variant
```

Do not edit the script, do not add a test payload; the mode bits plus the crontab line are the proof.

### Demo 3: reading systemd-analyze security output

Abridged, annotated sample for a root-running unit:

```
$ systemd-analyze security app.service
  EXPOSED                                          <- verdict per hardening question
NoNewPrivileges=                      EXPOSED      -> setuid escalation still possible inside unit
ProtectSystem=?                       EXPOSED      -> whole filesystem writable by unit
PrivateDevices=?                      EXPOSED      -> raw /dev reachable
SystemCallFilter=?                    CRITICAL     -> no seccomp allowlist at all
User=/DynamicUser=/Group=             CRITICAL     -> runs as root; every other control is weaker
...
Overall exposure level for app.service: 9.6 UNSAFE    -> aggregate; 0.0 fully contained, 10.0 unrestricted root
```

Reading discipline:

- Attack the CRITICAL lines first: they are dominated by missing `User=` and absent syscall/filesystem isolation and usually collapse the score by several points when fixed together.
- An EXPOSED line names the exact directive to add; cross-reference the table in What To Check for value and breakage risk before recommending.
- Track scores per unit across audits as the trend metric; a unit moving 9.6 → 2.x after remediation demonstrates the fix better than prose.

## Remediation

### Hardened unit template (typical Node.js / Python web app)

Deploy once per app service; adjust `ReadWritePaths=` to actual writable paths. The JIT exemption is explicit and commented — do not silently drop it.

```ini
# FIXED — hardened template, Node/Python web app behind a reverse proxy
[Unit]
Description=Internal web application
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=webapp
Group=webapp
WorkingDirectory=/srv/webapp
StateDirectory=webapp
RuntimeDirectory=webapp
UMask=0027

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=false        # EXEMPTION: V8/JVM JIT needs RWX mappings; set true only after
                                    # testing pure-Python or Node with --jitless; see regression notes
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=

ReadWritePaths=/srv/webapp/uploads   # strict mode requires explicit writable exceptions

TaskMax=256
LimitNOFILE=65535
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Notes: `MemoryDenyWriteExecute=true` is achievable for most Python services (CPython does not JIT by default) and for Node started with `--jitless`; apply it where the stack allows. If port binding below 1024 is required without root, add back exactly one capability: `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

### override.conf drop-in workflow (numbered)

1. Inspect current effective state: `systemctl cat <unit>.service`.
2. Create `/etc/systemd/system/<unit>.service.d/override.conf` containing only the keys being changed, under correct section headers (`[Service]` for all directives above).
3. Parse-check: `systemd-analyze verify /etc/systemd/system/<unit>.service`.
4. Activate metadata: `systemctl daemon-reload`.
5. Obtain orchestrator approval for restart — restart causes downtime and is never part of an unapproved audit action.
6. Restart: `systemctl restart <unit>`, then confirm `systemctl is-active <unit>` and the health endpoint.
7. Re-score: `systemd-analyze security <unit>` and record before/after.
8. Rollback path: delete `override.conf`, `daemon-reload`, approved restart.

### Container run hardening flag-set + compose equivalent

```bash
# FIXED
docker run -d --name api \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 512m \
  registry.example/api:1.4.2
```

Compose equivalents, key for key:

```yaml
# FIXED
services:
  api:
    image: registry.example/api:1.4.2
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE"]
    security_opt:
      - no-new-privileges:true
    pids_limit: 256
    mem_limit: 512m
```

Never mount `/var/run/docker.sock`; if CI must drive Docker, use a remote builder or rootless daemon per job.

### Capability drop-all/add-back example

```bash
# Drop everything, then grant only the single capability the service needs.
# Unit form:
#   CapabilityBoundingSet=
#   AmbientCapabilities=CAP_NET_BIND_SERVICE
# File-capability alternative (mutates the binary; prefer the unit directive):
setcap 'cap_net_bind_service=+ep' /usr/local/bin/app
```

Cap cheat-sheet for add-back decisions: `CAP_NET_BIND_SERVICE` binds ports below 1024 (the common legitimate need); `CAP_DAC_READ_SEARCH` bypasses file-read permission checks and has been abused with `open_by_handle_at` to read arbitrary files — do not add it; `CAP_SYS_ADMIN` is effectively "most of root" — treat any request for it as a design smell requiring escalation.

## Verification & Validation

Per-fix verification (after approved restart):

```bash
systemd-analyze security <unit>.service        # score must drop; record before/after
systemctl show -p User -p Group <unit>.service # shows new identity
ps -o user=,group= -p "$(systemctl show -p MainPID --value <unit>.service)"   # live process identity matches
systemctl show -p NoNewPrivileges -p ProtectSystem --value <unit>.service    # effective directive state
```

Negative tests proving containment without breaking function:

- App serves requests: `curl -fsS http://127.0.0.1:<port>/health` returns 200 after restart.
- State writes succeed under the strict filesystem: `sudo -u webapp touch /var/lib/webapp/.writecheck && rm /var/lib/webapp/.writecheck`.
- Escalation paths are closed: `sudo -u webapp head -1 /etc/shadow` fails with Permission denied.
- Egress policy behaves as declared where `IPAddressDeny=` is set: connect from the unit's context to a denied range and observe the configured refusal.

Regression notes — known breakage classes to re-test explicitly:

- `MemoryDenyWriteExecute=true` vs JavaScript/Java stacks is the most common regression; symptom is SIGSEGV or "mmap ... Permission denied" at startup. Mitigate per-app (`node --jitless`, pure-Python services) rather than by removing the directive globally.
- `RestrictAddressFamilies=` without AF_NETLINK breaks Go runtime interface/route enumeration; apps that discover their own outbound address (geo/IP allowlist flows) fail at startup. Add only AF_UNIX/AF_INET/AF_INET6 unless netlink use is confirmed.
- `PrivateTmp=true` confuses two-service file handshakes that exchange paths via `/tmp`; symptoms appear later when feature X calls service Y. Move the handshake to a `RuntimeDirectory=` path both units access explicitly.
- `SystemCallFilter=@system-service` may deny newer syscalls on older systemd releases; diagnose via `journalctl -u <unit> | grep -i seccomp` and map numeric denials with `ausyscall <num>`.

Config-as-code greps for repository audits:

```bash
rg -n 'privileged\s*:\s*true' --glob '*compose*' .
rg -n 'docker\.sock' .
rg -n 'network_mode\s*:\s*host|pid\s*:\s*host' --glob '*compose*' .
rg -n 'cap_add|SYS_ADMIN|DAC_READ_SEARCH' .
rg -n '^User=root|^User=$' deploy/systemd/
rg -n 'MemoryDenyWriteExecute|SystemCallFilter|NoNewPrivileges' deploy/systemd/
rg -n 'security_opt.*unconfined|seccomp=unconfined' .
```

## Severity Assessment

Anchors (CVSS v3.1; vectors shown so scores are reproducible):

| Finding | Severity | Vector | Score |
|---|---|---|---|
| Docker API/socket reachable by unauthenticated remote party | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 9.8 |
| docker.sock mounted into a remotely reachable container (attacker needs foothold in it) | Critical/High boundary | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.1 |
| Internet-facing app runs as root with no sandboxing (any RCE = host root), or root-writable cron chain reachable by app account | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 |
| Single missing directive (`NoNewPrivileges=`, `ProtectSystem=`, filter) individually on an exposed unit | Medium | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L` | 5.8 |
| Missing hardening on internal batch jobs with no external input path | Low | `CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L` | 4.3 |

Aggregate framing, mandatory in reports: a single missing directive rarely justifies Critical on its own — severity comes from chains. Combine identity (root), exposure (internet-facing listener), and missing layers into one finding narrative instead of emitting ten Mediums that hide the chain. Use `systemd-analyze security` deltas as the quantitative before/after evidence attached to each remediation.

## Common False Positives

- Core OS units legitimately need broad access: `systemd-udevd.service`, `systemd-modules-load.service`, `systemd-sysctl.service`, device managers, and storage daemons run privileged by design. Scope the directive audit to third-party and application units (those under `/etc/systemd/system`, `/opt`, `/usr/local`), not distro-provided infrastructure.
- Containers intentionally privileged on appliance hosts for hardware access (GPU passthrough, USB, SDR devices) are a documented design decision; record as accepted-risk with owner, not as an unmitigated finding.
- `DynamicUser=yes` is incompatible with long-lived socket/file ownership that must survive restarts under a stable UID outside `StateDirectory=`/`RuntimeDirectory=`; a static non-login user there is correct, not a finding.
- SELinux `Permissive` on short-lived disposable build hosts is still worth reporting, but with context that the host lifetime and workload reduce exposure versus a long-lived production server.
- High `systemd-analyze security` scores on `Type=oneshot` backup or image-pruning jobs that genuinely need broad filesystem reads are expected; recommend targeted `ProtectSystem=read-only`-compatible subsets rather than demanding score zero.
- An empty `.Config.User` in Docker combined with an image that itself declares `USER` in its final layer is contained; only flag root-in-container when neither the image nor the runtime sets an identity.

## References

- systemd.exec(5) — execution environment configuration, all directives in this module: <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>
- systemd.service(5) — unit file structure for service units: <https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>
- systemd-analyze(1) — `security` scoring and `syscall-filter` listings: <https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html>
- systemd.directives(7) — alphabetical directive index: <https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html>
- capabilities(7) — Linux capability semantics incl. CAP_DAC_READ_SEARCH and ambient capabilities: <https://man7.org/linux/man-pages/man7/capabilities.7.html>
- Docker documentation — engine security, seccomp profiles, resource constraints: <https://docs.docker.com/>
- SELinux Project: <https://selinuxproject.org/>
- AppArmor project (aa-status, complain/enforce modes): <https://apparmor.net/>
- CWE-250: Execution with Unnecessary Privileges: <https://cwe.mitre.org/data/definitions/250.html>
- CWE-269: Improper Privilege Management: <https://cwe.mitre.org/data/definitions/269.html>
- OWASP Top 10 2021 A05 – Security Misconfiguration: <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/>
