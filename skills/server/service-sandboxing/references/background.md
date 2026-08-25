# Service Sandboxing & Containment — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind non-root services, systemd sandboxing directives, MAC systems,
seccomp, and the container-runtime hazards (privileged mode, docker.sock);
SKILL.md carries the directive tables, hardened unit templates, and evidence
commands.

## How this class emerged

Classic Unix offered a binary choice: processes ran either as an ordinary user
or as all-powerful `root`. Finer-grained control arrived in layers:

- **Capabilities** split root's powers into independent units starting with
  Linux 2.2 (1999) — a web server could hold exactly "bind ports below 1024"
  without holding everything else. File-based and ambient capability sets later
  made it practical to drop privileges at exec time rather than run as root and
  switch down.
- **Kernel confinement primitives matured through the 2000s**: seccomp's strict
  mode appeared mid-decade and its programmable BPF-filter mode early in the
  2010s, letting a process allow-list its own syscalls; control groups and
  namespaces gave per-process views of resources, PIDs, mounts, and networks.
- **Mandatory access control went mainline**: SELinux (originating at the NSA)
  entered the kernel in 2003, AppArmor followed later in the decade. Both let a
  policy constrain what a compromised process may touch *even when Unix file
  permissions would have allowed it* — an independent backstop that keeps working
  when discretionary controls fail or misconfigure.
- **systemd made sandboxing declarative.** As systemd became the standard init
  system through the 2010s, per-unit directives (`User=`, `ProtectSystem=`,
  `SystemCallFilter=` and kin) turned these kernel features into one-line
  configuration — but always **opt-in per unit**, because the defaults remain
  permissive for compatibility. The `systemd-analyze security` exposure scorer
  arrived afterward to make the gap visible numerically.

Then containers industrialized the primitives — and simultaneously created the
newest hazards. Docker's mainstream arrival in 2013 made namespace-isolated
processes routine, but two conveniences quietly reintroduced full-root power:
running images without any user directive (uid 0 inside equals uid 0 on the
host for volume and kernel purposes), and mounting the daemon's control socket
into containers — a grant Docker's own security documentation frames bluntly:
only trusted users may control the daemon, because anyone who can talk to it can
bind the host's root filesystem into a container they control.

## Anatomy: two grants, one host

A minimal generic weak configuration needs just two shapes:

```ini
# /etc/systemd/system/app.service   [VULNERABLE]
[Service]
ExecStart=/usr/bin/node /opt/app/server.js     # no User=: implicit root
```
```yaml
# compose snippet                              [VULNERABLE]
ci-runner:
  image: builder:latest
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
```

Walkthrough of how these fail:

1. **The service runs as root with zero containment.** Any parser bug,
   dependency compromise, or deserialization flaw that yields code execution in
   this process yields *host root* immediately — no escalation step exists
   because none was left to perform.
2. **Every missing layer is inherited, not defaulted-to-safe.** No
   `NoNewPrivileges=` means setuid helpers still work inside the unit; no
   filesystem walls mean `/etc/shadow` and every other file are readable; no
   syscall filter means kernel attack surface is fully exposed.
3. **The CI grant is worse than it looks.** Whatever executes inside the
   sock-mounted container — including untrusted build scripts and package
   lifecycle hooks — reaches the Docker API. It can start a new container with
   the host's entire filesystem bind-mounted and read/write anything, achieving
   host-root equivalence without touching sudo or SELinux at all.
4. **The grant attaches to the socket, not to trust in today's image.** Even if
   the current workload is vetted, tomorrow's dependency, branch, or pipeline
   change inherits the same power silently.

Containment failures compound: one missing directive is usually Medium; the
same gap on an internet-facing root process is part of a Critical chain.

## Why naive fixes fail

- **Flipping every directive to maximum.** `MemoryDenyWriteExecute=true`
  crashes JIT runtimes (Node/V8, JVM) at startup; `RestrictAddressFamilies=`
  without AF_NETLINK breaks Go services' interface discovery; `PrivateTmp=`
  severs two-service /tmp handshakes. Harden incrementally and test each layer.
- **Disabling SELinux/AppArmor to make errors disappear.** Permissive modes and
  denial logs exist so policy can be tuned iteratively (audit → narrow module →
  enforce); disabling removes the backstop entirely and hides the real bug.
- **Assuming a directive took effect because the file says so.** Drop-ins
  override base units; verify effective state (`systemctl show`,
  `systemd-analyze security`) after reload-and-restart.
- **Choosing DynamicUser where identity must persist.** Services needing
  long-lived socket/file ownership outside managed state directories need a
  static non-login account — that is correctness, not a finding.
- **Treating container boundaries as containment.** Privileged mode,
  `--network host`, `--pid host`, and added `SYS_ADMIN`-class capabilities each
  punch specific holes; the default profile is a baseline to reduce from, not
  proof of isolation.
- **Auditing only the file bits of cron scripts.** A root-owned script inside a
  group-writable directory can be replaced via rename — parent-directory
  writability matters as much as the file's own mode.

## Common misconceptions

1. "Root in a container isn't really root." Without user-namespace remapping,
   uid 0 inside is the host's real uid 0 for volume access and kernel purposes.
2. "Mounting docker.sock is a harmless CI convenience." It delegates host-root-
   equivalent power to everything executing in that container — the classic
   finding of this module.
3. "Missing directives mean sane defaults." In systemd they mean the attacker
   inherits *all of it*; hardening is opt-in per unit.
4. "MAC systems are only for high-security environments." An enforcing MAC
   policy confines exactly the DAC-bypassing bug classes that defeat plain file
   permissions; `unconfined_service_t` on your service means you have none of it.
5. "A high exposure score means the tool thinks my app is broken." The score
   measures containment, not health — core OS units legitimately score high;
   scope the audit to application units.
6. "`NoNewPrivileges=` will break my stack." It blocks setuid/file-capability
   escalation for the unit tree; almost nothing in normal app stacks relies on
   those, which is why it costs nearly nothing and removes a whole class.
7. "Root-owned scheduled scripts are safe by ownership." If the script, anything
   it sources, or any directory on its path is writable by another principal,
   the next tick executes attacker-chosen code as root.

## How professionals think about it today

Modern practice reads containment as stacked layers, each revoking something the
attacker would otherwise inherit from the compromised process. The taxonomy
mirrors SKILL.md's own model:

| Layer | Domain | Typical gap | Defining control |
|---|---|---|---|
| Identity | service users | implicit-root units, shared accounts | dedicated/DynamicUser identities |
| Privilege | escalation paths | NoNewPrivileges absent, broad caps | empty bounding set + narrow ambient caps |
| Filesystem | unit visibility | whole-FS write access | ProtectSystem/Home/PrivateTmp + explicit exceptions |
| Kernel interface | syscall surface | unfiltered syscalls, open userns | SystemCallFilter, Restrict* families |
| Network | egress/ingress reach | unrestricted sockets | IPAddressAllow/Deny, PrivateNetwork |
| Independent backstop | MAC & runtime | disabled/permissive MAC, privileged containers | enforcing profiles, cap-drop-all runtimes |

Severity comes from chains — identity × exposure × missing layers combined into
one narrative — and `systemd-analyze security` deltas provide quantitative
before/after proof per unit.

## Read next

In `../SKILL.md`: **Scope & Objectives**, **Mental Model** (the six-layer
containment stack), **What To Check** (service inventory, directive-by-directive
table, analyzer workflow, MAC modes, seccomp outside systemd, container runtime
checks, cron chains), **Where To Look** (artifact map incl. config-as-code
analogues), **Patterns & Signatures** (vulnerable/fixed unit pairs, escape-grant
signatures), **Taint Tracing Guidance** (input→identity propagation),
**Exploitation & Reproduction** (read-only demos incl. the docker.sock chain),
**Remediation** (hardened template, override workflow, container flag-set,
capability cheat-sheet), **Verification & Validation** (negative tests,
regression notes), **Severity Assessment** (aggregate-chain framing), **Common
False Positives** (core OS units, appliance exemptions).

Sibling modules: `../linux-baseline/SKILL.md` (account hygiene and SUID surface
these units inherit), `../api-token-security/SKILL.md` (credentials riding
`Environment=` lines of over-shared identities), `../updates-patching/SKILL.md`
(removing daemons instead of fencing them), `../firewall-edge/SKILL.md`
(restricting what a contained unit can still reach), `../kubernetes-cluster/
SKILL.md` (where pod-level equivalents live).
