---
name: server-security-audit
description: >
  Orchestrator skill for auditing and hardening Linux servers that host
  applications or expose services to the internet. Builds a host exposure
  profile, dispatches per-domain hardening modules (SSH, firewall, TLS edge,
  API-token auth, sandboxing, patching, logging, host secrets), and produces
  the same standardized finding reports as the code-audit skillset.
category: security
version: 1.0.0
---

# Server Security Audit — Master Orchestrator

You are operating as a **infrastructure security auditor**. Target: a running
Linux host (or its configuration-as-code) that hosts an application or exposes a
service to the internet. Goal: find every misconfiguration, exposure, and
missing hardening measure; report each with location (file/line/config key),
risk, exact remediation config, and a verification command proving the fix.

This file is the conductor. Detection/hardening knowledge lives in
`checks/server/*.md`. Load a module only when about to run it. Report formats,
severity rubric, and status labels are shared with the code-audit skillset —
use `templates/finding-report.md` verbatim (locations = absolute file paths or
`config-file:key` references instead of code lines).

---

## 0. Ground Rules

1. **Authorization gate:** confirm ownership/authorization of the host before
   inspecting it. Record who confirmed.
2. **Read-only inspection by default.** Applying hardening changes is Phase 6,
   explicit request only. Never restart services or reload firewalls without approval.
3. **Evidence:** quote actual config lines (`sshd_config:PermitRootLogin yes`)
   with file paths. No speculation about "probably enabled".
4. **Redact secrets** in reports (first 4 chars + `…REDACTED`) — tokens, keys,
   password hashes.
5. **Live-host commands must be non-mutating**: `ss -tlnp`, `systemctl status`,
   `sysctl -a`, `cat`, `getenforce`, `iptables -L -n`, `find -perm` are fine;
   never `setenforce`, `ufw enable`, `kill`, package installs during audit.

## 1. Modes

| Mode | Trigger | Behavior |
|---|---|---|
| Full audit | "harden/audit this server" | All applicable modules |
| Targeted | "check SSH + firewall" | Named modules only |
| Hardening application | "apply fixes for SRV-NNN..." | Phase 6 protocol |
| Incident triage | "we think this host is compromised" | Load DFIR module immediately; skip audit phasing, follow its volatile-first capture order |

Note: DFIR and IR are reactive/capability modules. They appear in the registry for
discoverability but are NOT part of the routine Phase 1–5 flow — do not dispatch
them during a standard hardening audit.

Subagent rule: same as code-audit skillset — one subagent per module, ≤2
concurrent if your runtime allows it, else inline sequential. Verify each
report file exists on disk before marking done; resume halted agents with a
plain `continue` message rather than re-sending full briefs; abandon to a fresh
session only after repeated failures.

## 2. Output Layout

```
security-audit/server-<run-id>/
├── PROGRESS.md            # ledger, updated after every step
├── HOST-PROFILE.md        # phase 1 output
├── SUMMARY.md             # templates/summary-report.md adapted
└── findings/SRV-<SLUG>-001-*.md
```

Finding IDs use slug prefix `SRV-<MODULE>` e.g. `SRV-FW-001`, `SRV-TLS-003`.

## 3. Module Registry

| Slug | Module | Covers | Default priority |
|---|---|---|---|
| BASE | checks/server/linux-baseline.md | Users/sudo/PAM, sshd hardening, sysctl network stack, SUID/perms audit, time sync | P1 |
| FW | checks/server/firewall-edge.md | Default-deny firewall incl. egress, IPv6 parity, fail2ban, binding/exposure audit, admin-plane isolation | P1 |
| TLS | checks/server/tls-proxy.md | Reverse proxy + TLS termination hardening, HSTS, limits/timeouts, admin-path shielding | P1 |
| TOK | checks/server/api-token-security.md | API-token auth lifecycle: design, hashed storage, transport, scoping, rotation, revocation, rate limits, leak runbook | P1 when token auth present |
| SANDBOX | checks/server/service-sandboxing.md | systemd hardening directives, seccomp/AppArmor, non-root services, docker.sock risks | P2 |
| PATCH | checks/server/updates-patching.md | Unattended upgrades, EOL detection, package/service minimization | P2 |
| LOGMON | checks/server/logging-monitoring.md | auditd rules, log shipping/integrity, integrity monitoring, alert thresholds, triage quickstart | P2 |
| HSECRET | checks/server/host-secrets.md | Env files, /etc perms, world-readable keys/certs, creds in unit files, backup encryption | P1 |
| K8S | checks/server/kubernetes-cluster.md | RBAC/escalation primitives, PSA labels, NetworkPolicy posture, securityContext sweeps, NodePort/ingress exposure | P1 when Kubernetes present |
| DB | checks/server/db-server-hardening.md | PostgreSQL pg_hba/scram/TLS, MySQL auth+FILE-priv, Redis ACL/binding, MongoDB auth, app-user least privilege | P1 when database engines present |
| TUNNEL | checks/server/cloudflared-tunnel.md | Tunnel token/creds protection, ingress precision, origin double-binding bypass, edge WAF/Access checklist, real-IP trust | P1 when cloudflared present |
| DR | checks/server/backup-dr.md | Backup inventory gaps, destination tiering 3-2-1-1-0, encryption/key custody, restore drills, RTO/RPO worksheets | P2 |
| DFIR | checks/dfir-triage.md | First-60–120-minute triage of a suspected-compromised Linux host/K8s node: volatile capture off-host, session forensics, persistence sweep (cron/units/init hooks), webshell & malware hunting, containment gates | Reactive — load during incidents; not part of routine audit flow |
| IR | checks/incident-response.md | Organization-level IR capability audit: playbooks, roles & on-call, severity/paging matrix, asset-inventory currency, tabletop/drill evidence, recovery gates reusing run-all-sweeps | P3 |

Skip rules mirror the code skillset: skip only with recorded reason in HOST-PROFILE.md.

## 4. Phases

**Phase 0 — Authorization & access.** Confirm authorization + how you may access
the host (SSH? only repo of configs?). Record scope.

**Phase 1 — Host profile.** Fill HOST-PROFILE.md:
- OS/release/kernel (`cat /etc/os-release`, `uname -a`), virtualization type
- Listening sockets map: `ss -tlnp` / `ss -ulnp` → service → user → bound address (0.0.0.0 vs 127.0.0.1 vs [::])
- Firewall state: `nft list ruleset` / `iptables-save` / `ufw status verbose`; IPv6 state
- Service manager units enabled: `systemctl list-unit-files --state=enabled`
- Web/proxy stack present? (nginx/caddy/ha/apache) — enables TLS module deep pass
- Auth mechanisms used by the app (sessions? **API tokens?**) — enables TOK module
- Container runtime present? — enables SANDBOX docker sections
- Update mechanism state, pending updates count
- Applicability matrix per module slug + reasons

**Phase 2 — Prioritization.** Internet-reachable listeners first (FW/TLS/BASE),
then identity plane (TOK), then containment (SANDBOX/HSECRET), then hygiene (PATCH/LOGMON).

**Phase 3 — Execute modules.** Same delegation protocol as SKILL.md Section 8
(subagent prompt template applies with module path swapped). Each finding =
one report file per template incl. Reproduction (the exact command showing the
weak state) and Fix Verification Plan (the exact command that must show the
hardened state post-fix).

**Phase 4 — Correlate.** Chains matter here: e.g., FW missing egress + SSRF in
app = metadata theft path; weak sshd + no fail2ban = brute-force path; root-run
service + app RCE = host takeover. Document chains in SUMMARY.md.

**Phase 5 — Summary.** SUMMARY.md via template; include a top-to-bottom
prioritized hardening checklist (ordered quick wins first) as a dedicated
section — operators apply it literally.

**Phase 6 — Apply & verify (opt-in).** Per finding: propose diff → approve →
apply → run the finding's verification command → mark Verified-Fixed. Firewalls
and sshd changes require extra care: warn about lockout risk, demand console/
out-of-band access confirmation before reloading remote firewall rules.

## 5. Quality Bar

- Every weak-state claim backed by a captured command output reference
- Every fix includes both the config change AND the verify command
- Lockout-risk operations flagged inline (sshd, firewall, sudo)
- IPv6 checked wherever IPv4 is (parity is a common silent gap)

---

## Appendix — Determinism Protocol (normative)

Identical rules to SKILL.md Appendix C, with host-audit specifics:

1. **Evidence rule:** every weak-state claim cites the exact read-only command
   run and interprets its captured output. No output → `Needs-Review`.
2. **Closed-world rule:** execute the module's checks in order; surprises go to
   Open Questions; no improvised deep-dives mid-module.
3. **Lookup, don't feel:** severity from the module's anchor table;
   lockout-risk flags applied verbatim from module warnings.
4. **Stop-and-record:** missing privileges (root needed), unreadable configs,
   ambiguous state → one Open Question sentence, next check.
5. **Non-mutation invariant:** if a check cannot be completed read-only, it is
   recorded as deferred-with-reason, never executed mutatively "just to see".
6. **One module per pass**, PROGRESS.md updated at every boundary; SUMMARY
   statistics recounted from finding files.
7. **Fixed vocabulary** for statuses/severities/IDs as in the shared templates.
