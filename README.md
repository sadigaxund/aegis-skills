# Aegis Skills

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Check modules](https://img.shields.io/badge/check_modules-40-2ea44f)](#the-check-modules)
[![Orchestrators](https://img.shields.io/badge/orchestrators-3-blueviolet)](#whats-inside)
[![Runtime](https://img.shields.io/badge/runtime-bash_%2B_grep-lightgrey)](#requirements)

A reusable security-audit skillset that any coding agent can execute, from top-tier models
down to basic file-reading assistants. It audits source code and the Linux servers that
serve it, writes standardized finding reports with proof and fixes, and covers the loop
from detection through incident response.

It targets solo developers and small teams protecting their own internet-facing services,
and scales to a shared team methodology. New to security terms? Start with
[GUIDE.md](GUIDE.md); this file is the map and manual.

The project began in August 2026 as a distillation exercise with the ox-alpha model and is
now model-agnostic: any capable agent can run, audit, and extend it. There is nothing to
install and no accounts; you need `bash`, `grep` (ripgrep recommended), `find`, and
standard Unix tooling.

---

## What's inside

Three orchestrators divide the work. Each is an entry point you hand to an agent, and each
owns one folder under `skills/`.

| Orchestrator | Question it answers | Modules |
|---|---|---|
| [SKILL-CODE.md](SKILL-CODE.md) | What bugs are in the software? | `skills/code/` (24 modules) |
| [SKILL-SERVER.md](SKILL-SERVER.md) | How exposed are my machines? | `skills/server/` (12 modules) |
| [SKILL-OPERATIONS.md](SKILL-OPERATIONS.md) | Are we watching, responding, improving? | `skills/operations/` (4 modules) |

Supporting files: `templates/` (mandatory report formats), `tools/` (13 read-only evidence
sweep scripts plus a runner), [GUIDE.md](GUIDE.md) (human-readable concept guide), and
[COVERAGE.md](COVERAGE.md) (standards-to-modules completeness matrix).

### Install as agent skills

Every module follows the open [agentskills.io](https://agentskills.io) format
(`<name>/SKILL.md`), so the kit installs directly into Claude Code, OpenCode, Cursor,
Codex, Windsurf and 40+ compatible agents:

```bash
npx skills add AS-FOSS/aegis-skills                        # all 40 modules
npx skills add AS-FOSS/aegis-skills -s injection -s AUTHN  # pick modules
```

Claude Code users can alternatively install it as a plugin:

```text
/plugin marketplace add AS-FOSS/aegis-skills
/plugin install aegis@aegis
```

The three orchestrator files stay at the repository root as entry-point documents; read
them in the agent chat instead of installing.

## The check modules

### Code and application audits (`skills/code/`, owned by SKILL-CODE.md)

**Input handling and code execution**

| Slug | Module | Catches |
|---|---|---|
| INJ | injection.md | SQLi, NoSQLi, command injection, SSTI, eval-family, LDAP/XPath |
| FILE | file-handling.md | Path traversal, unsafe uploads/downloads, zip-slip |
| DESER | deserialization.md | Pickle/Java/.NET/YAML deserialization, XXE, prototype pollution |
| MEM | memory-safety.md | Overflows, UAF, integer bugs, format strings, Rust unsafe, leaks |

**Identity and access**

| Slug | Module | Catches |
|---|---|---|
| AUTHN | authn-session.md | Login flaws, session management, JWT/MFA/reset weaknesses |
| AUTHZ | authz-access-control.md | IDOR/BOLA, privilege escalation, tenant isolation |
| SSO | oauth-sso.md | OAuth/OIDC/SAML flows, PKCE, redirect validation |

**Web surface and protocols**

| Slug | Module | Catches |
|---|---|---|
| WEB | web-client.md | XSS, CSRF, clickjacking, postMessage abuse |
| SSRF | ssrf-url-security.md | SSRF, open redirects, cloud metadata exposure |
| PROTO | http-protocol.md | Request smuggling, host-header attacks, cache poisoning |
| API | api-security.md | Mass assignment, missing rate limits, GraphQL/gRPC gaps |

**Data, secrets and crypto**

| Slug | Module | Catches |
|---|---|---|
| SECRETS | secrets-data-exposure.md | Hardcoded credentials, secret sprawl, PII/log exposure |
| CRYPTO | crypto.md | Weak algorithms, IV/nonce misuse, insecure randomness |
| MAIL | email-sms.md | SPF/DKIM/DMARC gaps, header injection, OTP/SMS fraud |

**Logic, availability and platform**

| Slug | Module | Catches |
|---|---|---|
| LOGIC | business-logic-races.md | Workflow bypass, price tampering, race conditions |
| DOS | denial-of-service.md | ReDoS, unbounded allocation, decompression bombs |
| CONFIG | configuration-hardening.md | Debug/prod confusion, CORS, headers, IaC misconfig |

**Supply chain and integrity**

| Slug | Module | Catches |
|---|---|---|
| SUPPLY | supply-chain.md | Vulnerable deps, CI/CD flaws, lockfile hygiene |
| MALCODE | malicious-code.md | Deliberate malice: obfuscation, beacons, backdoor routes, build.rs implants |

**Specialized surfaces**

| Slug | Module | Catches |
|---|---|---|
| IAM | cloud-iam.md | Cloud IAM misconfig from Terraform/IaC, trust policies, public buckets |
| LLM | llm-ai.md | Prompt injection, tool-use abuse, RAG leakage, model cost abuse |
| DNS | dns-takeover.md | Subdomain takeover, dangling records |
| GAME | gaming-security.md | Client-trust violations, economy dupes, receipt fraud, leaderboard forgery |
| BAAS | baas-platform.md | Supabase RLS gaps, Firebase rules, preview-deployment exposure, payment-webhook integrity, CMS hygiene |

### Linux server audits (`skills/server/`, owned by SKILL-SERVER.md)

| Slug | Module | Covers |
|---|---|---|
| BASE | linux-baseline.md | Users/sudo/PAM, sshd hardening, sysctl, permissions |
| FW | firewall-edge.md | Default-deny firewall, egress filtering, fail2ban, docker bypass |
| TLS | tls-proxy.md | Reverse proxy hardening, modern TLS, admin-path shielding |
| TOK | api-token-security.md | API-token lifecycle from design to leak response |
| SANDBOX | service-sandboxing.md | systemd sandboxing, seccomp/AppArmor, docker.sock risks |
| PATCH | updates-patching.md | Unattended upgrades, EOL detection, attack-surface pruning |
| LOGMON | logging-monitoring.md | journald/auditd/rsyslog integrity, alert wiring |
| HSECRET | host-secrets.md | Secrets on disk, key/cert permissions, history leaks |
| K8S | kubernetes-cluster.md | RBAC escalation, NetworkPolicy, pod security standards |
| DB | db-server-hardening.md | PostgreSQL/MySQL/Redis/MongoDB hardening |
| TUNNEL | cloudflared-tunnel.md | Tunnel token protection, ingress precision, origin isolation |
| DR | backup-dr.md | Backup hygiene, encryption, restore drills, ransomware canaries |

### Operations loop (`owned by SKILL-OPERATIONS.md`)

| Slug | Module | Covers |
|---|---|---|
| DETECT | blue-team-detection.md | Detection coverage per class, alert thresholds, purple-team replay |
| IR | incident-response.md | Response playbooks, containment scenarios, tabletop kit |
| DFIR | dfir-triage.md | First-hours triage of a compromised host |
| VULN | vuln-mgmt-process.md | Prioritization, SLAs, exception register, metrics cadence |

Every module opens with a zero-background Prerequisites & Vocabulary primer, then follows
the same 12-section audit contract, from ripgrep-ready signatures through curl-based
reproduction steps to remediation diffs and fix-verification plans. See
[SKILL-CODE.md §Registry](SKILL-CODE.md) for trigger conditions and priorities, and
[GUIDE.md](GUIDE.md) for plain-language explanations of each class.

## Quick start

### 1. Audit a codebase

Point your agent at this repository with a prompt like:

```text
Read SKILL-CODE.md fully, then execute a full security audit of <path-to-target-repo>.
Authorization: I own this code. Static analysis only.
```

The agent runs recon, dispatches the applicable check modules, and writes findings plus a
summary under `security-audit/<run-id>/`.

### 2. Audit a server

```text
Read SKILL-SERVER.md fully, then audit host <host/IP> over SSH.
Authorization: I own this host. Read-only inspection only.
```

Same idea, host-flavored: exposure map first, then hardening checks, ending in a
prioritized checklist.

### 3. Collect evidence with the sweeps (recommended before a server audit)

The sweeps are shell scripts that pull the same set of facts from a host every time:
listeners, firewall state, config keys, secrets on disk. They write plain-text reports and
change nothing. Running them first means your agent only interprets results instead of
inventing commands, which matters most for weaker models.

Three steps. In every command below, replace `user@host` with your server login and
`/opt/aegis-skills` with wherever you want the toolkit to live on that server.

**Step 1: put this toolkit onto your server.** Run from your workstation, inside your
local clone of this repository (`./` means "this folder"). Pick whichever line fits:

```bash
git clone https://github.com/AS-FOSS/aegis-skills /opt/aegis-skills   # host has git access? run it there
rsync -a --exclude .git ./ user@host:/opt/aegis-skills/                  # otherwise push the folder from here
```

**Step 2: run every sweep on the server.** This creates a folder of text reports on the
server itself:

```bash
ssh user@host 'cd /opt/aegis-skills && ./tools/run-all-sweeps.sh'
```

**Step 3: copy those reports back to your workstation** so you can hand them to your
agent. `<timestamp>` is the folder name step 2 printed, like `sweep-evidence-20260825-0700`:

```bash
rsync -a user@host:/opt/aegis-skills/sweep-evidence-<timestamp>/ ./evidence/
```

Give each report to the agent together with its matching `skills/server/<name>/SKILL.md`.

## What you get per audit

```
security-audit/<run-id>/
├── PROGRESS.md          # resumable ledger of every step taken
├── TARGET-PROFILE.md    # languages, entry points, which modules apply and why
├── SUMMARY.md           # stats, top risks, chained attack paths, remediation roadmap
└── findings/
    └── INJ-001-sqli-in-search.md
```

Each finding file contains location, root cause, affected surface, a working PoC, impact,
a before/after fix, and a plan to verify the fix actually closes the hole. Statuses move
`Needs-Review → Probable → Confirmed → Fixed → Verified-Fixed`; severities come from
written rubrics with CVSS vectors.

## Ground rules baked into the skillset

- **Authorization gate:** agents refuse targets the user doesn't own or have written
  permission to test.
- **Evidence rule:** no claim without captured command output or quoted `file:line`;
  otherwise the finding auto-downgrades to `Needs-Review`.
- **Determinism protocol:** closed-world execution, stop-and-record instead of
  improvising, lookup-table severities. A weak model following it produces a complete,
  honest, reviewable audit; a strong model produces the same with fewer false positives.
- **Redaction rule:** secret values never appear in reports or sweep output.
- **Read-only default:** applying fixes is a separate, explicitly requested phase.

## Requirements

| Component | Needs |
|---|---|
| Code audits | Any agent with file-read and grep. Subagent support optional. |
| Server audits | SSH/read access to the host; root gives fuller fidelity, unprivileged still works. |
| Sweep scripts | bash and coreutils only; missing tools print `[skip: X not installed]`. |

## Versioning

Both orchestrators carry a `version:` frontmatter field. Bump the minor version when
adding or changing modules, the patch version for copy edits, and tag the commit
(`vX.Y.Z`). Audit runs record the version they executed, so posture can be diffed over
time. Current: v1.2.0.

## Extending

New modules follow the 13-section skeleton and register in their orchestrator's registry;
see Appendix B in `SKILL-CODE.md` for the authoring spec. New sweeps must satisfy
`tools/README.md`. Design rule for additions: a basic agent following the letter of the
module must still produce a correct result, so prefer literal commands over prose and
downgrade uncertainty instead of guessing.

## Scope and honesty

This covers the vulnerability classes behind most real-world breaches of internet-facing
services. It does not replace dynamic penetration testing, network-layer DDoS mitigation,
social-engineering defense, or a 24/7 SOC. It makes all of them cheaper by telling you
exactly where your weaknesses are.

## Credits and license

Project layout and some domain surfaces were inspired by browsing
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills).
Every module here was written natively for this playbook's format and accuracy contract.
Licensed Apache-2.0 ([LICENSE](LICENSE)). Security tooling: use only against systems you own
or are authorized to test.
