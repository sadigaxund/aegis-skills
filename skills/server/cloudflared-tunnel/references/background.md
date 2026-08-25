# Cloudflare Tunnel Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind tunnel credential protection, ingress precision,
origin double-binding bypass, edge-layer assumptions, and visitor-IP trust;
SKILL.md carries the exact sweeps, interview checklists, and hardened configs.

## How this class emerged

For most of web history, publishing a service meant opening inbound ports and
hardening whatever answered them. Reverse-tunnel tooling inverted that: an
outbound-only daemon dials out to a provider's edge, keeps the connection
alive, and visitors are relayed back down it — no inbound firewall rules at
all. Commercial predecessors (ngrok-class tools, early 2010s) proved the
pattern for developers; Cloudflare launched Argo Tunnel around 2017–2018,
renamed it Cloudflare Tunnel (daemon `cloudflared`), and opened it broadly in
2021. Later, remotely-managed tunnels let operators configure everything from
a dashboard using nothing but a token.

The model solved real problems — NAT-bound origins, DDoS-driven IP hiding —
and created a new failure class with two defining properties:

- **The credential IS the tunnel.** A token or credentials JSON is enough to
  connect a daemon to your hostname from anywhere on earth. Whoever extracts
  one runs their own connector with ingress rules of THEIR choosing — a
  persistent relay into your network that your perimeter was deliberately
  configured to allow.
- **Controls split between edge and origin.** WAF rules, rate limiting, bot
  management, and Zero Trust Access policies live in a cloud dashboard,
  invisible from the protected host. The origin sees only what arrives down
  the tunnel — unless it ALSO listens publicly, in which case direct-to-origin
  connections skip every edge control entirely.

That second property produced the signature breach pattern of this class:
origin IPs recovered through historical DNS records, certificate-transparency
logs, or plain scanning; firewalls relaxed because "traffic comes via
Cloudflare"; attackers connecting directly past all of it. Tunneling done
wrong is not zero-trust — it is trust with better marketing.

## Anatomy: one token line, two independent compromises

A minimal generic weak configuration needs one unit file and one listener.
Picture a small app host:

```
# /etc/systemd/system/cloudflared.service   (mode 644 — units must be readable)
[Service]
ExecStart=/usr/bin/cloudflared tunnel run --token eyJ...REDACTED...

$ ss -tlnp | grep gunicorn
LISTEN  0.0.0.0:8000   users:(("gunicorn",pid=910))     # app also bound publicly

# config.yml ingress (config-file mode variant):
ingress:
  - service: http://localhost:8080        # wildcard catch-all to the app
```

Walkthrough of how this fails:

1. Any local account reads the unit (644 is required by systemd) and extracts
   the token. From their own laptop they now run a second connector for YOUR
   tunnel — routing arbitrary hostnames into your LAN per their ingress.
2. Independently, a passive-DNS lookup or certificate-transparency entry
   reveals the origin IP behind `app.example.com`. The attacker connects to
   `http://<origin-ip>:8000/` directly; WAF, rate limits, bot fight, and
   Access policies never see that traffic — only the host firewall stands
   there, and it was opened "for Cloudflare".
3. The catch-all ingress means any hostname routed to the tunnel reaches the
   app: forgotten subdomains, internal tools, anything.
4. Debug logging echoes authorization headers into journald, readable by
   every member of the adm group.

Two separate full compromises of different character, both enabled by
defaults chosen for convenience.

## Why naive fixes fail

- **Deleting the exposed token without rotating.** Anything ever readable is
  burned; removal is cosmetic. Rotation (new credential, redeploy, revoke old)
  precedes cleanup, always.
- **`chmod 600` on unit files.** systemd requires units to be readable; the
  fix is removing secret material from units — credentials-file mode with
  restrictive perms or runtime injection from a secret manager.
- **Loopback binding while forgetting IPv6.** The app binds `127.0.0.1` for
  IPv4 but `[::]` stays open, or the container publishes on v4 only and v6
  leaks. Verify BOTH address families in listener tables.
- **Fetching Cloudflare IP ranges once and pinning them forever.** Ranges
  change; stale allowlists eventually block legitimate traffic or admit
  nothing useful. Fetch at deploy time, schedule re-review.
- **Assuming edge controls exist because "we're behind Cloudflare."** WAF and
  Access require deliberate configuration in the dashboard — unverifiable
  from the host, so record them as interview items, Confirmed/Unconfirmed,
  never as assumed-present findings.
- **`noTLSVerify: true` as a quick fix for internal certificates.** The hop
  becomes MITM-able by anyone positioned on the segment. Loopback plaintext
  honestly declares its threat model better than encrypted-but-unverified;
  otherwise deploy `caPool` + matching `originServerName`.
- **Wildcard catch-alls for convenience.** `- service: http_status:404`
  terminal rule costs one line and closes the any-hostname-reaches-the-app
  door plus ingress-miss error leakage.
- **Mounting the Docker socket into the cloudflared container "just in
  case".** An outbound relay needs no socket; the mount converts a daemon
  compromise into host takeover.

## Common misconceptions

1. "A tunnel replaces authentication." It replaces port exposure. Whatever
   reaches the origin arrives pre-authenticated-by-nothing unless Access
   policies or the app itself enforce something.
2. "No inbound ports means nothing is reachable." The tunnel is reachable —
   by whoever holds its credentials — and the origin may still answer
   directly if dual-bound.
3. "The origin IP can't be discovered." Historical DNS archives,
   certificate-transparency logs, misconfigured subdomains, banner
   fingerprints, and mail headers leak origins routinely.
4. "WARP and Cloudflare Tunnel are the same thing." Different products:
   device egress client versus inbound relay daemon. Verify process names
   before applying this module.
5. "The metrics endpoint is harmless." Runtime internals on a non-loopback
   bind are an information-leak finding; loopback-only is the expected state.
6. "Dashboard settings show up in the repo." They don't — which is precisely
   why the audit treats them as structured interviews rather than greps.
7. "Token mode and config mode are interchangeable security-wise." Token mode
   simplifies ops but concentrates the entire tunnel authority in one string;
   wherever it lands (unit, env, CI variable), readers own the tunnel.

## How professionals think about it today

Posture decomposes into four audited pillars — identity material, ingress
precision, edge layers, binding discipline — mapping onto SKILL.md's eight
domains like this:

| Pillar / domain | Typical gap | Defining control |
|---|---|---|
| Daemon discovery & run mode | orphan tunnels, unknown modes | documented unit-per-tunnel inventory |
| Identity-material exposure | tokens in units/envs; wide perms | 600 root-shaped creds; cert.pem off app hosts |
| Ingress precision | wildcard catch-alls, LAN targets | explicit mappings first, 404 last, loopback origins |
| Origin binding discipline | dual binds, opened firewalls | loopback + still-default-deny FW decision recorded |
| Edge-layer inventory | unverified WAF/Access/rate limits | interview checklist, quarterly re-confirmation |
| Visitor-IP handling | trusting forwarded headers broadly | CF-Connecting-IP trusted only from CF ranges |
| Egress interplay | QUIC path blocked silently | both transports modeled in egress design |
| Operational hygiene | root daemon, debug logs, single replica | dedicated user, info-level logging, ≥2 connectors |

Compounding is the scoring discipline: this module's findings multiply code-
audit findings rather than adding. Evaluate the shortest complete attack
path, never findings in isolation.

## Read next

In `../SKILL.md`: **Scope & Objectives** (eight domains in priority order),
**Prerequisites & Vocabulary**, **Mental Model** (outbound-only relay, two
silent bypasses, four pillars), **What To Check** (seven numbered sections
plus paste-ready sweep), **Where To Look** (host/repo/dashboard surface
table), **Patterns & Signatures** (ingress and systemd VULNERABLE/FIXED
pairs, grep signatures), **Taint Tracing Guidance** (five taint families),
**Exploitation & Reproduction** (Demos 1–3, attacker narrative, interview
checklist), **Remediation** (identity → sandbox → ingress → binding → edge →
visitor IP), **Verification & Validation** (restart gate, anti-bypass
negative test), **Severity Assessment**, **Common False Positives**,
**References**.

Sibling modules: `../firewall-edge/SKILL.md` (default-deny construction and
the CF-ranges allowlist decision), `../api-token-security/SKILL.md` (rotation
runbook for burned tokens), `../host-secrets/SKILL.md` (credential custody on
this same host), `../tls-proxy/SKILL.md` (the origin-side proxy hop and header
behavior), `../linux-baseline/SKILL.md` and `../service-sandboxing/SKILL.md`
(the systemd sandbox primitives behind the hardened drop-in),
`../kubernetes-cluster/SKILL.md` (the containerized connector variant).
