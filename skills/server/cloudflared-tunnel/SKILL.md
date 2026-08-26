---
name: aegis-cloudflared-tunnel-hardening
description: Audits Cloudflare Tunnel (cloudflared) deployments for daemon credential exposure, imprecise ingress rules, origin double-binding that bypasses edge protections, spoofable visitor-IP trust, and unverifiable-from-host edge-layer controls — with read-only sweeps, interview checklists, and hardened reference configs.
category_slug: TUNNEL
cwe: [CWE-16, CWE-284]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit one Linux host running the Cloudflare Tunnel daemon (`cloudflared`) — or the config-as-code repository that declares it. Eight domains, in priority order:

1. **Daemon discovery & run mode** — locate every cloudflared systemd unit; classify token-based mode (`cloudflared tunnel run --token ...`) vs config-file mode (`config.yml` + tunnel credentials JSON); detect undocumented or duplicate tunnels on one host.
2. **Identity-material exposure** — tunnel tokens embedded in unit files or environment variables, credentials JSONs (`/etc/cloudflared/<UUID>.json`), and the account-level `cert.pem`; permissions and placement. Whoever holds this material controls your tunnel.
3. **Ingress precision** — the `ingress:` table in `config.yml` is the tunnel's ACL: hostname→service mappings, terminal catch-all correctness, path-routing subtleties, origin targets pointing at LAN IPs, `noTLSVerify: true` hops, unix-socket targets.
4. **Origin binding discipline** — apps fronted by the tunnel MUST NOT also be reachable directly (wildcard binds, published container ports, missing firewall). Direct-to-origin access skips every Cloudflare protection.
5. **Edge-layer controls inventory** — WAF, rate limiting, bot fight, Zero Trust Access policies, Service Tokens, mTLS origin pull. These are configured in the Cloudflare dashboard and are INVISIBLE from the host/repo; record them strictly as interview questions.
6. **Real visitor IP handling** — the application must derive client IP from `CF-Connecting-IP` while trusting ONLY the Cloudflare/cloudflared proxy addresses; otherwise the value is client-spoofable.
7. **Egress interplay** — cloudflared needs outbound connectivity (443, plus UDP/7844 QUIC to regional edges); verify the egress-filtering design permits it AND treats Cloudflare ranges as an approved-destination example.
8. **Operational hygiene** — auto-update posture tradeoffs, metrics endpoint binding, log verbosity leaking sensitive data, multi-tunnel-per-host review, single-replica availability risk, containerized variants.

Out of scope (cross-references): firewall design and default-deny construction → FW/firewall-edge; token lifecycle, storage classes, rotation mechanics → TOK/api-token-security and HSECRET/host-secrets; TLS termination and cache/header behavior at proxies → TLS/tls-proxy; application-level authorization and request-forgery classes → AUTHZ/authz-access-control, PROTO/http-protocol; supply-chain pinning policy → SUPPLY/supply-chain; baseline sandboxing primitives → BASE/linux-baseline.

Operating rules:

- All inspection commands are read-only; mutating commands appear only under Remediation after approval.
- Prefer effective-state evidence (`ss -tlnp`, `systemctl cat`, `stat`) over documentation or claims.
- Commands needing root are tagged `[ROOT]`. Without root, audit world-readable state plus the config repo and judge rendered configs using Patterns & Signatures.
- REACTION DISCIPLINE: tunnel tokens are live secrets. When displaying unit contents or logs, pipe through the redaction filters shown in the sweep below and NEVER reproduce a raw token, `TunnelSecret`, or credentials-JSON body in the report.
- Restarting the cloudflared unit is service-affecting; propose restarts only under explicit approval (see Verification & Validation).
- Dashboard-side settings cannot be verified from here. Report them as "confirmed/unconfirmed — interview" rather than guessing.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **cloudflared / tunnel**: an outbound-only daemon relaying visitor traffic from Cloudflare's edge to local services
- **ingress rules**: the config table mapping which hostnames reach which local services
- **origin**: the real application behind the tunnel
- **direct-to-origin bypass**: reaching the app's own public port, skipping every Cloudflare protection
- **edge controls**: WAF, rate-limiting, and Access policies configured in the dashboard — invisible from this host
- **CF-Connecting-IP**: the header carrying the real visitor IP; trust it only from Cloudflare's addresses
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

cloudflared is an **outbound-only** daemon. It dials out to Cloudflare's edge network (QUIC over UDP/7844 to regional edge addresses, with an HTTP/2-over-TCP fallback) and keeps those connections alive. Public visitors hit a Cloudflare-hosted hostname; the edge relays each request back down the already-established connection to your daemon, which forwards it to a local origin service per the ingress rules. The host needs **no inbound ports opened for the tunnel** — the classic "open 80/443 and harden the web server" problem is replaced by a different one: whoever controls the daemon (or its credentials) has an always-on relay INTO your internal network that you deliberately punched through every perimeter.

The tunnel **replaces port exposure, not application authorization**. Two silent bypasses collapse the model. First, if the application behind the tunnel ALSO binds a public interface (`0.0.0.0:8000`) or the firewall was relaxed because "we use Cloudflare", anyone who learns the origin IP — via historical DNS records, certificate-transparency logs, misconfigured subdomains, or plain scanning — connects DIRECTLY and skips every Cloudflare protection: WAF rules, rate limits, bot management, Zero Trust Access policies all exist only at the edge. Second, even with perfect binding, whatever reaches the app arrives pre-authenticated-by-nothing unless the edge layers (Access/WAF) or the app itself enforce something; a tunnel to an unprotected admin panel is just a private door into an unlocked room.

Security posture therefore decomposes into four pillars, audited in order: (1) **daemon identity protection** — the token/credentials ARE the tunnel; exposure hands the attacker their own ingress with ingress rules of THEIR choosing; (2) **ingress precision** — `config.yml` decides which hostnames reach which local services, and a lazy catch-all turns the tunnel into a universal forwarder; (3) **what sits in front at the edge** — dashboard-configured WAF/rate-limit/Access layers that must be interviewed, never assumed; (4) **origin binding discipline** — loopback-only binds plus a STILL-default-deny firewall, so the tunnel remains the only road in. Treat every finding here as compounding with code-audit findings: an edge without app-layer authz is a single layer, and single layers fail completely.

## What To Check

Run the paste-ready sweep at the end of this section first `[ROOT]`, then work the tables below.

### 1. Daemon discovery & identity material

| Check | Command/grep | Healthy | Finding condition |
|---|---|---|---|
| Unit inventory | `systemctl list-units --all 'cloudflared*'`; `ls -la /etc/systemd/system/cloudflared* /usr/lib/systemd/system/cloudflared*` | Exactly the units documented for this host; each maps to a known tunnel | Undocumented unit, duplicate daemons, or `cloudflared@*.service` template instances nobody can attribute |
| Run-mode classification | `systemctl cat cloudflared` | ExecStart clearly shows token mode (`--token`) OR config mode (`--config` / default `/etc/cloudflared/config.yml`); matches change record | Mode unknown, or BOTH modes' material present with no explanation |
| Token-in-unit exposure | Redacted grep of unit text for `--token`, `-t`, `Environment=` lines (see sweep) | No secret material anywhere in the unit file | Token literal in `ExecStart=` or `Environment=` → any user/group that can read the unit controls your tunnel (rotation story → TOK module) |
| Credentials JSON perms | `stat -c '%a %U:%G %n' /etc/cloudflared/*.json` | `600 root:root` shape (or `640 root:cloudflared` if running unprivileged) | Group/world-readable; readable by the app user it fronts |
| Account cert perms | `stat -c '%a %U:%G %n' /etc/cloudflared/cert.pem ~/.cloudflared/cert.pem` | `600 root:root`; absent from app hosts where not needed | Present AND wide-readable — `cert.pem` is ACCOUNT-level material (create/delete tunnels, route DNS), worse than one tunnel's creds |
| Daemon owner | `ps -o user=,cmd= -C cloudflared`; `ss -tlnp` process fields | Dedicated least-privilege user (or containerized) | Running as root when no feature requires it |
| Tunnel-to-host mapping | Interview + `journalctl -u cloudflared --no-pager -n 200` startup lines (redact IDs before reporting if policy requires) | Every daemon traceable to a named tunnel and owner | Orphan tunnels (created, routed, forgotten) — each is an unmaintained door |

### 2. Ingress precision (config.yml mode)

Locate the config first (`find /etc /root/.cloudflared "$HOME/.cloudflared" -name 'config.yml' -path '*cloudflared*'`), then dump and read it as an ACL.

| Check | Command/grep | Healthy | Finding condition |
|---|---|---|---|
| Terminal catch-all | Last `ingress:` entry inspection | Final rule is exactly `- service: http_status:404` | Catch-all forwards to an app (`service: http://localhost:8000`) → ANY hostname routed to this tunnel reaches the app; also blocks ingress-rule-miss errors leaking to origin |
| Rule ordering semantics | Read table top-to-bottom | Most-specific hostnames/paths FIRST | Rules added after a broad rule are dead config — a "protected" hostname silently matched by an earlier broad rule |
| Hostname→service precision | Compare each `hostname:` against asset inventory | Every mapping has an owner and justification | Mappings to forgotten services (old admin panels, metrics UIs, debug endpoints) |
| Path-based routing subtleties | Inspect `path:` keys | Path rules used deliberately; admin paths either NOT exposed via tunnel or fronted by Access (interview) | Path regex narrower than intended (e.g., missing trailing-slash variant) exposing sibling routes, or admin paths tunneled with zero edge authn |
| Origin target locality | `grep -E 'service:' config.yml` | Targets are `http://localhost:<port>`, `unix:/...`, or loopback names | Targets point at LAN IPs (`10.x`, `192.168.x`) → tunnel relays into the wider network = lateral-pivot surface once the host or daemon is compromised |
| Origin TLS verification | `grep -B2 -A4 'noTLSVerify' config.yml` | No `noTLSVerify: true` occurrences | Any occurrence on a hop leaving the host = MITM finding on that hop (see Exploitation #3). Loopback hops may justify plaintext HTTP instead |
| SNI discipline | `originServerName` / `caPool` keys on HTTPS origins | Set to match the origin certificate | Absent on non-loopback HTTPS origins → verification fails open only because someone disabled it |
| Unix-socket targets | `service: unix:/path/to.sock`; then `stat` the socket | Socket dir/file owned by daemon-accessible group, mode ≤ `660`, parent dirs not world-writable | World-writable socket directory → local attacker replaces/reaches the origin service |

### 3. Origin binding discipline — THE key chain

For EVERY service named in the ingress table, find its listener line in `ss -tlnp` and classify its bind address:

| Check | Command/grep | Healthy | Finding condition |
|---|---|---|---|
| Bind address per origin | `ss -tlnp | grep <port>` per mapped service | Bound `127.0.0.1:` / `[::1]:` only | Bound `0.0.0.0`, `[::]`, private-interface IP, or published container port → tunnel is decorative; direct access bypasses ALL edge protections (High anchor) |
| Firewall still default-deny | Cross-ref FW sweep (`iptables -S INPUT` policies / `nft list ruleset` base-chain policy) | Inbound default-drop persists; nothing opened "for Cloudflare" | Rules loosened because "traffic comes via Cloudflare" — direct-IP access now succeeds for anyone who learns the origin IP |
| Anti-bypass design decision | Interview + FW ruleset reading | EITHER egress-style allowlist of Cloudflare IP ranges inbound at the edge/firewall, OR origin truly unlisted + default-deny firewall; decision recorded | Neither: unlisted-but-unfiltered origin relying solely on secrecy of the IP |
| Container origins | `docker ps --format ...` published ports; `ss -tlnp` inside netns if authorized | App containers publish nothing (`-p 127.0.0.1:...` at most); cloudflared reaches them via shared network | `-p 8000:8000` style publishes → DNAT bypasses INPUT-chain protections (cross-ref FW Docker section) |

### 4. Edge-layer controls inventory — dashboard-only, interview checklist

Nothing below is verifiable from the host or repo. Ask each question; record Confirmed / Unconfirmed / N-A with the interviewee's name and date. Do NOT report these as verified findings.

| Question | Why it matters | Healthy answer |
|---|---|---|
| Is a WAF managed ruleset attached to the zone/hostname? | Baseline exploit filtering exists only here | Yes — managed ruleset plus targeted custom rules |
| Are rate-limiting rules configured, especially on login/auth routes? | Without edge rate limits, credential stuffing hits the app at line speed | Yes — per-route limits on auth endpoints |
| Is Bot Fight Mode (or equivalent bot management) enabled? | Automated abuse filtering at edge | Enabled, or documented decision why not |
| Do Zero Trust Access policies front `/admin*` (or the whole hostname)? | Access = edge authn layer the app can additionally check (`Cf-Access-Jwt-Assertion`) | Admin paths behind Access at minimum |
| Service Tokens vs email OTP one-time-pin — which for machine vs human paths? | Email OTP suits humans; machine-to-machine needs Service Tokens | Machine paths use Service Tokens; human paths Access with appropriate IdP policy |
| Is Authenticated Origin Pulls (mTLS origin pull) enabled for sensitive zones? | Origin can reject anything that did NOT come through Cloudflare — closes the direct-IP bypass partially | Enabled on production hostnames, or compensating FW allowlist of CF ranges confirmed |
| Do cache rules/Page Rules strip or bypass security headers on cached responses? | Cached responses may lack headers set dynamically at origin | Headers verified on cached AND uncached responses (deep dive → TLS module) |

### 5. Real visitor IP handling at the application

The app sees connections FROM cloudflared (loopback) while real client IPs ride in `CF-Connecting-IP`. Trust configuration must match topology EXACTLY, else attackers spoof logs, rate-limit keys, and geo/IP ACLs by setting header values directly.

| Check | Command/grep | Healthy | Finding condition |
|---|---|---|---|
| nginx real_ip scoping | `grep -rE 'set_real_ip_from|real_ip_header' /etc/nginx/` | `real_ip_header CF-Connecting-IP;` with `set_real_ip_from` limited to Cloudflare ranges + loopback | `set_real_ip_from 0.0.0.0/0` or trusting arbitrary proxies → client-controlled IP spoofing |
| uvicorn/gunicorn proxy handling | Unit/env grep for `--proxy-headers`, `FORWARDED_ALLOW_IPS` | `--proxy-headers` WITH `FORWARDED_ALLOW_IPS=127.0.0.1` (the cloudflared/nginx hop only) | Proxy headers accepted from all addresses (default allows only 127.0.0.1 — confirm env hasn't widened it to `*`) |
| Express trust proxy | `grep -rn "trust proxy" src/ app/ server/` | Value enumerates exact trusted hops (`1`, or explicit IPs) — qualitative semantics review | `app.set('trust proxy', true)` → trusts every upstream hop including clients |
| Framework-level trusted-proxy lists | Django `SECURE_PROXY_SSL_HEADER`/`USE_X_FORWARDED_*`, Rails/Rack `ActionDispatch::RemoteIp` allowlists, Spring `ForwardedHeaderFilter` enablement | Middleware trusts ONLY Cloudflare/cloudflared addresses | Trusted-proxy list includes `0.0.0.0/0` or is commented out while code reads forwarded headers |

### 6. Egress requirements interplay

| Check | Command/grep | Healthy | Finding condition |
|---|---|---|---|
| Outbound path open | FW OUTPUT chain reading + connectivity evidence (`journalctl -u cloudflared | grep -i connect` shows registered connections) | UDP/7844 (QUIC) and TCP/443 (+TCP/7844 http2 fallback) reach Cloudflare edges | Egress filter breaks QUIC silently → degraded/failing tunnel (cross-ref FW egress module) |
| Approved-destination modeling | Egress policy doc/ruleset | Cloudflare edge ranges listed as approved destinations for the tunnel's user/service | Tunnel runs under an unrestricted-egress identity although its destination set is enumerable |
| Protocol fallback awareness | `systemctl cat cloudflared` protocol flags; journal protocol lines | Team knows QUIC→HTTP2 fallback behavior; egress rules cover both transports | Egress designed for QUIC only; fallback path blocked = intermittent outages misread as attacks |

### 7. Operational hygiene

| Check | Command/grep | Healthy | Finding condition |
|---|---|---|---|
| Update posture recorded | `cloudflared --version`; `systemctl cat cloudflared | grep -in update` | Explicit decision: pinned version + scheduled manual updates, OR package auto-update enabled; tradeoff acknowledged | Default drift: neither pinned nor reviewed — supply-chain tradeoff honesty required either way (auto-update ships vendor fixes fast but pulls new code unattended; pinning gives control but demands a patch cadence) |
| Metrics endpoint binding | `ss -tlnp | grep cloudflared`; expect loopback (commonly port 20241 — verify against your build's docs/help) | Bound `127.0.0.1` or disabled | Bound `0.0.0.0`/non-loopback → runtime/internals info-leak finding (Medium) |
| Log verbosity | `journalctl -u cloudflared -n 500 --no-pager` sampled (redact before quoting) | Info-level; no tokens, cookies, authorization headers visible | Debug logging echoing sensitive headers/values into journald → readable by anyone in `adm`/`systemd-journal` groups (Low-Medium) |
| Multiple tunnels per host | Unit inventory + ingress tables side by side | Each tunnel justified; resource/noise isolation intentional | Accidental multi-tenancy: unrelated blast radii share one daemon host |
| HA topology | Interview: how many replicas run this tunnel? | ≥2 connectors for production (also enables zero-downtime restarts) | Single daemon = single point of failure — availability risk adjacent to security incident response |
| Containerized variant | `docker inspect` / compose file / image tag | Image digest-pinned (cross-ref SUPPLY), no socket mounts needed (cloudflared needs NO docker socket), non-root user, config via mounted read-only file or token env from secret manager | Latest-tag image, socket mounted "just in case", root container |

### Paste-ready sweep (read-only)

```bash
# ===== cloudflared sweep [ROOT] =====
echo "== unit inventory =="; systemctl status cloudflared --no-pager 2>/dev/null | sed -n '1,5p'
ls -la /etc/systemd/system/cloudflared* /usr/lib/systemd/system/cloudflared* 2>/dev/null
echo "== effective unit text, REDACTED view (never paste raw tokens) =="
systemctl cat cloudflared 2>/dev/null | sed -E 's/(eyJ[A-Za-z0-9_-]{20,})/[REDACTED_TOKEN]/g'
echo "== token/env lines present? (values redacted) =="
systemctl cat cloudflared 2>/dev/null | grep -inE '(--token|Environment)' | sed -E 's/(eyJ[A-Za-z0-9_-]{20,}|=[A-Za-z0-9+/=_-]{40,})/[REDACTED]/g' || echo "none found"
echo "== identity-material permissions =="; stat -c '%a %U:%G %n' /etc/cloudflared /etc/cloudflared/*.json /etc/cloudflared/cert.pem "$HOME"/.cloudflared/cert.pem 2>/dev/null
echo "== locate config.yml =="; find /etc /opt /root/.cloudflared "$HOME/.cloudflared" -maxdepth 3 -name '*.yml' -o -maxdepth 3 -name '*.yaml' 2>/dev/null | grep -i cloudflared
CFG="$(find /etc/cloudflared /root/.cloudflared "$HOME/.cloudflared" -maxdepth 2 \( -name 'config.yml' -o -name 'config.yaml' \) 2>/dev/null | head -1)"
[ -n "$CFG" ] && { echo "-- $CFG --"; sed -n '1,120p' "$CFG"; }
echo "== metrics binding (expect 127.0.0.1) =="; ss -tlnp | grep -E 'cloudflared|:20241' || echo "no cloudflared TCP listener found"
echo "== FULL listener table -> feed every origin target to FW sweep =="; ss -tlnp
echo "== version + update-flag posture =="; cloudflared --version 2>/dev/null; systemctl cat cloudflared 2>/dev/null | grep -in update || echo "no update-related flags in unit"
echo "== log sensitivity sample (REDACTED) =="; journalctl -u cloudflared -n 100 --no-pager 2>/dev/null | sed -E 's/(eyJ[A-Za-z0-9_-]{20,})/[REDACTED]/g' | grep -icE 'authorization|cookie|cf-connecting-ip|debug' || echo "no sensitive-pattern hits in last 100 lines"
```

## Where To Look

Evidence collection: `tools/sweeps/sweep-cloudflared.sh` captures `[TNL-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

| Location | What it holds |
|---|---|
| `/etc/systemd/system/cloudflared.service`, `/etc/systemd/system/cloudflared*.service`, `/usr/lib/systemd/system/cloudflared*.service` | Unit definitions: ExecStart (run mode, token presence), User=, hardening directives, Environment= |
| `systemctl cat cloudflared` | Effective unit INCLUDING drop-ins (`/etc/systemd/system/cloudflared.service.d/*.conf`) — always prefer this over raw file reads |
| `/etc/cloudflared/config.yml` (also possible under `~/.cloudflared/` of the daemon user) | Tunnel UUID, credentials-file path, ingress rule table, originRequest options, metrics address |
| `/etc/cloudflared/<TUNNEL-UUID>.json` | Per-tunnel credentials JSON — contains the tunnel secret; perms are the check, contents never printed |
| `/etc/cloudflared/cert.pem` and `~/.cloudflared/cert.pem` | Account-level certificate from `cloudflared tunnel login`; grants tunnel/DNS management authority |
| `journalctl -u cloudflared` | Startup config echoes, connection registration, protocol fallbacks, error verbosity (redact before quoting) |
| `ss -tlnp` / `ss -ulnp` | Metrics binding, origin app bindings, anything else the daemon host listens on |
| Container runtime: `docker ps`, `docker inspect <ctr>`, compose files, k8s manifests/helm values | Image tags/digests, mounts (config, tokens), port publishes, user |
| Config-as-code repo: `.tf` files, Ansible roles, compose/kustomize | Terraform cloudflare-provider tunnel resources (resource naming has changed across provider major versions — grep broadly for `cloudflare_.*tunnel`, then validate names against your pinned provider version's docs rather than assuming), rendered unit templates, ingress YAML sources |
| Cloudflare dashboard / Zero Trust console (interview only) | WAF rulesets, rate limiting, bot fight, Access applications/policies, Service Tokens, Authenticated Origin Pulls, cache rules |

## Patterns & Signatures

Ingress table shapes:

```yaml
# VULNERABLE — wildcard catch-all forwards EVERYTHING to the app; LAN origin target;
# unverified TLS on an internal-network hop
ingress:
  - hostname: app.example.com
    service: http://192.168.1.50:8000
  - hostname: '*'
    service: http://localhost:8080        # any hostname routed here reaches this app
  # no terminal http_status:404 rule at all in effect for unknown hosts
```

```yaml
# FIXED — explicit mappings first, loopback origins, verified TLS with pinned SNI,
# terminal catch-all returns 404 from the edge path itself
ingress:
  - hostname: app.example.com
    service: http://localhost:8000
  - hostname: api.example.com
    path: ^/v2/.*
    originRequest:
      connectTimeout: 10s
    service: https://localhost:8443       # TLS to local TLS-terminating proxy
  - hostname: legacy.internal.example.com
    originRequest:
      caPool: /etc/cloudflared/internal-ca.pem
      originServerName: legacy.internal.example.com   # SNI matches origin cert
    service: https://10.20.0.11:8443
  - service: http_status:404              # ALWAYS last: terminal catch-all
```

Systemd shapes:

```ini
# VULNERABLE — root daemon, live token inline in ExecStart (any host reader owns the tunnel),
# no sandboxing, metrics implicitly default
[Unit]
Description=cloudflared

[Service]
ExecStart=/usr/bin/cloudflared tunnel run --token eyJ...REDACTED...
Restart=on-failure
```

```ini
# VULNERABLE — token via Environment= is equally exposed to anyone reading the unit/process env
[Service]
Environment=TUNNEL_TOKEN=eyJ...REDACTED...
ExecStart=/usr/bin/cloudflared tunnel run --token ${TUNNEL_TOKEN}
```

Grep signatures (host + repo):

```bash
grep -rn 'noTLSVerify:\s*true' --include='*.yml' --include='*.yaml' .          # MITM hop finding
grep -rEn 'service:\s*(http|tcp|ssh|rdp)://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' .  # LAN-origin targets
grep -rn 'hostname:' config.yml | sort                                          # exposure inventory
grep -rnE '\-\-token' /etc/systemd/system/                                      # token-in-unit
grep -rn "trust proxy" app/ src/ server/                                        # visitor-IP trust
grep -rEn 'set_real_ip_from' /etc/nginx/                                        # real_ip scoping
ss -tlnp | awk '$4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\[::\]:/'                        # dual-binding candidates (cross-ref FW)
```

Healthy shape summary: one documented unit per tunnel → dedicated user or container → credentials at `600 root:root` shape → ingress ends `- service: http_status:404` → every origin bound to loopback → firewall still default-deny → edge layers confirmed by interview.

## Taint Tracing Guidance

In config-as-code repos, trace these taints end-to-end:

1. **Secret taint** — source (CI variable, secret manager reference, `.env`, heredoc in Ansible) → sink (unit `ExecStart=`/`Environment=`, compose environment, terraform resource argument). If the rendered value lands in a world-readable file or repo history, treat as Critical (rotation → TOK module). Grep rendered artifacts, not just templates.
2. **Authz taint** — public hostname/path in ingress tables → sensitive route in the app's router (admin, debug, actuator, metrics). If the pair exists AND interview cannot confirm an Access policy, flag "edge-fronted admin path with zero Access/WAF front" (High anchor) even though the dashboard itself was not inspected.
3. **TLS-trust taint** — boolean/env driving `noTLSVerify` (e.g., a "skip_tls" convenience variable) → rendered `originRequest`. Defaults-on-insecure booleans propagate silently through templating; trace every consumer.
4. **Trust-topology taint** — deployment facts (app behind cloudflared/nginx) vs code facts (trusted-proxy allowlists, forwarded-header parsing). Mismatch in either direction = spoofable client IP (over-trust) or broken functionality (under-trust). Cross-check PROTO/AUTHZ modules for request-forgery-style header handling.
5. **Bind-address taint** — framework defaults (`app.run(host="0.0.0.0")`, `HOST=0.0.0.0` in Dockerfile ENV, compose `ports:` publish) → runtime reality in `ss -tlnp`. Repo intent does not bind sockets; effective state wins.

## Exploitation & Reproduction

All demonstrations are READ-ONLY on the audited host. External probing requires prior written authorization.

### Demo 1 — prove token-in-plainfile (interpretation discipline)

Run the sweep's redacted greps. Interpreting output WITHOUT ever reproducing the secret:

```text
/etc/systemd/system/cloudflared.service:5:ExecStart=/usr/bin/cloudflared tunnel run --token [REDACTED_TOKEN]
```

One line is enough for the finding. Narrative: the unit file is typically mode `644` (world-readable) because systemd requires units to be readable; therefore ANY local account (or anyone who later obtains arbitrary file-read via an app bug) reads the line, extracts the token, and runs `cloudflared tunnel run --token <value>` FROM THEIR OWN MACHINE — the tunnel now connects to their infrastructure too, with ingress rules they author, relaying into your origin network. The same applies to `Environment=` lines and process environments visible via `/proc/<pid>/environ` to same-UID readers. Severity anchor: Critical (see Severity Assessment). Remediation pointer: move to credentials-file mode with restrictive perms or secret-managed injection, rotate the exposed token (procedure → TOK module).

### Demo 2 — prove origin double-binding bypass

From the sweep's listener table, interpret a finding shape:

```text
State  Recv-Q Send-Q Local Address:Port  Process
LISTEN 0      128    127.0.0.1:49159     users:(("cloudflared",pid=1234,...))   # metrics on loopback: healthy
LISTEN 0      511    0.0.0.0:8000        users:(("gunicorn",pid=910,...))       # FINDING: app ALSO publicly bound
```

The app behind the tunnel binds `0.0.0.0:8000` while cloudflared forwards to it on loopback — the tunnel adds zero access restriction; it is now merely a second door. With authorization, confirm reachability from an EXTERNAL vantage: `curl -sS -o /dev/null -w '%{http_code}\n' --connect-timeout 5 http://<origin-ip>:8000/` returning `200` proves direct access that skips WAF/rate-limits/Access entirely. In-host proof without external access: firewall policy ACCEPT/default-deny analysis plus the wildcard bind suffices for the High finding.

### Demo 3 — prove the noTLSVerify hop

Finding shape in config:

```yaml
ingress:
  - hostname: legacy.internal.example.com
    originRequest:
      noTLSVerify: true          # FINDING
    service: https://10.20.0.11:8443
```

Narrative: cloudflared opens TLS to `10.20.0.11:8443` but skips certificate validation, so any actor positioned on that hop (compromised router/VM on the segment, ARP spoofing neighbor, rogue DHCP) terminates TLS with a self-signed cert, receives decrypted application traffic (cookies, bearer headers), and relays tampered responses. On-loopback plaintext HTTP would honestly declare its threat model better than encrypted-but-unverified TLS to a LAN IP. Check whether `caPool`/`originServerName` exist as ready-made fixes.

### Attacker narrative — why firewall discipline survives tunnels

1. **Origin discovery**: attacker wants the origin IP of `app.example.com` behind Cloudflare. Historical DNS records (passive-DNS services archive pre-Cloudflare A records), certificate-transparency logs naming `direct.app.example.com`, subdomain misconfigurations that CNAME to raw IPs, shodan/censys fingerprints of the origin's banner, or phishing/mail-server headers leaking internal IPs.
2. **Direct connect**: origin IP in hand, they browse `http://<origin-ip>/` (Host header set to the vhost). Every Cloudflare-side control — WAF managed rulesets, rate limiting, bot fight, Zero Trust Access, IP reputation — NEVER SEES THIS TRAFFIC. Only the host firewall stands between them and the app.
3. **Failure modes that enable step 2**: admin opened 80/443 "so Cloudflare can reach us"; app dual-bound `0.0.0.0`; IPv6 interface forgotten (parity gap); container DNAT publishing ports.
4. **Why the mitigations hold**: inbound firewall allowing ONLY Cloudflare IP ranges means discovered-origin-IP connections die at SYN; truly loopback-only bindings mean nothing answers regardless; Authenticated Origin Pulls (interview item) makes the origin reject non-Cloudflare-mTLS clients as defense-in-depth. The tunnel replaces port exposure ONLY if these hold.

### Dashboard-config interview checklist (record verbatim answers)

Ask, per production hostname: (1) Which managed WAF ruleset is attached? (2) Rate-limiting rules on which exact routes, with what thresholds? (3) Bot Fight Mode state? (4) Access applications covering which paths, which policies, what identity providers? (5) Service Token usage on which machine-to-machine routes vs email OTP one-time-pin on human routes? (6) Authenticated Origin Pulls enabled? (7) Any cache/Page-Rule behavior affecting security headers on cached responses (deep dive → TLS module)? Mark each Confirmed/Unconfirmed/N-A; Unconfirmed edge controls are REPORT GAPS, not assumed-present.

## Remediation

Apply in order: identity material → sandboxing → ingress precision → binding/firewall → edge layers → visitor IP. All commands below are MUTATING; require change approval and an agreed rollback.

### 1. Identity material

```bash
# [ROOT] dedicated user + restrictive material permissions (config-file mode shape)
useradd --system --home /nonexistent --shell /usr/sbin/nologin cloudflared 2>/dev/null || true
chown -R root:root /etc/cloudflared
chmod 755 /etc/cloudflared                      # traverse-only
chmod 600 /etc/cloudflared/*.json /etc/cloudflared/cert.pem
chgrp cloudflared /etc/cloudflared/<TUNNEL-UUID>.json   # only the file(s) this daemon needs
chmod 640 /etc/cloudflared/<TUNNEL-UUID>.json
```

If a token was ever exposed in a unit/repo/log: ROTATE it before cleanup (issuing new credentials, redeploying, revoking old — procedure → TOK/api-token-security). Deleting the line is not rotation. Prefer token mode with the token injected from a secret manager at runtime over literals in units; prefer NOT shipping account-level `cert.pem` to app hosts at all (keep it on the admin workstation that runs `cloudflared tunnel login`).

### 2. Hardened systemd drop-in

```ini
# /etc/systemd/system/cloudflared.service.d/hardening.conf
# [ROOT] systemctl daemon-reload after writing. Test in a maintenance window.
[Service]
User=cloudflared
Group=cloudflared
NoNewPrivileges=true
ProtectSystem=strict            # entire FS read-only; reading /etc/cloudflared still works
ProtectHome=true                # hides /root and /home incl. stray ~/.cloudflared material
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=          # no capabilities needed for outbound-only relay
AmbientCapabilities=
# CAVEAT: ProtectSystem=strict assumes config-file mode with READ-only needs.
# Run `cloudflared tunnel login`, credential creation, and manual updates interactively
# as an admin OUTSIDE this service context — the sandboxed daemon must never need write access.
```

Egress shaping CONCEPT (`IPAddressAllow=` on the unit can confine the daemon to Cloudflare ranges plus localhost for its metrics listener plus your resolvers): treat it as a follow-up hardening step requiring staged testing — an incomplete allowlist silently breaks tunnel registration or metrics, so validate against your cloudflared version's documented destination set during a maintenance window before enforcing (cross-ref FW egress module for the firewall-side equivalent).

### 3. Hardened ingress

Adopt the FIXED ingress shape from Patterns & Signatures: explicit hostname mappings first, loopback origins only, verified TLS with `caPool`/`originServerName` on any non-loopback hop, path rules reviewed against the app router, terminal `- service: http_status:404` ALWAYS last. Validate with `cloudflared tunnel ingress validate` (config-mode; dry-run check) and `cloudflared tunnel ingress rule --hostname <host> --path <path>` style lookup subcommands where available in your installed version — consult `cloudflared tunnel ingress --help` on the host rather than assuming flags.

### 4. Binding + firewall discipline

```bash
# App side: bind loopback (examples — adapt per framework)
# gunicorn:  --bind 127.0.0.1:8000      uvicorn: --host 127.0.0.1 --port 8000
# nginx origin vhost: listen 127.0.0.1:8080;
# docker: publish nothing, or -p 127.0.0.1:PORT:PORT at most
ss -tlnp | grep <origin-port>     # verify 127.0.0.1 binding took effect
```

Firewall: KEEP default-deny inbound. Decide and implement ONE anti-bypass design: (a) inbound allowlist restricted to published Cloudflare IP ranges (fetch current ranges from Cloudflare's published lists at remediation time; schedule re-review — ranges change), or (b) origin unlisted + default-deny with documented acceptance of residual discovery risk. Record the choice in the asset register (construction details → FW/firewall-edge module).

### 5. Dashboard hardening checklist (interview-format — execute IN the console with the owner)

1. Attach the zone-appropriate WAF managed ruleset; document exceptions.
2. Create rate-limiting rules on auth/login/sensitive routes (thresholds documented).
3. Enable Bot Fight Mode (or document the business reason not to).
4. Create Access applications covering `/admin*` (minimum) or the whole hostname; define policies with a real IdP — avoid email OTP one-time-pin for anything sensitive; use Service Tokens for machine-to-machine routes.
5. Enable Authenticated Origin Pulls for sensitive hostnames; deploy the client-cert check at the origin proxy accordingly.
6. Review cache rules/Page Rules for security-header behavior on cached responses (deep dive → TLS module).
7. Re-run this checklist quarterly; answers are point-in-time evidence.

### 6. Real visitor IP trust

```nginx
# nginx behind Cloudflare/cloudflared — trust ONLY CF ranges + local hops
set_real_ip_from 173.245.48.0/20;    # NOTE: fetch CURRENT published Cloudflare ranges at deploy time
set_real_ip_from 103.21.244.0/22;    # these four lines are ILLUSTRATIVE subset, not authoritative
set_real_ip_from 127.0.0.1;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
```

```bash
# uvicorn behind cloudflared/nginx on same host
ExecStart=/opt/app/venv/bin/uvicorn app:app --host 127.0.0.1 --proxy-headers
Environment=FORWARDED_ALLOW_IPS=127.0.0.1     # ONLY the literal proxy hop(s)
```

Express (qualitative semantics): `app.set('trust proxy', N)` trusts the outermost N hops of the chain; set it to exactly the number of trusted internal proxies (e.g., `1` for a single local nginx), NEVER `true` (trusts all) and never a broad CIDR including clients. Framework equivalents: Django `SECURE_PROXY_SSL_HEADER` only with matching proxy contract; Rails/Rack `ActionDispatch::RemoteIp` custom allowlists limited to proxy ranges. Cross-check detailed header-parsing risks → PROTO/http-protocol and AUTHZ/authz-access-control modules.

## Verification & Validation

Post-fix verification sequence:

1. **Re-run the full sweep** — every identity-material `stat` returns the intended mode/owner; redacted unit greps find no secret lines; ingress table ends with `http_status:404`; no `noTLSVerify: true` remains; metrics bound loopback.
2. **Restart gate** — restarting the cloudflared unit drops the tunnel (brief outage; with a single replica it is total). Obtain EXPLICIT approval naming the window before any restart. With ≥2 connectors, rolling restart one at a time.
3. **Through-path functional test** — after approved restart: public URL loads through the tunnel from an external vantage; HTTP status, TLS cert, and expected headers correct; `journalctl -u cloudflared -n 50` shows clean registration.
4. **Anti-bypass negative test (authorized external vantage)** — `curl --connect-timeout 5 http://<ORIGIN-IP>/` (and HTTPS, and IPv6 address if present) MUST time out or refuse. A 200 here means the High finding persists. Also confirm from the origin host that the firewall counters for dropped direct traffic increment when tested.
5. **Negative tests for regressions** — legitimate traffic unaffected: normal browsing, API clients, AND websocket/streaming endpoints exercised through the tunnel (proxy upgrades are part of the through-path); authenticated admin flows still work post-Access-policy changes; machine-to-machine clients holding Service Tokens authenticate successfully.
6. **Egress regression watch** — if egress restrictions were added (firewall or unit-level): monitor journal across several hours/days for connection errors indicating blocked transports. cloudflared negotiates its transport (QUIC preferred) and falls back (e.g., an explicit `--protocol http2` setting forces the TCP transport); an over-restrictive OUTPUT path can break the primary transport while leaving fallback flapping — qualitative symptom: intermittent "connection lost/registering" cycles. Confirm both transport paths reach their destinations before closing the ticket.
7. **Config-as-code regression greps** — in the repo: `grep -rn 'cloudflare_.*tunnel' *.tf` then review rendered resources against your PINNED provider version's docs (resource names changed across provider majors — validate, don't assume); ensure no secret argument holds a literal; ensure ingress-as-code ends with the 404 rule; CI should fail on `noTLSVerify:\s*true` and wildcard catch-alls.

## Severity Assessment

Anchors (vectors are starting points — adjust scope/impact to the audited environment):

| Severity | Finding | CVSS v3.1 vector |
|---|---|---|
| Critical | Tunnel token or credentials JSON world-readable, embedded in unit `ExecStart=`/`Environment=`, or committed to a repo — attacker gains their own ingress into the origin network | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (repo case); `AV:L` variant for host-local exposure |
| Critical | Account-level `cert.pem` exposed on an app host — grants tunnel/DNS management authority beyond one tunnel | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| High | Origin app dual-bound publicly / firewall opened "for Cloudflare" — direct-IP access bypasses ALL edge protections | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| High | Ingress wildcard-to-app catch-all or admin paths tunneled with zero Access/WAF front (interview-unconfirmed) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| High | `noTLSVerify: true` on any hop leaving the host — MITM position yields decrypted traffic and tampering | `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| Medium | Metrics endpoint bound non-loopback; LAN-IP origin targets creating lateral-pivot surface once host is compromised | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| Medium | No edge rate limiting on auth routes (interview-confirmed absence) — unthrottled credential stuffing | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| Low | Debug logging echoing sensitive headers into journald; unpinned daemon versions with no update cadence; single-replica tunnel availability risk | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |

Compounding rule: this module's findings MULTIPLY code-audit findings rather than adding. A tunnel fronting an app with an authz bug and no Access policy is ONE layer between the internet and the bug; a Critical token leak plus a dual-bound app means two independent full compromises of different character. When scoring, evaluate the shortest complete attack path, not individual findings in isolation.

## Common False Positives

- **WARP client vs Cloudflare Tunnel confusion**: a host running the WARP device client (`warp-svc`) is NOT running cloudflared tunneling — different product, different threat model (device egress vs inbound relay). Verify by unit/process name before applying this module; do not flag WARP hosts for missing ingress files.
- **Internal-only hostnames intentionally without Access**: a hostname routed over the tunnel but consumed only from networks that are themselves restricted (VPN-gated, zero-trust-device-only) may legitimately skip per-hostname Access policies IF the network restriction is confirmed and documented. Record as accepted-risk with evidence, not as a High finding.
- **Test/staging tunnels with relaxed posture**: lower environments often intentionally run simplified configs (no Access, broad catch-alls) against non-production data. If documented, scope findings down and reference the acceptance record; undocumented relaxed staging sharing credentials or networks with production is NOT exempt.
- **Metrics port absent entirely**: some deployments disable or never enable metrics listening; "port 20241 not found" is only a finding if the daemon IS running and bound elsewhere — check the actual listener list, not the expected port number alone.
- **Token-mode units showing base64-looking strings that are NOT tokens** (e.g., checksums, IDs): apply the redaction filter first, confirm the line shape matches `--token <value>` before raising the Critical anchor.

## References

- Cloudflare docs — Cloudflare Tunnel / cloudflared (connections, config-file ingress rules, run modes, firewall/egress guidance): developers.cloudflare.com
- Cloudflare docs — Zero Trust / Cloudflare Access (policies, Service Tokens, self-hosted apps): developers.cloudflare.com
- Cloudflare docs — WAF managed rulesets, rate limiting rules, bot management, Authenticated Origin Pulls, IP ranges: developers.cloudflare.com
- CWE-16 Configuration: https://cwe.mitre.org/data/definitions/16.html
- CWE-284 Improper Access Control: https://cwe.mitre.org/data/definitions/284.html

