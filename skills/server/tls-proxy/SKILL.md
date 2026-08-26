---
name: aegis-tls-proxy
description: Hardening-audit module for reverse-proxy edges and TLS termination (nginx primary; Caddy, HAProxy, Apache secondary) covering inventory, protocol/cipher posture, HSTS and edge headers, request limits, admin-path shielding, proxy-to-app hop trust, and ACME renewal hygiene.
category_slug: TLS
cwe: [CWE-16, CWE-319]
owasp: A02:2021 – Cryptographic Failures
---

## Scope & Objectives

Audit, read-only, the TLS-terminating reverse-proxy layer of a Linux host or its config-as-code repository. Determine:

1. Which process owns ports 80/443 and whether it leaks version information.
2. The full virtual-host map and what answers unrecognized Host headers.
3. TLS protocol floor, cipher/curve selection, session handling, OCSP stapling, chain completeness, SAN coverage, and certificate-expiry automation.
4. Edge response headers (HSTS and companions) and the nginx `add_header` inheritance trap.
5. Request-size and timeout limits at the edge versus what the application actually accepts.
6. Admin-path shielding (`/admin`, `/actuator`, `/metrics`) via CIDR allowlists, basic auth, mTLS, or a separate management vhost.
7. The proxy-to-application hop: transport security and forwarded-header (`X-Forwarded-For`, `Host`) trust correctness.
8. ACME/certbot operational hygiene: renewal timers, deploy hooks, rate-limit and challenge-path pitfalls.

Secondary coverage: Caddy automatic-HTTPS model, HAProxy bind-line TLS defaults, Apache `SSLProtocol`/`SSLCipherSuite` equivalents, and mod_security as a WAF option.

Out of scope (sibling modules): volumetric denial-of-service defense and rate-limit tuning depth (DOS module), application authorization logic (AUTHZ module), HTTP protocol abuse such as host-header poisoning payloads (code-audit http-protocol module). Every command in What To Check / Where To Look / Exploitation is non-mutating inspection; mutating steps appear only under Remediation and Verification.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **reverse proxy**: the front service that accepts visitor connections and forwards them to applications
- **TLS termination**: the point where encrypted traffic is decrypted (this proxy)
- **protocol/cipher floor**: the oldest encryption version and strength still accepted; legacy settings allow downgrade pressure
- **HSTS**: a response header telling browsers to use HTTPS only for the domain from now on
- **default_server / catch-all**: which site answers requests with unknown hostnames; first-match surprises live here
- **add_header inheritance trap**: declaring one header inside a location erases all server-level headers for it
- **ACME / certbot**: automated certificate issuance and renewal, which needs its challenge path left reachable
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Two trust boundaries meet at the proxy:

- Client to edge: TLS termination, HSTS, header policy, size/time limits, path gating. The attacker controls everything on this boundary.
- Edge to application: usually plaintext HTTP. Acceptable only when it never leaves the machine (`127.0.0.1`, `::1`, unix sockets). Across any network segment it is cleartext transmission (CWE-319).

Structural rules that produce most findings here:

- First match wins, twice. nginx picks the FIRST matching `server` block when none declares `default_server`, so an unnamed catch-all silently routes unknown Host headers into whichever vhost loaded first. ngx_http_access_module evaluates `allow`/`deny` top-down and stops at the first match, so `deny all;` placed first makes every allow below it dead code.
- Inheritance resets once. nginx `add_header` directives inherit from the enclosing level ONLY when the current level declares none. A single `add_header` inside a location erases every server-level header for that location's responses. Assume reset semantics for directive arrays.
- The served chain is not the stored chain. Clients see exactly what the proxy sends during the handshake, not what sits in the certificate directory. Chain gaps surface as "unknown authority" errors in non-browser clients while browsers appear fine.
- Renewal is decoupled from configuration. certbot renews on its own timer; if hardening blocks the ACME challenge path or the reload hook is missing, nothing fails today and the certificate dies weeks later.

Hold this model while checking: nearly every finding below is one of these four rules violated.

## What To Check

### 1. Proxy inventory and ownership

Run `sudo ss -tlnp | grep -E '(:80|:443)\s'` and record the `users:(("name",pid=X,fd=Y))` owner of each listener, including `[::]:443` IPv6 sockets. Map every listener to its config file. Flag listeners bound to `0.0.0.0` that should be interface-scoped.

### 2. Version disclosure (minor)

Run `curl -sI https://HOST/ | grep -iE '^(server|x-powered-by|x-aspnet)'`. `Server: nginx/1.24.0` leaks the version — a minor finding; nginx remediation is `server_tokens off;`, which still leaves bare `Server: nginx` (product visible, version hidden). Full suppression requires the third-party headers-more module — do not claim otherwise in findings. Passthrough banners like `X-Powered-By` indicate missing `proxy_hide_header`.

### 3. Virtual-host map extraction

With root on the box: run `sudo nginx -T 2>&1 | less`. This dumps the effective config including all includes. Caveats: needs root (reads key paths and included files); reflects on-disk state, not pending-reload runtime state (compare config mtimes against `systemctl status nginx` timestamps); containerized deployments may place binary/config differently. Config-as-code alternative: reconstruct the map by hand with `grep -RInE '^\s*(server_name|listen|include)' /repo/path`. For Caddy read `/etc/caddy/Caddyfile`; for HAProxy grep `bind`/`acl host`/`use_backend`; for Apache `grep -RIn '<VirtualHost\|ServerName' /etc/apache2/sites-enabled/`.

### 4. Default vhost catch-all behavior

Identify the implicit default: `sudo nginx -T | grep -n 'default_server'` plus which 443 `server` block appears first without it. Probe read-only from outside: `curl -sk -o /dev/null -w '%{http_code}\n' --resolve probe.invalid:443:TARGET_IP https://probe.invalid/`. A 200/301/302 means unrecognized Host headers reach an application — host-header attack surface (cross-ref code-audit http-protocol module). Expect connection close (`return 444;`) or an explicit catch-all stub instead.

### 5. TLS protocol floor, ciphers, curves, session settings

Inspect effective values: `sudo nginx -T | grep -nE 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_session_tickets|ssl_prefer_server_ciphers'`. Require exactly `ssl_protocols TLSv1.2 TLSv1.3;`. Presence of `TLSv1`, `TLSv1.1`, or `SSLv3` is a finding (High when auth-bearing endpoints are served). Absent `ssl_protocols` means library-dependent defaults — older OpenSSL builds enable TLSv1.0 — so treat as unverified until probed live (Exploitation R6). For ciphers do not hand-roll strings: require output from the Mozilla SSL Configuration Generator intermediate profile for the deployed nginx/OpenSSL pair; one known-good baseline string is given under Remediation F1. Curves: expect `ssl_ecdh_curve X25519:prime256v1:secp384r1;`. Sessions: `ssl_session_tickets off;` trades resumption performance for forward secrecy of resumed sessions — record the choice either way.

### 6. Certificate chain, SAN coverage, stapling, expiry automation

Verify with the commands catalogued in Exploitation R7/R8: served chain length ≥2 (leaf + intermediate), SAN covers every served `server_name`, stapling status via `-status`, expiry distance >30 days or an active timer. Check automation: `systemctl list-timers --all | grep -iE 'certbot|acme|dehydrated'` and, where installed, `sudo certbot certificates`. Honesty note: several major CAs (including Let's Encrypt) retired their OCSP responders in favor of CRLs starting 2025 — missing stapling is Low/informational where the CA no longer offers OCSP at all.

### 7. HSTS and edge headers

Run `curl -sI https://HOST/ | grep -i strict-transport-security`. Floor: `max-age=15552000` (180 days). Add `includeSubDomains` only after verifying EVERY subdomain serves valid HTTPS — it is effectively a commitment. Preload discussion lives in Remediation/V4. Count occurrences: more than one HSTS header = edge+app double-set conflict; pick ONE layer (edge recommended for uniformity) and disable the other. Companion set at edge: `X-Content-Type-Options nosniff`, `X-Frame-Options DENY` (or CSP `frame-ancestors`), `Referrer-Policy`. Audit the add_header inheritance trap (Mental Model): every location that declares any `add_header` must repeat ALL server-level headers — test affected paths individually with `curl -sI`.

### 8. Request limits and timeouts

Compare configured values against real traffic needs:

- `client_max_body_size` (nginx default 1m) must match the app's largest legitimate payload class: small JSON APIs 1–10m; upload endpoints get an explicit larger value ONLY on their own location, never server-wide.
- A proxy with NO cap placed in front of an app endpoint accepting unbounded uploads is a Medium DoS finding.
- Tighten timeouts toward `client_body_timeout 10s; client_header_timeout 10s; keepalive_timeout 15s; send_timeout 10s;` (defaults are 60s/75s) to shrink slowloris-style resource holding — summary here, full treatment in the DOS module.
- Header buffers: `client_header_buffer_size` (default 1k) and `large_client_header_buffers` (default `4 8k`) reject absurd headers with 400/414; lowering to `2 8k` trims worst-case per-connection memory.
- proxy_read_timeout honesty: never set below genuine p99 endpoint latency (reports, exports, streams). Measure the slowest real endpoint first, then add headroom — otherwise you trade a DoS risk for broken functionality (truncated responses, spurious 504s).

### 9. Admin-path shielding

Enumerate sensitive paths from configs and app docs: `/admin`, `/actuator`, `/metrics`, `/debug`, `/phpmyadmin`, `/wp-login`. From an external vantage: `for p in admin actuator metrics debug; do printf '%s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://HOST/$p/"; done`. A 200/302 from the internet is an ungated finding. Required end state per path: 403 (CIDR deny), 401 (basic auth), or mTLS rejection. Wherever allow/deny exists, verify ORDER: allow lines must precede `deny all;`. Treat any `optional_no_ca` as decorative unless paired with `$ssl_client_verify` enforcement (Remediation F3).

### 10. Proxy-to-app hop

From config truth: `sudo nginx -T | grep -nE 'proxy_pass|grpc_pass|uwsgi_pass'`. Loopback targets (`127.0.0.1`, `::1`, unix:) justify plaintext. RFC1918 or routeable targets over plaintext are a CWE-319 finding — fix with upstream TLS, mTLS, or a WireGuard mesh. Confirm forwarded headers exist: `proxy_set_header Host ...`, `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (or a deliberate rewrite — see Taint Tracing), `proxy_set_header X-Forwarded-Proto $scheme;`. Understand Host semantics: `Host $host` forwards the client-supplied value inward (safe ONLY once unknown hosts are rejected at the edge, check 4); `$proxy_host` sends the upstream identity instead, isolating the app but breaking virtual-host-aware routing. Hide backend banners with `proxy_hide_header X-Powered-By;` / `proxy_hide_header Server;`.

### 11. Secondary proxies

- Caddy: confirm a global `email` option exists (expiry notices); find any `tls internal` usage (private CA — ask where its roots live and who trusts them); header customization uses the `header { ... }` block shape.
- HAProxy: inspect every `bind ... ssl crt ...` line; require global `ssl-default-bind-options ssl-min-ver TLSv1.2` (HAProxy ≥ 2.2); the crt PEM must contain leaf + intermediates concatenated.
- Apache: require `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`, an SSLCipherSuite copied verbatim from the Mozilla generator Apache profile, and `Header always set Strict-Transport-Security "..."`. Note mod_security (`SecRuleEngine On`) as the available WAF layer.

### 12. ACME/certbot hygiene

Check `systemctl list-timers --all | grep -i certbot` shows an active timer; `sudo certbot certificates` for expiry sanity; deploy hooks present AND executable: `ls -la /etc/letsencrypt/renewal-hooks/deploy/` containing an nginx reload script (Remediation F2); functional proof with `certbot renew --dry-run` (hits LE staging only). Sweep hardening rules for anything blocking `/.well-known/acme-challenge/`: auth gates, deny rules, or location-level redirects that shadow the challenge path break renewal silently near expiry. Rate-limit awareness: production LE quotas are weekly (duplicate-cert and domain caps); pipelines must use `--staging`.

## Where To Look

Evidence collection: `tools/sweeps/sweep-tls-proxy.sh` captures `[TLS-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

Filesystem (host):

- `/etc/nginx/nginx.conf` — main file. Debian splits into `/etc/nginx/conf.d/*.conf` plus `/etc/nginx/sites-available/*` symlinked from `/etc/nginx/sites-enabled/*`; upstream/RHEL layouts keep one file or conf.d only.
- Effective truth: `sudo nginx -T` (disk state; reload-pending caveat).
- Certificates: `/etc/letsencrypt/live/<name>/fullchain.pem` and `privkey.pem`; archived copies under `../archive/`; renewal parameters `/etc/letsencrypt/renewal/<name>.conf`; hooks `/etc/letsencrypt/renewal-hooks/{deploy,renewal}/`.
- Caddy: `/etc/caddy/Caddyfile`; admin API defaults to localhost:2019 — confirm it is not remotely exposed.
- HAProxy: `/etc/haproxy/haproxy.cfg`; certificate bundles live at paths named by each `crt` argument.
- Apache: Debian `/etc/apache2/{sites-enabled,mods-enabled,ports.conf}`; RHEL `/etc/httpd/{conf,conf.d}/`.
- Timers/services: `systemctl list-timers --all`, `systemctl status nginx caddy haproxy apache2 httpd` as applicable.
- Package versions: `dpkg -l | grep -E 'nginx|caddy|haproxy|apache2'` or `rpm -qa | grep -E 'nginx|caddy|haproxy|httpd'`.
- Live sockets/processes: `ss -tlnp`, `ps aux | grep -E '[n]ginx|[c]addy|[h]aproxy|[h]ttpd|[a]pache'`.
- Access logs (read-only peeks): `/var/log/nginx/access.log` entries with foreign Host values confirm catch-all routing.

Remote probes (no credentials needed): the `openssl s_client` and `curl` invocations catalogued in Exploitation & Reproduction.

Repository sweeps (config-as-code):

- `grep -RInE 'ssl_protocols|ssl_ciphers|client_max_body_size|Strict-Transport-Security|set_real_ip_from|optional_no_ca|proxy_pass|reverse_proxy|bind .*ssl' .`
- Vhost map reconstruction: `grep -RInE 'server_name|ServerName|<VirtualHost|listen ' .`

## Patterns & Signatures

Finding signatures (nginx directives):

- `ssl_protocols` listing `TLSv1`, `TLSv1.1`, or `SSLv3` → legacy protocol exposure.
- No `ssl_protocols` anywhere → library-default floor, unverified; probe live before scoring.
- `ssl_ciphers` containing RC4, 3DES, CBC-only suites, or vague aliases (`HIGH`, `MEDIUM`) → regenerate from the Mozilla generator.
- `allow 0.0.0.0/0;` preceding or replacing `deny all;` → no-op gate.
- `deny all;` appearing BEFORE allow lines → allowlist dead code (availability bug: everyone blocked).
- `ssl_verify_client optional_no_ca;` without `$ssl_client_verify` enforcement → identity theater, not access control.
- `set_real_ip_from 0.0.0.0/0;` or trusted ranges covering the public internet → client-IP forgery.
- `proxy_set_header Host $host;` on an edge that fails check 4 → client-controlled Host taint passes inward; `Host $proxy_host` on vhost-aware apps → silent route breakage.
- Missing `proxy_set_header X-Forwarded-Proto $scheme;` behind an HTTPS edge → apps generate http:// URLs or redirect-loop (regression signature).
- Any `add_header` inside a location whose siblings are absent → server-level headers vanish on that path (verify per-path with `curl -sI`).
- Two `Strict-Transport-Security` headers in one response → double-set conflict.

Compliant signatures:

- `ssl_protocols TLSv1.2 TLSv1.3;` + generator intermediate cipher string + `ssl_session_tickets off;`.
- Catch-all: `server { listen 443 ssl default_server; ssl_reject_handshake on; }` (nginx ≥ 1.19.4) or `return 444;` stubs.
- Ordering inside gated locations: `allow <cidr>;` lines first, then `deny all;`, then `auth_basic`.
- Upstream targets of `http://127.0.0.1:<port>` or `unix:` sockets.
- Single-layer HSTS emitted with the `always` flag.

Response-shape signatures:

- `Server: nginx` vs `Server: nginx/x.y.z` (disclosure).
- 400/414 on oversized-header probes → buffer limits active.
- 413 on POST bodies above the cap → `client_max_body_size` active; no 413 on a huge upload while the app accepts it = finding pair.

Log signature: repeated access.log lines where the `$host` field matches no configured `server_name` → catch-all confirmed in production.

## Taint Tracing Guidance

Sources (client-controlled at the edge): Host header, request line / absolute-URI form, `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, cookies, original path with encodings.

XFF rule: every trusted proxy APPENDS what it saw as peer. Correct derivation walks the list right-to-left, skipping exactly the number of infrastructure proxies you operate, stopping at the first value you cannot attribute. Everything leftward is attacker-written text. Misconfiguration ranking:

1. App consumes the whole chain or leftmost entry → trivial spoofing (AUTHZ bypass, rate-limit evasion, log poisoning). Cross-ref AUTHZ module.
2. Edge runs `real_ip` with over-broad `set_real_ip_from` → the edge itself rewrites `$remote_addr` from forged input, poisoning `limit_conn`/`limit_req` keys and audit logs.
3. Correct shape: `set_real_ip_from` enumerates ONLY your CDN/LB ranges; `real_ip_header` names a header THEY control (e.g., `CF-Connecting-IP` behind Cloudflare); `real_ip_recursive on;` with exact trusted counts.

Host taint: with `proxy_set_header Host $host;`, whatever the client sent lands in app routing, URL generation, cache keys, and password-reset links. Gate at the edge FIRST (explicit `server_name` list plus a rejecting `default_server`), after which forwarded values are bounded to names you own. If the edge cannot reject unknown hosts, forward `$proxy_host` and have the app derive externally visible URLs from its own configured base URL.

Sink checklist downstream of edge decisions: session cookie scope attributes, redirect Location builders, webhook/callback validators, cache keys, and admin IP allowlists fed by XFF-derived addresses.

Trace procedure: pick one inbound request shape (e.g., POST /reset carrying forged XFF and an alien Host), walk the config top-down — which server matched, which location matched, which headers were forwarded, what the app plausibly derives — and record each boundary where taint crosses unchecked.

## Exploitation & Reproduction

All demonstrations are read-only network observation. Replace HOST with the audited name; run from outside any allowlisted CIDR unless stated otherwise.

R1. Listener ownership
`sudo ss -tlnp | grep -E '(:80|:443)\s'`
Read: `users:(("nginx",pid=X,fd=Y))` identifies the terminator; multiple 443 listeners on different addresses reveal split fronts worth mapping.

R2. Version disclosure
`curl -sI https://HOST/ | grep -iE '^(server|x-powered-by|x-aspnet)'`
Read: `Server: nginx/1.24.0` → disclosure (Low). Bare `Server: nginx` → tokens off. Passthrough `X-Powered-By` → backend banner leak.

R3. Configuration ground truth
Root: `sudo nginx -T 2>&1 | grep -nE 'ssl_protocols|ssl_ciphers|ssl_ecdh_curve|ssl_session_tickets|server_tokens|client_max_body_size|client_body_timeout|keepalive_timeout|large_client_header_buffers|allow |deny |ssl_verify_client|set_real_ip_from|proxy_pass|proxy_set_header|add_header'`
Caveats: requires root; shows disk state — a pending reload means runtime differs.
Repo alternative: `grep -RInE '^\s*(listen|server_name|ssl_|add_header|client_|allow|deny|proxy_|set_real_ip_from)' .`
Read: build a vhost x directive matrix from output; every blank cell means "unverified," not "safe."

R4. Catch-all behavior
`curl -sk -o /dev/null -w '%{http_code}\n' --resolve probe.invalid:443:TARGET_IP https://probe.invalid/`
Read: 200/301/302 → unknown Host reaches an app (cross-ref code-audit http-protocol module). 000 with curl exit 52 → connection closed (`return 444;` shape). Any app response body observed via plain `curl -sk https://probe.invalid/` is evidence of over-broad routing.

R5. Negotiated TLS baseline
`echo | openssl s_client -connect HOST:443 -servername HOST -status 2>/dev/null | grep -E '^(New|Cipher|Server Temp Key|OCSP)'`
Read fields:
- `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384` — negotiated protocol and cipher; TLSv1.2 floor acceptable, anything older escalates severity.
- `Server Temp Key: X25519, 253 bits` — curve in use.
- `OCSP response: no response sent` — stapling absent; `OCSP Response Status: successful (0x0)` — stapled.
The full dump also shows chain depth and `Verify return code: 0 (ok)` against your local trust store.

R6. Legacy-protocol forcing (proof attempt)
curl form: `curl -svo /dev/null --tlsv1.1 --tls-max 1.1 https://HOST/ ; echo exit=$?`
Hardened host: exit 35, message contains `alert protocol version` or `unsupported protocol`. Vulnerable host: exit 0 with an `SSL connection using TLSv1.1 / ...` line.
Client caveat: modern OpenSSL client builds refuse to OFFER TLS ≤1.1 (`no protocols available`) — that outcome is inconclusive about the SERVER; fall back to:
`echo | openssl s_client -connect HOST:443 -servername HOST -tls1_1 2>&1 | grep -E 'alert|Cipher is|Verify return'`
Hardened: `sslv3 alert handshake failure` or `tlsv1 alert protocol version`. Vulnerable: a negotiated TLSv1.1 cipher plus certificate chain. Repeat with `-tls1` for TLSv1.0.

R7. Chain completeness
`echo | openssl s_client -connect HOST:443 -servername HOST -showcerts 2>/dev/null | grep -c 'BEGIN CERTIFICATE'`
Local cross-check: `grep -c 'BEGIN CERTIFICATE' /etc/letsencrypt/live/<name>/fullchain.pem`
Read: complete chains serve 2 (leaf + intermediate) or occasionally 3 (cross-signed root). Serving exactly 1 while the stored file holds ≥2 → incomplete chain in transit. Symptom: browsers succeed (cached or AIA-fetched intermediates) while curl/wget/Java/Go/mobile clients fail with `unable to get local issuer certificate` / `certificate signed by unknown authority` — the classic "works for me" incident.

R8. SAN coverage and expiry distance
SAN: `echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -ext subjectAltName`
Expiry: `end=$(echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2); echo "days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))"`
Read: every served server_name must appear in SAN; days <30 → automation suspect (check R12).

R9. HSTS and header set
`curl -sI https://HOST/ | grep -ic strict-transport-security` then `curl -sI https://HOST/`
Read: count >1 → double-set conflict. Value below max-age 15552000 → weak. Missing entirely on a public HTTPS app → Medium anchor. Confirm companions (nosniff, frame policy, referrer-policy) appear once each.

R10. Admin-path reachability (external vantage)
`for p in admin actuator metrics debug; do printf '%s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://HOST/$p/"; done`
Read: 200/302 → ungated from internet (finding; capture representative bodies separately with `curl -s`, e.g., `/actuator/health`). 401 → auth gate present. 403 → deny/CIDR gate present.

R11. Hop transport (config-derived)
Source: proxy_pass lines from R3.
Read: `http://127.0.0.1:*` / unix sockets acceptable; `http://<RFC1918-or-public-ip>:*` plaintext across a network segment = CWE-319 anchor (score with the AV:A vector under Severity Assessment).

R12. Renewal machinery
`systemctl list-timers --all | grep -iE 'certbot|acme'` ; `ls -la /etc/letsencrypt/renewal-hooks/deploy/ 2>/dev/null` ; `sudo certbot certificates 2>/dev/null | grep -E 'Certificate Name|Expiry'`
Read: cert present but timer absent = manual renewal regime. Empty deploy dir + nginx = renewed certs sit unused until someone reloads by hand (silent future outage). Expiry column <30d corroborates R8.

## Remediation

Apply per finding; validate with `nginx -t && systemctl reload nginx`. Reload, never restart, for config/cert changes — restart drops live connections and is reserved for binary upgrades. Snippets labeled # FIXED.

### F1. Complete hardened nginx edge (# FIXED)

```nginx
# FIXED - /etc/nginx/sites-available/example.com

# Unknown-host catch-alls: keep ACME alive, close everything else
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 444; }
}
server {
    listen 443 ssl default_server;      # nginx >= 1.19.4
    ssl_reject_handshake on;            # refuses unknown-SNI handshakes; needs no cert
}

# Named vhost: HTTP -> HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;                           # nginx >= 1.25.1; older builds: append "http2" to listen
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    # Mozilla SSL Configuration Generator, INTERMEDIATE profile baseline.
    # Regenerate for your exact nginx/OpenSSL pair instead of editing blind:
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # add_header GOTCHA: these apply only because THIS level declares them.
    # Any location below adding its own add_header must REPEAT every line here.
    add_header Strict-Transport-Security "max-age=300" always;   # stage upward, see V4
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 10m;           # right-size to the app; tighter caps per location
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    send_timeout 10s;
    large_client_header_buffers 2 8k;
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;                    # safe BECAUSE catch-alls reject aliens (F1 block above)
        proxy_set_header X-Forwarded-For $remote_addr;  # edge is sole proxy: rewrite, don't extend
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;                         # raise only to measured p99 + headroom
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
```

Debian enablement: `ln -s ../sites-available/example.com /etc/nginx/sites-enabled/ && nginx -t && systemctl reload nginx`.

### F2. certbot renewal deploy hook (# FIXED)

```bash
# FIXED - /etc/letsencrypt/renewal-hooks/deploy/10-reload-nginx.sh
#!/bin/sh
set -eu
/usr/sbin/nginx -t
/bin/systemctl reload nginx
logger -t certbot-hook "reloaded nginx for ${RENEWED_LINEAGE:-unknown}"
```

Install executable: `install -m 0755 <src> /etc/letsencrypt/renewal-hooks/deploy/10-reload-nginx.sh`.
Reload-vs-restart: reload performs graceful worker rotation with zero dropped connections and fully suffices for replaced certs/keys — the normal renewal case. Restart is justified only when listen sockets, binaries, or module sets change. Prove the loop with `certbot renew --dry-run` (LE staging; no production quota consumed).

### F3. Admin-path shielding patterns (# FIXED)

CIDR allowlist + basic auth layer (ORDER matters):

```nginx
# FIXED
location ^~ /admin/ {
    allow 203.0.113.0/24;     # office/VPN egress
    allow 198.51.100.0/24;    # bastion subnet
    deny all;                 # MUST follow the allows: first match wins
    auth_basic "Administrators";
    auth_basic_user_file /etc/nginx/admin_htpasswd;
    proxy_pass http://127.0.0.1:8000;
}
location = /metrics {
    allow 127.0.0.1;
    deny all;
    proxy_pass http://127.0.0.1:8000;
}
```

htpasswd creation: `sudo htpasswd -cB /etc/nginx/admin_htpasswd alice` (apache2-utils; `-B` bcrypt is accepted by nginx on libxcrypt/glibc-crypt systems; drop `-B` for portable APR1: `sudo htpasswd -c /etc/nginx/admin_htpasswd alice`). Add further users WITHOUT `-c` (it truncates).

mTLS gate on a dedicated admin subdomain:

```nginx
# FIXED - admin.example.com server block
server {
    listen 443 ssl;
    server_name admin.example.com;
    ssl_certificate     /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;
    ssl_client_certificate /etc/nginx/client-ca.crt;   # YOUR issuing CA only
    ssl_verify_client on;
    ssl_verify_depth 2;
    # ... TLS/header/limit directives as in F1 ...
}
```

CAVEAT `ssl_verify_client optional_no_ca;`: requests a client cert and checks it parses and self-verifies, but ACCEPTS chains from ANY CA — fit only for logging/telemetry. Never ship it as a gate; if inherited from a template, flip to `on` or enforce manually: `if ($ssl_client_verify != SUCCESS) { return 403; }`.

Separate management plane alternative: bind the admin vhost to an internal address only (`listen 10.0.0.5:443 ssl;`) so it is unreachable from the internet even before firewalling.

### F4. Caddy key lines

```text
{
    email ops@example.com
}
example.com {
    tls ops@example.com
    header {
        Strict-Transport-Security "max-age=15552000"
        -Server
    }
    reverse_proxy 127.0.0.1:8000
}
```

Automatic HTTPS is mostly-safe-by-default (forced redirect, managed certs, sane protocol floor). Audit residuals anyway: account email deliverability, any `tls internal` issuers (locate and protect the private CA), presence of header customization.

### F5. HAProxy key lines

```text
global
    ssl-default-bind-options ssl-min-ver TLSv1.2
frontend https_in
    bind *:443 ssl alpn h2,http/1.1 crt /etc/haproxy/certs/example.com.pem
    default_backend app
```

The crt bundle must be leaf THEN intermediates concatenated with the private key (mirror of the fullchain layout checked in R7).

### F6. Apache key lines

```apache
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/example.com/privkey.pem
    SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder     off
    Header always set Strict-Transport-Security "max-age=300"
</VirtualHost>
```

Copy `SSLCipherSuite` verbatim from the Mozilla generator's Apache profile rather than composing it. Debian modules: `a2enmod ssl headers http2`. WAF option: `a2enmod security2` with `SecRuleEngine On` (mod_security) adds request filtering ahead of the app.

### F7. ACME challenge carve-out invariant (# FIXED)

Before any global deny/auth/redirect change, confirm the challenge path survives untouched:

```nginx
location /.well-known/acme-challenge/ { root /var/www/html; }   # stays PUBLIC
```

Blocking it fails nothing today — renewal breaks silently near expiry (Mental Model). Prefer dns-01 challenges, or route HTTP-01 through the dedicated catch-all shown in F1.

## Verification & Validation

V1. Protocol floor (after F1/F5/F6)
`echo | openssl s_client -connect HOST:443 -servername HOST -tls1_1 2>&1 | grep -i alert` → expect `handshake failure` / `protocol version` alert; repeat with `-tls1`. Then confirm the healthy modern path: `echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | grep '^New'` → `New, TLSv1.3, ...` (or TLSv1.2) with a strong cipher.

V2. Headers (after F1/F4/F6)
`curl -sI https://HOST/ | grep -i strict-transport-security` → exactly ONE header carrying the currently staged max-age. Duplication regression check: `curl -sI https://HOST/ | grep -ic strict-transport-security` must print 1; >1 means the app also sets it — remove at one layer (edge recommended).

V3. Negative/regression battery
- Site loads: `curl -sS -o /dev/null -w '%{http_code}\n' https://HOST/` → 200 (or the app's normal 30x chain ending in 200).
- Health from allowed CIDR: from a jump host INSIDE an allowlisted range: `ssh bastion 'curl -s -o /dev/null -w %{http_code} https://HOST/admin/'` → 200/401-with-valid-creds flow intact. A 403 from INSIDE the allowed range means your `deny all;` landed before the allows — the F3 ordering bug.
- Uploads still fit: `curl -sS -o /dev/null -w '%{http_code}\n' -F f=@legit-file.bin https://HOST/upload` → not 413; then `truncate -s 64M /tmp/opencode/big.bin` and repeat → 413 proves the cap.
- Unknown host still rejected: repeat R4 → still exit 52/000.

V4. External graders as spot-checks (public endpoints only): SSL Labs and `testssl.sh ./testssl.sh HOST:443` — aim for A/A+ with no protocol/cipher/chain warnings; retest after every TLS change. Third-party tooling, informational scoring: the config you audited remains the source of truth.
- Config clean: `nginx -t` → syntax ok, no unintended warnings (a deprecation note for old-vs-new http2 syntax is benign but record it).

V4. HSTS staged rollout (mandatory sequencing)
Committing a long max-age before HTTPS is proven stable is a self-inflicted lockout: browsers pin the policy for the full window, so any broken HTTPS deployment on a covered host/subdomain becomes unreachable for up to that duration. Stage: `max-age=300` (observe 24–48h, monitors clean) → `86400` → `604800` → `15552000`. Add `includeSubDomains` only AFTER enumerating every subdomain and proving valid HTTPS on each. Preload submission last — removal queues take months.

V5. Renewal loop (after F2)
`sudo certbot renew --dry-run` → success per lineage; hook fires (check `journalctl --since today | grep certbot-hook`); installed dates unchanged (dry run installs nothing).

V6. Repository regression greps (post-fix; hits must be explainable or gone)
- Legacy protocols: `grep -RInE 'TLSv1(\.[01])?[";[:space:]]' --include='*.conf' . | grep -viE 'TLSv1\.2|TLSv1\.3'`
- Decorative mTLS: `grep -RIn 'optional_no_ca' .`
- IP-forgery real_ip: `grep -RInE 'set_real_ip_from[[:space:]]+0\.0\.0\.0/0' .`
- Vhosts passing through without a body cap: `grep -RL 'client_max_body_size' $(grep -RIl 'proxy_pass' --include='*.conf' .)`
- allow/deny ordering eyeball near every gate: `grep -RIn -B3 'deny all;' --include='*.conf' .`

V7. Evidence retention: save R1–R12 outputs pre-fix and post-fix into the audit ticket; the diff is the proof of delta.

## Severity Assessment

Anchor findings to CVSS v3.1 vectors:

HIGH — TLSv1.0/1.1 enabled with weak suites (CBC/3DES/RC4) on authentication-bearing endpoints: enables downgrade-and-intercept classes against legacy clients. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N (7.4 High).

MEDIUM — Missing HSTS on a public HTTPS app: leaves an SSL-stripping window for network-adjacent attackers; requires user interaction to exploit. CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N (4.2 Medium).

MEDIUM — No effective body-size cap in front of an unbounded-upload app endpoint: cheap storage/memory exhaustion via large POSTs. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3 Medium).

MEDIUM — Plaintext proxy-to-app hop across a network segment (non-loopback RFC1918/public): adjacent actor sniffs credentials, tokens, session cookies in transit. CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (6.4 Medium).

LOW — Version disclosure (`Server: nginx/x.y.z`, `X-Powered-By`): weaponization aid only; requires a matching n-day. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N (3.6 Low).

LOW — Missing OCSP stapling: minor privacy signal during browsing; increasingly moot as CAs retire OCSP responders for CRLs. CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N (3.6 Low).

Modifiers: an admin path reachable AND unauthenticated from the internet raises the contained app's findings by a band (gate absence compounds everything behind it). Expired certs or broken chains with no automation score as availability incidents on top of confidentiality impact.

## Common False Positives

- CDN terminates TLS in front of origin (Cloudflare/Akamai/CloudFront/ALB): your s_client sees the EDGE cert/config, not the origin's. Attribute findings to the owning layer. Special case — Cloudflare "Flexible" SSL mode: visitor-to-edge is HTTPS but edge-to-origin is plaintext :80; if the origin answers port 80 with the app, that origin exposure is its own finding class (require Full/Full-strict mode plus origin refusal of :80). Detect by resolving the origin IP from DNS/infra docs and probing it directly outside CDN ranges.
- Cloud ALBs terminate TLS with provider-managed policy names: nginx-specific directives simply do not exist there; audit the LB security-policy name against provider documentation instead of failing the host for absent ssl_protocols.
- Internal-only proxies (mesh sidecars, intra-VPC ingress) with relaxed stapling/logging choices: apply the same protocol floor but weight severity down where blast radius is one trust zone; document the scope assumption rather than silently passing.
- Test/staging vhosts intentionally open (seed data, fake logins): confirm ownership in writing, attach a review/expiry date, exclude from scoring — never mark them "compliant."
- Site deliberately HTTP-only (no TLS anywhere): the missing-HSTS-on-HTTPS anchor does not apply; absence of TLS itself belongs to broader crypto posture (route accordingly).
- OCSP stapling "missing" when the issuing CA retired its responder (e.g., Let's Encrypt's 2025 wind-down): informational, not actionable.
- Presigned direct-to-object-storage uploads bypassing the proxy: absent `client_max_body_size` is irrelevant to that flow; the cap question moves to bucket policy (different module).

## References

- Mozilla SSL Configuration Generator — canonical protocol/cipher profiles per server and version: https://ssl-config.mozilla.org/ (mirror: https://mozilla.github.io/server-side-tls/ssl-config-generator/)
- nginx documentation: https://nginx.org/en/docs/
- RFC 6797 — HTTP Strict Transport Security (HSTS)
- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
- CWE-16: Configuration — https://cwe.mitre.org/data/definitions/16.html
- CWE-319: Cleartext Transmission of Sensitive Information — https://cwe.mitre.org/data/definitions/319.html
- OWASP Top 10:2021 A02 – Cryptographic Failures — https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- Let's Encrypt rate limits (staging-vs-production planning): https://letsencrypt.org/docs/rate-limits/
- Man pages: ss(8), openssl-s_client(1ssl), htpasswd(1), curl(1), certbot(1) where packaged; nginx ships nginx(8) on many distributions — otherwise consult the online nginx documentation above.
