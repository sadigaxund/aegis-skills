---
name: blue-team-detection
description: Detection-engineering companion that converts every vulnerability class this playbook's red-team modules can find into mandatory log signals, alert thresholds, and purple-team-validated detections so defenders catch both exploitation attempts and successful compromises.
category_slug: DETECT
cwe: [CWE-778]
owasp: A09:2021 – Security Logging and Monitoring Failures
---

# Blue-Team Detection Engineering (DETECT)

## Scope & Objectives

Invert the red-team view of this playbook into blue-team instrumentation requirements. Every other check module proves a vulnerability CLASS is exploitable; this module defines what must be LOGGED and what must ALERT so defenders see exploitation attempts (probes, bursts, error noise) and successful compromises (state changes, egress touches, deny-then-allow flips) for each of those classes.

Deliverables of an audit run with this module:

1. **Coverage matrix scorecard** — for each of the twelve classes (INJ, WEB, AUTHN, AUTHZ, SSRF, FILE, DESER, API, LOGIC, DOS, TOK, LLM), classify instrumentation as FULL / PARTIAL / BLIND using the matrix in Patterns & Signatures.
2. **Detection-rule catalog** — the concrete signals, log-line shapes, threshold starters, and false-positive pressures per class.
3. **Pipeline-flow verdict** — is the path app → log → shipper → store → alert → human intact, measured end to end.
4. **Purple-team validation record** — replay results proving each deployed detection actually fires (Exploitation & Reproduction).
5. **Remediation package** — emitter middleware, alert-config starter blocks, and runbook stubs sized to the team's stack.

Operating rules:

- Code-read access is assumed; auditing the CURRENT logging/alerting state is read-only (ripgrep evidence, config inspection). Mutating additions belong to the Remediation section and require change approval.
- Dynamic replay runs ONLY against authorized staging, mirroring the constraint in skills/code/injection.md. The goal is validating detections, not re-exploiting production.
- Absence of telemetry is scored as a finding in its own right (CWE-778): an undetected exploit class is a control gap even when the underlying bug is patched.
- Severity here means ALERT URGENCY (who gets woken up), not vulnerability CVSS; see the explicit note atop Severity Assessment.

Out of scope (cross-references, no duplication): sshd/sudo/auditd/host-integrity telemetry → the server skillset's `skills/server/logging-monitoring.md`; writing the vulnerabilities themselves → the corresponding red module per class; secret-redaction implementation detail → `skills/code/secrets-data-exposure.md`.

## Mental Model

Every exploit casts two shadows, and detection engineering instruments BOTH:

```
Shadow 1: THE ATTEMPT                 Shadow 2: THE SUCCESS
---------------------------           ---------------------------
probe bursts, malformed input         deny followed by allow on the
error strings surfacing               same resource/object
401/403 velocity                      outbound connections to places
latency fingerprints                  the app never talks to
sequential ID walks                   token reuse from wrong context
                                      spend/cost deviations
Detected by: AGGREGATES               Detected by: DISCRETE EVENTS
(velocity, ratio, deviation)          (single-instance, high-severity)
```

Classify every signal into one of three tiers, because they alert differently:

| Tier | Definition | Alert behavior | Examples |
|---|---|---|---|
| EVENT | Discrete security decision worth recording forever | Log always; alert instantly only for kill-switch-grade items | `authz.deny`, `egress.connect.blocked` to metadata IP, refresh-token reuse |
| AGGREGATE | Pattern visible only across many requests | Log the raw events; alert on windowed counts/ratios/deviations | brute-force curves, spray signatures, scraper walks, error bursts |
| INDICATOR | Composite suggesting SUCCESS, not just trying | Page immediately, lowest threshold in the system | deny-then-allow on same object, deserialization error burst PLUS new egress destination |

The event pipeline is a chain, and detection fails at the weakest hop:

```
[app emits] → [local sink] → [shipper] → [central store] → [detection] → [router] → [human + runbook]
   string-only   rotation      agent       retention        untuned       goes to     nobody
   no req-id     loses data    down        too short        thresholds    a dead      knows the
   PII inline    disk full     silently    cost-cap drops   = pure noise  mailbox     first move
```

Four axioms govern everything below:

1. **An unvalidated detection is a hypothesis, not a control.** A rule that has never fired under a known-good replay is decoration. Hence the purple-team loop is mandatory, not optional.
2. **Every page spends trust.** Alert budget is finite; ten false pages train the on-call to ignore the eleventh, true one. Alert only on ACTIONABLE signals, and give every alert a runbook line stating what to check first.
3. **Logs you cannot correlate are half-written.** A failure event without `request_id`, `src_ip`, and actor identifier cannot be joined into a story during triage. Correlation fields are part of the signal, not garnish.
4. **Local-only, string-only logs fail twice** — attacker-wipeable and unqueryable. Structured output shipped off-host is the floor, not the ceiling (host-side survival mechanics live in the server skillset's logging module).

## What To Check

Determine WHICH classes lack instrumentation, in this order:

### 1. Inventory the security-decision points

Enumerate where the codebase makes decisions worth recording: authentication handlers (login, MFA verify, token refresh), authorization checks (middleware, decorators, policy engines), parsers accepting complex input (upload validators, deserializers, XML/JSON bodies), outbound HTTP clients (fetch/requests/httpx wrappers), spend-adjacent code (checkout, discounts, refunds, LLM token metering). Produce a table: decision point → file:line → event emitted today (yes/no) → structured? → correlated by request-id?

### 2. Score all twelve classes against the matrix

For each class row in Patterns & Signatures, mark FULL (events emitted AND an alert consumes them), PARTIAL (events exist, nothing alerts — or alerts exist but no events feed them), or BLIND (no emission at all). Every BLIND and PARTIAL class becomes a finding; cite the missing signal column verbatim.

### 3. Run absence-greps for emission near security decisions

Ripgrep-compatible starting points; each needs MANUAL JUDGMENT because middleware may log upstream of these files:

```bash
# Auth-handling files that never reference any logger:
rg -il 'login|authenticate|verify_password|signIn|session' src/ \
  | xargs -I{} sh -c 'rg -q "logger\.|logging\.|log\." "{}" || echo "NO-LOGGING: {}"'
```

Judgment: a hit means no direct logger call IN THAT FILE; the route may still inherit access logging from middleware. Confirm what the middleware actually records (status codes only? or actor + reason?) before scoring AUTHN coverage.

```bash
# Authorization decision points: do denials emit anything?
rg -n 'Forbidden|403|PermissionDenied|AccessDenied|authorize\(|can\?' src/ | rg -iv 'test' 
# then, per hit file, check whether a deny path writes an event:
rg -c 'log|audit|event' $(rg -l 'PermissionDenied|AccessDenied' src/ | sort -u)
```

Judgment: framework exception classes (`PermissionDenied`, `ForbiddenError`) raised WITHOUT any adjacent audit call are the classic AUTHZ blind spot — the response exists, the telemetry does not.

```bash
# Deserialization entry points with error handling that swallows silently:
rg -n 'pickle\.loads|yaml\.unsafe_load|unserialize|ObjectInputStream|readObject|marshal\.loads' src/
```

Judgment: wrap-site `try/except` blocks whose except arm contains no logging line convert attack probes into silent no-ops. DESER telemetry lives exactly there.

```bash
# Metadata-endpoint awareness: should appear ONLY in guard/deny-list code, never reachable from user input:
rg -n '169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal' src/ deploy/ infra/ 2>/dev/null
```

Judgment: zero hits usually means NO egress guard exists (SSRF class BLIND at the network tier); hits only inside feature code that fetches URLs = worse.

```bash
# Token verification failures recorded?
rg -n 'jwt\.verify|decode\(.*token|verify_token|TokenError|ExpiredSignature' src/ | rg -i 'log|audit|event'
```

### 4. Verify structure, correlation, and redaction discipline

- Sample five representative security log lines from staging. Are they parseable JSON (or key=value)? Do they carry `request_id`, `src_ip`, actor id, outcome?
- Trace one request end-to-end: does the SAME `request_id` appear in web access log AND app event log? If nginx generates it, is it passed upstream (`proxy_set_header X-Request-ID $request_id`)?
- Grep for forbidden payloads in current logs: raw tokens, passwords, full request bodies, session cookies. Redaction gaps cross-reference `skills/code/secrets-data-exposure.md`; fix by hashing/truncation, never by deleting the event.

### 5. Probe pipeline health, not just emission

An emitter feeding a dead shipper is a BLIND class wearing a FULL costume. Confirm each hop: agent process/config present on app hosts (fluent-bit.conf / vector.toml / vendor agent), destination store receiving recent data, at least ONE alert rule consuming the security event stream, and a dead-man canary (`pipeline.canary` heartbeat event; alert when absent) if the team is ready to maintain one.

### 6. Grade alert quality on whatever exists

For every alert already deployed: Does it have a runbook line? A dedup/grouping policy? Was its threshold derived from measured baseline or guessed? When did it last fire, and were those fires actionable? Alerts with >90% benign close rate are candidates for retirement or retuning.

## Where To Look

Inspect these locations, in rough priority order:

| Location | What it tells you | Evidence commands / files |
|---|---|---|
| App middleware & auth hooks | Whether security EVENTS exist at all | Django `settings.py` LOGGING dict + signal receivers; Express `app.use(...)` loggers, winston/pino setup; Rails `around_action`; Spring filters/AOP |
| Web/proxy access logs | Correlation fields, status-code ratios, latency series | `nginx -T \| rg log_format`; Envoy/ALB/CDN access-log config |
| WAF / edge rules | Attempt-level SQLi/XSS telemetry | `modsecurity.conf`, `crs-setup.conf`: `SecRuleEngine` mode, whether engine logs carry rule ids |
| API gateway / rate limiter | Per-key velocity, scope enforcement events | gateway access logs, token-introspection logs |
| Shipper configs | Pipeline hop 3 exists and covers app output | `fluent-bit.conf`, `vector.toml`, DaemonSet manifests, vendor-agent install configs |
| Store & alert-as-code | Which detections actually consume the stream | Terraform `aws_cloudwatch_log_metric_filter` resources, Grafana Loki ruler rules, Datadog monitor definitions |
| LLM proxy/metering | Token accounting per identity | proxy usage logs, billing-export configs |

Access-log enrichment check — the three fields worth ADDING if absent (request-id correlation, response time, upstream status):

```nginx
# VULNERABLE (missing): no request correlation, no latency, no upstream visibility
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent"';

# FIXED (added): rt= request id, urt= total time, uct=/utime= upstream timings,
# ustatus= which upstream answered (exposes 5xx hidden behind proxy rewrites)
log_format main_ext '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" rt=$request_id urt=$request_time '
                    'uct=$upstream_connect_time ustatus=$upstream_status '
                    'utime=$upstream_response_time';
access_log /var/log/nginx/access.log main_ext;
proxy_set_header X-Request-ID $request_id;   # app must echo/consume it
```

Judgment notes: `$request_id` is nginx-generated per request since 1.11.0; if the app also generates ids, standardize on ONE propagated header or triage joins break. `$upstream_status` matters because proxies often mask backend 500s as generic 502s — SQLi error-burst detection depends on seeing the real status.

WAF reality check: `SecRuleEngine Off` (or DetectionOnly) means the WAF emits no enforcement telemetry and the INJ/WEB rows degrade to app-only signals — record that honestly in the matrix instead of assuming WAF markers exist.

## Patterns & Signatures

### Coverage matrix — the centerpiece artifact

Columns per row: what signal to log | where it lives | example log-line shape (JSON) | alert threshold STARTER (tune against baseline before paging on it) | false-positive pressure. Score each row FULL/PARTIAL/BLIND during What To Check.

| Class | Signal to log | Where it lives | Example log-line shape | Alert threshold starter | FP pressure notes |
|---|---|---|---|---|---|
| SQLi (INJ) | DB driver errors on parameterized endpoints; 500 spikes; WAF rule-id hits (CRS 942xxx family); p95 latency jump on search/order-by params | App error log; WAF engine log; APM latency series | `{"event_type":"db.query.error","route":"/search","driver_error":"SQLite3::SQLException","src_ip":"203.0.113.7","request_id":"b7c1"}` | ≥5 driver-error 500s / 5 min on one route family; or p95 latency ×3 baseline for 10 min | Genuine app bugs and migrations also throw driver errors; WAF absent is a gap to record, not safety |
| XSS (WEB) | CSP violation reports; reflected-payload echo markers; DOM sink errors on user-input routes | `report-uri`/`report-to` collector endpoint; app logs | `{"event_type":"csp.violation","directive":"script-src","blocked":"inline","route":"/profile","src_ip":"198.51.100.4"}` | Spike in violation reports naming input-echoing routes; any report with `<script` in blocked sample | Browser extensions and broken legit scripts generate constant low-level noise; trend, not single events |
| Authn failures (AUTHN) | Failed logins with reason; MFA push requests; token-verify failures; session-geo anomalies | Auth service event stream | `{"event_type":"auth.login.failure","actor_id":"u_8842","reason":"bad_password","src_ip":"203.0.113.7","ua":"python-requests/2.31","outcome":"failure"}` | Per-account ≥5 fails/15 min AND separately per-IP ≥30 fails/15 min (two distinct alerts) | Password-rotation days; office NAT; see dedicated AUTHN catalog below |
| Authz violations (AUTHZ) | Structured deny events actor/resource/action at decision points; per-principal 403 rate; admin actions | Authorization middleware audit stream | `{"event_type":"authz.deny","actor_id":"u_5521","resource":"invoice:88412","action":"read","outcome":"deny","request_id":"b7c1"}` | ≥20 denies/user/hour; ANY deny→allow flip by same principal+object = indicator tier | Stale UI links, role-transition confusion; see dedicated AUTHZ catalog below |
| SSRF (SSRF) | Outbound connect attempts from app hosts vs learned destinations; metadata-IP touches; unusual fetch schemes | Egress guard/firewall logs, DNS resolver logs, netflow | `{"event_type":"egress.connect.blocked","host_role":"web-1","dest_ip":"169.254.169.254","dest_port":80,"process":"node","outcome":"blocked"}` | ANY metadata-IP attempt = instant high-sev; new destination not on allowlist = investigate | Misconfigured integrations calling internal services; maintain allowlist with owners |
| File upload abuse (FILE) | Upload rejects; declared-vs-sniffed content-type mismatch; archive-expansion ratios; AV hits | Upload validator event stream | `{"event_type":"upload.rejected","actor_id":"u_2210","filename":"avatar.php;.jpg","declared":"image/jpeg","sniffed":"text/x-php","outcome":"rejected"}` | ≥10 rejects/user/day; ANY executable-sniff on image routes = ticket | Legit odd formats (HEIC, webp variants); polyglot-detection rules need tuning per accepted types |
| Deserialization (DESER) | Parser exception bursts (`pickle.UnpicklingError`, Java `StreamCorruptedException`) keyed by source IP | App error log at parser entry points | `{"event_type":"deser.error","parser":"pickle","error_class":"UnpicklingError","src_ip":"203.0.113.9","count_in_window":17}` | ≥10 parser errors/min from ONE source = probing | Internal producers sending version-skew payloads from many IPs at once |
| API abuse (API) | Per-key 401/403 velocity; scope-violation attempts; duplicate idempotency keys; monotonic page walks | Gateway/API-mgmt logs + app authz events | `{"event_type":"api.authz.scope_violation","key_id":"k_live_7f21","route":"/admin/export","key_scopes":["orders:read"],"outcome":"deny"}` | ≥50 auth failures/key/15 min; any scope violation on admin route = ticket; same idempotency-key twice = flag | Customer CI jobs with stale creds; monitoring probes; allowlist known integrations |
| Business logic (LOGIC) | Domain counters: discount stacking depth, refunds/account, price edits pre-checkout, duplicate submissions ms apart | App business-event stream (must be deliberately emitted) | `{"event_type":"logic.anomaly","kind":"refund_velocity","actor_id":"u_7731","value":6,"window":"24h","baseline_p95":1.2}` | >5× rolling 7-day p95 per account tier | Promotions and seasonal spikes; annotate marketing calendar into dashboards |
| DoS patterns (DOS) | rps per IP/ASN; concurrent-connection counts; slow-client byte rates; cache-miss ratio on expensive routes | LB/proxy metrics; app runtime metrics | `{"event_type":"dos.pattern","kind":"slowloris","conns_open":812,"bytes_per_sec":11,"src_asn":14061,"window_s":300}` | 2× p99 rps sustained 5 min per ASN; slowloris conns > configured floor | Flash crowds from press/viral moments; load tests — tag them or they page you |
| Token misuse (TOK) | JWT verify failures by cause; refresh-token REUSE after rotation; tokens observed in URLs | Auth/token service events | `{"event_type":"token.refresh.reuse","actor_id":"u_8842","token_hash":"sha256:9f2c…","first_use_ts":"…T09:58:01Z","reuse_ts":"…T10:41:19Z"}` | ANY refresh reuse post-rotation = compromise indicator, P1 candidate | Parallel tabs racing a refresh (allow tiny overlap window); clock skew at expiry edge |
| LLM tool abuse (LLM) | Tokens/day per identity tier; tool-call chain depth; sensitive-tool invocations; injection-marker inputs | LLM proxy/metering logs | `{"event_type":"llm.usage.rollup","identity_tier":"free","tokens_in":184000,"tokens_out":92000,"window":"day","ratio_vs_baseline":6.4}` | >5× 7-day baseline tokens/day per tier; injection-marker + privileged-tool-call combo = investigate | Legit power users; batch summarization jobs — give them their own identity tier |

### Class catalogs with concrete signatures

#### SQLi detection signals

Log three independent signal families; an attacker suppressing one usually trips another:

1. **Error telemetry** — DB error strings reaching app logs (`SQLite3::SQLException`, MySQL `You have an error in your SQL syntax`, PostgreSQL `unterminated quoted string`, MSSQL `Unclosed quotation mark`) plus the resulting 500 spike on parameterized endpoint families.
   ```json
   {"ts":"2026-08-24T10:15:04.512Z","event_type":"db.query.error","route":"/search",
    "param":"q","driver_error":"SQLite3::SQLException: unrecognized token",
    "http_status":500,"src_ip":"203.0.113.7","ua":"curl/8.5.0","request_id":"b7c14a02"}
   ```
2. **WAF/IDS markers, if present** — ModSecurity engine logs carry rule ids; the OWASP CRS 942xxx range names SQLi (e.g., 942100, the libinjection match). Log rule id + message + matched URI. Absence of a WAF is recorded as a coverage gap, never as "no attacks".
   ```json
   {"ts":"2026-08-24T10:15:05.100Z","event_type":"waf.match","rule_id":942100,
    "rule_msg":"SQL Injection Attack Detected via libinjection","uri":"/items?q=x%27",
    "action":"block","src_ip":"203.0.113.7"}
   ```
3. **Latency fingerprint for time-based blind** — time-based payloads inject `SLEEP(5)`/`pg_sleep(5)`/`WAITFOR DELAY`; the footprint is p95 latency multiplying ONLY on routes taking free-text params (search, sort columns), while other routes hold steady. Track per-route p95 as a metric series; alert on the divergence, not on absolute slowness.

Audit honesty note: full-query-text logging makes every query greppable but costs real volume (queries repeat millions of times daily), inflates storage spend, drags latency at high QPS, and vacuums user data INTO logs (PII tension — resolve via hashing/truncation per Verification & Validation, cross-reference `skills/code/secrets-data-exposure.md`). Prefer: capture query text only on ERROR, or sample at a fixed small rate.

#### Authentication attack detection

Two DISTINCT brute-force alerts — they catch different attackers and must never be merged:

- **Per-account velocity**: one account hammered (targeted takeover). Starter: ≥5 failures / 15 min → ticket; ≥20 → escalate.
- **Per-source-IP velocity**: one source failing everywhere (spray/stuffing engine). Starter: ≥30 failures / 15 min per source IP.

```json
{"ts":"2026-08-24T10:22:31.001Z","event_type":"auth.login.failure","actor_id":"u_8842",
 "action":"password_login","reason":"bad_password","outcome":"failure",
 "src_ip":"198.51.100.23","ua":"python-requests/2.31","request_id":"e40b9911"}
```

- **Password-spray signature**: MANY accounts × FEW attempts each × one IP/subnet. The per-account alert stays silent by design here; the spray alert catches it. Starter: ≥20 distinct target usernames with ≤3 attempts each, from one /24, inside 60 min.
- **Credential-stuffing fingerprint**: high 401 ratio on login (starter: >40% over 5 min) COMBINED with headless/non-browser UA clusters (`HeadlessChrome`, `python-requests`, `curl`, `okhttp`) and qualitative IP-reputation context if available. Any single leg alone is noise; the combination is the signal.
- **MFA-fatigue push storms**: repeated push approvals requested for one account. Starter: ≥5 pushes / 15 min / account.
  ```json
  {"ts":"2026-08-24T10:22:35.900Z","event_type":"auth.mfa.push.requested","actor_id":"u_8842",
   "attempt_no":6,"window_s":900,"outcome":"pending"}
  ```
- **Session anomalies / impossible travel**: same session identifier used from new geo/ASN mid-session.
  ```json
  {"ts":"2026-08-24T10:31:44.010Z","event_type":"session.anomaly.geo","actor_id":"u_8842",
   "session_hash":"sha256:9f2c…","prev_country":"US","new_country":"DE",
   "prev_asn":7922,"new_asn":3320,"decision":"step_up_required"}
   ```
  HONEST caveats, stated wherever this alert is deployed: mobile carrier NAT flips egress country legitimately; VPN users change ASN constantly; corporate split-VPN egress varies by region. Default disposition: step-up authentication or investigation queue — NOT automatic session kill and NOT a page. Hash session identifiers in logs; never log raw tokens.

#### Authorization violation detection

IDOR probe pattern: same endpoint, sequential or growing object identifiers, per-user 403/404 rate spiking. The access log already carries status codes; what is usually MISSING is the object identity — which is why structured deny events must exist at authorization-decision points:

```json
{"ts":"2026-08-24T10:31:02.220Z","event_type":"authz.deny","actor_id":"u_5521",
 "resource":"invoice:88412","action":"read","tenant_id":"t_14","resource_tenant":"t_09",
 "outcome":"deny","src_ip":"203.0.113.7","request_id":"c91d2204"}
```

Cross-tenant reads are impossible to detect from default logs (nothing fails loudly; the data just leaks) — so DESIGN guidance, not just config: emit the actor/resource/action triple at EVERY authorization decision, denies ESPECIALLY. A deny stream enables: per-principal probe-rate alerts, tenant-mismatch counters (`tenant_id != resource_tenant`), and forensic reconstruction. An allow-only world is blind.

Admin-action audit trail immutability basics: append-only destination (separate credentials that cannot delete), include before/after state, record approving ticket when applicable, ship off-host immediately:

```json
{"ts":"2026-08-24T10:33:19.480Z","event_type":"admin.action","actor_id":"a_102",
 "resource":"user:u_5521","action":"role.grant","before":["member"],"after":["admin"],
 "outcome":"success","approval_ticket":"CHG-4411"}
```

#### SSRF, file-handling, deserialization footprints

- **Egress anomalies from app hosts**: baseline which destination host:port pairs application hosts normally contact; alert on NEW destinations. Kill-switch rule above all others: ANY connection attempt toward cloud metadata (169.254.169.254, or fd00:ec2::254 on dual-stack AWS hosts, or the internal metadata hostname on GCP/Azure) = instant high-severity alert regardless of outcome, because even BLOCKED attempts prove exploit intent reached the network layer.
  ```json
  {"ts":"2026-08-24T10:41:07.330Z","event_type":"egress.connect.blocked","host_role":"web-1",
   "dest_ip":"169.254.169.254","dest_port":80,"process":"node","trigger":"ssrf_guard","outcome":"blocked"}
  ```
- **Parser-facing content-type anomalies**: uploads whose sniffed type contradicts the declared type, XML arriving where only JSON is expected, archives whose expansion ratio explodes. These are the request-side fingerprints of FILE-class attacks.
- **Deserialization exception bursts as attack telemetry**: gadget-chain hunting produces parse failures; a burst of `UnpicklingError`/`StreamCorruptedException` from one source is a live probe map of the parser surface. Log parser name + exception class + source, and count per window.

#### Token and API abuse

- **Per-key 401/403 velocity** — stolen-key triage starts here. Starter: ≥50 auth failures/key/15 min.
- **Scope-violation attempts** — VALID key hitting DISALLOWED endpoints is recon with a working credential; higher signal than raw 401 spam:
  ```json
  {"ts":"2026-08-24T10:52:12.001Z","event_type":"api.authz.scope_violation","key_id":"k_live_7f21",
   "route":"/admin/users/export","required_scope":"users:export","key_scopes":["orders:read"],"outcome":"deny"}
  ```
- **Pagination-scraping signatures**: same key walking `?page=N` monotonically (small step, high rate, near-zero errors). Count distinct pages/key/hour against the dataset's realistic size.
- **Replay indicators**: same request-id or idempotency key seen twice outside the client-retry envelope:
  ```json
  {"ts":"2026-08-24T10:41:19.002Z","event_type":"api.replay.suspect","idempotency_key":"8c9e44d0",
   "first_seen_ts":"2026-08-24T09:58:01Z","second_seen_ts":"2026-08-24T10:41:19Z","outcome":"flagged"}
  ```
- **LLM cost-anomaly alerts**: tokens/day per identity tier versus its own rolling 7-day baseline (starter: >5× jump); pair with tool-abuse signals below so a cost spike explains itself.

#### Business-logic and DoS pattern notes

LOGIC thresholds cannot come from a playbook — derive per-deployment baselines (rolling 7-day p95 per account tier) and alert on deviation MULTIPLES, with marketing-calendar annotations attached so campaigns stop eating pages. DOS starters live in the matrix row; the load-test tagging discipline (an internal marker header or known-source ranges agreed with ops, WITH EXPIRY) belongs in every deployment's runbook, because untagged load tests are the number-one self-inflicted DOS false positive.

#### LLM tool-abuse detection

Log the tool-call chain, not just prompts: sequence, target resources, argument paths. Signatures worth alerting: chain depth beyond norm (starter: >8 calls/session), sensitive-tool invocation following injection-marker inputs ("ignore previous instructions" class strings are WEAK evidence alone — treat the COMBO marker+privileged-tool as the investigable unit), and cross-capability sequences the product never intends (bulk file reads followed by outbound-send tools).

### Alert-quality engineering

- **Threshold philosophy**: alert on ACTIONABLE signals only. Before shipping any rule answer: what will the responder DO differently at 3 a.m. because this fired? If the answer is nothing, it is a dashboard panel, not an alert.
- **Runbook line per alert**: every alert config references a runbook whose first section is what-to-check-first. No runbook, no page — demote to ticket until written.
- **Severity mapping**: page (P1) / next-business-day (P2) / ticket (P3) / dashboard (P4) — full rubric in Severity Assessment.
- **Dedup & grouping concepts**: group identical signatures within a window (same signature + same grouped entity = one notification), cap re-notification frequency, and aggregate related entities (one campaign across 40 IPs should arrive as ONE incident-shaped alert, not forty).
- **Time-to-triage SLO (qualitative)**: define targets explicitly — e.g., P1 acknowledged <15 min, triaged <1 h; P2 triaged within next business day; then MEASURE acknowledgment timestamps. An SLO without a measured ack trail is a wish.
- **Detection-as-code**: once a rule survives tuning, encode it in Sigma rule format (see References) so detections version alongside code and port across backends.
- **Purple-team closure**: no detection counts as deployed until the replay procedure in Exploitation & Reproduction has fired it against staging. This loop closes with the rest of the playbook — red module proves the bug, this module proves the tripwire.

### SIEM-lite for small teams

When no SIEM exists, do NOT stall waiting for budget — a minimum-viable pipeline covers the top alerts:

```
structured JSON logs (app stdout / nginx)
        │
        ▼
log shipper — a lightweight agent such as Fluent Bit or Vector (both real, both fit)
        │
        ▼
managed central log store (CloudWatch Logs, Google Cloud Logging, Azure Monitor, or a hosted Loki/Datadog-class service)
        │
        ▼
metric filters / rule engine → alarms → pager + ticket queue
```

Top-3 metric-filter expressions, platform-agnostic pseudo-syntax:

```
FILTER auth_bruteforce_per_ip:
  MATCH  event_type == "auth.login.failure"
  GROUP  BY src_ip
  WINDOW 15m
  ALERT  WHEN count >= 30 -> notify:pager

FILTER ssrf_metadata_touch:
  MATCH  event_type == "egress.connect.blocked" AND dest_ip == "169.254.169.254"
  WINDOW instant
  ALERT  WHEN count >= 1 -> notify:pager-high

FILTER api_key_abuse:
  MATCH  event_type IN ("api.auth.failure", "api.authz.scope_violation")
  GROUP  BY key_id
  WINDOW 15m
  ALERT  WHEN count >= 50 -> notify:ticket
```

One REAL syntax example, certain as written — CloudWatch Logs metric filter pattern publishing 1 per matching event, alarm on the sum:

```
Filter pattern : { ($.event_type = "auth.login.failure") }
Metric         : SecurityEvents.LoginFailures   value 1, default 0
Alarm          : Sum >= 30 over period 900s, grouped per dimension where supported
```

## Taint Tracing Guidance

For this module, taint tracing means following the EVENT through its pipeline — the signal is "tainted" wherever a hop degrades it. Audit hop by hop:

```
[1 EMIT]      app writes structured security-event JSON to stdout/file
   │            fails when: string-only logs; missing correlation fields;
   │            PII/secrets inline forcing later wholesale redaction
   ▼
[2 SINK]      local collection (journald, container driver, log file + rotation)
   │            fails when: volatile-only storage; rotation shorter than
   │            investigation windows; disk-full silent drops
   ▼
[3 SHIP]      agent forwards off-host over TLS
   │            fails when: agent down with no dead-man alert; backpressure
   │            drops records under burst; clock skew breaks time windows
   ▼
[4 STORE]     central searchable store with retention
   │            fails when: retention < incident horizon; ingest caps silently
   │            discard during exactly the attack-driven volume spikes
   ▼
[5 DETECT]    metric filters / rule engine evaluate windows
   │            fails when: thresholds guessed not baselined; no dedup so one
   │            event storms into fifty pages (or one page buries fifty events)
   ▼
[6 ROUTE]     alert lands on pager / ticket / dashboard per rubric
   │            fails when: routed to an unmonitored mailbox; no ack tracking
   │            so nobody notices nothing happened
   ▼
[7 RESPOND]   human executes runbook: first-checks → escalate/rollback
                fails when: runbook absent or stale; blocks rolled back with
                no procedure and the attacker's traffic resumes
```

Verification steps per hop:

1. **EMIT**: pick three security decisions from the What To Check inventory; confirm each writes a parseable structured line containing `request_id`, `src_ip`, actor id, outcome.
2. **SINK**: confirm persistence across restart (host-side mechanics: server skillset logging module) and that rotation retains ≥ your longest detection window.
3. **SHIP**: stop-the-agent test in staging — does anyone notice within an hour? If not, add the dead-man canary before adding more rules.
4. **STORE**: query yesterday's events by `event_type`; measure end-to-end latency by injecting a canary marker event (`event_type:"pipeline.canary"`) at the app and timing its store arrival; skew >2 min breaks tight windows.
5. **DETECT**: for every rule, find its baseline derivation note (from Verification & Validation) or mark it UNTUNED.
6. **ROUTE**: fire one deliberate low-severity test alert monthly; time acknowledgment against the triage SLO.
7. **RESPOND**: tabletop the top-2 runbooks quarterly; stale runbooks are re-verified via the purple loop.

The composite INDICATOR tier deserves explicit tracing discipline: single events that only mean something JOINED to another (`deser.error` burst + new egress destination = exploitation in progress). Ensure the store can join on `src_ip` AND `request_id` within one window, or these composites are unbuildable.

## Exploitation & Reproduction

PURPLE-TEAM REPLAY procedures: the purpose is proving DETECTIONS FIRE, not re-proving vulnerabilities (the red modules did that). Run ONLY against authorized staging wired to the same pipeline as production. Red-module counterparts:

| Class | PoC source module | Replay below |
|---|---|---|
| INJ | skills/code/injection.md | R1 |
| AUTHN | skills/code/authn-session.md | R2, R3 |
| AUTHZ | skills/code/authz-access-control.md | R4 |
| SSRF | skills/code/ssrf-url-security.md | R5 |
| DESER | skills/code/deserialization.md | R6 |
| TOK/API | skills/server/api-token-security.md | R7 |

Generic loop for EVERY replay: deploy candidate detection on staging observability → replay the PoC → grep central store for expected events → assert alert fired within its configured window → record the checklist row.

**R1 — SQLi error-burst detection.** Replay the boolean-differential pair from skills/code/injection.md against staging `/search`:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -G https://staging.example/search \
  --data-urlencode "q=x' AND '1'='1"
curl -s -o /dev/null -w '%{http_code}\n' -G https://staging.example/search \
  --data-urlencode "q=x' AND '1'='2"
```

Expected events: ≥1 `db.query.error` carrying the request's `src_ip`/`request_id` (or WAF `waf.match` rows if CRS is deployed), then the `sqli-db-error-burst` alert within its 5-min window. If the endpoint returns clean 200s (parameterized correctly — good), validate detection instead with a forced driver-error replay agreed with the dev team, and say so in the checklist.

**R2 — AUTHN brute-force burst (~20 attempts, deliberately modest).**

```bash
for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code} ' -X POST \
  https://staging.example/login \
  --data-urlencode "username=victim@example.com" \
  --data-urlencode "password=wrongguess$i"; done
```

Expected events: 20 × `auth.login.failure` rows for one actor_id. Assert: per-account velocity alert FIRES; per-IP alert does NOT (20 < its 30 threshold) — this separation IS the test.

**R3 — Password-spray signature.** 25 distinct usernames × 2 attempts each, single source, ~5 s apart:

```bash
for u in user01@example.com user02@example.com … user25@example.com; do
  for n in 1 2; do curl -s -o /dev/null -X POST https://staging.example/login \
    --data-urlencode "username=$u" --data-urlencode "password=Spring${n}2026!"; sleep 5; done
done
```

Assert: spray alert fires; NEITHER brute-force alert fires. A spray alert that also trips brute-force rules is misgrouped — fix grouping before go-live.

**R4 — AUTHZ IDOR probe pattern.** Authenticate as low-privilege user A on staging; walk object ids:

```bash
for id in $(seq 88400 88430); do curl -s -o /dev/null -w '%{http_code} ' \
  -H "Authorization: Bearer $USER_A_TOKEN" https://staging.example/invoices/$id; done
```

Expected events: a stream of `authz.deny` rows (actor u_A, resource invoice:N). Assert: IDOR-probe alert (≥20 denies/user/hour starter) fires within window; each deny row shows tenant mismatch fields where applicable.

**R5 — SSRF metadata touch.** Replay the fetch-parameter PoC from skills/code/ssrf-url-security.md pointing at the metadata address:

```bash
curl -s -G https://staging.example/fetch --data-urlencode "url=http://169.254.169.254/latest/meta-data/"
```

Assert EITHER outcome proves detection value: guard present → `egress.connect.blocked` event AND instant high-sev alert (detection PASS); guard absent → connection succeeds (detection FAIL **and** a live vulnerability finding — report both).

**R6 — DESER exception-burst telemetry.** Post malformed serialized blobs to the parser endpoint ×10 from one source:

```bash
for i in $(seq 1 10); do curl -s -o /dev/null -X POST https://staging.example/import \
  -H 'Content-Type: application/octet-stream' --data-binary $'\x80\x04corruptblob'; done
```

Expected events: 10 × `deser.error` rows (parser name + exception class). Assert: burst alert (≥10/min/source starter) fires.

**R7 — Token replay indicator.** Send two identical requests minutes apart with the SAME `Idempotency-Key` header:

```bash
curl -s -X POST https://staging.example/orders -H "Idempotency-Key: purple-r7-key" -d '{"sku":"T1","qty":1}'
sleep 600
curl -s -X POST https://staging.example/orders -H "Idempotency-Key: purple-r7-key" -d '{"sku":"T1","qty":1}'
```

Expected events: second hit emits `api.replay.suspect`. Assert: flag/alert fires outside the client-retry envelope.

### Pass/fail checklist format

Record one row per detection; a detection without a green row is NOT deployed:

```
| Detection              | Replay | Expected event(s)         | Expected alert          | Window | Fired? | Time-to-fire | Notes                     |
|------------------------|--------|---------------------------|-------------------------|--------|--------|--------------|---------------------------|
| sqli-db-error-burst    | R1     | db.query.error            | sqli-db-error-burst     | 5m     | PASS   | 41s          | WAF rows also present     |
| auth-bruteforce-acct   | R2     | auth.login.failure ×20    | bruteforce-per-account  | 15m    | PASS   | 2m10s        | per-IP stayed silent: yes |
| password-spray-subnet  | R3     | auth.login.failure spread | password-spray-subnet   | 60m    | FAIL   | —            | grouping fix required     |
| ...                    |        |                           |                         |        |        |              |                           |
```

Tag all replay traffic with the internal test marker agreed with ops (for example a custom header such as `X-Security-Test-Run`) EXCEPT where the marker would change the path under test — and give every marker an expiry so test exclusions cannot rot into permanent blind spots.

## Remediation

Add instrumentation per major stack, emitting structured security-event JSON with ONE shared field schema:

| Field | Meaning | Notes |
|---|---|---|
| `ts` | ISO-8601 UTC event time | emitter clock; pipeline skew is checked separately |
| `event_type` | dotted taxonomy (`auth.login.failure`, `authz.deny`, …) | stable names — alerts key on these |
| `actor_id` | authenticated principal or attempted identifier | pseudonymize where PII policy demands (hash, do not omit) |
| `resource` | object acted on (`invoice:88412`) | enables IDOR/tenant-mismatch joins |
| `action` | verb (`read`, `password_login`, `role.grant`) | |
| `outcome` | `success` / `failure` / `deny` / `blocked` / `flagged` | denies are first-class, never dropped |
| `request_id` | correlation id shared with access logs | nginx `$request_id` propagated upstream |
| `src_ip` | source address | kept whole for IP-based alerts; see redaction note below |
| `ua` | user-agent | truncate to a sane length at emission |

### Express additions

```js
// FIXED (added): structured security-event emitter for Express
const crypto = require("crypto");

function emitSecurityEvent(req, evt) {
  const line = {
    ts: new Date().toISOString(),
    event_type: evt.event_type,
    actor_id: evt.actor_id ?? req.user?.id ?? null,
    resource: evt.resource ?? null,
    action: evt.action ?? null,
    outcome: evt.outcome,
    request_id: req.headers["x-request-id"] || req.id || crypto.randomUUID(),
    src_ip: req.ip,
    ua: (req.get("user-agent") || "").slice(0, 120),
    ...(evt.extra || {}),
  };
  process.stdout.write(JSON.stringify(line) + "\n"); // stdout -> shipper
}

// Wire wherever authentication rejects a credential:
function auditLoginFailure(req, actorId, reason) {
  emitSecurityEvent(req, { event_type: "auth.login.failure",
    actor_id: actorId, action: "password_login", outcome: "failure",
    extra: { reason } });
}

// Emit AT the authorization decision point — denies especially:
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user?.roles?.includes(role)) {
      emitSecurityEvent(req, { event_type: "authz.deny",
        actor_id: req.user?.id, resource: req.originalUrl,
        action: req.method, outcome: "deny", extra: { required_role: role } });
      return res.status(403).json({ error: "forbidden" });
    }
    next();
  };
}
```

```js
// VULNERABLE (missing): deny path returns with no event emitted
app.delete("/admin/users/:id", requireAdmin, (req, res) => { /* ... */ });
```

### Django additions

```python
# FIXED (added): structured security-event logging via auth signals
import json, logging
from django.contrib.auth.signals import user_login_failed, user_logged_in
from django.dispatch import receiver

seclog = logging.getLogger("security.events")

class EventFormatter(logging.Formatter):
    def format(self, record):
        evt = getattr(record, "event", None) or {"event_type": "app.log",
                                                 "message": record.getMessage()}
        evt.setdefault("ts", self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"))
        return json.dumps(evt)

# settings.py wires the formatter to stdout for the shipper:
# LOGGING = {
#     "version": 1,
#     "formatters": {"json": {"()": "myapp.logging.EventFormatter"}},
#     "handlers": {"security": {"class": "logging.StreamHandler",
#                               "formatter": "json", "stream": "ext://sys.stdout"}},
#     "loggers": {"security.events": {"handlers": ["security"], "level": "INFO"}},
# }

@receiver(user_login_failed)
def audit_login_failed(sender, credentials, request=None, **kwargs):
    seclog.info("", extra={"event": {
        "event_type": "auth.login.failure",
        "actor_id": str(credentials.get("username", "")),
        "action": "password_login", "outcome": "failure",
        "request_id": request.headers.get("X-Request-ID") if request else None,
        "src_ip": request.META.get("REMOTE_ADDR") if request else None,
        "ua": (request.META.get("HTTP_USER_AGENT") or "")[:120] if request else None,
    }})

@receiver(user_logged_in)
def audit_login_success(sender, request, user, **kwargs):
    seclog.info("", extra={"event": {
        "event_type": "auth.login.success", "actor_id": str(user.pk),
        "action": "password_login", "outcome": "success",
        "src_ip": request.META.get("REMOTE_ADDR"),
    }})
```

For AUTHZ in Django, wrap permission checks (or use a decorator around DRF permission classes) so every denial emits `authz.deny` with the actor/resource/action triple.

### Redaction discipline inside emitters

Hash identifiers that would otherwise be PII while PRESERVING joinability — omission destroys detection power, hashing does not:

```python
import hashlib
def pseudonymize(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
```

Apply to emails/usernames when policy requires; NEVER log raw tokens, passwords, cookies, or full request bodies. Truncation beats omission; hashing beats truncation for fields you must still group by. Full redaction rules: `skills/code/secrets-data-exposure.md`.

### Alert-config starter blocks — top five highest-value detections

Platform-neutral shape; adapt keys to your alerting system and TUNE against baseline before enabling paging:

```yaml
- alert: ssrf-metadata-touch            # P1 - kill-switch grade
  match: event_type == "egress.connect.blocked" AND dest_ip == "169.254.169.254"
  window: instant
  severity: P1
  dedup: 30m per host_role
  runbook: runbooks/ssrf-metadata-touch.md

- alert: token-refresh-reuse            # P1 - compromise indicator
  match: event_type == "token.refresh.reuse"
  window: instant
  severity: P1
  dedup: 15m per actor_id
  runbook: runbooks/token-refresh-reuse.md

- alert: auth-bruteforce-per-ip         # P2 - campaign signal
  match: event_type == "auth.login.failure"
  group_by: [src_ip]
  window: 15m
  when: count >= 30
  severity: P2
  dedup: 30m per src_ip
  runbook: runbooks/auth-bruteforce.md

- alert: password-spray-subnet          # P2 - low-and-slow catcher
  match: event_type == "auth.login.failure"
  group_by: [src_subnet_24]
  window: 60m
  when: distinct(actor_id) >= 20 AND max_attempts_per_actor <= 3
  severity: P2
  dedup: 2h per src_subnet_24
  runbook: runbooks/password-spray.md

- alert: sqli-db-error-burst            # P2 - exploitation attempt
  match: event_type == "db.query.error"
  group_by: [route]
  window: 5m
  when: count >= 5
  severity: P2
  dedup: 15m per route
  runbook: runbooks/sqli-db-error-burst.md
```

### Runbook template stub

Create one per alert BEFORE it may page:

```markdown
# Runbook: <alert-name>
Trigger condition: <one line copied from the alert config>
First checks (in order):
1. Exclude test-tagged traffic and allowlisted sources (with expiry check).
2. Pull grouped context: <exact query over event_type/grouping fields>.
3. Classify: benign-known / suspicious / confirmed-compromise.
Escalation: <when to page security-oncall; incident channel; who owns decision>
Rollback of blocks: <how to undo auto-blocking: exact command/API, TTL, owner>
Post-incident: threshold tuning notes; new FP signature? update baseline doc.
```

Filled example (ssrf-metadata-touch): first checks — confirm which app host and process initiated (`host_role`, `process` fields), pull the triggering `request_id` from the app log to find the input vector, check whether any connection SUCCEEDED after blocked attempts; escalation — page security-oncall immediately even if blocked (intent reached the network layer); rollback — egress-guard blocklist entries carry TTL + owner, restore via guard's allowlist API and record ticket.

## Verification & Validation

**Per-detection verification (positive tests).** Every detection passes the replay loop from Exploitation & Reproduction before it is considered live: green row in the checklist with measured time-to-fire inside its configured window. Re-run the full replay suite quarterly and after any pipeline migration (shipper swap, store change) because migrations silently break event field names.

**Negative tests and baseline noise measurement.** Normal traffic must NOT page. Before enabling paging on any new aggregate alert:

1. Run the rule in dashboard-only mode for a 1–2 week soak covering at least one weekend and one business-cycle peak.
2. Record benign counts per window; set the paging threshold above observed p99 with explicit headroom; write the derivation into the alert config as a comment so the next tuner knows it was measured, not guessed.
3. Deliberately replay BENIGN traffic resembling each signature (office-NAT login burst from a test range, compliant scraper walk) and confirm no page fires.
4. Verify dedup works: one sustained campaign produces ONE incident-shaped notification per dedup window, not one per event.

**Regression notes.**

- **Log volume/cost blowups**: new emitters can multiply ingest overnight. Watch GB/day per source; alert on 2× jump. Chatty event types get sampled AT THE SHIPPER (keep every high-severity event type unsampled). Ingest caps that silently discard during spikes defeat the entire module — configure overage behavior consciously.
- **PII-in-logs tension**: detection wants actor identity; privacy wants less PII. Resolution is hashing/truncation, NOT omission — pseudonymize emails/usernames (joinable), truncate UAs and tokens, never emit raw secrets or bodies. Cross-reference the redaction rules in `skills/code/secrets-data-exposure.md`; when that module's redaction changes, re-run this module's replay suite because hashed fields must remain groupable.
- **Clock drift regression**: windowed alerts assume emitter/store clocks agree within ~2 min; verify NTP/chrony sync on hosts (server skillset covers host config) after infrastructure changes.
- **Field-name drift**: alerts key on `event_type` strings; a renamed field kills rules silently. Keep the taxonomy in version control next to the alert configs; add a store-side query asserting each expected `event_type` appears at least once daily (dead-man check per class).

**Validation cadence summary:** purple replays quarterly + after migrations; canary heartbeat checked by alert; runbook tabletop twice yearly for the top-2 alerts.

## Severity Assessment

EXPLICIT SCOPE NOTE: this rubric scores ALERT URGENCY (paging priority), not vulnerability severity. CVSS-style scoring of the underlying bugs belongs to the originating red module; an alert about a patched-but-probed bug still pages according to THIS table.

| Priority | Meaning | Response target | Detection categories mapped |
|---|---|---|---|
| P1 — page now | Compromise INDICATOR or kill-switch signal; responder action changes within minutes | Acknowledge <15 min; triage <1 h | Metadata-IP touch (even blocked); refresh-token reuse post-rotation; deny→allow flip on same principal+object; deser-burst PLUS new egress destination composite |
| P2 — next business day | Sustained campaign against controls; exploitation attempt with volume | Triage next business day; monitor continuously meanwhile | Brute-force velocity (either axis); password-spray signature; credential-stuffing fingerprint combo; SQLi error burst / WAF SQLi hits; API key-velocity breach; LLM cost anomaly >5× baseline |
| P3 — ticket | Real signal, low urgency or single-instance | Ticket queue, reviewed daily | Isolated scope-violation attempts; single MFA-fatigue occurrence; upload-reject spikes; IDOR deny-rate below page bar; pagination-scrape flags |
| P4 — dashboard only | Context, trends, tuning inputs | Reviewed in weekly ops review | CSP violation trend; baseline drift metrics; threshold-tuning counters; dead-man canary status; compliant-scraper traffic |

Tuning guidance:

1. Start conservative: ship new detections one priority level LOWER than your instinct, then promote after the first clean month — trust lost to false pages takes months to rebuild.
2. Promote on corroboration, not volume alone: two weak signals joined (marker input + privileged tool call) justify promotion where neither alone does.
3. Retire or demote any alert with >90% benign close rate across a quarter; record why in the alert config.
4. Every P1/P2 MUST have its runbook written BEFORE paging enables; P3/P4 may lag but need owner assignment.
5. Review the whole rubric quarterly against incident history: if real incidents arrived via channels you scored P3, the rubric is wrong, not the incidents.

## Common False Positives

- **Shared-IP office NAT bursts**: an office behind one egress IP fails logins en masse after a scheduled password rotation — textbook spray/brute-force signature, entirely benign. Mitigations: ASN/org-level allowlist entries WITH EXPIRY, UA-diversity cross-check (real browsers vary; tooling clusters), require multi-signal confirmation before paging.
- **Legitimate scrapers with robots.txt compliance**: well-behaved crawlers walking pagination slowly match scraping signatures. Mitigations: rate-and-volume thresholds rather than existence-of-walk; registered good-bot identification honored; keep them P4 unless they exceed declared politeness bounds.
- **Batch jobs tripping velocity alerts**: nightly reconciliation, reporting exports, and data pipelines hammer APIs on schedule. Mitigations: allowlists carrying EXPIRY + OWNER + REASON (reviewed quarterly; permanent allows rot into blind spots), give batch identities their own tier so their baselines separate from humans.
- **Retry storms inflating counts**: client-side retries multiply one genuine failure into N logged events, breaching thresholds spuriously and masking the real single failure among duplicates. Mitigations: dedup by request-id/idempotency-key BEFORE counting; count unique attempt identifiers, not raw rows.
- **Impossible-travel environment noise**: mobile carrier NAT, consumer VPN egress switching, corporate split-VPN region routing all produce geo/ASN jumps. Mitigation already stated: step-up/investigate disposition, never auto-kill or page on geo alone.
- **Self-inflicted scanner noise**: your own purple replays, pen-test windows, and load tests fire real alerts. Mitigation: the internal test marker header with EXPIRY discipline, agreed with ops, applied everywhere except paths whose behavior it would change.
- **Framework/version churn error noise**: dependency upgrades change driver exception strings, breaking string-matched INJ/DESER signatures both ways (false positives AND silent misses). Mitigation: prefer structured fields (`error_class`, parser name) over message text matching; include signature-source in the quarterly replay pass.

## References

Standards and cheat sheets:

- OWASP Cheat Sheet Series — Logging Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Top 10 2021 A09:2021 – Security Logging and Monitoring Failures — https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
- NIST SP 800-61, Computer Security Incident Handling Guide (incident-response lifecycle this module's triage SLOs feed)
- CWE-778: Insufficient Logging of Errors
- Sigma rule format project — detection-as-code standard for encoding tuned rules portably — https://github.com/SigmaHQ/sigma

Companion modules in this playbook:

- Host-side telemetry (sshd/sudo/auditd/integrity/shipping survival): server skillset `skills/server/logging-monitoring.md` — authoritative for everything below the application layer; this module deliberately does not duplicate it.
- Red-team counterparts feeding the coverage matrix rows: `skills/code/injection.md` (INJ), `skills/code/web-client.md` (WEB), `skills/code/authn-session.md` (AUTHN), `skills/code/authz-access-control.md` (AUTHZ), `skills/code/ssrf-url-security.md` (SSRF), `skills/code/file-handling.md` (FILE), `skills/code/deserialization.md` (DESER), `skills/code/api-security.md` (API), `skills/code/business-logic-races.md` (LOGIC), `skills/code/denial-of-service.md` (DOS), `skills/server/api-token-security.md` (TOK), `skills/code/llm-ai.md` (LLM).
- Redaction rules resolving the PII-in-logs tension: `skills/code/secrets-data-exposure.md`.










