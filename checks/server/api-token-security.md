---
name: server-api-token-security
description: Audits the full lifecycle of bearer/API tokens protecting an internet-exposed HTTP API — minting entropy and format, hash-only server storage, transport rules, scoping, expiry and rotation, revocation, per-key rate limits, and log hygiene — with read-only evidence commands and hardened reference implementations.
category_slug: TOK
cwe: [CWE-522, CWE-307]
owasp: A07:2021 – Identification and Authentication Failures
---

## Scope & Objectives

Audit every stage of the token lifecycle for one internet-exposed HTTP API that authenticates machine clients with opaque bearer/API tokens (strings presented as `Authorization: Bearer <token>` or an API-key header). Ten domains, in priority order:

1. **Design** — entropy floor (>=128 bits from a CSPRNG), format conventions (type prefix, checksum), forbidden token bases.
2. **Server-side storage** — the classic fatal flaw: plaintext or reversibly encrypted tokens in the database versus store-the-hash-only.
3. **Transport** — TLS-only enforcement, header versus query-string versus cookie carriage.
4. **Scoping & privilege model** — god-tokens versus scoped, tenant-bound, read/write-separated keys.
5. **Expiry & rotation** — lifetime policy, downtime-free rotation with overlap windows, stale-token reaping.
6. **Revocation & incident readiness** — revocation latency including cached-auth gaps, leak-response runbook.
7. **Rate limiting & abuse controls** — per-key quotas, 429 semantics, unauthenticated-endpoint separation.
8. **Key-enumeration resistance** — uniform timing/error behavior on invalid tokens.
9. **Logging & monitoring** — safe fields, never-log-full-token rule, anomaly alerting.
10. **Client hygiene & host sprawl** — distribution guidance, and where tokens hide on the host (bridge to HSECRET).

Out of scope (cross-references): JWT structure, algorithms, `none`/weak-secret validation → AUTHN (`checks/authn-session.md`); CSRF consequences of cookie-carried credentials → WEB (`checks/web-client.md`); general API abuse, pagination/enumeration, unauthenticated-endpoint hardening → API (`checks/api-security.md`); TLS termination and header stripping at the edge → TLS (`checks/server/tls-proxy.md`); secret contents in files/repos → SECRETS (`checks/secrets-data-exposure.md`); volumetric thresholds → DoS (`checks/denial-of-service.md`). Where this playbook names a logging-monitoring module, apply its alert-routing guidance when that module exists in your copy.

Operating rules:

- All inspection is read-only. Mutating commands appear only under Remediation and require Phase 6 approval.
- Commands needing root are tagged `[ROOT]`; commands needing read credentials for the application database are tagged `[APP-DB]`. Without those privileges, audit from the config-as-code repo and report the gap as "not verified on host".
- Judge effective state: middleware code that runs, schema that is deployed, logs that are being written. Config intent is secondary evidence.

## Mental Model

An attacker needs exactly one valid token. Every lifecycle weakness is a different place to get one:

```
Attacker goal: obtain ONE valid token ──▶ replay it from anywhere on the internet
How they get it                       Why it was possible (this module)
------------------------------------  -------------------------------------------------
SQLi / leaked DB backup          ◀──  tokens stored plaintext in DB (storage) = fatal
grep /var/log on any one box     ◀──  full tokens written to access/app logs
Referer header / browser history ◀──  tokens carried in the query string
public CI logs / client repos    ◀──  hardcoded tokens, no env-var guidance to users
online guessing                  ◀──  low-entropy minting + no per-key rate limit
ex-contractor's old key          ◀──  no expiry, no revocation path, no last-used signal
cached authz after revoke        ◀──  revocation "done" but token keeps working to TTL
```

Two insights drive most verdicts, and agents get both wrong in both directions:

- **Hash choice is context-dependent.** Password databases need slow, salted KDFs (argon2/bcrypt) because humans pick guessable secrets; the KDF buys nothing else. An API token minted with >=128 bits of CSPRNG entropy has no guessable structure, so `SHA-256(token)` is sufficient protection at rest: inverting it means searching >=2^128 candidates, which is infeasible. Using argon2 here is not "more secure" — it just makes every request pay ~100 ms and invites auth-endpoint DoS. Conversely, `SHA-256("password123")` protects nothing. Verdict follows entropy of the input, not the algorithm's fashion.
- **A revocation that takes effect later is not a revocation.** Any positive-TTL cache between the token check and the authority table converts "revoked" into "revoked within N seconds". Quantify N from code, always.

Lifecycle-stage view used for triage throughout this module:

| Lifecycle stage | Flaw | Detection method | Severity anchor |
|---|---|---|---|
| Mint | Entropy <128 bits or non-CSPRNG randomness (`Math.random`, Mersenne Twister) | Read minting code; compute `log2(alphabet^len)` | High (Critical if short + unthrottled) |
| Mint | uuid4-only tokens | `randomUUID()`/`uuid4()` in mint path | Borderline — see What To Check #1 |
| Mint | No type prefix / no checksum | Inspect token format samples | Low |
| Mint | Derived from user ID, email, timestamp, counter | Read minting code | High |
| Store | Plaintext/reversible token column | Schema introspection; no `*_hash` sibling | Critical |
| Store | Hash truncated (<32 bytes) or unsalted MD5/SHA-1 | Column size / algorithm in code | High |
| Transport | Query-string carriage | Access-log grep for `token=` params | High |
| Transport | Token accepted over plain HTTP | Listener/proxy config (cross-ref TLS) | High |
| Scope | Single god-token shared by integrations; no scope columns | Client inventory vs token rows | High |
| Expiry | All `expires_at` NULL and no revoke capability | DDL + admin surface inventory | High |
| Rotate | Rotation requires simultaneous cutover (downtime or breakage) | Runbook/integration incident history | Medium |
| Revoke | Auth cache lacks invalidation on revoke | Read cache TTL code path | High |
| Limit | No per-key quota; 429 never returned | Config review; response headers on docs endpoints | Medium |
| Enumerate | Invalid-token responses differ in timing/body by cause | Coarse timing loop; error taxonomy | Medium |
| Log | Full tokens in logs | Log grep for `Bearer <20+ chars>` | High |
| Distribute | Tokens hardcoded in repos/configs | Repo/host grep sweep | Medium (cross-ref SECRETS) |

Classify findings by which link in the chain they break; a Medium gap becomes Critical once it chains with an adjacent entry point (e.g., unthrottled + 8-char tokens = online-guessable).

## What To Check

### 1. Token Design: Entropy, Format, Forbidden Bases

Locate the minting code and read it. Search both sides of the stack:

```bash
rg -n "randomBytes|randomUUID|uuid4|token_hex|token_urlsafe|secrets\.choice|randbelow" server/ src/ app/
rg -n "Math\.random|random\.random|random\.randint|Random\(\)|mt19937" server/ src/ app/   # non-CSPRNG = flag
```

Apply the floor: **>=128 bits from a CSPRNG**, i.e. `crypto.randomBytes(16)` minimum, 32 bytes preferred. Compute entropy yourself: `bits = log2(alphabet_size ^ length)`. A 43-char base64url string carries ~256 bits; a 32-hex-char string carries 128; an 8-char alphanumeric string carries ~47.6 and is a High finding on its own.

The uuid4 judgment — apply verbatim: UUIDv4 contains 122 random bits from a CSPRNG. Brute-forcing 2^122 is as infeasible as 2^128 for any realistic adversary, so uuid4-derived tokens are **borderline-acceptable, flagged**: (a) 122 < 128, below the stated floor, so it never passes silently; (b) uuid4 strings carry no type prefix and no checksum, so they are indistinguishable from other UUIDs in logs and configs and survive paste-errors until they hit the server; (c) uuid4 is routinely reused as a general-purpose identifier, so the same value often appears in non-secret contexts, training users to copy it around. Recommend a purpose-built prefixed format; do not raise a Critical for entropy alone.

Required format properties (Low severity when absent, but always reported):

- Type prefix identifying secret family and environment: `sk_live_`, `pat_`, `ghp_` style. Enables secret-scanning tools, visual triage in logs, and safe prefix logging.
- Trailing checksum (e.g., 8 chars of `SHA-256(body)` base64url) so mistyped tokens fail locally instead of generating auth traffic and enabling typo-slurping on the wire.

Forbidden bases — flag any token derived from or containing: user IDs, email addresses, timestamps, sequential counters, hostnames/MACs, or `JWT` signed with `none`/weak symmetric secrets (verify the last one in AUTHN, `checks/authn-session.md`; from this module treat "JWT accepted as bearer credential" as a pointer finding, not a duplicate audit).

### 2. Server-Side Storage (the Classic Fatal Flaw)

Introspect the deployed schema `[APP-DB]`:

```sql
SELECT table_name, column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE column_name ~* '(token|api_key|apikey|secret|credential)'
ORDER BY table_name, ordinal_position;
```

Verdict rules:

- Any column holding the authenticable token value itself (name without `_hash`/`digest`, populated with full-length token strings) while the API accepts that value → **Critical**. Confirm by sampling lengths only, never values: `SELECT length(secret_col), count(*) FROM t GROUP BY 1;` — uniform lengths consistent with minted tokens corroborate without exposing material.
- Reversibly encrypted storage (AES etc. with a key in app config) → **High**: the decryption key lives next door, so the control collapses under any app-level read primitive. Report as "plaintext-equivalent under key compromise".
- Correct shape: exactly one authoritative column named `token_hash`/`token_digest` holding `SHA-256(raw_token)` (32-byte digest), covered by a UNIQUE index. Why SHA-256 suffices HERE and argon2 does not belong: pre-image resistance is all that is needed once input entropy >=128 bits — there is nothing to "slow down" because guessing is already dead (see Exploitation d for the math). Slow KDFs per-request also multiply CPU cost on the hottest code path. This asymmetry cuts both ways: if you find password-style hashing (bcrypt/argon2) applied to high-entropy tokens, note it as unnecessary overhead (informational, not a finding); if you find plain hashing applied to low-entropy tokens, the hash is decoration — severity stays driven by the entropy finding.
- Reject truncated digests (<32 bytes for SHA-256) and anything unsalted-MD5/SHA-1 flavored: High.

### 3. Transmission Rules

- TLS-only: the API must refuse token-bearing requests on plain HTTP. Edge evidence cross-refs TLS (`checks/server/tls-proxy.md`); app-side, confirm no code path honors `X-Forwarded-Proto: http` bypasses.
- Carriage: `Authorization: Bearer` header is the default-correct choice (RFC 6750). Custom headers (`X-API-Key`) are acceptable when consistently enforced. **Query-string carriage (`?access_token=`/`?api_key=`) is a High finding**: it lands in access logs, browser history, `Referer` headers on any outbound link, and intermediary devices. If legacy clients force it, demand the log-redaction mitigation in Remediation and a deprecation clock.
- Cookie carriage: tokens in cookies inherit the browser CSRF model (cross-ref WEB, `checks/web-client.md`: SameSite, CSRF tokens, no wildcard-domain cookies). For machine APIs this is usually a design smell; report as Medium with CSRF cross-ref unless browser flows genuinely require it.

### 4. Scoping & Privilege Model

- Inventory issued tokens `[APP-DB]`: `SELECT client_id, count(*), array_agg(DISTINCT scopes) FROM api_tokens GROUP BY 1;` One row serving every integration = god-token pattern → High.
- Required model: per-client keys carrying explicit scopes (e.g., `read:invoices`, `write:invoices`), tenant/resource binding (`tenant_id` NOT NULL wherever objects are tenant-owned), and separated read/write credentials for sensitive surfaces.
- Enforce scopes in middleware, never by convention. Flag any code that parses scope/tenant claims out of token *content* without a signature or server-side authority row — unverified self-asserted scope is privilege escalation by token crafting → High (or Critical if write/admin scopes are claimable).
- Check admin endpoints require a distinct scope and that no existing token holds it "temporarily".

### 5. Expiry & Rotation

- Lifetime policy: prefer finite `expires_at`. Long-lived tokens are acceptable only with documented compensating controls: scheduled rotation policy, usage monitoring, and instant revocation capability (all three, else High).
- Measure reality `[APP-DB]`:

```sql
SELECT count(*) FILTER (WHERE expires_at IS NULL) AS immortal_tokens, count(*) AS total FROM api_tokens;
SELECT max(last_used_at) AS stale_active FROM api_tokens WHERE revoked_at IS NULL;
```

- `last_used_at` must be updated on use (throttled writes are fine, e.g. at most once/minute per token). Absent tracking → Medium (kills compromise detection and stale-key hygiene).
- Stale reaping policy: unused >90 days → disable then delete after retention window; document the numbers, verify a job or runbook exists.
- Rotation mechanics must support overlap windows (both tokens valid simultaneously) so integrations cut over without downtime. A cutover that requires simultaneous switch-and-pray → Medium process finding; production breakage from past rotations is corroboration.

### 6. Revocation & Incident Runbook

- Prove a revocation path exists and is reachable: admin UI, API, or documented ops procedure. No path at all → High.
- Trace the hot auth path for caches (in-process maps, Redis, CDN/auth-service caches). For each layer record: key shape, TTL value, and whether a revoke operation deletes/updates the cache. **Cache-without-invalidation is a High finding**: the revoked token keeps working until TTL expiry; quantify the window from code (`ttl_seconds`) and state it in the finding.
- Leak-response runbook checklist (existence + drill evidence):
  1. Revoke the token (verify revocation propagates within the stated bound).
  2. Hunt usage: search logs by token prefix and token id for post-leak activity; establish timeline.
  3. Rotate dependent integrations: issue replacements with identical scopes via overlap window.
  4. Assess blast radius: scopes + tenant binding + `last_used_at` deltas decide notification duty.
  5. Notify the token owner/customer with factual window and actions taken.
  6. Postmortem: how it leaked (logs? repo? support ticket?), which control failed.
- Compromise indicators worth alerting on (wire into the logging-monitoring module): impossible travel on API source IPs for one token, 401 spikes followed by 200s (guessing succeeded), brand-new User-Agent or ASN for a known client id, request-volume step-change.

### 7. Rate Limiting & Abuse Controls Per Key

- Every authenticated request must be attributable to a key, and every key must have a quota: burst limit (token-bucket, absorbs retries) and sustained limit (requests/minute and/or day). Absence → Medium; absence on write/admin endpoints → High.
- Semantics: exceed returns `429` with `Retry-After` (seconds) — verify headers in code/docs; silent connection drops or 500s are findings.
- Unauthenticated endpoints (login, token mint, signup) need their own stricter buckets keyed by IP+identifier, distinct from per-key limits (cross-ref API `checks/api-security.md` and DoS `checks/denial-of-service.md`).
- Edge limiting (nginx `limit_req`) may complement but must key on something stable per client — see Remediation for the `$http_authorization` caveat.

### 8. Key-Enumeration Resistance

- Uniform rejection: invalid token, malformed token, unknown key, expired, revoked → identical status (401), identical body shape, indistinguishable timing. Error taxonomies that reveal "expired" vs "unknown" help legit debugging but hand enumeration oracle to attackers — require generic messages + distinct internal logs → Medium when violated.
- Constant-time comparison: the final check comparing presented-token digest against stored digest must use `crypto.timingSafeEqual` (Node) / `hmac.compare_digest` (Python) / equivalent. **Honest exploitability note:** the compared values are hashes; an attacker's input produces a uniformly random digest, so a memcmp early-exit leaks how many leading bytes match a value the attacker cannot aim — remote exploitation through network jitter is unrealistic in practice. Mandate it anyway: it costs one function call, removes an entire class of audit findings, and protects future refactors (e.g., someone adds a prefix-match shortcut). Non-constant-time compare → Low-to-Medium depending on what else is compared (comparing raw prefixes/user-visible identifiers raises it).
- Coarse field check (do not hammer production): time 20 requests with an invalid token of fixed shape and eyeball the spread — see Verification for the method and its caveats.

### 9. Logging & Monitoring of Token Use

- Never-log-full-token rule: no access log, app log, error tracker, or APM payload may contain the raw token. Safe fields: token PREFIX (first ~12 chars), token database id, client id, authenticated subject, source IP, UA, route, latency.
- Sweep actual logs (see Where To Look block): hits for `Bearer [A-Za-z0-9_.=-]{20,}` or `access_token=` → High finding, because log readership (ops, SIEM, log shipper, backups) is far wider than DB readership.
- Alerting hooks (cross-ref logging-monitoring module): per-key 401-rate anomaly, quota saturation, scope-denied bursts (`403` spikes indicate a compromised token probing boundaries), new-UA/new-geo per client id.

### 10. Client-Side Hygiene for Tokens You Distribute

- Public docs and quickstarts must show environment-variable loading, never inline literals; sample code containing plausible tokens gets flagged even when fake, because users copy it verbatim into repos (cross-ref SECRETS `checks/secrets-data-exposure.md`).
- Webhook signing secrets get the same lifecycle as tokens: CSPRNG generation, hash-at-rest, prefix identification, rotation with dual acceptance, constant-time HMAC verification. Brief here; depth in SECRETS.
- Distribution channel: tokens displayed once at creation; support tickets/email containing live tokens = High finding (goes into third-party mail stores).

### 11. Where Tokens Hide on the Host (Bridge to HSECRET)

Tokens you already issued tend to accumulate outside the token service:

- App config files: `.env`, `application.yml`, `settings.py` constants, JSON configs under `/opt/<app>` — check permissions (`600`, owned by service user) and content.
- systemd unit files: `Environment=` lines embed secrets in world-readable units; any local user can read them via the unit file itself or `systemctl show <unit> -p Environment` (unit properties are not gated by file DACs for typical installs). `/proc/<pid>/environ` is restricted to the owning user (or root) — so the exposure differs: unit-file `Environment=` leaks to *all* local users; process environ only to same-uid/root. Prefer `EnvironmentFile=` with a `600` root-owned or service-user-owned file, or a secret manager.
- Shell histories: operators doing `export API_TOKEN=...` leave credentials in `~/.bash_history`; check root and service-user histories during the host sweep.
- Full depth (dump hunting, CI artifacts, image layers) → HSECRET `checks/secrets-data-exposure.md`.

## Where To Look

Evidence collection: `tools/sweeps/sweep-api-tokens.sh` captures `[TOK-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

| Evidence | Location | Access |
|---|---|---|
| Minting + auth middleware source | repo: `auth/`, `middleware/`, `security/` dirs; search `Bearer`, `X-API-Key` | read |
| Schema truth | application DB `information_schema.columns` (not migrations — they drift) `[APP-DB]` | read creds |
| Token rows (metadata only) | `api_tokens`-equivalent table: prefixes, scopes, expiry, last-used `[APP-DB]` | read creds |
| Edge config | `/etc/nginx/nginx.conf`, `/etc/nginx/conf.d/*.conf`, Caddy/HAProxy equivalents | read |
| Service environment | `/etc/systemd/system/*.service` (`Environment=`, `EnvironmentFile=`), `systemctl show <unit> -p Environment` | read `[ROOT]` for show on root units |
| App config | `.env*`, `application.yml`, `settings.py`, `config/*.json` under `/opt`, `/srv`, app home | read |
| Process environment (same-user) | `/proc/<app-pid>/environ` | same uid or `[ROOT]` |
| Logs | `/var/log/nginx/access.log*`, app log dirs, journalctl for the service | read `[ROOT]` |
| Shell history | `/root/.bash_history`, `/home/*/.bash_history` | read `[ROOT]` |

Paste-ready read-only sweep (~15 lines):

```bash
# ===== [READ-ONLY SWEEP] token-bearing configs, env, logs on one host =====
sudo grep -RInE '(api[-_]?(key|token)|bearer|access[-_]?token|auth[-_]?token|secret)[-=_ ]+["'"'"']?[A-Za-z0-9_.+-]{16,}' \
  /etc/systemd/system /opt /srv /var/www 2>/dev/null | head -40
sudo grep -RHnE '^Environment=.*(TOKEN|KEY|SECRET|PASSWORD)' /etc/systemd/system 2>/dev/null | head -20
sudo find /opt /srv /etc /home -maxdepth 5 \( -name '.env' -o -name '.env.*' \) -exec stat -c '%a %U:%G %n' {} + 2>/dev/null
sudo ls -la /root/.bash_history /home/*/.bash_history 2>/dev/null
sudo grep -RhoE '(API_TOKEN|API_KEY|SECRET)[A-Z_]*=\S{8,}' /root/.bash_history /home/*/.bash_history 2>/dev/null | head
# --- full tokens hitting disk in logs? (counts per file) ---
sudo grep -REo 'Bearer [A-Za-z0-9_.=-]{20,}' /var/log/nginx /var/log/apache2 /var/log/apps 2>/dev/null | cut -d: -f1 | sort | uniq -c | head
sudo zgrep -hcoE '[?&](access_token|api_key|apikey|token)=[A-Za-z0-9_-]{8,}' /var/log/nginx/access.log* 2>/dev/null | paste -sd+ | bc
# --- DB schema introspection [REQUIRES APP-DB READ CREDS - request from owner; skip if unavailable] ---
# psql "$APP_DB_URL" -c "SELECT table_name,column_name,data_type FROM information_schema.columns WHERE column_name ~* '(token|api_key|secret)';"
# mysql -u"$DBUSER" -p"$DBPASS" -e "SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.COLUMNS WHERE COLUMN_NAME REGEXP 'token|api_key|secret';"
```

## Patterns & Signatures

### Canonical storage schema

```sql
-- FIXED: authoritative API-token table (PostgreSQL dialect)
CREATE TABLE api_tokens (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  client_id       BIGINT NOT NULL REFERENCES clients(id),
  token_prefix    VARCHAR(15) NOT NULL,        -- e.g. 'sk_live_Xk29fQ' : display/log-safe identifier
  token_hash      BYTEA NOT NULL,              -- SHA-256(raw token); raw value is NEVER persisted
  scopes          TEXT[] NOT NULL DEFAULT '{}',-- e.g. '{read:invoices,write:invoices}'
  tenant_id       BIGINT REFERENCES tenants(id), -- NOT NULL wherever objects are tenant-owned
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ,                 -- NULL only with documented compensating controls
  last_used_at    TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  rotated_from_id BIGINT REFERENCES api_tokens(id)
);
CREATE UNIQUE INDEX ux_api_tokens_token_hash ON api_tokens (token_hash);  -- O(1) lookup by digest
CREATE INDEX ix_api_tokens_client ON api_tokens (client_id);
CREATE INDEX ix_api_tokens_prefix ON api_tokens (token_prefix);
```

The prefix-column trick: the unique index lives on `token_hash`, so verification stays exact and collision-free; `token_prefix` exists only for humans — support tickets ("my key starting `sk_live_Xk29…`"), log correlation, and revocation hunts — without ever storing enough material to authenticate.

### Token minting

```javascript
// FIXED: 256-bit CSPRNG body + type prefix + integrity checksum (Stripe-style shape)
const crypto = require('crypto');
function mintToken(env /* 'live' | 'test' */) {
  const body = crypto.randomBytes(32).toString('base64url');            // 256 bits
  const raw = `sk_${env}_${body}`;
  const checksum = crypto.createHash('sha256').update(raw).digest('base64url').slice(0, 8);
  return { raw: `${raw}_${checksum}`, prefix: raw.slice(0, 12) };        // return raw ONCE; persist hash+prefix
}
```

```sql
-- VULNERABLE: any of these shapes in a mint/storage path is a finding
-- CREATE TABLE api_tokens (id ..., token TEXT NOT NULL, client_id ...);         -- plaintext column
-- token = md5(user_id || timestamp)                                             -- derivable base
-- SET token = SUBSTRING(MD5(raw), 1, 16)                                        -- truncated digest
```

### Auth middleware — Node/Express

```javascript
// VULNERABLE: plaintext lookup, == compare, immortal cache, no scope check
const tok = await db.query('SELECT * FROM api_tokens WHERE token = $1',
  [req.headers.authorization.slice(7)]);
if (tok && tok.rows[0].token === req.headers.authorization.slice(7)) { req.client = tok.rows[0]; next(); }
```

```javascript
// FIXED: hash-lookup flow + constant-time verify + revocation-aware cache
const crypto = require('crypto');
const authCache = new Map();                       // digestHex -> {row|null, validUntil}
const CACHE_TTL_MS = 60_000;                       // bounds revocation lag at <=60 s

async function authenticate(req, res, next) {
  const m = /^Bearer ([A-Za-z0-9_-]{40,})$/.exec(req.get('authorization') || '');
  if (!m) return res.status(401).set('WWW-Authenticate', 'Bearer').end();
  const presented = m[1];
  const digest = crypto.createHash('sha256').update(presented).digest();   // Buffer(32)

  let entry = authCache.get(digest.toString('hex'));
  if (!entry || entry.validUntil < Date.now()) {
    const r = await db.query(
      'SELECT * FROM api_tokens WHERE token_hash = $1 AND revoked_at IS NULL', [digest]);
    entry = { row: r.rowCount ? r.rows[0] : null, validUntil: Date.now() + CACHE_TTL_MS };
    authCache.set(digest.toString('hex'), entry);
  }
  const tok = entry.row;
  if (!tok || tok.revoked_at !== null ||
      (tok.expires_at && new Date(tok.expires_at) < new Date())) {
    return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').end();
  }
  if (!crypto.timingSafeEqual(digest, Buffer.from(tok.token_hash))) {      // constant-time end-to-end
    return res.status(401).end();
  }
  req.auth = { tokenId: tok.id, clientId: tok.client_id, scopes: tok.scopes, tenantId: tok.tenant_id };
  next();
}

function requireScope(s) {
  return (req, res, next) =>
    (req.auth && req.auth.scopes.includes(s)) ? next() : res.status(403).json({ error: 'insufficient_scope' });
}

// On revoke: authCache.delete(sha256Hex(revokedToken)); redis.publish('token_events', JSON.stringify({op:'revoke', id}));
```

### Auth dependency — Python/FastAPI (Django DRF: same flow as an `BaseAuthentication.authenticate()` returning `(user, auth)`)

```python
# VULNERABLE: raw-value ORM filter + != None checks leaking state via exception type
def get_client(request):
    raw = request.query_params.get("token", "")           # query-string carriage too
    t = ApiToken.objects.filter(value=raw).first()        # plaintext column
    if t is None:
        raise NotAuthenticated("unknown token")           # distinct error = enumeration oracle
    return t
```

```python
# FIXED: FastAPI dependency — hash lookup, constant-time compare, bounded cache
import hashlib, hmac, time
from fastapi import Request, HTTPException, status

_CACHE: dict[str, tuple[object, float]] = {}
_TTL = 60.0                                            # seconds; bounds revocation lag

async def bearer_auth(request: Request) -> AuthContext:
    authz = request.headers.get("authorization", "")
    if not authz.startswith("Bearer ") or len(authz) < 40:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
    presented = authz[7:].encode()
    digest = hashlib.sha256(presented).digest()
    now = time.monotonic()
    hit = _CACHE.get(digest.hex())
    if hit is None or hit[1] < now:
        row = await db.fetch_row(
            "SELECT * FROM api_tokens WHERE token_hash = $1 AND revoked_at IS NULL", digest)
        hit = (row, now + _TTL)
        _CACHE[digest.hex()] = hit
    tok = hit[0]
    if tok is None or tok["revoked_at"] is not None or (
            tok["expires_at"] is not None and tok["expires_at"] <= now_utc()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)   # identical body/timing shape for all causes
    if not hmac.compare_digest(digest, bytes(tok["token_hash"])):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
    return AuthContext(token_id=tok["id"], client_id=tok["client_id"],
                       scopes=tok["scopes"], tenant_id=tok["tenant_id"])
```

### Code-signature quick table (repo greps)

| Signature | Meaning |
|---|---|
| `req.query.token`, `request.query_params["api_key"]`, `parse_str($_GET['access_token'])` | query-string transport finding |
| `WHERE token = ?` against a non-`_hash` column | plaintext-storage path |
| `token === provided`, `== raw`, `.equals(` on strings | non-constant-time compare |
| `Math.random(...)` near token/key generation | non-CSPRNG minting |
| `cache.set('auth:' + token, ...)` with no matching delete in revoke code | revocation gap |
| `logger.info(...authorization...)`, `console.log(headers)` | full-token logging |

### Log-redaction pattern when legacy clients force query-string tokens

```nginx
# MITIGATION (not cure): drop the query string from logged request lines entirely
log_format safe '$remote_addr [$time_local] "$request_method $uri $server_protocol" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log safe;
```

```python
# App-side belt-and-suspenders: redact before any logger sink
class TokenRedactor(logging.Filter):
    _PAT = re.compile(r"(access_token|api_key|apikey)=([A-Za-z0-9_-]{4})[A-Za-z0-9_-]+")
    def filter(self, record):
        record.msg = self._PAT.sub(r"\1=\2***redacted***", str(record.getMessage()))
        return True
```

## Taint Tracing Guidance

For repo/config audits, trace the token as a taint from source to every sink and classify the representation at each hop.

**Sources (where a raw token enters a system):**

- `req.headers.authorization` / `request.headers["Authorization"]` / `request.META["HTTP_AUTHORIZATION"]` — expected source.
- `X-API-Key` or any custom credential header.
- `req.query.token`, `searchParams.get("access_token")`, Flask `request.args`, Django `request.GET`, PHP `$_GET[...]` — query-string transport finding at the source itself.
- Cookies carrying API tokens (cross-ref WEB CSRF).
- Ops-side: CLI flags (`--token=...`), shell exports, CI variables printed in build logs.

**Sinks (where a raw token must never land):**

1. Persistence: ORM `create()/update()`, raw INSERT/UPDATE, migration defaults writing the authenticable value into anything but a `*_hash` column → Critical sink.
2. Logs: any logger call receiving headers, request dumps (`JSON.stringify(req.headers)`), exception objects with attached auth context → High sink.
3. Responses/templates: echoing "the token you sent" in errors or debug pages → enumeration/material-leak sink.
4. Outbound propagation: URLs built for redirects/analytics containing the token; third-party SDKs initialized with the token in client-side code.
5. Config/repo: literals committed anywhere (cross-ref SECRETS).

**Procedure:**

1. Find the auth entry point (middleware/dependency/authentication class) — this is ground truth for representation.
2. Follow the token variable forward: classify each assignment as RAW or DIGEST. A single hop where RAW reaches persistence or logging is a finding; name file:line in the report.
3. Backward pass for minting: locate generator calls; confirm CSPRNG and length; flag derivable inputs.
4. Check comparison operations on the path: string equality operators are non-constant-time by definition.
5. Check cache writes keyed by RAW vs DIGEST and whether revoke deletes them.
6. For webhook signing secrets repeat steps 1–5 (same lifecycle).

## Exploitation & Reproduction

All demonstrations are read-only. Never paste discovered token values into reports — reference prefix + id.

**(a) Prove plaintext storage via schema dump.**

```sql
-- [APP-DB] read-only
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE column_name ~* '(token|api_key)' ORDER BY 1;
-- Finding shape: a column like api_tokens.token TEXT with NO sibling *_hash column,
-- while application code filters WHERE token = <presented value>.
SELECT length(token) AS len, count(*) FROM api_tokens GROUP BY 1 ORDER BY 2 DESC LIMIT 5;
```

Interpretation without reading values: lengths clustered at one uniform value matching the documented format (e.g., all rows `len=51`) show real minted material is stored whole; if instead only hashes were stored you would see a fixed `bytea`/32-byte column named `_hash`. Narrative for the report: an attacker with any DB read primitive (SQLi, exposed backup, misconfigured replica) obtains every customer's live credentials in one query — no cracking step exists because no hash step exists. That is why this is the Critical anchor of the module.

**(b) Prove query-string transport via access-log grep.**

```bash
sudo zgrep -hcE '[?&](access_token|api_key|apikey|token)=[A-Za-z0-9_-]{8,}' /var/log/nginx/access.log* | paste -sd+ | bc
sudo zgrep -hoE '^[^ ]+ [^ ]*\?[a-z_]*token=[A-Za-z0-9_-]{6}' /var/log/nginx/access.log | sort | uniq -c | head   # prefix only!
```

A count >0 is the finding; report the count and date range ("1,204 requests carried credentials in URLs over 30 days"), plus downstream blast radius: those same values sit in log shipping pipelines, SIEM retention, and any backup of `/var/log`. Referer leakage compounds it whenever browsers (not curl clients) use such URLs.

**(c) Prove the revocation gap by reading the cache code path.**

Read the middleware (Patterns section shows both shapes). Record: cache layer, key, TTL constant, and presence/absence of eviction in the revoke handler. Corroborate on-host when Redis is used (read-only commands):

```bash
redis-cli --scan --pattern '*auth*' | head            # key naming shows token-derived keys exist
redis-cli TTL "$(redis-cli --scan --pattern '*auth*' | head -1)"    # remaining validity of a cached entry
```

Narrative: operator revokes stolen token at T+0; attacker keeps full access until `TTL` elapses (state the measured number, e.g., "3600 s"). If the app runs N replicas each with in-process caches, revocation propagates only as fast as their TTLs — multiply the window accordingly. This converts "we revoked" (incident-closed) into "revocation lag = hours" (High finding).

**(d) Brute-force narrative with the math.**

An online guessing attack against the API needs no foothold — only patience and missing rate limits. The keyspace decides everything:

```text
8-char alphanumeric token (62-symbol alphabet):
  keyspace      = 62^8 = 218,340,105,858,848 ≈ 2.18e14 ≈ 2^47.6
  offline       : sha256 @ ~1e10 H/s (one GPU rig)  -> 2.18e14 / 1e10 ≈ 21,834 s ≈ 6 h     DEAD
  online        : @ 1,000 req/s, unthrottled        -> ≈ 6,927 years                      alive-but-noisy
  verdict       : fails the 128-bit floor by a factor of ~2^80; dead the moment any hash
                  database leaks, and trivially scannable even in plaintext dumps.

UUIDv4 token:
  keyspace      = 2^122 ≈ 5.3e36
  offline @ 1e10 H/s -> ≈ 1.7e19 years   -> entropy is fine; borderline flag is about format/handling.

32-byte CSPRNG token (the floor case):
  keyspace >= 2^128 ≈ 3.4e38; @ 1e12 H/s -> 3.4e26 s ≈ 1.1e19 years              ALIVE
```

Report template: "Token entropy measured at ~47.6 bits against the 128-bit floor; combined with absent per-key throttling (Check 7) this permits sustained online guessing at realistic rates; offline recovery is ~6 GPU-hours per token once any store leaks." Then fix design, not just rate limits.

## Remediation

### Migration plan: plaintext tokens → hashed (no downtime)

1. **Add columns** (`token_hash BYTEA`, `token_prefix VARCHAR(15)`, plus `expires_at`, `last_used_at`, `revoked_at` if missing). No unique index yet.
2. **Deploy dual-check auth (v1):** middleware verifies `SHA-256(presented)` against `token_hash` first; on miss, falls back to the legacy plaintext column; on legacy hit, immediately writes `token_hash` and blanks the plaintext column (progressive backfill on use — most active keys convert within hours).
3. **Backfill job** for idle keys, batched to avoid lock storms:

```sql
-- run in batches of ~10k until 0 rows updated
UPDATE api_tokens
   SET token_hash = sha256(convert_to(token, 'UTF8')), token_prefix = left(token, 12), token = ''
 WHERE token <> '' AND token_hash IS NULL;
```

4. **Verify:** `SELECT count(*) FROM api_tokens WHERE token <> '' OR token_hash IS NULL;` must be 0. Re-run step 3 if not.
5. **Deploy hash-only auth (v2):** remove the plaintext fallback path from middleware.
6. **Drop the plaintext column** in a maintenance window; rotate any token that cannot tolerate the transition (paranoid clients) via the rotation runbook below.

### Rotation runbook (zero-downtime overlap window)

1. Mint the replacement token with identical scopes/tenant binding; record `rotated_from_id`.
2. Deliver it out-of-band to the client (never email/ticket); display once.
3. Open an **overlap window** (e.g., 7 days): both old and new tokens validate. Implementation: simply do not revoke the old one yet; both rows authenticate independently.
4. Watch `old.last_used_at`: contact integrations still using the old key as the window closes.
5. At window end, revoke the old token (`revoked_at = now()`); keep the row for audit; confirm 401s appear only for holdouts you already contacted.
6. After the retention period, reap revoked/expired rows per policy.

Top operational mistake to warn about: revoking before replacements are live and confirmed — that is how "rotation" becomes an outage. The overlap window exists precisely to prevent it.

### Rate-limit config shapes

```javascript
// FIXED: express-rate-limit — IP gate BEFORE auth, per-key quota AFTER auth
const { rateLimit } = require('express-rate-limit');
const ipLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: 'draft-7' }); // unauthenticated surface
app.use('/api', ipLimiter);
app.use(authenticate);
const keyLimiter = rateLimit({
  windowMs: 60_000,
  max: (req) => req.auth.quotaPerMin ?? 600,          // sustained quota per key
  keyGenerator: (req) => String(req.auth.tokenId),     // stable per-client identity, NOT the raw token
  standardHeaders: 'draft-7',
});
app.use('/api', keyLimiter);
```

```nginx
# Edge complement — honest caveat: limit_req keyed on $http_authorization works mechanically,
# but nginx then stores RAW tokens as shared-memory keys (readable via debug/core dumps) and the
# key changes if clients vary header casing/padding. Prefer app-layer limiting keyed on token id;
# use the edge zone only as a coarse backstop, and always pair with an IP zone for junk traffic.
limit_req_zone $http_authorization zone=perkey_backstop:10m rate=600r/m;
limit_req_zone $binary_remote_addr    zone=perip:10m           rate=30r/m;
limit_req  zone=perip burst=20 nodelay;
```

Semantics to enforce: exceed → `429` with `Retry-After: <seconds>`; burst (token bucket) sized to absorb legitimate retries; sustained cap protects the backend; unauthenticated endpoints get their own tighter buckets (cross-ref API).

### Revocation-cache invalidation pattern

Choose one, state the tradeoff in the design doc:

- **Event invalidation (preferred):** revoke handler deletes locally AND publishes `token_events {op:'revoke', id}` on Redis pub/sub / Postgres `LISTEN-NOTIFY` / queue; every worker evicts on receipt. Revocation lag ≈ milliseconds; cost = subscription plumbing.
- **Short TTL bound (acceptable fallback):** cache TTL <= 60 s hard-coded and documented. Tradeoff stated plainly: any revoked token remains valid up to 60 s — acceptable only because the attacker window is short and bounded; never combine with long-TTL CDN caches of auth decisions.

Either way, the revoke code path must touch every cache layer identified during Check 6 — write the list down at incident time.

## Verification & Validation

Post-fix verify list:

1. Schema shows `*_hash` (BYTEA, 32 bytes) with UNIQUE index; no authenticable-value column remains: re-run the introspection query from Check 2.
2. Logs contain prefixes only: sweep block's Bearer regex returns zero hits over fresh traffic; sample app logs for header dumps.
3. Auth flow: valid token authenticates (positive test); wrong-but-well-formed token returns uniform 401 identical in body/size to expired/revoked responses (negative test); revoked token returns 401 within the documented bound (revoke a test token, poll with it, measure lag).
4. Timing uniformity rough test (with caveat):

```bash
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{time_total}\n' \
  -H 'Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' https://api.example.com/v1/me; done \
  | sort -n | sed -n '1p;$p'
```

Compare min/max spread against the same loop with a valid token. Treat results honestly: network jitter dwarfs nanosecond memcmp deltas; this test catches gross oracles (e.g., DB-miss vs DB-hit paths differing by tens of ms), not subtle ones. Absence of gross spread passes; subtle differences get noted, not failed.

5. Negative tests for scoping: read-only token hitting a write route gets 403 (not 404/500); tenant-A token requesting tenant-B resource gets 403/404 consistently.
6. Regression notes: after enabling per-key limits, confirm legitimate batch jobs are not 429-thrashing (watch Retry-After compliance); after TTL/cache changes, confirm auth p95 latency unchanged.

CI/config-repo greps (fail build on hits):

```bash
! git grep -InE "(Math\.random|random\.random)\(\).*([Tt]oken|[Kk]ey)"        # non-CSPRNG minting
! git grep -InE "req\.(query|query_params)\.(get\()?['\"](access_token|api_key|token)['\"]"
! git grep -InE "(authorization|Bearer).*(logger\.|console\.|print\()"       # full-token logging
git grep -qIn "timingSafeEqual\|compare_digest" -- server/ src/              # constant-time compare present
```

## Severity Assessment

| Finding | Anchor | CVSS v3.1 vector | Score / note |
|---|---|---|---|
| Plaintext/reversible tokens in DB serving an internet API | Critical | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8. PR:N assumes chaining with a DB read primitive (SQLi, leaked backup) — treat as present until the audit proves otherwise; if genuinely no read primitive exists, re-score honestly as `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` = 6.8 and keep the finding visible |
| No expiry AND no revocation path (or revocation lag unbounded by cache invalidation) | High | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 — any single leak is permanent; PR:L models the holder of one long-lived key |
| Full tokens written to logs (access/app/SIEM) | High | `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 7.3 — log plane readership adjacent-network model |
| Query-string token transport on internet endpoints | High | `AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` | 7.0 — passive capture via logs/Referer/history |
| Low-entropy minting (<128 bits) or non-CSPRNG randomness | High | derive from context: offline-recoverable → rate as storage-Critical chain; online-guessable + unthrottled → `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 8.1 with throttle absent |
| God-token shared across integrations / no scoping | High | qualitative privilege-breadth gap; nearest anchor `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 when admin scopes ride the same key | report breadth explicitly |
| No per-key rate limits / missing 429 semantics | Medium | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | 4.8 |
| Missing last-used tracking / stale-key hygiene | Medium | qualitative — detective-control gap; CVSS cannot express exposure-duration extension | policy Medium: it silently extends dwell time of every other flaw |
| uuid4-only tokens; derivable metadata in tokens | Borderline/Low-Med | entropy math decides (122 bits passes brute force; format/handling flags remain) | flag, do not cry Critical |
| No type prefix/checksum in token format | Low | qualitative — operational identification/scanability gap; no direct confidentiality impact | policy Low |

## Common False Positives

- **mTLS certificate auth replacing tokens.** Client certs are a different authenticator model; do not demand token hashing/prefixes. Still verify the analogous lifecycle: a CRL/OCSP path that actually shortens trust on compromise, cert rotation runbook, and CN/SAN mapping to scopes. If CRL/OCSP is unreachable at runtime, that is the real finding.
- **Internal-only APIs behind VPN/mesh.** Token weaknesses stand, but severity downgrades for exposure-dependent anchors (transport, enumeration, rate limits): document the network boundary as the compensating control, downgrade one level max for storage findings — plaintext stays at least High because insiders and backups exist.
- **Opaque session cookies misread as API tokens.** Browser session cookies (`connect.sid`, `sessionid`, framework defaults) belong to the web-session model — audit them under AUTHN/WEB (`checks/authn-session.md`, `checks/web-client.md`), not here. Do not file "token stored plaintext" against a server-side session store keyed by random cookie id.
- **JWTs mistaken for opaque tokens.** If the "API token" is structurally a JWT (three dot-separated segments), its risks are signature/validation risks audited by AUTHN (`checks/authn-session.md`); from this module only carry over the transport/scoping/logging checks.
- **Encrypted-at-rest token columns.** Reversible encryption is a mitigation claim, not innocence: verify key custody before accepting a downgrade below High (see Check 2 verdict rules).

## References

- RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage (transport rules, `WWW-Authenticate` error semantics): <https://www.rfc-editor.org/rfc/rfc6750>
- NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management (authenticator entropy, storage, verifier requirements): <https://pages.nist.gov/800-63-3/sp800-63b.html>
- OWASP Authentication Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- OWASP REST Security Cheat Sheet (token carriage, TLS-only, caching of auth decisions): <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- OWASP Secrets Management Cheat Sheet (distribution, rotation, webhook signing secrets): <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- OWASP API Security Project (A02 Broken Authentication family context): <https://owasp.org/www-project-api-security/>
- CWE-522 Insufficiently Protected Credentials: <https://cwe.mitre.org/data/definitions/522.html>
- CWE-307 Improper Restriction of Excessive Authentication Attempts: <https://cwe.mitre.org/data/definitions/307.html>

Internal cross-references: JWT/session deep-dive → `checks/authn-session.md`; CSRF consequences of cookie-carried credentials → `checks/web-client.md`; API-wide abuse controls → `checks/api-security.md`; host-side secret sprawl → `checks/secrets-data-exposure.md`; edge TLS enforcement → `checks/server/tls-proxy.md`; volumetric thresholds → `checks/denial-of-service.md`.




