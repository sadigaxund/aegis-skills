# API Token Security — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind minting entropy, hash-only storage, transport rules, scoping,
rotation/revocation, and leak response; SKILL.md carries the exact schema
shapes, middleware patterns, and evidence commands.

## How this class emerged

Machine-to-machine authentication grew out of simple API keys in the early
web-services era: generate a string, hand it to a customer, look it up on every
request. The bearer model was formalized when the OAuth framework and its bearer
usage specification were published in 2012 — including, notably, explicit
warnings that tokens passed in URLs end up in logs, browser history, and
referral headers. A decade later those warnings describe some of the most common
findings in exactly the form they predicted.

The storage question has its own history. Password databases learned the hard
way that human-chosen secrets need deliberately *slow* hashing functions:
key-derivation designs from the late 1990s onward (bcrypt and successors,
memory-hard functions crowned by a public competition in the mid-2010s) exist to
make offline guessing expensive. That history created an overgeneralization —
"hashing credentials means slow hashing" — which this module's central insight
corrects:

- **Entropy decides the hash.** A token minted from a cryptographic random
  generator with at least 128 bits of unpredictability has no guessable
  structure. Inverting even fast SHA-256 over it requires searching more than
  two-to-the-128 candidates — infeasible for any realistic adversary. Slow KDFs
  add nothing except latency on the hottest code path.
- **Low-entropy inputs are fatal either way.** Hashing a short or derivable
  value with any function merely decorates the weakness; the keyspace stays
  guessable once any store leaks.

Meanwhile, breach after breach involving plaintext credential columns pushed the
industry toward store-the-hash-only as the default posture, prefix-plus-checksum
formats (popularized by large platforms so leaked strings can be recognized and
scanned automatically) became expected hygiene, and secret-scanning tooling now
assumes such prefixes exist. Rotation matured operationally too: zero-downtime
overlap windows replaced switch-and-pray cutovers that turned routine rotations
into outages.

## Anatomy: one weak table, every customer compromised

A minimal generic weak implementation:

```sql
CREATE TABLE api_tokens (
  id     SERIAL PRIMARY KEY,
  client INTEGER NOT NULL,
  token  TEXT    NOT NULL        -- the authenticable value itself
);
```
```
GET /v1/invoices?access_token=sk_live_9f3ac2...   # token in the URL
# auth middleware:
SELECT * FROM api_tokens WHERE token = $1         # plaintext lookup
```

Walkthrough of how this fails:

1. Any read primitive against the database — a SQL injection bug, a leaked
   backup, a misconfigured replica — returns every customer's live credentials
   in one query. No cracking step exists because no hash step exists.
2. The same values are already sitting elsewhere: query-string carriage put them
   into access logs, log-shipping pipelines, SIEM retention, and any backup of
   the log directory. Readership of logs is far wider than readership of the
   database.
3. Nothing bounds lifetime (`expires_at` all NULL) or use: no per-key quota
   means a replayed token can pull data at line rate until someone notices.
4. When the leak is finally discovered, revocation works — but any cache in
   front of the lookup keeps honoring the dead token until its TTL elapses, so
   "we revoked" quietly means "revoked within N seconds," where N is whatever
   nobody measured.
5. Because one shared key serves every integration for each client, rotation
   means coordinating every consumer simultaneously or breaking them.

Each step is a lifecycle-stage failure, which is why this module audits the
whole chain rather than any single control.

## Why naive fixes fail

- **Encrypting instead of hashing.** Reversible encryption keeps the key next
  door in application config; any app-level read primitive collapses the
  control. It is plaintext-equivalent under key compromise, not protection.
- **Applying password-style slow hashes to tokens.** Argon2/bcrypt on a
  ≥128-bit random input buys nothing and multiplies CPU cost per request on the
  hottest path — inviting denial-of-service on your own auth endpoint.
- **Revoking at the database while caches forget to evict.** Every layer between
  check and authority (in-process maps, Redis, CDN-cached decisions) must be
  touched by the revoke path, or bounded by a documented short TTL.
- **Hard-cutover rotation.** Replacing a token before replacements are live and
  confirmed converts housekeeping into downtime. The overlap window — both
  tokens valid while clients migrate — exists precisely to prevent this.
- **Helpful error messages.** Distinguishing "expired" from "unknown" in
  responses builds an enumeration oracle; keep bodies uniform and push detail
  to internal logs.
- **Logging tokens for debugging.** Full-token lines in access or application
  logs re-broaden every other control's failure; prefix-and-id fields give the
  same correlation value without the material.

## Common misconceptions

1. "Proper token hashing means bcrypt or argon2." The algorithm follows the
   input: slow KDFs defend guessable human secrets; high-entropy random tokens
   need only pre-image resistance, which SHA-256 provides.
2. "We encrypt tokens at rest, so we're fine." Encryption is a mitigation claim
   contingent on key custody — verify where the key lives before accepting any
   downgrade below the storage finding.
3. "TLS makes transport choices irrelevant." HTTPS protects the wire, not the
   destination: query-string tokens still land in server logs, browser history,
   and Referer headers on outbound links.
4. "Revoked tokens stop working immediately." Any positive-TTL cache between
   check and authority converts revocation into delayed revocation; quantify the
   lag from code, always.
5. "UUID-based tokens are a vulnerability." Their 122 random bits are
   practically unguessable; the honest flags are format ones — no type prefix,
   no checksum, and reuse of the same string shape in non-secret contexts.
6. "A single shared key per customer is simpler for everyone." It maximizes
   blast radius, blocks scope separation, and makes rotation a coordination
   event; per-client scoped keys cost little and bound damage.
7. "Rate limits are an anti-abuse nicety." Per-key quotas are also detection:
   guessing attempts, replay spikes, and stolen-key exfiltration all trip them.

## How professionals think about it today

Modern practice audits the full lifecycle — an attacker needs exactly one valid
token, and every stage is a different place to get one. The taxonomy mirrors
SKILL.md's own lifecycle-stage view:

| Lifecycle stage | Typical flaw | Defining control |
|---|---|---|
| Mint | low entropy, non-CSPRNG, derivable bases | ≥128 bits CSPRNG; prefix + checksum format |
| Store | plaintext or reversible columns | hash-only (`SHA-256`), unique index, prefix column |
| Transport | query-string carriage, plain HTTP | header carriage, TLS-only enforcement |
| Scope | god tokens, self-asserted claims | per-client scopes, tenant binding, middleware enforcement |
| Expiry & rotation | immortal tokens, cutover breakage | finite lifetimes, last-used tracking, overlap windows |
| Revoke | caches without invalidation | event invalidation or bounded TTL, measured lag |
| Limit | unthrottled keys, no 429 semantics | burst + sustained quotas, Retry-After |
| Enumeration | cause-revealing errors, timing tells | uniform 401 shape, constant-time compare |
| Log | full tokens in logs | prefix/id-only fields, anomaly alerts |
| Distribute | hardcoded samples, email/ticket delivery | env-var guidance, display-once channels |

Severity chains aggressively: low-entropy minting plus absent throttling equals
online-guessable credentials; plaintext storage plus any DB-read primitive
equals total compromise — classify findings by which link they break, not in
isolation.

## Read next

In `../SKILL.md`: **Scope & Objectives** (ten domains), **Mental Model**
(attacker-goals table and the two driving insights), **What To Check** (design,
storage, transport, scoping, expiry, revocation, limits, enumeration, logging,
distribution, host sprawl), **Where To Look** (sweep block and artifact table),
**Patterns & Signatures** (canonical schema, mint/middleware pairs, redaction
patterns), **Taint Tracing Guidance** (raw-vs-digest classification procedure),
**Exploitation & Reproduction** (schema/log/cache proofs and the brute-force
math), **Remediation** (zero-downtime migration, rotation runbook, limiter
shapes), **Verification & Validation**, **Severity Assessment**, **Common False
Positives** (mTLS, session cookies, JWT confusion).

Sibling modules: `../tls-proxy/SKILL.md` (the edge enforcing TLS-only and header
hygiene), `../host-secrets/SKILL.md` (where issued tokens accumulate on hosts),
`../logging-monitoring/SKILL.md` (wiring the anomaly alerts), and the code-side
playbooks this module defers to: `skills/code/authn-session/SKILL.md` (JWT and
session mechanics), `skills/code/api-security/SKILL.md` (endpoint abuse beyond
authn), `skills/code/secrets-data-exposure/SKILL.md` (repo/config secret
hunting).
