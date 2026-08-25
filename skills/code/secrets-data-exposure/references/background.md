# Secrets & Data Exposure — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no prior security background assumed. Teaches the *why*; SKILL.md keeps the
fingerprint tables, sweep scripts, and rotation runbooks.

## How this class emerged

Credentials lived in source code for decades because programs needed them and
version control made copying convenient. Three shifts turned that habit into an
industry-scale problem:

- **Public code hosting.** Once forges made every repository browsable,
  automated harvesters began watching for credential-shaped strings; keys
  pushed to public repos are picked up within minutes, not days. Scanning the
  same patterns became a defensive discipline (regular-expression engines such
  as secret scanners, plus forge-side push blocking).
- **Immutable history.** Git stores every version of every file as permanent
  objects. A secret removed in commit N remains fully recoverable from commits
  before N until garbage collection — and clones, forks, and CI caches keep
  copies regardless. Deletion is not revocation.
- **The logging and analytics era.** Debug prints became centralized,
  long-retention log databases. Anything interpolated into them — request
  bodies, Authorization headers, exception text — became a durable copy of
  sensitive data outside every access control around the original store.

Supply-chain incidents closed the loop on consequence: leaked maintainer
credentials led to the 2018 hijacking of the npm `event-stream` package, where
a new owner introduced malicious code that was then distributed to countless
downstream builds — one leaked token, ecosystem-wide blast radius. Regulatory
regimes (GDPR effective 2018) simultaneously raised the cost of PII sprawl in
logs, exports, and backups.

## Anatomy

A single committed value hops trust boundaries forever:

```yaml
# config/database.yml  -- committed by accident
production:
  host: db.internal.corp
  username: app_rw
  password: "hunter2-real-value"
```

Walkthrough of the hop chain:

1. **Created** next to code because it was convenient during development.
2. **Committed** — the value is now a blob reachable from any past revision;
   `.gitignore` added afterwards changes nothing about existing history.
3. **Built** — if injected at compile time, the value also lands in shipped
   artifacts (`dist/*.js`, mobile packages); client-bundle env prefixes make
   this automatic.
4. **Deployed/Observed** — a stack trace or debug endpoint echoes connection
   details; a logger prints config objects into retained log storage.
5. **Compromised** — anyone with any copy (clone, fork, backup, log index) can
   authenticate as the application against production.

Rotation is the only cure after exposure: revoke at the provider, issue a new
value through runtime injection, *then* optionally rewrite history to shrink
future blast radius. Purging without rotating leaves every existing copy live.

## Why naive fixes fail

One subsection because the recurring errors are structural:

- **Deleting the file in a later commit** leaves the blob recoverable; history
  retains everything ever committed.
- **Adding `.gitignore` after the fact** prevents future tracking only.
- **Obfuscation (Base64/hex/split strings)** is encoding, not encryption —
  reversible by anyone, and scanners decode routinely.
- **"Private repo means safe"** ignores employees, contractor tokens, future
  breaches, and repos flipped public or mirrored.
- **Entropy scanning alone** misses low-entropy real passwords bound to secret-
  named variables ("password123" authenticates fine).
- **Rotating only the obvious copy** leaves duplicates in CI variables, teammate
  clones, ticket text, and backup archives live.
- **Client-side env prefixes as build magic**: anything under framework-public
  prefixes ships to every visitor's browser by design — treat as published.

## Common misconceptions

1. "We deleted it from the repo, so we're fine." History, forks, clones, and CI
   caches retain blobs; rotation must come first and cannot be undone later.
2. "Base64/Kubernetes Secrets encode, so it's protected." Both are readable
   rewrites; anyone with the artifact gets the plaintext.
3. "Our scanner found nothing, so nothing is there." Pattern coverage is finite:
   custom internal formats, low-entropy passwords, and split-string assembly
   pass silently. Clean scans lower suspicion, never prove absence.
4. "Logs are ephemeral." Aggregators, retention policies, and crash-reporting
   breadcrumbs turn log lines into long-lived searchable copies of secrets/PII.
5. "PII in API responses is fine because the user is authenticated."
   Over-exposed fields (`password_hash`, `otp_secret`) ride along on self-
   responses and leak whenever any read path mis-scopes.
6. "Publishable/test keys are leaks." Keys designed for public embedding
   (`pk_live_`, sandbox tokens) and vendor-documented sample values are noise —
   flag misuse and restriction gaps, not existence.
7. "History rewrite substitutes for rotation." Rewrite shrinks future exposure;
   every copy scraped before the purge stays compromised until rotated.

## How professionals think about it today

Practice models the problem as lifecycle hops plus data classification,
matching SKILL.md's structure:

| Branch | Core question | Defining control |
|---|---|---|
| Hardcoded credentials | Where does the value originate? | secret managers + runtime injection; no literals in tracked files |
| VCS history & artifacts | Did a hop already happen? | mandatory-first rotation; history purge as cleanup; full-history scans in CI |
| Client-shipped values | Does the bundle contain it? | grep built output, not just source; public-prefix hygiene |
| Runtime disclosure | Do endpoints echo internals? | generic errors; debug switches off; management surfaces locked |
| Logging leakage | What reaches the log sink? | redaction middleware; structured logging; header scrubbing |
| Response over-exposure | Which fields serialize? | DTO allowlists per role; deny-by-default tags |
| Data at rest | Is stored data classified and protected? | column encryption, CVV prohibition, masked exports, locked backups |

Two professional habits: triage candidates rather than dropping them (entropy
and fingerprints are signals, verdicts need context — when unsure, mark
Needs-Review), and classify exposed data so severity tracks harm (contact PII <
government IDs < health/financial < biometrics). Compliance hooks are factual
constraints, not severity decoration: storing card verification codes after
authorization is prohibited outright by PCI DSS regardless of exploitability.

## Read next

In `../SKILL.md`: **Mental Model** (the six-hop exposure table), **What To
Check** (per-surface procedures), **Patterns & Signatures** (ready-to-run
triage sweep and fingerprint table), **Taint Tracing Guidance**
(definition-site -> leak-sink flows), **Remediation** (manager integration,
rotate-vs-rewrite rule, DTO allowlists, redaction middleware),
**Common False Positives** (public keys, sample values, test-mode tokens).

Sibling modules: `../authn-session/SKILL.md` (credential strength and reset
flows consuming these secrets), `../crypto/SKILL.md` (encryption at rest and
key management depth), `../configuration-hardening/SKILL.md` (debug switches
and management surfaces), `../supply-chain/SKILL.md` (leaked publishing tokens
becoming package-level compromise), `../api-security/SKILL.md` (response
shaping at the API layer).
