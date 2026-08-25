---
name: baas-platform-checks
description: Audits Backend-as-a-Service and managed-platform configuration - Supabase RLS, Firebase security rules, connection-string databases, serverless host exposure, payment-webhook integrity, and managed CMS posture - for broken-access-control footguns that expose or corrupt production data.
category_slug: BAAS
cwe: [CWE-284, CWE-16]
owasp: A01:2021 – Broken Access Control
---

## Scope & Objectives

This module audits the managed platforms where modern products actually run. It is configuration-first: the platform vendor secures its infrastructure; the application owner secures everything configured on top of it, and on every platform below there is a default whose failure mode equals full-database compromise.

**Shared-responsibility baseline.** The vendor patches Postgres, scales Firestore, signs TLS, and operates the control plane. You own, without exception:

- Row Level Security (RLS) enablement and policy quality on every table.
- Security rules files (Firestore / Realtime Database / Storage).
- Network access lists and credential hygiene on connection-string databases.
- Which environment variables reach the browser and who can open preview deployments.
- Whether fulfillment logic verifies provider signatures before granting anything.
- CMS core/plugin/theme lifecycle and hardening constants.

**In scope:** Supabase; Firebase (Firestore, Realtime Database, Storage); connection-string-only platforms (Neon, Supabase-Postgres direct connections, Railway, Render, Upstash, MongoDB Atlas); serverless hosts (Vercel, Netlify and similar); Stripe-shaped payment webhooks; WordPress-class managed CMS.

**Out of scope:** cloud IAM deep dives (see the IAM module), TLS/certificate posture, DNS takeover (dedicated module), mobile-specific storage.

**Objectives — produce a finding only when you can name the artifact:**

1. Detect every data surface reachable by the anonymous/public identity without authorization logic (RLS off, permissive rules, 0.0.0.0/0 allowlists).
2. Detect privileged material (service_role keys, service-account JSON, Upstash REST tokens, connection strings) reaching clients, bundles, or VCS — cross-reference the SECRETS module.
3. Verify payment-webhook handlers verify provider signatures, recompute amounts server-side, and dedupe deliveries idempotently.
4. Verify host-level exposure: preview deployment protection, published source maps, header/redirect misconfigurations.
5. Verify CMS update posture and hardening constants.
6. Mark every live-data probe `requires-db-credentials` or `authorized-only`; prefer static evidence from repo artifacts first because console or database access is often unavailable to the auditor.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **RLS (Row Level Security)**: database feature deciding which rows each user may read or write
- **anon key**: the public Supabase key shipped in every browser bundle; safe only while RLS guards every table
- **service_role key**: master key that bypasses RLS entirely; must never reach client code
- **security rules**: Firebase's configuration file deciding who may read or write each collection and file
- **preview deployment**: auto-generated public URL per branch that can leak staging data and variables
- **webhook signature verification**: checking the payment provider cryptographically signed a callback before granting anything
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Five invariants drive every check in this module:

1. **The public client key is public by design.** The Supabase anon key ships in every browser bundle. RLS is therefore the *only* boundary between the internet and your tables. Any table without RLS enabled is world-readable AND world-writable through PostgREST, regardless of how "internal" it looks in the schema.
2. **Platform defaults favor onboarding speed, not security.** New Supabase tables ship with RLS disabled; blank Firebase rule sets have historically been permissive test-mode; Mongo Atlas accepts `0.0.0.0/0` network access with one click. Assume defaults are wrong until proven otherwise.
3. **Anything inside the browser bundle is attacker-readable.** Env prefixes (`NEXT_PUBLIC_`, `VITE_`, `NUXT_PUBLIC_`) are compile-time public-by-construction; so is any secret accidentally prefixed, bundled, or shipped in a source map.
4. **Any URL that renders content without authentication is attacker-reachable.** Preview deployments mint a public URL per branch by default, carrying staging data and preview-scoped env vars.
5. **An endpoint granting value must prove the sender and dedupe replays.** An unauthenticated webhook route that upgrades accounts after reading attacker-supplied JSON is the classic vibe-coder Critical.

Platform footgun matrix:

| Platform | Footgun | Detection | Hardened state |
|---|---|---|---|
| Supabase | New tables default to RLS OFF; anon key public by design | Migrations scan (`create table` with no following `enable row level security`); `pg_tables` introspection (`requires-db-credentials`) | RLS enabled + owner-scoped policies covering select/insert/update/delete; documented exceptions only |
| Supabase | `service_role` bypasses RLS entirely | Grep client code/bundles/env for the key reaching frontend (cross-ref SECRETS) | Key exists only in server-side runtime env; rotated if ever client-exposed |
| Firebase | `allow read, write: if true` scaffolding; forgotten Storage rules file | Review `*.rules`; emulator/simulator evaluation | Auth-scoped granular rules, simulator-tested, Storage rules reviewed same session |
| Firebase | Test-mode expiry timer past date = permanently open | Parse `request.time < timestamp(X)` against current date | Rules migrated off test timers before expiry; prod rules never rely on time alone |
| Neon/Railway/Render/Upstash/Atlas | Public endpoint + credentials-in-connection-string auth; Atlas accepts `0.0.0.0/0` | Connection-string scan; access-list config review | TLS-enforced strong credentials; IP-restricted or private networking; tokens never in clients |
| Vercel/Netlify | Every branch gets a public preview URL by default | Deploy logs/commit-status hosts; unauth fetch probe | Deployment protection enabled for all non-production targets |
| Payment webhooks | Unsigned handler grants entitlements from client JSON | Handler code review: `constructEvent` absent | Signature verification + event-type allowlist + consumed-once idempotency |
| WP-class CMS | Stale plugins, admin file editor on, `xmlrpc.php` open | `wp-config.php` review; authorized curl probes | Patched components, editing disabled, xmlrpc off, application passwords, debug off |

Corollary used throughout What To Check: **rules are not filters** (Firebase) and **policies are not presence** (Supabase). A rule that does not constrain the query shape cannot rescue a broad query; a policy that merely exists but says `using (true)` protects nothing. Presence of the control is checked separately from quality of the control.

## What To Check

Work platform by platform. A finding is complete only when it names the failing control and the artifact that proves it (migration file, rules file, handler route, config constant). Static evidence first; live probes only per Exploitation & Reproduction.

### Supabase

- **RLS enablement (the flagship check).** Scan every SQL migration for `create table` statements in the `public` schema and verify a following `alter table <schema>.<table> enable row level security;` exists in the same migration set or any later one. Absence = world-readable AND world-writable via PostgREST using the anon key.
- **Live-database confirmation (`requires-db-credentials`).** When database credentials are supplied, run:

  ```sql
  -- requires-db-credentials: live RLS state, read-only
  select schemaname, tablename, rowsecurity
  from pg_tables
  where schemaname = 'public'
  order by tablename;
  ```

  Every row must show `rowsecurity = true`, or carry a documented decision that the table is intentionally public.
- **Policy quality.** For each RLS-enabled table, audit the `create policy` statements:
  - Flag scaffolding placeholders: policies whose expression is `using (true)` or `with check (true)` with no role or ownership predicate.
  - Verify predicates reference identity correctly: `auth.uid() = user_id` / `owner_id` column comparisons, not free variables that never bind.
  - Map coverage per operation: a table readable only through a `for select` policy still allows anonymous INSERT/UPDATE/DELETE attempts to be evaluated against no policy (denied) — but the inverse is the killer: write-capable policy with no select policy, or an UPDATE policy missing its `with check` half, letting rows be moved to another owner. Enumerate which of `for select / insert / update / delete` have policies and whether each gap is intentional.
- **service_role exposure.** The service_role key bypasses RLS entirely. Grep client code, committed bundles, `.env*` files consumed by frontend builds, and any `NEXT_PUBLIC_`/`VITE_` prefixed variable for the service_role value or its variable name (cross-ref SECRETS). Any hit = full unauthenticated database compromise once the bundle ships.
- **Storage buckets.** Inspect bucket creation migrations (`insert into storage.buckets ... public true`) and `storage.objects` policies. Public buckets are legitimate for avatars-by-design but must be documented; flag undocumented public buckets holding non-public object classes. Remember storage access also evaluates RLS on `storage.objects` — over-broad policies there leak every bucket.
- **Edge functions secrets.** Edge functions should read secrets from the runtime-managed secrets store (e.g., `Deno.env.get(...)`), never from hardcoded literals or files inside the function directory that get bundled.

### Firebase

- **Rules file review.** Read every rules file: `firestore.rules`, `storage.rules`, `database.rules.json`. Flag these shapes:
  - `allow read, write: if true;` — fully open.
  - `allow read, write: if request.auth != null;` — better, but grants *any* authenticated user *any* document; flag when data is per-user.
  - Missing `request.auth != null` on write paths.
  - Wildcard path grants like `match /{document=**}` applied project-wide, or broad segment wildcards (`match /data/{id}`) where sub-collections intended narrower scope.
  - Separate-operation gaps: `allow read` granted while `write` is split into create/update/delete with only some covered.
- **Rules are not filters.** A rule cannot rescue a query that asks for broader data unless the rule itself constrains the query shape: if the client issues a collection query without the constraint the rule checks per-document, Firestore rejects the whole query rather than filtering results. Conversely a permissive rule plus a narrow client-side filter equals a leak — anyone queries directly. Audit rules as the authority, never the client code's query habits.
- **Storage rules are a separate file, often forgotten.** Projects harden Firestore and leave `storage.rules` at test-mode openness. Review it in the same pass; flag uploads readable/writable by `request.auth == null`.
- **Test-mode expiry timers.** Scaffolded test rules end in `allow read, write: if request.time < timestamp(<future-date>);`. Parse the date; if it is in the past, the rule is inert-but-open depending on surrounding matches — treat expired-timer-plus-permissive-fallback as open. If future-dated, note the expiry date in the finding and require migration before expiry.
- **Admin SDK / service accounts.** Flag any `*-firebase-adminsdk-*.json`, `serviceAccountKey.json`, or tracked JSON containing `"type": "service_account"` and a `"private_key"` field (cross-ref SECRETS). Also flag Admin SDK initialization imported into client-reachable code paths.

### Connection-String Databases (Neon / Railway / Render / Upstash / Mongo Atlas)

- **Default endpoint publicity.** These platforms provision internet-reachable endpoints; the connection string's credentials are the ONLY authentication. Treat every committed or logged connection string as a full-compromise credential (cross-ref SECRETS).
- **TLS enforcement.** Verify TLS is mandatory, not optional: Postgres-family strings should carry `sslmode=require` or stronger (not `sslmode=disable`/`prefer`); Redis-family connections should use TLS endpoints; Atlas enforces TLS by default — confirm nothing downgrades it.
- **Upstash REST tokens.** Upstash REST API tokens are bearer credentials: possession = full data access including writes. Flag them anywhere near client bundles, mobile apps, or browser-exposed env prefixes; they belong server-side only.
- **Mongo Atlas network access list.** The classic trap: project network access list containing `0.0.0.0/0` (allow from anywhere). Console screenshots described by the user count as evidence; repo-side, look for Terraform/CLI provisioning of access lists with world-open CIDRs. Recommend specific egress IPs or private endpoints.
- **Credential sprawl.** Check how many distinct copies of `DATABASE_URL` / `MONGO_URL` / `REDIS_URL` exist across shell scripts, CI logs, docker-compose environment blocks, and preview-environment configs; each copy is another leak surface.

### Serverless Hosts (Vercel / Netlify)

- **Env var scoping.** Variables prefixed `NEXT_PUBLIC_`, `VITE_`, or `NUXT_PUBLIC_` (and equivalents) are inlined into the browser bundle at build time — they are published values, not configuration (cross-ref SECRETS; this trap is named here once and pointed to). Grep those prefixes for secret-shaped names (keys, tokens, URIs with credentials).
- **Preview deployments.** By default every git branch/push gets a publicly fetchable deployment URL carrying staging data and preview-scoped env vars. Verify protection is enabled via console guidance phrasing: in the host's project settings, deployment-protection options (SSO-gated access, shared password, bypass-token schemes) must cover all preview/branch deployments, not just production. If the user provides console screenshots, read them for the protection toggle state.
- **Source maps.** Production source maps published to the browser hand attackers your original source. Check `next.config.js` for `productionBrowserSourceMaps: true`, build scripts emitting maps into the publish directory, and confirm by fetching `<bundle>.js.map` from production (authorized target).
- **Header and redirect misconfigurations.** Review `vercel.json` / `netlify.toml` / `_headers` / `_redirects`: wildcard catch-all rewrites that mask internal routes, redirects with `!` negation mistakes creating open redirects, missing security headers (CSP, X-Frame-Options) on all routes.
- **Environment sprawl across environments.** Preview/prod env divergence means a secret removed from production may still live in preview context — reachable through the unprotected preview URL. Inventory which variables exist per environment and prune.

### Payment Webhooks (Stripe-Shaped, Generic Pattern)

- **Signature verification is mandatory before granting anything.** Fulfillment endpoints MUST verify the provider signature over the RAW request body using the endpoint signing secret. Stripe shapes, name them confidently:
  - Node: `stripe.webhooks.constructEvent(rawBody, sigHeader, endpointSecret)` — throws on failure; reject with 4xx.
  - Python: `stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)` — raises `ValueError` (payload parse) or `stripe.SignatureVerificationError`; reject with 4xx.
  - Flag handlers that parse JSON first (`express.json()` before the raw-body capture, `request.get_json()` then re-serialize) — signature verification fails or is silently skipped.
- **Never trust prices/amounts/currency from the client.** Recompute totals server-side from the catalog/price IDs known to the provider. On return/redirect, validate the checkout session server-side (retrieve the session by ID from the provider, not from client-supplied fields) before granting entitlements.
- **Idempotent fulfillment.** Providers retry deliveries. Dedupe by event ID with a consumed-once table: insert the event ID inside the same transaction as fulfillment; unique-violation = already processed = return success without re-granting.
- **Event-type allowlist.** Handle only event types you explicitly define (`checkout.session.completed`, `invoice.paid`, ...); ignore-and-ACK everything else. Flag switch/if chains acting on arbitrary `event.type` strings with default-grant behavior.
- **The classic vibe-coder Critical:** an unauthenticated `/api/webhook|/upgrade` route reading attacker-posted JSON (`{"type":"checkout.session.completed","email":"victim@x"}`) and upgrading the account with no signature check. Any "webhook" route that mutates entitlements without provider-signature verification is this finding regardless of naming.

### Managed CMS (WordPress-Class)

- **Update posture.** Inventory core/plugin/theme versions from repo artifacts or authorized probes; flag anything visibly stale relative to current stable, and any plugin/theme present but not activated/used — remove unused ones entirely.
- **Disable in-admin file editing.** Verify `wp-config.php` defines `DISALLOW_FILE_EDIT` as `true` (absence = vulnerable default: admin users can edit plugin/theme PHP, turning any compromised admin session into remote code execution).
- **xmlrpc.php.** If unused (no Jetpack-class integration requiring it), disable it; left open it serves brute-force amplification and pingback abuse. Existence probe is in Exploitation & Reproduction (`authorized-only`).
- **Application passwords.** Integrations (mobile apps, XML-RPC clients, automation) should use per-application passwords revocable independently of the main account password.
- **wp-config hygiene.** Unique salts/auth keys defined (no placeholder phrases); `WP_DEBUG` false in production; debug log must not be web-readable.
- **Admin surface.** `/wp-admin` and `wp-login.php` should be protected with MFA and/or rate limiting. Path obscurity (renamed login) is a minor, honest note only — it is not a control.

### Serverless functions (Lambda / Cloud Functions / Workers)

- **One IAM role per function.** A shared execution role turns any single function's compromise into fleet-wide reach; wildcard resources (`Resource: "*"`, `"Action": "*"`, broad service wildcards) in a function role are the finding shape — scope each role to exactly that function's inputs and outputs.
- **Every event source is untrusted input.** API Gateway requests, S3 event records, queue messages, scheduled triggers: payloads arrive attacker-influenced no matter how internal the wiring looks. Validate schema and identity inside the handler boundary; never trust the invoking platform to have screened the payload.
- **Limits AND concurrency caps.** Timeout and memory settings bound one invocation; concurrency/reserved-capacity settings bound the bill. Cost-based DoS is a real category: one viral bug fanning out into unlimited concurrent executions becomes a five-figure invoice overnight.
- **Function URLs / HTTP triggers require auth.** Default-invoke function URLs and public HTTP triggers are the accidental-exposure classic: verify every trigger authenticates (IAM-signed requests or an authenticating gateway in front) — "no public invoke by accident" is a checklist item, not an assumption.
- **Secrets fetched from the platform secrets store at cold start.** Initialization reads them from the managed secrets/parameter store; never baked into deployment packages, bundled layers, or artifact-shipped env snapshots.

## Where To Look

### Supabase

- `supabase/migrations/*.sql` — table definitions, `create policy`, `enable row level security`, bucket inserts.
- `supabase/config.toml` — project linkage; `supabase/functions/**` — edge function code and secret reads.
- Client init: `src/lib/supabase*.ts`, any file importing `@supabase/supabase-js` and calling `createClient(`.
- `.env*` files consumed by frontend builds; committed bundles under `dist/`, `.next/`, `public/`.

### Firebase

- `firestore.rules`, `storage.rules`, `database.rules.json`, `firebase.json` (rules file wiring).
- `functions/` — Admin SDK usage (`firebase-admin` imports, `initializeApp(` with credential arguments).
- Tracked JSON matching `*serviceAccount*.json`, `*-firebase-adminsdk-*.json`, or containing `"type": "service_account"`.

### Connection-String Databases

- `.env*`, `docker-compose*.yml` environment blocks, CI definitions, shell scripts.
- ORM config: `prisma/schema.prisma` datasource url env indirection, Sequelize/Knex config files.
- Provisioning-as-code: Terraform for Atlas access lists / Neon projects; platform CLI scripts in `scripts/`.

### Serverless Hosts

- `vercel.json`, `netlify.toml`, `_headers`, `_redirects`, `public/_headers`.
- `next.config.js` (`productionBrowserSourceMaps`), build scripts in `package.json`.
- Deploy logs / commit status checks (user-supplied) revealing preview hostnames per branch.

### Payment Webhooks

- Route handlers: Next.js `app/api/**/route.ts` and `pages/api/**`, Express/Fastify route registrations, Django/Flask/FastAPI URL configs — search for path fragments `webhook|stripe|checkout|billing|fulfil`.
- The handler body: presence/order of `constructEvent` vs JSON body parsing; entitlement mutations (`update ... plan/pro/tier`) reachable from it.

### Managed CMS

- `wp-config.php` (constants), `wp-content/plugins/` and `wp-content/themes/` listings, `xmlrpc.php` presence, web-server config (`nginx.conf`, `.htaccess`).

## Patterns & Signatures

Ripgrep-compatible signature hunt over repo artifacts (run from repo root):

```bash
# BaaS SDK surfaces
rg -n "supabase" -g '!node_modules' -g '!package-lock.json'
rg -n "createClient\(" -g '!node_modules' --type ts --type js
rg -n "from\(['\"]" src/ -g '!node_modules'          # supabase-js table access surfaces to diff against RLS-enabled set
# Firebase artifacts and rules
rg -n "firebaseio\.com|firestore\.rules|database\.rules|storage\.rules"
rg -n "initializeApp\(|getFirestore\(|firebase-admin" -g '!node_modules'
# Webhook integrity
rg -n "constructEvent|SignatureVerificationError|stripe-signature"
# Browser-exposed env prefixes (cross-ref SECRETS)
rg -n "NEXT_PUBLIC_[A-Z_]+|VITE_[A-Z_]+|NUXT_PUBLIC_[A-Z_]+" -g '!node_modules'
# Privileged material
rg -n "service_role|SERVICE_ROLE" -g '!node_modules'
rg -n "postgres(ql)?://[^[:space:]\"']+"              # connection strings — REDACT every match before reporting
# Permissive policy/rule shapes
rg -n "using\s*\(\s*true\s*\)|with check\s*\(\s*true\s*\)" supabase/
rg -n "allow\s+read,\s*write|if\s+true" --glob '*.rules'
```

**Manual-judgment note:** no grep can prove a migration lacks RLS enablement — SQL semantics require reading the migration sequence. Use the signature output to enumerate candidate tables (`create table` hits) and manually diff each against the set of `enable row level security` statements across all migrations, honoring later `alter table` additions. Report as `Needs-Review` until confirmed.

Paste-ready read-only sweep (values REDACTED always; run from repo root):

```bash
# aegis-sweep :: baas-platform :: read-only :: all secret-shaped values REDACTED
red() { sed -E 's/([A-Za-z_]*(KEY|TOKEN|SECRET|PASSWORD|PRIVATE)[A-Za-z_]*)[=:][^[:space:]"]+/\1=[REDACTED]/g; s#((postgres(ql)?|mongodb(\+srv)?|mysql|redis))://[^[:space:]"]+#\1://[REDACTED]#g'; }
echo "== platform markers =="
git ls-files | grep -E '(^|/)(firestore|storage|database)\.rules$|firebase\.json$|vercel\.json$|netlify\.toml$|(^|/)supabase/config\.toml$|schema\.prisma$|wp-config\.php$'
echo "== SDK entry points =="
git grep -lnE "createClient\(|initializeApp\(|new Pool\(|mongoose\.connect|stripe\(" -- '*.ts' '*.tsx' '*.js' '*.jsx' '*.py' | head -30
echo "== migrations missing RLS enable (manual confirm) =="
for f in $(git ls-files 'supabase/migrations/*.sql'); do git show ":$f" | grep -qie 'create table' && ! git show ":$f" | grep -qie 'enable row level security' && echo "RLS-GAP? $f"; done
echo "== rules files (contents safe to print) =="
for f in $(git ls-files '*.rules'); do echo "--- $f"; cat "$f"; done
echo "== browser-exposed env prefixes =="
git grep -nE "NEXT_PUBLIC_[A-Z_]+|VITE_[A-Z_]+|NUXT_PUBLIC_[A-Z_]+" | red | head -40
echo "== privileged material in tracked files =="
git grep -niE "service_role|service_account|BEGIN (RSA )?PRIVATE KEY|constructEvent" | red | head -40
echo "== connection strings anywhere =="
git grep -niE "(postgres(ql)?|mongodb(\+srv)?|mysql|redis)://" | red | head -20
```

Interpretation: `RLS-GAP?` lines are candidates only (manual confirmation required); rules file contents are configuration, not secrets, and may be printed; every other stream passes through `red()` so no key value ever reaches the report or terminal.

## Taint Tracing Guidance

Model each platform boundary as source-to-sink; the control that must sit on the path is named per pair.

| Source (attacker-influenced or public-by-design) | Sink | Required gate on path |
|---|---|---|
| Supabase anon key + `from('<table>')` call in client bundle | PostgREST row read/write | RLS enabled + operation-scoped policy on `<table>` |
| `service_role` key value | Anything client-reachable: bundle, repo, preview env | Server-only runtime env; never a public env prefix |
| Env var with public prefix (`NEXT_PUBLIC_`, `VITE_`, `NUXT_PUBLIC_`) | Compiled JS in browser | None possible — value is public at build time; only non-secrets may take this path |
| Webhook route `req.body` / `request.get_data()` | Entitlement mutation (plan, credits, license, unlock) | `constructEvent` over RAW body + event-type allowlist + consumed-once dedupe |
| Client-supplied amount/currency/priceId/email | Order record or fulfillment decision | Server-side recompute from provider catalog; session retrieved by ID server-side |
| Firebase query issued by client | Documents evaluated against rules | Rule must constrain the query shape itself (rules-are-not-filters) |
| Service-account JSON path | VCS history, forks, clones | Untracked + ignored + rotated if ever committed |
| Upstash REST token / connection string | Logs, CI output, client code, error reporters | Bearer-secret handling: server-side env only |

Worked traces:

1. Client bundle imports `createClient(SUPABASE_URL, SUPABASE_ANON_KEY)` and calls `.from('documents')`. Trace stops at the table name: diff it against the migrations' RLS-enabled set. No policy for anon role = anonymous read/write proof available via curl (procedure a).
2. `pages/api/stripe/webhook.ts` begins with `const event = req.body` and no `constructEvent` appears anywhere in the file. The body taints `grantPlan(...)` directly — unsigned fulfillment confirmed statically; verify live with procedure (b).
3. `NEXT_PUBLIC_STRIPE_SECRET_KEY` in `.env.local`: prefix taint guarantees bundling into shipped JS. Report as Critical-adjacent secret exposure even before fetching the bundle to confirm (cross-ref SECRETS).

## Exploitation & Reproduction

Static-first throughout: console access may be absent, so every procedure starts from repo artifacts. Run live steps only against targets you are authorized to test. Never exfiltrate data beyond one-row existence proofs; REDACT all values in reports.

### (a) Supabase Anonymous Read/Write Proof

1. Extract from repo: project URL (`NEXT_PUBLIC_SUPABASE_URL`, supabase config, or client init literal) and anon key variable reference. Do not print either.
2. Enumerate candidate tables from migrations (`create table` hits) minus the manually-confirmed RLS-enabled set.
3. Probe read (`requires target authorization`):

```bash
BASE="$SUPABASE_PROJECT_URL"; ANON="$SUPABASE_ANON_KEY"   # values never echoed
curl -s -o /dev/null -w "%{http_code}\n" \
  "$BASE/rest/v1/<table>?select=*&limit=1" \
  -H "apikey: $ANON" -H "authorization: Bearer $ANON"
# 200            -> anonymous read succeeds = Critical when rows are non-public
# 401/403/empty-with-error (e.g., permission code 42501) -> RLS enforcing as intended
```

4. Probe write:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  "$BASE/rest/v1/<table>" \
  -H "apikey: $ANON" -H "authorization: Bearer $ANON" \
  -H "content-type: application/json" -H "prefer: return=minimal" -d '{}'
# 201 -> anonymous INSERT succeeds = Critical (world-writable table)
# 401/403/42501 -> insert policy blocking as intended
```

Expected observables: HTTP 200 with row JSON (read) or 201 (write) proves full-database compromise via the public key alone; 401/403 or an empty body with a PostgREST permission error demonstrates the policy layer working.

### (b) Stripe Webhook Replay/Rejection Test

1. Locate the fulfillment route in repo and confirm statically whether `constructEvent` gates the handler.
2. Unsigned probe against your own deployment:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:3000/api/stripe/webhook" \
  -H "content-type: application/json" \
  -d '{"id":"evt_forged_001","type":"checkout.session.completed","data":{"object":{"customer_email":"attacker@example.com"}}}'
# Expected when correct: 400/verification-failure observable, no entitlement change.
# 200 plus account upgrade = Critical: unsigned fulfillment accepts forged events.
```

3. Authorized test-mode round-trip using the stripe CLI conceptually: `stripe listen --forward-to <local-handler>` then `stripe trigger checkout.session.completed`; confirm the handler logs successful verification and fulfills once.
4. Tamper-and-replay: capture the delivered test event, alter its payload or resend it verbatim after fulfillment; the endpoint must reject tampering (signature mismatch) and must not double-grant on verbatim replay (idempotency). Observable: second delivery returns success but entitlement state unchanged exactly once.

### (c) CMS Probes (`AUTHORIZED-ONLY`)

```bash
curl -s -o /dev/null -w "xmlrpc: %{http_code}\n"  "https://TARGET/xmlrpc.php"
# 200/405 -> endpoint present and reachable (disable when unused); 403/404 -> blocked
curl -s -o /dev/null -w "debuglog: %{http_code}\n" "https://TARGET/wp-content/debug.log"
# 200 with PHP notices -> WP_DEBUG logging publicly readable; 403/404 -> acceptable
```

Do not brute-force, do not enumerate users, do not POST to xmlrpc methods; existence probes only.

### (d) Preview URL Discovery And Protection Check

1. Discover hosts without touching consoles: PR histories, commit status checks, and deploy logs expose per-branch deployment hostnames (patterns typically `<branch-or-hash>--<site>.netlify.app` and `<deployment>-<project>.vercel.app`).
2. Fetch one discovered host unauthenticated:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<preview-host>/"
# 200 rendering the app shell with no auth challenge = unprotected preview
```

3. Confirm scope minimally: note whether staging API base URLs or preview env markers appear in the served HTML/bundle references; do not dump staging data.
4. Expected observable when protected: redirect to an SSO/login challenge or 401 before any app shell renders.

## Remediation

### Supabase

Enable RLS on every public-schema table and add owner-scoped policies covering all four operations:

```sql
-- VULNERABLE: table reachable by the public anon key, no RLS
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text,
  body text
);
```

```sql
-- FIXED: deny-by-default, then grant narrowly per operation
alter table public.documents enable row level security;

create policy documents_select_own on public.documents
  for select using (auth.uid() = owner_id);

create policy documents_insert_own on public.documents
  for insert with check (auth.uid() = owner_id);

create policy documents_update_own on public.documents
  for update using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);   -- prevents re-parenting rows to another owner

create policy documents_delete_own on public.documents
  for delete using (auth.uid() = owner_id);
```

Tables used only by server code (service_role) should have no anon/authenticated policies at all — RLS enabled plus zero policies already denies the public roles.

**service_role isolation pattern:** the service_role key lives only in server-side runtime env (`process.env.SUPABASE_SERVICE_ROLE_KEY` behind a non-public name). It must never receive a `NEXT_PUBLIC_`/`VITE_`/`NUXT_PUBLIC_` prefix, never appear in client-callable modules (in Next.js, import it only from modules marked server-only), never enter VCS or preview env contexts. If it ever shipped in a bundle, rotate it immediately — deletion of the variable does not un-leak it.

### Firebase

```javascript
// VULNERABLE: scaffolding left open project-wide
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
```

Hardened starter (deny by default; grant narrowly; mirror the same shape in `storage.rules`):

```javascript
// FIXED: starter - replace collection names/fields to match the real schema
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid}/private/{docId} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    match /posts/{postId} {
      allow read: if true;                       // documented intentional public content
      allow create: if request.auth != null
        && request.resource.data.authorUid == request.auth.uid;
      allow update, delete: if request.auth != null
        && resource.data.authorUid == request.auth.uid;
    }
    // no catch-all match -> everything else denied
  }
}
```

Migrate off test-mode timers before their timestamps pass; never combine a timer with a trailing permissive fallback. Validate iteratively in the emulator/rules playground before deploying.

### Connection-String Platforms

- Rotate any credential that appeared in repo, logs, or clients; store replacements in platform secret managers only.
- Enforce TLS in the string: `?sslmode=require` (Postgres-family); TLS endpoints for Redis-family; keep Atlas default TLS untouched.
- Atlas: replace `0.0.0.0/0` network access with specific egress IPs or private networking.
- Upstash REST tokens are bearer secrets: server-side env only, scoped per database, rotated on suspicion.

### Payment Webhooks

```javascript
// VULNERABLE: trusts client JSON, no signature check -> forged upgrades
app.post("/api/stripe/webhook", express.json(), async (req, res) => {
  const event = req.body;
  if (event.type === "checkout.session.completed") {
    await grantPlan(event.data.object.customer_email, event.data.object.amount);
  }
  res.sendStatus(200);
});
```

Node fixed middleware:

```javascript
// FIXED (Node): verify over RAW body before anything else
app.post("/api/stripe/webhook",
  express.raw({ type: "application/json" }),   // raw bytes required for signature
  (req, res) => {
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send("signature verification failed");
    }
    if (!["checkout.session.completed", "invoice.paid"].includes(event.type)) {
      return res.status(200).end();            // allowlist: ACK unknown types, act on none
    }
    fulfill(event);                             // internally: recompute price from catalog,
    return res.json({ received: true });        // dedupe by event.id (consumed-once)
  });
```

Python fixed handler:

```python
# FIXED (Python/Flask): construct_event over raw payload; reject on failure
import stripe
from flask import Flask, request, abort

@app.post("/api/stripe/webhook")
def webhook():
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(
            request.get_data(), sig, app.config["STRIPE_WEBHOOK_SECRET"]
        )
    except ValueError:
        abort(400)                              # invalid payload
    except stripe.SignatureVerificationError:
        abort(400)                              # signature mismatch
    if event["type"] not in HANDLED_EVENTS:
        return ("", 200)
    fulfill(event)                              # recompute + dedupe inside
    return ("", 200)
```

Consumed-once table backing idempotent fulfillment:

```sql
-- FIXED: unique(event_id) makes replay inserts fail inside the fulfillment transaction
create table public.processed_webhook_events (
  event_id     text primary key,
  provider     text not null,
  processed_at timestamptz not null default now()
);
-- flow: begin; insert into processed_webhook_events(event_id, provider) values ($1,'stripe');
--       on conflict do nothing -> skip fulfillment; commit after granting entitlements
```

### Serverless Hosts — Preview Protection Checklist

Console-guidance phrasing (verify state via user-provided screenshots; no CLI):

1. Project settings → deployment/access protection: require authentication for every non-production deployment (team SSO gate, shared password, or bypass-token scheme).
2. Confirm protection covers branch and preview targets, not only production aliases.
3. Remove secrets from preview-scoped env vars unless strictly required; treat preview context as public until protection is proven on.
4. Disable production source maps (`productionBrowserSourceMaps` unset/false; strip `.map` from publish directory).
5. Audit `vercel.json` / `netlify.toml` redirects/rewrites for open-redirect and route-masking mistakes; add security headers globally.

### Managed CMS Hardening Checklist

```php
// FIXED - wp-config.php additions (production)
define('DISALLOW_FILE_EDIT', true);   // blocks plugin/theme PHP editing from admin UI
define('WP_DEBUG', false);            // no debug output or web-readable debug.log
```

- Update core/plugins/themes; delete unused plugins/themes rather than deactivating.
- Keep unique salts/auth keys in `wp-config.php` (no placeholder phrases).
- Disable `xmlrpc.php` when no integration requires it (web-server rule or removal).
- Use per-application passwords for integrations; enforce MFA and rate limiting on logins; path obscurity is optional garnish, not a control.

## Verification & Validation

Post-fix verification (positive):

- Rerun the `pg_tables` introspection: every public-schema row reports `rowsecurity = true` (or carries a documented public-by-design exception). Re-run procedure (a): reads/writes against protected tables now return 401/403 or permission errors via the anon key.
- Firestore/RTDB/Storage: run the revised rule sets through the rules simulator (console playground) and the local emulator suite; every unauthenticated read/write test case must evaluate to deny, every intended grant to allow.
- Webhook: `stripe trigger checkout.session.completed` in test mode fulfills exactly once; a verbatim replay updates no entitlement state; a tampered payload is rejected at signature verification.
- CMS probes return non-reachable codes for `xmlrpc.php` and `wp-content/debug.log`; `DISALLOW_FILE_EDIT` visible in deployed `wp-config.php`.

Negative tests (product intent preserved):

- Intended anonymous reads still work: public landing/marketing tables return 200 through the anon key; public blog documents remain readable under hardened Firebase rules.
- A real customer checkout completes end-to-end in test mode and grants entitlements exactly once.
- Authenticated users can still perform their intended CRUD on their own rows.

Regression notes:

- Over-tight RLS can silently break realtime subscriptions — Supabase realtime evaluates your policies; a missing select policy for the subscribing role stops receiving events. Test subscriptions after policy changes.
- Rules tightened too far break legitimate client queries (rules-are-not-filters): a per-document rule without a matching query constraint rejects whole queries. Iterate against the emulator before deploying; watch client logs for permission-denied on valid flows.
- Revoking anon grants on tables the frontend legitimately reads will break those screens — diff client `.from('<table>')` usage against the hardening set before applying.

Greps rerun post-fix: the Patterns & Signatures block should show zero hits for `service_role` outside server-only modules, zero secret-shaped names under public env prefixes, and `constructEvent` present in every fulfillment handler. Any residual hit needs a documented exception.

## Severity Assessment

Vectors assume an internet-reachable deployment; adjust AV/PR downward only with documented network-boundary evidence.

| Anchor | Finding | CVSS v3.1 vector | Approx. score |
|---|---|---|---|
| Critical | PII-bearing table with RLS off, readable AND writable by anyone holding the public anon key | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | ~9.8 |
| Critical | Firestore/RTDB rules fully open (`allow read, write: if true`) on user data | same shape as above | ~9.8 |
| High | service_role key recoverable from shipped client bundle (RLS bypass = full DB control); treat as Critical-equivalent when live-confirmed | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L` | ~9.2 |
| High | Unsigned webhook fulfillment granting entitlements from forged JSON | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` | ~8.1 |
| High | Unprotected public preview exposing prod-like data/env vars | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | ~8.1 |
| Medium | Public-read storage bucket undocumented (avatar-style exposure of a broader object class than intended) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | ~5.3 |
| Medium | `xmlrpc.php` left open when unused (brute-force amplification/pingback abuse surface) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | ~5.3 |
| Low | Platform/component version disclosure banners | `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N` | ~3.6 |

Anchor discipline: RLS enabled-but-permissive is graded by what its worst reachable operation exposes, not as "missing RLS"; expired-but-inert test-mode rules are graded by whether any live path currently grants access.

## Common False Positives

- **Tables intended to be public.** Landing-page/marketing content tables reachable via the anon key are by-design when a documented decision exists. Verify writes are still denied before downgrading; an intentional public READ with open WRITE is never a false positive.
- **RLS enabled-but-permissive is not RLS off.** A table with `rowsecurity = true` and `using (true)` policies fails differently: report it as policy-quality (High/Critical by exposure), not as the missing-RLS Critical anchor. Audit policy quality as a separate finding either way.
- **Future-dated Firebase test-mode timers.** A fresh project legitimately carries `request.time < timestamp(<future>)`. Confirm project age against the timestamp; flag only expired-and-open rules or prod data living under a timer.
- **Internal tools bound to VPN/allowlists.** A public Supabase endpoint or Atlas listener behind a verified network boundary makes raw internet-exposure scoring moot. Document the boundary evidence (access-list config, screenshot) and mark not-applicable-with-evidence instead of clean.
- **Hash-named preview URLs.** Un-guessable preview hosts reduce discovery but are not protection (URLs leak through referrers, logs, scanners). Note reduced exposure; still recommend enforced authentication.
- **Public bucket with only avatar objects and a documented decision** — informational; escalate if object classes broader than avatars land there.
- **`constructEvent` present but fed parsed JSON.** The call exists, so "unsigned handler" does not apply; the finding degrades to broken-verification (often still exploitable) rather than no-verification.

## References

Official documentation roots:

- supabase.com/docs — Row Level Security guides, PostgREST API keys, Storage access control, Edge Functions secrets
- firebase.google.com/docs — Firestore security rules, Realtime Database rules, Cloud Storage security, App Check, Admin SDK
- stripe.com/docs/webhooks — signature verification (`constructEvent` / `construct_event`), test-mode CLI event triggering
- vercel.com/docs — environment variable scoping, deployment protection, source maps settings
- netlify.com/docs — access control for deploys, headers and redirects configuration
- developer.wordpress.org — `wp-config.php` constants, application passwords, roles and capabilities
- neon.tech/docs — connection strings and TLS
- docs.railway.app and render.com/docs — database provisioning and networking
- docs.upstash.com — REST token authentication for Redis
- mongodb.com/docs/atlas — network access lists and connection security

OWASP references:

- owasp.org/Top10/A01_2021-Broken_Access_Control/
- cheatsheetseries.owasp.org (Authorization, Authentication, and Transaction Authorization cheat sheets)
