# BaaS & Managed Platforms — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the platform checklists, signature sweeps, and remediation.

## How this class emerged

For most of the web's history, "the database" sat behind an application that
owned every access decision. Backend-as-a-Service inverted that: Firebase
(pioneering realtime sync databases in the early 2010s, acquired by Google in
2014) and Supabase (founded around the Postgres ecosystem's managed resurgence)
put a data API directly in the browser, guarded not by application code but by
declarative rules — Postgres Row Level Security policies on one platform,
JSON rule files on another. The security boundary moved from code you review
line-by-line into configuration whose *absence* is silent.

The failure class was born with the model: a database reachable by anyone
holding the public client key is safe exactly as long as every table, file, and
query path carries an explicit deny-by-default policy — and new projects ship
with those guards off because onboarding speed sells. Connection-string
platforms (managed Postgres, Redis, Mongo) recreated the older risk in newer
clothing: one credential string equals full data control, so it leaks like any
secret while feeling like config. Serverless hosts added per-branch public
preview URLs; payment providers added webhook endpoints that grant entitlements;
WordPress-class CMSs contributed decades of "admin convenience" defaults.

Postgres shipped Row Level Security in its 9.5 release (2016), giving Supabase
its policy engine; the industry's shared lesson since is that on these
platforms the *configuration is the application*, and auditing it is not
optional hardening but the actual access-control review.

## Anatomy: one table, one public key

The minimal shape needs only a migration that forgets one statement:

```sql
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text,
  body text
);
-- no "alter table ... enable row level security" anywhere after this
```

Walkthrough of what any visitor can do:

1. The browser bundle ships the project URL and the anon key by design — they
   are public constants, printed in every quickstart.
2. The client SDK calls the auto-generated REST API for `documents`. Because
   RLS is off, the anon role's grants apply to *every row*: reads return all
   documents; writes insert and modify at will.
3. Nothing "broke" — Postgres enforced precisely the privileges it was given.
   The bug is that the platform's only boundary (policies) was never enabled,
   and nothing warns loudly enough to stop a sprint.
4. The identical shape recurs across platforms: a Firestore rules file reading
   `allow read, write: if true`, a Mongo Atlas network list containing
   `0.0.0.0/0`, an Upstash REST token pasted into frontend env, a preview
   deployment serving staging data to whoever guesses the branch URL.

Payment fulfillment completes the family:

```javascript
app.post("/api/stripe/webhook", express.json(), async (req, res) => {
  const event = req.body;                    // attacker-supplied JSON
  if (event.type === "checkout.session.completed")
    await grantPlan(event.data.object.customer_email);
});
```

No signature verification means anyone can POST a forged "payment succeeded"
event and upgrade themselves. The fix pattern is uniform across the module:
make the boundary explicit and deny-by-default (enable RLS + scoped policies;
auth-scoped rules; IP-restricted network lists), keep privileged material
server-side only, and make value-granting endpoints prove sender identity over
the raw bytes before granting anything.

## Why naive fixes fail

One subsection because the failure modes rhyme across platforms:

- **Enabling RLS without policies — or policies without RLS.** Enabled-but-empty
  denies everything (breaking the app until reverted); policies alone leave the
  grants wide open. Both halves must exist per operation, per table.
- **`using (true)` placeholder policies.** Scaffolding examples copy into
  production verbatim; a policy that exists but constrains nothing protects
  nothing. Presence and quality are separate findings.
- **UPDATE policies missing their `with check` half.** The `using` half limits
  which rows may be edited; without `with check (auth.uid() = owner_id)` a user
  can edit their own row *into* someone else's ownership.
- **"Rules are just filters" assumptions on Firebase.** A rule cannot rescue a
  query broader than itself — Firestore rejects whole queries rather than
  filtering — and a broad rule plus careful client code still equals a leak,
  because anyone can query directly.
- **Rotating the leaked key but keeping it client-side.** Deletion of a variable
  does not un-leak a bundle; service_role keys and connection strings must move
  behind server-only runtime environments or rotation buys days, not safety.
- **Hash-named preview URLs as protection.** Unguessable hostnames leak through
  referrers, logs, scanners, and commit statuses; authentication gates are the
  control, obscurity is a delay.
- **Parsing JSON before verifying webhook signatures.** Signature libraries
  require the raw request body; middleware that consumes and re-serializes it
  makes verification fail or get skipped — the check must sit first in the
  handler chain.
- **Idempotency by hope.** Providers retry deliveries; fulfillment without a
  consumed-once event ledger double-grants on replay even when signatures work.

## Common misconceptions

1. "The anon key is a secret." It is public by construction — printed in
   client bundles. Treating it as confidential leads teams to skip RLS because
   "nobody has the key."
2. "RLS enabled means the table is secure." Policy quality decides: `using
   (true)`, missing operation coverage, or absent `with check` each fail
   differently than RLS-off, but all fail.
3. "Firebase test-mode timers will expire anyway." Future-dated timers lapse
   into whatever surrounding matches allow; expired-plus-permissive fallbacks
   stay open indefinitely, and prod data under a timer is already exposed.
4. "Managed platforms handle security." Vendors patch infrastructure; grants,
   rules files, network lists, and key placement remain the customer's side of
   the shared-responsibility line, unpatched by definition.
5. "Storage buckets inherit database rules." Storage evaluates its own rules
   (Supabase: `storage.objects` policies; Firebase: a separate `.rules` file).
   Hardened Firestore beside open storage.rules is a common split posture.
6. "Public env prefixes are fine because values look harmless."
   `NEXT_PUBLIC_`/`VITE_` variables are compile-time inlined into shipped JS;
   one mis-prefixed secret publishes it to every visitor, permanently cached.
7. "The webhook worked in testing, so verification is fine." Test-mode success
   proves the happy path; tampered payloads and verbatim replays exercise the
   signature and idempotency controls that testing skipped.

## How professionals think about it today

Modern practice audits these platforms as five invariants — public client keys
are public; defaults favor onboarding; bundles are attacker-readable; authless
URLs are attacker-reachable; granting endpoints must prove sender and dedupe —
applied per platform. The taxonomy mirrors SKILL.md's sections:

| Platform/class | Footgun | Defining control |
|---|---|---|
| Supabase | RLS off by default; service_role bypasses all | enable-per-table + four-operation owner-scoped policies |
| Firebase | permissive scaffolds; forgotten Storage rules | deny-by-default rules, simulator-tested, timer migration |
| Connection-string DBs | credential = full control | TLS-enforced strings, IP-restricted/private networking, server-side tokens |
| Serverless hosts | unprotected previews, published source maps | deployment protection covering non-prod targets; map suppression |
| Payment webhooks | unsigned, replayable fulfillment | raw-body signature verify + event allowlist + consumed-once ledger |
| Managed CMS | admin file editing, xmlrpc, stale plugins | hardening constants, update lifecycle, MFA on admin surface |

Severity anchors to reachability with the public identity: world-readable AND
world-writable tables via the anon key are Critical; service_role in a bundle is
Critical-equivalent once confirmed live; undocumented public buckets and open
xmlrpc sit lower. Static evidence (migrations diffed against RLS-enablement,
rules files, handler order) carries findings when console or database access is
unavailable — name the failing control and the artifact that proves it.

## Read next

In `../SKILL.md`: **Mental Model** (five invariants, footgun matrix), **What To Check** (per-platform procedures), **Where To Look** (artifact paths),
**Patterns & Signatures** (SDK/rule/credential greps, redacted sweep), **Taint
Tracing Guidance** (source→sink gates per pair), **Exploitation & Reproduction**
(anon-key proofs, webhook replay), **Remediation** (hardened SQL/rules/handlers),
**Verification & Validation**, **Severity Assessment**, **Common False
Positives**.

Sibling modules: `../secrets-data-exposure/SKILL.md` (service_role and service-
account JSON handling), `../authz-access-control/SKILL.md` (policy design
principles), `../cloud-iam/SKILL.md` (serverless execution roles, function URL
auth), `../configuration-hardening/SKILL.md` (security headers on hosted edges),
`../crypto/SKILL.md` (webhook HMAC design depth), `../dns-takeover/SKILL.md`
(dangling platform DNS records).
