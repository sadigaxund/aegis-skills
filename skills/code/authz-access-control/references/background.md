# Access Control — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no prior security background assumed. Teaches the *why*; SKILL.md keeps the
route matrices, bypass test loops, and remediation choke points.

## How this class emerged

Access control is computing's oldest security problem — formal access models
date to the early 1970s military research that distinguished who may *read*
from who may *write*. Role-based access control was formalized in the 1990s to
map organizational job titles onto permissions. The web era made the problem
worse in two specific ways:

- **Object identifiers moved to the client.** REST-style URLs put record keys
  (`/invoices/1042`) into every request. The 2000s frameworks fetched whatever
  the key named; "insecure direct object reference" entered the OWASP Top 10 in
  2010 as the label for forgetting the ownership predicate.
- **Server-rendered UI checks dissolved.** When SPAs hid admin screens behind
  client-side conditionals, teams confused hiding a button with guarding an
  endpoint.

The API decade renamed and re-ranked the same failures: OWASP's API Security
Top 10 (first published 2019) promoted them to BOLA (object axis) and BFLA
(function axis), ranking object-level breakage first because stateless APIs lean
entirely on client-supplied IDs. Mass assignment gained notoriety through public
demonstrations against Ruby-on-Rails apps in 2012, pushing strong-parameters
into framework defaults. Multi-tenant SaaS then made tenant isolation an
engineering discipline of its own — one mis-scoped query or cache key crosses
customer boundaries at scale.

## Anatomy

One route can fail both independent axes at once:

```js
router.get("/invoices/:id", requireAuth, async (req, res) => {
  res.json(await Invoice.findByPk(req.params.id));
});
```

Walkthrough:

1. **Function axis** passes: `requireAuth` proves the caller is a valid user,
   so invoking this endpoint is permitted for every user (BFLA would fail here
   if an unauthenticated caller could reach it, or if only admins should).
2. **Object axis** fails silently: `findByPk` fetches whichever invoice the key
   names. Nothing compares the row's owner or tenant to the caller.
3. The attacker authenticates normally, changes `1042` to `1043`, and reads a
   stranger's invoice. No exploit code, no malformed input — just a different
   legal value in a parameter designed to be changed.

The deeper lesson: **authentication answers "who are you"; authorization
answers "may you touch this"** — and they must be answered separately for the
action and for each object instance. A validated, well-typed integer is still
someone else's integer. Validation is never authorization.

## Why naive fixes fail

One subsection because the recurring errors are structural:

- **Hiding links and buttons** guards the UI, not the endpoint; bundles, proxy
  logs, and API docs reveal every route.
- **Unguessable IDs (UUIDs) are mitigation, not fix.** They slow enumeration but
  leak via referrals, exports, emails, and other users' responses — and a
  capability is not an entitlement check.
- **Client-side role checks** (`if (user.role === 'admin')` gating routes in the
  SPA) are trivially edited; the server must re-derive role from its own store.
- **Guarding one verb** misses method asymmetry: DELETE/PATCH handlers on the
  same path, catch-all routers, and method-override headers.
- **Checking ownership after fetching** ("fetch, then compare, then maybe
  redact") leaks existence and timing even when it blocks data.
- **Trusting forwarded headers** (`X-Original-URL`, `X-Forwarded-For`) moves the
  decision to attacker-controlled bytes unless a trusted proxy guarantees them.
- **Obscure admin paths** are security by obscurity; wordlists and JS bundles
  find them.

## Common misconceptions

1. "We have authentication middleware, so we're covered." Middleware proves
   identity on the function axis only; the object axis needs predicates in the
   query itself.
2. "UUIDs prevent IDOR." They prevent guessing, not possession — leaked IDs work
   identically whether sequential or random.
3. "The frontend hides admin routes from normal users." Hiding is rendering;
   enforcement lives server-side or not at all.
4. "Our ORM/abstraction handles tenancy." Most ORMs fetch any primary key by
   default; tenant scoping exists only where explicitly added per query or via
   global filters/row-level security.
5. "A 404 for foreign objects means we're safe." Existence oracles leak too:
   differing timing, empty-but-200 bodies, or error text distinguish states.
6. "Authorization tests need only one account." Single-account tests verify
   owners keep access; only two-account matrices prove strangers do not.
7. "Caches and queues are plumbing, not authorization surfaces." Shared cache
   keys without tenant prefixes and consumers without re-checks cross tenants
   exactly like a missing WHERE clause.

## How professionals think about it today

Practice evaluates every route along SKILL.md's independent axes, then layers
centralized policy over both:

| Axis / branch | Question | Defining control |
|---|---|---|
| Function-level (BFLA) | May this subject invoke this action? | deny-by-default routing wall; role guards per subtree |
| Object-level (BOLA/IDOR) | May it touch THIS instance? | ownership/tenant predicate inside the query |
| Attribute-level | May it read/write these fields? | serializer allowlists per role |
| Vertical escalation | Can identity claims be self-granted? | roles derived server-side; mass-assignment blocklists |
| Tenant isolation | Does context come from the principal? | tenant from session, not input; scoped caches/queues/indexes |
| Bypass primitives | Do path/verb/header variants split guard from handler? | normalize before deciding; strip proxy headers |
| Delegation & impersonation | Who acts when support logs in as a customer? | scoped short-TTL tokens + immutable audit trail |

Professional habits: centralize decisions in one choke point per stack;
prefer allow-style policies where absence of a rule means deny; backstop with
database row-level security; snapshot-test route tables so new endpoints cannot
appear without paired guards; and always run the two-account matrix across
every route x role x {own, foreign, nonexistent} object.

Severity intuition: unauthenticated reachability of privileged actions is
Critical; authenticated vertical escalation High; single-object cross-tenant
reads scale with data sensitivity rather than with count — one medical record
outweighs a thousand catalog rows.

## Read next

In `../SKILL.md`: **Mental Model** (the two-axis table plus decision
procedure), **What To Check** (BFLA/BOLA/escalation/bypass/delegation),
**Where To Look** (per-stack route tables and guard markers), **Patterns &
Signatures**, **Taint Tracing Guidance** (lookup helpers lacking a principal
parameter), **Remediation** (choke-point table, before/after recipes, RLS
backstop), **Common False Positives**.

Sibling modules: `../authn-session/SKILL.md` (identity establishment feeding
these decisions), `../api-security/SKILL.md` (API-layer mass assignment and
exposure), `../business-logic-races/SKILL.md` (workflow-order abuse such as
multi-step skips), `../cloud-iam/SKILL.md` (infrastructure IAM analogues),
`../secrets-data-exposure/SKILL.md` (over-exposed fields as a data problem).
