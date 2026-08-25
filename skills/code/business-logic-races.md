---
name: business-logic-races-checks
description: Audit playbook module for business logic flaws and race conditions covering workflow and state-machine bypass, price and amount tampering, check-then-act TOCTOU races, time-based logic abuse, limit counting defects, approval-flow weaknesses, and referral or gift-system abuse across all mainstream languages and frameworks.
category_slug: LOGIC
cwe: [CWE-362, CWE-367, CWE-20, CWE-639]
owasp: A04:2021 – Insecure Design
---

## Scope & Objectives

### Objective

Audit the target repository for flaws where the application trusts the client's data, ordering, or timing instead of enforcing its own rules: checkout steps that can be skipped, totals that arrive precomputed, balances debited through unsynchronized read-modify-write sequences, trials extended by client clocks, limits counted on the wrong field, approvals signed by their own requester. For every finding produce file:line evidence, a static-first reproduction recipe, a severity with rationale, and a stack-correct fix built around transactions, row locks, atomic conditional updates, idempotency keys, or server-side transition guards.

### In Scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Workflow / state-machine bypass | Direct call to the order-creation endpoint skipping payment; UI-only email-verification gate; password change without old password; step tokens accepted unsigned or unvalidated | CWE-20 (where a client-set field drives the transition) |
| Price / quantity / amount tampering | Client-computed `total` persisted as-is; negative quantities minting store credit; coupon stacking without validation; unlimited discount-code reuse; floating-point money | CWE-20 |
| Race conditions (check-then-act) | Balance check then debit; stock decrement; voucher single-use enforcement; rate-limit counters themselves; uniqueness at signup | CWE-362 |
| TOCTOU on resources | Upload published before or during malware scan; expiry checked at render but not at action; permission revocation vs live sessions | CWE-367 |
| Double execution | Double-spend, double-vote, double-refund; missing idempotency keys on payment endpoints; webhook replay | CWE-362 |
| Limit / counting logic | Check on one field, increment on another; per-request vs per-day windows; soft-delete resurrecting quotas | CWE-362 |
| Approval / multi-party flows | Self-approval, unenforced approval order, circular delegation chains, four-eyes claimed but single-principal path exists | Design finding (CWE-20 when client-set status drives it) |
| Referral / cashback / gift systems | Self-referral loops, gift-card brute force, negative-amount transfers crediting both sides | CWE-20 |
| Cross-user enumeration inside business flows | Pagination walking others' orders, invoices, vouchers to farm codes or balances | CWE-639 |

Workflow bypasses with no client-set field map to OWASP A04:2021 (design weakness) rather than a single code-level CWE; document them as design findings with the transition table as evidence.

### Out of Scope (cross-references)

- Object-level IDOR mechanics and bulk-export enumeration -> AUTHZ module. Flag here only where the damaged thing is a business invariant (quota, vote tally, voucher pool), and hand the access-control defect to that module.
- Mass-assignment binding mechanics (binder allowlists, DTO configuration) -> API module. Consume its output: every client-writable `status`, `price`, or `balance` field found there becomes a workflow or tampering candidate here.
- Login throttling policy and credential-stuffing thresholds -> AUTHN module. Here, cover only the correctness of the rate-limit counter implementation under concurrency.
- Injection payloads in parameters discovered during flow probing -> INJECTION module.
- Gift-card code entropy and secret storage -> SECRETS module; redemption brute-force feasibility -> API module (rate limiting). Cover here only the redemption race and balance math.

### Operating Assumptions

Read-only repository access; no running instance guaranteed. Static confirmation grounded in documented framework semantics (transaction scopes, lock modes, database constraint behavior) is sufficient evidence for reporting. Dynamic reproduction only against explicitly authorized environments; the concurrent-request recipes in this module assume written authorization.

## Mental Model

### Every Business Flow Is a Server-Side State Machine

An order moves CART -> SUBMITTED -> PAID -> SHIPPED. A voucher moves ACTIVE -> REDEEMED. A withdrawal is a transition on a balance. Screens, buttons, wizard steps, and disabled controls are presentation; the only real machine is the set of legal transitions the server enforces. Findings appear wherever the server lets a caller choose a transition directly (skip), repeat a transition (replay or race), or supply the operands of the transition (tamper). Start every audit by locating the machines: enumerate entities carrying lifecycle columns (`status`, `state`, `stage`) and enumerate every handler that mutates them.

### The Five Questions (core method)

For every business-critical transition, ask and answer in writing:

1. Can steps be reordered or skipped? Call the later endpoint directly with a hand-built request; the UI is not the API.
2. Is any amount, count, flag, or timestamp client-controlled? Trace every operand of the transition back to its source.
3. Is there a check-then-act gap? Find the `if` guarding the write; determine whether anything (an `await`, a network call, a second statement) sits between check and write, and whether the pair shares one transaction with a lock.
4. What happens twice? What happens zero times? Fire the request twice concurrently (replay, race) and strip prerequisites (skip); the answers expose missing idempotency and unenforced preconditions.
5. Is the operation idempotent and replay-safe? Look for an idempotency key honored server-side, a natural unique constraint, or a conditional write that turns the second identical request into a no-op.

Map answer patterns to finding classes:

| Answer pattern | Finding class |
|---|---|
| Q1: later step reachable out of order | Workflow bypass |
| Q2: yes | Tampering (price, quantity, state, time) |
| Q3: unprotected gap | TOCTOU race (CWE-362 / CWE-367) |
| Q4: twice is profitable | Double-spend / replay |
| Q4: zero times achievable | Precondition bypass (forced-error state) |
| Q5: no | Payment and webhook replay risk |

### Two Failure Families, Two Greps

Family one, trusted data: the server executes correct logic on attacker-chosen operands (totals, currencies, quantities, statuses, timestamps, step tokens). Family two, trusted ordering and timing: the server executes correct logic assuming each operation happens once, in sequence, alone; concurrency, retries, and direct calls violate each assumption. Grep differently per family: the data family greps for assignments sourced from request objects; the ordering family greps for read-modify-write pairs and for the absence of transaction vocabulary around money writes.

### Counters Are Money

Balances, credits, points, stock, quota, vote tallies, redemption counters: each is a counter whose integrity equals financial or entitlement integrity. A counter updated by application-side arithmetic (read `x.balance`, subtract in code, save) is a race waiting for its first concurrent pair. Demand atomic shapes everywhere: a single conditional `UPDATE`, a filtered `$inc`, an `INCRBY` inside Lua, or a row-locked transactional decrement. Anything less is a finding.

### Networks Retry: Nothing Mutating Is Called Exactly Once

Payment webhooks, mobile clients on flaky links, orchestrator retries, browser double-clicks, and proxy retransmits guarantee every mutating endpoint eventually receives duplicates. The absence of idempotency protection on charge, refund, transfer, payout, and provisioning endpoints is a finding on its own, even before any race exists.

### Concurrency Beats Politeness

Any gap between check and write widens under load and is trivially weaponized by firing tens of parallel requests; once scripted, attack complexity is Low. In-process locks (Python `threading.Lock`, Java `synchronized`, Go `sync.Mutex`) exclude competitors within one process only; production deployments run many workers and replicas. Real exclusion lives in the shared datastore: row locks, atomic statements, unique indexes, and serialized queues. Treat every in-process guard around money as decorative until the database agrees.

## What To Check

### Workflow and State-Machine Bypass

- Enumerate intended step order for every flow (signup -> verify -> onboard; cart -> payment -> order; password reset; KYC). Write the ordered list into working notes; every later step becomes a bypass candidate.
- Call each later-step endpoint directly with a minimal valid request. Rejection must originate from persisted state (`order.status == PAID`), never from trusting an echoed step token or hidden-field value.
- Diff client-side guards against server handlers: locate SPA routing files (`routes.js`, `App.tsx`, Angular `canActivate`, React `ProtectedRoute`, Vue `beforeEnter`, Next.js middleware). A guard existing only in the router is UI-only; confirm the paired API handler enforces the same predicate.
- Hunt state fields bound from requests: `status`, `state`, `step`, `verified`, `approved`, `is_paid` read from body/query/form. Each hit is a transition the client can drive.
- Validate step/flow tokens server-side: `step_token`, `checkout_session`, `flow_id` values must be checked against server session state and bound to one user and one next state. Unsigned, globally guessable, or reusable tokens fail.
- Password change flows: require the current password or an authenticated reset token. A body carrying only `new_password` is a finding (session theft escalates to permanent takeover).
- Email verification: find where the flag is written; confirm protected actions read the persisted flag server-side rather than trusting UI hiding. Test whether verification accepts predictable, hashless, or unexpiring tokens.
- Onboarding/KYC gates: locate the `onboarding_complete`-style predicate and verify every downstream endpoint enforces it, not just the dashboard redirect.

### Price, Quantity, and Amount Tampering

- Locate total computation: search for `total`, `subtotal`, `grand_total` assignments. If the value originates from the request body, or the server persists whatever arrives, record the endpoint: totals must be recomputed at write time from catalog data.
- Cart payloads carrying `unit_price`: legitimate clients may echo prices, but the server must ignore them and join catalog prices itself. Confirm in the persistence path, not the DTO.
- Currency handling: identify the source of `currency`. Flag client-selected currency applied to fixed-price catalog items (JPY-priced item paid as nominal USD), missing currency on money columns, and any float/double holding money (`float price`, JS arithmetic on cents). Demand integer minor units or `DECIMAL`.
- Negative and zero operands: reason through `-1` quantities, `-100` refund/transfer/top-up amounts, zero-cost orders. Verify validation (`@Positive`, `@Min(0)`, schema `minimum`) actually executes on every write path including admin panels, importers, GraphQL resolvers, and queue consumers.
- Coupons: audit apply/redeem handlers for percentage-vs-absolute confusion, unvalidated stacking (multiple coupons per order), reuse without per-user/global consumption counters, expiry checked client-side, minimum-order rules enforced only in UI, and discounts not clamped to order subtotal (negative subtotals).
- Free-tier quota resets: find quota fields and reset jobs. Determine whether deleting the account, re-signing up, cycling plan downgrade/upgrade, or changing email resets consumption. Consumption must key to immutable identity, not mutable plan rows or email strings.

### Race Conditions and TOCTOU

- For each handler mutating a counter or scarce resource, extract the exact sequence READ (`findOne`, `get`, `SELECT`) -> CONDITION (`if balance >= x`) -> WRITE (`save`, `UPDATE`, `decrement`). Record file:line for both READ and WRITE. Absent a single transaction containing a row lock, or replacement by one conditional atomic statement, log a CWE-362 candidate.
- Prioritize balances, wallets, credits, points; then stock, inventory, seat/slot reservations (note if oversell is documented as tolerated; adjust severity, do not silently drop).
- Voucher/coupon/gift-card single use: demand an INSERT into a redemptions table guarded by `UNIQUE(voucher_id)` (or `(voucher_id, user_id)`), or an atomic conditional UPDATE checking affected rows. A boolean flip via read-modify-write fails under concurrency.
- Signup uniqueness: confirm a database UNIQUE constraint on username/email/phone exists (check migrations/schema), not merely an application-level `exists()` probe; duplicate-key errors should surface as friendly conflicts.
- Rate-limit counters: inspect limiter internals. Non-atomic GET-then-INCR, or application-side dicts, undercount under parallel load. Demand `INCR`/`INCRBY` with expiry or a Lua script.
- Upload pipelines: compare publish/serve timing against antivirus/media processing. If objects are readable before scan verdicts land, or scans read bytes that concurrent writes replace, flag CWE-367. The fixed shape stages uploads in a temp location and publishes by atomic rename after verdict.
- Revocation vs live state: ban/disable/de-role handlers versus JWT validity windows, cached authorization decisions, and pooled sessions. Report revocation latency when privileged tokens stay valid until natural expiry with no blacklist or introspection step.
- Payments: mark withdraw/refund/transfer/capture handlers lacking idempotency keys as double-spend candidates. Webhook receivers must verify signatures before parsing trust, then de-duplicate provider event ids before mutating state.

### Time-Based Logic

- Trial periods: find where `trial_end` / `trial_ends_at` is computed. Flag derivation from client-supplied timestamps (body `started_at`, header dates, client-asserted JWT claims). Deadlines derive from the server clock at creation and compare against the server clock at use.
- Expiry comparisons: confirm every gating action compares stored expiry against server `now()`. Render-time-only checks leave action endpoints usable past expiry.
- Scheduled jobs: list cron/queue schedules resetting quotas, expiring holds, closing batches. Identify gap bugs: daily-at-midnight reset makes windows job-to-job, not calendar-day; missed or doubled runs break allowances. Flag additive resets (grant += X) over idempotent ones (set window start).
- Timezone/DST edges: find mixed UTC/local usage in expiry math (`Carbon::now()` vs DB `NOW()` vs JS `Date`). "23:59 local" evaluated in UTC opens bypass windows; recurring jobs during DST fall-back can execute twice.
- JWT time claims: confirm validation of `exp`/`nbf` against server clock with small skew tolerance. Flag client-asserted `iat` or custom claims feeding trial or cooldown math.

### Counting and Limit Logic

- Pair every limit constant (`MAX_*`, `max_uses`, `daily_limit`) with the field incremented at consumption. Mismatches (check `usage_count`, increment `uses`; check per-user, increment global) produce either permanent blockage or infinite allowance.
- Per-request vs aggregate: limits must read persistent per-period counters, not values that reset per request, per process restart, or per in-memory dict eviction.
- Soft-delete interactions: if consumption queries exclude soft-deleted rows (`WHERE deleted_at IS NULL`) while the limit intends lifetime totals, purging history resurrects quota. Compare count-query filters against business intent.
- Window definitions: rolling vs fixed windows and timezone anchoring of "day"; fixed windows allow burst-doubling at boundaries (100 at 23:59 plus 100 at 00:01).
- Pagination-based enumeration of others' records (shared admin listings exposed to users, sequential-ID invoice pages): record as input for the AUTHZ module; note here only where scraping damages a business invariant (farming referral codes, harvesting vouchers).

### Approval and Multi-Party Flows

- Extract approver identity from the server session exclusively; `approved_by` accepted from the payload is a self-approval primitive.
- Require creator-vs-approver rejection (`created_by == approver_id` refused) wherever four-eyes is claimed.
- Enforce transition order: approve/reject handlers validate current status permits the action (`SUBMITTED -> APPROVED` legal; approve-before-submit or approve-after-cancel illegal).
- Walk delegation resolution for cycles (A delegates to B delegates to A) and depth limits; flag silent cycle acceptance or stack-exhausting recursion.
- Confirm claimed four-eyes processes cannot complete through one principal holding both roles (self-group membership, admin granting then exercising approval rights).

### Referral, Cashback, and Gift Systems

- Self-referral: check referrer linkage validation (distinct identity proof, device/payment fingerprinting, email normalization). Purely client-declared `referred_by` with immediate credit equals an infinite money loop given disposable identities; document the economics.
- Reward triggers: rewards post only after irreversible qualifying events (paid orders, not submitted ones) and are themselves idempotent (reward rows keyed by qualifying entity id).
- Gift cards: assess code alphabet/length entropy, hashed-at-rest storage (cross-ref SECRETS), redemption throttling (cross-ref API rate limiting), and partial-redemption residual-balance updates (race-prone read-modify-write).
- Transfers: reject negative/zero amounts, sender == recipient, and two-row non-atomic movement (debit committed then credit failing). Flag self-transfer loops farming per-transaction cashback.

### Idempotency and Replay Safety

- Inventory money-moving endpoints (charge, capture, refund, payout, transfer, top-up, subscribe, provision). Each requires one of: a client-supplied idempotency key honored server-side with stored-response replay, natural idempotency (conditional update consuming a nonce), or documented safe retry semantics. Absence is a finding.
- Webhooks/callbacks: require provider signature verification, event-id de-duplication storage, and out-of-order tolerance (monotonic `updated_at` guard) before any state mutation.

## Where To Look

### Business-Domain File and Symbol Inventory

Build the audit surface with filename and symbol searches (adapt to repo layout):

| Domain | Path/name keywords | Entity/symbol keywords |
|---|---|---|
| Orders/checkout | `checkout`, `cart`, `order`, `basket` | `Order`, `Cart`, `LineItem`, `place_order`, `submitOrder` |
| Payments/ledger | `payment`, `billing`, `ledger`, `wallet`, `invoice` | `Charge`, `Refund`, `Balance`, `LedgerEntry` |
| Promotions | `coupon`, `promo`, `discount`, `voucher`, `gift` | `Coupon`, `Redemption`, `GiftCard` |
| Entitlements | `plan`, `subscription`, `trial`, `quota`, `entitlement` | `Subscription`, `Usage`, `Allowance` |
| Trust transitions | `verify`, `kyc`, `onboard`, `approve`, `review` | `Verification`, `Approval`, `KYCStatus` |
| Movement | `transfer`, `withdraw`, `payout`, `topup`, `cashback`, `referral` | `Transfer`, `Withdrawal`, `Reward` |
| Scarce goods | `inventory`, `stock`, `seat`, `slot`, `reservation` | `StockItem`, `Reservation` |

### Schema and Migration Definitions

- Read migrations and schema files first (`migrations/`, `db/schema.rb`, `prisma/schema.prisma`, JPA `@Entity` classes, Django `models.py`): constraints here are ground truth. For each money/state column record: type (`DECIMAL` or bigint minor units vs float), NULLability, defaults, UNIQUE indexes, CHECK constraints, foreign keys.
- Extract enum definitions for lifecycle columns; they reveal the intended state machine. List every transition referenced in code and diff it against the enum's implied legality.
- Missing-constraint observations feed Remediation directly: no UNIQUE on redemptions, no CHECK on balances means the last-line defenses are absent.

### Client Gates to Diff Against Server

- SPA route guards and wizard components (`ProtectedRoute`, `canActivate`, `beforeRouteEnter`, stepper libraries), disabled buttons, hidden form sections. Each corresponds to a server-side check that must exist independently of the client.

### Jobs, Queues, Cron

- Celery beat, Sidekiq scheduler, Quartz, node-cron, Kubernetes CronJobs, cloud scheduler entries: quota resets, expiring holds, batch closings, reward postings. These carry time-based logic findings.

### Configuration and Flags

- Trial lengths, plan quotas, coupon definitions, feature flags toggling payment enforcement, seed/demo payment providers left enabled in production configuration.

## Patterns & Signatures

Run all regexes from the repo root with ripgrep; expect noise, then triage by opening hits. Keep patterns single-line (no lookarounds, no cross-line matching) for ripgrep compatibility.

### Read-Modify-Write Shapes

```regex
\b(findOne|findById|findFirst|firstOrFail|get_object_or_404|objects\.get)\b.{0,60}\b(account|wallet|balance|stock|inventory|quota|coupon|voucher|credit|points)\b
\.(balance|stock|quantity|credits|points|uses|usage_count)\s*=\s*[^=]
\b(save|persist|updateOne|updateMany|update\(|SaveChangesAsync|flush)\(
\b(INCR|DECR|INCRBY|DECRBY|increment|decrement|incrBy)\(
```

A hit pairing line one (READ), line two (in-place assignment), and line three (WRITE) inside one handler is the canonical race shape; capture all three file:line references as evidence.

### Check-Then-Act Conditionals

```regex
if\s*\(?\s*[\w.]*\b(balance|stock|remaining|available|slots|seats|credits|quota|uses_left|max_uses)\b\s*(>=?|<=?|==|!=)
\bexists\(|\bexists\?\(|\.Exists\(|countDocuments
\b(count\(\)|COUNT\(\*\)|count\(\*\))\b.{0,40}(<|>|<=|>=)
```

### Money-Mutation Route Names (candidate endpoint list)

```regex
/(pay|charge|refund|withdraw|deposit|transfer|redeem|payout|topup|purchase|subscribe|cashback|reward)s?
```

### Transaction Vocabulary (complement of the absence marker)

Search within roughly +/- 40 lines of each money-mutating handler body. These keywords are the expected companions of safe writes:

```regex
select_for_update|with_for_update|FOR UPDATE|LOCK IN SHARE MODE|with_lock|lock!|lockForUpdate
PESSIMISTIC_WRITE|LockModeType|SERIALIZABLE|Isolation\.
DB::transaction|TransactionScope|BeginTx|begin_transaction|withTransaction|startSession
WATCH|\bMULTI\b|\bEVAL\b|evalsha|redis\.Lua|atomic\(|F\("balance"\)|F\('balance'\)
```

Absence-marker judgment rule: absence of this vocabulary near a money write is a lead, never proof. Before reporting: check global wrappers (Django `ATOMIC_REQUESTS = True` in settings, base-controller transactions, ORM unit-of-work behavior); note that atomicity wrappers give rollback, not mutual exclusion, so a globally-atomic request can still race its reads. Report the specific unlocked READ/CONDITION/WRITE lines with file:line, not "missing keyword". Conversely, if a lock or atomic statement does exist up the call chain, drop the candidate.

### State and Step Fields From Requests

```regex
req\.body\.(status|state|step|stage|verified|approved|is_paid|role)
["'](status|state|step|verified|approved|is_paid)["']\s*:
request\.data\.get\(["'](status|state|step|approved|verified)
\$_(POST|GET|REQUEST)\[["'](status|state|step|approved|verified)["']\]
```

### Totals and Prices From Requests

```regex
["']?(total|grand_total|amount_due|final_total|unit_price|price|amount|discount_value|currency)["']?\s*[:=]\s*-?[0-9"']
(float|double|Float|Double)\s+(price|amount|total|balance|fee)
Math\.round\(.{0,30}(price|amount|total)|toFixed\(2\)
```

### Time Sources

```regex
Date\.now\(\)|new Date\(\)|datetime\.now\(\)|time\.Now\(\)|Time\.now|Carbon::now|LocalDateTime\.now|Instant\.now\(\)
\biat\b|\bexp\b|\bnbf\b|claims\[.(iat|exp|nbf).\]|issuedAt|expiration
trial_(start|end|days)|trialStart|trialEnd|expiresAt|expires_at|valid_until|reset_at|period_start
```

### Limits and Counters

```regex
max_uses|usage_limit|usage_count|times_used|redemption_count|daily_limit|per_day|monthly_quota|[A-Z_]*MAX_[A-Z_]+
window_start|next_reset|rolling|fixed_window
page_size|pageSize|\boffset\b|cursor=
```

### Approvals

```regex
(approved_by|approver|reviewer_id|rejected_by|delegated_to|four_?eyes)
(created_by|author_id|requester).{0,30}(==|!=|equals).{0,30}(approver|user_id|current_user)
status\s*(===?|==)\s*["'](APPROVED|Approved|PAID|SHIPPED)["']
```

### Idempotency Presence

```regex
Idempotency[-_ ]?Key|idempotency_key|idempoten[a-z]*|event_id|eventId|dedup[a-z]*|\bnonce\b|replay
```

Zero hits across a repo containing payment endpoints is itself a high-priority lead.

### Language-Specific Primitives to Demand

| Stack | Required primitive for counter safety |
|---|---|
| Python/Django | `select_for_update()` inside `transaction.atomic()`; `F()` expressions for single-column deltas |
| Python/SQLAlchemy | `with_for_update()` on the SELECT within one `session.begin()` |
| Java/JPA | `LockModeType.PESSIMISTIC_WRITE` or `@Version` columns inside `@Transactional` |
| C#/EF Core | `[Timestamp] RowVersion` concurrency token or guarded `ExecuteUpdate`; explicit `TransactionScope` |
| Node/Mongo | `findOneAndUpdate({_id, balance: {$gte: amt}}, {$inc: {...}})`; multi-document work via session `withTransaction` (replica set required) |
| Node/Redis | Lua script (check+write atomically) over `WATCH/MULTI/EXEC` retries |
| Go | `database/sql` `BeginTx` plus `SELECT ... FOR UPDATE`; never `sync.Mutex` across replicas |
| Ruby/Rails | `ActiveRecord::Base.transaction` with `.lock` / `with_lock`; SQL-side deltas |
| PHP/Laravel | `DB::transaction(fn)` plus `lockForUpdate()`; `decrement()` compiles to atomic SQL |
| SQL itself | `UPDATE ... SET col = col - :x WHERE ... AND col >= :x` plus UNIQUE indexes as final backstop |

## Taint Tracing Guidance

### Source Taxonomy for This Module

| Source | Trust level | Handling rule |
|---|---|---|
| Body/query fields (`price`, `total`, `qty`, `currency`, `status`, `step`, `approved_by`) | Attacker-controlled | Never drive money or state transitions directly; recompute or reject |
| Headers (`Idempotency-Key`, client dates) | Semi-controlled | Key: opaque dedupe token bound to user plus request hash. Dates: never feed expiry math |
| JWT/session claims | Trusted only if server-signed and server-issued | Client-asserted `iat` or custom `trial_start` claims are attacker-controlled |
| Webhook payloads | Attacker-influenceable | Verify signature first, de-duplicate event id second, mutate third |
| Catalog/database-derived values | Trusted | The only legitimate operands for totals and pricing |

### Propagation Paths to Walk

- Controller/DTO -> service -> repository: walk each operand of the final write back to its source. A DTO-layer validator rejecting negatives guards nothing unless every write path passes through it; admin endpoints, GraphQL resolvers, importers, and queue consumers routinely bypass the front-door validation.
- Item arrays: `items[]` loops multiply tampering (one legitimate line item hides one negative-quantity item). Trace per-element handling and per-element validation.
- Cross-service hops: totals computed in service A but persisted by service B; the trust decision lives in A while B blindly persists whatever arrives.
- Async/job boundaries: the request validates, then enqueues a job that executes later without revalidation. Time passes and state changes between check and act; require re-validation inside the consumer.

### Sink Inventory

Treat as sinks: writes to `balance`, `credits`, `points`, `stock`, `usage_count`, lifecycle `status`/`state` columns, `expires_at`/`trial_end` fields, reward or grant inserts, role/permission grants, and any third-party money API call (`stripe.Charge.create`, payout SDKs, bank transfer APIs). A tainted operand reaching a sink is a candidate finding. A tainted operand reaching only a comparison (`if body.total == computed.total`) is a weak guard at best: equality still leaks an oracle, and the computed side may itself consume tainted inputs.

## Exploitation & Reproduction

Execute dynamic reproduction only against environments you are explicitly authorized to test. When no instance exists, deliver the static trace (see Static-Only Confirmation Protocol) as the reproduction of record.

### Setup Variables

```bash
BASE="https://target.example"
TOKEN="eyJ..."   # authenticated low-privilege test session
```

### Repro A: Concurrent Redemption of a Single-Use Voucher

1. Confirm statically that the redeem handler flips a boolean via read-modify-write (capture file:line of READ and WRITE, verify no lock and no UNIQUE constraint on redemptions).
2. Fire ten simultaneous requests:

```bash
for i in $(seq 1 10); do
  curl -s -o "resp_$i.json" -w "%{http_code} " \
    -X POST "$BASE/api/vouchers/redeem" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"code":"WELCOME50"}' &
done
wait; echo
grep -h -o '"success":[a-z]*' resp_*.json | sort | uniq -c
```

Equivalent xargs form:

```bash
printf '%s\n' $(seq 1 10) | xargs -P10 -I{} curl -s -X POST "$BASE/api/vouchers/redeem" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME50"}' -o "resp_{}.json"
grep -l 'success.:true' resp_*.json | wc -l
```

3. Expected observable when vulnerable: more than one `"success":true` / HTTP 200 for one voucher; account credited multiple times. Patched behavior: exactly one success, remainder 409/422.
4. If all-but-one requests fail, raise parallelism to 50-100, minimize payload variance, and check whether a queue serializes writes in front of the handler (that serialization is a mitigation; document it rather than claiming exploitability).

### Repro B: Concurrent Withdrawal / Double Spend

1. Statically confirm the withdraw handler shows balance-check then separate debit write with no shared transaction or lock.
2. Fund the authorized test account, then race two withdrawals:

```bash
for i in $(seq 1 2); do
  curl -s -X POST "$BASE/api/wallet/withdraw" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"amount":100.00,"destination":"ext-test-acc-1"}' &
done
wait
curl -s "$BASE/api/wallet/balance" -H "Authorization: Bearer $TOKEN"
```

3. Scale signal by launching N parallel withdrawals of `(balance / N) + 1` each.
4. Expected observable when vulnerable: two success responses, negative final balance, or one payout recorded twice in the ledger.

### Repro C: Workflow Bypass via Direct Endpoint Access

Checkout-without-payment sequence:

```bash
# 1. Create cart through the normal entry point.
CART_ID=$(curl -s -X POST "$BASE/api/cart" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"items":[{"sku":"SKU-1","qty":1}]}' | grep -o '"id":"[^"]*"' | head -1)

# 2. Jump directly to order creation, skipping POST /api/payments entirely,
#    supplying the status field the payment step would have set.
curl -s -X POST "$BASE/api/orders" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"cart_id\":\"$CART_ID\",\"status\":\"SUBMITTED\",\"payment_id\":null}"
```

Expected observable when vulnerable: 200/201 returning an order in SUBMITTED or PAID state despite zero payment records; contrast against the UI-enforced sequence cart -> pay -> order.

Further bypass probes:

- Email-verification-gated feature: call the gated endpoint directly using an unverified fixture account; success equals bypass.
- Password change: `curl -s -X POST "$BASE/api/user/password" -d '{"new_password":"New123!"}'` succeeding without current-password or session re-authentication equals finding.
- Step-token skip: replay the final-step request while omitting or garbage-substituting intermediate step tokens; acceptance equals server-side non-validation.

### Repro D: Price Tampering Request Body Diff

Capture a legitimate checkout body from the browser devtools, then send its tampered twin:

```json
{"cart_id":"c-123","items":[{"sku":"SKU-1","qty":1,"unit_price":49.90}]}
{"cart_id":"c-123","items":[{"sku":"SKU-1","qty":1,"unit_price":0.01}],"total":0.01,"currency":"USD"}
```

Negative-quantity credit variant:

```json
{"items":[{"sku":"SKU-1","qty":-3,"unit_price":49.90}]}
```

Expected observable when vulnerable: stored order reflects attacker values (0.01 charged, or wallet/store credit increased by 149.70 through refund-on-negative-purchase logic). Currency variant: identical numeric total posted under `USD` where the catalog priced the item in `JPY`. Compare persisted order rows (admin view, order confirmation endpoint) against catalog prices as evidence.

### Repro E: Coupon Reuse and Stacking

- Sequential reuse: apply code, complete order, apply same code on next order; success every time means no per-user or global consumption enforcement.
- Stacking: issue repeated calls to the apply-coupon endpoint within one cart (or submit multiple codes where the UI allows one); observe discounts summing past bounds, including negative subtotals.
- Note per-account apply-throttling presence here; brute-force feasibility of code space routes to the API module rate-limit analysis.

### Static-Only Confirmation Protocol

When no test instance is authorized:

1. Print the handler source; bracket the READ statement and the WRITE statement with file:line numbers.
2. Search the enclosing function plus decorators/middleware for transaction vocabulary (Patterns section). Nothing found equals gap candidate.
3. Check global wrappers before concluding: settings flags (`ATOMIC_REQUESTS`), base-controller transactions, ORM unit-of-work autoflush, queue serialization ahead of the endpoint. Remember atomicity wrappers prevent partial failure, not interleaved reads.
4. Check schema backstops: UNIQUE on redemption tables, CHECK on balances. Absence removes the last-line defense and raises severity.
5. Write the causal chain into the report: "Request A completes READ at wallet.py:120; Request B reads the same stale balance at wallet.py:120; both pass the guard at :121; both WRITE at :140; invariant broken." That chain is the reproduction.

## Remediation

Apply fixes in layers, strongest first: constrain the database, atomize the write, serialize structurally hot paths, then harden the protocol with idempotency keys, state machines, and server-side recomputation. One layer alone is brittle; ship at least a database backstop plus an atomic write for every invariant.

### Canonical Pattern: Atomic Conditional Update (SQL)

Single-statement mutation carrying its own guard; affected-rows = 0 signals rejection. Every stack below maps onto this shape:

```sql
-- FIXED: atomic guarded debit; no separate SELECT, no application-side branch
UPDATE accounts
   SET balance = balance - :amount
 WHERE id = :account_id
   AND balance >= :amount;
-- application checks rowCount(): 0 -> insufficient funds
```

Redemption as insert-only fact with a database-enforced cap:

```sql
-- FIXED: single use enforced by UNIQUE; second insert raises duplicate-key
CREATE TABLE voucher_redemptions (
  voucher_id  BIGINT NOT NULL,
  user_id     BIGINT NOT NULL,
  redeemed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (voucher_id)
);
```

Last-line constraints for every invariant named in this module:

```sql
ALTER TABLE accounts     ADD CONSTRAINT chk_balance_nonneg CHECK (balance >= 0);
ALTER TABLE order_items  ADD CONSTRAINT chk_qty_positive   CHECK (qty > 0);
ALTER TABLE users        ADD CONSTRAINT uq_users_email     UNIQUE (email);
ALTER TABLE coupons_used ADD CONSTRAINT uq_coupon_user     UNIQUE (coupon_id, user_id);
```

Money columns: `DECIMAL(19,4)` or bigint minor units, `NOT NULL`, never float/double.

### Python

```python
# VULNERABLE: check-then-act; gap spans two queries and all intervening logic
acct = Account.objects.get(pk=account_id)
if acct.balance >= amount:
    acct.balance -= amount
    acct.save()
```

```python
# FIXED: row lock + atomic delta inside one transaction
from django.db import transaction
from django.db.models import F

with transaction.atomic():
    acct = Account.objects.select_for_update().get(pk=account_id)
    if acct.balance < amount:
        raise InsufficientFunds()
    acct.balance = F("balance") - amount
    acct.save(update_fields=["balance"])
```

asyncio note: a coroutine that awaits between check and write yields the event loop and interleaves other coroutines; single-process asyncio provides zero mutual exclusion. Multi-worker deployments (gunicorn, uvicorn workers, celery processes) share nothing in memory; only database locks and atomic statements serialize across them. Celery note: tasks redeliver after broker visibility timeouts, so handlers must be idempotent; key side effects on task/entity ids and record them in a unique-constrained journal table before executing.

SQLAlchemy equivalent: `session.execute(select(Account).where(...).with_for_update())` inside one explicit `session.begin()` block.

### Java

```java
// VULNERABLE: plain find + setter; two transactions read the same balance
Account a = em.find(Account.class, id);
if (a.getBalance().compareTo(amount) >= 0) {
    a.setBalance(a.getBalance().subtract(amount));
}
```

```java
// FIXED: pessimistic row lock inside an explicit transaction boundary
@Transactional(isolation = Isolation.READ_COMMITTED)
public void withdraw(Long id, BigDecimal amount) {
    Account a = em.find(Account.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (a.getBalance().compareTo(amount) < 0) throw new InsufficientFunds();
    a.setBalance(a.getBalance().subtract(amount));
}
```

Isolation notes: REPEATABLE_READ or snapshot isolation does not stop two writers from both passing a balance guard (write skew); either take the pessimistic row lock as shown, run the guarded path SERIALIZABLE, or translate to the conditional-UPDATE shape. Optimistic alternative: annotate `@Version Long version;` and retry on `OptimisticLockException`.

### C#

```csharp
// VULNERABLE
var acct = db.Accounts.Find(id);
if (acct.Balance >= amount) { acct.Balance -= amount; }
await db.SaveChangesAsync();
```

```csharp
// FIXED: RowVersion concurrency token + explicit transaction scope
public byte[] RowVersion { get; set; }  // [Timestamp] on the entity class

using var scope = new TransactionScope(TransactionScopeOption.Required,
    new TransactionOptions { IsolationLevel = IsolationLevel.ReadCommitted },
    TransactionScopeAsyncFlowOption.Enabled);
var acct = db.Accounts.Single(x => x.Id == id);
if (acct.Balance < amount) throw new InsufficientFunds();
acct.Balance -= amount;
await db.SaveChangesAsync();  // DbUpdateConcurrencyException on lost update
scope.Complete();
```

Where EF Core 7+ is available, prefer translating guard and write into one statement (`ExecuteUpdate` with a `WHERE Balance >= amount` predicate) so no interleaving point exists at all.

### Node.js

No native transaction spans `await`s; correctness comes from conditional atomic operations, Mongo transactions on replica sets, or Redis Lua.

```javascript
// VULNERABLE: await gap between check and write; concurrent requests interleave here
const acct = await accounts.findOne({ _id });
if (acct.balance >= amount) {
  await accounts.updateOne({ _id }, { $set: { balance: acct.balance - amount } });
}
```

```javascript
// FIXED (single document): conditional atomic update; matchedCount 0 => insufficient
const r = await accounts.updateOne(
  { _id, balance: { $gte: amount } },
  { $inc: { balance: -amount } }
);
if (r.matchedCount === 0) throw new InsufficientFunds();
```

Multi-document work requires a replica set and a session:

```javascript
// FIXED (multi-document): Mongo transaction
const session = client.startSession();
try {
  await session.withTransaction(async () => {
    const acct = await accounts.findOne({ _id }, { session });
    if (acct.balance < amount) throw new InsufficientFunds();
    await accounts.updateOne({ _id }, { $inc: { balance: -amount } }, { session });
    await ledgers.insertOne({ accountId: _id, delta: -amount }, { session });
  });
} finally { await session.endSession(); }
```

Redis counters: never GET-then-DECR blindly; make check+write one atomic script.

```lua
-- FIXED: returns remaining balance, or -1 when funds are insufficient
local bal = tonumber(redis.call('GET', KEYS[1]) or '0')
if bal < tonumber(ARGV[1]) then return -1 end
return redis.call('DECRBY', KEYS[1], ARGV[1])
```

### Go

```go
// VULNERABLE: two bare statements; sync.Mutex would only guard one process
var bal int64
db.QueryRowContext(ctx, `SELECT balance FROM accounts WHERE id=$1`, id).Scan(&bal)
if bal >= amount {
    db.ExecContext(ctx, `UPDATE accounts SET balance=$1 WHERE id=$2`, bal-amount, id)
}
```

```go
// FIXED: single Tx holding the row lock until commit
tx, err := db.BeginTx(ctx, nil)
if err != nil { return err }
defer tx.Rollback()

var bal int64
err = tx.QueryRowContext(ctx,
    `SELECT balance FROM accounts WHERE id=$1 FOR UPDATE`, id).Scan(&bal)
if err != nil { return err }
if bal < amount { return ErrInsufficientFunds }

_, err = tx.ExecContext(ctx,
    `UPDATE accounts SET balance = balance - $1 WHERE id = $2`, amount, id)
if err != nil { return err }
return tx.Commit()
```

`sync.Mutex` scope warning: it excludes goroutines within one binary only; replicas bypass it entirely. Reserve mutexes for in-process caches, never for money.

### Ruby

```ruby
# VULNERABLE
acct = Account.find(id)
acct.update!(balance: acct.balance - amount) if acct.balance >= amount
```

```ruby
# FIXED
Account.transaction do
  acct = Account.lock.find(id)            # SELECT ... FOR UPDATE
  raise InsufficientFunds if acct.balance < amount
  acct.balance -= amount                  # or express as SQL delta
  acct.save!
end
# equivalent shorthand: acct.with_lock { ... }
```

Outside a held lock, never assign a money field from a previously-read value; prefer SQL-side deltas so the arithmetic executes next to the row.

### PHP (Laravel)

```php
// VULNERABLE
$acct = Account::find($id);
if ($acct->balance >= $amount) {
    $acct->balance -= $amount;
    $acct->save();
}
```

```php
// FIXED
use Illuminate\Support\Facades\DB;

DB::transaction(function () use ($id, $amount) {
    $acct = DB::table('accounts')->where('id', $id)->lockForUpdate()->first();
    if ($acct->balance < $amount) {
        throw new InsufficientFunds();
    }
    DB::table('accounts')->where('id', $id)->decrement('balance', $amount);
});
```

`decrement()` compiles to atomic `SET balance = balance - ?`; combine it with a guarded WHERE clause for check-free safety where business rules allow.

### Idempotency Key Design and Handling

```sql
CREATE TABLE idempotency_keys (
  key             VARCHAR(255) PRIMARY KEY,
  user_id         BIGINT      NOT NULL,
  request_hash    CHAR(64)    NOT NULL,
  response_status SMALLINT,
  response_body   JSONB,
  created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (key)
);
```

Handling pattern (stack-independent):

1. Require the client header on charge/refund/transfer/provision endpoints; scope the stored key with `user_id`.
2. Attempt `INSERT ... ON CONFLICT DO NOTHING`. Zero inserted rows means duplicate: SELECT the stored response and replay it verbatim without re-executing side effects. For simultaneous duplicates of an in-flight request, take a row lock on the key row and wait or return 409.
3. Execute business logic in one transaction; commit the response snapshot together with the business writes so replay is exact.
4. Reject key reuse carrying a different `request_hash` (422): prevents collision smuggling of a second payload under a paid key.

### Server-Side State Machine Enforcement

Model lifecycles explicitly and route every mutation through the guard:

```python
# FIXED: closed transition table; anything unlisted is rejected
from enum import Enum

class OrderStatus(Enum):
    CART = "CART"; SUBMITTED = "SUBMITTED"; PAID = "PAID"
    SHIPPED = "SHIPPED"; DELIVERED = "DELIVERED"; CANCELLED = "CANCELLED"; REFUNDED = "REFUNDED"

TRANSITIONS = {
    OrderStatus.CART:      frozenset({OrderStatus.SUBMITTED}),
    OrderStatus.SUBMITTED: frozenset({OrderStatus.PAID, OrderStatus.CANCELLED}),
    OrderStatus.PAID:      frozenset({OrderStatus.SHIPPED, OrderStatus.REFUNDED}),
    OrderStatus.SHIPPED:   frozenset({OrderStatus.DELIVERED}),
}

def transition(entity, target, actor):
    if target not in TRANSITIONS.get(entity.status, frozenset()):
        raise IllegalTransition(f"{entity.status} -> {target}")
    entity.status = target
    entity.save(update_fields=["status"])   # persist inside a transaction
```

Rules: lifecycle columns hold enums and are non-null; direct `status=` assignments outside the guard are banned by review and grep; payment-driven transitions fire only from verified provider callbacks whose event ids passed de-duplication; step/flow tokens bind server-side to `(user, session, next_state)` and are consumed single-use.

### Server-Side Recomputation Rule

Compute totals, taxes, discounts, and currency conversion at write time from server-owned data (catalog tables, pricing service, FX rates). The client-supplied total is at most an integrity hint: recompute server-side and, on mismatch, reject or accept-and-flag per product policy; never silently persist the client figure. Validate quantity positivity on every path. Clamp coupon discounts to order subtotal; apply single-coupon semantics unless stacking is explicitly modeled with precedence and cap rules.

### Queue Serialization for Hot Resources

When contention is structural (one inventory row during flash sales), funnel every mutation for the resource through a single ordered channel: message-broker partition keyed by `account_id`/`sku_id` consumed by exactly one worker, or a DB-backed job table polled per resource shard. Producers receive 202 plus job id; consumers perform locked transactions and publish results. This trades latency for the impossibility of interleaving.

### Optimistic Locking Version Columns

Low-contention tables: add `version INT NOT NULL DEFAULT 0`; every update runs `... WHERE id = :id AND version = :expected_version` setting `version = version + 1`; zero affected rows means concurrent modification: retry or 409. Native support: JPA `@Version`, EF `[Timestamp]`, Rails `lock_version`. Combine with CHECK constraints so even a lost-update bug cannot mint negative balances.

### Clock Hygiene

Store expiry and trial deadlines server-side at creation; compare against the server clock at every use; ignore client timestamps everywhere. Implement resets as idempotent "set current window start" operations rather than additive grants. Pin scheduled jobs to UTC and handle DST transitions explicitly in window math.

## Verification & Validation

### Concurrency Regression Tests

Port the template below to pytest, JUnit, xUnit, or go test as available. Require a real database (testcontainers or CI service container); in-memory fakes hide exactly this defect class.

```
GIVEN an account with balance 100
  AND endpoint POST /wallet/withdraw accepting {"amount": 100}

WHEN 10 threads simultaneously POST /wallet/withdraw
THEN exactly 1 response is success (2xx)
 AND final stored balance == 0
 AND no ledger row implies a negative balance

GIVEN an account with balance 900
WHEN 10 threads each withdraw 100 concurrently
THEN exactly 9 succeed
 AND final balance == 0

GIVEN single-use voucher V
WHEN 20 threads redeem V concurrently
THEN exactly 1 redemption row exists
 AND the other 19 responses are 409/422

FINALLY rerun each scenario at parallelism 2, 10, and 50; outcomes must not vary
```

Worker-pool sketch for the harness:

```text
barrier = Barrier(N)
results = parallel_map(range(N),
    lambda i: (barrier.wait(), http_post(WITHDRAW_ENDPOINT, body))[1])
assert count_2xx(results) == expected_successes
assert stored_balance_after == expected_final_balance
```

### Negative Tests (legitimate flows unaffected)

- Sequential withdrawal/debit of available funds succeeds; overdraft attempt fails with a clean domain error.
- Normal checkout through the full step order completes; direct order-creation now returns 409 "payment required".
- Valid coupon applies exactly once per order and once per user where configured; second application rejected.
- Password change with correct current password works; without it returns 400/403.
- Verified users reach gated features immediately; guards must not punish the honest path.
- Retrying a completed payment with the same idempotency key replays the original response and creates no second charge.
- Quota consumption survives process restarts; window reset fires exactly once per period.

### Manual Review Checklist

- Every lifecycle column has a server-enforced transition guard, not merely enum typing.
- Every money write sits inside a transaction with a lock or is one conditional atomic statement, verified against global wrapper settings.
- Every payment-class endpoint honors an idempotency key or a natural unique constraint.
- Totals recomputed server-side on every order/refund path including admin, importer, and webhook copies.
- All expiry comparisons use the server clock against stored values.
- Limit checks and consumption increments touch the same field, window, and key.
- Approval handlers reject creator-equals-approver and enforce status order.
- Referral rewards post only after irreversible qualifying events and are idempotent.
- Schema carries UNIQUE/CHECK backstops for every invariant above.

### Post-Fix Greps

Confirm fixes landed and no sibling regressed:

```bash
rg -n "select_for_update|lockForUpdate|PESSIMISTIC_WRITE|with_lock|FOR UPDATE" app/
rg -ni "Idempotency-Key|idempotency_key" app/
rg -n "CHECK \\\(balance|UNIQUE \\\(voucher" migrations/
rg -n "req\.body\.(total|price|amount|status|qty)" app/
```

Expected: transaction vocabulary adjacent to every money handler; zero request-sourced totals reaching persistence (or a recompute call at each); constraint migrations present.

## Severity Assessment

### Mapping and Rubric

Score with the official CVSS v3.1 calculator against the specific asset; vectors below are starting points.

| Finding class | Primary CWE | Illustrative vector | Default rating |
|---|---|---|---|
| Money creation: double-spend, negative-transfer credit, unlimited coupon/referral loops | CWE-362 / CWE-20 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` (~7.1) | Critical |
| Workflow bypass reaching privileged outcome (unpaid fulfillment, unverified account performing KYC-gated actions, self-approved payouts) | CWE-20 (A04 design) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | High to Critical by blast radius |
| Bounded race: one voucher reused, oversell of limited units | CWE-362 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L` | High |
| Quota/free-tier abuse or discount stacking without direct loss | CWE-20 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` | Medium |
| Revocation latency (banned user retains access minutes-to-hours) | CWE-367 | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` | Medium |
| Cosmetic state inconsistency without economic effect | CWE-362 | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L` | Low |

Attack complexity stays Low for races once a parallel script exists (Repro A/B are reliable by construction); some programs argue AC:H pre-automation. Resolve via program policy and let the rubric band, not the decimal, carry the message.

Rubric anchors:

- Critical: attacker mints, multiplies, or moves money/value at scale (double-spend, self-funding referral loops, unpaid orders fulfilled).
- High: bypass reaches a privileged or trust transition without direct cash (verification skip feeding fraud pipelines, self-approval of payments).
- Medium: bounded economic leakage (quota resets, capped stacked discounts) or revocation gaps.
- Low: user-visible inconsistent state with no economic or trust consequence.

### CWE Selection Notes

Assign CWE-362 for unsynchronized concurrent access; CWE-367 specifically where a check's validity expires before its dependent use (upload scan vs publish, revocation vs live session). Assign CWE-20 for tampered operands (totals, negative quantities, client-driven statuses). Assign CWE-639 when the flaw reduces to user-controlled keys addressing others' objects, cross-referencing the AUTHZ module. Do not assign CWE-840: it survives only as a deprecated Category alias, not an assignable weakness; map findings to the root-cause weaknesses above and tag the report OWASP A04:2021.

## Common False Positives

- Lock or atomic statement exists higher in the call chain (base service, interceptor, repository base class): the naive-looking handler is already serialized. Verify the entire chain before reporting.
- Conditional atomic write already in place: `updateOne({_id, balance: {$gte: amt}}, {$inc: ...})` resembles read-modify-write but is safe when `matchedCount` is checked.
- Database UNIQUE/CHECK backstops exist, so even a raced write cannot violate the invariant; downgrade to hardening note unless combined with poor error handling.
- Single-threaded runtime with zero await/yield between check and write plus genuinely single-process deployment (embedded tooling, admin CLI): no interleaving point exists. Multi-worker production deployment voids this exemption.
- Negative amounts rejected by validated DTOs on all paths including admin, import, and webhook copies of the endpoint.
- Rate limiting enforced at gateway/WAF layer, making a racy application-level counter unreachable in practice; still record as defense-in-depth debt.
- Intended business behavior confirmed in product documentation or tickets: tolerated oversell, quotas meant to reset on plan change, rounding pools absorbing fractional cents.
- Pagination exposure of shared collections is an access-control defect routing to the AUTHZ module when no business invariant is damaged.
- Queue or consumer serializes all writes for the resource (single-partition topic keyed by resource id, single-worker shard): apparent read-modify-write inside the consumer cannot interleave.
- Sandbox/demo payment providers behind feature flags that are off in production configuration.

## References

- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') — https://cwe.mitre.org/data/definitions/362.html
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition — https://cwe.mitre.org/data/definitions/367.html
- CWE-20: Improper Input Validation — https://cwe.mitre.org/data/definitions/20.html (operand tampering mapping)
- CWE-639: Authorization Bypass Through User-Controlled Key — https://cwe.mitre.org/data/definitions/639.html (cross-ref AUTHZ)
- CWE-840: Business Logic Errors — listed only as a warning: deprecated Category alias, not an assignable weakness
- OWASP Top 10:2021 A04:2021 – Insecure Design — https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP ASVS 4.0.3, V1.11 Business Logic (sequential-step-order requirements) and V4 Access Control — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide, Business Logic Testing chapter (WSTG-BUSL series) — https://owasp.org/www-project-web-security-testing-guide/
