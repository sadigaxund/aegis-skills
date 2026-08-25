# Business Logic & Race Conditions — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, regexes, and per-stack fix recipes.

## How this class emerged

Business-logic flaws are as old as commerce software. The first online shops of
the mid-1990s computed order totals in the browser and posted them to a server;
whoever noticed could edit the number before sending it. As e-commerce grew,
so did the pattern: any value the client sends back and the server trusts is a
tampering candidate. Security literature eventually grouped these under "input
validation," but the root cause is older and broader — the server executes its
rules correctly on attacker-chosen operands.

Race conditions have an even longer pedigree inside operating systems and
databases; concurrency researchers formalized them decades before the web.
What changed in the 2010s was their arrival in *business* code:

- Web applications stopped being single-process. Load balancers, worker pools,
  containers, and microservices multiplied the copies of any program state,
  while application-level locks guarded only one copy at a time.
- Frameworks made read-modify-write trivial (`account.balance -= amount; save`)
  while hiding the database's locking vocabulary behind convenience methods.
- Researchers demonstrated that "fire ten parallel requests" reliably lands two
  inside millisecond-wide windows, turning a theoretical defect into a practical
  money-printing primitive against vouchers, balances, and rate limiters.

The industry's answer accumulated in layers: idempotency keys for retries,
atomic conditional updates for counters, unique constraints as final backstops,
and explicit server-side state machines for workflows. Each layer exists because
the naive version of the previous one failed.

## Anatomy: the check-then-write gap

The canonical vulnerable shape fits in four lines. Every stack has a dialect of
it; this is Python-flavored pseudocode.

```python
acct = db.get_account(user_id)          # READ
if acct.balance >= amount:              # CONDITION
    acct.balance = acct.balance - amount  # arithmetic in application memory
    db.save(acct)                       # WRITE
```

Failure walkthrough with two concurrent requests A and B (balance starts at 100,
both withdraw 80):

1. A reads balance 100. B reads balance 100 — both pass the guard.
2. A writes 20. B then writes 20 again, overwriting A's result.
3. Final stored balance is 20 instead of -60-or-rejected. The ledger records
   two payouts; the invariant "money only leaves once per unit owned" broke.
4. Nothing crashed. No exception fired. Both responses were success. The bug is
   invisible until reconciliation — which may be months later.

The same gap explains voucher reuse (READ `used == false` → flip to true),
stock oversell, double-refund on retried webhooks, and signup uniqueness holes.
Wherever a decision and the write it licenses live apart, interleaving wins.

A second, non-concurrent anatomy covers tampering:

```python
order = Order(items=body.items, total=body.total)   # client-supplied total
order.save()
```

Here there is no race at all: the attacker simply names their own price because
nobody recomputed it from catalog data.

## Why naive fixes fail

Each tempting quick fix below fails against this class; SKILL.md's Remediation
section shows what works instead.

- **Client-side guards** (disabled buttons, hidden steps, JS validation): the
  API accepts hand-built requests; anything enforced only in the UI is absent.
- **In-process locks** (`synchronized`, `threading.Lock`, `sync.Mutex`):
  they exclude competitors inside one process only. Production runs many
  workers and replicas; each holds its own lock object.
- **"Fast enough" reasoning**: assuming the window is too small to hit. Scripted
  parallel requests hit millisecond windows routinely; load makes gaps wider.
- **try/catch around the write**: catching the duplicate-key error after the
  side effect already happened does not undo a payout or refund already issued.
- **Re-checking before save**: another read just widens the same window unless
  the recheck shares a transaction/lock with the write.
- **Blacklisting negative amounts** on one endpoint: validation must hold on
  every path (admin panels, importers, queue consumers, GraphQL resolvers);
  one unwritten path mints credit anyway.
- **Trusting webhook signatures alone**: signature proves the provider sent the
  event, not that you haven't processed it twice; replay needs dedup storage.
- **Session/framework magic**: atomicity wrappers give rollback on failure,
  not mutual exclusion between readers; globally-atomic requests can still race.

## Common misconceptions

1. **"The UI controls the workflow."** The UI is a suggestion. The server-side
   handler reachable directly is the real machine; every later step must be
   re-guarded by persisted state, not by the sequence the browser happened
   to follow.
2. **"Race conditions are exotic."** For counters, they are the default outcome
   of application-side arithmetic. Only atomic statements, row locks, or unique
   constraints prevent them; everything else is timing luck.
3. **"Transactions make me safe."** A transaction makes multi-statement work
   all-or-nothing; it does not stop two transactions from reading the same
   stale balance and both writing. Exclusion needs locks or conditional updates.
4. **"Idempotency keys are optional polish."** Networks retry. Browsers
   double-click. Orchestrators redeliver. Any mutating endpoint without replay
   protection will eventually execute twice — that is a finding by itself.
5. **"Testing proved it can't be reproduced."** A single manual retry says
   little about a millisecond window under load; absence of evidence from an
   unsystematic probe is not evidence of absence. Static confirmation of the
   unlocked READ→WRITE pair is sufficient for reporting.
6. **"Storing prices client-side saves round trips."** It moves the pricing
   authority to the attacker. Catalog joins are cheap; negative subtotals are
   not.
7. **"Soft-deleted rows don't count."** If limits count rows excluding deleted
   ones but business intent counts lifetime usage, purging history resurrects
   quota — a counting-logic defect, not a data-loss bug.

## Modern taxonomy map

Matches the In Scope table of `../SKILL.md`; use these names when reporting.

| Class | One-line essence | Typical root cause |
|---|---|---|
| Workflow / state-machine bypass | Later step callable directly | Transition legality checked nowhere, or from client data |
| Price/quantity/amount tampering | Client supplies transition operands | Values persisted instead of recomputed |
| Race conditions (check-then-act) | Two requests interleave READ/CONDITION/WRITE | No shared transaction+lock or atomic statement |
| TOCTOU on resources | State changes between check and use | Check and act separated by await/network call/time |
| Double execution | Same mutation profitable twice | Missing idempotency keys / dedupe of event ids |
| Limit / counting logic | Limit checks one field, consumption increments another | Field/window/key mismatch |
| Approval / multi-party flows | Requester signs own approval | Approver identity from payload; no status-order guard |
| Referral / cashback / gift abuse | Reward loops via disposable identities | Rewards keyed to mutable identity, not immutable facts |
| Cross-user enumeration in flows | Walking others' orders/vouchers | IDOR mechanics (route to AUTHZ) damaging invariants here |

Severity intuition: classes that mint or destroy money/entitlements directly
(double-spend, negative quantities, self-referral loops) start Critical/High;
workflow bypasses that skip payment rank High; pure counting mismatches that
merely lock users out trend Medium.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — every flow is a state machine; the Five Questions method.
2. **What To Check** — per-class checklists (bypass, tampering, races, time,
   counting, approvals, referral systems, idempotency).
3. **Patterns & Signatures** — ripgrep shapes for read-modify-write triples and
   missing transaction vocabulary.
4. **Remediation** — the layered fix recipe (constraints → atomic statements →
   serialization → protocol-level idempotency), per language.
5. **Verification & Validation** — concurrency regression tests and negative
   tests proving honest flows still work.

Sibling modules that own adjacent defects (hand findings over rather than
duplicating their analysis):

- `../authz-access-control/` — object-level IDOR and bulk-export enumeration.
- `../api-security/` — mass assignment binding mechanics; redemption rate limiting.
- `../authn-session/` — login throttling policy and credential-stuffing thresholds.
- `../secrets-data-exposure/` — gift-card code entropy and secret storage.
- `../injection/` — injection payloads discovered during flow probing.
