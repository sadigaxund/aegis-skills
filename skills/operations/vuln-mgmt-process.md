---
name: vulnerability-management-process
description: Defines the recurring vulnerability-management loop that consumes this skillset's audit outputs and keeps every finding prioritized, remediated, verified, and measured over time for small teams.
category_slug: VULN
cwe: []
owasp: N/A – Process (maps to NIST CSF Identify/Respond)
---

# Vulnerability Management Process (VULN)

## Adaptation Note — Read First

This module deviates from the red-team template on purpose: it is not
vulnerability hunting; it defines the RECURRING loop that consumes what every
other module produces. Section meanings are remapped as follows:

| Template section | Meaning HERE |
|---|---|
| What To Check | Readiness/maturity audit of an existing VM program: does each loop stage exist, with evidence? |
| Where To Look | Where program artifacts should live: tracking dirs, registers, calendars, cron, CI configs |
| Patterns & Signatures | The templates: priority decision tree, worked example, exception schema, metrics formulas, agendas |
| Taint Tracing Guidance | How one advisory/audit output propagates through the stages to a terminal state |
| Exploitation & Reproduction | Tabletop: one finding walked through the FULL loop end-to-end on paper |
| Remediation | Building missing stages, in dependency order |
| Severity Assessment | The priority-adjustment bands and SLA table themselves |

Empty `cwe` array is intentional: this module audits process capability, not a code-level weakness class. It sits downstream of both orchestrators — `SKILL-CODE.md` (code slugs) and `SKILL-SERVER.md` (host slugs) — and borrows incident-side vocabulary from IR (`skills/operations/incident-response.md`). It produces findings only about the program itself.

## Scope & Objectives

Two halves, one lifecycle:

**Half A — PROGRAM READINESS AUDIT.** Answer with evidence: when a finding lands tomorrow (from an audit, a scanner, or an advisory feed), does anything besides improvisation happen between discovery and verified closure?

**Half B — LOOP OPERATING SYSTEM.** Fill-in-ready templates for each stage: loop charter, triage records, SLA defaults, exception register, metrics set, monthly review agenda, cadence schedule.

Deliverables of an audit run with this module:

1. **Loop scorecard** — each stage graded PRESENT / PARTIAL / ABSENT with artifact pointers.
2. **Gap list feeding Remediation** — every ABSENT stage becomes a build task with an owner.
3. **Adopted templates** — SLA table, exception register, agenda skeleton in team docs, brackets populated.
4. **Retro-triaged backlog** — open findings carrying recorded priority decisions, not just severities.
5. **Metrics baseline** — the five numbers computed once by hand, then monthly.

Operating rules:

- **Consume, never duplicate.** Audit modules decide SEVERITY (rubrics normative); this module decides PRIORITY and CLOCKS. Re-litigating rubric severity inside triage is forbidden — adjust priority visibly instead.
- **Files are the tracker.** Until ~50 open findings, a directory of finding `.md` files plus one index file IS the system. Do not deploy tooling first.
- **Honesty about mitigation.** Records always say which happened: fixed, mitigated-and-clock-stopped, or accepted-on-paper-with-expiry. Silent blurring of the three is the classic small-team failure.
- **Every stage emits an artifact.** An unrecorded triage, unarchived sweep, or undated review did not happen.

Out of scope: executing audits themselves (SKILL-CODE.md / SKILL-SERVER.md), incident response (IR), paging thresholds (DETECT), patch mechanics (PATCH), backup drills (DR). This module wires their outputs together.

## Mental Model

The loop, with this skillset mapped onto each stage:

```
            ┌─────────────────────────────────────────────────────────┐
            │                                                         │
            ▼                                                         │
   [1 INVENTORY]  repos, hosts, tunnels/hostnames, k8s clusters,      │
    what exists?   DBs, third-party SaaS with data access, DNS names  │
            │                                                         │
            ▼                                                         │
   [2 FIND]       <- SKILL-CODE.md / SKILL-SERVER.md audits on cadence;    │
    hunt for      dependency scanners (commands per SUPPLY module);   │
    weaknesses    sweep-patching.sh host state; distro security       │
                  trackers; pentest/bug-bounty intakes                │
            │                                                         │
            ▼                                                         │
   [3 TRIAGE &    priority = f(base severity, reachability/exposure,  │
    PRIORITIZE]    known-exploitation intel, asset criticality)        │
            │                                                         │
            ▼                                                         │
   [4 REMEDIATE]  batches BY COMPONENT, quick wins first inside the   │
    do the work    batch; fix-vs-mitigate decided explicitly; finding │
                   reports' Remediation sections ARE the work orders  │
            │                                                         │
            ▼                                                         │
   [5 VERIFY]     <- each finding's own Fix Verification Plan;        │
    prove closure  regression tests merged; module greps re-run;      │
                   run-all-sweeps.sh evidence diff where applicable   │
            │                                                         │
            ▼                                                         │
   [6 TRACK &     open-by-severity, MTTR per band, exception count,   │
    METRICS]      audit-coverage freshness, SLA breaches              │
            │                                                         │
            └─────────────────────────────────────────────────────────┘
```

Five axioms:

1. **Audit severity is not operational priority.** The rubric yields severity; the loop adds exposure, reachability, exploitation intel, and asset criticality to yield priority. Two identical-severity findings in different queues is the system working.
2. **Nothing leaves the loop except through verification.** `Fix Status` transitions from `templates/finding-report.md` — `Open` → `Fixed (unverified)` → `Verified-Fixed` (or `Risk-Accepted`) — are gated: the last step requires executing THAT finding's Fix Verification Plan. That is why the template mandates the section.
3. **Clocks attach at triage time, not fix time.** The SLA countdown starts when a finding receives its priority; backlog age before triage is a separate program defect.
4. **The inventory is the join key.** Advisories arrive per-package; impact is per-service. Only an inventory answers "do WE run this?" in minutes instead of archaeology.
5. **Cadence beats heroics.** A quarterly full audit that recurs, a weekly cron'd sweep, and a 30-minute monthly review outperform any burst of effort after a scary blog post.

Cadence defaults (full table in Patterns & Signatures): full audit quarterly or on major change; targeted audits event-driven; sweeps weekly; advisory watch weekly; inventory re-attestation quarterly minimum; review monthly.

## What To Check

Audit each loop stage; grade PRESENT / PARTIAL / ABSENT and record the artifact pointer (or its absence). Definitions: PRESENT = artifact exists, is current, and a named owner can produce it on request; PARTIAL = exists but stale, unowned, or unexercised; ABSENT = improvisation is the mechanism.

### V1. Stage 1 — inventory exists and is attested-fresh

The inventory covers ALL surface classes: code repos, hosts, cloudflare tunnels and their hostnames, k8s clusters/namespaces, databases, third-party SaaS with data access (payment, email, analytics, error-tracking), and all DNS names. Evidence: one named artifact with per-entry `last-reviewed` dates, re-attested within 90 days (quarterly minimum). Inventory-as-code principle: derive entries from IaC/manifests where possible so currency is automatic. Cross-check both directions: two random inventory rows must exist in reality; one live service or DNS name must appear in inventory — the newest service missing fails this item. Living artifacts: `sweep-code-recon.sh` output archives plus latest TARGET-PROFILE.md / HOST-PROFILE.md (cross-ref SKILL-CODE.md Phase 1 / SKILL-SERVER.md Phase 1).

### V2. Stage 2 — FIND sources are wired, not aspirational

Check each source for an actual trigger, not a stated intention:

| Source | PRESENT means | Evidence to demand |
|---|---|---|
| Full audits | Ran within last quarter OR major-change trigger documented | dated run dirs under `security-audit/`, PROGRESS.md files |
| Targeted audits | Event-driven rule written down (new endpoint/service/dependency class → audit that slug within the sprint) | convention doc + recent targeted run |
| Dependency scanning | Per-ecosystem command runs in CI or on schedule | workflow file calling the SUPPLY-module commands |
| Host patch state | sweep-patching.sh output archived per host, reviewed | dated evidence dirs from `tools/run-all-sweeps.sh` |
| Advisory watch | Weekly glance habit over distro security trackers (Ubuntu Security Notices / Debian tracker / Fedora errata qualitatively) plus dependency advisory feeds (RustSec, npm/GitHub advisories) | recurring calendar entry + dated notes file |
| External inputs | Pentest reports / bug-bounty reports have a named intake path (even if "forward to triage" placeholder) | documented route into the tracker |
| Dynamic scanning (DAST) | OWASP ZAP (or equivalent) baseline-scans reachable environments on a schedule; findings flow into the same tracker | scan config + dated reports. Note: dynamic testing is outside this kit's static scope — ZAP-style tooling is the bridge, and its findings still enter Stage 3 identically |

### V3. Stage 3 — triage rules written down and actually applied

Priority formula recorded (Patterns & Signatures); SLA table adopted with sign-off; every open finding shows base severity + adjustments + final priority in a TRIAGE RECORD; deviations justified in writing. Sample five findings: any missing TRIAGE RECORD caps this item at PARTIAL.

### V4. Stage 4 — remediation workflow organized

Fix work batches by component/service rather than severity-scatter; finding reports' Remediation sections used verbatim as work orders; fix-vs-mitigate decisions recorded with rationale; downtime windows consolidated per service.

### V5. Stage 5 — verification gate enforced

No finding reaches `Verified-Fixed` without its own Fix Verification Plan executed: targeted PoC re-test, regression tests merged, re-scan scope greps re-run clean, sweep-evidence before/after diff archived where applicable. Sample closed findings for this evidence chain.

### V6. Stage 6 — tracking and metrics exist

Finding files discoverable across run dirs via one index; the five metrics computable in under 30 minutes; monthly reviews held with dated agenda files. A tracker nobody can query is PARTIAL regardless of completeness.

### V7. Exception workflow enforced

Register exists; every row carries all mandatory fields including expiry ≤180 days; expired exceptions were reviewed on time, not silently extended.

### V8. Cadence actually scheduled

Calendar/cron/CI evidence for: quarterly-or-on-change full audits, event-driven targeted audits, weekly sweeps, weekly advisory glance, monthly review, quarterly inventory re-attestation. An unscheduled cadence is PARTIAL by definition — intentions do not recur.

## Where To Look

Capability leaves artifacts. Absence of artifacts where they should be is
itself the finding.

| Item | Where it should live | Tell-tale absence |
|---|---|---|
| Program charter + SLA table (V3) | Version-controlled doc (`docs/vuln-mgmt.md` or wiki root), linked from CI and review agendas | Lives only in chat scrollback or someone's head |
| Finding tracker/index (V6) | One `security-audit/TRACKER.md` indexing every finding file across `<run-id>/findings/`; graduate to spreadsheet/DefectDojo-class tool only past ~50 open items | Findings stranded in old run dirs; no index |
| Inventory artifact (V1) | Promoted living doc fed by TARGET-PROFILE.md/HOST-PROFILE.md + `sweep-code-recon.sh` archives, per-entry review dates | Regenerated ad hoc per audit, never reconciled against reality |
| Exception register (V7) | Single `security-audit/EXCEPTIONS.md` | Approvals scattered through DMs/tickets |
| Sweep schedule (V2/V8) | cron/systemd timer or CI job invoking `tools/run-all-sweeps.sh`; evidence archived under dated directories | "We ran it once during the audit" |
| Dependency scans (V2) | CI workflow files (`.github/workflows/*.yml`) running the SUPPLY-module commands per ecosystem | Manual-only runs, last output months old |
| Advisory-watch notes (V2) | Recurring weekly calendar event + append-only notes file | Nobody can say who watches trackers |
| Audit cadence (V8) | Quarterly calendar event + written trigger list for targeted audits | Last full audit >12 months ago |
| Triage records (V3) | Inside each finding file (append section) or central decisions log referenced by finding ID | Priority decided verbally, unrecorded |
| Metrics + agendas (V6) | Dated monthly files appended next to the tracker | Numbers recomputed from memory each quarter |

Also inspect: git history of the charter (a doc edited yearly is a shelf document); whether CI scan steps actually pass (a red ignored job is worse than none — it normalizes ignoring).

## Patterns & Signatures

The operating templates. All blocks are fill-in-ready; copy into team docs and
populate brackets before findings arrive, not after.

### P1. Priority decision tree (Stage 3 core)

```
START: base severity from the finding report (C/H/M/L/Info). The rubric in
       templates/finding-report.md is normative; do NOT re-derive it.
  |
  v
Q1 KNOWN EXPLOITATION: maps to a CISA Known Exploited Vulnerabilities (KEV)
   Catalog entry, or credible active-exploitation reporting for the class?
   YES -> P0 treatment: fix-or-mitigate inside 7d REGARDLESS of base severity.
   Record what maps.
  |
Q2 REACHABILITY: vulnerable surface reachable from public internet WITHOUT
   auth? YES -> bump one band UP (Critical stays Critical; Low -> Medium).
   NO -> keep band; record the gate (auth / internal-only / build-time).
  |
Q3 COMPENSATING CONTROLS: does a named control genuinely cover THIS path?
   (Cloudflare WAF rule blocking the payload class; Cloudflare Access gating
   the admin route; tunnel ingress pinning the hostname; egress firewall
   denying metadata reach) -> MAY hold at band WITH written justification:
   control named, what it blocks, what slips past. Provisional — control
   changing or failing reopens the question automatically.
  |
Q4 EPSS TIE-BREAK: published EPSS score exists for the relevant CVE (FIRST
   Exploit Prediction Scoring System — probability-of-exploitation)? Use it
   to order same-band items, higher first. Never invent or estimate scores;
   "not consulted" is a valid entry.
  |
Q5 ASSET CRITICALITY: payment path > auth plane > prod data stores > internal
   tooling > marketing site. Same-band conflicts resolve toward the more
   critical asset; criticality also justifies tightening SLAs below.
  |
  v
FINAL PRIORITY (P0-P3) -> SLA clock starts today (table in Severity Assessment).
```

Fill-in-ready triage record (append to each finding file or central log):

```markdown
TRIAGE RECORD — <SLUG-NNN>
Base severity: [C/H/M/L]        (from finding report — not re-litigated here)
KEV / active exploitation: [no | yes + source named]
Reachability: [internet-unauth | internet-auth | internal-only | build-time]
Band adjustment: [none | bumped +1 band | held-at-band-with-control]
Compensating control: [named control + covers / does-not-cover]
EPSS: [published value + date checked | "not consulted"]
Asset criticality: [payment-path | auth-plane | prod-data | internal | marketing]
FINAL PRIORITY: [P0|P1|P2|P3]   SLA due date: [YYYY-MM-DD]
Decided by / date: [name] / [date]
```

### P2. Worked prioritization example (three findings)

**Finding A — `SSRF-003`, SSRF in webhook URL fetcher. Base High.**
Q1: app logic flaw, no CVE → no KEV mapping. Q2: endpoint internet-reachable but request-signed (authenticated class) → no auto-bump, gate recorded. Q3: host egress firewall denies 169.254.169.254/link-local, metadata path closed → HOLD at High, justification names the rule and what slips past (DNS-rebinding-class fetches). Q5: payment-integration path tightens urgency within band. **Final: P1, due 30 days** — held at band, not downgraded; hold expires if the firewall rule changes.

**Finding B — `SUPPLY-004`, vulnerable prod-path dependency, DoS-class CVE. Base Medium.**
Q1: CVE appears on the KEV Catalog → JUMP QUEUE immediately. **Final: P0, fix-or-mitigate within 7 days**, despite Medium base — exploitation-in-the-wild outranks theoretical impact math.

**Finding C — `WEB-007`, missing CSP header (reflected-XSS-friction class). Base Low.**
Q1: no mapping. Q2: marketing pages internet-reachable unauthenticated → BUMP one band, Low → Medium. Q3: no compensating control claimed → no hold. Q5: lowest-criticality asset stays at floor of the new band. **Final: P2, due 90 days** — bump applied honestly, not inflated beyond one band.

### P3. Exception register schema

```markdown
# Exception Register — security-audit/EXCEPTIONS.md
# Every field mandatory. Expiry MANDATORY, max 180 days from approval.

| Exception ID | Finding ID | Reason (why now) | Compensating control | Owner | Approved by | Expiry date | Review trigger |
|---|---|---|---|---|---|---|---|
| EXC-2026-001 | AUTHZ-002  | [refactor lands next sprint] | [Access policy gates admin route] | [name] | [name] | 2026-11-20 | [policy removed / new pentest finding] |
```

Rules: a row missing owner or expiry is INVALID — treat that finding as OPEN at full priority until fixed. Lapsed exceptions auto-reopen findings at original priority. Review triggers fire early when the compensating control changes. `Risk-Accepted` Fix Status in the finding file links to its row here.

### P4. Cadence table + sweep cron sketch

| Activity | Trigger | Cadence |
|---|---|---|
| Full audit, all applicable slugs (SKILL-CODE.md + SKILL-SERVER.md) | scheduled OR major change (new service, auth overhaul, migration) | quarterly minimum |
| Targeted audits | event-driven: new endpoint / service / dependency class introduced | within the introducing sprint |
| Host sweeps (`tools/run-all-sweeps.sh`) | scheduled | weekly |
| Dependency scans | push to main + scheduled | per CI, weekly floor |
| Advisory watch (distro trackers + dep advisories) | recurring glance | weekly, ~30 min |
| Inventory re-attestation | scheduled | quarterly minimum |
| Monthly VM review | calendar | monthly, 30 min hard stop |
| DR restore drill | per DR module cadence | per DR module |
| Exception expiry sweep | scheduled | monthly (agenda item) |

```bash
# /etc/cron.d/vuln-mgmt-sweeps (or systemd timer) — weekly read-only sweeps,
# evidence archived by date; %% escaping so cron passes literal % to date(1).
0 6 * * 1  ubuntu  cd /opt/sec-tools/aegis-skills && ./tools/run-all-sweeps.sh \
  > /var/log/vm-sweeps/"$(date +\%Y\%m\%d)"-sweeps.log 2>&1
```

CI variant: nightly scheduled workflow running the same script plus the SUPPLY-module scanner commands; fail-open forbidden — a silently disabled scan job must page someone (DETECT wiring discipline).

### P5. Metrics formulas (compute from files, recount never estimate)

| Metric | Formula | Source of truth |
|---|---|---|
| Open by severity trend | count of finding files with `Fix Status` ∈ {Open, Fixed (unverified)} grouped by severity; snapshot monthly | tracker index over `<run-id>/findings/*.md` |
| Mean time to remediate (MTTR) per severity | mean(date reaching `Verified-Fixed` − date finding file created) per band; exclude `Risk-Accepted`; also report MAX | finding files' dates/status |
| Exception count + expiring-soon | register row count; subset with expiry ≤30 days out | EXCEPTIONS.md |
| Audit-coverage freshness | days since last full/targeted audit PER SLUG = today − run-id date of latest run touching that slug | `security-audit/<run-id>/PROGRESS.md` files |
| SLA-breach count | open findings whose SLA due date < today, listed by priority, oldest first | triage records |

### P6. Monthly review agenda skeleton (30 minutes, hard stop)

```markdown
MONTHLY VM REVIEW — <YYYY-MM>
1. Numbers first (5m): five metrics vs last month; note trends, not anecdotes.
2. SLA breaches (10m): every breached finding gets a NEW committed date or an
   escalation; "we'll get to it" is not an outcome.
3. Exceptions (5m): expiring ≤30d — renew with fresh justification or lapse to
   open; verify compensating controls still exist.
4. Coverage gaps (5m): slugs stale beyond a quarter → schedule targeted audits.
5. One improvement (5m): smallest automation that shrinks NEXT month's load.
Output: dated agenda file appended beside tracker; actions get owners+dates.
```

## Taint Tracing Guidance

Remapped: how one INPUT — advisory, scanner output, audit finding, external
report — propagates through the stages to a terminal state. Every input must
reach a sink; inputs that evaporate mid-flow are the loop's leak.

```
SOURCES (entry points):                SANITIZERS (legal transformations):
 - finding file, any slug of             - dedup merge onto existing finding
   SKILL-CODE.md / SKILL-SERVER.md              (SKILL-CODE.md Phase 4; cross-ref line,
 - dependency-scanner output               not duplicate file)
   (SUPPLY-module commands)              - documented compensating control
 - sweep-patching.sh evidence              (holds band, never deletes)
 - distro security notice / dep          - scope exclusion WITH recorded
   advisory feed                           reason ("vendored fork, patched" + proof)
 - KEV catalog update / EPSS movement    - false-positive disproval w/ evidence
 - pentest / bug-bounty report
 - staff observation                     SINKS (terminal states only):
                                           - Verified-Fixed (evidence chain)
                                           - Risk-Accepted (exception row)
                                           - closed-as-false/disproven (recorded)
```

Propagation rules:

1. **Single entry point within one business day.** Every source lands in the tracker as a new finding file (template verbatim) or a cross-reference line on an existing one. An advisory discussed in chat but absent from the tracker has NOT been received.
2. **Inventory lookup before triage.** Resolve per-package inputs against inventory first — which repos import it, which hosts run it, which tunnel exposes it. The same CVE on a build host and the payment-path API becomes two differently-prioritized instances.
3. **No work without a TRIAGE RECORD.** Fixing before prioritizing lets the loudest voice set the queue. Taint reaches Stage 3 before Stage 4 opens.
4. **Stage 4 carries the work order verbatim**: the finding's own Remediation section. Mid-flight scope changes loop BACK through triage; never mutate silently.
5. **Stage 5 is the barrier to the good sink.** `Open` → `Fixed (unverified)` may advance on a merged diff; `Verified-Fixed` requires the FVP executed: PoC re-test, regression tests merged, re-scan greps clean, sweep diff archived where applicable.
6. **Sanitizers are temporary.** A compensating-control hold expires when the control changes; exception rows expire by date — either event re-injects the finding at original priority.
7. **Every input exits through ONE named sink with its record.** "Decided it was fine" without an artifact is not a sink — it is a leak.

## Exploitation & Reproduction

Remapped: tabletop walkthrough of ONE finding traveling the FULL loop end-to-end ON PAPER. Non-destructive; no packets anywhere. Use real team artifacts where they exist; blanks encountered are readiness findings — record them as such. Timebox 60 minutes; participants: tech lead + one auditor role; the facilitator walks stages, injects complications, grades artifacts.

**Subject:** `INJ-001` — SQL injection via unsanitized ORDER BY in the order-search endpoint of orders-api. Status Confirmed, base severity High, full Fix Verification Plan (FVP) present in the finding report.

| Day | Stage | What happens on paper | Artifact produced |
|---|---|---|---|
| D0 | FIND | Quarterly full audit dispatches INJ slug; finding file written with PoC + FVP | `findings/INJ-001-order-search.md`; PROGRESS.md row |
| D0 | INVENTORY | Tracker index links finding → inventory row: orders-api, internet-facing via cloudflared tunnel, Postgres backend, payment path | tracker index line |
| D1 | TRIAGE | TRIAGE RECORD: no KEV mapping (app logic flaw); reachability internet-unauth → bump High→Critical-band treatment; no control claimed (tunnel Access policy does NOT gate this public product endpoint — hold unavailable); asset = payment path | completed triage block |
| D1 | CLOCK | Final priority P0-equivalent; SLA due D8 | due date recorded |
| D2–D7 | REMEDIATE | Batch = whole orders-api component in ONE window: INJ-001 plus sibling `LOGIC-003` race found in same service; quick-win first (ORDER BY allowlist, <1h effort per report); fix-vs-mitigate box: WAF rule REJECTED as terminal because payload space varies — decision recorded | merged PR referencing finding IDs |
| D7–D8 | VERIFY | Execute THIS finding's FVP: original PoC now returns HTTP 400; GIVEN/WHEN/THEN regression test merged into CI; injection-module greps re-run over changed files — clean; sweeps diff N/A for code fix, targeted re-scan noted | test names + outputs referenced in finding file |
| D8 | TRANSITION | `Fix Status`: Open → Fixed (unverified) at merge → Verified-Fixed after gate | status updated |
| D9 | TRACK | Metrics updated: MTTR sample (9d vs P0 7d SLA — counted as breach? No: verified D8, met); coverage freshness stamp refreshed for INJ | monthly metrics snapshot |
| D30 | REVIEW | Monthly review cites case; lesson: batching by component surfaced LOGIC-003 that severity-scatter would have deferred | agenda file entry |

Facilitator injects (drop one mid-walkthrough):

- "A Cloudflare Access policy COULD gate this endpoint — hold there? For how long?" (fix-vs-mitigate box + expiry discipline)
- "The regression test fails on a legitimate Unicode order-by value at D6." (does VERIFY block closure honestly?)
- "The same pattern appears in a second repo's admin tool." (inventory propagation + re-triage, not copy-paste priority)
- "The fixer is on leave at verify time." (bus factor: who may execute the FVP?)

Pass criteria: all six stages produced their named artifacts; both status transitions legal under template rules; clocks honored; every injected complication got a recorded decision rather than improvisation.

## Remediation

Building missing stages, ordered so each step enables the next. Every item maps to its V-finding and produces an artifact.

**B1. Stand up the tracker first (fixes V6).** Create `security-audit/TRACKER.md` indexing every finding file across run dirs: ID, title, severity, Fix Status, priority, due date. A 30-minute grep over `<run-id>/findings/` — before anything else, because every later stage reads and writes this file.

**B2. Adopt triage rubric + SLA defaults (V3).** Copy the Severity Assessment tables into `docs/vuln-mgmt.md`, mark TEAM-TUNABLE rows, get one named owner's sign-off. Retro-triage the open backlog oldest-first until every open finding carries a TRIAGE RECORD. No new scans until the backlog has clocks — otherwise you manufacture debt faster than decisions.

**B3. Promote inventory to a living artifact (V1).** Merge latest TARGET-PROFILE.md + HOST-PROFILE.md into one inventory doc with per-entry `last-reviewed` dates covering all seven surface classes. Reconcile once against reality (DNS zone listing, tunnel ingress configs, k8s namespace dump); set the quarterly re-attest reminder; derive from IaC wherever possible so currency is automatic rather than remembered.

**B4. Wire automated FIND sources (V2).** In order of cheapness: (1) CI jobs running the SUPPLY-module scanner command per ecosystem present; (2) weekly cron for `tools/run-all-sweeps.sh` with dated evidence dirs; (3) calendar events — quarterly full audit, weekly advisory glance over distro trackers and dependency feeds; (4) written trigger list for event-driven targeted audits.

**B5. Enforce the verify gate (V5).** Team convention in CONTRIBUTING: a PR fixing a finding MUST reference the finding ID and execute its Fix Verification Plan; regression tests land in CI, not comments. Reviewers ask for FVP evidence the way they ask for tests.

**B6. Create the exception register (V7).** Copy the P3 schema to `security-audit/EXCEPTIONS.md`. Migrate verbal risk-acceptances immediately; any legacy "we decided it was fine" without owner + expiry reopens as OPEN at full priority today.

**B7. Run the first monthly review (V6/V8).** Compute the five metrics by hand once — the slowness is diagnostic. Hold the 30 minutes; append the dated agenda file. Recurrence does the rest.

**B8. Schedule every cadence (V8).** Calendar + cron entries from the P4 table. Done only when a stranger could predict when each activity next fires from artifacts alone.

Order rationale: tracker before rubric (you prioritize real things), rubric before automation (clocks must exist before scanners produce volume), inventory early because every input resolves against it.

### Small-team realism — sacrifice order under time pressure

When capacity collapses, drop IN THIS ORDER (leftmost first):

```
metrics formality < exception formality < monthly review < SLA-table precision
    < triage discipline < inventory accuracy
```

Never skip triage discipline or inventory: those two convert unknown risk into known risk, which is the entire point. Everything left of them is reporting overhead reconstructable later FROM the files the right side keeps honest. Corollary — **automation before headcount**: deterministic sweeps (`tools/run-all-sweeps.sh`, `tools/sweeps/sweep-code-recon.sh`, `tools/sweeps/sweep-patching.sh`) and CI scanners replace analyst hours outright; add people only after automation is saturated.

## Verification & Validation

The program is verified by exercise, not inspection:

| Capability | Verification method | Pass criterion |
|---|---|---|
| Tracker completeness (V6) | Pick one random live service; locate all its findings via tracker ≤5 min | found without archaeology |
| Triage integrity (V3) | Sample 5 open + 5 closed findings: TRIAGE RECORD present, adjustments follow the tree literally | ≥4/5 correct; misses corrected same week |
| Verify gate (V5) | Sample 10 `Verified-Fixed` findings: FVP evidence exists (re-test result, merged test names, re-scan refs) | 10/10 or offenders reopen as Open |
| Exception hygiene (V7) | All rows carry owner + expiry ≤180d; lapsed rows were actioned on time | zero silent extensions |
| SLA accounting | Recompute breach metric by hand vs last reported figure | numbers match exactly |
| Freshness (V1/V8) | Inventory re-attested ≤90d; every registered slug audited within its cadence window | within bounds or gap ticketed |
| Full loop (all) | Tabletop walkthrough (Exploitation & Reproduction) twice yearly, rotating subject findings | pass criteria met both times |

Validation rules:

1. **Every verification produces an artifact** — sample sheet, drill record, recomputation note. No artifact = not verified = PARTIAL at next audit.
2. **Regressions reopen findings at ORIGINAL severity and priority** — a rotted fix never benefits from its former closure date.
3. **After every real incident**, re-run this module's readiness audit (Half A): real incidents are the cheapest readiness data available (cross-ref IR postmortem AUDIT-SKILLSET section).
4. **Annually, audit the defaults themselves**: SLA durations, cadence table, and asset-criticality tiers are re-signed or consciously changed — drift by neglect is how programs become theater.

## Severity Assessment

Two layers, kept separate on purpose. SEVERITY comes from the finding-report rubric (`templates/finding-report.md`, exploitability-first tie-breakers) and is final at report time. PRIORITY is operational, assigned here, and may move a finding up or hold it — never silently down.

### Priority adjustment rules

| Rule | Effect on band | Constraint |
|---|---|---|
| Internet-reachable WITHOUT auth | bump one band up (max Critical) | reachability evidence recorded in triage record |
| Auth-gated / internal-only / build-time-only | no change | the gate is named in the record |
| KEV-catalog mapping or credible active exploitation | jump queue → P0 treatment regardless of band | source named; no folklore |
| Compensating control covers THIS path | MAY hold at current band | written justification; hold expires if control changes |
| Published EPSS score exists | tie-break ordering within same band | never fabricate values; "not consulted" allowed |
| Asset criticality (payment > auth > prod-data > internal > marketing) | resolves same-band conflicts toward critical assets | tiers listed in team charter |

When genuinely torn between two priorities, take the lower AND write down why — mirroring the severity rubric's conservative tie-breaker.

### SLA table (defaults — rows marked TEAM-TUNABLE)

| Priority | Meaning | Fix-or-mitigate within | Tunable? |
|---|---|---|---|
| P0 | Known-exploited class, OR Critical severity | 7 days | floor only — tighten, do not loosen |
| P1 | High severity, or bumped-from-High | 30 days | yes |
| P2 | Medium severity (incl. bumped-from-Low) | 90 days | yes |
| P3 | Low / Info | next quarter — or indefinitely OK with a one-line note in the record | yes |

**Mitigation-counts-as-progress rule.** A WAF rule, Cloudflare Access gate, or config change that genuinely blocks exploitation STOPS the SLA clock honestly IF recorded as mitigation: control named, residual path stated, review date ≤180 days. It NEVER converts silently into done — an unrecorded mitigation is an open finding breaching its SLA while everyone believes it closed.

**Exception workflow.** Anything not fixed by due date becomes either (a) a recorded exception (P3 schema: finding-id, reason, compensating-control, owner, expiry ≤180d MANDATORY, review trigger) with `Fix Status: Risk-Accepted` linked to its row, or (b) a visible SLA breach in the monthly review. There is no third state where findings quietly age out.

## Common False Positives

Program-audit traps that make maturity LOOK present:

1. **Document exists ≠ program.** An SLA table never applied to a live finding is PARTIAL at best. Test: pick any open finding and follow its clock.
2. **Scanner output ≠ tracked finding.** An `npm audit` dump pasted into chat has not entered the loop until it is a finding file or cross-reference line.
3. **Severity ≠ priority.** Identical-severity findings in different queues with different due dates is the adjustment rules working — flagging it as inconsistency misreads the design.
4. **CVSS base score alone as priority.** Base scores ignore reachability and exploitation intel; using them solo recreates the problem Stage 3 exists to solve.
5. **Mitigated ≠ fixed.** The WAF rule quietly promoted to permanent fix, no record, no review date — the most common silent failure in small teams.
6. **Exception ≠ closure.** `Risk-Accepted` without an expiry-dated register row is an open finding wearing a costume.
7. **Last audit's TARGET-PROFILE ≠ inventory.** Services shipped after the run are invisible to it; freshness dates exist to catch this.
8. **Dev-only dependency noise inflating counts.** Scope scanner output to production paths per SUPPLY guidance before counting metrics — but still fix dev-path items at P3.
9. **Verified-Fixed claimed without FVP execution.** No merged regression test, no re-scan output → reopen. Status transition rules are not advisory.
10. **MTTR averages hiding outliers.** Report MAX alongside mean; one 400-day Critical hides comfortably inside a healthy average.
11. **One quiet quarter ≠ trend.** Metrics earn meaning across quarters; single snapshots justify only baseline establishment.
12. **Fabricated EPSS/CVSS/exploitation claims in triage records.** Forbidden everywhere in this skillset, doubly here where they set queues; "not consulted" is always acceptable.

## References

- NIST SP 800-40 *Patch Management* publication family (revision numbering has shifted across editions — consult the CSRC catalog for the current revision): https://csrc.nist.gov
- NIST Cybersecurity Framework — Identify/Respond function mapping stated in frontmatter: https://www.nist.gov/cyberframework
- CISA Known Exploited Vulnerabilities (KEV) Catalog — authoritative known-exploited list; consult current entries via https://www.cisa.gov
- FIRST Exploit Prediction Scoring System (EPSS) — published probability-of-exploitation scores: https://www.first.org
- FIRST Common Vulnerability Scoring System (CVSS) specification — the base-severity vocabulary used by finding reports: https://www.first.org
- Orchestrators: `SKILL-CODE.md` Section 4 registry (code slugs, Phase 4 dedup rule, Phase 6 fix protocol); `SKILL-SERVER.md` Section 3 registry (SRV slugs, Phase 6 hardening application)
- Sibling modules: SUPPLY `skills/code/supply-chain.md` (dependency-scanner command matrix — pointer only, not duplicated here), PATCH `skills/server/updates-patching.md`, DETECT `skills/operations/blue-team-detection.md` (P1–P4 paging rubric: alert urgency, distinct from this module's remediation priority), IR `skills/operations/incident-response.md` (when a tracked finding becomes a live incident), DR `skills/server/backup-dr.md` (drill-cadence model)
- Templates: `templates/finding-report.md` (severity rubric, statuses, Fix Verification Plan mandate, `Fix Status` transitions); `templates/target-profile.md` (inventory seed artifact)
- Tooling: `tools/run-all-sweeps.sh`, `tools/sweeps/sweep-code-recon.sh`, `tools/sweeps/sweep-patching.sh`, `tools/README.md` sweep contract
