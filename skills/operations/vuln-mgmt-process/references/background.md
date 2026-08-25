# Vulnerability Management Process — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind the inventory→find→prioritize→remediate→verify→
metrics loop, priority-vs-severity separation, exception registers, and fix
verification; SKILL.md carries the decision tree, SLA tables, and templates.

This module remaps the standard audit headings (its Adaptation Note says so):
What To Check is a program-maturity audit, Exploitation & Reproduction is a
paper walkthrough of one finding through the full loop, and Severity
Assessment covers priority bands and SLAs. Everything below aligns with that
mapping.

## How vulnerability management emerged

Managing flaws deliberately — rather than patching when something breaks —
is younger than most assume, and it grew out of a data problem, not a
technical one.

- **Before common names (pre-1999).** When two organizations discussed "the
  buffer overflow in that FTP server," they could not reliably mean the same
  bug. Advisory formats varied by vendor, and tracking what was fixed where
  was clerical heroism; mailing lists and ad-hoc disclosure handled
  coordination informally.
- **CVE gave bugs identity (1999).** The Common Vulnerabilities and Exposures
  effort, launched by MITRE in 1999, assigned each distinct vulnerability a
  stable identifier — the CVE ID. Like social security numbers for bugs, IDs
  made deduplication, cross-referencing, and trend counting possible at scale.
- **Databases and scores industrialized comparison (2005–2015).** NIST's
  National Vulnerability Database went live in 2005, aggregating CVE data
  into a searchable public store. FIRST took stewardship of CVSS — the Common
  Vulnerability Scoring System — publishing version 1 in 2005, then v2, v3,
  and later revisions, giving every finding an interpretable severity number.
  Scanners spoke these dialects natively, and organizations discovered the
  real problem only afterward: scanners produce findings far faster than
  teams can fix them.
- **Prioritization became the discipline (late 2010s–today).** A decade of
  backlog research showed base scores poorly predict which bugs get
  exploited, so practice shifted to risk-based inputs: published evidence of
  exploitation in the wild (CISA's Known Exploited Vulnerabilities catalog,
  launched November 2021) and predictive probability-of-exploitation scores
  (FIRST's Exploit Prediction Scoring System, EPSS, publishing daily since
  early 2021). Meanwhile consensus control frameworks descending from the
  SANS/CIS "Top 20" controls (first published in 2008) kept insisting that
  inventory, patching cadence, and process discipline outrank any scanner
  purchase.

The recurring lesson: tooling keeps producing findings; programs succeed or
fail on the PROCESS that turns findings into verified fixes — which is why
this module audits stages and artifacts rather than running scans itself.

## Anatomy: one advisory's journey through the loop

The minimal unit of the process is a single finding traveling from input to
terminal state. Here is the whole journey in generic shape:

```
INPUT      a dependency advisory names component X, affected range < 2.3.1
   │
   ▼
[1 INVENTORY]  lookup: which repos import X? which hosts run it? which tunnel
   │           exposes it? -> answers in minutes, not archaeology
   ▼
[2 FIND]   joins the same tracker as audits, sweeps, and external reports —
   │       one entry point per business day.
   ▼
[3 TRIAGE] record filled: base severity MEDIUM; known-exploited list? no;
   │       internet-reachable without auth? YES -> bump one band; no control
   │       claimed; asset = payment path. FINAL PRIORITY P1, SLA due in 30d.
   ▼
[4 REMEDIATE] batched with other fixes touching the same component/service,
   │          executed from the finding report's own remediation section;
   │          fix-vs-mitigate decided explicitly and written down.
   ▼
[5 VERIFY] the finding's own verification plan executes: PoC re-test now
   │       fails safely, regression test merged, re-scan greps clean. Status
   │       may now read Verified-Fixed. Not before.
   ▼
[6 METRICS] MTTR sample recorded; open-count snapshot updated; monthly review
   │        sees trends, not anecdotes.
   └──────────────────────────────────────────────────────────────► closed
```

Walkthrough of why each stage exists:

1. **Inventory first** because advisories arrive per-package while impact is
   per-service. Without it, every advisory triggers an org-wide scramble; the
   same flaw on a build host versus a payment-path API deserves different
   urgency — only inventory knows where each instance lives.
2. **One entry point** because findings arriving via chat, email, tickets,
   AND a tracker evaporate mid-flow — not in the tracker means not received.
3. **Triage before work** because fixing whatever the loudest voice noticed
   lets quiet critical items rot invisibly. Severity is NOT relitigated;
   priority adjusts for reachability, exploitation intel, and asset
   criticality — visibly, on a record.
4. **Batching** because scatter-shot fixing burns context-switch time; one
   change window per component or service surfaces sibling issues together.
5. **The verify gate** exists because "I merged a diff" and "the
   vulnerability is gone" are different claims. Unverified fixes reopen
   silently all the time; the gate makes reopening rare and loud.
6. **Metrics** convert incidents into program steering: mean time to
   remediate, breach counts, exception aging — computed from files, never
   estimated.

## Why naive approaches fail

- **Severity-only queues.** Working strictly down a CVSS-sorted list ignores
  reachability and exploitation reality: a medium-severity bug actively
  exploited in the wild outranks a theoretical critical behind three layers
  of authentication — exactly the jump SKILL.md's decision tree encodes.
- **Scanning more instead of fixing systematically.** Adding tools multiplies
  findings without adding closure capacity; the backlog grows, dashboards go
  red, everyone learns to ignore them. The bottleneck is the triage-and-verify
  pipeline, never scan volume.
- **Deploying a tracker platform first.** Until roughly fifty open findings,
  a directory of finding files plus one index IS the system. Tooling adopted
  before process automates the chaos instead of replacing it.
- **Silent mitigation blur.** A WAF rule quietly promoted from stopgap to
  permanent "fix," unrecorded, leaves an open finding everyone believes
  closed — the classic small-team failure the mitigation-counts-as-progress
  rule and mandatory review dates exist to stop.
- **Exception sprawl without expiry.** Risk acceptance is legitimate ONLY as
  a register row with owner, justification, compensating control, and expiry.
  Verbal acceptances are leaks wearing approval costumes; lapsed exceptions
  must auto-reopen their findings.
- **Gaming MTTR.** Closing tickets as "fixed" pre-verification, or excluding
  risk-accepted items from averages, makes the metric lie. Report MAX
  alongside mean — one 400-day critical hides inside a healthy average.
- **Treating triage clocks as optional during backlogs.** Backlog age before
  triage is its own program defect; SLA countdowns attach at priority
  assignment so invisible rot cannot accumulate upstream of the queue.

## Common misconceptions

1. "Running a scanner means we manage vulnerabilities." Scanning is Stage 2
   of six. Programs are judged on inventory freshness, triage records,
   verification gates, and metrics — none of which a scanner provides.
2. "Critical score always means fix first." Base severity ignores exposure
   and exploitation. Identical-severity findings in different priority queues
   is the adjustment rules WORKING, not inconsistency.
3. "Zero-days are the real problem." Most breaches exploit known,
   unpatched-for-months flaws. Cadence on boring knowns beats panic-chasing
   exotics — which is also why known-exploited status jumps the queue ahead
   of higher-severity neighbors.
4. "Patching is IT's job, prioritization is security's, verification is
   QA's." Fragmented ownership is how findings fall between stages; the loop
   needs named owners per stage and artifacts crossing the boundaries.
5. "Exceptions are failures of the process." Conscious, documented, expiring
   risk acceptance is a FEATURE — it converts silent debt into visible
   decisions. Undocumented deferrals are the failure mode.
6. "Once fixed, always fixed." Fixes regress: refactors reintroduce removed
   unsafe calls, upgrades drop hardening flags. Regressions therefore reopen
   at ORIGINAL severity and priority, benefiting from nothing.
7. "Metrics are management theater." The five numbers exist to steer next
   month's effort and expose lies elsewhere ("we're fine"). A tracker nobody
   can query within thirty minutes caps program maturity regardless of
   completeness.

## How professionals think about it today

Modern programs read vulnerability management as one loop with two honest
accounting systems; SKILL.md implements both, and every finding lands in one
cell.

| Layer | Sub-types in this module | What it answers |
|---|---|---|
| Loop stages | INVENTORY / FIND / TRIAGE & PRIORITIZE / REMEDIATE / VERIFY / TRACK & METRICS | Does each stage exist, with an artifact and owner? |
| Accounting | severity bands (rubric-final) vs priority bands P0–P3 (operational) vs exception register | What is truly owed, deferred-with-expiry, or closed-with-proof |
| Inputs | audit modules, dependency scanners, sweeps, advisory feeds, pentest/bug-bounty reports, staff observations | Where findings enter — all funneled to one tracker |
| Cadence | quarterly full audits, weekly sweeps + advisory glance, monthly review, quarterly re-attestation | Does recurrence survive busy quarters? |

Cross-cutting habits distinguish maturity: consume-don't-duplicate (audit
modules own severity; this loop owns clocks), automation-before-headcount
(scripts and CI replace analyst hours), and the small-team sacrifice order —
under pressure, drop metrics formality first and inventory accuracy NEVER,
because triage discipline plus accurate inventory are what convert unknown
risk into known risk.

## Read next

In `../SKILL.md`: **Adaptation Note — Read First**, **Prerequisites &
Vocabulary**, **Scope & Objectives**, **Mental Model** (loop diagram + five
axioms + cadence defaults), **What To Check** (V1–V8 stage audit), **Where To
Look** (artifact locations), **Patterns & Signatures** (priority tree, worked
example, exception schema, cadence table, metrics formulas, agenda),
**Taint Tracing Guidance** (how inputs propagate to terminal states),
**Exploitation & Reproduction** (paper walkthrough through the full loop),
**Remediation** (build order B1–B8 + sacrifice order), **Verification &
Validation**, **Severity Assessment**, **Common False Positives**,
**References**.

Sibling modules in operations/: `../incident-response/SKILL.md` (when a
tracked finding becomes a live incident), `../blue-team-detection/SKILL.md`
(alert urgency — a different axis than remediation priority), and
`../dfir-triage/SKILL.md` (first-hours response when exploitation is
observed). Closest companions elsewhere: code skillset `supply-chain`
(dependency-scanner commands feeding Stage 2); server skillset
`updates-patching` (patch mechanics beneath Stage 4) and `backup-dr`
(drill-cadence model borrowed here); orchestrators whose registry feeds FIND.
