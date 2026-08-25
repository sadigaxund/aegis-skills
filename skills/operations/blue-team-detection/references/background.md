# Blue-Team Detection Engineering — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind security-event logging, alert thresholds, coverage matrices, and
purple-team replay validation; SKILL.md carries the class-by-class signals,
threshold starters, and remediation code.

One vocabulary note up front: this module scores ALERT URGENCY — who gets
woken up and how fast. That is a different question from how severe an
underlying vulnerability is, and SKILL.md's Severity Assessment section exists
precisely to keep the two apart.

## How detection engineering emerged

Computers have logged their own activity almost since they existed, but logs
were an accounting and debugging tool for decades, not a defense. Three shifts
turned them into one.

- **Intrusion detection became a discipline (1980s).** A 1980 government
  report by James P. Anderson proposed that computer misuse could be
  identified from audit records, and Dorothy Denning's 1987 model formalized
  the idea of detecting intruders statistically: watch events, build a
  baseline of normal, flag deviation. Nearly every "anomaly detection"
  product today descends from that paper.
- **Signature sharing industrialized (late 1990s–2000s).** Open-source
  network IDS rules (Snort appeared in 1998) let defenders share plain-text
  attack signatures; the ModSecurity web-application firewall and its Core
  Rule Set carried the same idea to HTTP traffic in the mid-2000s, which is
  where the `942xxx` SQLi rule ids this module mentions come from. Gartner
  coined the term SIEM in 2005 for the growing category of central platforms
  that store and correlate such events, and NIST SP 800-92 (2006) made log
  management a named security function rather than an ops afterthought.
- **Detection became engineering (2013–today).** MITRE ATT&CK went public in
  2015, organizing attacker behavior into a shared matrix defenders could map
  detections against. The Sigma rule format emerged around 2016 as a
  vendor-neutral YAML dialect for writing a detection once and translating it
  to whatever backend a team owns — the "detection-as-code" habit SKILL.md
  recommends. By the late 2010s "detection engineer" was appearing as a job
  title, reflecting the shift from buying alerts to building and validating
  them. The purple-team idea — red attackers and blue defenders working the
  same replay together so every attack technique is tested against every
  detection — crystallized in the same period.

The recurring lesson: tools kept arriving, but organizations still failed to
detect attacks they had the data for, because nobody owned the chain from
application event to pager message. That chain is what this module audits.

## Anatomy: one failed login becomes one page

The minimal unit of this craft is small enough to hold in your head. Here is
the whole pipeline with generic names:

```
1. EMIT     the app writes one structured line when a decision happens:
            {"event_type":"auth.login.failure","actor_id":"u_8842",
             "src_ip":"203.0.113.7","outcome":"failure","request_id":"e40b"}
2. SINK     the line lands somewhere durable off the app process itself.
3. SHIP     an agent forwards it off-host to a central store.
4. STORE    the store keeps it queryable long enough to matter.
5. DETECT   a rule counts: failures grouped by src_ip over 15 minutes.
6. ROUTE    count crosses threshold -> notification routed per priority.
7. RESPOND  whoever is paged follows a runbook: first checks, then act.
```

Walkthrough of why each hop matters, using one brute-force burst as the story:

1. Twenty wrong passwords arrive at `/login` in four minutes, all for one
   account. The application emits twenty failure events — or emits nothing,
   if the developer never added a logging call on the rejection path. Most
   un-instrumented apps are silent here; that silence is the most common
   finding in the entire module.
2. If emitted, the lines must survive: stdout into a container that discards
   output on restart means hop 2 already lost them.
3. The shipper must actually be running. A dead agent produces no errors of
   its own unless someone built a dead-man check.
4. In the store, the events become countable. Twenty rows keyed by
   `src_ip` and `actor_id`.
5. The detection is just arithmetic: `count >= 5` per account per 15 minutes
   fires the per-account alert; note the module insists on a SECOND alert
   grouped by source IP, because spray attacks spread attempts across many
   accounts and never trip the per-account counter.
6. Routing decides whether arithmetic reaches a human. A rule that emails a
   dead mailbox equals no rule.
7. The runbook turns a page into action: exclude allowlisted sources, pull
   context, classify benign vs suspicious vs compromise.

Two ideas elevate this from plumbing to engineering. First, tiers: some
signals only mean something as AGGREGATES (velocity, ratios across many
requests), while others are INDICATORS of success even alone (a refresh token
used twice after rotation), and those must page instantly. Second, closure: a
rule nobody has ever fired deliberately is a hypothesis. Purple-team replay —
re-enacting the twenty bad logins on staging and asserting the alert fired —
is what converts it into a control.

## Why naive approaches fail

- **Grepping strings in raw logs at incident time.** Without structured
  events emitted at the moment of decision, investigation means archaeology
  through free text that may not exist. Detection begins at emission, not at
  the console.
- **Guessing thresholds.** "Alert if more than 10" sounds reasonable until
  baseline measurement shows a busy Monday does thirty. Rules not derived
  from observed baselines either never fire or fire constantly; both fail.
- **Logging everything.** Volume is not coverage. Full request bodies and
  every debug line bury real signals under noise, inflate cost, and vacuum
  secrets into storage — creating a new exposure while failing the old one.
- **Buying the platform first.** A SIEM consuming nothing but firewall logs
  cannot see application-level authorization denials or token reuse. Emitters
  come before analytics; the pipeline fails at its weakest hop regardless of
  how expensive the strongest hop was.
- **Trusting unvalidated rules.** Field renames, shipper outages, and
  framework upgrades silently break rules. Only replay — firing the detection
  on purpose — proves it works, which is why SKILL.md makes the checklist row
  mandatory per rule.
- **Paging on single weak signals.** One odd user-agent string is noise;
  marker input PLUS a privileged tool call is a lead. Teams that page per
  signal train themselves to ignore pages within weeks — alert budget is
  spent trust, not free information.
- **Treating absence of telemetry as safety.** No alerts firing can mean
  "no attacks" or "no sensors." Scoring BLIND classes explicitly, as the
  matrix does, is how professionals tell those apart.

## Common misconceptions

1. "We have a SIEM, therefore we detect things." A store detects nothing by
   itself; rules consuming well-formed events do. Coverage is measured per
   attack class, not per product purchased.
2. "More alerts means more security." Every page spends responder trust. Ten
   false pages reliably buy ignorance of the eleventh true one. Fewer,
   better-derived, validated alerts beat volume.
3. "The WAF blocks attacks, so we don't need our own telemetry." An edge
   device in blocking mode is one sensor with one view — and it can be turned
   off, evaded, or absent entirely (SKILL.md records `SecRuleEngine Off` as a
   gap, not safety). Application-side events remain the ground truth.
4. "Thresholds are set once and done." Traffic changes, features launch,
   campaigns happen. Untuned rules rot silently; the soak-then-page workflow
   and quarterly replay pass exist because tuning is continuous.
5. "A fired alert means we were attacked successfully." Most alerts mark
   ATTEMPTS (probes, bursts, error noise). Success has its own shapes —
   deny-then-allow flips, new egress destinations, token reuse — which is
   exactly why the INDICATOR tier exists.
6. "False positives are just noise we tolerate." They are trust withdrawals.
   Alerts above roughly ninety percent benign close rate are candidates for
   retirement, because responders have already retired them mentally.
7. "Correlation fields are optional garnish." An event without
   `request_id`, `src_ip`, and actor identity cannot join into a story during
   triage. Half the value of logging is joinability, and it must be designed
   in at emission time — hashing identifiers preserves joins where omission
   destroys them.

## How professionals think about it today

Modern practice treats detection as three orthogonal maps, and SKILL.md is
organized around exactly these; every audit finding lands in one cell.

| Map | Sub-types in this module | What it answers |
|---|---|---|
| Signal tier | EVENT / AGGREGATE / INDICATOR | Does this mean something alone, across many requests, or only joined? |
| Attack class | INJ, WEB, AUTHN, AUTHZ, SSRF, FILE, DESER, API, LOGIC, DOS, TOK, LLM | Which exploitation shadow are we instrumenting — attempt, success, or both? |
| Pipeline hop | EMIT → SINK → SHIP → STORE → DETECT → ROUTE → RESPOND | Where does the signal die between app and human? |

Grading is uniform across all twelve classes: FULL (events emitted AND
consumed by a tuned alert), PARTIAL (one side missing), BLIND (no emission).
Every PARTIAL and BLIND cell is a finding. Alert quality gets its own rubric
(P1 page-now through P4 dashboard-only), with a runbook required before any
rule may page. Validation is behavioral: the purple-team loop replays each
red-module PoC against staging and asserts expected events plus expected
alert inside the configured window, recorded as pass/fail rows.

## Read next

In `../SKILL.md`: **Scope & Objectives** (the inversion premise and five
deliverables), **Prerequisites & Vocabulary**, **Mental Model** (two-shadows
diagram, tier table, seven-hop pipeline, four axioms), **What To Check**
(inventory → matrix scoring → absence-greps → structure checks → pipeline
health → alert-quality grading), **Where To Look** (middleware to alert-as-
code locations), **Patterns & Signatures** (the twelve-class coverage matrix,
class catalogs, alert-quality engineering, SIEM-lite), **Taint Tracing
Guidance** (hop-by-hop verification), **Exploitation & Reproduction**
(purple-team replays R1–R7), **Remediation** (emitters, redaction, alert
configs, runbook template), **Verification & Validation** (soak tests,
regression notes), **Severity Assessment** (alert-urgency P1–P4 rubric),
**Common False Positives**, **References**.

Sibling modules in operations/: `../incident-response/SKILL.md` (what happens
after an indicator pages — the response half of this loop), `../dfir-triage/`
SKILL.md (first-hours host evidence when an indicator means compromise),
`../vuln-mgmt-process/SKILL.md` (how detection gaps and fixes get clocks).
Closest companions elsewhere: server skillset `logging-monitoring`
(sshd/sudo/auditd telemetry below the application layer) and
`skills/code/secrets-data-exposure/SKILL.md` (redaction rules resolving the
PII-in-logs tension); the red modules named in SKILL.md's References supply
each class's attack side.
