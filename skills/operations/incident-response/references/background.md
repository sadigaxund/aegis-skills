# Incident Response — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind readiness audits, the six-phase lifecycle, containment
scenarios, communication templates, and tabletop exercises; SKILL.md carries
the checklists, fill-in templates, and scenario playbooks themselves.

This module remaps the standard audit headings (its Adaptation Note says so):
What To Check means readiness-audit items, Exploitation & Reproduction means
tabletop exercises, and Severity means incident impact SEV1–SEV4 rather than a
vulnerability score. Everything below aligns with that mapping.

## How incident response emerged

Incident response as a named profession has a precise birthday, which is rare
in this field.

- **The Morris worm and the first CERT (November 1988).** On November 2,
  1988, a self-replicating program brought a meaningful fraction of the young
  internet to its knees within hours — including machines at universities and
  research labs whose administrators had no one to call, because nobody's job
  description included "handle an internet-wide emergency." Within weeks,
  DARPA stood up the Computer Emergency Response Team Coordination Center at
  Carnegie Mellon's Software Engineering Institute. The founding insight was
  organizational, not technical: response capability must exist BEFORE the
  incident, with phones, procedures, and people who have rehearsed.
- **A network of teams formed (1990s).** Response teams multiplied — vendors,
  governments, corporations — and in 1990 they federated as FIRST, the Forum
  of Incident Response and Security Teams. The vocabulary of CSIRTs (Computer
  Security Incident Response Teams), escalation, and coordinated disclosure
  dates from this era.
- **Playbooks became doctrine (2000s).** NIST SP 800-61, first published in
  2004 and revised since, codified the lifecycle almost everyone now uses:
  Preparation; Detection & Analysis; Containment, Eradication & Recovery;
  Post-Incident Activity — which practitioners commonly expand into the six
  phases this module follows (preparation, detection & analysis, containment,
  eradication, recovery, lessons learned). SANS training spread handler
  handbooks and the habit of written per-phase checklists.
- **Notification obligations changed the stakes (2010s–today).** Breach-
  notification regimes turned response into a legal clock: the GDPR's
  requirement to notify regulators of personal-data breaches within 72 hours
  of becoming aware (enforceable from May 2018) is the emblematic example,
  and contractual clauses plus cyber-insurance policies add their own clocks.
  SKILL.md deliberately treats these as CONCEPTS to inventory in advance —
  deadlines vary by jurisdiction and contract, so the readiness item is a
  written obligations table, never memory.
- **Exercises replaced shelfware (throughout).** Tabletop exercises were
  borrowed from military and emergency-management culture: walk through a
  scenario aloud, no systems touched, and let the gaps surface safely.
  Decades of post-incident reports repeat one finding — plans existed on
  paper but failed in practice — which is why modern programs verify by
  exercise, not by document inspection.

The recurring lesson: incidents are won or lost before they start, in the
quality of preparation artifacts and rehearsal. Improvisation under pressure
is what unprepared organizations do instead.

## Anatomy: one declared incident, minute by minute

The minimal unit of IR practice is a declared incident with a timeline.
Everything else hangs off that skeleton:

```
INCIDENT INTAKE (the whole form fits on one screen)
Incident ID:   IR-YYYYMMDD-NN        Declared by / at (UTC)
What happened: [one sentence, observed facts only]
When first seen + detection source
Scope guess:   [labeled GUESS]       Evidence pointers: [alert/log links]
Customer-impacting / data-exfil-suspected: yes/no/unknown
Initial severity: SEV1-4            Comms thread + responder scribe: names

FIRST-HOUR CHECKLIST (condensed)
declare -> assign roles aloud -> start scribe timeline -> preserve volatile
evidence -> short-term containment -> severity via decision tree -> open
out-of-band channel -> pull detection context -> first exec update ->
record the containment-vs-evidence tradeoff decision
```

Walkthrough of why each piece exists, using a leaked API token as the story:

1. An alert fires: production token seen in a public repo. Someone declares:
   opens ticket `IR-20260824-01`, fills intake. Declaring converts chat
   chatter into an object with an owner, a clock, and a record.
2. Roles go out loud — incident lead, scribe, responders — because implicit
   leadership is how two people each assume the other revoked the token.
3. The scribe timeline starts: every action logged with UTC timestamps,
   append-only. This is chain-of-custody-lite; it costs seconds and saves
   the postmortem from mythology.
4. Evidence before remediation: capture what exists (who used the key, from
   where) BEFORE revoking destroys further use evidence. Order-of-volatility
   applies even here — live sessions die first.
5. Short-term containment: revoke the token NOW, investigate second. A live
   credential being "watched" is an active breach. Long-term containment
   follows over hours: rotate dependents, audit grants.
6. Severity comes from a lookup table, not a debate: suspected data exposure
   starts at SEV1; a leak with no confirmed misuse sits at SEV2 until
   evidence upgrades it. Upgrading is free; downgrading needs confirmation.
7. The out-of-band channel opens — precisely because primary tooling
   (email/Slack/identity provider) may itself be the compromised asset.
8. An executive update goes out on cadence with facts-only content and an
   explicit next-update time. Silence breeds rumor; speculation creates
   liability.

## Why naive approaches fail

- **Improvising at 3 a.m.** Without pre-written playbooks, the first hour is
  spent deciding WHO decides. Every readiness item in SKILL.md exists to
  move decisions from crisis time to calm time.
- **Writing prose nobody can execute.** A forty-page policy document is not
  a playbook. Capability = artifact + person who can find it + rehearsal;
  SKILL.md scores a document last edited 18 months ago as ABSENT-in-effect.
- **Fixing before preserving.** The remediation reflex — patch, reboot,
  rebuild — destroys the record of how the attacker got in. Eradication
  without root cause guarantees a repeat performance.
- **Trusting single-channel communications.** If Slack, email, and the
  identity provider share fate, one incident removes both the systems AND
  the ability to coordinate about them. The out-of-band channel must be
  independent and rehearsed.
- **Assuming backups mean recoverability.** "Backups exist" and "we restored
  service X on date Y in Z minutes" are different sentences. Untested
  restore is a hope, and hopes do not survive ransomware.
- **Treating notification as a technical afterthought.** Regulatory and
  contractual clocks start at awareness, not at convenience. Discovering
  your obligations during an incident guarantees missed ones; counsel joins
  early, not after cleanup.
- **Relying on heroes.** One engineer who handled everything brilliantly and
  then left the company is not capability — it is a single point of failure
  that already failed.

## Common misconceptions

1. "IR is purely technical." Most first-hour failures are organizational:
   unclear roles, unreachable people, dead channels, unknown obligations.
   That is why half this module audits process artifacts rather than hosts.
2. "We'd know immediately if we were breached." Detection lag is the norm,
   often measured in weeks without deliberate telemetry (see the sibling
   detection module). Readiness assumes you found out LATE.
3. "Containment means shutting everything down." Pulling the plug trades
   visibility for safety blindly and destroys volatile evidence. Containment
   has two clocks — minutes-scale access cuts and hours-scale hardening —
   and each scenario names which actions preserve evidence while stopping
   spread.
4. "Postmortems find who to blame." Blame guarantees silence next time.
   Blameless review targets systems and contributing factors, which is the
   only way the fixes actually reach engineering.
5. "Tabletops are theater for executives." A good tabletop surfaces real
   blockers — unreachable escrow, stale rosters, missing retention — at zero
   production risk. It is the cheapest readiness data available, which is
   also why SKILL.md re-audits after every REAL incident.
6. "Legal and comms wait until the techies finish." Notification clocks run
   during investigation, and one wrong public claim is unretractable. Exec
   updates and customer statements have templates and owners from minute one.
7. "Severity debates are process failure." Arguing against an explicit
   matrix IS the matrix working; instant assignment via unwritten rules is
   the dangerous case.

## How professionals think about it today

Modern programs read IR as three layers, and SKILL.md maps onto all three;
every audit finding lands in exactly one place.

| Layer | Sub-types in this module | What it answers |
|---|---|---|
| Readiness (Half A) | R1 playbook … R9 disclosure channel | If an incident starts NOW, does anything besides improvisation happen? |
| Execution (Half B) | six phases × five scenarios (token, webshell/RCE, DB exfil, bad dependency, committed secrets) | Who does what, in which order, with which template? |
| Verification | SEV1–SEV4 matrix, escalation chains, tabletop kit, metrics (TTD/TTM) | How do we know any of the above works? |

Two cross-cutting habits distinguish mature programs: every action emits an
artifact (drill records, restore logs, dated agendas — no artifact equals
not verified), and findings feed back into prevention modules after every
incident, closing the loop with vulnerability management and detection.

## Read next

In `../SKILL.md`: **Adaptation Note — Read First**, **Prerequisites &
Vocabulary**, **Scope & Objectives** (both halves), **Mental Model**
(lifecycle diagram + four axioms), **What To Check** (readiness items R1–R9),
**Where To Look** (artifact locations), **Patterns & Signatures** (scenario
grid, phase playbooks, first-hour checklist, five scenario walkthroughs),
**Taint Tracing Guidance** (escalation/communication chains), **Exploitation
& Reproduction** (tabletop facilitation kit and injects), **Remediation**
(B0–B8 build order), **Verification & Validation** (exercise-based pass
criteria), **Severity Assessment** (SEV1–SEV4 matrix), **Common False
Positives**, **References**.

Sibling modules in operations/: `../blue-team-detection/SKILL.md` (where the
page comes from and how alert urgency feeds severity), `../dfir-triage/SKILL.md`
(the first-hours host forensics this module hands off to), `../vuln-mgmt-process/
SKILL.md` (how post-incident fixes get priorities and clocks). Closest
companions elsewhere: server skillset `logging-monitoring` (evidence sources)
and `backup-dr` (restorable-backup proof), code skillset `supply-chain` and
`secrets-data-exposure` (two of the five scenario classes).
