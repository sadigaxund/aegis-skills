---
name: security-operations-loop
description: >
  Orchestrator for the reactive and continuous side of security: scheduled
  sweeps, detection engineering, alert triage, incident response, forensic
  triage, vulnerability tracking, and drills. Owns the operating rhythm that
  keeps findings from the two audit masters (SKILL.md, SKILL-SERVER.md)
  from decaying.
category: security
version: 1.0.0
---

# Security Operations Loop — Master Orchestrator

Where the audit masters answer "what's wrong today?", this master answers
"how do we watch, respond, and improve between audits?" It runs on a cadence
and on trigger, not per-audit.

Identity split across the three masters:

| Master | Question it answers | Mode |
|---|---|---|
| SKILL.md | What bugs are in the software? | proactive, per-run |
| SKILL-SERVER.md | How exposed/hardened are the machines? | proactive, per-run |
| **SKILL-OPERATIONS.md** | **Are we watching, responding, improving?** | continuous / reactive |

## Ground Rules

Same non-negotiables as both audit masters (authorization gate, evidence rule,
redaction, fixed vocabulary) plus two operations-specific ones:

1. **Incidents outrank audits.** If an incident is active, drop scheduled work
   and follow DFIR/IR sequencing; resume the loop only after stand-down.
2. **Every alert gets an outcome.** Triage ends in a recorded verdict (true /
   false positive / needs-more-data). Silent dismissal is how real detections
   get ignored later.

## Module Registry

| Slug | Module | Role in the loop |
|---|---|---|
| DETECT | checks/blue-team-detection.md | Detection coverage per vulnerability class; structured event logging; alert thresholds; purple-team replay validation |
| IR | checks/incident-response.md | Lifecycle playbooks: readiness audit + containment scenarios keyed to finding classes |
| DFIR | checks/dfir-triage.md | First-60–120-min compromised-host triage; volatile capture; rebuild-vs-investigate frame |
| VULN | checks/vuln-mgmt-process.md | The tracking loop: prioritize, SLAs, exceptions, metrics, cadences |

Shared modules owned by other masters but used here: LOGMON
(checks/server/logging-monitoring.md — telemetry plumbing when wiring
detections), DR canaries (checks/server/backup-dr.md §6), SUPPLY scanner
commands (dependency advisories feed FIND), sweeps toolkit
(tools/run-all-sweeps.sh — doubles as post-rebuild verification).

## Operating Rhythm

### Steady state (scheduled)

| Cadence | Activity | Module/tool |
|---|---|---|
| Weekly | Run sweeps on hosts; glance at distro security notices + dependency advisories | tools/run-all-sweeps.sh, SUPPLY §FIND |
| Monthly | 30-min metrics review: open-by-severity, MTTR, exceptions expiring, coverage freshness | VULN §metrics |
| Quarterly | Full code audit (SKILL.md) + host audit (SKILL-SERVER.md); immutability drill | both masters, DR §6 |
| Twice yearly | Restore drill + IR tabletop | DR, IR tabletop kit |
| On demand | Targeted audit when new endpoint/service/dep class lands | relevant slug only |

### Reactive triggers

| Trigger | Load first | Then |
|---|---|---|
| Alert fired / anomaly suspected | DETECT triage intake | DFIR if host-suspicion; IR SEV matrix for severity |
| "We think this host is compromised" | DFIR immediately | IR containment scenarios after scoping |
| Leaked secret / compromised token found | TOK leak runbook + IR scenario (a) | rotation cascade, then hunt usage |
| Malicious dependency suspected | MALCODE verdict flow | SUPPLY response ladder + IR scenario (d) |

## Phases of the loop

1. **Observe** — telemetry exists and ships off-host (LOGMON readiness items).
2. **Detect** — rules/thresholds per vulnerability class armed and
   purple-team-validated (DETECT replay loop R1–R7).
3. **Triage** — every alert gets a recorded verdict within the paging rubric's
   time target.
4. **Respond** — IR playbook phase execution; DFIR technical sequence on
   affected hosts; evidence preserved before remediation.
5. **Recover** — rebuild from IaC; return-to-service gate = re-run targeted
   audit modules + sweeps until clean.
6. **Learn** — postmortem action items; findings feed VULN tracking; gaps found
   during response become edits to the audit modules themselves.

## Output Conventions

Reuse the shared templates: incidents produce an IR timeline note (per
incident-response.md), forensic actions land in the responder log (DFIR),
tracked risks become standard finding reports under `security-audit/<run-id>/`
so the two audit masters can re-verify them on the next pass. PROGRESS-style
ledger optional here; the VULN tracker is the source of truth.

## Determinism Note

Same Appendix-C discipline applies verbatim: alerts get verdicts from the
DETECT rubric, incidents get severities from the IR SEV matrix, triage notes
cite the query/output that justified them. No vibes-based closures.
