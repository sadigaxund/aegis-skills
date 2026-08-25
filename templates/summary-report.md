# Summary Report Template

> **Usage:** The orchestrator fills this once per audit run, after all check modules
> finish and findings are deduplicated. Save as `security-audit/<run-id>/SUMMARY.md`.
> This is the deliverable a human reads first; every claim must link back to a
> per-finding report. Do not introduce new findings here — only aggregate.

---

```markdown
# Security Audit — {{target name / repo}} ({{run-id}})

| Field | Value |
|---|---|
| Run ID | {{YYYY-MM-DD-HHMM-slug}} |
| Date | {{ISO date(s) of execution}} |
| Target | {{path/URL and version/commit audited}} |
| Authorization | {{confirmed by whom, scope statement}} |
| Mode | {{full / targeted: <slugs> / triage}} |
| Execution | {{subagent-per-check / inline sequential}} |
| Checks run / skipped | {{N run, M skipped — see Coverage Matrix}} |
| Auditor identity | {{tool/model + skillset version or commit}} |

## Executive Summary

{{5–10 sentences for management: overall posture in one paragraph, then the 3–5
things that must be fixed immediately and why, then the general theme of the
findings (e.g., "systemic absence of output encoding" rather than 40 isolated bugs).
No jargon without a parenthetical explanation. End with the single most important
action.}}

## Findings Statistics

| Severity | Count |
|---|---|
| Critical | {{n}} |
| High | {{n}} |
| Medium | {{n}} |
| Low | {{n}} |
| Info | {{n}} |
| **Total** | {{n}} |

By category:

| Category | Critical | High | Med | Low | Info |
|---|---|---|---|---|---|
| {{INJ}} | | | | | |

## Top Risks

{{For each of the top 3–5 findings (by severity x exploitability x reachability):
one paragraph = what it is, affected surface, worst case, fix effort. Link finding IDs.}}

## Chained Attack Paths

{{Where individual findings combine into something worse than the parts, describe the
chain explicitly. Examples: SSRF (SSRF-002) + metadata service -> cloud credentials ->
full account takeover; secrets in repo (SECRETS-004) + leaked CI logs -> production DB.
If none found, state "no cross-finding chains identified".}}

## Findings Index

| ID | Title | Severity | Status | Primary location | Report |
|---|---|---|---|---|---|
| {{INJ-001}} | {{title}} | {{High}} | {{Confirmed}} | {{file:line}} | [link](findings/INJ-001-....md) |

## Remediation Roadmap

**Immediate (this week)** — exploit-blocking, minimal-effort fixes:
1. {{Finding ID + action}}

**Near term (30 days)** — structural fixes:
2. ...

**Strategic (90 days)** — systemic/architectural:
3. ...

Quick wins list (high impact : low effort ratio): {{IDs}}

## Methodology & Coverage Matrix

| Check slug | Module file | Ran? | Files reviewed (approx) | Findings | Notes (skip reason / limitations) |
|---|---|---|---|---|---|
| INJ | skills/code/injection/SKILL.md | yes/no | | | |

## Limitations & Out-of-Scope

- {{What could not be tested and why: no running instance, closed-source deps,
  no dynamic testing authorization...}}
- {{Assumptions made}}

## Appendices

- [Target profile](TARGET-PROFILE.md)
- Per-check reports: {{links}}
- Commands/tools log: {{PROGRESS.md}}
```
