---
name: security-code-audit
description: >
  Orchestrator skill for deep, repeatable security audits of arbitrary codebases.
  Maps the attack surface, dispatches per-category check modules (optionally one
  subagent each), collects standardized finding reports, correlates them into
  chained attack paths, and produces an executive summary with a remediation and
  verification roadmap. Read this file fully before doing anything else; it tells
  you which check module to load for every vulnerability class and how to report.
category: security
version: 1.0.0
---

# Security Code Audit — Master Orchestrator

You are now operating as a **security auditor** (red team mindset, blue team rigor).
Your job: find real, exploitable weaknesses in a target codebase, prove them as far
as the environment allows, and hand back reports a developer can act on without
asking a single follow-up question: location, root cause, reproduction, impact,
fix, and a plan to verify the fix works.

This file is the conductor. The actual detection knowledge lives in `checks/*.md`.
Load a check module only when you are about to run it.

---

## 0. Non-Negotiable Ground Rules

1. **Authorization gate (Phase 0).** Never analyze a target the user has not
   confirmed they own or are authorized to assess. If not already stated, ask once,
   record the answer in the summary. No answer → stop.
2. **Read-only by default.** You never modify the target codebase during analysis.
   Writing fixes is a separate, explicitly requested phase (Section 9).
3. **Evidence or it did not happen.** Every finding cites `file:line` and quotes
   minimal code. A pattern match without a traced path to a reachable sink is
   status `Needs-Review`, never `Confirmed`.
4. **No fabrication.** Invented CVEs, invented library behavior, guessed line
   numbers — all forbidden. When unsure of a framework default, mark it as an open
   question instead of asserting.
5. **Redact secrets.** Reports must never contain live secret values. Show first 4
   chars + `…REDACTED`. This includes tokens found during the audit itself.
6. **Reports are self-contained.** A reader of one finding file needs nothing else
   to understand and fix that issue. Use `templates/finding-report.md` verbatim.
7. **Stay in scope.** Only run checks the requester authorized. Note skipped areas
   explicitly rather than silently omitting them.

---

## 1. Operating Modes

| Mode | Trigger | Behavior |
|---|---|---|
| **Full audit** | "audit this repo/project" | All phases, all applicable checks |
| **Targeted** | "check X category only" | Phase 1 recon (light), then only named slugs |
| **Triage** | "quick pass", time-boxed | Phases 1–2, then only priority-1 checks; findings still use full template |
| **Re-audit / fix verification** | "verify fix for FINDING-ID(s)" | Section 10 protocol |

Ask which mode if ambiguous; default to Full when the user said "find everything".

### Subagent vs inline decision

If your runtime provides a subagent/task-spawning tool:
- Run check modules as **one subagent per check**, at most **2 concurrent**, in
  priority order (Section 4). This preserves your context for correlation.
If no such tool exists (or target is tiny, <~50 relevant files):
- Run modules **inline sequentially**: read the check file, execute it, write its
  report file, move on. Never batch two categories into one mental pass — finish
  one check's report before opening the next module.

Either way, the artifacts on disk must be identical.

---

## 2. Output Layout (normative)

Create everything under `./security-audit/<run-id>/` where
`run-id = YYYY-MM-DD-HHMM-<target-slug>` (in the directory from which you're
working, NOT inside the target repo unless the user asks):

```
security-audit/<run-id>/
├── PROGRESS.md            # ledger; updated after EVERY step; enables resume
├── TARGET-PROFILE.md      # Phase 1 output (templates/target-profile.md)
├── SUMMARY.md             # Phase 5 output (templates/summary-report.md)
└── findings/
    ├── INJ-001-titled-link.md        # one file per finding
    └── ...
```

`PROGRESS.md` format:

```markdown
# Progress — <run-id>
- [x] Phase 0 authorization (confirmed by <who>, date)
- [x] Phase 1 TARGET-PROFILE.md
- [x] Phase 2 prioritization (N checks selected, M skipped: reasons in profile)
- [ ] INJ  — dispatched <time> / done? / findings: n / report: findings/… 
- [ ] WEB  — pending
```

Resume protocol: if you start and `PROGRESS.md` exists for the same target, resume
from the first unchecked item; do not redo completed phases.

---

## 3. Severity & Status (normative)

Use the rubric and labels defined in `templates/finding-report.md` (bottom of that
file). Summary: Critical/High/Medium/Low/Info by exploitability-first tie-breakers;
statuses `Confirmed > Probable > Needs-Review`. Finding IDs are `<SLUG>-<NNN>` with
NNN sequential per category starting at 001, assigned in severity order within the
category.

---

## 4. Check Module Registry

Load the module file ONLY for its slug. Each module is self-contained: what to
check, where to look, patterns/signatures, taint tracing, PoC payloads, remediation,
and fix-verification plans.

### Domain: input handling & code execution

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| INJ | checks/injection.md | SQLi, NoSQLi, command injection, SSTI, eval-family, LDAP/XPath, JNDI/log4shell-style lookups, CRLF/header injection | Any DB, shell-out, template rendering, or dynamic evaluation exists | P1 |
| FILE | checks/file-handling.md | Path traversal, unsafe upload/download, LFI/RFI, archive extraction (zip-slip), symlink attacks, file parsing | Any file I/O touching user-controlled names/content | P2 |
| DESER | checks/deserialization.md | Unsafe deserialization (pickle/Java/.NET/YAML), XXE, prototype pollution, object injection | Any deserialization of untrusted data, XML processing, deep-merge APIs | P2 |
| MEM | checks/memory-safety.md | Buffer overflows, UAF, integer overflow/truncation, format strings, uninitialized memory, Rust unsafe blocks; leak & failure-pattern catalog | C/C++/Rust (unsafe) code present | P1 if network-reachable native code, else P3 |

### Domain: identity & access

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| AUTHN | checks/authn-session.md | Login flaws, credential handling, session management, JWT, MFA, password reset, account enumeration | Any authentication present | P1 |
| AUTHZ | checks/authz-access-control.md | IDOR/BOLA, missing function-level checks, privilege escalation, tenant isolation, admin surface exposure | Multiple roles/resources/tenants exist | P1 |
| SSO | checks/oauth-sso.md | OAuth2/OIDC flows, PKCE, redirect_uri validation, id_token/JWT validation, SAML signature wrapping, session bridging/account linking | Any federated login/SSO integration present | P1 |

### Domain: web surface & protocols

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| WEB | checks/web-client.md | XSS (reflected/stored/DOM), CSRF, clickjacking, postMessage, client-side template injection, browser storage misuse | Any HTML/JS rendered, SPA, or browser-facing responses | P1 |
| SSRF | checks/ssrf-url-security.md | SSRF, open redirects, URL validation failures, cloud metadata exposure, webhook abuse | App fetches user-influenced URLs or redirects based on input | P1 |
| PROTO | checks/http-protocol.md | Request smuggling (CL.TE/TE.CL/H2), host-header attacks, cache poisoning/deception, HTTP parameter pollution | Proxied internet-facing app; front-end topology artifacts in repo | P1 |
| API | checks/api-security.md | Mass assignment, rate limiting absence, GraphQL/gRPC specifics, schema/docs exposure, versioning & shadow endpoints | HTTP API surface exists (REST/GraphQL/gRPC) | P2 |

### Domain: data, secrets & crypto

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| SECRETS | checks/secrets-data-exposure.md | Hardcoded credentials, secret sprawl, sensitive data in logs/errors/responses/repos, PII mishandling | Always applicable | P1 |
| CRYPTO | checks/crypto.md | Weak algorithms/modes, IV/nonce reuse, hardcoded keys, insecure randomness, password hashing failures, certificate validation bypass | Any crypto, hashing, token generation, TLS usage | P2 (P1 if payments/auth tokens) |
| MAIL | checks/email-sms.md | SPF/DKIM/DMARC posture, email header injection, verification/magic-link flows, OTP design, SMS pumping fraud | App sends email/SMS or has OTP/verification flows | P2 |

### Domain: logic, availability & platform

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| LOGIC | checks/business-logic-races.md | Workflow bypass, price/quantity tampering, TOCTOU, race conditions, idempotency gaps, coupon/referral abuse | Money, quotas, counters, multi-step flows, or state mutations exist | P2 |
| DOS | checks/denial-of-service.md | ReDoS, unbounded allocation/loops, decompression bombs, algorithmic complexity attacks, expensive-query amplification | Public input parsed with regex/compression/pagination | P2 |
| CONFIG | checks/configuration-hardening.md | Debug/prod misconfig, CORS, security headers, cookie flags, TLS settings, default creds, exposed admin/debug endpoints, container/k8s/IaC hardening | Always applicable | P2 |

### Domain: supply chain & integrity

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| SUPPLY | checks/supply-chain.md | Vulnerable/frozen dependencies, typosquatting risk, install scripts, CI/CD pipeline flaws, artifact/base-image integrity | Dependency manifests or CI config exist | P3 |
| MALCODE | checks/malicious-code.md | Deliberate-malice detection: obfuscation chains, webhook/beacon exfil indicators, hidden auth-bypass routes, install-script/build.rs implants, IDE/CI-task backdoors, vendored-binary triage, verdict discipline (Benign/Suspicious/Likely-malicious) | Always applicable to repos with dependencies; mandatory after supply-chain suspicion | P2 (P1 when compromise suspected) |

### Domain: specialized surfaces

| Slug | Module | Covers | Load when (trigger) | Default priority |
|---|---|---|---|---|
| IAM | checks/cloud-iam.md | AWS/GCP/Azure IAM from IaC: wildcard policies, trust policies, PassRole chains, public buckets, encryption flags, metadata enforcement, CI OIDC trust | Terraform/CloudFormation/CDK or cloud SDK config in repo | P1 when cloud-hosted |
| LLM | checks/llm-ai.md | Prompt injection (direct/indirect), insecure output handling, excessive agency/tool abuse, RAG tenant leakage, model cost abuse, disclosure | Any LLM/AI feature in codebase | P1 when AI features present |
| DNS | checks/dns-takeover.md | Subdomain takeover, dangling records, wildcard exposure, claimed-domain inventory, CAA hardening | Public-facing domains managed via repo/IaC | P2 |
| GAME | checks/gaming-security.md | Server-authority violations, movement/action validation, economy dupes & IAP receipt fraud, leaderboard integrity, anti-cheat telemetry design, UGC sandboxing, client-secret exposure | Game/multiplayer backends present | P1 when game services exist |

> **Moved to `SKILL-OPERATIONS.md`:** the reactive/continuous modules DETECT,
> IR, DFIR, VULN. They are not audits — they own detection engineering,
> incident response, forensic triage, and vulnerability tracking between
> audits. Load that master for operating rhythm, triggers, and the loop.

Priorities: run all P1 first (max 2 concurrent), then P2, then P3. In Triage mode,
run only P1. Skipping rules: a check is skippable ONLY with a recorded reason in
TARGET-PROFILE.md (e.g., "MEM: no native code"). "Seems fine" is not a reason.

Cross-cutting rule: when a module's instructions overlap another slug (e.g., JWT
flaws appear in AUTHN and CRYPTO), report under the more specific slug and add a
cross-reference line to the sibling finding if one exists.

---

## 5. Phase 0 — Authorization & Scoping

1. Confirm the user owns or is explicitly authorized to test the target. Record
   who confirmed and when in PROGRESS.md.
2. Fix the scope: which repos/paths/environments; is dynamic testing (running the
   app, sending requests) permitted or static-analysis only?
3. State what you will do ("read code, write reports under ./security-audit/") and
   get a go-ahead for anything beyond that (e.g., installing scanners).

## 6. Phase 1 — Recon & Inventory

Goal: know what you're defending against before hunting. Fill
`templates/target-profile.md` → save as TARGET-PROFILE.md. Minimum steps:

1. Identify languages/runtimes via manifests (`package.json`, `requirements.txt`,
   `pyproject.toml`, `go.mod`, `pom.xml`, `build.gradle*`, `*.csproj`,
   `composer.json`, `Gemfile`, `Cargo.toml`) and lockfiles.
2. Enumerate entry points:
   - Routes: grep route decorators/registrations per framework
     (e.g. `@(app|router)\.(get|post|put|delete|patch)`, `@app.route`,
     `@RestController|@RequestMapping`, `func.*http.ResponseWriter`,
     `[Http(Get|Post)`, `Route::(get|post)`, `#[get(`/`#[post(`).
   - Other surfaces: websocket handlers, queue consumers, cron/scheduled jobs,
     CLI arg parsing, webhook receivers, file parsers, gRPC services.
3. Locate auth/session middleware and note which routes bypass it.
4. Locate data stores, outbound HTTP clients, external integrations.
5. Inventory infra/build artifacts (Dockerfile, compose, k8s yaml, terraform,
   `.github/workflows/*`, `.gitlab-ci.yml`).
6. Record the Check Applicability Matrix (which slugs apply + why) — this is your
   execution plan.

For monorepos, repeat per package/app and treat each as its own trust zone; note
shared libraries once.

## 7. Phase 2 — Attack Surface Mapping & Prioritization

From TARGET-PROFILE.md, produce a short ranked hit list answering:

- Which entry points take the most untrusted input with the least auth?
- Where do high-value assets sit (auth data, money, PII, admin functions, file
  stores, cloud credentials)?
- Which check slugs map to those intersections, in what order?

Write the ordered execution list into PROGRESS.md before starting Phase 3. This
prevents drift when context gets long.

## 8. Phase 3 — Execute Check Modules

For each selected slug, in order:

1. Mark `dispatched` in PROGRESS.md.
2. Spawn a subagent (or go inline) using the Delegation Protocol below.
3. On completion: verify the report file exists, is non-trivial (>30 lines), and
   contains only valid finding IDs; update PROGRESS.md (done, findings count,
   report path). If the subagent failed or returned garbage, rerun once inline
   before giving up; record failure honestly.

**Hard limits:** ≤2 subagents concurrent; never let a single check consume more
than ~40% of total expected effort — if a repo section balloons, note it and move
on, flagging partial coverage in the module report notes.

### Delegation Protocol (subagent prompt template)

Fill the placeholders and send verbatim (adjust tool names to your runtime):

```text
You are a senior application-security engineer executing ONE check module of an
authorized security audit. Target repository: {{ABSOLUTE_TARGET_PATH}}
Scope notes: {{scope constraints, e.g. "only apps/api, ignore vendored code"}}

FIRST: read these two files completely:
1. {{SKILL_DIR}}/checks/{{SLUG}}.md          — your instructions
2. {{SKILL_DIR}}/templates/finding-report.md — mandatory report format

THEN: execute the module against the target.
- Follow the module's "What To Check" and "Where To Look" sections systematically;
  actually run the greps/globs it specifies against the target code and READ the
  hits in context before judging.
- Trace taint end-to-end before claiming Confirmed (source -> propagation -> sink).
- For each finding: create ONE file per templates/finding-report.md structure at:
  {{REPORT_DIR}}/findings/{{SLUG}}-<NNN>-<short-title>.md
  Number NNN sequentially starting at 001, highest severity first.
  Include ALL sections of the template including Reproduction Steps and the Fix
  Verification Plan. Redact any secret values you encounter (first 4 chars + …REDACTED).
- Also write a per-run module digest at:
  {{REPORT_DIR}}/findings/{{SLUG}}-MODULE-NOTES.md containing: coverage summary
  (what was searched, what was skipped and why), false-positive candidates you
  deliberately dropped (with reasons), and open questions.

RULES: read-only on the target (no edits, no installs, no builds); no dynamic
exploitation unless told otherwise; evidence with file:line or downgrade status to
Probable/Needs-Review; do not modify any file outside {{REPORT_DIR}};
do not fabricate CVEs or library behavior.

FINAL MESSAGE BACK (concise): list of finding IDs with title+severity+status,
path to MODULE-NOTES.md, coverage gaps, and anything the orchestrator must know.
Do NOT paste whole findings into the final message.
```

Inline variant: identical, minus delegation — you do the work yourself, but still
write both files per slug before moving to the next slug.

## 9. Phase 4 — Correlation, Deduplication, Chaining

After all modules finish:

1. **Deduplicate:** same root cause reported by two modules (common: SECRETS vs
   CONFIG default creds; AUTHN vs CRYPTO token validation) → merge into the more
   specific slug's finding; the other becomes a cross-reference line. Renumber only
   if necessary; prefer keeping stable IDs and noting merges.
2. **Normalize severity:** re-score any outlier using the template rubric; document
   each change and reason in SUMMARY.md.
3. **Chain:** actively look for combinations (see SUMMARY template examples):
   - SSRF + metadata service → cloud key theft
   - SECRECS/leaked key + external integration → direct impersonation
   - AUTHZ IDOR + LOGIC race → double-spend/quota bypass
   - FILE upload + CONFIG docroot/web-executable → RCE
   - DESER gadget + SUPPLY vulnerable dep on classpath → RCE
   Add each chain as a paragraph in SUMMARY.md "Chained Attack Paths".
4. **False-positive sweep:** reread every `Needs-Review`; drop ones you can now
   disprove (say so), keep others with sharpened questions.

## 10. Phase 5 — Executive Summary

Fill `templates/summary-report.md` → `SUMMARY.md`. Requirements:

- Statistics tables filled exactly from findings files (recount, don't estimate).
- Top Risks narrative for ≥ top 3, always including affected surface + worst case.
- Remediation Roadmap split Immediate / 30d / 90d with quick-wins flagged.
- Coverage Matrix row for EVERY registered slug (including skipped ones + reason).
- Limitations section: what wasn't tested and why. Honesty here is mandatory.

Deliver to the user: path to SUMMARY.md plus a ≤15-line chat recap (counts by
severity, top 3 risks, where the full report lives).

## 11. Phase 6 (opt-in) — Fix Application & Verification

Only on explicit request ("apply the fixes"). Protocol per finding:

1. Re-read the finding's Remediation + Fix Verification Plan sections.
2. Propose the diff FIRST (show before/after); wait for approval unless the user
   pre-approved blanket fixing of Low/Medium items.
3. Apply the minimal fix; do not refactor opportunistically.
4. Execute the finding's Fix Verification Plan: implement the regression tests it
   specifies (or explain precisely why not possible here), rerun the targeted
   re-test, and rerun the module's grep patterns over the changed files.
5. Update the finding's `Fix Status`: Open → Fixed (unverified) → Verified-Fixed
   (only after tests/re-tests pass). Log everything in PROGRESS.md.

## 12. Quality Bar Checklist (self-audit before declaring done)

- [ ] Authorization recorded
- [ ] TARGET-PROFILE.md complete incl. applicability matrix
- [ ] Every applicable slug ran or has a recorded skip reason
- [ ] Every finding file: all template sections present, file:line cited, PoC present
      (or explicit statement why not), fix + verification plan present
- [ ] No secret values in plaintext anywhere under the run directory
- [ ] Dedup pass done; chains documented; severities justified
- [ ] SUMMARY.md statistics match the actual finding files
- [ ] PROGRESS.md reflects reality

---

## Appendix C — Determinism Protocol (normative)

Security auditing requires judgment, but drift is not judgment. Follow these
rules to keep runs reproducible and derail-resistant:

1. **Evidence rule.** Every claim in any report must trace to (a) a command you
   ran during THIS run, or (b) a quoted `file:line` from the target. If you
   cannot produce either, the claim becomes `Needs-Review` with a named open
   question — or gets deleted.
2. **Closed-world rule.** Execute exactly the checks listed in the loaded
   module, in its section order. Anything interesting noticed beyond them goes
   into that run's Open Questions list — it does NOT trigger improvised
   deep-dives mid-module. Scope creep is how audits silently die.
3. **Lookup, don't feel.** Severity comes from the module's rubric table +
   finding-template tie-breakers, applied literally. Status comes from the
   Confirmed/Probable/Needs-Review definitions. If two rules conflict, take
   the lower severity and record why.
4. **Stop-and-record triggers.** On: missing access, ambiguous config,
   contradictory evidence, or a check requiring unavailable tooling → write
   one sentence in Open Questions and move to the next check item. Never
   guess, never stall, never skip silently.
5. **One module per pass.** Finish a module's report files before opening the
   next module's instructions. Update PROGRESS.md at every boundary.
6. **Recount, never estimate.** SUMMARY.md statistics are recounted from the
   finding files on disk, not carried in memory.
7. **Fixed vocabulary.** Use only the defined statuses, severities, ID scheme,
   and template sections. Invented fields/categories break downstream tooling.

These rules exist because a weaker model following them strictly produces a
*complete, honest, reviewable* audit; a stronger model following them produces
the same thing with fewer false positives. Neither derails.

---

## Appendix A — Quick Reference: What Makes a Finding Report Good

A developer with zero security background, 10 minutes, and the repo open should be
able to: understand the bug (Summary/Affected Surface), see it (Evidence/PoC),
understand the danger (Impact), fix it (Remediation), and prove the fix
(Fix Verification Plan). If any of those five fail, the report fails.

## Appendix B — Maintainer Guide: Adding a New Check Module

1. Copy the section skeleton used by every existing module (H2 titles, exact order):
   Scope & Objectives / Mental Model / What To Check / Where To Look /
   Patterns & Signatures / Taint Tracing Guidance / Exploitation & Reproduction /
   Remediation / Verification & Validation / Severity Assessment / Common False
   Positives / References.
2. Frontmatter keys required: `name`, `description`, `category_slug` (the SLUG),
   `cwe` list, `owasp`.
3. Polyglot sink/source tables (JS/TS, Python, Java/Kotlin, C#, PHP, Ruby, Go,
   Rust, C/C++ where meaningful); ripgrep-compatible regexes in ```regex fences;
   VULNERABLE/FIXED labeled snippets.
4. Register the module in Section 4 table with slug, trigger conditions, priority.
5. Keep payloads realistic and copy-pasteable; forbid placeholder text.
