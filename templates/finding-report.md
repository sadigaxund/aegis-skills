# Finding Report Template

> **Usage:** Copy this template once per confirmed or suspected vulnerability.
> Save as `security-audit/<run-id>/findings/<SLUG>-<NNN>-<short-kebab-title>.md`.
> Every field is mandatory. If a field genuinely does not apply, write `N/A` plus one
> sentence of justification. Never delete sections. Never invent evidence: if you cannot
> point at code, the finding status must be `Probable` or `Needs-Review`, never `Confirmed`.
>
> Replace every `{{placeholder}}`. Keep section order exactly as below.

---

```markdown
# {{FINDING_ID}}: {{Short imperative title, e.g. "SQL injection in /api/users search"}}

| Field | Value |
|---|---|
| Finding ID | {{SLUG-NNN}} |
| Category | {{Check slug, e.g. INJ}} |
| Title | {{Same as heading}} |
| Severity | {{Critical / High / Medium / Low / Info}} |
| CVSS v3.1 | {{Vector string + score, e.g. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)}} |
| CWE | {{CWE-ID name(s), most specific first}} |
| OWASP | {{OWASP Top 10 2021 category}} |
| Status | {{Confirmed / Probable / Needs-Review}} |
| Fix Status | {{Open / Fixed (unverified) / Verified-Fixed / Risk-Accepted}} |
| Locations | {{path/to/file.ext:LINE, path/to/other.ext:LINE}} |
| Introduced by / since | {{commit, version, or "unknown"}} |

## Summary

{{2–4 sentences: what is wrong, where, why it matters. Written so a manager can
understand it without reading the rest.}}

## Affected Surface

{{WHO can reach this and HOW FAR it reaches. Answer explicitly:}}
- **Entry points:** {{URL routes / RPC methods / CLI flags / file formats / message topics affected}}
- **Required privileges:** {{unauthenticated / any user / specific role / physical access}}
- **Reachable from:** {{public internet / partner network / localhost-only / build-time only}}
- **Data or assets exposed:** {{what an attacker gains: records, tokens, RCE, funds...}}
- **Blast radius:** {{single tenant / whole system / supply-chain downstream consumers}}
- **Preconditions & constraints:** {{WAF, encoding requirements, race timing windows, feature flags}}

## Root Cause Analysis

{{Explain the defect mechanically: the data flow from untrusted source to dangerous
sink, and which control is missing or bypassed. Reference exact functions and lines.
State WHY the existing code is insufficient (e.g. "parameterized query exists but
ORDER BY column is interpolated").}}

## Evidence

{{Minimal verbatim snippets with file:line above each. Trim to relevant lines.
Redact secret values: show first 4 characters + `…REDACTED`.}}

## Exploitation Scenario

{{A concrete attacker story, numbered steps, from "attacker has X" to "attacker
achieves Y". Include any payloads inline. This is the narrative a defender uses to
prioritize; make it realistic, not theoretical.}}

## Reproduction Steps (PoC)

{{Exact, copy-pasteable reproduction. Numbered. Include: environment assumptions,
exact requests/commands with payloads, expected observable result proving the vuln.}}

```bash
# Example shape:
curl -i "http://TARGET/api/users?order=(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END)"
# Expected: response delayed ~5s -> boolean/time-based SQLi confirmed
```

{{If dynamic testing was not possible (static-only audit), provide the PoC anyway and
mark Status accordingly. State explicitly what could NOT be verified dynamically.}}

## Impact

{{Concrete consequences mapped to C-I-A: confidentiality / integrity / availability.
Include realistic worst case and likely case. Mention compliance/regulatory exposure
only when clearly applicable (PII, PHI, PCI).}}

## Remediation

**Recommended fix:** {{one primary approach}}

```{{language}}
// VULNERABLE (current)
{{current code}}

// FIXED (proposed)
{{corrected code}}
```

**Why this fix works:** {{the control added and what it breaks in the attack chain}}

**Alternatives / defense-in-depth:**
- {{e.g., DB user least privilege, WAF rule, allowlist at reverse proxy}}

**Effort estimate:** {{trivial (<1h) / small (<1d) / medium (<1wk) / large (>1wk)}}

## Fix Verification Plan

{{How to PROVE the hole is closed. Must include all three:}}

1. **Targeted re-test:** repeat the exact PoC above; expected post-fix result:
   {{e.g., HTTP 400, no delay, parameter rejected}}.
2. **Regression tests to add:**

   ```text
   GIVEN a request with payload <X> WHEN processed THEN <safe observable outcome>
   ```

3. **Manual re-check checklist:**
   - [ ] {{specific item, e.g. ORDER BY column matched against allowlist}}
   - [ ] {{negative test: legitimate values still work}}
4. **Re-scan scope:** {{which grep patterns / check files to rerun after fix}}

## Residual Risk & Notes

{{What remains risky even after the fix, adjacent issues noticed, dependencies on
other findings, anything the fixer must not break.}}

## References

- {{CWE links, OWASP Cheat Sheet entries, vendor docs — stable URLs only}}
```

---

## Severity rubric (normative)

| Severity | Definition | Typical examples |
|---|---|---|
| **Critical** | Attacker gains RCE, auth bypass for admins, full DB read/write, or mass exfiltration of all tenants' data — with no/minimal privileges | Unauth SQLi returning hashes, deserialization RCE, SSRF->cloud metadata keys |
| **High** | Significant compromise: account takeover, cross-tenant read/write, stored XSS hitting many users, private repo/package takeover, secrets leak enabling further access | IDOR on PII, weak password reset token, path traversal read of app configs |
| **Medium** | Real but bounded impact: needs unusual preconditions, affects limited data, or requires user interaction | Reflected XSS with CSP friction, CSRF on low-value action, verbose stack traces w/o secrets |
| **Low** | Minor information disclosure, hardening gap, defense-in-depth absence with no direct exploit path | Missing security headers, username enumeration, outdated-but-not-vulnerable dep |
| **Info** | Observation worth recording; no exploit path today | Noteworthy design decision, potential future risk |

Tie-breakers (apply in order): exploitability > impact > reachability > data sensitivity.
When torn between two bands, choose the lower band and say why in Residual Risk.

## Status labels (normative)

| Status | Meaning |
|---|---|
| `Confirmed` | Code path fully traced AND validated statically line-by-line; PoC constructed. Dynamic validation done if environment allowed. |
| `Probable` | Strong static evidence; some link in the chain unverified (runtime config, framework default unknown). |
| `Needs-Review` | Pattern match with plausible exploitability; requires human or runtime confirmation. Orchestrator must deduplicate these aggressively. |
