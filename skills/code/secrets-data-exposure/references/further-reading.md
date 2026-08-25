# Secrets & Data Exposure — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.

## Standards & cheat sheets

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) - storage, handling, and rotation rules backing the secret-manager remediation.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) - what must never reach log sinks and how to design event data, per the logging-leakage checks.
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) - generic-error patterns behind the stack-trace-disclosure findings.

## Deep dives

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) - inbound vs outbound hardcoding variants framing the hardcoded-credential finding class.
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html) - the formal definition and examples for secrets/PII written to logs.
- [gitleaks (GitHub)](https://github.com/gitleaks/gitleaks) - widely used regex-based secret scanner; the pre-commit/CI gate shown in Remediation (note: project now accepts security patches only).

## Vendor docs / tooling

- [GitHub Docs: Push protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations) - forge-side blocking of secret-bearing pushes referenced by the guardrails section.
- [git-filter-repo (GitHub)](https://github.com/newren/git-filter-repo) - the history-rewrite tool recommended by the git project for post-rotation purges in the rotate-vs-rewrite rule.
