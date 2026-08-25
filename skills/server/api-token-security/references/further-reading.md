# API Token Security — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's Remediation section remains the primary fix reference.

## Protocol & standards

- [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) - normative basis for header-vs-query carriage, WWW-Authenticate error semantics, and the security considerations (URL leakage, short-lived/scoped tokens) cited throughout.
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - authenticator entropy, verifier, and lifecycle requirements grounding the mint/storage floors (note: superseded by SP 800-63-4 as of August 2025; page states this).

## Cheat sheets (OWASP)

- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) - storage, throttling, and error-message guidance backing the lockout/enumeration checks.
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) - token-in-header vs URL rules and caching-of-auth-decision warnings behind the transport findings.
- [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) - distribution, rotation, and webhook-secret lifecycle guidance for the client-hygiene domain.

## Project context

- [OWASP API Security Project](https://owasp.org/www-project-api-security/) - the Top 10 family (notably Broken Authentication, 2023 edition) situating these token flaws among real-world API breach patterns.

## Weakness mapping

- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) - the class covering plaintext/recoverable credential storage, parent of the plaintext-password and recoverable-format variants.
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) - the missing-throttle weakness class behind unbounded online guessing and absent per-key quotas.

Nothing here replaces the in-repo evidence rules: judge effective state (deployed
schema, running middleware, actual logs) per SKILL.md first; these links
corroborate.
