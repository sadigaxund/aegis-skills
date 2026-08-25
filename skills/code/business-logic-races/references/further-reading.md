# Business Logic & Race Conditions — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & cheat sheets

- [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html) - canonical server-side-recompute and state-machine guidance backing the tampering/bypass classes.
- [OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) - authorization rules for money-moving transitions, matching the approval-flow checks.

## Deep dives

- [CWE-362: Race Condition](https://cwe.mitre.org/data/definitions/362.html) - formal definition (exclusivity/atomicity) behind every check-then-act finding in What To Check.
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html) - the check-vs-use gap variant, including the access()-then-open() exemplar mirrored by upload/revocation races here.
- [PortSwigger Web Security Academy: Race conditions](https://portswigger.net/web-security/race-conditions) - limit-overrun and hidden multi-step-sequence methodology with the single-packet delivery technique for authorized labs.
- [PortSwigger Web Security Academy: Business logic vulnerabilities](https://portswigger.net/web-security/logic-flaws) - taxonomy of excessive client trust, flawed assumptions, and domain-specific flaws matching this module's classes.

## Vendor docs

- [Stripe API: Idempotent requests](https://docs.stripe.com/api/idempotent_requests) - production-grade idempotency-key contract (stored response replay, parameter-mismatch rejection) that Remediation's key table implements.
- [PostgreSQL: Transaction Isolation](https://www.postgresql.org/docs/current/transaction-iso.html) - authoritative explanation of why snapshot isolation still allows write skew; grounds the row-lock/conditional-UPDATE requirement.
- [MongoDB: Transactions](https://www.mongodb.com/docs/manual/core/transactions/) - single-document atomicity vs multi-document transactions on replica sets, matching the Node.js fix patterns.

(9 URLs total; each returned HTTP 200 with matching content when fetched.)
