# Access Control — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.

## Standards & cheat sheets

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) - deny-by-default and per-request re-validation principles behind the centralized policy layer.
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) - design patterns (RBAC/ABAC/ReBAC trade-offs) informing the choke-point architecture.
- [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) - identifier-mapping vs access-check guidance matching the BOLA remediation.
- [OWASP API Security 2023 - API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) - the API-era framing (and prevention checklist) for the object axis.
- [OWASP API Security 2023 - API5: Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) - role-hierarchy questions that structure the BFLA review.

## Deep dives

- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) - the formal IDOR/BOLA definition, including why validated keys are not authorized keys.
- [PortSwigger Web Security Academy: Access control vulnerabilities](https://portswigger.net/web-security/access-control) - vertical/horizontal escalation taxonomy plus the URL-matching and header-override bypass classes mirrored by the bypass tests.

## Vendor docs

- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) - authoritative semantics (default-deny, permissive vs restrictive policies, bypass caveats) for the RLS defense-in-depth recipe.
