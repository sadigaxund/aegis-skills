# Configuration Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's Remediation section remains the primary fix reference.

## Standards & cheat sheets

- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) - rule-by-rule container hardening (socket exposure, USER, capabilities, read-only filesystems) backing the container class.
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html) - pod securityContext, NetworkPolicy, and RBAC guidance matching the orchestration checks.
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) - develop/deploy/runtime lifecycle controls for the Terraform and IaC findings.
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) - per-header recommendations (HSTS, nosniff, Referrer-Policy, Set-Cookie flags) behind the header baseline table.

## Deep dives

- [CWE-16: Configuration (category)](https://cwe.mitre.org/data/definitions/16.html) - the umbrella entry mapping this module's OWASP A05 lineage; notes why modern CWE prefers behavior-specific descendants.
- [CWE-1188: Initialization with an Insecure Default](https://cwe.mitre.org/data/definitions/1188.html) - the mappable base weakness formalizing "insecure default accepted".
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) - normative browser behavior for preflight, credentials, and wildcard rules that the reflection findings exploit.
- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors) - exploit walkthroughs of origin reflection, null-origin allowlists, and suffix-match bugs.

## Vendor docs

- [Django deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/) - vendor-mandated prod settings (`DEBUG`, `ALLOWED_HOSTS`, `SESSION_COOKIE_SECURE`) matching the Django remediation block.
- [Spring Boot Actuator reference](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html) - authoritative endpoint list and `management.endpoints.web.exposure.include` semantics used in the actuator findings.

Nothing here replaces the in-repo evidence rules: cite `file:line` and the
effective production profile from SKILL.md first; these links corroborate.
