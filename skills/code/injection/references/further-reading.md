# Injection — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.

## Standards & cheat sheets

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) - canonical parameterization/allowlist rules that back the SQL class in Remediation.
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) - language-by-language argv-array guidance matching the command-injection classes.
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) - filter escaping specifics behind the RFC 4515 rule in What To Check.
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) - cross-cutting positive-security-model framing that matches this module's one-root-cause mental model.

## Deep dives

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) - formal definition, consequences, and mitigation taxonomy for the module's highest-severity class.
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) - distinguishes argument-supplied vs fully attacker-selected command forms; frames the argument-injection sub-type.
- [PortSwigger Web Security Academy: SQL injection](https://portswigger.net/web-security/sql-injection) - structured walkthrough of detection through blind/second-order exploitation for lab verification context.
- [PortSwigger Web Security Academy: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection) - detect-identify-exploit methodology underlying the SSTI engine-discrimination approach.
- [RFC 4515: LDAP String Representation of Search Filters](https://datatracker.ietf.org/doc/html/rfc4515) - the normative grammar defining exactly which characters LDAP filters must escape.

## Vendor docs

- [MongoDB Manual: $where operator](https://www.mongodb.com/docs/manual/reference/operator/query/where/) - vendor documentation of server-side-JavaScript queries, including deprecation and scripting-disable guidance cited in NoSQL remediation.
- [Apache Log4j Security page](https://logging.apache.org/log4j/2.x/security.html) - vendor-advisory record of the JNDI lookup vulnerability family and fixed-version guidance referenced in code/expression evaluation checks.
