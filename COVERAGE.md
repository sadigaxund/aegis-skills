# Coverage Matrix

Maps industry-standard control areas to the Aegis module(s) that check them.
Purpose: prove completeness, expose gaps honestly, and give buyers/maintainers
a one-page answer to "does this kit cover X?"

**Depth legend:**

- **playbook** — dedicated module with full detection/reproduction/remediation/verification contract
- **section** — substantive coverage inside a broader module
- **process** — covered as workflow/guidance (VULN/IR), not automated checking
- **out of scope** — deliberately not covered; named so the absence is a decision, not an oversight

## OWASP Top 10 (2021)

| OWASP category | Covered by | Depth |
|---|---|---|
| A01 Broken Access Control | AUTHZ · API · IAM | playbook |
| A02 Cryptographic Failures | CRYPTO · TLS (server) | playbook |
| A03 Injection | INJ · WEB · DESER (XSS) | playbook |
| A04 Insecure Design | LOGIC · GAME · LLM | playbook |
| A05 Security Misconfiguration | CONFIG · server masters (BASE/FW/TLS/SANDBOX) | playbook |
| A06 Vulnerable & Outdated Components | SUPPLY · PATCH · K8S image posture | playbook |
| A07 Identification & Authentication Failures | AUTHN · TOK · SSO | playbook |
| A08 Software & Data Integrity Failures | DESER · MALCODE · SUPPLY | playbook |
| A09 Logging & Monitoring Failures | DETECT · LOGMON | playbook |
| A10 SSRF | SSRF · TUNNEL (egress side) | playbook |

## Selected OWASP ASVS v4 areas

| ASVS area | Covered by | Depth |
|---|---|---|
| V1 Architecture & threat modeling | threat-model *process* lives in VULN/GUIDE; no facilitation module | process |
| V2 Authentication | AUTHN · SSO | playbook |
| V3 Session Management | AUTHN (session sections) | playbook |
| V4 Access Control | AUTHZ | playbook |
| V5 Validation, Sanitization & Encoding | INJ · WEB | playbook |
| V6 Stored Cryptography | CRYPTO | playbook |
| V7 Error Handling & Logging | SECRETS (exposure) · DETECT (signals) | section |
| V8 Data Protection | SECRETS · CRYPTO-at-rest rows | section |
| V9 Communications | TLS (server) · CRYPTO | playbook |
| V10 Malicious Code | MALCODE | playbook |
| V11 Business Logic | LOGIC · GAME | playbook |
| V12 Files & Resources | FILE · TUNNEL (object storage notes) | playbook |
| V13 API & Web Service | API · SSO · WEBHOOKS in BAAS | playbook |
| V14 Configuration | CONFIG · server masters | playbook |

## CIS Controls v8 groups

| CIS control group | Covered by | Depth |
|---|---|---|
| 1 Inventory of enterprise assets | TARGET/HOST-PROFILE + sweep-code-recon | section |
| 2 Software inventory / supported software | PATCH · SUPPLY manifests | section |
| 3 Data protection | SECRETS · CRYPTO · DR (encryption) | section |
| 4 Secure configuration | CONFIG · BASE · SANDBOX | playbook |
| 5 Account management | AUTHN · HSECRET (host accounts) | playbook |
| 6 Access control management | AUTHZ · IAM · TOK | playbook |
| 7 Continuous vulnerability management | VULN · SUPPLY scanners | playbook/process |
| 8 Audit log management | LOGMON · DETECT | playbook |
| 9 Email & browser protections | MAIL · WEB | section |
| 10 Malware defenses | MALCODE · DFIR triage | section |
| 11 Data recovery | DR | playbook |
| 12 Network infrastructure management | FW (host) · — network appliances out of scope | partial/out of scope |
| 13 Network monitoring & defense | DETECT · LOGMON | section |
| 14 Security awareness | — | out of scope (human layer) |
| 15 Service provider management | IAM third-party trust rows · IR vendor contacts | section |
| 16 Application software security | the entire code-audit master | playbook |
| 17 Incident response | IR · DFIR | playbook |
| 18 Penetration testing | audits approximate this statically; dynamic testing out of scope | out of scope (dynamic) |

## Known boundaries (deliberate)

Dynamic exploitation testing (DAST/pentest) — bridge via OWASP ZAP against reachable
environments; findings enter the same VULN loop. Human-layer controls (training,
phishing simulations, insider programs). Windows/AD estates. OT/ICS, wireless,
firmware/hardware. Network appliance configs (pfSense/NGFW). See README "Scope and
honesty".

*Maintainers: when adding a module, re-scan this file and fill rows; when OWASP/CIS
update versions, re-map. Keep depth labels honest — "process" and "section" are not
"playbook".*
