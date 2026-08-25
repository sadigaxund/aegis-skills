# OAuth 2.0 / OIDC / SAML Federation — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's flaw table and remediation shapes remain the primary
audit reference.

## Specifications

- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749) - base protocol: grants, endpoints, and the security-considerations section every finding cites.
- [RFC 7636 - Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636) - defines the code-interception attack PKCE answers and the S256 verifier/challenge math behind the flow checks.
- [RFC 8252 - OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252) - loopback-IP redirect rules (any port) and exact-match registration requirements used to judge native-client validators.
- [RFC 9700 - Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700) - current BCP mandating exact redirect matching, deprecating implicit/password grants, and detailing mix-up and injection countermeasures.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) - id_token claim definitions and the validation steps backing the RP claim matrix.
- [OAuth 2.1 (draft overview)](https://oauth.net/2.1/) - consolidated diff list (PKCE required, implicit omitted, exact string matching) for framing legacy findings.

## Weakness entry

- [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) - umbrella weakness for XSW and alg-confusion findings at signature-verifying sinks.

## Practitioner guides

- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html) - schema-validation-first XSW countermeasures plus audience/Destination/window checks mirroring the SAML section.
- [PortSwigger Web Security Academy: OAuth authentication vulnerabilities](https://portswigger.net/web-security/oauth) - exploitation walkthroughs (redirect_uri bypass techniques, flawed CSRF, unverified registration) aligned with the module's procedures.

Prefer these over blog posts when corroborating a finding: RFCs fix normative
language, the BCP fixes "current practice", and the two guides map findings to
reproducible test cases.
