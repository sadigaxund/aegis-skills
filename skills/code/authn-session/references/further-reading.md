# Authentication & Session Management — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.

## Standards & cheat sheets

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) - login, throttling, and uniform-error guidance backing the Login & credential verification checks.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) - session-id properties, expiration, and renewal rules behind the session lifecycle checks.
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - the Argon2id/bcrypt/scrypt/PBKDF2 parameter floors cited in Remediation.
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) - reset-token issuance/consumption requirements mirrored by the recovery flow checks.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) - factor selection and MFA-flow design constraints behind the MFA section.
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) - algorithm-pinning, key-management, and invalidation guidance for the JWT checks.
- [NIST SP 800-63B: Digital Identity Guidelines (Authentication)](https://pages.nist.gov/800-63-3/sp800-63b.html) - the normative source for password policy (length over composition), KDF storage, and authenticator assurance levels.

## Deep dives

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) - parent class tying together the bypass, replay, and weak-recovery children this module maps findings onto.
- [PortSwigger Web Security Academy: Authentication vulnerabilities](https://portswigger.net/web-security/authentication) - brute-force, MFA-bypass, and reset-poisoning walkthroughs that contextualize the Exploitation & Reproduction steps.

## Vendor docs / protocol specs

- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) - normative claim semantics (`iss`/`aud`/`exp`) that verification code must actually enforce.
