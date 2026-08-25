# Cryptographic Failures — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.

## Standards & cheat sheets

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) - current Argon2id/scrypt/bcrypt/PBKDF2 floors backing the parameter table in Remediation.
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) - algorithm/mode/randomness rules matching the Wrong-primitive/Mode/Key classes.
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) - key lifecycle, rotation, and separation guidance behind the cross-purpose-reuse check.
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) - protocol floors and cipher-suite policy grounding the TLS client checks.
- [NIST SP 800-63B (Digital Identity Guidelines)](https://pages.nist.gov/800-63-3/sp800-63b.html) - normative memorized-secret verifier requirements (salted, memory-hard KDFs) cited by the password-storage section.

## Deep dives

- [CWE-327: Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html) - umbrella weakness with DES/SHA-1 exemplars for the Wrong-primitive class.
- [CWE-338: Weak PRNG](https://cwe.mitre.org/data/definitions/338.html) - seeded/time-based generator failures behind the insecure-randomness findings.
- [RFC 9106: Argon2](https://datatracker.ietf.org/doc/html/rfc9106) - the memory-hard password-hashing specification, including its own parameter recommendations.

## Vendor docs

- [MDN: Crypto.getRandomValues()](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues) - browser-side CSPRNG source referenced by the randomness provenance checklist.
- [Node.js crypto module](https://nodejs.org/docs/latest/api/crypto.html) - vendor reference for `createCipheriv`/`getAuthTag`/`timingSafeEqual`/`scrypt`, the safe replacements named throughout the dangerous-call table.

(9 URLs total; each returned HTTP 200 with matching content when fetched.)
