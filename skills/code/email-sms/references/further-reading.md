# Email & SMS/OTP Flows — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & frameworks

- [RFC 7208: SPF](https://datatracker.ietf.org/doc/html/rfc7208) - normative SPF mechanics including the 10-lookup limit (§4.6.4) behind check A4 and the terminator semantics in Mental Model.
- [RFC 6376: DKIM Signatures](https://datatracker.ietf.org/doc/html/rfc6376) - selector/key model and signing rules grounding the DKIM artifact checks and rotation guidance.
- [RFC 7489: DMARC](https://datatracker.ietf.org/doc/html/rfc7489) - alignment definitions and policy progression (`p=none`→`quarantine`→`reject`) that findings language mirrors.

## Deep dives

- [CWE-93: CRLF Injection](https://cwe.mitre.org/data/definitions/93.html) - formal definition with worked examples for the header-injection sink class.
- [NIST SP 800-63B (Digital Identity, Authentication)](https://pages.nist.gov/800-63-3/sp800-63b.html) - authenticator assurance framing for OTP/out-of-band design; classic edition, now superseded by SP 800-63-4 — cite the current revision in formal reports.
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) - OTP design rules (entropy, expiry, attempt caps) matching the OTP Design Spec Block.

## Vendor docs

- [Google libphonenumber](https://github.com/google/libphonenumber) - maintained country-aware parsing/validation library recommended over regex-only E.164 checks in Remediation.

(7 URLs total; each returned HTTP 200 with matching content when fetched.
Dropped during verification: a Twilio SMS-pumping-fraud doc page that now
returns HTTP 404 — the pumping guidance lives in SKILL.md's anti-abuse bundle,
so no replacement link was needed.)
