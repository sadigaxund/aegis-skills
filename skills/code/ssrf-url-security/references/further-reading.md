# SSRF & URL Security — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's sink catalog remains the primary per-language reference.

## Standards & cheat sheets

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) - canonical validation/network-layer controls backing the parse-validate-pin-revalidate policy.
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) - open-redirect prevention patterns for the module's Location-header class.
- [WHATWG URL Standard](https://url.spec.whatwg.org/) - the normative parser (userinfo, backslash, IPv4-form, IDNA rules) that validator-vs-sink mismatch findings are measured against.

## Deep dives

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) - formal definition, consequences, and the confused-deputy framing behind the mental model.
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html) - phishing mechanics and mitigation set for the redirect half of the module.
- [PortSwigger Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf) - structured walkthrough of filter bypasses via encodings, parser quirks, and open redirects.

## Vendor docs

- [AWS: Use the Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) - vendor semantics of IMDSv1 vs IMDSv2 (PUT token, headers, hop limit) cited in the metadata exploitability logic.

Static confirmation per SKILL.md's Procedure 0 is reportable on its own; these
links corroborate the parser, redirect, and metadata behavior the chain relies on.
