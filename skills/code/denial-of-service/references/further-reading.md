# Denial of Service — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's harnesses and config tables remain the primary audit tools.

## Weakness entries (CWE)

- [CWE-400 Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) - umbrella entry behind every missing-limits finding; its mitigation text frames throttling as an architecture-phase duty.
- [CWE-1333 Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html) - canonical ReDoS definition including the three conditions that make backtracking a weakness, cited by this module's findings.
- [CWE-409 Improper Handling of Highly Compressed Data](https://cwe.mitre.org/data/definitions/409.html) - decompression-bomb entry whose demonstrative XML-bomb example shows 2^32-character expansion from a tiny document.

## Cheat sheets & community references

- [OWASP: Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) - "evil regex" anatomy with the worked NFA path-counting example backing the vulnerable-shape catalog.
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) - layered methodology separating application/session/network attacks, matching this module's application-layer scope boundary.
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) - per-stack parser hardening that disables DTDs/entities, killing billion-laughs expansion at the root.

## Engine rationale

- [google/re2 on GitHub](https://github.com/google/re2) - project README stating the design goal of untrusted-user regex handling with linear-time matching guarantees, grounding the engine-differences table.

Severity evidence should cite the CWE entry plus your measured amplifier;
these links corroborate definitions, never substitute for the offline doubling
harness results SKILL.md requires.
