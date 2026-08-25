# Deserialization & Object Injection — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & cheat sheets

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) - per-language safe-deserialization review methods (PHP/Python/Java/.NET) matching the sink tables.
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) - parser-by-parser hardening flags mirrored in Remediation's XXE table.
- [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html) - merge-boundary defenses behind the T3 structural-key stripping fix.

## Deep dives

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) - the base weakness, with pickle and readObject exemplars for T1 reporting language.
- [CWE-611: XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) - formal file-read/SSRF/DoS consequence framing for XXE findings.
- [CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html) - variant definition plus freeze/null-prototype mitigations cited in the pollution fix.
- [PortSwigger Web Security Academy: Insecure deserialization](https://portswigger.net/web-security/deserialization) - PHP/Java serialization format walkthroughs and magic-method/gadget-chain exploitation context for authorized labs.

## Vendor docs

- [Python pickle documentation](https://docs.python.org/3/library/pickle.html) - official warning that pickle is not secure, plus `find_class` restriction — the authoritative source for the module's Python guidance.
- [Microsoft Learn: BinaryFormatter migration guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/) - vendor record of BinaryFormatter removal in .NET 9, backing "replace regardless of filters" remediation.

(9 URLs total; each returned HTTP 200 with matching content when fetched.)
