# Supply Chain — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's scanner matrix remains the primary tooling reference.

## Standards & cheat sheets

- [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) - cross-ecosystem hardening guidance matching the module's three-layer mental model.
- [OWASP GitHub Actions Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html) - dangerous triggers, SHA pinning, and secret-handling rules backing the CI/CD checks.
- [SLSA](https://slsa.dev/) - the provenance-level vocabulary (build integrity, attestations) used in the build-integrity gap findings.
- [CycloneDX](https://cyclonedx.org/) - the SBOM standard named by the SBOM-generation remediation; format reference for inventory findings.
- [OSV](https://osv.dev/) - open vulnerability database behind osv-scanner; query model for the network-gated scanner sweep.

## Deep dives

- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) - formal definition of the EOL/unmaintained finding class.
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) - root weakness for unpinned installs, curl-bash, and unsigned artifacts.

## Vendor docs

- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) - platform-owner guidance on `pull_request_target`, script injection, third-party action pinning, and self-hosted runner risk.

Offline discipline still applies: conclusions from these references supplement,
never replace, the manifest-level evidence SKILL.md requires per finding.
