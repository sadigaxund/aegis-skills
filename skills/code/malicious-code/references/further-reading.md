# Deliberate Malice Detection — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's fences and sweep block remain the primary tools.

## Formal definitions

- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html) - the umbrella weakness (trapdoor, timebomb, logic-bomb family) behind every verdict class in this module; also records the Trojan-horse terminology history cited in background.md.
- [CWE-507: Trojan Horse](https://cwe.mitre.org/data/definitions/507.html) - base-level child defining benign-appearance-plus-hidden-behavior, i.e. the concealment leg of the Mental Model triangle.
- [OWASP Top 10 2021 A08: Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) - the category named in SKILL.md front-matter; URL resolves into the 2021 Top-10 document.

## Cheat sheets & integrity frameworks

- [OWASP Cheat Sheet Series: Third Party Javascript Management](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html) - third-party-script risk management backing the dependency-hunting checks.
- [SLSA](https://slsa.dev/) - build-integrity level vocabulary referenced by the provenance-attestation prevention item.
- [in-toto](https://in-toto.io/) - attestation framework covering "what steps ran between source and artifact"; formal basis for provenance findings.
- [Sigstore documentation](https://docs.sigstore.dev/) - keyless signing and transparency-log concepts behind release-artifact verification guidance.

## Ecosystem mechanics (install/build-time surfaces)

- [npm scripts documentation](https://docs.npmjs.com/cli/v11/using-npm/scripts) - authoritative lifecycle-hook execution order (`preinstall`/`install`/`postinstall`/`prepare`) audited by fence F19a.
- [Cargo Book: Build Scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html) - defines `build.rs` compile-time execution and `OUT_DIR` rules audited by fence F19c.

## Vetting & concealment foundations

- [OpenSSF Scorecard](https://github.com/ossf/scorecard) - the maintainer/provenance risk signals named in SKILL.md's new-dependency vetting gate.
- [UTS #39: Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/) - confusable/homoglyph detection theory behind fence F07's Cyrillic/Greek identifier scans.

Offline discipline still applies: conclusions from these references supplement,
never replace, the file:line evidence chains SKILL.md requires per finding.
