# Incident Response — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's fill-in templates and playbooks remain the primary reference.

## Lifecycle doctrine (NIST)

- [NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final) - the four-phase lifecycle SKILL.md expands into six phases; note the CSRC page records it as withdrawn April 2025 and superseded by Rev. 3 — cite it for phase vocabulary, not current guidance.
- [NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final) - the current revision (April 2025), restating IR as a CSF 2.0 community profile; use when mapping readiness findings to framework functions.
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - the Respond/Recover function mapping stated in this module's frontmatter; CSF 2.0 profiles are the bridge between SEV decisions and governance language.

## Government readiness resources (CISA)

- [CISA Resources & Tools](https://www.cisa.gov/resources-tools) - stable root for free incident-response assets, including CISA Tabletop Exercise Packages that extend SKILL.md's facilitation kit with ready-made scenarios and injects.
- [CISA StopRansomware](https://www.cisa.gov/stopransomware) - one-stop ransomware resource backing scenario playbooks' containment-before-recovery ordering and reporting paths.

## Team and service frameworks (FIRST)

- [FIRST CSIRT Services Framework v2.1](https://www.first.org/standards/frameworks/csirts/) - structured service catalog (event management, incident management, evidence analysis) useful for naming what a small team's IR capability should include when auditing Half A.

Dropped this session: SANS "Incident Handler's Handbook"
(`sans.org/white-papers/incident-handlers-handbook/`) returned HTTP 404 and is
omitted despite appearing in ../SKILL.md's References.

Nothing here replaces the in-repo artifact rules: capability is verified by
drill records and dated templates per SKILL.md first; these links corroborate
doctrine.
