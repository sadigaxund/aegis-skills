# Blue-Team Detection Engineering — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's coverage matrix and replay procedures remain the primary reference.

## Standards behind the frontmatter mapping

- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html) - the weakness class this module scores as its own finding; centralized logging and logging of security-relevant successes AND failures are its named mitigations.
- [OWASP Top 10:2021 A09 — Security Logging and Monitoring Failures](https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/) - category definition matching the frontmatter; its prevention list (log failures, alert thresholds, local-only storage as a failure mode) mirrors the matrix rows. Note: the shorter `/Top10/A09_2021-…` path now redirects; use this canonical one.
- [NIST SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) - the September 2006 publication cited in the primer's history; foundational framing of log management as a security process.

## Detection-as-code and shared rule libraries

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) - main Sigma rule repository (3000+ community rules); the detection-as-code standard named in SKILL.md's Alert-quality section, with converters for every major backend.
- [MITRE Cyber Analytics Repository (CAR)](https://car.mitre.org/) - analytics expressed with hypothesis, pseudocode, and UNIT TESTS you can run to trigger them — the closest public analog to this module's purple-team replay checklist discipline.
- [MITRE ATT&CK](https://attack.mitre.org/) - the adversary-behavior knowledge base for mapping what each class's signals are FOR; its detections section (analytics, data components) complements CAR.

## Purple-team collaboration and log hygiene

- [OTRF/ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) - community playbook structuring hunts as plan-execute-report with validation queries against pre-recorded datasets — reusable patterns for building replays R1-R7 style.
- [OWASP Cheat Sheet Series: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) - event-level what-to-log guidance (which decisions deserve events, what fields to include) backing SKILL.md Section 1 inventory work at application level.

Nothing here replaces the in-repo evidence rules: cite emitted events and fired
alerts per SKILL.md first; these links corroborate definitions and supply
portable rule formats.
