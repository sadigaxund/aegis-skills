# Vulnerability Management Process — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's decision tree and SLA tables remain the primary reference.

## Prioritization inputs (Stage 3)

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - the authoritative known-exploited list behind the Q1 queue-jump; CISA explicitly frames it as an input to vulnerability-management prioritization frameworks like this module's.
- [FIRST EPSS](https://www.first.org/epss/) - daily 0-1 exploitation-probability scores backing the Q4 tie-break; includes usage guidance on combining EPSS with CVSS and KEV, and publishes CSV/API data for automation.

## Severity vocabulary (what triage must not re-litigate)

- [FIRST CVSS](https://www.first.org/cvss/) - the scoring system whose base-severity vocabulary finding reports carry; current version v4.0 with consumer implementation guide.
- [NIST National Vulnerability Database](https://nvd.nist.gov/) - U.S. government repository of standards-based vulnerability management data; where advisory lookups resolve identifiers and metrics.
- [CVE Program](https://www.cve.org/) - the identifier system that makes deduplication and cross-referencing possible at all; background for why findings cite stable IDs.

## Process and patch doctrine

- [NIST SP 800-40 Rev. 4, Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/pubs/sp/800/40/r4/final) - frames patching as preventive maintenance with an identify-prioritize-install-verify cycle mapping onto Stages 3-5 of the loop (April 2022).
- [CIS Critical Security Controls](https://www.cisecurity.org/controls) - prioritized best-practice framework descending from the 2008 consensus controls named in the primer's history; useful when justifying cadence and hygiene investments to leadership.

## Tooling graduation (only past ~50 open findings)

- [DefectDojo / django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) - open-source vulnerability management platform (dedup, remediation tracking, reporting); the concrete "DefectDojo-class tool" SKILL.md's tracker section names as the graduation path.

Nothing here replaces the in-repo honesty rules: severity stays rubric-final,
priority decisions get TRIAGE RECORDS, and "not consulted" is always an
acceptable entry per SKILL.md first; these links supply data and doctrine.
