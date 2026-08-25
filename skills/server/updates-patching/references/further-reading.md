# Updates & Patch Discipline — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's Remediation section remains the primary fix reference.

## Vendor security & lifecycle portals

- [Ubuntu Security](https://ubuntu.com/security) - Canonical's overview of LTS support patterns, ESM extensions, and the unattended-upgrades mechanism named in the automation checks.
- [Debian Security](https://www.debian.org/security/) - the DSA advisory stream and official unattended-upgrades recommendation backing the Debian-family automation config.
- [Debian Security Bug Tracker](https://security-tracker.debian.org/tracker/) - per-package/per-suite vulnerability status used to corroborate debsecan-style findings against installed sets.
- [Alpine release branches](https://alpinelinux.org/releases/) - the authoritative branch-support table resolving the "which Alpine branch is maintained" needs-review questions.

## Lifecycle reference

- [endoflife.date](https://endoflife.date/) - aggregated, sourced EOL data for hundreds of products (distros, runtimes, server software); useful cross-check when a release string's support status must be verified, never guessed.

## Audit tooling

- [OpenSCAP](https://www.open-scap.org/) - project home for oscap and SCAP Security Guide content behind the optional profile-evaluation scans in SKILL.md §9.
- [Lynis](https://cisofy.com/lynis/) - vendor page for the host-based auditor (`lynis audit system`) framed as read-only corroboration in SKILL.md §9.

## Weakness mapping

- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html) - the mapped base weakness for running EOL software: unmaintained components make fixes impossible, not just delayed.

Nothing here replaces the in-repo evidence rules: cite live command output
(`apt-check`, `dnf updateinfo`, `uname -r` vs installed kernels) per SKILL.md
first; these links corroborate.
