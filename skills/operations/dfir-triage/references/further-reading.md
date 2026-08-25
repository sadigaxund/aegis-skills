# DFIR Triage — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's Steps 0-7 and capture starter remain the primary reference.

## Doctrine (why the sequence looks this way)

- [RFC 3227: Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227.html) - the February 2002 Best Current Practice that codified order-of-volatility, things-to-avoid (don't shutdown, don't trust on-host programs), and chain-of-custody documentation behind SKILL.md's golden rules.
- [NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final) - the 2006 guide framing collection/examination/analysis/reporting as distinct steps; the ancestor of this module's responder-log and evidence-bundle discipline.

## Memory acquisition and analysis

- [Volatility Foundation / volatility3](https://github.com/volatilityfoundation/volatility3) - the standard framework for extracting artifacts from RAM samples independent of the investigated system; where Step 2's memory decision leads when a dump exists.
- [LiME — Linux Memory Extractor](https://github.com/jtsylve/LiME) - loadable-kernel-module acquisition supporting `path=tcp:<port>` streaming exactly as used in Step 2.4; README documents its formats, digests, and the Shmoocon 2012 origin. (Canonical repo after the former 504ensicsLabs org moved.)

## Timeline building and indicator context

- [log2timeline/plaso](https://github.com/log2timeline/plaso) - super-timeline engine named in Step 7 as the escalation path when triage-grade merging is insufficient.
- [GTFOBins](https://gtfobins.github.io/) - curated catalog of Unix binaries abusable for shells/privilege escalation; context for judging whether cron/unit payload shapes are plausibly malicious.
- [ss(8) man page](https://man7.org/linux/man-pages/man8/ss.8.html) - normative syntax for the socket-state filters and flags used throughout volatile capture.
- [journalctl(1) man page (Debian)](https://manpages.debian.org/bookworm/systemd/journalctl.1.en.html) - authoritative option reference (`--since`, `-o short-iso`, `--vacuum-*`, boot selection) behind Steps 2-4 journal commands; replaces freedesktop.org's `latest` path, which returned HTTP 418 this session.

Nothing here replaces the in-repo evidence rules: cite captured bundles,
hashes, and responder-log lines per SKILL.md first; these links corroborate
method and syntax.
