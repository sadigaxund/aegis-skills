# Backup & Disaster Recovery — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding plane needs authoritative backing;
SKILL.md's worksheets and remediation skeletons remain the primary reference.

## Encrypted capture tools

- [restic](https://restic.net/) - upstream confirmation that cryptography is applied "in every part of the process" (client-side encryption by default) plus restore-verifiability claims behind the tool-identity posture checks.
- [BorgBackup](https://www.borgbackup.org/) - authenticated-encryption model ("your backup server never needs to be trusted — it only ever sees ciphertext") backing the repokey/escrow discussion.
- [age (GitHub)](https://github.com/FiloSottile/age) - small-explicit-keys wrap-before-upload tool named in encryption starters; SSH-recipient convenience documented.

## Key material & WORM destinations

- [GnuPG documentation](https://gnupg.org/documentation/) - manuals and guides for gpg-wrapped archives where sites already run PGP-based pipelines.
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) - governance vs compliance retention modes ("retention period can't be shortened" in compliance mode) and legal holds behind immutability-tier validation drills.

## Logical dumps

- [pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html) - consistent-concurrent-export semantics, custom/directory formats, and version-compatibility limits (dumps load forward, not backward) cited in capture-safety and regression notes.

Note on gaps: CISA's "Data Backup Options" page was attempted but returned 503
this session, so no government-guidance link is included — the 3-2-1-1-0
lineage stays qualitative per SKILL.md References; consult guidance sources
directly when citing them in reports.
