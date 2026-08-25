# Database Server Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding engine needs authoritative backing;
SKILL.md's judgement tables and hardened blocks remain the primary reference.

## PostgreSQL

- [The pg_hba.conf File](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html) - first-match-wins stated normatively, per-method verdicts (trust/reject/scram/md5/password/peer/cert), and upstream's own md5-deprecation warning backing the migration ladder.
- [Connections and Authentication (GUCs)](https://www.postgresql.org/docs/current/runtime-config-connection.html) - listen_addresses default localhost, ssl off-by-default, ssl_min_protocol_version TLSv1.2, password_encryption scram default and non-retroactivity notes.
- [The Password File (.pgpass)](https://www.postgresql.org/docs/current/libpq-pgpass.html) - the 0600-or-ignored rule behind the client-side credential-file check and its silent-auth-fallback trap.

## Redis

- [Redis ACLs](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/) - the exact `user default on nopass ~* &* +@all` vulnerable signature, category model (@dangerous vs @scripting), hashed-password storage, and external aclfile semantics behind the ACL-first recommendation.

## MongoDB

- [Enable Access Control](https://www.mongodb.com/docs/manual/tutorial/enable-authentication/) - authorization: enabled setup path including the first-user/localhost flow that Check on localhost-exception posture references.
- [SCRAM Authentication](https://www.mongodb.com/docs/manual/core/security-scram/) - SCRAM-SHA-1 vs SCRAM-SHA-256 mechanisms, server-side digesting requirement for SHA-256, and driver-support floor cited in the mechanism-posture table.

Note on gaps: MySQL documentation (dev.mysql.com) and the OpenSearch security
manual were attempted but could not be fetched this session (403 bot-blocking
and JS-only redirect stubs respectively), so no links to them are included —
consult vendor manuals directly when auditing those engines; SKILL.md's tables
carry the operative values.
