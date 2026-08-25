#!/usr/bin/env bash
# sweep-db.sh — evidence sweep for checks/server/db-server-hardening.md (DB)
# STRICTLY READ-ONLY. Sole network action in this entire sweep: the DB-RD
# localhost redis PING / ACL LIST attempt. Everything else is offline files.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep DB

hdr 00 "engine/port detection"
PG=0 MY=0 RD=0 MG=0
grun ss bash -c "ss -tlnp 2>/dev/null | grep -E ':(5432|3306|6379|27017)[[:space:]]' || echo '[no db listeners]'"
listen=""
command -v ss >/dev/null 2>&1 && listen=$(ss -tln 2>/dev/null)
echo "$listen" | grep -q ':5432' && PG=1
echo "$listen" | grep -q ':3306' && MY=1
echo "$listen" | grep -q ':6379' && RD=1
echo "$listen" | grep -q ':27017' && MG=1
command -v psql >/dev/null 2>&1 && PG=1
command -v mysql >/dev/null 2>&1 && MY=1
command -v redis-cli >/dev/null 2>&1 && RD=1
command -v mongosh >/dev/null 2>&1 || command -v mongo >/dev/null 2>&1 && MG=1
printf '[detected] pg=%s mysql=%s redis=%s mongo=%s\n' "$PG" "$MY" "$RD" "$MG"

if [ "$PG" = 1 ]; then
  hdr PG "postgresql conf keys + pg_hba method column"
  run bash -c 'confs=$(timeout 30 find /etc/postgresql -name postgresql.conf 2>/dev/null | sort | head -3); [ -n "$confs" ] || echo "[NOTE] postgresql.conf not under /etc/postgresql (custom data dir?)"; for f in $confs; do echo "--- $f"; grep -nE "^[[:space:]]*(listen_addresses|ssl|ssl_min_protocol_version|password_encryption)[[:space:]]*=" "$f" || echo "[keys commented-out or absent -> package defaults apply]"; done'
  run bash -c 'hbas=$(timeout 30 find /etc/postgresql -name pg_hba.conf 2>/dev/null | sort | head -3); [ -n "$hbas" ] || echo "[NOTE] pg_hba.conf not located"; for f in $hbas; do echo "--- $f"; echo "-- active rows:"; grep -nvE "^[[:space:]]*#|^[[:space:]]*$" "$f" | head -25; echo "-- trust/md5 rows:"; grep -nE "\b(trust|md5)\b" "$f" || echo "[none]"; done'
fi

if [ "$MY" = 1 ]; then
  hdr MY "mysql/mariadb cnf security keys"
  run bash -c "timeout 30 grep -RInsE '^[[:space:]]*(bind[-_]address|skip[-_]networking|require_secure_transport|validate_password)[[:space:]]*=' /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null | head -20; true"
  note "anonymous-user/test-db enumeration needs SQL login — [NOTE requires-auth]"
fi

if [ "$RD" = 1 ]; then
  hdr RD "redis conf (requirepass masked) + localhost probe (sole network exception)"
  run bash -c 'rcs=$(timeout 30 find /etc/redis /etc/redis.conf -maxdepth 2 -name "*.conf" 2>/dev/null | sort | head -3); [ -n "$rcs" ] || echo "[NOTE] redis.conf not located"; for f in $rcs; do echo "--- $f"; grep -nE "^(bind|protected-mode|port|aclfile)" "$f"; grep -nE "^requirepass" "$f" | sed -E "s/^(requirepass[[:space:]]+).*$/\1[REDACTED]/"; done'
  run bash -c 'redis-cli --no-auth-warning -h 127.0.0.1 ping 2>&1 | head -2'
  note "ACL LIST attempt, auth-less (NOAUTH error = auth enforced); values redacted:"
  run bash -c 'redis-cli --no-auth-warning -h 127.0.0.1 acl list 2>&1 | head -10 | redact'
fi

if [ "$MG" = 1 ]; then
  hdr MG "mongodb conf bindIp / authorization"
  run bash -c 'mcs=$(timeout 30 find /etc -maxdepth 3 \( -name "mongod.conf" -o -name "mongodb.conf" \) 2>/dev/null | sort | head -3); [ -n "$mcs" ] || echo "[NOTE] mongod/mongodb conf not under /etc"; for f in $mcs; do echo "--- $f"; grep -nE "(^[[:space:]]*bindIp|^[[:space:]]*security:|^[[:space:]]*authorization)" "$f" || echo "[keys absent -> authorization off by default]"; done'
fi

hdr 99 "app-side connection-string files on host (filenames only, no content)"
run bash -c "timeout 30 find /opt /srv /home -xdev -maxdepth 5 -type f -exec grep -IlE 'postgres(ql)?://|mysql://|redis://' {} + 2>/dev/null | sort | head -30"

finish_sweep
