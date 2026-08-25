#!/usr/bin/env bash
# sweep-backups.sh — evidence sweep for skills/server/backup-dr.md (DRB)
# STRICTLY READ-ONLY, fully OFFLINE. Observes jobs/scripts/archives only —
# never runs, triggers, dry-runs, restores or mutates any backup mechanism.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
export -f redact
init_sweep DRB
rootwarn

hdr 01 "scheduled-job inventory: timers, crontabs, cron dirs"
run bash -c 'out=$(systemctl list-timers --all --no-pager 2>/dev/null | grep -iE "backup|restic|borg|snap|rman"); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no backup-flavored systemd timers]"'
run bash -c 'u=$(id -un 2>/dev/null || echo unknown); out=$(crontab -l 2>/dev/null | grep -inE "backup|dump|restic|borg|rsync|sync|rman"); [ -n "$out" ] && { echo "crontab($u):"; printf "%s\n" "$out"; } || echo "[crontab($u): no backup lines / unreadable]"'
run bash -c 'spool=""; for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && [ -r "$f" ] && spool="$spool $f"; done; [ -n "$spool" ] || { echo "[no readable per-user cron spools visible]"; exit 0; }; for f in $spool; do echo "--- $f"; grep -inE "backup|dump|restic|borg|rsync|sync" "$f" || echo "  [no backup lines]"; done; true'
run bash -c 'ls -la /etc/cron.d /etc/cron.daily 2>/dev/null; out=$(timeout 30 grep -RinsHE "backup|dump|restic|borg|rsync" /etc/crontab /etc/cron.d 2>/dev/null | redact); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no backup references in /etc/crontab or /etc/cron.d]"; true'

hdr 02 "backup-script hunt by filename"
DRB_SCRIPTS="$(timeout 30 find /usr/local/sbin /usr/local/bin /opt /root -maxdepth 3 -type f \( -iname "*backup*" -o -iname "*dump*" -o -iname "*restic*" -o -iname "*borg*" \) 2>/dev/null | sort)"
[ -n "$DRB_SCRIPTS" ] && printf '%s\n' "$DRB_SCRIPTS" || echo "[no backup/dump/restic/borg-named files under /usr/local/{sbin,bin} /opt /root (depth 3)]"

hdr 03 "destination hints inside found scripts (redacted)"
[ -n "$DRB_SCRIPTS" ] && grepr "rsync|restic|borg|s3|rclone|scp|gsutil|aws s3" $DRB_SCRIPTS || echo "[no scripts to inspect for destinations]"

hdr 04 "encryption markers -> encrypted-by-tool inference"
ENC=""
PLAIN=""
for s in $DRB_SCRIPTS; do
  [ -r "$s" ] || continue
  if grep -qiE "\bage\b|gpg|openssl enc|restic|borg" "$s" 2>/dev/null; then ENC="$ENC $s"; fi
  if ! grep -qiE "\bage\b|gpg|openssl enc|restic|borg" "$s" 2>/dev/null \
     && grep -qE "(^|[[:space:]])tar([[:space:]]|$)|gzip|\.t?gz([.[:space:]]|$)" "$s" 2>/dev/null; then PLAIN="$PLAIN $s"
  fi
done
printf '[encrypted-by-tool candidates]:'
for s in $ENC; do printf ' %s' "$s"; done
echo
printf '[likely-UNENCRYPTED (plain tar/gzip only)]:'
for s in $PLAIN; do printf ' %s' "$s"; done
echo
[ -z "$ENC" ] && [ -z "$PLAIN" ] && note "no tool/archive markers in hunted scripts — coverage question for module sec.1"

hdr 05 "checksum-manifest practice in scripts"
[ -n "$DRB_SCRIPTS" ] && grepr "sha256|sha1sum|md5sum|checksum" $DRB_SCRIPTS || echo "[no scripts / no manifest-practice markers found]"

hdr 06 "failure-alerting hooks in scripts"
[ -n "$DRB_SCRIPTS" ] && grepr "MAILTO|[Mm]ail( | -)|[Nn]otify|[Ll]ogger|curl .*(hook|alert)" $DRB_SCRIPTS || echo "[no scripts / no failure-alert hooks found]"

hdr 07 "restore/recovery documentation existence (filenames only)"
run bash -c 'hits=$(timeout 30 grep -rliE "restore|recovery|RTO|RPO" /opt/docs /srv/docs 2>/dev/null; timeout 30 find /root -maxdepth 4 -type f \( -iname "*.md" -o -iname "*.txt" -o -iname "README*" -o -iname "*runbook*" -o -iname "*restore*" \) -exec grep -liE "restore|recovery" {} + 2>/dev/null); hits=$(printf "%s\n" "$hits" | sort -u | sed "/^$/d"); [ -n "$hits" ] && printf "%s\n" "$hits" || echo "[no restore/recovery docs in /opt/docs /srv/docs /root (maxdepth 4)]"'

hdr 08 "local backup-artifact locations (sample + sizes)"
run bash -c 'dirs=""; for d in /var/backups /opt/backups /srv/backups* /mnt/*backup*; do [ -d "$d" ] && dirs="$dirs $d"; done; [ -n "$dirs" ] || { echo "[no local artifact dirs among /var/backups /opt/backups /srv/backups* /mnt/*backup*]"; exit 0; }; ls -ldt $dirs | head -10; echo "-- sizes:"; for d in $dirs; do du -sh "$d" 2>/dev/null; done | head -5'

finish_sweep
