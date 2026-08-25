#!/usr/bin/env bash
# sweep-logging.sh — evidence sweep for skills/server/logging-monitoring/SKILL.md (LOGMON)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep LOGMON

hdr 01 "journald persistence"
grepr '^\s*#?\s*Storage' /etc/systemd/journald.conf
run bash -c 'ls -ld /var/log/journal 2>/dev/null || echo "[MISSING /var/log/journal -> volatile journal likely]"'

hdr 02 "rsyslog present + auth log target"
run systemctl is-active rsyslog
run ls -l /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages

hdr 03 "remote shipping markers"
grepr '(@@|@)[[:alnum:].:_-]+' /etc/rsyslog.conf /etc/rsyslog.d/*

hdr 04 "auditd status"
run systemctl is-active auditd
rootwarn
grun auditctl auditctl -s

hdr 05 "audit rules presence"
rootwarn
grun auditctl auditctl -l
run bash -c 'wc -l /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null || echo "[no audit rules files]"'

hdr 06 "integrity monitoring"
run bash -c 'command -v aide || command -v aide.wrapper || echo "[aide not installed]"'
run bash -c 'command -v osqueryd || echo "[osqueryd not installed]"'
run bash -c "systemctl list-timers --all --no-pager 2>/dev/null | grep -iE 'aide|osquery' || echo '[no fim timers]'"

hdr 07 "log dir headroom"
run df -h /var/log
run df -i /var/log

hdr 08 "auth log perms spot check"
run bash -c 'stat -c "%a %U:%G %n" /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null'

hdr 09 "logrotate coverage for key files"
run bash -c 'ls /etc/logrotate.d/ 2>/dev/null | grep -iE "rsyslog|syslog|auth" || echo "[no matching logrotate entries]"'

finish_sweep
