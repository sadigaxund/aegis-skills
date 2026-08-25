#!/usr/bin/env bash
# sweep-sandbox.sh — evidence sweep for skills/server/service-sandboxing.md (SBX)
# STRICTLY READ-ONLY: observes processes/units/containers; no docker mutations,
# no MAC changes, no cron edits. Daemon-denied paths degrade to [cmd-failed]/notes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep SBX

hdr 01 "root-run processes"
run bash -c "ps -eo user,pid,comm --no-headers 2>/dev/null | awk '\$1==\"root\"' | head -40"

hdr 02 "enabled third-party unit files (sample)"
grun systemctl bash -c "systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | grep -vE '^(systemd|snap|getty|dbus|cron|rsyslog|ssh|udev)' | head -30"

hdr 03 "systemd-analyze security exposure scores (up to 15 app-ish units)"
if command -v systemd-analyze >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
  run bash -c 'systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | awk "{print \$1}" | grep -E "\.service$" | grep -vE "^(systemd-|getty|dbus|cron|rsyslog|ssh|udev|snap)" | head -15 | while read -r u; do printf -- "--- %s\n" "$u"; systemd-analyze security "$u" 2>/dev/null | grep -iE "overall exposure"; done'
else
  note "[skip: systemd-analyze/systemctl unavailable]"
fi

hdr 04 "docker presence + runtime risk posture"
if command -v docker >/dev/null 2>&1; then
  run bash -c "docker info 2>/dev/null | grep -iE 'rootless|server version|cgroup' | head -8 || echo '[docker info denied]'"
  run bash -c "docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | head -20 || true"
  note "[ROOT/docker-group] inspect below is blank when daemon access is denied"
  run bash -c 'docker ps -q 2>/dev/null | head -20 | while read -r c; do docker inspect "$c" --format "{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} binds={{.HostConfig.Binds}}" 2>/dev/null; done | head -30'
else
  note "[skip: docker not installed]"
fi

hdr 05 "docker.sock exposure hunt"
run bash -c 'timeout 30 find / -xdev -name docker.sock -ls 2>/dev/null | head -10'
note "socket bind-mounted into namespaces (procfs; readable pids only):"
run bash -c "grep -H docker.sock /proc/[0-9]*/mountinfo 2>/dev/null | cut -c1-180 | head -10"

hdr 06 "MAC state: SELinux / AppArmor"
grun getenforce getenforce
run bash -c '[ -r /sys/fs/selinux/enforce ] && { printf "selinux-enforce="; cat /sys/fs/selinux/enforce; } || echo "[no selinuxfs]"'
rootwarn
grun aa-status bash -c 'aa-status 2>/dev/null | head -12'
run bash -c '[ -d /sys/kernel/security/apparmor ] && echo "[apparmor securityfs present]" || echo "[no apparmor securityfs]"'

hdr 07 "cron entries writable by group/other (non-root edit chain)"
run bash -c 'for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] || continue; m=$(stat -c "%04a" "$f"); case "$m" in ??[2367]?|???[2367]) echo "WRITABLE-NONROOT $m $f";; *) echo "ok $m $f";; esac; done | head -30'

finish_sweep
