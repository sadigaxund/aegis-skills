#!/usr/bin/env bash
# sweep-patching.sh — evidence sweep for skills/server/updates-patching.md (PATCH)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep PATCH

hdr 01 "os-release"
run cat /etc/os-release

hdr 02 "kernel-vs-installed"
run uname -r
note "running kernel above; newest installed below — divergence = reboot debt"
if command -v dpkg-query >/dev/null 2>&1; then
  run bash -c "dpkg -l 'linux-image-[0-9]*' 2>/dev/null | awk '/^ii/{print \$2, \$3}' | sort -V | tail -n 5"
elif command -v rpm >/dev/null 2>&1; then
  run bash -c "rpm -q kernel 2>/dev/null | sort -V | tail -n 5"
else
  note "[skip: neither dpkg nor rpm detected]"
fi

hdr 03 "pending updates count (best-effort)"
note "counts may be stale — no package-index refresh is performed (read-only sweep)"
if command -v apt >/dev/null 2>&1; then
  run bash -c "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l"
fi
if command -v dnf >/dev/null 2>&1; then
  note "[dnf check-update exits 100 when updates exist — expected, not an error]"
  run bash -c "dnf -q check-update 2>/dev/null | grep -cE '\.(el|fc)[0-9]+' ; true"
fi

hdr 04 "unattended-upgrade config presence"
note "missing file below => mechanism absent"
grepr 'Update-Package-Lists|Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades
grepr 'apply_updates|upgrade_type' /etc/dnf/automatic.conf

hdr 05 "relevant timers"
run bash -c "systemctl list-timers --all --no-pager 2>/dev/null | grep -iE 'apt|dnf|yum|unattended' || echo '[no matching timers]'"

hdr 06 "uptime / reboot debt"
run uptime -s
run uptime

hdr 07 "classic offender services state"
for svc in rpcbind nfs-server avahi-daemon cups postfix telnet.socket tftpd-hpa vsftpd smb nftables; do
  run systemctl is-active "$svc"
  run systemctl is-enabled "$svc"
done

finish_sweep
