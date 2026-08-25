#!/usr/bin/env bash
# sweep-baseline.sh — evidence sweep for skills/server/linux-baseline.md (BASE)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep BASE

hdr 01 "identity"
run id
grun who who
grun last bash -c 'last -a 2>/dev/null | head -15'

hdr 02 "uid0 + empty-password users"
run awk -F: '$3==0{printf "%s uid=0 shell=%s\n",$1,$7}' /etc/passwd
if [ -r /etc/shadow ]; then
  run awk -F: '($2==""){print $1" EMPTY-PASSWORD"}' /etc/shadow
else
  note "[ROOT] /etc/shadow unreadable — empty-password check skipped"
fi

hdr 03 "sudo posture"
if sudo -n true 2>/dev/null; then
  run sudo -l
else
  note "[sudo -n true failed] grant enumeration unavailable as this identity"
fi
[ -r /etc/sudoers ] || note "[ROOT] /etc/sudoers unreadable — config grep partial"
grepr 'NOPASSWD' /etc/sudoers /etc/sudoers.d/*

hdr 04 "sshd effective config"
rootwarn
if command -v sshd >/dev/null 2>&1; then
  run sshd -T
else
  note "[sshd binary not in PATH — file-text fallback only]"
fi
note "file-text fallback (/etc/ssh/sshd_config; drop-ins in sshd_config.d/ may override):"
grepr '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|MaxAuthTries)' /etc/ssh/sshd_config

hdr 05 "sysctl network/kernel keys"
for k in net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.tcp_syncookies kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled; do
  run sysctl -n "$k"
done

hdr 06 "suid/sgid inventory"
note "[COST] full-filesystem traversal, capped at 30s"
run bash -c 'timeout 30 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort'

hdr 07 "world-writable files sample (first 50)"
run bash -c "timeout 30 find / -xdev ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' -perm -0002 -type f 2>/dev/null | head -50"

hdr 08 "cron/at access-control files"
for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
  if [ -e "$f" ]; then run stat -c '%a %U:%G %n' "$f"; else note "$f absent"; fi
done

hdr 09 "core dump settings"
grepr '^\s*#?\s*Storage' /etc/systemd/coredump.conf
run bash -c 'ulimit -c'

hdr 10 "time sync state"
rootwarn
grun timedatectl timedatectl status

finish_sweep
