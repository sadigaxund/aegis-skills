#!/usr/bin/env bash
# sweep-secrets-host.sh — evidence sweep for checks/server/host-secrets.md (HSEC)
# STRICTLY READ-ONLY. Every secret-bearing surface pipes through redact;
# file CONTENTS of credential stores are never dumped — metadata/perms only.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep HSEC

hdr 01 "env/config secret-file hunt (names+perms only, never contents)"
rootwarn
note "[COST] capped at 30s"
run bash -c 'timeout 30 find /etc /opt /srv /home -xdev -maxdepth 6 -type f \( -name ".env" -o -name "*.env" -o -name "*credential*" -o -name "*secret*" \) -printf "%m %u:%g %p\n" 2>/dev/null | sort | redact | head -60'

hdr 02 "world-readable key material (/etc/ssh,/etc/ssl/private,/etc/nginx + homes)"
run bash -c 'timeout 30 find /etc/ssh /etc/ssl/private /etc/nginx -xdev -type f -perm -0004 -printf "%m %u:%g %p\n" 2>/dev/null | sort | head -40'
note "private-key-style files in home dirs:"
run bash -c 'timeout 30 find /root /home -xdev -maxdepth 5 -type f \( -name "id_rsa*" -o -name "id_ecdsa*" -o -name "id_ed25519*" -o -name "id_dsa*" -o -name "*.pem" -o -name "*.key" \) -printf "%m %u:%g %p\n" 2>/dev/null | sort | redact | head -40'

hdr 03 "systemd unit Environment= lines (values redacted)"
run bash -c "grep -RInsE '^[[:space:]]*Environment=' /etc/systemd/system 2>/dev/null | redact | head -50"

hdr 04 "shell history credential leakage (matched lines redacted)"
for h in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history; do
  [ -e "$h" ] || continue
  if [ -r "$h" ]; then
    run bash -c "grep -aE '(-p[P ]|PASSWORD|TOKEN|SECRET)' '$h' 2>/dev/null | redact | head -8"
  else
    note "[ROOT] $h unreadable — skipped"
  fi
done

hdr 05 "db client cred files (.pgpass/.my.cnf) perms + cnf password lines (redacted)"
run bash -c 'stat -c "%a %U:%G %n" ~/.pgpass /root/.pgpass /root/.my.cnf /etc/mysql/my.cnf 2>/dev/null || true'
run bash -c 'ls -1 /etc/mysql/*.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | xargs -r stat -c "%a %U:%G %n"'
note "[.pgpass/.my.cnf contents never dumped — permission metadata only]"
run bash -c "timeout 30 grep -RInsE '(^|[[:space:]])pass(word)?[[:space:]]*=' /etc/mysql 2>/dev/null | redact | head -20"

hdr 06 "per-home .ssh inventory (home-dir mode + key/authorized_keys modes)"
run bash -c 'for d in /root /home/*; do [ -d "$d/.ssh" ] || continue; printf "%s home-mode=%s\n" "$d" "$(stat -c %a "$d")"; stat -c "%a %U:%G %n" "$d/.ssh" "$d/.ssh"/authorized_keys "$d/.ssh"/id_* 2>/dev/null; done'

hdr 07 "backup-script embedded-credential hints (matched lines redacted)"
run bash -c "timeout 30 grep -RIniE 'pass(w(or)?d)?[= ]' /usr/local/sbin /usr/local/bin /opt 2>/dev/null | head -40 | redact"

finish_sweep
