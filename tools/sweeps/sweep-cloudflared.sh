#!/usr/bin/env bash
# sweep-cloudflared.sh — evidence sweep for checks/server/cloudflared-tunnel.md (TNL)
# STRICTLY READ-ONLY and fully OFFLINE: filesystem + systemd introspection only,
# zero network actions anywhere in this sweep. Tunnel tokens are live secrets:
# every unit/config surface prints through redact() — raw tokens never appear.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
export -f redact
HOME="${HOME:-/root}"
init_sweep TNL
rootwarn

hdr 01 "daemon presence"
run bash -c 'out=$(systemctl list-unit-files --no-pager 2>/dev/null | grep -i cloudflared); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no cloudflared unit-files]"'
run bash -c 'out=$(systemctl is-active cloudflared 2>&1); printf "is-active: %s\n" "$out"'
run bash -c 'out=$(ps -o user=,pid=,etime=,cmd= -C cloudflared 2>/dev/null); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no running cloudflared process]"'

hdr 02 "unit file dump + ExecStart/Environment lines (token values REDACTED)"
run bash -c 'shopt -s nullglob; units=(/etc/systemd/system/cloudflared*.service /lib/systemd/system/cloudflared*.service /usr/lib/systemd/system/cloudflared*.service); [ ${#units[@]} -gt 0 ] || { echo "[no cloudflared*.service unit files on disk]"; exit 0; }; for u in "${units[@]}"; do echo "--- $u"; sed -n "1,80p" "$u"; done | redact'
run bash -c 'shopt -s nullglob; units=(/etc/systemd/system/cloudflared*.service /lib/systemd/system/cloudflared*.service /usr/lib/systemd/system/cloudflared*.service); [ ${#units[@]} -gt 0 ] || exit 0; grep -HnE "ExecStart|Environment" "${units[@]}" | redact || echo "[no ExecStart/Environment lines]"'
run bash -c 'out=$(systemctl cat cloudflared 2>/dev/null); [ -n "$out" ] && printf "%s\n" "$out" | redact || echo "[systemctl cat unavailable for cloudflared]"'

hdr 03 "credential material permissions (file CONTENTS are never printed)"
run bash -c '[ -d /etc/cloudflared ] || { echo "[/etc/cloudflared absent]"; exit 0; }; find /etc/cloudflared -maxdepth 1 -exec stat -c "%a %U:%G %n" {} + 2>/dev/null | sort'
run bash -c 'for d in /root/.cloudflared "$HOME/.cloudflared"; do [ -d "$d" ] || { echo "[$d absent or unreadable]"; continue; }; echo "--- $d"; find "$d" -maxdepth 1 -exec stat -c "%a %U:%G %n" {} + 2>/dev/null | sort; done; true'

hdr 04 "config.yml ingress table dump (redacted view)"
run bash -c 'cfg=$(timeout 30 find /etc/cloudflared /root/.cloudflared "$HOME/.cloudflared" -maxdepth 2 \( -name "config.yml" -o -name "config.yaml" \) -type f 2>/dev/null | sort); [ -n "$cfg" ] || { echo "[no cloudflared config.yml found]"; exit 0; }; for f in $cfg; do echo "--- $f"; cat "$f"; done | redact'

hdr 05 "metrics binding check (expect loopback-only; commonly :20241)"
run bash -c 'command -v ss >/dev/null 2>&1 || { echo "[skip: ss not installed]"; exit 0; }; out=$(ss -tlnp 2>/dev/null | grep -E ":2024[0-9][[:space:]]"); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no TCP listener in :20240-:20249 range]"'
run bash -c 'cfg=$(timeout 30 find /etc/cloudflared /root/.cloudflared "$HOME/.cloudflared" -maxdepth 2 -type f -name "config*" 2>/dev/null | sort); [ -n "$cfg" ] || exit 0; grep -HniE "metrics" $cfg | redact || echo "[no metrics key in config file(s)]"'

hdr 06 "origin double-bind cross-check (FULL listener table)"
note "compare each [TNL-04] ingress origin target against this table:"
note "healthy = 127.0.0.1/[::1] binds only; 0.0.0.0/[::]/LAN binds = direct-access bypass (module sec.3)"
grun ss ss -tlnp

hdr 07 "auto-update posture + daemon version"
run bash -c 'shopt -s nullglob; units=(/etc/systemd/system/cloudflared*.service /lib/systemd/system/cloudflared*.service /usr/lib/systemd/system/cloudflared*.service); [ ${#units[@]} -gt 0 ] || { echo "[no unit files to grep]"; exit 0; }; grep -Hnie "update" "${units[@]}" | redact || echo "[no update-related flags in unit files]"'
grun cloudflared cloudflared --version
note "posture verdict = pinned+manual cadence OR package auto-update, recorded deliberately (module sec.7)"

finish_sweep
