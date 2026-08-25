#!/usr/bin/env bash
# sweep-firewall.sh — evidence sweep for skills/server/firewall-edge/SKILL.md (FW)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep FW

hdr 01 "listener map"
rootwarn
[ "$(id -u)" = 0 ] || note "[ROOT] -p process attribution requires privileges"
grun ss ss -tlnp
grun ss ss -ulnp

hdr 02 "firewall backend detection + ruleset dumps"
rootwarn
for s in nftables ufw firewalld iptables netfilter-persistent; do
  run systemctl is-active "$s"
done
grun nft nft list ruleset
grun iptables-save iptables-save
grun ufw ufw status verbose
grun firewall-cmd firewall-cmd --list-all

hdr 03 "default policy hint lines"
if command -v nft >/dev/null 2>&1; then
  run bash -c "nft list ruleset 2>/dev/null | grep -iE 'policy (accept|drop)'"
fi
if command -v iptables >/dev/null 2>&1; then
  run bash -c "iptables -S 2>/dev/null | grep '^-P'"
fi
if command -v iptables-save >/dev/null 2>&1; then
  run bash -c "iptables-save 2>/dev/null | grep -iE '^:[A-Za-z-]+ (ACCEPT|DROP)'"
fi
if command -v ufw >/dev/null 2>&1; then
  run bash -c "ufw status verbose 2>/dev/null | grep -iE 'Status|Default'"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  run bash -c "firewall-cmd --list-all 2>/dev/null | grep -iE 'target|policy'"
fi

hdr 04 "ipv6 parity quick check"
grun ss ss -6 -tlnp
if command -v nft >/dev/null 2>&1; then
  run bash -c "nft list tables 2>/dev/null | grep -E 'table (inet|ip6)' || echo '[no inet/ip6 nft table -> IPv6 likely unfiltered]'"
fi
if command -v ip6tables >/dev/null 2>&1; then
  run bash -c "ip6tables -S 2>/dev/null | grep '^-P'"
fi

hdr 05 "fail2ban state"
run systemctl is-active fail2ban
rootwarn
grun fail2ban-client fail2ban-client status

hdr 06 "docker presence + published-port bypass indicators"
[ -S /var/run/docker.sock ] && note "docker socket present: /var/run/docker.sock"
if command -v docker >/dev/null 2>&1; then
  [ "$(id -u)" = 0 ] || note "[ROOT] docker ps may fail unprivileged"
  run docker ps --format 'table {{.Names}}\t{{.Ports}}'
else
  note "[skip: docker not installed]"
fi
if command -v iptables >/dev/null 2>&1; then
  run bash -c "iptables -S DOCKER-USER 2>/dev/null | head -10"
fi
if command -v nft >/dev/null 2>&1; then
  run bash -c "nft list ruleset 2>/dev/null | grep -i docker-user | head -10"
fi

hdr 07 "cloud-metadata reachability marker"
note "[INFO] canonical cloud-metadata endpoint: 169.254.169.254 — NOT probed by this read-only sweep"

finish_sweep
