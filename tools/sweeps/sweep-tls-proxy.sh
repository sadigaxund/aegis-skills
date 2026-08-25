#!/usr/bin/env bash
# sweep-tls-proxy.sh — evidence sweep for skills/server/tls-proxy.md (TLS)
# STRICTLY READ-ONLY.
# NETWORK SCOPE NOTE — the ONLY network actions in this sweep are LOOPBACK-ONLY:
#   [TLS-06] openssl s_client probes to 127.0.0.1 on locally-listening 443/8443
#   [TLS-07] one curl -k HEAD request against https://127.0.0.1/
# No other section contacts the network; everything else is offline inspection.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
export -f redact
init_sweep TLS
rootwarn

NG=0; CA=0; HA=0; AP=0

hdr 01 "proxy detection: :80/:443 listener ownership + binaries"
run bash -c 'command -v ss >/dev/null 2>&1 || { echo "[skip: ss not installed]"; exit 0; }; out=$(ss -tlnp 2>/dev/null | grep -E ":(80|443)[[:space:]]"); [ -n "$out" ] && printf "%s\n" "$out" || echo "[nothing listening on :80/:443]"'
for b in nginx caddy haproxy apache2 httpd; do
  if command -v "$b" >/dev/null 2>&1; then
    printf '[detected] %-8s %s\n' "$b" "$(command -v "$b")"
    case "$b" in nginx) NG=1 ;; caddy) CA=1 ;; haproxy) HA=1 ;; apache2|httpd) AP=1 ;; esac
  fi
done
[ $((NG + CA + HA + AP)) -eq 0 ] && note "no proxy binary found in PATH — TLS may terminate elsewhere (CDN/LB)"

hdr 02 "nginx effective config ([ROOT]) + static fallback greps"
if [ "$NG" -eq 1 ]; then
  note "[ROOT] nginx -T dumps the effective config; partial/absent when unprivileged"
  grun nginx nginx -T
fi
run bash -c 'out=$(timeout 30 grep -RInsE "^[[:space:]]*(ssl_protocols|ssl_ciphers|server_tokens|add_header)" /etc/nginx 2>/dev/null | head -60); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no ssl_protocols/ssl_ciphers/server_tokens/add_header directives under /etc/nginx]"'

hdr 03 "secondary proxy key directives (only for detected binaries)"
[ "$CA" -eq 1 ] && run bash -c 'f=/etc/caddy/Caddyfile; [ -f "$f" ] || { echo "[no /etc/caddy/Caddyfile]"; exit 0; }; grep -nE "(^|[[:space:]])tls |auto_https|^\{|email|reverse_proxy" "$f" | head -40 || echo "[no key lines matched in Caddyfile]"'
[ "$HA" -eq 1 ] && run bash -c 'f=/etc/haproxy/haproxy.cfg; [ -f "$f" ] || { echo "[no /etc/haproxy/haproxy.cfg]"; exit 0; }; grep -nE "^[[:space:]]*(bind .*ssl|ssl-default-bind|ssl-default-server)" "$f" | head -40 || echo "[no bind/ssl-default lines matched]"'
[ "$AP" -eq 1 ] && run bash -c 'd=""; [ -d /etc/apache2 ] && d=/etc/apache2; [ -d /etc/httpd ] && d=/etc/httpd; [ -n "$d" ] || { echo "[no apache config dir]"; exit 0; }; out=$(timeout 30 grep -RInsE "^[[:space:]]*(SSLProtocol|SSLCipherSuite|SSLHonorCipherOrder|<VirtualHost|ServerName)" "$d" 2>/dev/null | head -40); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no SSL directives found under $d]"'

hdr 04 "local cert/key inventory (private-key material must be mode 600)"
run bash -c 'roots=""; for r in /etc/letsencrypt/live /etc/ssl/private /etc/nginx/ssl; do [ -d "$r" ] && roots="$roots $r"; done; [ -n "$roots" ] || { echo "[none of /etc/letsencrypt/live /etc/ssl/private /etc/nginx/ssl exist]"; exit 0; }; echo "-- scanning:$roots"; out=$(timeout 30 find $roots \( -name "*.pem" -o -name "*.crt" -o -name "*.key" \) -printf "%m %p\n" 2>/dev/null | sort); [ -n "$out" ] && printf "%s\n" "$out" | awk "{print} (\$1 != \"600\" && \$2 ~ /(key|privkey)/) {print \"   ^ [FLAG] key material not mode 600\"}" || echo "[no cert/key files under scanned roots]"'

hdr 05 "certificate expiry for local certs (openssl x509)"
grun openssl bash -c 'certs=$(timeout 30 find /etc/letsencrypt/live /etc/ssl/private /etc/nginx/ssl -type f \( -name "fullchain.pem" -o -name "cert.pem" -o -name "*.crt" \) 2>/dev/null | sort); [ -n "$certs" ] || { echo "[no local certs located for expiry check]"; exit 0; }; for c in $certs; do echo "--- $c"; openssl x509 -noout -enddate -subject -in "$c" 2>/dev/null || echo "[unreadable / not an x509 pem]"; done'

hdr 06 "LIVE LOCAL PROBE — loopback-only network exception"
note "EXCEPTION SCOPE: openssl s_client to 127.0.0.1 on locally-listening 443/8443 ONLY; nothing remote"
grun openssl bash -c 'command -v ss >/dev/null 2>&1 || { echo "[skip: ss not installed — cannot confirm local listeners]"; exit 0; }; ports=$(ss -tln 2>/dev/null | grep -E ":(443|8443)[[:space:]]" | sed -E "s/.*:(443|8443)[[:space:]].*/\1/" | sort -u); [ -n "$ports" ] || { echo "[no local :443/:8443 listener — probes skipped]"; exit 0; }; for p in $ports; do echo "--- 127.0.0.1:$p modern handshake:"; out=$(timeout 10 openssl s_client -connect 127.0.0.1:$p </dev/null 2>/dev/null | grep -E "^(subject|issuer|Verify return code)"); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no handshake metadata returned]"; echo "--- 127.0.0.1:$p TLSv1.1 floor probe (handshake FAILURE = hardened) verbatim tail:"; timeout 10 openssl s_client -connect 127.0.0.1:$p -tls1_1 </dev/null 2>&1 | tail -6; done'

hdr 07 "HSTS/header spot-check — loopback-only network exception"
note "EXCEPTION SCOPE: single curl HEAD request against https://127.0.0.1/ ONLY"
run bash -c 'command -v curl >/dev/null 2>&1 || { echo "[skip: curl not installed]"; exit 0; }; out=$(curl -skI --connect-timeout 5 https://127.0.0.1/ 2>&1 | grep -iE "^(HTTP/|strict-transport-security|x-content-type-options|x-frame-options|referrer-policy|server):"); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no localhost HTTPS response or none of the watched headers present]"'

finish_sweep
