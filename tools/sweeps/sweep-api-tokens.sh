#!/usr/bin/env bash
# sweep-api-tokens.sh — evidence sweep for checks/server/api-token-security.md (TOK)
# STRICTLY READ-ONLY. Token-bearing surfaces pipe through redact; log hits print
# COUNTS per file, never values. DB introspection needs owner-supplied read
# creds — emitted as [APP-DB] notes, never executed here.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep TOK

hdr 01 "token-bearing config hunt under unit/app dirs (matched lines redacted)"
rootwarn
note "[COST] capped at 30s"
run bash -c 'timeout 30 grep -RInsE "(api[-_]?(key|token)|bearer|access[-_]?token|auth[-_]?token|secret)[-=_ :]+[A-Za-z0-9_.+-]{16,}" /etc/systemd/system /opt /srv /var/www 2>/dev/null | redact | head -40'

hdr 02 "systemd Environment= / EnvironmentFile= lines + referenced-file perms"
run bash -c "grep -RHnsE '^Environment=.*(TOKEN|KEY|SECRET|PASSWORD)' /etc/systemd/system 2>/dev/null | redact | head -20"
run bash -c "grep -RHnsE '^EnvironmentFile=' /etc/systemd/system 2>/dev/null | head -20"
run bash -c 'grep -hsE "^EnvironmentFile=" /etc/systemd/system/*.service 2>/dev/null | sed "s/^EnvironmentFile=-\?//;s/%.*//" | xargs -r stat -c "%a %U:%G %n" 2>/dev/null'

hdr 03 ".env-style file inventory (names+perms only, contents never dumped)"
run bash -c 'timeout 30 find /opt /srv /etc /home /var/www -xdev -maxdepth 5 \( -name ".env" -o -name ".env.*" \) -printf "%m %u:%g %p\n" 2>/dev/null | sort | head -40'

hdr 04 "shell history token exports (matched lines redacted)"
for h in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history; do
  [ -e "$h" ] || continue
  if [ -r "$h" ]; then
    run bash -c "grep -aoE '(API_TOKEN|API_KEY|[A-Z_]*(TOKEN|SECRET)[A-Z_]*)=\S{8,}' '$h' 2>/dev/null | redact | head -8"
  else
    note "[ROOT] $h unreadable — skipped"
  fi
done

hdr 05 "full tokens hitting disk in logs (COUNTS per file only)"
rootwarn
run bash -c "timeout 60 grep -REo 'Bearer [A-Za-z0-9_.=-]{20,}' /var/log/nginx /var/log/apache2 /var/log/apps 2>/dev/null | cut -d: -f1 | sort | uniq -c | head -20"
run bash -c "zgrep -hcoE '[?&](access_token|api_key|apikey|token)=[A-Za-z0-9_-]{8,}' /var/log/nginx/access.log* 2>/dev/null | paste -sd+ | bc"

hdr 06 "edge stack presence + rate-limit directives (TOK §7 cross-check)"
for b in nginx caddy haproxy apache2 httpd traefik; do
  if p="$(command -v "$b" 2>/dev/null)"; then note "$b present at $p"; else printf '[skip: %s not installed]\n' "$b"; fi
done
run bash -c 'grep -RnsE "limit_req(_zone)?|limit conn" /etc/nginx 2>/dev/null | head -20'
note "[APP-DB] schema introspection requires owner-supplied read creds; run by hand:"
note "[APP-DB]   psql \"\$APP_DB_URL\" -c \"SELECT table_name,column_name,data_type FROM information_schema.columns WHERE column_name ~* '(token|api_key|secret)';\""
note "[APP-DB]   psql \"\$APP_DB_URL\" -c \"SELECT count(*) FILTER (WHERE expires_at IS NULL) AS immortal_tokens, count(*) FROM api_tokens;\""

finish_sweep
