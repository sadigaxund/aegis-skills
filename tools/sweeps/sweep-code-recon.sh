#!/usr/bin/env bash
# sweep-code-recon.sh — Phase-1 recon evidence sweep (RCON) over a TARGET DIR.
# Usage: sweep-code-recon.sh <target-dir>   (target required; else usage exit 2)
# STRICTLY READ-ONLY over the target (find/grep/cat/wc-class inspection only);
# fully offline; nothing under the target is created or modified.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"

if [ "$#" -lt 1 ]; then
  printf 'usage: %s <target-dir>\n' "$0" >&2
  exit 2
fi
TARGET="$(cd -- "$1" 2>/dev/null && pwd)" || TARGET=""
if [ -z "$TARGET" ] || [ ! -d "$TARGET" ]; then
  printf 'error: target is not a directory: %s\n' "$1" >&2
  exit 2
fi
export RCON_TARGET="$TARGET"
export RCON_PRUNE="( -name node_modules -o -name .git -o -name vendor -o -name venv -o -name .venv -o -name dist -o -name build )"
init_sweep RCON
note "target dir: $TARGET (pruned from scans: node_modules .git vendor venv .venv dist build)"

hdr 01 "dependency manifests (maxdepth 4)"
run bash -c 'out=$(timeout 30 find "$RCON_TARGET" -maxdepth 4 $RCON_PRUNE -prune -o -type f \( -name package.json -o -name requirements.txt -o -name pyproject.toml -o -name go.mod -o -name pom.xml -o -name "build.gradle*" -o -name "*.csproj" -o -name composer.json -o -name Gemfile -o -name Cargo.toml \) -print 2>/dev/null | sort); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no dependency manifests found]"'

hdr 02 "lockfiles (maxdepth 4)"
run bash -c 'out=$(timeout 30 find "$RCON_TARGET" -maxdepth 4 $RCON_PRUNE -prune -o -type f \( -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name npm-shrinkwrap.json -o -name Pipfile.lock -o -name poetry.lock -o -name uv.lock -o -name Cargo.lock -o -name go.sum -o -name composer.lock -o -name Gemfile.lock -o -name packages.lock.json -o -name gradle.lockfile \) -print 2>/dev/null | sort); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no lockfiles found]"'

hdr 03 "infra/deploy artifacts (Dockerfile/compose/terraform/k8s/deploy/workflows)"
run bash -c 'files=$(timeout 30 find "$RCON_TARGET" -maxdepth 4 $RCON_PRUNE -prune -o -type f \( -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -o -name "*.tf" \) -print 2>/dev/null | sort); dirs=$(timeout 30 find "$RCON_TARGET" -maxdepth 4 -type d \( -path "*/.github/workflows" -o -name k8s -o -name kubernetes -o -name deploy -o -name deployments -o -name terraform -o -name helm -o -name charts \) -print 2>/dev/null | sort); wf=$(timeout 30 find "$RCON_TARGET/.github/workflows" -maxdepth 2 -type f -print 2>/dev/null | sort); all=$(printf "%s\n%s\n%s\n" "$files" "$dirs" "$wf" | sed "/^$/d" | sort -u); [ -n "$all" ] && printf "%s\n" "$all" || echo "[no Dockerfile/compose/terraform/k8s/deploy/workflow artifacts found]"'

hdr 04 "language LOC rough split (vendored dirs pruned, maxdepth 6)"
run bash -c 'list=$(timeout 30 find "$RCON_TARGET" -maxdepth 6 $RCON_PRUNE -prune -o -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" -o -name "*.py" -o -name "*.go" -o -name "*.java" -o -name "*.rs" -o -name "*.php" -o -name "*.rb" -o -name "*.cs" \) -print 2>/dev/null); [ -n "$list" ] || { echo "[no source files for tracked extensions]"; exit 0; }; for ext in js jsx ts tsx py go java rs php rb cs; do fs=$(printf "%s\n" "$list" | grep -E "\.${ext}\$"); [ -n "$fs" ] || continue; nf=$(printf "%s\n" "$fs" | wc -l); loc=$(printf "%s\0" "$fs" | xargs -0 cat 2>/dev/null | wc -l); printf "%-5s files=%-6s approx_loc=%s\n" "$ext" "$nf" "$loc"; done'

hdr 05 "route-decorator hit counts per framework family (counts + top files)"
run bash -c '
scan(){
  lbl="$1"; pat="$2"
  ex="--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor"
  tot=$(timeout 30 grep -rhIE $ex -- "$pat" "$RCON_TARGET" 2>/dev/null | wc -l)
  printf "%-26s total_hits=%s\n" "$lbl" "$tot"
  [ "$tot" -gt 0 ] || { echo "    (no hits)"; return 0; }
  timeout 30 grep -rcIE $ex -- "$pat" "$RCON_TARGET" 2>/dev/null | grep -v ":0$" | sort -t: -k2,2rn | head -15 | sed "s/^/    /"
}
scan "express/fastapi-decorators" "@(app|router)\.(get|post|put|delete|patch)"
scan "flask-route" "@app\.route"
scan "spring-mappings" "@RequestMapping|@GetMapping|@PostMapping|@RestController"
scan "php-laravel-route" "Route::"
scan "go-handlers" "func .*Handle|HandleFunc"
scan "controller-heuristic" "[Cc]ontroller"
'

hdr 06 "auth middleware mention count (file count, case-insensitive)"
run bash -c 'fl=$(timeout 30 grep -rIlEi --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor -- "passport|jwt|oauth|session" "$RCON_TARGET" 2>/dev/null | sort); n=$(printf "%s" "$fl" | grep -c .); printf "files_with_auth_mentions=%s\n" "$n"; [ -n "$fl" ] && printf "%s\n" "$fl" | head -15 | sed "s/^/  /"; true'

hdr 07 "env/sample secret-shaped files present (filenames only, never contents)"
run bash -c 'out=$(timeout 30 find "$RCON_TARGET" -maxdepth 5 $RCON_PRUNE -prune -o -type f \( -name ".env*" -o -name "*.pem" -o -name "id_rsa*" \) -print 2>/dev/null | sort); [ -n "$out" ] && printf "%s\n" "$out" || echo "[no .env* / *.pem / id_rsa* files found]"'

hdr 08 "entry-point hints summary (shallow-depth filename counts)"
run bash -c 'hits=0; for b in main server app index wsgi asgi; do n=$(timeout 30 find "$RCON_TARGET" -maxdepth 3 -type f \( -name "$b.py" -o -name "$b.js" -o -name "$b.ts" -o -name "$b.go" -o -name "$b.rb" \) 2>/dev/null | wc -l); [ "$n" -gt 0 ] && { printf "%-8s files=%s\n" "$b" "$n"; hits=$((hits+1)); }; done; [ "$hits" -gt 0 ] || echo "[no entry-point filename hits at depth<=3]"'

finish_sweep
