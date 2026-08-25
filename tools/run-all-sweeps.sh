#!/usr/bin/env bash
# run-all-sweeps.sh — deterministic evidence collection for a host audit.
# Usage: ./run-all-sweeps.sh [evidence-dir]
# Runs every sweep-*.sh (excluding lib), tees output to evidence files,
# records durations and failures. READ-ONLY on the target by design.
set -u
HERE="$(cd "$(dirname "$0")/sweeps" && pwd)"
EV="${1:-./sweep-evidence-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$EV"
echo "# Evidence dir: $EV"
echo "# Tip: export CODE_TARGET=/path/to/repo before running to point sweep-code-recon at your app"
overall=0
for s in "$HERE"/sweep-*.sh; do
  name="$(basename "$s" .sh)"
  [ "$(basename "$s")" = "sweep-lib.sh" ] && continue
  echo "=== running $name"
  start=$(date +%s)
  if [ "$name" = "sweep-code-recon" ]; then
    bash "$s" "${CODE_TARGET:-$PWD}" >"$EV/$name.txt" 2>&1   # code-recon takes a repo target
  else
    bash "$s" >"$EV/$name.txt" 2>&1
  fi
  rc=$?
  end=$(date +%s)
  echo "    rc=$rc dur=$((end-start))s -> $EV/$name.txt ($(wc -l <"$EV/$name.txt") lines)"
  [ $rc -eq 0 ] || overall=$rc
done
echo "# DONE overall=$overall"
echo "# NEXT: hand each $EV/<name>.txt to the agent together with its matching"
echo "# skills/server/<name>/SKILL.md — findings are produced from module rubrics, not raw output."
