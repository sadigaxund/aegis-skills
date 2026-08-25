#!/usr/bin/env bash
# sweep-lib.sh — shared helpers for ALL sweep scripts.
# Contract: sweeps are STRICTLY READ-ONLY evidence collectors. No mutations,
# no installs, no restarts, no network probes unless the script says so inline.
# They exist so auditing agents gather IDENTICAL evidence every run and only
# spend judgment on interpretation (see skills/server/*.md for interpretation).
# shellcheck shell=bash

SWEEP_SLUG="UNSET"

init_sweep(){
  SWEEP_SLUG="$1"
  echo "# SWEEP=$SWEEP_SLUG host=$(hostname 2>/dev/null) kernel=$(uname -r) date=$(date -Is) uid=$(id -u)"
  [ "$(id -u)" = "0" ] || echo "# NOTE: running unprivileged — sections marked [ROOT] will be partial"
}

# hdr ID "description"  -> opens a stable section agents key findings to
hdr(){ printf '\n===== [%s-%s] %s =====\n' "$SWEEP_SLUG" "$1" "$2"; }

# run cmd args...  -> echo command, run it, never abort on failure
run(){
  printf -- '--- $ %s\n' "$*"
  "$@" 2>&1
  local rc=$?
  [ $rc -eq 0 ] || printf '[cmd-failed rc=%s]\n' "$rc"
  return 0
}

# guard binary && then-run : guarded run "cmd" args...
grun(){
  local bin="$1"; shift
  if command -v "$bin" >/dev/null 2>&1; then run "$@"; else printf '[skip: %s not installed]\n' "$bin"; fi
}

# redact masks long token-like strings in piped output:  ABCD1234567890... -> ABCD…REDACTED
redact(){
  sed -E 's/([A-Za-z0-9+\/_-]{4})[A-Za-z0-9+\/_-]{16,}/\1…REDACTED/g'
}

# grep-with-redaction for secret-bearing surfaces
export -f redact   # visible inside `bash -c` subshells used by sweep scripts

grepr(){ # grepr PATTERN FILES...
  local pat="$1"; shift
  grep -nIE "$pat" "$@" 2>/dev/null | redact || echo "[no matches]"
}

note(){ printf '[NOTE] %s\n' "$*"; }
rootwarn(){ [ "$(id -u)" = "0" ] || note "[ROOT] full fidelity requires root — partial output follows"; }

finish_sweep(){
  printf '\n# END SWEEP=%s\n' "$SWEEP_SLUG"
  printf '# Interpretation: load the matching skills/code/<module>.md — verdicts live there,\n'
  printf '# not here. This script only guarantees identical evidence per run.\n'
}
