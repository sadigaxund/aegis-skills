#!/usr/bin/env bash
# sweep-k8s.sh — evidence sweep for skills/server/kubernetes-cluster/SKILL.md (K8S)
# STRICTLY NON-MUTATING: every kubectl call is a read (get/config/auth can-i)
# and auto-skips when kubectl is absent or RBAC denies it. No cluster writes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/sweep-lib.sh"
init_sweep K8S

hdr 01 "tooling + context"
grun kubectl bash -c 'kubectl config current-context 2>&1 | head -3'

hdr 02 "identity self-audit (canonical output)"
grun kubectl kubectl auth can-i --list

hdr 03 "rbac wildcard signal + bindings sample"
note "[crude signal] line count of verbs entries + literal \"*\" rules across ALL ClusterRoles:"
run bash -c 'kubectl get clusterroles -o yaml 2>/dev/null | grep -cE "verbs?:|- \"\*\""'
note "[tighter signal] count of lines containing a bare \"*\":"
run bash -c 'kubectl get clusterroles -o yaml 2>/dev/null | grep -c "\"\*\""'
run bash -c 'kubectl get clusterrolebindings -o wide 2>/dev/null | head -25'

hdr 04 "privileged / hostPath / NodePort exposure counts"
run bash -c 'kubectl get pods -A -o json 2>/dev/null | grep -cE "\"privileged\": *true"'
run bash -c 'kubectl get pods -A -o json 2>/dev/null | grep -cE "\"hostPath\""'
run bash -c 'kubectl get svc -A 2>/dev/null | grep NodePort | head -15'

hdr 05 "PSA enforce label per namespace"
grun kubectl bash -c "kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{\" \"}{.metadata.labels.pod-security\\.kubernetes\\.io/enforce}{\"\\n\"}{end}' 2>/dev/null | head -40"

hdr 06 "NetworkPolicy coverage per namespace (missing row = uncovered ns)"
run bash -c 'kubectl get netpol -A --no-headers 2>/dev/null | awk "{c[\$1]++} END{for (n in c) printf \"%s %d\n\", n, c[n]}" | sort | head -30'

hdr 07 "SA token automount posture (pods not opted out carry tokens by default)"
run bash -c 't=$(kubectl get pods -A --no-headers 2>/dev/null | wc -l); o=$(kubectl get pods -A -o json 2>/dev/null | grep -c "\"automountServiceAccountToken\": false"); t=${t:-0}; o=${o:-0}; printf "pods-total=%s opted-out=%s default-on=%s\n" "$t" "$o" "$((t-o))"'
note "[approximation] JSON-grep cannot see explicit true vs omitted; treat default-on as token-bearing"

finish_sweep
