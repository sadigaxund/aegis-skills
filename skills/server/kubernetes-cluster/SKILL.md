---
name: kubernetes-cluster-hardening
description: Audits Kubernetes cluster security posture across API server access, RBAC blast radius, admission control, workload securityContexts, NetworkPolicy coverage, secrets handling, and ingress/exposure surface, with read-only sweeps for live clusters and config-as-code repositories.
category_slug: K8S
cwe: [CWE-250, CWE-284, CWE-732]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit one Kubernetes cluster — or its config-as-code repository (plain manifests, Helm charts, Kustomize overlays) — in eight domains:

1. **Cluster access & API server** — kubeconfig hygiene, self-inspection of effective permissions, anonymous-auth and legacy insecure-port exposure, etcd encryption-at-rest presence.
2. **RBAC** — wildcard rules, anonymous bindings, cluster-admin holder count, default ServiceAccount token automounting, privilege-escalation primitives (`escalate`, `bind`, `impersonate`, `serviceaccounts/token`).
3. **Admission control & policy** — PodSecurity admission labels per namespace; PodSecurityPolicy as legacy-only detection; policy engines (Kyverno, Gatekeeper) noted qualitatively.
4. **Workload securityContext** — cluster-wide coverage sweep of `runAsNonRoot`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`; privileged containers; hostPath, hostNetwork/hostPort/hostPID hunts. Deep pod-spec hardening lives in the configuration-hardening module — do not duplicate it here beyond the cluster-level view.
5. **NetworkPolicy posture** — default-deny presence per namespace, egress rarity, DNS allowance gotcha.
6. **Secrets handling in-cluster** — env-var vs volume-mount tradeoff, etcd-encryption tie-in, external operators (ExternalSecrets/SealedSecrets) named generically.
7. **Ingress/LB exposure & observability** — public vs internal classes, TLS termination, NodePort sprawl, audit-policy existence, event review discipline.
8. **Node baseline pointers** — kubelet authorization mode and read-only port when node-visible, with a one-line hand-off to the linux-baseline module.

Operating rules:

- Every command is **read-only**: `get`, `list`, `describe`, `auth can-i`, file reads, greps. Never run `apply`, `delete`, `create token`, `exec`, or `port-forward` during audit. Mutating commands appear only under Remediation and Verification, inside an approved change window.
- The live cluster and its Git repo are **two views of one system**. Audit both; reconcile drift (repo says restricted, cluster says privileged → someone applied out-of-band).
- On managed clusters (GKE/EKS/AKS), control-plane flags and EncryptionConfiguration are provider-managed and invisible from workload context. Audit what is auditable from your identity and record the limitation explicitly in the report — absence of evidence is not evidence of safety there.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **namespace**: a cluster partition grouping workloads and their policies
- **RBAC**: rules binding identities to allowed verbs on resources (`get`, `list`, `exec`, …)
- **ServiceAccount token**: the identity file mounted into every pod; whoever can run commands in a pod holds it
- **automount**: the default-ON behavior of mounting that token into pods
- **admission**: policies that validate or modify objects before they are created
- **NetworkPolicy**: a per-namespace firewall; where none exists, any pod can reach any pod
- **etcd**: the cluster's database holding all Secrets, base64-encoded unless encryption-at-rest is enabled
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function

## Mental Model

Every capability in Kubernetes is an API request: *verb on resource in apiGroup, scoped to a namespace*. The request path is the audit map:

```
Client ──▶ Authentication ──▶ Authorization (RBAC) ──▶ Admission ──▶ etcd
           x509 / bearer /     verbs × resources ×      mutating then
           OIDC / anonymous    namespaces               validating
                                                        (PodSecurity,
                                                         Kyverno/Gatekeeper)
```

Consequences that drive every check below:

- **Identity is a mounted file.** A pod's ServiceAccount token is projected into the container at `/var/run/secrets/kubernetes.io/serviceaccount/token` unless `automountServiceAccountToken: false`. Whoever can `exec` into a pod holds its identity. Default is automount = on.
- **The network is flat until denied.** Any pod can reach any pod in any namespace by IP unless a NetworkPolicy blocks it. Ingress+egress default-deny per namespace is the baseline; egress policies are rarer and must always carve out DNS.
- **RBAC is transitive through tokens.** Escalation primitives (`escalate`, `bind`, `impersonate`, `create serviceaccounts/token`) let a low identity mint or borrow a higher one. Chain severity = the ceiling of what the chain reaches, not the starting point.
- **etcd is the crown jewels.** All Secrets live there, base64-encoded, encrypted only if an EncryptionConfiguration (or provider feature) is active. Anyone who can read etcd bypasses RBAC entirely.
- **cluster-admin is total compromise.** One wildcard binding to a workload identity means every Secret, exec into every pod, privileged DaemonSets on every node. Count and justify each holder.

## What To Check

### 1. Cluster access & API server

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| kubeconfig file permissions | `stat -c "%a %U %G" ~/.kube/config` | `600`, owned by the invoking user | group/world-readable (`644+`) or shared root-owned copy |
| Effective permissions of current identity | `kubectl auth can-i --list` | only intended verbs; no wildcards | `*.*` row, or `escalate`/`bind`/`impersonate` verbs (see Exploitation section for output reading) |
| Anonymous authentication flag | `grep -E "anonymous-auth" /etc/kubernetes/manifests/kube-apiserver.yaml` | flag absent (defaults to false) or explicitly `=false` | `--anonymous-auth=true` without compensating RBAC |
| Anonymous reachability (behavioral) | `curl -sk -o /dev/null -w "%{http_code}" https://<api>:6443/api/v1/namespaces` | `401` or `403` | `200` — anonymous listing succeeds. Do NOT use `/version` as the test: `/version` and `/healthz` are anonymously readable by default via built-in public-info roles |
| Legacy insecure port | `grep -rn "insecure-port\|insecure-bind-address" /etc/kubernetes/ 2>/dev/null` | no hits | flag present (historical clusters; removed from kube-apiserver in v1.24) |
| etcd encryption at rest | `grep -E "encryption-provider-config" /etc/kubernetes/manifests/kube-apiserver.yaml` | flag points at an EncryptionConfiguration file using aescbc/kms provider | absent → Secrets stored plaintext in etcd. May be invisible from workload context on managed clusters — record the limitation honestly rather than reporting a false finding either way |
| etcd client/peer cert requirement | `grep -E "client-cert-auth|peer-client-cert-auth|trusted-ca-file" /etc/kubernetes/manifests/etcd.yaml` | `true` with CA files set; etcd listens on control-plane-only interfaces | `false` or missing while etcd is network-reachable from pods/nodes = Critical (qualitative check; do not extract data to prove it — port reachability alone is sufficient evidence) |

Cluster-admin count reasoning: enumerate holders, then classify each subject. Expect only platform identities (cloud add-on service accounts, `system:masters` group members) plus a small break-glass human list. Every workload ServiceAccount bound to cluster-admin is Critical; every broad human group is High until justified in writing.

```bash
# Holder inventory + classification (read-only)
command -v kubectl >/dev/null 2>&1 || exit 0
kubectl get clusterrolebindings -o json 2>/dev/null \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin") |
           .metadata.name as $b |
           (.subjects // [])[]? |
           "\($b)\t\(."kind")\t\(."name")\t\(."namespace" // "-")"' \
  | sort
```

Anonymous-auth exposure check on managed clouds: node-level static-pod manifests do not exist there. Fall back to the behavioral curl test above against the provider endpoint and record that control-plane flags cannot be inspected directly.

### 2. RBAC

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| Wildcard verbs/resources in custom ClusterRoles | fenced jq below | no `"*"` outside `system:` built-ins | any user-created role with `"*"` verbs or resources |
| Bindings to unauthenticated/anonymous | `kubectl get rolebindings,clusterrolebindings -A -o json \| jq ...` (see sweep) | none exist | any binding naming `system:unauthenticated` or `system:anonymous` = **Critical** |
| Default SA token automounting | inspect Deployments/Pods for `automountServiceAccountToken` | `false` wherever the workload does not call the API | field absent (= defaults to true) on pods with no API need |
| Escalation primitives held by app SAs | read Role/ClusterRole rules for `escalate`, `bind`, `impersonate`, `create` on `roles`, `rolebindings`, `serviceaccounts/token`, `pods/exec` | absent from workload identities | present = **High**; walk the full chain before scoring |

```bash
# Wildcard rules in non-system ClusterRoles (read-only)
kubectl get clusterroles -o json 2>/dev/null | jq -r '
  .items[]
  | select((.metadata.name | startswith("system:") | not)
           and ((.metadata.name | startswith("kubeadm:")) | not))
  | select(any(.rules[]?;
      ((.verbs     // []) | index("*"))
      or ((.resources   // []) | index("*"))))
  | .metadata.name'
```

Privilege-escalation primitives catalog — treat each row as an escalation *primitive*, verified by reading rule blocks:

| Primitive (verbs → resources) | What it grants |
|---|---|
| `escalate` → `roles`, `clusterroles` | modify any role to include permissions you lack, then inherit them |
| `bind` → `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings` | bind an existing powerful role to yourself or your SA |
| `create`/`update` on `roles` + binding rights | author then wear a custom admin role |
| `impersonate` (+headers subresources) → `users`, `groups`, `serviceaccounts` | act as anyone, including cluster-admin users |
| `create` → `serviceaccounts` and `serviceaccounts/token` | mint TokenRequest tokens for any SA in scope — see the step-by-step chain in Exploitation & Reproduction |
| `create` → `pods` (any ns where a stronger SA automounts) | schedule a pod wearing that SA's token |
| `create` → `pods/exec`, `pods/attach` | enter other workloads and steal their mounted tokens |
| `get`/`list` → `secrets` | direct credential theft across scope |

Service-account-token-request escalation chain (understand it; verify statically):

1. Attacker holds a token for app SA `A` (stolen from a compromised pod's projected volume).
2. `A`'s Role grants `create` on `serviceaccounts/token` in namespace N.
3. Any stronger SA exists in N (for example a CI deployer with cluster-wide rights).
4. `A` issues a TokenRequest for that SA — `kubectl create token <sa> -n N` semantics — receiving a fresh bearer token.
5. The attacker now operates as the stronger SA; repeat until cluster-admin or stop at the widest reachable role.

Audit verification is steps 1–3 done by *reading*: list SAs, dump Roles/Bindings, map who can mint whom. Never run step 4 during an audit — issuing credentials is a mutating action.

Per-namespace least privilege framing: default expectation is that a workload SA resolves to zero cross-namespace rights and single-digit same-namespace rights. Anything wider needs a written reason attached to the finding.

### 3. Admission control & policy

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| PodSecurity enforce labels per namespace | `kubectl get ns --show-labels \| grep pod-security.kubernetes.io/enforce` | every user namespace labeled `enforce: baseline` or `restricted` (with matching `-version` pin) | label absent, or set to `privileged` |
| PodSecurityPolicy legacy detection | `kubectl get psp` | command returns "not found"/no resources (PSP removed in v1.25) | PSP objects still served = pre-v1.25 legacy cluster needing migration; mention once, do not audit PSP rules |
| Policy engine presence | `kubectl api-resources \| grep -iE "kyverno\|gk-\|constraints.gatekeeper"` | Kyverno or Gatekeeper present = org has policy-as-code option; absence is informational, not a finding by itself | engine installed but zero policies defined |

Exact label keys to look for on namespaces: `pod-security.kubernetes.io/enforce`, `pod-security.kubernetes.io/enforce-version`, `pod-security.kubernetes.io/warn`, `pod-security.kubernetes.io/warn-version`, `pod-security.kubernetes.io/audit`, `pod-security.kubernetes.io/audit-version`. Values: `privileged`, `baseline`, `restricted` (or version pins). `warn`/`audit` labels without `enforce` mean the standard is advisory only — report as Medium, not healthy.

### 4. Workload securityContext (cluster-wide view)

Deep per-container hardening detail belongs to the configuration-hardening module; here measure coverage across the whole fleet.

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| Privileged containers | jq over `kubectl get pods -A -o json` (see sweep) | none in user namespaces | any hit = instant **High** |
| hostPath mounts | jq over pod volumes | none, except documented platform Daemons | `/`, `/var/run/docker.sock`, `/var/run/containerd/containerd.sock`, `/proc`, `/sys`, `/var/lib/kubelet` = **Critical** patterns |
| `runAsNonRoot`/`allowPrivilegeEscalation:false`/`readOnlyRootFilesystem:true` coverage | count fields across all Deployment/Pod specs | high coverage; gaps tracked as backlog | widespread absence (>50% of workloads unset) |
| hostNetwork/hostPort/hostPID/hostIPC | jq over pod specs | absent, or justified platform components (CNI, ingress daemonsets) | unreviewed usage in app workloads |

### 5. NetworkPolicy posture

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| Default-deny presence per namespace | netpol count loop (see sweep) + shape inspection | ≥1 policy selecting ALL pods (`podSelector: {}`) with `policyTypes` covering Ingress and Egress | zero policies in a user namespace, or policies that select nothing meaningful |
| DNS allowance gotcha | inspect egress-denying policies for UDP/TCP 53 to kube-dns/CoreDNS | explicit DNS exception present wherever egress is denied | missing exception — enforcing this breaks ALL name resolution cluster-wide; flag as a deployment blocker before it ships |
| Egress policy rarity | count policies whose `policyTypes` includes `Egress` | acknowledged rare; if zero, note staged rollout intent | none planned anywhere (note, not blocker) |

Egress NetworkPolicies are uncommon because they break things subtly. If none exist, record it and point remediation at the staged approach used by the firewall-edge module philosophy: observe, then allow known flows, then deny. Never flip straight to deny-all egress.

### 6. Secrets handling in-cluster

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| env-var vs mounted volume usage | `kubectl get deploy -A -o jsonpath=...` over `env[].valueFrom.secretKeyRef` vs volume `secret:` mounts | sensitive values volume-mounted (files, revocable, not visible in `describe`/process env) | long-lived env-var copies of high-value secrets |
| etcd encryption tie-in | Access-table check above | EncryptionConfiguration or provider-managed encryption active | absent — Secrets readable by anyone with etcd/RBAC-read path |
| External secret operators | `kubectl get crds \| grep -iE "externalsecrets\|sealedsecrets"` | ExternalSecrets or SealedSecrets CRDs present = good pattern in use | absence is informational; recommend generically |
| Secrets committed to Git repos | out of scope here | — | cross-ref the SECRETS module pointer — scan repos separately, never inside this module |

Env vars trade convenience for leakage surface: they appear in `kubectl describe pod`, child processes, and crash dumps; mounted Secret volumes update on rotation and need explicit file reads to exfiltrate.

### 7. Ingress/LB exposure

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| Ingress classes split | `kubectl get ingressclasses` | public and internal classes exist and are used deliberately | one public class serving everything incl. internal-only routes |
| TLS termination presence | `kubectl get ingress -A -o yaml \| grep -A3 "tls:"` | `tls:` block + secret ref on every user-facing route | plaintext HTTP routes carrying auth or data |
| LB annotations review | `rg -n "service\.beta\.kubernetes\.io" .` in repo; `kubectl get svc -A -o yaml \| grep -B2 -A2 loadBalancer` | internal-facing schemes annotated deliberately (provider-specific annotation families) | internal-only service published on a public LB by omission |
| NodePort sprawl | `kubectl get svc -A \| awk 'NR==1 \|\| /NodePort/'` | zero or a documented handful | many NodePorts bypassing ingress TLS/policy controls |

### 8. Audit logging & observability

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| API server audit policy | `grep -E "audit-policy-file\|audit-log-path" /etc/kubernetes/manifests/kube-apiserver.yaml` | both flags set, policy file covers write/authz events at Metadata minimum | absent on self-managed control plane = Low finding (detection gap). Managed clusters: often provider-managed — verify in provider console, else record limitation |
| Event review discipline | `kubectl get events -A --sort-by=.lastTimestamp \| head -40` | Warning events triaged on a schedule; discipline documented | events ignored. Note events expire (~default 1h TTL) — they are a triage aid, not an audit trail |
| Runtime detection | check whether a Falco-class agent runs as DaemonSet | named option worth recommending; presence noted qualitatively | — |

### 9. Node baseline pointers

| Check | Command / grep | Healthy state | Finding condition |
|---|---|---|---|
| kubelet authorization mode | `grep -A2 "^authorization:" /var/lib/kubelet/config.yaml` (on nodes you can reach) | `mode: Webhook` | `AlwaysAllow` when visible = **High** |
| kubelet read-only port | `curl -m 3 -s http://<node>:10255/pods \| head -c 200` | connection refused/timeout | JSON pod inventory returned = unauthenticated info leak |
| Node SSH/OS hardening | — | — | one-line cross-ref: apply the linux-baseline module to every node image/host |

### Consolidated read-only sweep

Paste-ready. Guards its own prerequisites; mutates nothing; skips cleanly when tooling or RBAC is missing.

```bash
#!/usr/bin/env bash
# Kubernetes posture sweep — strictly non-mutating.
command -v kubectl >/dev/null 2>&1 || { echo "SKIP: kubectl missing"; exit 0; }
command -v jq      >/dev/null 2>&1 || { echo "SKIP: jq missing"; exit 0; }
kubectl auth can-i list pods >/dev/null 2>&1 || { echo "SKIP: no API access"; exit 0; }
echo "[identity]"; kubectl config current-context; kubectl auth can-i --list
echo "[cluster-admin holders]"
kubectl get clusterrolebindings -o json | jq -r '.items[]|select(.roleRef.name=="cluster-admin")|.metadata.name+" -> "+([.subjects[]?."name"]|join(","))'
echo "[wildcard rules in user ClusterRoles]"
kubectl get clusterroles -o json | jq -r '.items[]|select((.metadata.name|startswith("system:")|not) and any(.rules[]?;((.verbs//[])|index("*")) or ((.resources//[])|index("*"))))|.metadata.name'
echo "[anonymous/unauthenticated bindings]"
kubectl get clusterrolebindings,rolebindings -A -o json | jq -r '..|objects|select(.subjects?)|select(any(.subjects[]?;."name"=="system:unauthenticated" or ."name"=="system:anonymous"))|"\(.kind // "b") \(.metadata.namespace // "-")/\(.metadata.name)"'
echo "[privileged containers in user namespaces]"
kubectl get pods -A -o json | jq -r '.items[]|select(.metadata.namespace|startswith("kube-")|not)|.metadata.namespace+"/"+.metadata.name as $p|(.spec.containers+.spec.initContainers? // [])[]|select(.securityContext.privileged==true)|$p+" ctr="+.name'
echo "[hostPath mounts]"
kubectl get pods -A -o json | jq -r '.items[]|.metadata.namespace+"/"+.metadata.name as $p|.spec.volumes[]?|select(.hostPath)|$p+" -> "+.hostPath.path'
echo "[netpol count per namespace (want default-deny in each user ns)]"
for ns in $(kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}'); do printf '%-30s %s\n' "$ns" "$(kubectl get networkpolicies -n "$ns" -o name 2>/dev/null | wc -l)"; done
echo "[PSA enforce labels]"; kubectl get ns --show-labels | grep -E 'pod-security.kubernetes.io/enforce' || echo "NONE FOUND"
echo "[NodePort/LoadBalancer services]"; kubectl get svc -A | awk 'NR==1||/NodePort|LoadBalancer/'
```

## Where To Look

Evidence collection: `tools/sweeps/sweep-k8s.sh` captures `[K8S-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

| Surface | Location | What it proves |
|---|---|---|
| Live API objects | everything via `kubectl get/describe` under your audited identity | effective runtime state; authoritative for RBAC bindings |
| kubeconfigs | `~/.kube/config`, `$KUBECONFIG`, `/root/.kube/config` on jump hosts | permission hygiene of operator identities |
| Control-plane static pods | `/etc/kubernetes/manifests/kube-apiserver.yaml`, `etcd.yaml` (self-managed control-plane nodes) | apiserver/etcd flags: anonymous-auth, encryption-provider-config, audit-policy-file |
| kubeadm config | `/etc/kubernetes/*.conf`, ConfigMap `kube-system/kubeadm-config` | cluster-lifetime defaults |
| kubelet config | `/var/lib/kubelet/config.yaml` on every node | authorization mode, read-only port |
| Manifest repo | `**/*.{yaml,yml}`, `charts/**/values.yaml`, `kustomize/**` | intended state; catches drift when diffed against live |
| Helm rendered output | `helm template <release> ./chart -f values-prod.yaml` | what actually deploys — values files lie when overrides stack |

Assessment tooling mentions (presence = maturity signal, absence = informational):
- kube-bench — CIS Kubernetes Benchmark scans of control-plane and node hardening posture.
- kubesec — static risk scoring of workload manifests.
- OPA Gatekeeper / Kyverno — admission-time policy engines (which policies actually enforce matters more than installation).
- falco / tetragon — runtime drift detection versus declared workload behavior.
- Harbor-style registry hardening — image scanning/signing/quota controls at the registry layer.
- Distroless base images — minimal runtime surface for containerized workloads.
- etcd security assessment pointer — client/peer TLS, authn/authz flags, secret encryption-at-rest (control-plane static-pod row above).

## Patterns & Signatures

Run the ripgrep battery from a repository root. All read-only.

```bash
# --- manifest-repo signature battery ---
rg -n --glob '*.{yaml,yml}' 'privileged:\s*true' .                       # instant High
rg -n --pcre2 --glob '*.{yaml,yml}' 'allowPrivilegeEscalation:\s*(?!false)' .
rg -n --glob '*.{yaml,yml}' 'hostPath:' .                                # inspect every hit
rg -n --glob '*.{yaml,yml}' 'path:\s*(/|/var/run/docker\.sock|/var/run/containerd/containerd\.sock|/proc(/sys)?|/sys|/var/lib/kubelet)' .   # Critical patterns
rg -n --glob '*.{yaml,yml}' 'host(Network|PID|IPC):\s*true' .
rg -n --glob '*.{yaml,yml}' 'hostPorts?:' .
rg -n --glob '*.{yaml,yml}' 'automountServiceAccountToken:\s*true' .
rg -l --glob '*.{yaml,yml}' 'serviceAccountName:' .                      # then read each file: automount false present?
rg -n --glob '*.{yaml,yml}' 'verbs:.*"\*"|resources:.*"\*"|apiGroups:.*"\*"' .   # wildcard RBAC
rg -l --glob '*.{yaml,yml}' 'kind:\s*(ClusterRole|Role)\s*$' .           # feed this list into the wildcard grep
rg -n --glob '*.{yaml,yml}' 'type:\s*NodePort' .
rg -n --glob '*.{yaml,yml}' 'namespace:\s*default\b' .                   # workloads in default ns
rg -c --glob '*.{yaml,yml}' 'kind:\s*NetworkPolicy' .                    # zero per user-ns dir = no default-deny evidence
rg -n --glob '*.{yaml,yml}' 'pod-security\.kubernetes\.io/enforce' .     # PSA labels in Git
rg -n --glob '**/values*.{yaml,yml}' 'privileged|hostPath|NodePort' .    # Helm override files
```

Helm coverage note: chart defaults often live in `values.yaml` while the risky decision sits in an environment override (`values-prod.yaml`, `--set` flags in CI). Grep the whole chart tree, then render with the production values and re-grep the output — that is the artifact that ships.

YAML pairs — vulnerable form, then fixed form:

```yaml
# VULNERABLE — app identity holds full administrative power cluster-wide
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: payments-api
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

```yaml
# FIXED — namespaced Role, named resources, read-only verbs
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payments-api
  namespace: payments
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["payments-api-config"]
  verbs: ["get", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["payments-api-db"]
  verbs: ["get"]
```

```yaml
# VULNERABLE — token mounted although the app never calls the API;
# container privileged; host runtime socket exposed
spec:
  containers:
  - name: worker
    image: registry.example.com/worker:latest
    securityContext:
      privileged: true
    volumeMounts:
    - name: dockersock
      mountPath: /var/run/docker.sock
  volumes:
  - name: dockersock
    hostPath:
      path: /var/run/docker.sock
```

```yaml
# FIXED — no token, no privileges, no host mounts
spec:
  automountServiceAccountToken: false
  containers:
  - name: worker
    image: registry.example.com/worker@sha256:7a4f1c...  # pin immutable digest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

```yaml
# VULNERABLE — bypasses ingress TLS/policy tier
apiVersion: v1
kind: Service
metadata:
  name: payments-api
spec:
  type: NodePort
```

```yaml
# FIXED — ClusterIP behind the ingress controller
apiVersion: v1
kind: Service
metadata:
  name: payments-api
spec:
  type: ClusterIP
```

## Taint Tracing Guidance

Treat each finding as a taint source and trace it forward (what can this identity reach?) and backward (who can touch this sink?). Report chains as one compound finding scored at its terminal sink.

| Taint source | Propagation path | Terminal sink | Scoring consequence |
|---|---|---|---|
| SA token auto-mounted in pod | exec/file-read → API calls as that SA | widest role reachable via bindings, escalation primitives, or token minting | severity = ceiling of reachable roles, not the pod's own rights |
| `/var/run/docker.sock`-class hostPath | container → host runtime API → sibling containers | root on node → node credentials → whole-cluster reach | treat as host + cluster compromise, Critical |
| etcd reachable without client certs | any network peer → direct state read/write | every Secret regardless of RBAC | Critical; verify by port reachability only |
| Exposed anonymous-capable API endpoint | external client → RBAC of `system:anonymous` | whatever anonymous/unauthenticated bindings grant | Critical if any binding widens it; Medium if truly zero-rights |
| Wildcard ClusterRole bound to workload SA | SSRF/supply-chain/pod compromise yields admin API access | full cluster control incl. all Secrets | Critical even though "it's just one role" |
| Secret committed to Git | repo clone / CI logs → credential reuse | depends on secret type | hand off to SECRETS module; note linkage here |

Method:

1. On every High/Critical workload or RBAC finding, run the self-inspection technique *as mapped onto the affected identity*: read its RoleBindings and dump the referenced roles.
2. Walk escalation edges (primitives catalog above) to a fixpoint: which identities can mint/impersonate/bind to whom?
3. Record the chain explicitly ("pod X in ns payments reaches cluster-admin in two steps via token-request primitive") — this is what makes remediation prioritizable.

## Exploitation & Reproduction

Everything in this section is read-only demonstration and static reasoning. No exploitation is performed against live clusters; chains are proven by reading configuration, which is sufficient evidence.

### 1. Self-audit interpretation guide: `kubectl auth can-i --list`

This is THE canonical self-inspection technique — it asks the API server to evaluate the current kubeconfig identity's effective rules, including group memberships and any ClusterRoleBindings you cannot enumerate directly. Run it first on every engagement:

```bash
kubectl auth can-i --list
```

Example output for a dangerously over-privileged deployer identity:

```
Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []               [*]
                                                [*]                 []               [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]
```

Read rows like this:

- `*.*` with verbs `[*]` — cluster-admin-equivalent. Every Secret, every pod, every node. Score the whole engagement through this lens; report as Critical if bound to anything other than break-glass humans.
- A `Resources` cell of `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings` combined with verbs containing `escalate` or `bind` — can promote itself to any existing role. Escalation primitive.
- `serviceaccounts` plus `serviceaccounts/token` with `create` — TokenRequest minting chain (below).
- `users`, `groups`, `serviceaccounts` with `impersonate` — act as anyone via impersonation headers.
- `pods`/`pods/exec` with `create` — schedule or enter workloads to harvest their mounted tokens.
- `secrets` with `get`/`list` — direct credential theft within scope.
- The trailing `Non-Resource URLs` column showing `[*]` — unrestricted access to API paths (health, metrics, logs endpoints).
- Every row absent except `selfsubject*` review verbs — least privilege as intended; spot-check one expected verb positively (`kubectl auth can-i get secrets -n payments`) because an empty list can also mean a misconfigured kubeconfig rather than a hardened one.

Targeted single-question form, useful when checking a specific escalation edge:

```bash
kubectl auth can-i create serviceaccounts/token -n payments
kubectl auth can-i bind clusterrolebindings -n kube-system
kubectl auth can-i impersonate users
```

Note honestly in the report: answering these for *another* identity requires `--as=system:serviceaccount:<ns>:<name>` and the `impersonate` verb; without it, derive other identities' rights by reading Role/RoleBinding objects instead.

### 2. Pod-exec → same-node token theft: static verification narrative

Scenario verified purely from configuration reads:

1. Namespace `payments` runs two workloads. Deployment `worker` uses ServiceAccount `payments-worker`; a ClusterRoleBinding grants that SA `create pods/exec` cluster-wide "for debugging". Deployment `api` runs as SA `payments-deployer`, whose Role includes broad write rights.
2. Both Deployments omit `automountServiceAccountToken` — so both default to true and carry live tokens at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
3. Chain, stated statically: anyone who can exec into `worker` reads its token → uses it to `exec` into `api` → reads the stronger `payments-deployer` token → operates with deployer rights. Same node not even required; network-flat design makes cross-node identical.
4. Verification commands used during audit — all reads:

```bash
kubectl get deploy -n payments worker api \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.serviceAccountName}{"\t"}{.spec.template.spec.automountServiceAccountToken}{"\n"}{end}'
# empty third column = automount defaults ON = token present

kubectl get clusterrolebindings,rolebindings -A -o wide | grep -E 'payments-worker|payments-deployer'
kubectl get clusterrole <referenced-role> -o yaml | grep -E '^  resources:|^  verbs:' 
```

5. Report wording: "Exec-to-token-theft chain exists between worker→deployer identities; verified via automount default and RBAC rule inspection. No exec was performed." Severity follows the terminal sink per Taint Tracing.

### 3. Manifest-repo vulnerable→fixed diffs

```diff
 # roles/payments-api.yaml
 rules:
-- apiGroups: ["*"]
-  resources: ["*"]
-  verbs: ["*"]            # VULNERABLE
+- apiGroups: [""]
+  resources: ["configmaps", "secrets"]
+  resourceNames: ["payments-api-config", "payments-api-db"]
+  verbs: ["get", "watch"]  # FIXED: named resources, read-only
```

```diff
 # deploy/payments-worker.yaml
 spec:
   template:
     spec:
+      automountServiceAccountToken: false   # FIXED: app never calls the API
       containers:
       - name: worker
         securityContext:
-          privileged: true                  # VULNERABLE
+          allowPrivilegeEscalation: false   # FIXED
+          readOnlyRootFilesystem: true
+          capabilities:
+            drop: ["ALL"]
```

```diff
 # svc/payments-api.yaml
 spec:
-  type: NodePort        # VULNERABLE: bypasses ingress tier
+  type: ClusterIP       # FIXED: served via ingress w/ TLS termination
```

## Remediation

Apply inside an approved change window; all blocks below are the target state.

### Hardened workload template

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: payments
spec:
  replicas: 2
  selector:
    matchLabels: { app: payments-api }
  template:
    metadata:
      labels: { app: payments-api }
    spec:
      serviceAccountName: payments-api
      automountServiceAccountToken: false          # no API identity unless required
      securityContext:                             # pod-level
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: api
        image: registry.example.com/payments-api:v1.4.2   # prefer immutable sha256 digest pinning
        securityContext:                           # container-level
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        resources:
          requests: { cpu: 100m, memory: 128Mi }
          limits:   { cpu: "1",  memory: 512Mi }
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
```

If the workload must call the Kubernetes API, keep automounting but scope its Role to the minimum verbs/resources shown below — never leave it defaulted AND unscoped.

### Default-deny NetworkPolicy pair with DNS exception

```yaml
# FIXED: deny-by-default for the namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
---
# FIXED: carve out DNS BEFORE enabling egress denial, or everything breaks
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-dns
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns     # verify the real selector: kubectl get svc -n kube-system kube-dns -o yaml
    ports:
    - { protocol: UDP, port: 53 }
    - { protocol: TCP, port: 53 }
```

Add per-application allow policies after DNS; stage egress denial per namespace, never fleet-wide at once (see the staged approach in the firewall-edge module philosophy).

### Least-privilege RBAC for a typical app SA

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payments-api-app
  namespace: payments
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["payments-api-config"]
  verbs: ["get", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["payments-api-db"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payments-api-app
  namespace: payments
subjects:
- kind: ServiceAccount
  name: payments-api
  namespace: payments
roleRef:
  kind: Role
  name: payments-api-app
  apiGroup: rbac.authorization.k8s.io
```

Rules of thumb while rewriting RBAC: namespaced Role over ClusterRole whenever possible; `resourceNames` where the API allows it; strip `escalate`, `bind`, `impersonate`, `serviceaccounts/token`, `pods/exec` from every workload identity; reduce human cluster-admin holders to a documented break-glass list.

### Namespace PodSecurity labels

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest   # pin a minor version in production for upgrade stability
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
```

Stage rollout: apply `warn` first, collect violations for one release cycle, fix manifests, then set `enforce`. Policy engines (Kyverno, Gatekeeper) are the established options once built-in PodSecurity ceilings are hit — evaluate them qualitatively against org requirements before adopting either.

### Kubelet / node items (pointers)

Set kubelet `authorization.mode: Webhook` and `readOnlyPort: 0` in `/var/lib/kubelet/config.yaml` on every node; treat any `AlwaysAllow` or open 10255 as High. Node SSH/OS baseline, runtime socket permissions, and patch level are owned by the linux-baseline module — hand off rather than duplicating checks here.

## Verification & Validation

### Post-fix sweeps must come back clean

Re-run the full read-only sweep block and the repo battery. Expected clean state:

- `kubectl auth can-i --list` for every workload identity shows only intended rows; no `*.*`, no escalation primitives.
- Wildcard grep returns only built-in `system:` roles; zero user-created wildcard rules.
- Zero privileged containers and zero hostPath volumes in user namespaces.
- Every user namespace shows ≥1 default-deny NetworkPolicy with both policyTypes, plus the DNS exception policy where egress is denied.
- `kubectl get ns --show-labels` shows PSA enforce labels on all user namespaces.
- NodePort listing is empty or matches the documented exception list.

### Functional verification (change window only — these commands mutate)

Positive/negative pair after enabling default-deny:

```bash
# POSITIVE control: DNS still resolves (the classic regression)
kubectl run netcheck --rm -it --restart=Never --image=busybox:1.36 -n payments \
  -- nslookup kubernetes.default.svc.cluster.local

# NEGATIVE test: cross-namespace access now blocked
kubectl run probe --rm -it --restart=Never --image=busybox:1.36 -n payments \
  -- wget -qO- --timeout=3 http://<service>.<other-ns>.svc.cluster.local || echo "BLOCKED (expected)"

# APP serves: deploy and hit the route end-to-end
kubectl rollout status deploy/payments-api -n payments
curl -fsS https://payments.example.com/healthz
```

An application that deploys, resolves DNS, and serves through ingress while cross-namespace probes fail is the pass condition. A broken DNS lookup means the egress policy lacks the UDP/TCP 53 carve-out — fix before proceeding.

### Regression watchlist

| Change | Known regression | Mitigation |
|---|---|---|
| Egress default-deny | Cluster DNS breakage — every FQDN-based connection fails, looking like an app outage | Always ship the DNS exception first; verify with nslookup positive control |
| PSA `enforce: restricted` | Legacy manifests fail admission silently in CD pipelines | Roll out warn → audit → enforce; grep pipeline logs for PodSecurity warnings during the warn phase |
| RBAC tightening | Operators/controllers (Argo CD, Prometheus Operator, cert-manager) need broad list/watch and will crash-loop | Grant scoped Roles to their SAs deliberately, verify each controller's dashboard/health after tightening, and document exceptions explicitly — scope exceptions by design, never by accident |
| automount=false flip | Workload that secretly called the API starts failing with 401 at runtime | Check app logs for API usage before flipping; provide a scoped Role if genuinely needed |

### IaC greps post-fix

```bash
# All four must return nothing outside the documented-exceptions file
rg -n --glob '*.{yaml,yml}' 'privileged:\s*true' . | rg -v exceptions.yaml
rg -n --glob '*.{yaml,yml}' 'hostPath:' . | rg -v exceptions.yaml
rg -n --glob '*.{yaml,yml}' 'type:\s*NodePort' . | rg -v exceptions.yaml
rg -n --glob '*.{yaml,yml}' 'verbs:.*"\*"|resources:.*"\*"' . | rg -v system-roles/
# And this must return hits for every user namespace directory:
rg -c --glob '*.{yaml,yml}' 'kind:\s*NetworkPolicy' .
```

## Severity Assessment

Score chains at their terminal sink. Vectors are illustrative CVSS v3.1 base anchors for triage consistency — adjust scope/privilege metrics to the environment before quoting numbers.

| Finding | Severity | Example CVSS v3.1 vector |
|---|---|---|
| Unauthenticated Kubernetes API exposure (anonymous auth + permissive bindings, or etcd/API reachable without auth) | **Critical** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) |
| docker.sock-class hostPath mounted into workload container | **Critical** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (9.2) |
| Wildcard ClusterRole bound to workload ServiceAccount | **Critical** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (9.2) |
| Bindings naming `system:unauthenticated`/`system:anonymous` with real rights | **Critical** | same family as unauthenticated exposure |
| Privileged containers in user namespaces | **High** | `AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (8.4) |
| Token-request / escalate / bind / impersonate primitives available to app SAs | **High** | `AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (8.4) |
| No default-deny NetworkPolicy in user namespaces | **Medium** | `AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L` (5.5) |
| Missing PodSecurity enforce labels (or warn-only) | **Medium** | qualitative — enables the High items above |
| Missing audit policy on self-managed control plane | **Low** | qualitative — detection gap, not direct compromise |

Cluster-admin blast radius framing — state this in every report: a single cluster-admin binding converts any foothold into total compromise of everything the cluster touches. It yields read access to all Secrets (defeating every upstream control), exec into every pod, privileged DaemonSets on every node (converting to host-fleet compromise), and persistent API objects that survive pod cleanup. When counting holders, treat each additional human beyond the break-glass list as High, each workload SA as Critical, and justify every platform identity in writing.

## Common False Positives

- **System namespaces are legitimately privileged.** `kube-system`, `kube-public`, `kube-node-lease` and platform namespaces (ingress controller, CNI, monitoring) run privileged containers, hostNetwork, and hostPath by design. Scope workload sweeps to user namespaces and maintain an explicit platform allowlist instead of reporting these as findings.
- **Built-in roles contain wildcards on purpose.** `cluster-admin` and `system:*` ClusterRoles legitimately hold `*`. Audit *bindings* and user-created roles — the existence of built-in wildcard roles is not a finding.
- **Managed control planes hide their config.** On GKE/EKS/AKS there are no static-pod manifests and no EncryptionConfiguration file visible to you. Absence of evidence is not misconfiguration: audit what your identity can see (RBAC, workloads, netpols), verify provider-managed features via provider documentation/console, and record the visibility limitation in the report.
- **Dev/staging clusters run relaxed posture legitimately.** Findings remain real but severity is contextual; document the environment boundary explicitly so relaxed dev baselines never normalize into production reviews.
- **A NetworkPolicy present ≠ default-deny.** A policy with a narrow podSelector or missing `policyTypes: Egress` leaves most traffic untouched. Verify shape (`podSelector: {}` + both policyTypes) before crediting coverage.
- **PSA warn/audit labels are advisory only.** Without the `enforce` label nothing is blocked; report warn-only namespaces as Medium, not compliant.
- **Helm values files mislead.** Chart defaults get overridden per environment; only rendered output (`helm template -f values-prod.yaml`) shows what ships.
- **Missing `runAsNonRoot` may still run non-root.** An image with a non-root `USER` directive works today but regresses silently on image swap — still record it as hardening debt, not as an active privilege finding.

## References

- Kubernetes documentation root — https://kubernetes.io/docs/home/
- Using RBAC Authorization (defines verbs incl. escalate/bind/impersonate semantics) — https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Pod Security Standards — https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Pod Security Admission (label keys and modes) — https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Configure Service Accounts for Pods (automountServiceAccountToken) — https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
- Encrypting Secret Data at Rest (EncryptionConfiguration) — https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
- Network Policies — https://kubernetes.io/docs/concepts/services-networking/network-policies/
- kube-apiserver command-line reference (man-page equivalent: flags incl. anonymous-auth, audit-policy-file, encryption-provider-config) — https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
- kubelet config reference (man-page equivalent: authorization mode, readOnlyPort) — https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
- kubectl Command Reference (man-page equivalent: auth can-i, create token) — https://kubernetes.io/docs/reference/kubectl/
- CIS Kubernetes Benchmark (Center for Internet Security) — https://www.cisecurity.org/benchmark/kubernetes
- NSA & CISA, "Kubernetes Hardening Guidance" (v1.1, August 2022; original August 2021) — https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETESHARDENINGGUIDANCE.PDF
