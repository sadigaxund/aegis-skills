# Kubernetes Cluster Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind API-server exposure, RBAC escalation primitives,
PodSecurity labels, NetworkPolicy posture, securityContext coverage, secret
handling, and ingress/NodePort exposure; SKILL.md carries the exact sweeps,
judgement tables, and hardened manifests.

## How this class emerged

Kubernetes was open-sourced by Google in June 2014 as a container orchestrator
descended from its internal Borg system. Its founding assumption was a trusted
internal cluster inside one company's network: a flat pod network where any
pod could reach any pod, credentials mounted into every workload for
convenience, and authorization designed around "the platform team is the only
tenant." Security controls arrived later, layered onto that foundation:

- **RBAC generalized slowly.** The first releases used attribute-based rules;
  role-based access control reached general availability in v1.8 (2017).
  Even then, *bindings* — who wears which role — remained operator choices,
  and the default ServiceAccount token kept automounting into every pod.
- **The network stayed flat until someone denied it.** The NetworkPolicy API
  existed early, but enforcement depends entirely on the CNI plugin, and the
  default posture everywhere is allow-all. Per-namespace default-deny remains
  something each team must deliberately build — including the DNS exception,
  whose absence has broken more egress rollouts than any other single mistake.
- **Pod policy churned through generations.** PodSecurityPolicy tried to gate
  privileged workloads at admission but was hard to configure and was removed
  in v1.25 (2022), replaced by Pod Security Admission driven by namespace
  labels (privileged / baseline / restricted). Clusters straddle all three
  eras, which is why audits detect PSP remnants rather than audit them.
- **Publicized breaches set the checklist.** Cryptojacking intrusions via
  unauthenticated dashboards and exposed APIs became notorious in 2018;
  incident reports repeatedly showed the same chain: one open surface → a
  mounted service-account token → escalation via permissive RBAC → cluster
  takeover. Guidance bodies codified the countermeasures (CIS Benchmark, NSA/
  CISA hardening guidance), all converging on least-privilege identities,
  default-deny networking, and locked-down workload specs.

The recurring lesson: Kubernetes defaults optimize for workloads running, not
for surviving a compromised workload. Every check in this module exists
because some default quietly hands capability to whoever gets a foothold.

## Anatomy: one wildcard binding, one owned cluster

A minimal generic weak configuration needs two objects. Picture a product
team's deployment:

```
# ClusterRole bound to the app's ServiceAccount:
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]                    # VULNERABLE: total power for a cache worker

# Deployment omits automountServiceAccountToken  ->  defaults ON:
#   token projected at /var/run/secrets/kubernetes.io/serviceaccount/token
```

Walkthrough of how this fails:

1. The worker container is compromised through an application bug (or pulls a
   poisoned image). Whoever runs commands inside reads the mounted token.
2. That token now speaks to the API server with wildcard authority: read every
   Secret in every namespace (database URLs, API keys, TLS keys), exec into
   any pod, schedule privileged DaemonSets on every node.
3. Escalation needs no further bugs — `create pods` alone means scheduling a
   pod that mounts stronger identities; `pods/exec` means walking into them.
4. Persistence is trivial: new ClusterRoleBindings survive pod cleanup.
5. Because the network is flat, no NetworkPolicy ever interrupted lateral
   movement between the first foothold and etcd's crown jewels.

No kernel exploit appears anywhere in that chain. Identity was a mounted
file; authorization said yes. Severity follows the ceiling of what the chain
reaches — cluster-admin — not the lowly worker where it started.

## Why naive fixes fail

- **Flipping namespaces straight to `enforce: restricted`.** Legacy manifests
  fail admission silently in CD pipelines; production deploys break at
  2 a.m. Roll out warn → audit → enforce over a release cycle instead.
- **Default-deny egress without the DNS carve-out.** Denying egress without
  allowing UDP/TCP 53 to kube-dns breaks name resolution cluster-wide — every
  FQDN-based connection dies, looking like a full outage. Ship the DNS
  exception FIRST, prove resolution, then deny.
- **Removing automount from workloads that secretly call the API.** They fail
  at runtime with 401s. Check application logs before flipping; provide a
  scoped Role when the need is genuine.
- **Deleting wildcard Roles that controllers depend on.** Argo CD, Prometheus
  Operator, cert-manager and friends legitimately need broad list/watch and
  will crash-loop without it. Tighten with scoped grants per controller and
  verify each dashboard afterward.
- **Auditing `kube-system` as if it were a user namespace.** Platform
  namespaces run privileged containers, hostNetwork, and hostPath by design.
  Sweep user namespaces; keep an explicit platform allowlist.
- **Treating built-in wildcard roles as findings.** `cluster-admin` holds `*`
  legitimately. The finding is a *binding* — especially any workload identity
  wearing it — not the existence of the role.
- **Assuming managed control planes are configured well because they are
  invisible.** On GKE/EKS/AKS there are no static-pod manifests to grep.
  Absence of evidence is not evidence of safety; verify provider features
  through provider channels and record the visibility limit honestly.
- **Fixing the repo but not the live cluster (or vice versa).** Drift between
  Git intent and applied state means someone applied out-of-band; both views
  must reconcile or neither counts.

## Common misconceptions

1. "RBAC is enabled, so we're authorized properly." RBAC is machinery; the
   bindings are the policy. A cluster with RBAC on and cluster-admin bound to
   ten workload identities is less safe than one audited carefully.
2. "NetworkPolicies apply by default." No policy selecting a pod means fully
   open traffic to it — and even deployed policies do nothing unless the CNI
   enforces them. Shape matters too: narrow selectors or missing Egress
   policyTypes leave most traffic untouched.
3. "`warn` labels protect us." Warn/audit PSA modes advise; nothing blocks.
   Only `enforce` gates admission — warn-only namespaces are Medium findings.
4. "Secrets are encrypted in etcd." Base64 is encoding, not encryption. Until
   EncryptionConfiguration (or a provider feature) is active, anyone reading
   etcd bypasses RBAC entirely.
5. "Namespaces are security boundaries." They partition objects and policy
   scope, but a flat network plus cross-namespace RBAC makes them conveniences,
   not walls, until default-deny and scoped roles make them real.
6. "cluster-admin for CI is fine — it's internal." Internal is exactly where
   SSRF and supply-chain compromises land; one wildcard binding converts any
   foothold into everything the cluster touches, including all Secrets.
7. "PodSecurityPolicy still guards our old cluster." PSP was removed in v1.25;
   served PSP objects mark a legacy cluster needing migration, not protection.

## How professionals think about it today

Every capability is an API request — verb on resource in scope — so the audit
reads the request path: Authentication → Authorization → Admission → etcd.
Findings map to SKILL.md's eight domains:

| Domain | Typical gap | Defining control |
|---|---|---|
| Cluster access & API server | anonymous reachability, kubeconfig sprawl | behavioral probes, 600 kubeconfigs, etcd client certs |
| RBAC | wildcards, escalation primitives, holder count | named resources, verbs scoped, break-glass list |
| Admission & policy | unlabeled/warn-only namespaces | enforce labels staged warn→audit→enforce |
| Workload securityContext | privileged containers, hostPath sockets | runAsNonRoot, no privilege escalation, ro-rootfs |
| NetworkPolicy posture | zero default-deny; DNS gotcha | podSelector:{} + both policyTypes + UDP/TCP 53 carve-out |
| Secrets handling | env-var copies of high-value values | volume mounts, etcd encryption, external operators |
| Ingress/LB exposure | NodePort sprawl bypassing TLS tier | ClusterIP behind ingress, deliberate LB annotations |
| Node baseline pointers | kubelet AlwaysAllow, open 10255 | Webhook mode, readOnlyPort 0, linux-baseline hand-off |

Chain scoring is the discipline that separates professionals: trace taint
sources forward (what can this token reach?) and backward (who touches this
sink?), report chains at their terminal sink, and treat cluster-admin blast
radius as the standing worst case.

## Read next

In `../SKILL.md`: **Scope & Objectives**, **Prerequisites & Vocabulary**,
**Mental Model** (request-path diagram and five consequences), **What To
Check** (nine numbered sections incl. the primitives catalog),
**Where To Look** (surface table incl. Helm-rendered truth), **Patterns &
Signatures** (manifest battery, VULNERABLE/FIXED pairs), **Taint Tracing
Guidance**, **Exploitation & Reproduction** (`auth can-i --list` reading
guide, static chains), **Remediation** (hardened template, default-deny pair,
PSA labels), **Verification & Validation** (positive/negative controls),
**Severity Assessment**, **Common False Positives**, **References**.

Sibling modules: `../linux-baseline/SKILL.md` (node OS baseline hand-off),
`../service-sandboxing/SKILL.md` (deeper per-process containment below the pod
level), `../logging-monitoring/SKILL.md` (API audit policy and event review
discipline), `../api-token-security/SKILL.md` (token lifecycle analogies for
ServiceAccount tokens), `../firewall-edge/SKILL.md` (staged observe→allow→deny
egress philosophy), `../backup-dr/SKILL.md` (etcd snapshot custody).
