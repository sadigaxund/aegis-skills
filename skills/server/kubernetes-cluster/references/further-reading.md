# Kubernetes Cluster Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding domain needs authoritative backing;
SKILL.md's sweep commands and judgement tables remain the primary reference.

## RBAC & identity

- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) - normative verb/resource model, wildcard caution, default roles, and the privilege-escalation-prevention restrictions behind the primitives catalog.
- [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) - automountServiceAccountToken semantics (SA-level vs pod-level, pod wins) backing every automount check.

## Admission control

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) - the privileged/baseline/restricted control tables (hostPath bans, capability drops, runAsNonRoot) that PSA labels enforce.
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) - enforce/audit/warn mode semantics proving warn-only namespaces block nothing; label keys and version pins.

## Networking & secrets at rest

- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) - additive-policy model, default-deny shapes, and the exact DNS warning ("default deny-all egress policy also blocks DNS traffic") behind the carve-out blocker; plugin-enforcement prerequisite.
- [Encrypting Confidential Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) - confirms etcd stores plaintext without EncryptionConfiguration, provider comparison (aescbc/secretbox/kms v2), and key-custody cautions.

## Control-plane & benchmarks

- [kube-apiserver command-line reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/) - flag-level ground truth (--anonymous-auth, --encryption-provider-config, --audit-policy-file) for static-pod manifest audits on self-managed clusters.
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) - consensus baseline incl. managed-flavor editions (EKS/GKE/AKS/OKE/OpenShift) aligned with SKILL.md's rubrics.

Nothing here replaces read-only evidence rules: judge live bindings and rendered
manifests per SKILL.md first; these links corroborate flag and API semantics.
