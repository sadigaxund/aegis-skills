---
name: cloud-iam-checks
description: Audit playbook module for cloud IAM and identity misconfiguration recovered from repository and IaC artifacts - wildcard policies, confused-deputy trust policies, unconstrained iam:PassRole chains, instance/task-role versus long-lived-key posture, S3/KMS/secrets-store misconfiguration, GCP and Azure role-binding defects, privilege-escalation path reasoning, IMDS hardening, and CI/CD OIDC federation scoping.
category_slug: IAM
cwe: [CWE-250, CWE-284]
owasp: A01:2021 – Broken Access Control
---

# Cloud IAM & Identity Misconfiguration (Repo/IaC)

## Scope & Objectives

### Objective

Determine, from static artifacts alone, whether the infrastructure-as-code in the repository grants cloud identities more authority than their workloads require, or opens trust relationships to principals outside the intended boundary. For every finding produce: `file:line` evidence, the pattern class (wildcard policy, confused deputy, PassRole chain, public storage, missing encryption-at-rest default, plaintext parameter type, over-broad OIDC sub filter, and so on), a severity per the anchors in Severity Assessment, a least-privilege rewrite, and an explicit `Needs-Review` marker whenever exploitability depends on runtime facts the repository cannot prove.

### Provider weighting

AWS is primary: Terraform, CloudFormation, CDK-synthesized templates, Terraform state, user-data scripts, EKS IRSA annotations, GitHub Actions OIDC. GCP and Azure are secondary sweeps: project IAM bindings, service-account key material generation, storage IAM members, subscription-scope role assignments, shared-key storage auth, Key Vault authorization model, managed-identity adoption.

### In scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Wildcard identity policies | `"Action": "*"` / `resources = ["*"]` in inline or managed policy documents | CWE-250 |
| AdministratorAccess attachment | App-facing roles attached `arn:aws:iam::aws:policy/AdministratorAccess` | CWE-250 |
| Trust-policy defects | `Principal: "*"`, root-account trust without `sts:ExternalId`, cross-account assume-role with no conditions (confused deputy) | CWE-284 |
| Unconstrained PassRole | `iam:PassRole` on `Resource: "*"` combined with compute verbs (EC2 run, Lambda create/update, SSM session) | CWE-250 |
| Long-lived keys vs roles | Hardcoded `access_key`/`secret_key` in provider blocks; AKIA material embedded in `user_data`; credential-bearing `.tfstate` committed | CWE-798 adjacency, reported structurally here |
| S3 exposure | `acl = "public-read"`, missing `aws_s3_bucket_public_access_block`, bucket policy `Principal:"*"` + `s3:GetObject` on sensitive prefixes | CWE-284 |
| Encryption defaults | EBS/RDS/SQS/SNS resources lacking server-side encryption configuration; KMS key policies with wildcard principals | CWE-284 |
| Secrets-store misuse | Password-named SSM parameters typed `String` instead of `SecureString`; SecretsManager unused where obvious; SSM document parameters carrying secrets | CWE-284 |
| GCP bindings | `roles/Owner` to `allUsers`/`allAuthenticatedUsers`; `google_service_account_key` private-key generation in repo; bucket readers `allUsers` | CWE-284 |
| Azure assignments | Contributor/Owner at subscription scope for service principals; storage accounts with shared-key auth enabled and `default_action = "Allow"` network rules; Key Vault access-policy model instead of RBAC; missing managed identities | CWE-284 |
| Metadata hardening | EC2/launch-template `metadata_options` absent or `http_tokens = "optional"` (IMDSv1 reachable) | CWE-284 |
| CI/CD OIDC federation | Trust policies for `token.actions.githubusercontent.com` with unscoped or wildcard `sub` filters, missing audience condition | CWE-284 |

### Out of scope (cross-references)

- Secret-value fingerprinting, entropy analysis, rotation procedure -> SECRETS module. This module reports structural placement of credentials (provider block, state, user_data) and defers key-material classification.
- Application SSRF discovery and URL-validation bypasses -> SSRF module. This module consumes its conclusion ("a fetch primitive reaches instance metadata") when chaining.
- DNS dangling-resource takeover mechanics -> DNS-TAKEOVER module. Record one-line pointers only: a bucket name referenced by a third-party DNS record is that module's lead.
- Runtime cloud enumeration, live API calls against real accounts: out of scope unless the auditor has explicitly authorized read-only CLI access; see Exploitation & Reproduction for the single sanctioned verification command shape.
- Kubernetes RBAC quality -> CONFIG/AUTHZ modules; this module reads only the IRSA annotation that binds a service account to an AWS role.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **principal**: any cloud identity that can act — a user, role, or service
- **trust policy**: the document stating who is allowed to adopt a cloud role
- **confused deputy**: a trusted service tricked into spending its authority on an attacker's behalf
- **iam:PassRole**: permission to attach a role to compute, i.e., run code carrying that role's powers
- **wildcard policy**: permissions written as `"*"`, meaning every action on every resource
- **permission boundary**: a cap on the maximum authority an identity can ever hold
- **OIDC federation**: CI/cloud login via short-lived tokens instead of long-lived keys
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

### The identity plane is a directed graph

Principals (IAM users, roles, federated identities, service principals, workload identities) are nodes. Edges are "can become" relationships written in trust policies (`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`) plus delegation edges created at runtime (`iam:PassRole`). Authority is not attached to nodes alone: request-time evaluation intersects six policy layers - identity policy, resource policy (bucket/key/queue policies), permission boundary, SCP, session policy, and explicit deny anywhere. A node's effective authority is therefore contextual; audit both the node and every edge that terminates on it.

### Two defect families

1. **Static over-grant** - the node itself holds too much: wildcard actions/resources, `AdministratorAccess`, managed-policy sprawl accumulated over years. Exploitability is direct once any foothold on the principal exists.
2. **Trust mis-grant** - too many principals can become powerful nodes: `Principal:"*"`, account-root trust without conditions, missing `ExternalId`, loose OIDC subject filters. These convert outsiders or low-trust insiders into insiders without stealing anything.

Audit both families; they compound. An app role that is merely read-only becomes critical if anyone on the internet can assume it.

### Escalation primitives are an algebra

Treat each mutable-authority verb as a primitive and reason set-theoretically. Can the principal create access keys for other users? Then it is those users. Can it attach policies or put inline policies? Then it grants itself anything. Can it pass roles plus launch or update compute? Then it runs code under any role it can name. Can it update a Lambda function's code or environment? Same result. A single primitive rarely matters; two primitives chained usually equal full control. Enumerate which primitives each audited role holds before judging severity - see Patterns & Signatures for the catalog and Taint Tracing Guidance for chaining method.

### Blast radius starts from repo architecture

A role's risk equals the union of what its holders can do, mediated by how credentials reach holders. Read the architecture from the repo: which workload assumes the role (instance profile, task definition, IRSA annotation, Lambda function config), what network surface that workload exposes (public ALB? API gateway?), and whether the metadata service mediates credential retrieval (IMDSv1 fallback = trivially fetchable via any server-side fetch bug). An over-privileged role on an internet-facing workload is a different severity class than the same role on an isolated batch job. When the repo cannot prove the runtime hop, mark the chain `Needs-Review(runtime)` rather than guessing.

### State files are serialized authority

`.tfstate` records everything Terraform knows, including secret attributes of resources it manages (`aws_iam_access_key.secret`, database master passwords, generated tokens). Committed state is simultaneously a secrets spill and an infrastructure map that makes every other finding easier to exploit. Treat state hygiene as an IAM finding even though value-level triage belongs to SECRETS.

### Confused deputy, stated plainly

A vendor role trusted by many customer accounts (trust principal = customer account root, no condition keys) is exercisable by *anyone who learns the role ARN* - ARNs are not secrets. The attacker points their own tooling at the role, omits the `sts:ExternalId` the vendor would normally inject, and the assume succeeds because nothing binds the caller to a legitimate integration. The fix is a condition key, an ExternalId, or a source-VPC/source-ARN constraint - never secrecy of the ARN.

### Documentation discipline

Separate three claim strengths in findings: `Confirmed-static` (pattern + evidence + all hops provable from repo), `Needs-Review(runtime)` (hop depends on deployed state: attached profile, actual env vars, account-level IMDS default), `Needs-Review(intent)` (possible deliberate exception: break-glass role awaiting owner confirmation). Never silently upgrade a weaker claim to a stronger one.

## What To Check

Work the checklist in order; AWS items A-G are the priority sweep, H-I the secondary providers, J-L cross-cutting.

### A. Wildcard and administrator policies

1. Extract every policy document from `.tf` (`data "aws_iam_policy_document"` blocks, inline `policy = jsonencode()` bodies, heredoc policies), `.tf.json`, and CloudFormation `PolicyDocument` blocks.
2. Flag any statement whose `Action` or `Resource` is `"*"` unless it is a `Deny` statement or scoped by a condition block that meaningfully constrains it (`Condition` with `aws:SourceArn`, `s3:prefix`, and similar - read the condition, do not assume).
3. Flag managed-policy attachments of `AdministratorAccess`, `PowerUserAccess` (when compute verbs matter), or service-full-access arns (`arn:aws:iam::aws:policy/*FullAccess*`) on roles held by application workloads rather than human break-glass identities.
4. Count inline policies per role/user (`aws_iam_role_policy`, `aws_iam_user_policy`); more than two on one principal usually means drift between an intended managed policy and copy-pasted inline variants - record both versions when they differ.

### B. Trust policies and cross-account access

5. For every `AssumeRole`-bearing trust policy, resolve each principal entry: same-account role (fine), account root of another account (confused-deputy candidate), `"*"` (critical candidate), external IDP/federated provider (check conditions next).
6. Verify every cross-account trust carries at least one binding condition: `sts:ExternalId`, `aws:PrincipalOrgID`, `aws:SourceArn`, or `aws:SourceAccount`. Absence of all four = confused-deputy finding.
7. For OIDC federated trusts, verify both an audience condition (`token.actions.githubusercontent.com:aud` equals `sts.amazonaws.com` for GitHub) and a subject filter pinned to repository plus ref; treat `repo:org/*` wildcards or missing sub conditions as findings.

### C. PassRole and escalation primitives

8. Grep for `iam:PassRole`; for each occurrence read the sibling statements in the same role's policy set. Classify the pair (PassRole + which compute verb): `ec2:RunInstances`, `lambda:CreateFunction`/`lambda:UpdateFunctionCode`, `ssm:StartSession`, Glue/EMR job definitions if present.
9. Flag `iam:PassRole` whose `Resource` is not a named-role allowlist. Cross-reference the target roles' own authority to compute the reachable ceiling (see Taint Tracing Guidance step method).
10. Enumerate the remaining primitives per principal: `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `ssm:StartSession`.

### D. Instance/task roles versus long-lived keys

11. Search Terraform `provider` blocks and any `.tfvars`/overrides for hardcoded `access_key` / `secret_key` / `token` arguments. Report structurally (IaC anti-pattern) and cross-reference SECRETS for key fingerprints found elsewhere.
12. Inspect `user_data` blobs, bootstrap scripts, and container entrypoints for exported `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` values; the fix pattern is an instance profile or task role, never env-var keys.
13. Detect committed state: `*.tfstate`, `*.tfstate.backup`, `.terraform/terraform.tfstate`, and remote-state configuration pointing at unencrypted or public buckets. Note whether `aws_iam_access_key` resources exist anywhere - their secret attributes land in state verbatim.

### E. S3 posture

14. Flag literal public ACLs (`public-read`, `public-read-write`, `authenticated-read`) and CloudFormation `AccessControl: PublicRead`.
15. Diff bucket inventory against `aws_s3_bucket_public_access_block` resources; every bucket must have all four flags true or a documented exception. Absence-grep method: enumerate first, then diff - never report absence from a single negative grep.
16. Read bucket policies for `Principal:"*"` combined with `s3:GetObject`/`s3:ListBucket` on prefixes holding names like `backup`, `dump`, `pii`, `export`, `logs`, user uploads.
17. Note versioning and MFA-delete posture briefly (`aws_s3_bucket_versioning` present?) as governance observations, not standalone findings.
18. When a bucket name appears in third-party DNS records or docs, add one line pointing to the DNS-TAKEOVER module.

### F. KMS and encryption-at-rest defaults

19. Per resource type, check the encryption attribute exists: EBS `encrypted`, RDS `storage_encrypted`, SQS `sqs_managed_sse_enabled`, SNS `kms_master_key_id`, S3 `server_side_encryption_configuration`. Use the enumerate-then-diff method.
20. Read custom key policies for wildcard principals or `kms:Decrypt` granted broadly; note missing `enable_key_rotation`.
21. Apply honesty about CMK vs default SSE: AWS-managed default encryption satisfies most confidentiality goals; reserve severity for plaintext-disabled storage, never for "CMK absent".

### G. Secrets in cloud-native stores

22. Find SSM parameter resources whose names contain password/secret/token/key but whose `type` is `"String"` instead of `"SecureString"`.
23. Where the repo generates credentials (`random_password`, DB blocks), note whether they flow into SecretsManager or plain parameters/state; flag plaintext-parameter placement.
24. Scan SSM document definitions for parameters with secret-looking default values passed into commands.

### H. GCP sweep

25. Flag project/folder/org IAM bindings granting `roles/Owner`, `roles/Editor`, or `roles/iam.serviceAccountKeyAdmin` to `allUsers`, `allAuthenticatedUsers`, or domain-wide groups without justification evidence.
26. Flag `google_service_account_key` resources outright: repo-managed private-key generation is private-key material creation; recommend Workload Identity Federation.
27. Flag bucket-level IAM members `allUsers` with reader/objectViewer roles; note absence of VPC Service Controls perimeter definitions as informational only.

### I. Azure sweep

28. Flag `azurerm_role_assignment` with Contributor/Owner/User Access Administrator at subscription or management-group scope assigned to service principals; expected scope is resource-group or narrower.
29. Flag storage accounts where `shared_access_key_enabled` is true (or attribute absent, the default-enabled case) and `network_rules.default_action` is `"Allow"` or the network_rules block is missing entirely.
30. Note Key Vault authorization model: `enable_rbac_authorization = false` with legacy access policies is a governance observation; prefer RBAC.
31. Note managed-identity adoption gaps: virtual machines or app services configured with stored client secrets while lacking an `identity {}` block.

### J. Metadata-service hardening

32. For every `aws_instance` and `aws_launch_template`, require `metadata_options` with `http_tokens = "required"` and `http_put_response_hop_limit = 1`. Absence means IMDSv1 fallback remains possible (subject to unknown account-level defaults - mark accordingly).
33. Chain-note: link each IMDSv1-capable workload to the SSRF module conclusion for its codebase; IMDSv1 + SSRF = credential theft narrative, documented jointly.

### K. CI/CD OIDC federation

34. Locate OIDC provider definitions and their consuming trust policies (`arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com`); audit the sub/aud conditions per item 7.
35. Also scan `.gitlab-ci.yml` `id_tokens`, Bitbucket `oidc:` settings, and cloud deploy steps inside CI configs for equivalent over-scoping.

### L. tfstate and backend hygiene

36. Verify remote backend configuration uses encryption (`encrypt = true`), locking, and a non-public bucket; flag local backends and committed state files per item 13.

### M. Identity governance & elevation (cross-cutting)

37. PIM/JIT elevation patterns: Azure PIM role-assignment settings and AWS Identity Center elevation — standing always-active assignments where just-in-time activation is available but unused are governance findings.
38. Access recertification cadence: absence of periodic access reviews / role-minning over IAM bindings means privilege creep accumulates silently.
39. Service-principal/SaaS consent abuse surface: inventory OAuth grants and service principals holding broad delegated permissions or tenant-wide admin consent, with who consented and when.
40. Serverless execution-role least-privilege: per-function execution policies (Lambda-style) — wildcard `Action`/`Resource` on a shared execution role is the finding shape.

### N. Account separation, IaC scanning & provider detection

41. Production accounts/subscriptions/projects separated from dev/staging with distinct credentials and limited cross-account paths; a single identity that can touch both prod and CI is the escalation highway.
42. IaC scanned by policy-as-code tooling before apply: Checkov or tfsec (now part of Trivy) for Terraform, OPA/Conftest for structured config — presence check plus whether findings actually gate anything; scanners that run but never block are dashboards, not controls.
43. Provider-native threat detection enabled and routing somewhere watched: GuardDuty (AWS), Defender for Cloud / Microsoft Defender for Cloud plans (Azure), Security Command Center (GCP). Enabled-but-unread counts as PARTIAL.

## Where To Look

| Artifact | Path hints | Why it matters |
|---|---|---|
| Terraform | `**/*.tf`, `**/*.tf.json`, `**/*.auto.tfvars`, `modules/**`, `environments/**` | Primary source for policies, trusts, buckets, keys, parameters |
| Terraform state | `**/*.tfstate`, `**/*.tfstate.backup`, `.terraform/**`, backend blocks in `terraform {}` | Embedded secrets; infrastructure map; backend posture |
| CloudFormation | `**/*.yaml`, `**/*.yml`, `**/*.template.json` containing `AWSTemplateFormatVersion` or top-level `Resources:` | Policy/trust defects in YAML dialect |
| CDK output | `cdk.out/**`, `*.synth.template.json`, `asset.*.json` neighbors | Synthesized truth actually deployed, including CDK-generated role names |
| Serverless/SAM | `serverless.yml`, `template.yaml`, `policies/**` | Inline `iamRoleStatements` and `Policies` frequently wildcarded |
| Bootstrap scripts | `user_data = <<EOF`/`base64` blobs, `scripts/bootstrap*`, packer/provision shells | Env-var AKIA material; curl-to-metadata usage |
| CI/CD workflows | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `buildspec.yml` | OIDC federation scope; cloud creds in pipeline env |
| Kubernetes IRSA | `**/serviceaccount*.yaml`, Helm `values.yaml` with `eks.amazonaws.com/role-arn` annotations | Binds pod identity to an audited AWS role |
| GCP IaC | `google_*` resources in `.tf`, Deployment Manager YAML | Bindings, SA keys, storage members |
| Azure IaC | `azurerm_*` resources, `azuredeploy.json`, `**/*.bicep` | Role assignments, storage auth, Key Vault model |
| Docs adjacency | `README`, `docs/runbooks`, `infra/**` naming | Identifies break-glass roles and environment boundaries before judging |

## Patterns & Signatures

### Core wildcard hunting block

Run from repo root; all patterns are ripgrep-compatible. Treat every hit as a candidate, then read the surrounding statement before judging.

```bash
# JSON/YAML policy documents (Terraform heredocs, CFN, synthesized CDK)
rg -n '"(Action|NotAction)"\s*:\s*"\*"'            -g '*.json' -g '*.yaml' -g '*.yml' -g '*.tf'
rg -n '"(Resource|NotResource)"\s*:\s*"\*"'        -g '*.json' -g '*.yaml' -g '*.yml' -g '*.tf'
rg -n '"Principal"\s*:\s*"\*"'                     -g '*.json' -g '*.yaml' -g '*.yml' -g '*.tf'
rg -n '"AWS"\s*:\s*"\*"'                           -g '*.json' -g '*.yaml' -g '*.yml' -g '*.tf'

# HCL-native policy bodies
rg -n '(actions|resources)\s*=\s*\[.*"\*"'         -g '*.tf' -g '*.tf.json'
rg -n 'identifiers\s*=\s*\[\s*"\*"\s*\]'           -g '*.tf'
rg -n 'type\s*=\s*"AWS"' -A2 -g '*.tf' | rg 'identifiers.*\*'   # eyeball results

# High-value managed policies
rg -n 'AdministratorAccess|PowerUserAccess|FullAccess'  -g '*.tf' -g '*.json' -g '*.yaml' -g '*.yml'

# Trust and delegation edges
rg -n 'sts:AssumeRole'                             -g '*.tf' -g '*.json' -g '*.yaml' -g '*.yml'
rg -n 'iam:PassRole'                               -g '*.tf' -g '*.json' -g '*.yaml' -g '*.yml'
rg -n 'token\.actions\.githubusercontent\.com'     -g '*.tf' -g '*.json' -g '*.yaml' -g '*.yml'

# Storage posture
rg -n 'acl\s*=\s*"(public-read|public-read-write|authenticated-read)"'  -g '*.tf'
rg -n 'AccessControl:\s*(PublicRead|PublicReadWrite)'                   -g '*.yaml' -g '*.yml'

# Long-lived key structure
rg -n '(access_key|secret_key|token)\s*='          -g '*.tf'
rg -n 'AKIA[0-9A-Z]{16}'                           -g '*.tfstate*' -g '*.tfvars' -g '*.sh' -g '*.tf'
```

Absence-greps (`http_tokens`, public-access blocks, encryption attributes) cannot be single negative greps: enumerate the resource population first, then diff against the hardening attribute. Report absence only after the enumeration step.

### Identity policies

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| IAM role/user policy doc | `"Action": "*"` or `actions = ["*"]` | `rg -n '"Action"\s*:\s*"\*"'` / `rg -n 'actions\s*=\s*\["\*"\]'` | Explicit action list per service need |
| Policy resources | `resources = ["*"]` on data-plane actions | `rg -n 'resources\s*=\s*\[.*"\*"' -g '*.tf'` | ARN of specific bucket/queue/table |
| Managed attachment | `AdministratorAccess` on app role | `rg -n 'AdministratorAccess' -g '*.tf'` | Job-function or custom least-privilege policy |
| Inline sprawl | Multiple `aws_iam_role_policy` per role | `rg -n 'resource\s+"aws_iam_role_policy"' -g '*.tf'` | Consolidated versioned managed policy |

```hcl
# VULNERABLE
resource "aws_iam_role_policy" "app" {
  name = "app-policy"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# FIXED
resource "aws_iam_role_policy" "app" {
  name = "app-objectstore"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "UploadPrefixCrud"
      Effect    = "Allow"
      Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
      Resource  = [
        aws_s3_bucket.uploads.arn,
        "${aws_s3_bucket.uploads.arn}/uploads/*"
      ]
    }]
  })
}
```

Wildcard in a `Deny` statement or inside a condition-scoped allow is not automatically a finding: read the full statement first.

### Trust policies

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| Role trust | `"Principal": "*"` | `rg -n '"Principal"\s*:\s*"\*"'` | Named principals only |
| Cross-account trust | Account-root principal, zero conditions | `rg -n ':root"' -g '*.tf' -g '*.json'` plus manual condition read | Root principal + `StringEquals sts:ExternalId` (or OrgID/SourceArn) |
| OIDC trust | `sub` filter `repo:org/*` or absent | inspect every `token.actions.githubusercontent.com` hit | `aud` equals-check + `sub` pinned to repo and ref |

```hcl
# VULNERABLE - confused deputy: any caller who learns this ARN can assume
data "aws_iam_policy_document" "vendor_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::210987654321:root"]
    }
  }
}

# FIXED - ExternalId binds the caller to the legitimate integration
data "aws_iam_policy_document" "vendor_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::210987654321:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["9f1c3a7e-52d4-4b6a-8e0f-77c2b91d4a03"]  # random per customer, never reused
    }
  }
}
```

### PassRole chains

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| PassRole scope | `iam:PassRole` with `Resource: "*"` | `rg -n 'iam:PassRole' -C4 -g '*.tf'` then read Resource | Allowlist exact target-role ARNs |
| PassRole pairs | Combined with `ec2:RunInstances` / `lambda:*` / `ssm:StartSession` | same, read sibling statements | Separate deploy roles from runtime roles |

```hcl
# VULNERABLE - holder can run code under any role in the account
statement {
  actions   = ["iam:PassRole", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"]
  resources = ["*"]
}

# FIXED - pass exactly one named role to exactly one consumer
statement {
  sid       = "PassSpecificRuntimeRole"
  actions   = ["iam:PassRole"]
  resources = [aws_iam_role.fn_runtime.arn]
}
statement {
  sid       = "ManageOwnFunction"
  actions   = ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"]
  resources = [aws_lambda_function.worker.arn]
}
```

### S3 posture

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| Bucket ACL | `acl = "public-read"` literals | `rg -n 'acl\s*=\s*"public-read'` | ACL omitted; object ownership set; PAB enforced |
| Public access | Missing `aws_s3_bucket_public_access_block` | enumerate buckets, diff against `rg -l 'aws_s3_bucket_public_access_block'` | All four PAB flags true |
| Bucket policy | `Principal:"*"` + `s3:GetObject` on sensitive prefix | read every bucket policy JSON | Condition-bound or named principals; OAC for CDN delivery |
| Governance | No versioning block | `rg -n 'resource\s+"aws_s3_bucket_versioning"'` vs bucket list | Versioning on state/data buckets; MFA-delete where justified |

```hcl
# VULNERABLE
resource "aws_s3_bucket" "exports" {
  bucket = "acme-prod-pii-exports"
  acl    = "public-read"
}

# FIXED - hardened pair (bucket + full public access block)
resource "aws_s3_bucket" "exports" {
  bucket = "acme-prod-pii-exports"
}
resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Encryption defaults

| Resource | Risky pattern | Detection method | Hardened pattern |
|---|---|---|---|
| EBS volume | `encrypted` attribute absent | enumerate `aws_ebs_volume`, diff vs `encrypted` | `encrypted = true` + KMS key id |
| RDS instance | `storage_encrypted` absent/false | enumerate `aws_db_instance`, diff vs `storage_encrypted` | `storage_encrypted = true` |
| SQS queue | `sqs_managed_sse_enabled` absent/false | enumerate queues, diff | `sqs_managed_sse_enabled = true` (or CMK `kms_master_key_id`) |
| SNS topic | `kms_master_key_id` absent | enumerate topics, diff | `kms_master_key_id` set for sensitive topics |
| KMS key | Key policy grants `kms:Decrypt` to `"*"` principal; rotation off | read every `aws_kms_key` policy | Named principals; `enable_key_rotation = true` |

Honesty rule: absence of a customer-managed CMK is not itself a finding when AWS-managed default SSE covers the resource; flag plaintext-capable configurations and unrotatable long-lived keys instead.

### Secrets stores

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| SSM parameter | Password-named param typed `String` | `rg -in 'name\s*=\s*"[^"]*(password\|secret\|token\|api[-_]key)[^"]*"' -g '*.tf'` then read sibling `type` | `type = "SecureString"` + `key_id` |
| SecretsManager | Generated creds bypass it into params/state | trace `random_password` consumers | `aws_secretsmanager_secret_version` or SecureString |
| SSM document | Secret-looking parameter defaults fed to commands | read document definitions | Runtime-supplied parameters; no default secrets |

```hcl
# VULNERABLE
resource "aws_ssm_parameter" "db_password" {
  name  = "/prod/db/master_password"
  type  = "String"
  value = random_password.db.result
}

# FIXED
resource "aws_ssm_parameter" "db_password" {
  name   = "/prod/db/master_password"
  type   = "SecureString"
  key_id = aws_kms_key.ssm.arn
  value  = random_password.db.result
}
```

Note either way: `value` lands in tfstate; backend encryption (item L) is the compensating control.

### GCP signatures

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| Project binding | Owner/Editor to `allUsers`/`allAuthenticatedUsers` | `rg -n 'allUsers\|allAuthenticatedUsers' -g '*.tf'` | Named groups/domains; least-privilege custom roles |
| SA keys | `google_service_account_key` present | `rg -n 'google_service_account_key' -g '*.tf'` | Workload Identity Federation; no downloaded keys |
| Bucket IAM | `allUsers` reader on storage bucket | same allUsers grep, read member lists | Uniform bucket-level access + named bindings |

```hcl
# VULNERABLE
resource "google_project_iam_binding" "owner" {
  project = var.project_id
  role    = "roles/Owner"
  members = ["allAuthenticatedUsers"]
}

# FIXED
resource "google_project_iam_binding" "deployer" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  members = ["group:ci-deployers@example.com"]
}
```

VPC Service Controls absence: informational note only - record that no access-context-manager/perimeter definitions exist in-repo.

### Azure signatures

| Resource | Risky pattern | Detection grep | Hardened pattern |
|---|---|---|---|
| Role assignment | Contributor/Owner at subscription or management-group scope for a service principal | `rg -n 'role_definition_name\s*=\s*"(Contributor\|Owner\|User Access Administrator)"' -g '*.tf'` then read `scope` | Resource-group or narrower scope; least-privilege role |
| Storage auth | Shared-key auth enabled + open network rules | `rg -n 'shared_access_key_enabled\|default_action' -g '*.tf'` | `shared_access_key_enabled = false`; `default_action = "Deny"` |
| Key Vault | Legacy access-policy model | `rg -n 'enable_rbac_authorization' -g '*.tf'` | `enable_rbac_authorization = true` |
| Workload identity | Stored SP secrets, no `identity {}` | enumerate vm/appservice blocks, diff vs `identity` | System-assigned managed identity |

```hcl
# VULNERABLE
resource "azurerm_storage_account" "app" {
  name                     = "acmeappstorage001"
  resource_group_name      = azurerm_resource_group.app.name
  location                 = azurerm_resource_group.app.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # no network_rules block -> default_action effectively Allow; shared key enabled by omission
}

# FIXED
resource "azurerm_storage_account" "app" {
  name                      = "acmeappstorage001"
  resource_group_name       = azurerm_resource_group.app.name
  location                  = azurerm_resource_group.app.location
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  shared_access_key_enabled = false
  network_rules {
    default_action             = "Deny"
    virtual_network_subnet_ids = [azurerm_subnet.app.id]
  }
  identity { type = "SystemAssigned" }
}
```

### Metadata-service and workload identity

| Resource | Risky pattern | Detection method | Hardened pattern |
|---|---|---|---|
| EC2 / launch template | `metadata_options` absent, or `http_tokens = "optional"` | enumerate instances/templates, diff vs `http_tokens` | `http_tokens = "required"`, hop limit 1 |
| user_data bootstrap | Exported AKIA env vars | `rg -n 'AWS_ACCESS_KEY_ID\|AWS_SECRET_ACCESS_KEY'` across scripts/heredocs | Instance profile; no static keys |
| IRSA annotation | Pod bound to over-privileged role | `rg -rn 'eks\.amazonaws\.com/role-arn' -g '*.yaml'` then audit target role | Dedicated per-workload role |

```hcl
# VULNERABLE - IMDSv1 fallback reachable from any SSRF-prone process
resource "aws_instance" "app" {
  ami           = var.ami
  instance_type = "m5.large"
  iam_instance_profile = aws_iam_instance_profile.app.name
}

# FIXED
resource "aws_instance" "app" {
  ami                  = var.ami
  instance_type        = "m5.large"
  iam_instance_profile = aws_iam_instance_profile.app.name
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
```

### CI/CD OIDC federation

| Resource | Risky pattern | Detection method | Hardened pattern |
|---|---|---|---|
| GitHub OIDC trust | No sub condition at all | inspect every provider trust policy | `StringLike sub = repo:<org>/<repo>:ref:refs/heads/main` |
| Loose sub | `repo:org/*` (any branch/fork path) | same inspection | Pin ref; use environment claim for deploy gates |
| Audience | Missing aud check | same inspection | `StringEquals token.actions.githubusercontent.com:aud = sts.amazonaws.com` |

The canonical GitHub subject format is `repo:<org>/<repo>:ref:refs/heads/<branch>`; pin both repository and branch, and gate production deploys through GitHub Environments so the subject becomes the environment form instead.

## Taint Tracing Guidance

IAM auditing traces two taint classes through static artifacts: credential material (where do keys live) and authority flow (who can become whom).

### Credential-material tracing

1. **Sources**: provider-block arguments, `.tfvars` files, committed state files, user_data heredocs, bootstrap scripts, CI environment blocks, `random_password`/key resources whose outputs are serialized into parameters or state.
2. **Propagation**: follow Terraform references (`var.x`, `resource.a.b`) across modules; resolve variable defaults in `variables.tf` before flagging; remember heredoc string interpolation can embed secrets into scripts.
3. **Sinks**: anything persisted or logged - git-tracked files, container images built from repo scripts, CI logs echoing env vars.
4. Report placement findings here (structure); report value fingerprints and rotation steps via SECRETS module. Never quote a live secret value; show first four characters plus `…REDACTED`.

### Authority-flow tracing

1. Build the "can become" graph: for each role, parse its trust policy into edges (principal -> this role), annotating conditions found (`ExternalId`, OrgID, sub filters).
2. Build the delegation map: for each `iam:PassRole`, record holder -> passed-role edge plus the compute verbs co-located in the same policy statement set.
3. Seed nodes: internet-reachable workload roles identified from load balancer/API gateway/public-subnet wiring in the same repo; CI pipeline identities; any principal already flagged in credential tracing.
4. Walk outward: from a seed, enumerate primitives it holds (catalog above). Each primitive either grants data access directly or creates new graph edges (PassRole -> target role's full policy set; UpdateAssumeRolePolicy -> arbitrary trust rewrite). Continue until reaching administrator-equivalent verb sets or exhaustion.
5. Classify every hop: provable from repo = static fact; dependent on deployed state (profile actually attached, function actually exists, account-level IMDS default) = `Needs-Review(runtime)`.

### Cross-file resolution discipline

- Module variables hide literals: chase `policy_json = var.foo` to caller values before declaring a policy clean.
- CDK synthesizes role names (`cdk.out/*.template.json`): audit the synthesized output as ground truth when present, since hand-written intent may differ.
- When two sources disagree (module default vs override), the effective value is the one wired at the call site; cite both file locations.

## Exploitation & Reproduction

All reasoning below is static. No live-cloud commands are required for this module; running anything against a real account requires explicit read-only CLI authorization from the owner. If such authorization exists, the canonical verification tool is `aws iam simulate-principal-policy` (shape given at the end of this section).

### Walkthrough 1: AdministratorAccess on an app-facing role

Sample vulnerable file (as commonly recovered from an app repo):

```hcl
# example/main.tf  -- VULNERABLE
data "aws_iam_policy_document" "app_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "prod_app_role" {
  name               = "prod-app-role"
  assume_role_policy = data.aws_iam_policy_document.app_trust.json
}

resource "aws_iam_role_policy_attachment" "app_admin" {
  role       = aws_iam_role.prod_app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_instance" "api" {
  ami                  = var.api_ami
  instance_type        = "m5.large"
  iam_instance_profile = aws_iam_instance_profile.prod_app.name
  # no metadata_options block -> IMDSv1 fallback possible
}
```

Static reasoning procedure:

1. Identify the identity: `aws_iam_role.prod_app_role` is assumed by EC2 (trust statement) and attached to instance profile `prod_app`, which is bound to `aws_instance.api`.
2. Determine exposure of the holder: `api` has no `metadata_options`; unless account-level defaults enforce IMDSv2 (unknowable from repo - mark `Needs-Review(runtime)`), instance metadata responds over plain HTTP.
3. Determine authority: the single attachment is `AdministratorAccess`, i.e., action/resource wildcard across all services. There is no permission boundary resource on the role.
4. Compose the chain: any server-side request forgery in the API process (verify against SSRF module findings for this codebase) reaches `169.254.169.254/latest/meta-data/iam/security-credentials/prod-app-role` and returns session credentials for the role.
5. Compute impact from the credentials: AdministratorAccess means the holder can create IAM users and keys, modify trust policies, attach policies, and touch every data plane in the account. Full account compromise from one unauthenticated web request.
6. Record: severity Critical per anchors; evidence lines are the attachment block plus the missing metadata_options; runtime caveat noted on step 2.

### Walkthrough 2: unconstrained PassRole escalation chain

Sample vulnerable policy fragment held by a CI deploy role:

```hcl
# example/ci.tf  -- VULNERABLE
data "aws_iam_policy_document" "ci_deploy" {
  statement {
    sid       = "DeployAnything"
    effect    = "Allow"
    actions   = [
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "iam:PassRole",
    ]
    resources = ["*"]
  }
}
```

Static reasoning procedure:

1. Enumerate primitives: update Lambda code, update Lambda configuration (including environment variables and - critically - the function's execution role), pass any role.
2. Pick the ceiling: list account roles visible in the repo's own IaC; suppose `aws_iam_role.payments_job` holds `s3:*` on a PII bucket and `dynamodb:*` on customer tables (read those policies from the same repo).
3. Chain: holder passes `payments_job` onto any existing Lambda function via `lambda:UpdateFunctionConfiguration`, then replaces the function payload via `lambda:UpdateFunctionCode`.
4. Trigger: invoking the function (the holder can invoke functions it updated if `lambda:InvokeFunction` is present; otherwise the next scheduled trigger executes the payload) runs attacker code under `payments_job`, reading the PII bucket and tables without ever holding those permissions directly.
5. Note the algebra: neither primitive alone reaches the data; PassRole alone needs a compute sink; UpdateFunctionCode alone keeps the old execution role. The pair equals the union of all passable roles' authorities.
6. Record: High per anchors (latent chain requiring foothold on the CI identity); mark step 4's invocation assumption `Needs-Review(runtime)` if no invoke permission is visible.

### SSRF-to-IMDS narrative (cross-reference)

When the SSRF module confirms a fetch primitive on a workload holding role R: fetch primitive -> instance metadata endpoint -> role-R session credentials -> R's full authority exfiltrated off-box. This module contributes R's policy analysis and the IMDSv1/v2 gate status; the SSRF module owns the fetch-primitive evidence. Write the joint chain once, in whichever module carries the confirmed entry point, and cross-link both finding IDs.

### Authorized-CLI verification shape (only with explicit read-only approval)

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/prod-app-role \
  --action-names s3:GetObject iam:CreateUser iam:PassRole ssm:StartSession \
  --resource-arns arn:aws:s3:::acme-prod-pii-exports/uploads/object1 \
  --output json
```

Read each `EvaluationResult.EvalDecision`. Run `aws iam simulate-principal-policy --help` first: option names and supported condition handling vary by CLI version, and the caller needs `iam:SimulatePrincipalPolicy` permission on the target ARN. Expect `allowed` only for intended data-plane pairs and `implicitDeny` for escalation primitives.

## Remediation

### Least-privilege rewrites for common service needs

S3 - CRUD on one bucket prefix:

```json
# FIXED
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListUploadPrefix",
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::acme-app-uploads",
      "Condition": { "StringLike": { "s3:prefix": ["uploads/*"] } }
    },
    {
      "Sid": "CrudUploadObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::acme-app-uploads/uploads/*"
    }
  ]
}
```

SQS - send/receive on one queue:

```json
# FIXED
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes"
    ],
    "Resource": "arn:aws:sqs:us-east-1:111122223333/app-jobs"
  }
}
```

DynamoDB - table-scoped CRUD including its indexes:

```json
# FIXED
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
      "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"
    ],
    "Resource": [
      "arn:aws:dynamodb:us-east-1:111122223333/table/orders",
      "arn:aws:dynamodb:us-east-1:111122223333/table/orders/index/*"
    ]
  }
}
```

### Trust-policy template with ExternalId

For vendor-style cross-account access. Generate one random ExternalId per customer (128-bit); never reuse across customers, never store it where customers can read other tenants' values:

```json
# FIXED
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::210987654321:root" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "9f1c3a7e-52d4-4b6a-8e0f-77c2b91d4a03" }
    }
  }]
}
```

Prefer `aws:PrincipalOrgID` when both sides are in one AWS Organization, and `aws:SourceArn`/`aws:SourceAccount` for service-invoked roles.

### Scoped CI/CD OIDC trust

Full hardened GitHub Actions trust policy - audience check plus repository-and-branch-pinned subject:

```json
# FIXED
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:acme-org/payments-api:ref:refs/heads/main"
      }
    }
  }]
}
```

Grant this role only the deployment verbs it needs; keep it off escalation primitives entirely.

### State backend hygiene

Remote encrypted locked backend replaces local/committed state:

```hcl
# FIXED
terraform {
  backend "s3" {
    bucket         = "acme-tfstate-prod"
    key            = "prod/network.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/tfstate"
    dynamodb_table = "tfstate-locks"   # Terraform >= 1.10 may use use_lockfile = true instead
  }
}
```

Add a public-access block on the state bucket, purge committed `.tfstate*` from git history, rotate every credential that ever touched state.

### GCP and Azure hardening

- Replace every `google_service_account_key` with Workload Identity Federation; representative shape:

```hcl
# FIXED (consult provider docs for the full argument set)
resource "google_iam_workload_identity_pool" "ci" {
  workload_identity_pool_id = "github-ci-pool"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.ci.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  attribute_condition                = "assertion.repository == \"acme-org/payments-api\""
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
```

- Azure: scope role assignments to resource-group level, set `shared_access_key_enabled = false`, `default_action = "Deny"` plus explicit allows, `enable_rbac_authorization = true`, and adopt system-assigned identities over stored client secrets.
- GCP bindings: replace broad member sets with named groups/domains and prefer predefined narrow roles (`roles/storage.objectAdmin`) or custom roles over Owner/Editor.

### Migration discipline

Never swap an app role's policy in one commit. Attach the new least-privilege policy alongside the legacy attachment, observe CloudTrail `AccessDenied` events attributable to the role for one to two weeks of normal operation, fix gaps, then remove the legacy attachment. Apply IMDSv2 enforcement per instance family after confirming agents support token-based metadata.

## Verification & Validation

### Post-fix grep sweeps

Rerun the signature greps from Patterns & Signatures and require zero hits (or reviewed-and-accepted exceptions) for:

```bash
rg -n '"Action"\s*:\s*"\*"' -g '*.tf' -g '*.json' -g '*.yaml' -g '*.yml'
rg -n 'AdministratorAccess' -g '*.tf' -g '*.json'
rg -n 'acl\s*=\s*"public-read' -g '*.tf'
rg -n 'iam:PassRole' -C4 -g '*.tf'          # every hit must show a named-role Resource list
rg -n 'AKIA[0-9A-Z]{16}' -g '*.tfstate*'    # after history purge: zero hits
rg -n 'google_service_account_key' -g '*.tf'
```

For absence-class findings, rerun the enumeration-then-diff: bucket list vs public-access-block resources; instance/launch-template list vs `http_tokens = "required"`; EBS/RDS/SQS/SNS lists vs their encryption attributes. Every enumerated resource must appear in the hardened set.

### Simulated-policy expected matrix

With authorized read-only CLI, the fixed `prod-app-role` should simulate as follows (decisions are literal `EvalDecision` values):

| Action | Resource | Expected decision |
|---|---|---|
| s3:GetObject | arn:aws:s3:::acme-app-uploads/uploads/x | allowed |
| s3:GetObject | arn:aws:s3:::acme-app-uploads/backups/x | implicitDeny |
| iam:CreateUser | * | implicitDeny |
| iam:PassRole | arn:aws:iam::111122223333:role/payments_job | implicitDeny |
| ssm:StartSession | * | implicitDeny |
| sqs:SendMessage | arn:aws:sqs:us-east-1:111122223333/app-jobs | allowed |

### Negative tests

- The deploy pipeline runs green end-to-end on a feature branch (plan + apply + smoke stage).
- Application smoke suite passes against a staging environment built from the fixed IaC: object upload/download on its prefix, queue send/receive, table read/write.
- CI deploy job using the scoped OIDC role completes; an attempt from any other branch or repo fails with a trust-policy denial recorded in CloudTrail.

### Regression discipline

Over-tightening breaks runtime features that only manifest in production traffic paths. Stage rollouts: new policy alongside old, watch CloudTrail `AccessDenied` for the role across one to two full business cycles, close gaps, then remove legacy attachments. Never verify IAM changes by "deploy worked once" alone; data-plane verbs used by background jobs surface days later.

## Severity Assessment

Rate latent misconfigurations by the best statically-reasonable chain, not by the config line in isolation; downgrade one tier when no holder is reachable from any identified entry point and mark `Needs-Review(runtime)`.

| Anchor | Example finding | CVSS v3.1 vector | Score |
|---|---|---|---|
| Critical | AdministratorAccess attached to internet-facing app role (Walkthrough 1) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| Critical | Hardcoded cloud access keys committed to repo/state (live keys) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| Critical | Public bucket holding PII markers with anonymous write/list also enabled | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N | 9.3 |
| High | Unconstrained iam:PassRole paired with compute verbs on a foothold-prone identity | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H | 8.5 |
| High | Wildcard trust principal / cross-account assume-role missing all binding conditions | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H | 8.5 |
| Medium | Missing encryption-at-rest defaults (EBS/RDS/SQS/SNS without SSE configuration) | CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 5.7 |
| Medium | Loose OIDC trust scoping (org-wide sub wildcard, no branch pin) | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N | 5.9 |
| Low | Governance gaps: tagging policy absent, versioning/MFA-delete posture notes | CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N | 2.7 |

Scoring honesty notes: a strictly read-only public bucket scores 8.6 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`); classify it Critical only when anonymous listing/writing exists or bulk regulated data is exposed - otherwise report High with the chaining condition stated. Chaining is the multiplier: a High latent primitive on an SSRF-reachable workload inherits the entry point's PR:N reachability and should be re-scored upward with the joint finding documented in both modules.

## Common False Positives

- **Break-glass roles intentionally privileged.** `AdministratorAccess` on a named human break-glass role with evidence of an approval workflow (documented activation procedure, MFA requirement, alerting, time-boxed sessions) is accepted design. Require the workflow evidence in-repo or in runbooks before crediting; without evidence, it stays a finding at reduced confidence.
- **Sandbox and development accounts.** Relaxed posture in an account documented as a non-production boundary (separate account id, no production data flows, no peering to prod) is a governance observation, not a Critical exposure. Verify the boundary is real: check provider profiles, state keys, and naming for account separation; if prod and dev share one account, the "dev" excuse evaporates.
- **Permission boundaries applied elsewhere in the stack.** A role whose identity policy looks wild may carry `permissions_boundary` referencing a restrictive managed policy, or sit under SCPs limiting effect. Verify the boundary resource exists and read it before crediting the mitigation - a boundary that itself allows `*` changes nothing.
- **Wildcard inside Deny statements or conditions.** `"Action": "*"` under `"Effect": "Deny"` or within condition-gated statements (for example `aws:PrincipalOrgID` scoped) is hardening, not exposure.
- **`Principal: "*"` behind enforced public-access blocks.** A bucket policy wildcard principal combined with all-four-true `aws_s3_bucket_public_access_block` and a condition block can still be private; confirm the PAB resources exist and apply to that bucket before flagging as public.
- **CDK bootstrap artifacts.** Synthesized CDK bootstrap roles (`cdk-hnb659fds-*`) look over-permissive but are deployment machinery bounded by the CDK CLI's own scoping; flag only when they are assumable by untrusted principals.

## References

- AWS Identity and Access Management User Guide - https://docs.aws.amazon.com/iam/
- AWS IAM best practices - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- IAM roles (trust policies, delegation) - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
- The confused deputy problem and ExternalId - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
- IAM Access Analyzer - https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- EC2 instance metadata service configuration (IMDSv2) - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Amazon S3 Block Public Access - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- Terraform AWS provider documentation root - https://registry.terraform.io/providers/hashicorp/aws/latest/docs
- Terraform Google provider documentation root - https://registry.terraform.io/providers/hashicorp/google/latest/docs
- Terraform Azure provider documentation root - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs
- Google Cloud IAM documentation - https://cloud.google.com/iam/docs
- Azure RBAC documentation - https://learn.microsoft.com/azure/role-based-access-control/
- GitHub Actions OIDC cloud-configuration docs - https://docs.github.com/actions
- CIS Benchmarks portal (CIS Amazon Web Services Foundations Benchmark; CIS Google Cloud Computing Foundations Benchmark; CIS Microsoft Azure Foundations Benchmark) - https://www.cisecurity.org/cis-benchmarks
- CWE-250: Execution with Unnecessary Privileges - https://cwe.mitre.org/data/definitions/250.html
- CWE-284: Improper Access Control - https://cwe.mitre.org/data/definitions/284.html
- OWASP Top 10 2021 A01: Broken Access Control - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- Tooling for policy-diff support during audits: AWS IAM Access Analyzer, cloudsplaining (salesforce/cloudsplaining), PMapper (nccgroup/PMapper)


