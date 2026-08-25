# Cloud IAM & Identity Misconfiguration — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, regexes, and per-provider fix recipes.

## How this class emerged

Cloud computing replaced a physical security model with a policy model. Before
the cloud, "who can touch this machine" was answered by network segments, locked
server rooms, and operating-system accounts. When infrastructure became API
calls in the late 2000s and early 2010s, that answer had to be rewritten as JSON
documents: identity policies saying what a principal may do, trust policies
saying who may adopt a role, and resource policies attached to storage and
keys. Every physical boundary became a line of configuration.

Three forces turned this rewrite into a durable bug class:

- **Scale of delegation.** A single organization routinely creates thousands of
  principals across dozens of accounts. Hand-writing least-privilege policies
  for each does not fit human review bandwidth, so wildcards creep in — first as
  scaffolding during prototyping, then forever.
- **Asymmetric teardown.** Creating a role, a bucket, or a trust relationship is
  one Terraform block; noticing later that it grants too much requires reading
  six intersecting documents. Over-grants are invisible until someone looks.
- **The credential-delivery problem.** Workloads need credentials to act. The
  earliest pattern — long-lived keys pasted into config files — leaked through
  version control so reliably that providers built role assumption, instance
  profiles, task roles, and managed identities specifically to retire static
  keys. Each generation of fix introduced its own misconfiguration surface:
  trust policies too broad, PassRole unconstrained, metadata endpoints exposed.

The confused-deputy problem predates all of this — it was named in the 1980s by
Norman Hardy to describe a privileged program tricked into misusing its
authority on an attacker's behalf. The cloud gave it an exact implementation:
a service or vendor role trusted broadly, callable by anyone who learns its ARN,
because nothing binds the caller to a legitimate integration. Cross-account
condition keys (`sts:ExternalId` and relatives) exist precisely because of it.

The most recent chapter is CI/CD federation. Long-lived deploy keys stored in
pipeline secrets were replaced by short-lived OIDC tokens minted per job — a big
improvement whose failure mode is now the *scope of the token*: a subject filter
of `repo:org/*` hands any fork-workflow path in the organization a valid cloud
session. Same class, new syntax.

## Anatomy: a wildcard policy on an internet-facing workload

The minimal vulnerable shape needs only two artifacts. First, a role whose
policy is maximally permissive:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
```

Second, a compute instance allowed to assume that role, reachable from the
internet, retrieving its credentials from an instance-metadata endpoint that
answers plain HTTP requests (the legacy v1 behavior).

Failure walkthrough:

1. The application on the instance has a server-side request forgery bug: one
   endpoint fetches a URL supplied in a parameter. The attacker points it at the
   link-local metadata address every cloud uses for instance self-description.
2. The metadata service, having no session-token requirement, answers with
   temporary credentials for the role.
3. Those credentials carry `"Action": "*"`. There is no permission boundary, no
   SCP, no explicit deny anywhere in the account narrowing them.
4. The holder can now create IAM users, attach AdministratorAccess to itself
   permanently, read every bucket, and modify every trust policy. One untrusted
   URL fetch became full account compromise.
5. Nothing crashed at any step; every API call returned success. The audit trail
   starts only after the theft.

Note the two defect families compounding here, exactly as SKILL.md's Mental
Model describes: *static over-grant* (the wildcard) plus *trust/exposure
mis-grant* (metadata reachable from attacker-influenced code). Either alone
would have contained the blast radius.

A second anatomy covers the confused deputy, needing only a trust policy:

```json
{ "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::210987654321:root" },
  "Action": "sts:AssumeRole" }
```

Any principal in account 210987654321 may adopt this role. Account IDs are not
secrets; they appear on invoices, in support tickets, in public S3 URLs. An
attacker who is a *customer* of that account's product — or who compromises any
low-privileged principal there — assumes the role and inherits whatever it can
do, without ever stealing a key.

## Why naive fixes fail

- **"We rotated the keys"**: rotation addresses stolen long-lived keys but not
  wildcard policies or open trusts; the same over-grant re-mints itself on the
  next credential.
- **"It's internal only / the VPC protects it"**: reachability assumptions live
  outside the repository. SSRF, a misconfigured proxy, or a pivot from another
  workload erases the network argument — which is why findings mark runtime hops
  `Needs-Review` rather than trusting either direction.
- **Renaming `Action: "*"` to a huge explicit list copied from another role**:
  copy-paste propagates the original sin; unless each action is justified by a
  workload need, this is a wildcard wearing a costume.
- **Deleting the risky role immediately**: workloads hold role references in
  profiles, task definitions, IRSA annotations, and function configs. Breaking
  the binding takes production down and teaches the team to fear IAM changes;
  the SKILL.md migration discipline (parallel attachment, observe, then remove)
  exists because the direct swap fails this way.
- **Adding `Deny *` somewhere "just in case"**: explicit deny wins everywhere,
  including the paths your own batch jobs need. Blanket denies produce silent
  breakage days later when background jobs surface their failures.
- **Trusting the provider console's default view**: consoles summarize; they do
  not evaluate intersection across identity policy, resource policy, permission
  boundary, SCP, RCP, and session policy. Effective authority is the
  intersection, and only policy evaluation (or authorized simulation) reveals it.
- **Hiding behind obfuscation of ARNs or account IDs**: identifiers are
  discoverable. Confused-deputy fixes are conditions (ExternalId, OrgID,
  SourceArn), never secrecy.
- **Enforcing IMDSv2 "at the account level eventually"**: defaults differ by
  region, launch path, and account age. Per-resource `http_tokens = required`
  in IaC is the enforceable statement; intent-to-enable-later is not a control.

## Common misconceptions

1. **"IAM is the provider's responsibility."** Providers supply the machinery;
   the customer writes the policies. Almost every finding in this module is
   customer-authored text.
2. **"`Resource": "*"` is fine inside our one account."** Authority compounds:
   today's benign list-everything verb becomes tomorrow's escalation primitive
   when paired with PassRole or UpdateAssumeRolePolicy.
3. **"Roles are safer than users, so any role shape is acceptable."** Roles are
   safer credential *delivery*; their *authority* can be arbitrarily larger than
   any user's. A wildcarded internet-facing role outranks a scoped user key.
4. **"Nobody knows our account ID / role ARN."** Neither is secret. Trust must
   rest on conditions, not on the hope that identifiers stay unknown.
5. **"Least privilege breaks things, so we start broad."** Starting broad is how
   the privilege-creep baseline forms. Start narrow, observe AccessDenied events,
   widen deliberately — the reverse order cannot be audited.
6. **"Encryption settings are a storage topic, not IAM."** KMS key policies are
   IAM documents; a key policy granting Decrypt to everyone silently voids the
   encryption-at-rest story for everything using that key.
7. **"Committed tfstate is just a map, the values are redacted."** State files
   serialize resource attributes verbatim, including generated key material.
   Structural placement is an IAM-class finding even before value triage.

## Modern taxonomy map

Matches the In Scope table of `../SKILL.md`; use these names when reporting.

| Class | One-line essence | Typical root cause |
|---|---|---|
| Wildcard identity policies | `Action`/`Resource` = `*` on app-facing roles | Prototyping scaffold never narrowed |
| AdministratorAccess attachment | Managed full-access policy on workload roles | Convenience attachment at setup |
| Trust-policy defects | `Principal:"*"`, root trust, no conditions | Copy-pasted cross-account templates |
| Unconstrained PassRole | PassRole on `*` beside compute verbs | Deploy roles written once, reused everywhere |
| Long-lived keys vs roles | Static keys in provider blocks/user_data/state | Pre-role-era patterns surviving |
| S3 exposure | Public ACLs, missing PAB, `Principal:"*"` reads | Website-hosting era defaults |
| Encryption defaults | Missing SSE attributes; wildcard key policies | Resource-by-resource omission |
| Secrets-store misuse | Password-named params typed String | SecureString not chosen at creation |
| GCP bindings | Owner/Editor to allUsers/allAuthenticatedUsers | Quick-share bindings never revoked |
| Azure assignments | Contributor/Owner at subscription scope | Portal-first workflows encoded in IaC |
| Metadata hardening | IMDSv1 fallback left enabled | Absent metadata_options blocks |
| CI/CD OIDC federation | Loose `sub` filters, missing audience checks | Wildcards replacing enumeration |

Severity intuition: authority that reaches the identity plane (create users,
attach policies, rewrite trusts) anchors Critical; data-plane-only over-grants
anchor High/Medium by data sensitivity; governance gaps (no PIM, no recert)
anchor Low but amplify everything else.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — the directed identity graph, two defect families, the
   escalation-primitive algebra, state-as-authority.
2. **What To Check** — the ordered A–N sweep from wildcard hunting through
   OIDC federation to account separation.
3. **Patterns & Signatures** — ripgrep battery plus VULNERABLE/FIXED pairs per
   resource type (identity, trust, PassRole, S3, encryption, secrets, GCP,
   Azure, metadata, OIDC).
4. **Taint Tracing Guidance** — credential-material tracing vs authority-flow
   tracing, seed nodes, cross-file resolution discipline.
5. **Exploitation & Reproduction** — static walkthroughs composing chains, and
   the authorized-CLI simulation shape.
6. **Remediation** — least-privilege rewrites, ExternalId template, scoped OIDC
   trust, backend hygiene, staged migration discipline.

Sibling modules that own adjacent defects (hand findings over rather than
duplicating their analysis):

- `../secrets-data-exposure/` — value-level key fingerprinting and rotation.
- `../ssrf-url-security/` — the fetch primitive that reaches instance metadata.
- `../dns-takeover/` — buckets and endpoints referenced by dangling records.
- `../authz-access-control/` — application-level authorization defects.
- `../configuration-hardening/` — non-IAM service and platform hardening.
