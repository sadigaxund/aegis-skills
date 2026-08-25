# Cloud IAM & Identity Misconfiguration — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & frameworks

- [OWASP Top Ten project](https://owasp.org/www-project-top-ten/) - the risk-catalog frame behind the module's A01 (Broken Access Control) mapping; use for report vocabulary.
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) - least-privilege and deny-by-default principles that the least-privilege rewrites in Remediation implement.

## Deep dives

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) - formal definition backing every wildcard-policy and AdministratorAccess finding.
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) - pillar entry covering the trust-misgrant family; note it is mapping-discouraged, so cite child CWEs in final reports.
- [PortSwigger Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf) - the fetch-primitive half of the SSRF-to-metadata chain this module composes with its IAM half.

## Vendor docs

- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) - canonical AWS guidance on federation, roles over keys, conditions, boundaries, SCPs/RCPs.
- [AWS: Grant permissions to pass a role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html) - authoritative PassRole semantics including the Resource-scoping pattern item C checks against.
- [AWS EC2: Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) - IMDSv1/v2 mechanics, token sessions, and hop limits behind check J.
- [GitHub Actions: OIDC security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) - subject/audience claim structure that the scoped trust-policy template pins.
- [Google Cloud IAM documentation](https://cloud.google.com/iam/docs) - GCP bindings, service accounts, and Workload Identity Federation referenced by the H-sweep fixes.
- [Azure RBAC best practices](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices) - Microsoft's own scope-narrowing, PIM, and wildcard-avoidance guidance matching the I-sweep findings.

(11 URLs total; each returned HTTP 200 with matching content when fetched.
Dropped during verification: an owasp.org Top-10:2021 A01 deep link that now
serves only a redirect stub — the project root above replaces it.)
