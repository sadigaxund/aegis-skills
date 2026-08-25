# DNS Takeover & Dangling Records — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & frameworks

- [RFC 8499: DNS Terminology](https://www.rfc-editor.org/rfc/rfc8499.html) - consensus definitions (CNAME, TTL, NXDOMAIN, wildcard, delegation) grounding every term in Prerequisites & Vocabulary.
- [RFC 8659: CAA Resource Record](https://datatracker.ietf.org/doc/html/rfc8659) - normative CAA semantics; its own Security Considerations confirm the "partial mitigation" framing in Remediation.
- [CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html) - the module's mapped CWE entry for name-based trust decisions.

## Deep dives

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - community claim matrix with per-provider status and fingerprints; use for current claimability leads, then verify against provider docs as SKILL.md requires.

## Vendor docs

- [AWS Route 53: Public DNS query logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html) - what query logging records and how to enable it, backing zone-hygiene check 6.
- [Cloudflare DNS documentation](https://developers.cloudflare.com/dns/) - record management/DNSSEC reference for zones delegated to Cloudflare.
- [Google Cloud DNS documentation](https://cloud.google.com/dns/docs) - GCP-managed zone behavior and record types for multi-cloud inventories.
- [GitHub Pages: custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site) - GitHub's own domain-verification guidance ("avoid takeover attacks") behind the Pages row of the claim table.
- [Heroku: Custom domain names](https://devcenter.heroku.com/articles/custom-domains) - Heroku explicitly warns that removing an app without updating DNS exposes you to subdomain takeover; primary-source confirmation of the PaaS dangle model.

(9 URLs total; each returned HTTP 200 with matching content when fetched.)
