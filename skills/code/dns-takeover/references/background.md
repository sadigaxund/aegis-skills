# DNS Takeover & Dangling Records — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, regexes, claim table, and SOP ordering.

## How this class emerged

The Domain Name System is older than the web and was designed for a network of
cooperating institutions. Its central mechanic — delegation — lets a zone owner
say "for this name, ask that service." When platform-as-a-service vendors
arrived in the late 2000s, they leaned on delegation to give customers custom
hostnames without running DNS themselves: you point a CNAME at
`your-app.vendor.example`, and the vendor's edge routes by Host header. The
vendor became the authority for whether a name behind your domain still has an
owner — but your zone kept pointing at it.

The failure class crystallized when two operational habits collided:

- **Ephemeral compute, durable DNS.** PaaS apps, storage buckets, and CDN
  distributions are created and destroyed in seconds from CLI commands and CI
  pipelines. DNS records lived in consoles, spreadsheets, and other teams'
  repos — rarely in the same changeset as the teardown.
- **Globally-unique tenant names.** Most providers allocate endpoints from a
  flat namespace shared by all customers (`app-name.vendor.example`). If the
  name is free again after deletion, *any other customer can register it* — and
  your record still points there.

Security researchers systematized this into "subdomain takeover" in the
mid-2010s: enumerate hostnames, resolve them, fingerprint provider default
pages ("No such app", "There isn't a GitHub Pages site here", `NoSuchBucket`
XML), then register the freed tenant. The community-maintained claim matrix
that followed turned ad-hoc folklore into per-provider preconditions — and,
over time, several vendors hardened their platforms by requiring domain-control
verification before binding custom domains, which is why SKILL.md marks some
rows qualitative and demands live verification rather than trusting any table.

The deeper lesson the class teaches is about **claim continuity**: every
hostname your organization publishes is a distributed claim spanning app code,
IaC, DNS zones, and a third party's tenant registry. No single layer knows when
the chain breaks; audits must diff the layers against each other.

## Anatomy: one dangling CNAME

Minimal vulnerable shape — two artifacts in different systems:

```
DNS zone (still present):
    legacy-marketing.example.com.  CNAME acme-legacy-mktg.herokuapp.com.
Heroku (app deleted months ago):
    (no app named acme-legacy-mktg)
```

Failure walkthrough:

1. Resolution: `legacy-marketing.example.com` still answers with its CNAME
   target. The provider's edge accepts the connection and, finding no tenant
   bound to that endpoint, serves its default error page.
2. Discovery: an attacker enumerates subdomains (certificate-transparency logs,
   brute force, old docs), resolves each, and fingerprints responses. The
   default page matches the provider's documented marker.
3. Claim: the attacker runs `heroku create acme-legacy-mktg` on their own
   account. The name was globally free; registration succeeds. Their content is
   now served at the endpoint — and therefore at your hostname.
4. Trust: the attacker's page loads at `https://legacy-marketing.example.com`,
   frequently with a provider-managed valid TLS certificate. It is same-origin
   with everything under `example.com`: cookies scoped `Domain=example.com`
   flow to it, OAuth redirect URIs registered for it deliver authorization
   codes to it, CSP and CORS entries trusting it now trust attacker code.
5. Persistence: caches hold the mapping for the TTL; nothing about the setup
   ever alerts, because no component considers the mismatch an error.

Note what did NOT happen: no exploit against your servers, no credential theft,
no DNS protocol attack. The vulnerability is bookkeeping — a claim outliving
its justification.

The wildcard variant needs only one more character: `*.example.com` pointed at
a multi-tenant provider means one dangle converts unlimited first-level names
at once, which is why SKILL.md treats wildcards as severity-critical surface
regardless of current health.

## Why naive fixes fail

- **"Just delete the record"**: deleting before checking dependents breaks live
  integrations, and deleting before the TTL window elapses creates exactly the
  dangling state attackers scan for if the provider claim is released early.
  Ordering (TTL down → drain → delete record → wait → release claim LAST) is
  the fix; the single action is not.
- **"We'll add a wildcard catch-all so nothing dangles"**: a wildcard bound to
  one service amplifies every future dangle and hands parent-domain cookie
  scope to whichever tenant backs it. It trades many small risks for one huge
  structural one.
- **"CAA will stop the takeover"**: CAA restricts which certificate authorities
  may issue certificates for a name. It does not stop the takeover itself and
  does not touch cookie scope, OAuth callbacks, or non-TLS abuse; it only makes
  CA-shopping harder. Publishing CAA is worthwhile hardening — as partial
  mitigation, never as prevention.
- **"Fingerprint matched, so it's confirmed vulnerable"**: provider default
  pages change wording; some active tenants serve parking pages that look
  identical to dangles; some providers hold claims internally despite generic
  errors. A fingerprint is a candidate signal; claimability per current
  provider behavior decides the report.
- **"NXDOMAIN proves we're safe"**: a name resolving to nothing discloses that
  the hostname existed and is stale — infrastructure topology leakage — but is
  a different (lower-severity) failure class than a claimable dangle. Treating
  them identically mis-rates findings in both directions.
- **"DNSSEC fixes this"**: DNSSEC protects resolution integrity on paths you
  serve; a correctly-resolved CNAME to a freed tenant is exactly what DNSSEC
  signs. Defense-in-depth yes, takeover prevention no.
- **"Registrar lock is enough"**: transfer lock protects the whole-zone
  primitive (NS-level hijack) — important, one line in remediation — but does
  nothing about individual dangling records inside the zone.

## Common misconceptions

1. **"Takeover requires hacking DNS."** It requires registering a free name at
   a provider whose endpoint your zone references. The attack surface is your
   asset inventory, not the protocol.
2. **"Only marketing sites dangle."** Any decommissioned workload leaves them:
   internal tools, staging hosts, API gateways, verification TXT records for
   services long retired. The boring names are often the trusted ones.
3. **"Our provider would never let someone claim our name."** Provider claim
   models change over time — some hardened with domain verification, others
   remain first-come-first-served. Assertions must be checked against current
   provider docs, not memory.
4. **"A valid padlock means the site is ours."** Providers auto-provision TLS
   via challenges answered at the edge; whoever controls the origin during the
   challenge controls the cert. Valid TLS on attacker content is part of the
   impact, not evidence of safety.
5. **"HttpOnly cookies protect us."** Script cannot read them, but requests the
   attacker page initiates while the visitor browses still carry scoped
   cookies, subject to target CORS policy. HttpOnly reduces theft, not abuse.
6. **"We inventoried once, years ago."** Claims decay continuously; the audit
   method is re-running a diff between deployable workloads, IaC records, and
   doc/env references — a repeatable process, not a snapshot.
7. **"Stale TXT verification records are harmless clutter."** Ownership-proof
   artifacts for retired services can let whoever still controls that service's
   org re-verify your domain — a live claim, just a quiet one.

## Modern taxonomy map

Matches the In Scope table of `../SKILL.md`; use these names when reporting.

| Class | One-line essence | Typical root cause |
|---|---|---|
| Dangling CNAME to PaaS | Record points at deleted Heroku/Azure-class app | Teardown outside DNS repo |
| Dangling alias to object-storage websites | Alias to vanished S3/GCS website bucket | Bucket lifecycle vs record lifecycle |
| Wildcard amplification | One shared backing service behind `*.zone` | Catch-all convenience |
| Zone hygiene | Internal naming leaks, stale NS/TXT, missing query logging, missing CAA | Set-and-forget zones |
| Blast-radius artifacts in code | Cookie `Domain=`, OAuth redirects, CORS/CSP trusting subdomains | Parent-domain trust granted freely |

Severity intuition: takeover of any name carrying an OAuth callback, wildcard
takeover, or sibling-of-session-cookie-scope takeover anchor Critical/High;
isolated marketing names anchor Medium; stale-but-unclaimable leftovers anchor
Low/informational.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — the five-stage takeover chain and why same-origin power
   under your domain drives severity.
2. **What To Check** — inventory building, three-way decommission diff,
   teardown-script review, wildcard classification, blast-radius extraction.
3. **Where To Look** — artifact-by-artifact paths from Terraform Route53 to
   GitHub Pages CNAME files and `.env` origins.
4. **Patterns & Signatures** — the provider claim table, ripgrep battery, and
   the live fingerprint markers authorized verification may rely on.
5. **Exploitation & Reproduction** — static phase output shape, gated Phase 2
   command set, and the own-domain lab reproduction.
6. **Remediation** — inventory-first checklist, TTL-aware safe-decommission
   SOP, wildcard policy, honest CAA framing, monitoring sweep script.

Sibling modules that own adjacent defects (hand findings over rather than
duplicating their analysis):

- `../email-sms/` — SPF/DKIM/DMARC policy strength and sender spoofing.
- `../cloud-iam/` — buckets/endpoints whose exposure posture interacts with
  DNS claims (S3 public access, CloudFront aliases).
- `../configuration-hardening/` — platform-level hardening gaps surfaced by
  zone hygiene reviews.
