---
name: dns-takeover-checks
description: Audit playbook module for DNS attack surface and subdomain takeover (CWE-350), covering claimed-hostname inventory extraction from repo/IaC artifacts, dangling-record reasoning from decommission asymmetry, provider claim-table fingerprinting for authorized live verification, zone-hygiene review, and TTL-aware safe-decommission remediation.
category_slug: DNS
cwe: [CWE-350]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

### Objective

Audit every hostname the organization claims — as evidenced by repository artifacts — and determine which of those claims can be hijacked by an attacker who registers the underlying service. For each finding produce: file:line evidence of the claimed hostname, the DNS target it resolves to, the owning artifact chain (config -> IaC -> docs), a takeover-precondition assessment per the claim table below, a status of `Confirmed-static`, `Dangling-candidate (Needs-Review)`, or `Verified-live`, and a blast-radius statement naming exactly which cookies, OAuth clients, CSP/CORS allowlists, or phishing-trust surfaces depend on that name.

### In Scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Dangling CNAME to PaaS | `legacy-marketing.example.com` still points at `acme-legacy.herokuapp.com`; app was deleted in a teardown script but the record remains | CWE-350 |
| Dangling alias to object-storage website endpoints | Route53 A-alias to `acme-old-assets.s3-website-us-east-1.amazonaws.com` whose bucket no longer exists | CWE-350 |
| Wildcard amplification | `*.example.com` -> one shared service; a single unclaimed name under the wildcard yields infinitely many hijackable names | CWE-350 |
| Zone hygiene | Public zone leaks internal naming (`jenkins-intranet.example.com`), stale NS delegations, stale TXT ownership-proof records, missing query logging, missing CAA | CWE-350 |
| Blast-radius artifacts in code | Cookies set with `Domain=.example.com`, OAuth `redirect_uri` lists containing inventoried subdomains, CORS/CSP allowlists trusting `*.example.com` | CWE-350 |

### Out of Scope (cross-references)

- SPF/DKIM/DMARC policy strength and sender-spoofing analysis -> email-sms module if present; this module only checks that DKIM/SPF records exist when mail is known to be sent from the domain and cross-references.
- Registrar account compromise, domain theft, and business-email-compromise fraud -> out of scope; this module flags registrar lock posture in one line under Remediation.
- Live scanning of third-party infrastructure without written authorization -> forbidden by this module; all live procedures are gated behind an explicit authorization banner.

### Operating Assumptions

Read-only access to the repository; no live DNS access is guaranteed or required for the static phase. Static evidence alone never proves a record is dangling — it proves a *candidate* that requires authorized live verification (`Needs-Review`). Every dynamic command in this module is marked with its requirement: network egress plus written authorization from the zone owner.

## Mental Model

### The Takeover Chain

Subdomain takeover is a five-stage failure of claim continuity:

1. **Claim**: The organization registers a hostname `promo.example.com` and points it via CNAME (or A/ALIAS) at a provider endpoint, e.g. `acme-promo.herokuapp.com`. The provider routes requests for that endpoint back to content under your subdomain — you have delegated name resolution to the provider's tenant namespace.
2. **Decommission asymmetry**: The application team tears down the Heroku app / Azure site / S3 bucket. Compute teardown scripts run; DNS records live in a different repo, different team, different change cadence. The record survives; the claim behind it does not.
3. **Dangle**: The provider now has no tenant bound to `acme-promo.herokuapp.com`. Resolving `promo.example.com` lands on the provider's edge, which answers with a default error/parking page ("No such app", GitHub Pages 404, S3 `NoSuchBucket` XML).
4. **Hijack**: An attacker queries the subdomain, fingerprints the provider's default response, and registers the now-free tenant name (`heroku create acme-promo`). The provider binds their content to the endpoint your DNS still points at.
5. **Same-origin power**: The attacker serves arbitrary content at `https://promo.example.com` — often with a provider-managed valid TLS certificate. This is not defacement-on-a-random-host; it is content served **inside your parent-domain trust boundary**.

### Why Same-Origin Under Your Domain Is Severe

State what each power means concretely, because severity depends on it:

- **Cookie scope**: Any cookie issued with `Domain=example.com` is transmitted to *every* subdomain, including attacker-controlled ones. A non-`HttpOnly` session cookie is readable via `document.cookie` from the attacker's page. An `HttpOnly` cookie is not script-readable but is still attached to requests the attacker page initiates while browsing under that cookie's scope (subject to the target API's CORS policy) — so `HttpOnly` reduces theft, not abuse. Check the repo for `Domain=` cookie attributes to quantify this.
- **OAuth callback abuse**: If any identity provider client has `redirect_uri=https://promo.example.com/callback` registered, authorization codes for that client flow through the attacker's server. Grep the repo and auth configs for redirect registrations referencing inventoried hosts.
- **Valid TLS on attacker content**: Providers auto-provision certificates (HTTP-01 or similar) for custom domains they host. The attacker controls the origin during the challenge, so `https://promo.example.com` shows a browser padlock. Phishing gains full trust indicators.
- **CSP bypass via same-origin**: A page CSP allowing `promo.example.com` (e.g., for scripts or frame-ancestors) trusts attacker content once the name flips.
- **CORS reflection trust**: Backends reflecting or allowlisting origins like `https://*.example.com` hand credentialed cross-origin read access to the attacker's origin.
- **Internal-name leakage**: Hostnames such as `grafana-staging.internal.example.com` published in a public zone document infra topology to attackers even before any takeover.

### Amplifiers and Dampeners

- **Wildcard records** (`*.example.com`) amplify one dangling target into unlimited hijackable names; treat as severity-critical surface.
- **High TTLs** extend both the vulnerable window after dangle and the recovery window after fix; TTL is a first-class variable in every remediation step.
- **CAA does not prevent takeover** — it constrains which CAs may issue for the name. It narrows the TLS-trust impact only partially (see Remediation for honest framing).

## What To Check

Work through these in order; each produces a concrete artifact.

1. **Build the claimed-domain inventory.** Run every ripgrep pattern in Patterns & Signatures across the whole repo (include hidden files, exclude `.git` and vendored deps). Collect one row per unique hostname: hostname, source file:line, DNS target if visible in the same artifact, provider classification.
2. **Map inventory rows to DNS records in IaC.** For each hostname, find its record definition (`aws_route53_record`, Cloudflare/DNSimple/GCP equivalents, zone exports, Helm ingress values). A hostname with no IaC record is managed manually — flag for process review under Remediation item 1.
3. **Run the decommission diff (three-way).** Compare three sets per hostname: (a) hostnames referenced by *deployable* workloads (k8s manifests with live Services/Deployments, active Procfile/heroku refs, vercel projects); (b) hostnames present in DNS IaC; (c) hostnames referenced only by docs/env/history. Any name in (b) or (c) but absent from (a) is a `Dangling-candidate (Needs-Review)` — the service may be gone while the claim remains.
4. **Inspect teardown scripts for ordering bugs.** Find `terraform destroy -target`, `heroku apps:destroy`, `az webapp delete`, `aws s3 rb` invocations and their surrounding changesets. If the same branch deletes compute but leaves `route53_record` blocks untouched, record the orphaned records as candidates.
5. **Classify wildcard records.** Locate every `*.zone` record or ingress hostspec. For each, determine the single backing service and whether any name under the wildcard could dangle independently. Wildcards pointing at multi-tenant providers are critical findings regardless of current health.
6. **Review zone hygiene in IaC:** query logging configured (`aws_route53_query_log` or console equivalent) or absent; public-zone records whose names/targets leak internal topology (`internal`, `intranet`, `staging-jenkins`, RFC1918-ish naming); NS delegations matching current registrar nameservers; TXT verification records (`google-site-verification=`, `MS=ms…`, `atlassian-domain-verification=`, `loaderio=`) still present after the corresponding service is gone; CAA records present or absent.
7. **Quantify blast radius from app code.** Grep for cookie `Domain=.example.com` attributes, OAuth client redirect/callback URL lists containing inventoried subdomains, CORS origin allowlists using parent-domain suffixes, CSP directives naming subdomains. Attach hits to the relevant inventory rows.
8. **Check mail adjacency one line only.** If MX or mail-sending config exists, confirm SPF and DKIM selector records appear somewhere authoritative, then defer policy quality to the email-sms module. Do not duplicate that analysis here.
9. **Assign status and severity per row.** `Confirmed-static` = inconsistency provable from repo alone (e.g., docs reference a deleted app's endpoint). `Dangling-candidate (Needs-Review)` = plausible dangle requiring live dig/curl. Never report "confirmed takeover" without the authorized live phase.
10. **Emit the Needs-Review command set.** For each candidate, pre-fill the exact `dig`/`curl` lines from Exploitation & Reproduction with the real hostname so the reviewer can execute them during an authorized window.
11. **Fold in discovery enrichments:** certificate-transparency logs (crt.sh) as a discovery source for forgotten subdomains into the step-1 inventory; dnstwist-style typosquat monitoring of brand domains; broken-link hijacking review of outbound links aimed at lapsed third-party domains.

## Where To Look

| Artifact | Path patterns to search | What to extract |
|---|---|---|
| Terraform Route53 | `infra/**/*.tf`, `*.tf` anywhere | `resource "aws_route53_record"` blocks; `type = "CNAME"` / `"A"` with alias targets; `aws_route53_zone`; `aws_route53_query_log` presence; TXT records |
| Kubernetes ingresses | `**/ingress*.yaml`, `k8s/**`, `charts/**`, `helm/**` | `spec.rules[].host`, `tls.hosts`, backend Service names (cross-check the Service exists) |
| nginx / Apache vhosts | `**/*.conf`, `nginx/**`, `deploy/**` | `server_name` lists, proxy upstreams (dead upstream + live server_name = candidate) |
| Caddyfile | `Caddyfile`, `**/Caddyfile` | Site addresses at block start; they double as DNS claims when a DNS challenge/provisioning pipeline exists |
| Vercel / Netlify configs | `vercel.json`, `netlify.toml` | `domains`, route `host` values |
| GitHub Pages | root-level `CNAME` file(s), `docs/CNAME`, `.github/**` workflows deploying Pages | The single hostname line inside `CNAME` |
| Heroku references | `Procfile`, `app.json`, CI deploy scripts, docs | `<app>.herokuapp.com` targets and app names used in `heroku` CLI calls |
| Azure references | ARM/Bicep/Terraform, CI scripts | `<site>.azurewebsites.net` names |
| Documentation & README links | `README*`, `docs/**`, `*.md` | Absolute links to owned-subdomain URLs — often the last surviving evidence of retired hosts |
| Environment templates | `.env.example`, `.env*`, `config/*.yml` | `BASE_URL`/`SITE_URL`/`PUBLIC_URL`/`ORIGIN` values |
| Cookie/OAuth/CORS surfaces | app source | `Domain=` cookie attributes; `redirect_uri`/callback allowlists; CORS origin config; CSP header construction |

Search with hidden-file coverage enabled (`rg --hidden --no-ignore -g '!.git' -g '!node_modules' -g '!vendor'`) because env files and dot-directories carry many claims.

## Patterns & Signatures

### Provider Claim Table

| Provider | Target pattern | Claim precondition | Fingerprint category |
|---|---|---|---|
| GitHub Pages | `<user/org>.github.io`; custom domain via repo `CNAME` file | GitHub username/org unregistered, or project path free under an org you control | HTML 404 containing the exact marker string in the fingerprint table below |
| Heroku | `<app>.herokuapp.com` | App name is globally unique — register it (`heroku create <name>`) | HTML page headed "No such app" |
| Azure App Service / Websites | `<site>.azurewebsites.net` | Site name available at creation time in the region | Default 404 marker text class ("404 Web Site not found" family); verify current wording against provider docs |
| AWS S3 website hosting | `<bucket>.s3-website-<region>.amazonaws.com`, legacy `<bucket>.s3.amazonaws.com` / regional virtual-host forms | Bucket name (partition-globally unique) recreatable in the same region + website hosting enabled | XML error body with `<Code>NoSuchBucket</Code>` shape |
| Amazon CloudFront | `<dist>.cloudfront.net` | Historically trivial; today adding a CNAME alias to a distribution requires proving domain control (certificate validation), so treat as hardened — re-check docs.aws.amazon.com before asserting | Generic CloudFront error page ("The request could not be satisfied" family) |
| Google Cloud Storage website | `<bucket>.storage.googleapis.com` and regional forms | Historical claimability behavior is uncertain; do not assert. Check cloud.google.com storage docs for current custom-domain/bucket-name rules | XML `NoSuchBucket`-shaped error (same category as S3) |
| Fastly | `<svc>.global.ssl.fastly.net`, `<svc>.freetls.fastly.net` | Historically claimable by binding the domain to a new service; current behavior may require domain verification — check developer.fastly.com | Default Fastly error/cache-miss page class |
| Self-hosted Varnish/nginx edge | A record to a retired origin IP | No external tenant system — no takeover, but stale claims disclose infra and can be re-registered if the IP is reassigned by the hoster | Connection refused / stale content / wrong-vhost content |
| Shopify (classic example, qualitative) | CNAME to `<shop>.myshopify.com` | Shop handle availability | Provider parking/password page class — check help.shopify.com |
| Tumblr (classic example, qualitative) | CNAME to `domains.tumblr.com` | Free blog-handle registration mapping | Provider "not found" blog page class |
| Zendesk (classic example, qualitative) | CNAME to `<subdomain>.zendesk.com` | Subdomain availability at signup | Zendesk registration/parking page class |

For every row marked qualitative or hardened: state uncertainty explicitly in findings, cite the provider docs root, and rely on the live curl step rather than the table for the final call.

### Inventory Extraction Regexes (ripgrep-compatible)

Substitute `example.com` with the audited zone. Run all from the repo root.

```sh
# nginx server_name blocks
rg -n --hidden --no-ignore -g '!.git' -g '!node_modules' '(?i)\bserver_name\s+[^;{]+'

# k8s / helm ingress hosts
rg -n --hidden --no-ignore -g '!.git' '(?i)^\s*-?\s*host:\s*["'\'']?([a-z0-9*.-]+\.)?example\.com\b'

# terraform CNAME/alias record blocks (context dump; read type/records lines)
rg -n -A8 --hidden --no-ignore -g '*.tf' '(?i)resource\s+"aws_route53_record"'

# terraform records targeting classic takeover providers
rg -n --hidden --no-ignore -g '*.tf' '(?i)(herokuapp\.com|azurewebsites\.net|cloudfront\.net|github\.io|s3-website[.-][a-z0-9-]+\.amazonaws\.com|\.s3\.amazonaws\.com)'

# generic provider-target sweep across all text artifacts
rg -n --hidden --no-ignore -g '!.git' -g '!node_modules' \
  '(?i)[a-z0-9][a-z0-9-]*\.(herokuapp\.com|azurewebsites\.net|cloudfront\.net|github\.io|global\.ssl\.fastly\.net|freetls\.fastly\.net|myshopify\.com|zendesk\.com|storage\.googleapis\.com)'
# S3 virtual-host style endpoints
rg -n --hidden --no-ignore -g '!.git' '[a-z0-9.-]+\.s3(-website)?([.-][a-z0-9-]+)?\.amazonaws\.com'

# vercel.json domains/routes
rg -n '"(domains|routes|host|value|destination)"' vercel.json

# GitHub Pages CNAME files (read contents; one hostname per file)
fd -H -t f '^CNAME$' && rg -l '.' $(fd -H -t f '^CNAME$')

# .env BASE_URL-style origins
rg -n --hidden --no-ignore -g '.env*' '(?i)(BASE_URL|SITE_URL|PUBLIC_URL|ORIGIN|API_URL)\s*=\s*https?://[^/\s]+'

# owned-subdomain links surviving in docs
rg -o -n --hidden --no-ignore 'https://([a-z0-9-]+\.)+example\.com[^)"'\'' >]*'
```

### Config Snippets

```hcl
# infra/dns.tf
# VULNERABLE(dangling pattern): teardown deleted the app but this block survived;
# acme-legacy-marketing.herokuapp.com has no owner behind it.
resource "aws_route53_record" "legacy_marketing" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "legacy-marketing.example.com"
  type    = "CNAME"
  ttl     = 3600
  records = ["acme-legacy-marketing.herokuapp.com"]
}
```

```hcl
# infra/dns.tf
# FIXED(removed-or-reclaimed): record removed in the same changeset that decommissions
# the app; TTL was lowered to 60 one week earlier so caches expire before deletion.
# Wildcard alternative rejected; per-service records generated from inventory.
resource "aws_route53_record" "promo_2026" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "promo.example.com"
  type    = "CNAME"
  ttl     = 60
  records = ["acme-promo-live.herokuapp.com"]   # app verified deployed and claimed
}
```

```nginx
# deploy/nginx/sites.conf
# VULNERABLE(dangling pattern): upstream was retired; DNS still points here and the
# vhost answers with 502, advertising a dead claim.
server {
  listen 443 ssl;
  server_name promo.example.com;
  location / { proxy_pass http://retired-promo-upstream; }
}
```

```nginx
# deploy/nginx/sites.conf
# FIXED(removed-or-reclaimed): dead vhost deleted; upstream and DNS record removed together.
server {
  listen 443 ssl;
  server_name promo.example.com;
  location / { proxy_pass http://promo_upstream; }   # service verified running
}
```

```yaml
# k8s/ingress.yaml
# VULNERABLE(dangling pattern): backend Service deleted elsewhere; ingress still
# publishes legacy-api.example.com and routes to default-backend 404.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: legacy-api
spec:
  rules:
    - host: legacy-api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: legacy-api-svc   # does not exist anymore
                port:
                  number: 80
```

```yaml
# k8s/ingress.yaml
# FIXED(removed-or-reclaimed): rule removed with its workload in one PR; host absent
# from cluster, DNS record retired through the decommission SOP.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: current-api
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api-svc   # exists in same manifest set
                port:
                  number: 80
```

### Live Fingerprint Table

Use only these markers during authorized verification; they are widely documented response strings.

| Provider | Marker string or category | Confidence note |
|---|---|---|
| GitHub Pages | `There isn't a GitHub Pages site here.` | Widely documented exact string; match case-insensitively |
| Heroku | `No such app` | Widely documented heading phrase |
| Azure App Service | `404 Web Site not found` | Marker text class; confirm current wording at learn.microsoft.com before reporting |
| S3 / GCS object-storage | XML body containing `<Code>NoSuchBucket</Code>` (often plus `The specified bucket does not exist`) | Widely documented XML error shape |
| CloudFront | Error page of the form `ERROR: The request could not be satisfied` | Category-level; presence indicates missing/invalid distribution config, not automatically claimability |

Anything else (Fastly, Shopify, Tumblr, Zendesk, GCS specifics): do not hardcode strings; fetch the live response, classify it against the provider's documented default-page category, and check that provider's docs.

## Taint Tracing Guidance

Treat hostnames as taint subjects flowing between artifact layers; the "vulnerability" materializes when claim continuity breaks across layers.

- **Sources**: hostname literals surfaced by the inventory regexes above — `server_name` values, ingress hosts, `CNAME` file lines, vercel domains, `.env` origins, doc links, heroku CLI invocations.
- **Propagators**: Terraform variables and modules (`var.domain`, `${local.subdomain}`), Helm values templates (`.Values.ingress.host`), env substitution in CI deploy scripts, templated nginx configs. Resolve each propagator chain to concrete values before matching; a hostname that only exists post-render must be matched by rendering (`helm template`) not by grep alone.
- **Sinks**: DNS record definitions in IaC (`route53_record` blocks, Cloudflare/DNSimple providers), zone export files, registrar dashboards documented in runbooks.
- **Dangle rule (source -> sink mismatch)**: hostname present at a sink (DNS record) while no deployable workload references it anywhere in the deploy tree -> `Dangling-candidate (Needs-Review)`.
- **Reverse rule (outage risk)**: workload references a hostname absent from all sinks -> cleanup of neighbors may break it; record before deleting anything.
- **Wildcard expansion tracking**: a sink entry `*.example.com` expands to unbounded sources; trace the *single* backing target and mark every inventoried first-level name under the wildcard as dependent on that one claim.
- **Cross-layer blast-radius edges**: when a hostname reaches a cookie `Domain=` attribute, an OAuth `redirect_uri`, a CORS allowlist entry, or a CSP directive, draw the edge in the report — these edges decide severity, not the DNS record itself.

## Exploitation & Reproduction

### Phase 1 — Static (no network required)

1. Run the full regex battery; deduplicate into the inventory table: `hostname | source file:line | dns target | provider | status`.
2. Render templates where needed (`helm template`, `terraform console`) so propagator-hidden hosts are included.
3. Execute the three-way decommission diff (What To Check step 3). Output the candidate list with the artifact evidence for each: e.g., `docs/runbook.md:42` mentions `acme-legacy-marketing.herokuapp.com`, deploy tree contains no Heroku reference, `infra/dns.tf:88` retains the record.
4. Read teardown/deploy scripts for ordering bugs (What To Check step 4); attach any orphan-producing commit or script as evidence.
5. Collect blast radius: for each candidate hostname, list cookie scopes, OAuth redirect registrations, CORS/CSP entries that trust it. State expected impact in one sentence per candidate ("attacker page under `.example.com` cookie scope; non-HttpOnly session readable").
6. Classify severity using Severity Assessment; emit the pre-filled Phase 2 command set per candidate. Expected outcome of this phase: zero network calls, fully cited Needs-Review list.

### Phase 2 — Live Verification (REQUIRES network access AND written authorization from the zone owner)

Run only inside an approved engagement window, only against hostnames in the audited zone, and never attempt to register/claim anything outside domains you own. Record raw outputs.

1. Resolve the chain and expect observable outcomes:

   ```sh
   dig +short legacy-marketing.example.com CNAME
   # expected if claim intact: "acme-legacy-marketing.herokuapp.com."
   dig +short legacy-marketing.example.com A
   # expected: provider edge IPs (or NXDOMAIN if the dangle is total)
   ```

2. Fingerprint over HTTP and HTTPS:

   ```sh
   curl -sS -m 10 -D - -o /tmp/body.txt http://legacy-marketing.example.com/
   curl -sS -m 10 https://legacy-marketing.example.com/ -o /tmp/body-tls.txt || true
   grep -iE "No such app|There isn.t a GitHub Pages site here|NoSuchBucket|404 Web Site not found|request could not be satisfied" /tmp/body*.txt
   ```

3. Interpret outcomes: provider default-page marker + resolvable CNAME = dangling confirmed at HTTP layer -> takeover-precondition per claim table decides urgency (Heroku/S3-class names usually directly claimable; CloudFront-class hardened). NXDOMAIN or connection refused = different failure class (stale infra disclosure), downgrade accordingly. Your own application's content = healthy, close as false positive for this row.
4. Where TLS succeeded, capture `curl -v` certificate subject/SAN output to document the valid-TLS-on-dangling-host condition.
5. Write results back into the inventory (`Verified-live` vs `Needs-Review unresolved`), then hand off to Remediation.

### Safe Lab Reproduction (your own domain only)

Perform end-to-end mechanics on a domain you registered, to build reviewer intuition without touching third-party assets. Outbound DNS/HTTP from your lab machine requires ordinary network consent; everything else stays inside your own accounts.

1. Use a domain you own, e.g. `lab.your-domain.dev`. Pick an unused label `takeover-lab.lab.your-domain.dev`.
2. In your DNS provider create: `takeover-lab.lab CNAME unused-lab-app-7f3c.herokuapp.com` with TTL 60. Do NOT create the Heroku app yet.
3. Wait for propagation, then verify the dangle: `dig +short takeover-lab.lab.your-domain.dev CNAME` returns the herokuapp target, and `curl -sS http://takeover-lab.lab.your-domain.dev/` returns the Heroku "No such app" class page.
4. Claim it: log into your own Heroku account, `heroku create unused-lab-app-7f3c`, deploy a static index reading `LAB CLAIMED`. This mirrors exactly what an attacker would do — which is why step 6's ordering matters.
5. Re-verify: `curl -sSi http://takeover-lab.lab.your-domain.dev/` now returns 200 with your content served through your subdomain; repeat with `https://` and observe the provider-managed valid certificate for your hostname.
6. Clean up in SOP order (Remediation): lower TTL, delete the DNS record, wait out the TTL window, THEN destroy the Heroku app last. Note timings in the engagement log.
7. Never perform steps 2–5 against names you do not own: registering someone else's dangling target IS the attack.

## Remediation

### Inventory-First Checklist

1. Consolidate the inventory table into IaC: every claimed hostname gets a reviewed record definition in version control. No console-created DNS changes; require PR review for zone edits.
2. Generate per-service records from the deploy manifests where possible (Terraform `for_each` over a service map) so deleting a workload forces a visible DNS diff in the same PR.
3. Prune now: delete every record whose workload is verifiably gone, using the SOP below; delete stale TXT verification records (`google-site-verification=`, `MS=ms…`, `atlassian-domain-verification=`, `loaderio=`) once their services are confirmed retired.
4. Move internal-only names out of public zones into private hosted zones; rename leaky conventions (`jenkins-intranet.example.com`) during migration.
5. Deploy CAA records (see below) and enable Route53 query logging (or provider equivalent) on public zones.

### Safe-Decommission SOP (TTL-aware ordering)

1. **Enumerate dependents**: cookies scoped to the name, OAuth redirect URIs, CORS/CSP allowlists, docs links, partner integrations. Update or schedule removal of each.
2. **Lower TTL first**: set affected records to 60s at least one max-TTL-period before teardown (e.g., a week ahead if records were 3600s). Rationale in step 6.
3. **Drain usage**: remove app-level references (redirect URIs, allowlists) in normal deploys; watch access/query logs until traffic to the hostname trends to zero.
4. **Delete the DNS record** in a reviewed changeset together with (not after) workload deletion — one PR removes both sides of the claim.
5. **Wait out caches**: keep the service alive but unused until every resolver cache holding the old TTL has expired. While your record still resolves anywhere, releasing the claim early would create exactly the dangling state attackers scan for.
6. **Release the service claim LAST**: destroy the Heroku app / Azure site / S3 bucket only after the TTL window from steps 2–5 has fully elapsed. This ordering keeps the endpoint answering harmlessly under your name while caches flush, then closes the claim once nothing resolves to it.
7. **Verify closure**: rerun the Phase 2 dig/curl pair; expect NXDOMAIN or an unresolvable name, never a provider default page under your hostname. Keep the hostname on the monitoring sweep for 30 days.

### Wildcard Policy

- Prohibit `*.example.com` records unless a documented single-tenant catch-all justifies them; each exception must name its one backing service and its owner.
- Never combine wildcards with multi-tenant provider aliases: one dangle then compromises unlimited names plus parent-domain cookie scope.
- Prefer explicit records generated from inventory; wildcard needs discovered in audit become findings regardless of current health.

### CAA Records (partial mitigation — honest framing)

CAA constrains which certificate authorities may issue for the zone; it does NOT stop takeover, does not stop a CA you permit, and does not affect non-TLS abuse (cookie scope, OAuth callbacks). It reduces the attacker's ability to shop for a friendly CA.

```
example.com.        IN CAA 0 issue "letsencrypt.org"
example.com.        IN CAA 0 iodef "mailto:security@example.com"
; forbid issuance entirely on infrastructure-free zones:
legacy-parked.example.com. IN CAA 0 issue ";"
```

**DNSSEC on your own zones** (adjacent hardening, not takeover prevention): sign authoritative zones (`algorithm 13` ECDSAP256SHA256 is the common modern choice) and publish DS records at the registrar. DNSSEC protects resolution integrity against cache poisoning on paths you serve; it does nothing against dangling CNAMEs, so treat it as defense-in-depth alongside — never instead of — the inventory and reclaim discipline above.

### Monitoring Sweep (read-only concept + cron sketch)

Run an hourly read-only sweep that re-resolves every inventoried hostname, fingerprints responses against the marker table, writes a report, and diffs against last sweep state:

```cron
# crontab -e  (dns-audit service account; read-only dig/curl against owned zones)
17 * * * *  /opt/dns-audit/dangling-sweep.sh >> /var/log/dns-audit/sweep.log 2>&1
```

```sh
#!/bin/sh
# /opt/dns-audit/dangling-sweep.sh — READ-ONLY; authorized internal monitoring.
DOMAIN_FILE=/opt/dns-audit/claimed-hosts.txt     # one hostname per line, generated from repo inventory
STATE=/opt/dns-audit/state/last-sweep.txt
OUT=/opt/dns-audit/reports/sweep-$(date +%Y%m%dT%H%M).txt

: > "$OUT"
while IFS= read -r host; do
  [ -z "$host" ] && continue
  cname=$(dig +short "$host" CNAME | head -n 1)
  body=$(curl -sS -m 10 "http://${host}/" 2>/dev/null || true)
  marker=""
  printf '%s' "$body" | grep -q "No such app"                              && marker="heroku-no-such-app"
  printf '%s' "$body" | grep -q "There isn't a GitHub Pages site here"     && marker="github-pages-404"
  printf '%s' "$body" | grep -q "<Code>NoSuchBucket</Code>"                && marker="object-storage-nosuchbucket"
  printf '%s' "$body" | grep -q "404 Web Site not found"                   && marker="azure-default-404-class"
  [ -n "$marker" ] && printf 'DANGLING %s -> %s [%s]\n' "$host" "${cname:-A/NXDOMAIN}" "$marker" >> "$OUT"
done < "$DOMAIN_FILE"

if [ -f "$STATE" ]; then diff -u "$STATE" "$OUT" > "${OUT}.diff" || true; fi
mkdir -p "$(dirname "$STATE")" && cp "$OUT" "$STATE.new" && mv "$STATE.new" "$STATE"
[ -s "$OUT" ] && echo "ALERT: dangling candidates present; see $OUT"
```

Alert on any `DANGLING` line via your normal paging channel.

### Registrar Posture (one line)

Enable registrar transfer lock and account MFA so NS-level changes — the whole-zone takeover primitive — require out-of-band approval.

## Verification & Validation

### Post-Fix Verifies

1. Sweep returns clean: run `dangling-sweep.sh` manually; expect zero `DANGLING` lines across the full inventory.
2. For each remediated record, confirm resolution state matches intent: deleted records NXDOMAIN; retained records resolve AND serve the expected application content (`curl` body check, not just DNS).
3. Confirm zone hygiene items landed: query logging enabled, CAA records resolvable (`dig example.com CAA +short`), stale TXT/NS artifacts gone (`dig example.com TXT +short`, `dig example.com NS +short` cross-checked against registrar listing).

### Negative Tests

1. Legitimate subdomains still resolve and serve correctly after cleanup — test every record adjacent to deleted ones (apex, www, api) before and after the change window.
2. A deliberately healthy control host (e.g., `www`) passes through the sweep script without producing a marker hit — proves fingerprint logic has no false-positive drift.
3. TLS still validates on all surviving names post-change (`openssl s_client` or curl exit codes), proving no cert-binding collateral damage.

### Regression Notes

1. Deleting active records during cleanup is the primary outage risk: mandate a dry-run diff review step — `terraform plan` output attached to the PR showing exactly which records are destroyed, reviewed against the inventory before apply. Never apply zone changes without this step.
2. Re-run the full inventory regex battery post-fix: any hostname appearing in app code/docs with no IaC record signals either manual-shadow DNS (process gap) or an accidental removal — both are regression findings.
3. Keep decommission SOP step 6 (claim release LAST) enforced by checklist in teardown PR templates; a teardown PR that destroys compute while retaining DNS records reopens the entire bug class.

## Severity Assessment

State the blast radius found in THIS repo — which cookie scopes, which OAuth clients, which allowlists trust the name — rather than generic claims. Anchor examples (adjust to observed impact):

| Finding class | Example | CVSS v3.1 vector |
|---|---|---|
| Critical | Wildcard takeover, or takeover of any subdomain carrying an OAuth callback/redirect registration | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| High | Sibling-subdomain takeover inside main-site cookie scope (`.example.com` session cookies) with valid attacker TLS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| Medium | Isolated marketing subdomain takeover; no shared cookies, no auth surface trusts the name | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` |
| Low | Stale TXT ownership-proof artifacts or orphaned NS delegation without active dangle; info-disclosure of infra topology | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` |

Modifiers: multiply perceived severity upward when wildcard amplification applies to an otherwise-Medium finding; downgrade High to Medium only when the repo proves cookies are host-scoped AND no OAuth/CORS/CSP trust references the name. A `Dangling-candidate (Needs-Review)` unresolved by the live phase reports as Medium-maximum pending verification — never inflate static uncertainty into Critical.

## Common False Positives

1. **Reserved-but-intentionally-parked domains**: some orgs defensively register lookalike/parked subdomains. Documented intent (naming convention like `parked-`, an OWNERS note, or IaC comments) converts these to informational findings, not vulnerabilities. Record the intent evidence.
2. **Provider parking pages that ARE claimed**: a provider default-looking page does not always mean the tenant is gone — some providers serve branded parking for active paid accounts. Before reporting, complete the live phase and verify claimability against current provider docs; a fingerprint match alone is insufficient when the page differs from the documented default-marker category.
3. **CDN-managed records where the provider holds the claim internally**: aliases to CloudFront/CDN endpoints can error transiently or serve generic error pages while the distribution remains valid and the alternate-domain binding is owner-controlled. Treat hardened-provider rows (CloudFront) as false positives unless evidence shows the alias binding itself was released.
4. **Multi-tenant catch-all apps serving by Host header**: an application answering many hostnames with real customer content is healthy even though naive curl shows "unexpected" content — confirm the backend exists before flagging.
5. **NXDOMAIN leftovers**: a hostname resolving to nothing is stale-infrastructure disclosure, not takeover; classify Low/informational instead of claiming a dangle.

## References

- CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Decision — https://cwe.mitre.org/data/definitions/350.html
- can-i-take-over-xyz (community-maintained vulnerability matrix per provider; use for current claimability status, not as authority for fingerprints hardcoded here) — https://github.com/EdOverflow/can-i-take-over-xyz
- RFC 8499, DNS Terminology — https://www.rfc-editor.org/rfc/rfc8499.html
- Provider documentation roots (consult for current custom-domain, claim, and default-page behavior): https://docs.github.com , https://devcenter.heroku.com , https://learn.microsoft.com , https://docs.aws.amazon.com , https://cloud.google.com , https://developer.fastly.com , https://help.shopify.com

