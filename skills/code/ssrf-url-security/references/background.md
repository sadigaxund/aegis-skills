# SSRF & URL Security — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the sink catalogs, payload ladders, and remediation code.

## How this class emerged

The bug is as old as server-side features that fetch things on a user's behalf:
URL importers, feed readers, link previewers, webhook pingers. Early literature
filed these under "unvalidated redirects" cousins or port-scan helpers; the
modern name — server-side request forgery — crystallized in the early 2010s,
when practitioners recognized the shared shape: an attacker supplies a
*destination*, and the server's own network position does the reaching.

Two developments turned a curiosity into a headline class:

- **Cloud metadata services.** Link-local addresses (AWS popularized
  `169.254.169.254`) hand out instance facts and — fatally — IAM role
  credentials to anything that asks from inside the host. An SSRF stopped
  being "internal port scan" and became "cloud account takeover with one GET."
- **Microservice and orchestration networks.** Pods, service meshes, and
  internal admin consoles made the inside of a deployment far more valuable
  than any single database behind a firewall.

The industry response has been layered: application frameworks grew real URL
parsers and redirect hooks; AWS introduced IMDSv2 in 2019 (a session-token PUT
plus header requirement) specifically to blunt GET-only SSRF; egress filtering
and dedicated fetch proxies moved from exotic to recommended defense-in-depth.
None of it retires the code-level check, because every mitigation assumes the
application validates destinations correctly in the first place.

## Anatomy: one parameter, one fetch, one network

The minimal vulnerable shape fits in four lines:

```python
url = request.args.get("url")          # source: attacker-chosen destination
resp = requests.get(url)               # sink: follows redirects by default
return resp.content                    # optional amplifier: body returned
```

Walkthrough of one request:

1. The attacker submits `?url=http://169.254.169.254/latest/meta-data/iam/` —
   or any internal address the server can reach and they cannot.
2. The library resolves and dials from *inside* the VPC/pod. Firewalls that
   block outsiders see a normal outbound request from a trusted workload.
3. Nothing "broke" — the feature did exactly what it was built to do, just with
   a destination chosen by someone else. The bug is that no boundary separated
   "destinations users may pick" from "networks this server may touch."
4. If responses are echoed back, internal bodies come straight out. If not,
   timing and error differentials still prove reachability (blind SSRF).

Validation that looks present usually is not, because the validator and the
sink disagree about what the URL *is*:

```python
if url.startswith("https://trusted.example.com"):   # string-prefix view
    ...
requests.get(url)   # https://trusted.example.com@169.254.169.254/
                    # parser view: userinfo "trusted...", HOST = metadata IP
```

Every mainstream URL grammar places everything after the last `@` in the host;
prefix-matching validators do not. The same divergence family includes
backslash-as-slash (WHATWG parsers fold `\`, strict parsers keep it), numeric
IP encodings (`2130706433`, `0x7f000001`, `127.1` all reach loopback), and
double-decoding applied after validation. The durable fix — parse-validate-pin-
revalidate — works because it aligns both sides on one parsed representation,
checks every resolved address at dial time, and re-runs validation per redirect.

## Why naive fixes fail

One subsection because each naive fix has a named bypass tier:

- **Blocklists of literal IPs and names.** Numeric encodings, IPv6 forms
  (`[::1]`, `[::ffff:127.0.0.1]`), and DNS-name services mapping arbitrary
  subdomains to loopback walk straight past enumerated strings. You cannot list
  an infinite language of spellings.
- **Allowlists evaluated once on the raw string.** Suffix/substring matches
  accept `eviltrusted.com`; prefix matches accept userinfo tricks; anything
  short of parse-then-exact-compare is representation theater.
- **Trusting DNS names without pinning addresses.** Validation resolves the
  name, passes, and the client re-resolves at connect time into attacker-controlled
  DNS (TTL 0). Any validate-then-connect gap owns this rebinding window.
- **Counting redirects instead of validating them.** Raising `maxRedirects`
  still lands hop N on metadata; only per-hop revalidation closes the classic
  302-to-`169.254.169.254` amplification.
- **Relying on provider header gates alone.** IMDSv2 blocks GET-only sinks;
  GCP/Azure require specific headers — but a sink that forwards attacker-chosen
  method and headers crosses all of them. Header gates are hardening, not fixes.
- **Egress firewalls as the primary control.** Network deny rules help and
  should exist, but flat pod networks, NAT exceptions, and IPv6 gaps routinely
  leave lanes open; the report still requires the application-layer fix.
- **`FILTER_VALIDATE_URL`-style syntax checks.** Syntax validity says nothing
  about which hosts are permitted; treating parser success as authorization is
  a category error.

## Common misconceptions

1. "SSRF requires the response body." Blind SSRF proves reachability through
   timing (refused vs. hang vs. distinct status), error text, and out-of-band
   callbacks — enough for internal port scanning and metadata confirmation.
2. "We don't have a 'fetch URL' feature, so we're clear." Importers, avatar
   proxies, PDF renderers, SSO issuer settings, analytics Referer fetchers, and
   webhook configurators are all fetch primitives wearing product costumes.
3. "IMDSv2 means cloud metadata is handled." IMDSv2 defeats GET-only clients;
   sinks where the attacker controls method plus headers (many HTTP libraries)
   still complete the token flow, so enforcement must be verified in IaC.
4. "Open redirects are low severity, full stop." As standalone phishing aids,
   yes — but chained behind an SSRF filter they convert a validated URL into an
   internal one, which is why this module audits them together.
5. "HTTPS-only allowlists stop scheme abuse." Scheme locking stops
   `file://`/`gopher://`, but https URLs pointing at internal IPs remain SSRF;
   scheme and host checks answer different questions.
6. "The firewall makes code-level validation redundant." Egress controls are
   defense-in-depth whose coverage shifts with every network refactor; findings
   cite both layers and demand neither substitutes for the other.
7. "IPv6 range checks are optional extras." Link-local `fe80::/10`, ULA
   `fc00::/7`, and IPv4-mapped `::ffff:0:0/96` are first-class internal ranges;
   dotted-quad-only policies miss entire families of loopback-equivalents.

## How professionals think about it today

Modern practice decomposes every candidate into four layers — source,
validation, resolution, transport — and reports the first layer where control
is lost. The taxonomy mirrors SKILL.md's sections:

| Class | Failure layer | Defining control |
|---|---|---|
| Classic SSRF | validation absent | enumerate every outbound-fetch feature |
| Filter-bypass SSRF | validation (parser mismatch) | real parser + exact host compare + full IP-range denial |
| Redirect amplification | resolution across hops | manual redirect loop, revalidate every hop |
| DNS-rebinding TOCTOU | resolution over time | pin validated address onto the connection |
| Blind SSRF | detection gap | timing/error differentials + OOB callbacks |
| Metadata exposure | transport reaches link-local | IMDSv2/hop-limit in IaC + denied ranges incl. 169.254/16 |
| Internal-service pivots | transport inside trust zone | least-privilege fetch service, egress policy as backup |
| Open redirects | browser-side Location sinks | parse-and-exact-match same-origin enforcement |

Severity thinking follows credential proximity: read access to role credentials
or k8s service-account paths is Critical; blind internal port scanning is
High–Medium by environment; open redirects alone stay Low–Medium unless chained.
Static confirmation (source → validator → sink with documented library defaults)
is sufficient evidence — dynamic probes are corroboration against authorized
targets, never a prerequisite for reporting.

## Read next

In `../SKILL.md`: **Mental Model** (four layers, parser-mismatch root),
**What To Check** (feature enumeration through egress review), **Where To Look**
(sink catalog and repo signals), **Patterns & Signatures** (evasion ladder,
metadata cheat-sheet), **Taint Tracing Guidance** (validator/sink semantics
diffing), **Exploitation & Reproduction** (static-first procedures), **Remediation**
(parse-validate-pin-revalidate per language), **Common False Positives**.

Sibling modules: `../oauth-sso/SKILL.md` (`redirect_uri` interception chains),
`../dns-takeover/SKILL.md` (dangling names amplifying rebinding-style bugs),
`../http-protocol/SKILL.md` (parser quirks below the URL layer), `../crypto/SKILL.md` (webhook HMAC design), `../cloud-iam/SKILL.md` (what stolen role
credentials unlock), `../configuration-hardening/SKILL.md` (actuator surfaces
reachable through the fetch primitive).
