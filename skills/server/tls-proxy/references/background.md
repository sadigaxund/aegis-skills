# TLS Proxy & Edge Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind protocol floors, certificate posture, edge headers, request limits,
admin-path shielding, and the proxy-to-app trust hop; SKILL.md carries the exact
probes, hardened blocks, and verification sequences.

## How this class emerged

Encrypted web traffic began as Netscape's SSL in the mid-1990s; the IETF
standardized it as TLS in 1999. For its first fifteen years the protocol stack
accumulated versions nobody removed: servers kept accepting SSLv3 and TLS 1.0
long after attacks against them were public, because disabling them broke old
clients. The cleanup came in waves — SSLv3 fell out of favor in the mid-2010s,
and the IETF formally deprecated TLS 1.0 and 1.1 in the early 2020s — which is
why "protocol floor" is a *configuration* finding: the library usually still
supports the legacy versions until the operator says otherwise.

Three more historical shifts shaped this layer:

- **Automated certificates.** Paid certificates with manual renewals meant
  expired-cert outages were routine. Free, automated issuance via the ACME
  protocol (mainstream since the mid-2010s) inverted the failure mode: renewal
  now happens on a timer, decoupled from your web-server configuration — so a
  hardening change that silently blocks the challenge path fails *weeks later*,
  near expiry, with nothing broken today.
- **The reverse proxy became the standard edge.** As applications stopped
  binding port 443 themselves, a proxy front (nginx above all, then Caddy,
  HAProxy, Apache) took over termination, header policy, size limits, and path
  gating — decisions the application never sees and cannot fix.
- **Headers became policy.** Strict Transport Security (standardized 2012) and
  companion headers let the server instruct browsers to enforce HTTPS-only,
  framing limits, and content-type discipline. They are cheap, but they carry
  commitment semantics: set carelessly, they can lock users out for their full
  max-age duration.

## Anatomy: one vhost, four quiet failures

A minimal generic weak edge looks like this:

```nginx
server {
    listen 443 ssl;                 # first-loaded block = implicit catch-all
    ssl_certificate     /etc/letsencrypt/live/site/fullchain.pem;
    # no ssl_protocols line -> library-dependent floor, possibly TLS 1.0
    location / {
        add_header X-Something "1";             # erases ALL server-level headers
        proxy_pass http://10.0.4.7:8000;        # plaintext hop across the network
    }
}
```

Walkthrough of how this fails:

1. **Unknown Host headers reach the app.** With no explicit `default_server`
   rejecting them, requests for any hostname resolving to this IP match the
   first-loaded vhost and are proxied inward — handing attackers host-header
   attack surface (cache keys, password-reset links, routing).
2. **The protocol floor is unverified.** Absent `ssl_protocols`, an older
   OpenSSL build negotiates TLS 1.0 with a client that insists on it — exactly
   what downgrade-and-intercept tooling aims for.
3. **Header hygiene vanishes on one path.** Because nginx inherits header lists
   only when the inner level declares none, that single `add_header` inside the
   location erases every server-level security header for those responses.
   Verify per-path or you will miss it.
4. **Credentials cross the wire in cleartext.** The upstream hop rides plaintext
   HTTP over a real network segment; anything adjacent — a compromised peer VM,
   a sniffing tenant — reads tokens and session cookies in transit.
5. **Renewal is a time bomb elsewhere.** If hardening later adds auth or denies
   to everything except the named vhost without carving out the ACME challenge
   path, nothing fails today — and the certificate quietly dies at expiry.

## Why naive fixes fail

- **Hand-composing cipher strings.** Cipher names, ordering, and OpenSSL-version
  quirks make hand-rolled strings fragile; profiles generated for your exact
  server/library pair exist precisely to prevent this class of error.
- **Committing long HSTS max-age immediately.** Browsers pin the policy for the
  whole window; if HTTPS later breaks on a covered host or subdomain, affected
  users stay locked out up to that duration. Stage upward (minutes → hours →
  days → 180 days) after monitoring stays clean, and add `includeSubDomains`
  only after proving valid HTTPS on every subdomain.
- **Reversing allow/deny order.** Access rules evaluate top-down and stop at
  the first match; `deny all;` written first makes every allow below it dead
  code — an availability bug disguised as hardening.
- **Treating requested client certificates as verified ones.** A mode that
  checks the cert parses but accepts any chain is identity theater; gates need
  strict verification plus enforcement of the verify result.
- **Blocking the challenge path while tightening paths.** Global auth/deny/
  redirect rules shadow `/.well-known/acme-challenge/` silently; carve-outs must
  be tested with a staging dry-run before production quota is involved.
- **Setting proxy timeouts below real latency.** Reports and exports legitimately
  take minutes; clamping read timeout to a tidy number trades a DoS risk for
  truncated responses and spurious 504s. Measure p99 first.

## Common misconceptions

1. "Browsers load the site, so TLS is fine." Browsers fetch missing intermediates
   opportunistically; non-browser clients (curl, Java, mobile SDKs) fail on
   incomplete chains with "unknown authority" — the classic works-for-me incident.
2. "`server_tokens off` hides our stack." It removes the version only; bare
   product identification remains, and full suppression needs third-party
   modules. Treat disclosure as low-severity fingerprinting aid, not invisibility.
3. "We ask for a client certificate, so it's mTLS-gated." Requesting is not
   enforcing; only strict verification plus checking the verification result
   constitutes access control.
4. "`X-Forwarded-For` gives me the client's IP." The leftmost entries are
   attacker-written text; only walking right-to-left past exactly your own
   infrastructure yields an attributable address.
5. "Internal traffic doesn't need encryption." Across any network segment,
   plaintext hops expose credentials to everyone adjacent — the definition of
   the cleartext-transmission weakness class.
6. "Certificate automation means certificates are handled." Automation covers
   issuance; reload hooks, challenge-path reachability, and rate-limit hygiene
   remain manual responsibilities that fail silently when neglected.
7. "Two HSTS headers are better than one." Duplicate headers are a conflict
   between edge and app; pick one layer (the edge) and remove the other.

## How professionals think about it today

Modern practice treats the proxy as two trust boundaries meeting — hostile
client-to-edge, and edge-to-app that must be either loopback-local or encrypted
— and maps every check onto one boundary. The taxonomy mirrors SKILL.md's own
sections:

| Domain | Typical gap | Defining control |
|---|---|---|
| Inventory & ownership | mystery listeners on 80/443 | process-to-config mapping |
| Version disclosure | banner leaks aiding recon | token suppression, banner hiding |
| Vhost map / catch-all | unknown Hosts routed inward | explicit names + rejecting default server |
| TLS floor & ciphers | legacy protocols, ad-hoc strings | generated intermediate profile, modern floor |
| Certificate posture | short expiry, missing chain/SAN | served-chain checks, active renewal timer |
| Edge headers | inheritance trap, double-set HSTS | one canonical layer, `always` flag |
| Request limits | uncapped uploads, slow-client holding | right-sized body caps and timeouts |
| Admin-path shielding | `/admin` 200 from internet | CIDR/auth/mTLS gates in correct order |
| Proxy-to-app hop | plaintext across segments | loopback/unix targets or upstream TLS |
| Renewal machinery | dead timers, missing deploy hooks | dry-run proof, executable hooks |

Severity follows exposure and chain position: an ungated admin path raises
everything behind it by a band; a broken renewal loop is an availability
incident waiting for its date.

## Read next

In `../SKILL.md`: **Scope & Objectives**, **Mental Model** (two boundaries, four
structural rules), **What To Check** (twelve numbered areas), **Where To Look**
(filesystem, remote probes, repo sweeps), **Patterns & Signatures** (finding and
compliant directive shapes), **Taint Tracing Guidance** (Host and XFF derivation
rules), **Exploitation & Reproduction** (R1–R12 read-only probes),
**Remediation** (F1–F7 hardened blocks including the complete edge config and
ACME invariant), **Verification & Validation** (staged HSTS rollout, negative
battery), **Severity Assessment**, **Common False Positives** (CDN-fronted
origins, provider-managed LBs).

Sibling modules: `../firewall-edge/SKILL.md` (whether these ports are reachable
at all), `../api-token-security/SKILL.md` (what rides the hop you secure),
`../linux-baseline/SKILL.md` (clock sync underpinning certificate validation and
log correlation), `../updates-patching/SKILL.md` (proxy-package currency),
`../logging-monitoring/SKILL.md` (where access-log evidence lands).
