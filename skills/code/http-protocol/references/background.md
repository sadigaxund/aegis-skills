# HTTP Protocol Attacks — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why*; SKILL.md carries the desync matrices, payload cheat-sheets,
and proxy configuration fixes.

## How this class emerged

HTTP/1.0 was simple: one request per connection. The 1997-era introduction of
persistent connections ("keep-alive") made browsers fast but created the
question that defines this whole module: **where does one request end and the
next begin?** Two answers were standardized — a `Content-Length` byte count,
and chunked transfer encoding terminated by a zero-size chunk — plus a rule
that if both appear, Content-Length must be ignored.

The attacks began as soon as deployments grew a second parser:

- In the mid-2000s researchers formalized "request smuggling": when a front-end
  proxy and a back-end server resolve conflicting framing headers differently,
  an attacker's request body is reinterpreted by the back-end as the start of
  the next request on the reused connection.
- Virtual hosting added the Host header problem: one IP serving many sites
  needs some header to pick a destination, so applications started trusting a
  client-controlled value to build password-reset links, redirects, and even
  upstream routing decisions.
- Caches introduced a third disagreement: which parts of a request identify it
  ("the cache key") versus merely influence its response ("unkeyed inputs").
  Anything unkeyed yet reflected becomes a poisoning primitive served to every
  subsequent visitor; deception flips the direction, storing victims' private
  responses under keys strangers can fetch.
- Duplicate parameters (HPP) exploit the same theme at the framework layer:
  two layers collapsing `?role=user&role=admin` differently split validation
  from execution.

The modern lesson: these are *disagreement* bugs between parsers that are each
individually RFC-compliant-ish. Fixes live in edge normalization and strict
rejection policies, not application refactors — which is why findings here are
usually configuration-level deliverables.

## Anatomy: CL.TE in four lines

Minimal generic vulnerable exchange (front-end prefers Content-Length,
back-end prefers Transfer-Encoding):

```text
POST /search HTTP/1.1
Host: shop.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Failure walkthrough:

1. The front-end reads `Content-Length: 13` and forwards exactly 13 body bytes:
   `0\r\n\r\nSMUGGLED`.
2. The back-end honors `Transfer-Encoding: chunked`; the `0\r\n\r\n`
   terminator ends the request cleanly, leaving `SMUGGLED` buffered on the
   persistent connection.
3. The next legitimate user whose request lands on that socket has the
   attacker's `SMUGGLED` prefix spliced onto the front of their request —
   method, path, and headers all attacker-chosen.
4. Consequences scale with imagination: responses delivered off-by-one (queue
   displacement), captured victim requests including session cookies, poisoned
   caches, or security controls bypassed entirely because the smuggled second
   request never passed the front-end's inspection.

TE.CL is the mirror image (front-end chunks, back-end counts bytes), TE.TE
obfuscates the header so only one parser recognizes it (`xchunked`,
`Transfer-Encoding :` with a space, obs-fold continuations), and CL.0 exploits
routes that never read their bodies. Same anatomy, different disagreement.

## Why naive fixes fail

Each tempting approach below fails; SKILL.md's Remediation section shows the
working shapes.

- **"Just use HTTPS."** Encryption hides smuggling from passive observers;
   both parsers still parse plaintext inside the tunnel. TLS changes nothing.
- **Disabling keep-alive everywhere as a first move**: removes the delivery
   channel but wrecks latency budgets and does not stop request tunnelling
   variants; per-route fallbacks exist for a reason.
- **Application-level header filtering**: the app is downstream of the
   disagreement; by the time it sees anything, framing was already decided.
   Normalization belongs at the outermost terminating layer.
- **Dropping `Transfer-Encoding` blindly**: forwarding a raw chunked body with
   the header stripped corrupts every legitimate chunked upload; strip means
   de-chunk-and-reissue with correct Content-Length.
- **Trusting the CDN/WAF to normalize**: provider behavior varies by product
   and plan tier; assumptions without verification are Needs-Review, not safe.
- **Building absolute URLs from whatever Host arrives**: password-reset
   emails, canonical tags, and redirects inherit attacker hosts; only a
   configured allowlist breaks that dependency.
- **Caching by file extension alone**: `/settings/nonexistent.js` tricks
   extension rules into caching authenticated pages — the deception enabler.
- **Fixing HPP by picking "first wins" in one place**: unless validation and
   business logic read through the *same* accessor, split-brain survives.

## Common misconceptions

1. **"Request smuggling is dead."** HTTP/2 end-to-end removes classic CL/TE
   ambiguity, but h2-to-h1 downgrade paths, CL.0 routes, and browser-powered
   client-side desync keep the class alive wherever proxies translate.
2. **"The Host header isn't user input."** It arrives over the network from the
   client like any other header; frameworks defaulting to trusting it are why
   reset-poisoning works at all.
3. **"Caches only store static files."** Caches store whatever their rules say
   — often keyed by extension or directory prefix — including authenticated
   dynamic responses that should never have been eligible.
4. **"If both servers are 'compliant,' there's no risk."** Compliance permits
   leniencies (bare-LF tolerance, whitespace handling); two lenient parsers can
   still disagree. Strict rejection of ambiguity is the fix, not conformance.
5. **"Duplicate query parameters are harmless."** Every stack collapses them
   somehow (first, last, comma-joined); security checks reading a different
   occurrence than business code is a working bypass.
6. **"`X-Forwarded-*` headers come from my LB, so they're trusted."** They are
   trusted only if the edge *overwrites* them on ingress; appended values let
   clients smuggle host/scheme hints past your own proxy.
7. **"One finding here means rewrite the app."** These are almost always
   configuration defects; the deliverable is a proxy/LB/cache config change
   plus regression tests, not application refactoring.

## Modern taxonomy map

Matches the coverage list in `../SKILL.md`'s Scope & Objectives section:

| Class | Essence | Canonical marker |
|---|---|---|
| Request smuggling (CL.TE) | Front counts bytes, back reads chunks | Both headers present |
| Request smuggling (TE.CL) | Front chunks, back counts bytes | Chunk-size prefix confusion |
| TE obfuscation / duplicate CL | One parser fooled by malformed TE | `xchunked`, obs-fold, `CL: 5, 5` |
| CL.0 | Route ignores its body on kept-alive socket | POST handlers never reading body |
| H2→H1 downgrade hazards | Re-serialization reintroduces ambiguity | Ingress terminating h2, proxying h1 |
| Host-header abuse | Server builds links/routes from attacker Host | Reset links, `$host` proxy_pass |
| Cache poisoning | Unkeyed input reflected into cached content | `X-Forwarded-Host` in canonical tags |
| Web cache deception | Victim's private response stored under public key | Extension/path cache-rule tricks |
| HPP | Layers collapse duplicates differently | checker-first vs consumer-last |
| Spoofable internal headers | Edge forwards `X-Original-URL` etc. verbatim | ACL bypass via header trust |

Severity intuition: confirmed desync enabling cross-user queue poisoning is
Critical; persistent cache poisoning and reset-poisoning chains rank High;
bounded HPP bypasses trend Medium.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — framing ambiguity, queue displacement, cache key model,
   three Host consumers, HPP collapse rules.
2. **What To Check** — the ordered twelve-step procedure from front-end map to
   internal-header stripping.
3. **Where To Look** — deployment artifacts that reveal every hop pair.
4. **Patterns & Signatures** — topology ripgrep block, desync matrix by proxy
   pair, framing/HPP/cache probe cheat-sheets.
5. **Remediation** — edge normalization configs, Host hardening, cache rules,
   HPP conventions.
6. **Common False Positives** — single-tier apps, pure h2 paths, and CDNs that
   genuinely normalize.

Sibling modules owning adjacent defects:

- `../injection/` — CRLF injection sinks in application code feeding headers.
- `../api-security/` — WebSocket upgrade hijacking details.
- `../configuration-hardening/` — general proxy/TLS hardening overlap.
