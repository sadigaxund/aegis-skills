# HTTP Protocol Attacks — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & cheat sheets

- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html) - the formal weakness behind every desync finding, with duplicate-CL and TE+CL exemplars.
- [RFC 9112: HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc9112) - normative framing rules (Content-Length vs Transfer-Encoding conflict handling, request-smuggling security considerations) the whole module leans on.

## Deep dives

- [PortSwigger Web Security Academy: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) - canonical CL.TE / TE.CL / TE.TE walkthroughs plus advanced h2-downgrade, CL.0, and browser-powered desync material.
- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header) - reset-poisoning, routing-based SSRF, and virtual-host confusion methodology matching the Host model's three consumers.
- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) - unkeyed-input discovery and cache-key flaw exploitation underlying the poisoning checks.
- [PortSwigger Web Security Academy: Web cache deception](https://portswigger.net/web-security/web-cache-deception) - path/delimiter/normalization discrepancy catalog behind extension-rule deception findings.

## Vendor docs

- [MDN: Host header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) - reference statement of Host semantics (mandatory in HTTP/1.1, single-instance requirement) grounding the host-abuse checks.

(7 URLs total; each returned HTTP 200 with matching content when fetched.
Sibling-module cross-references live in background.md's "Read next" section.)
