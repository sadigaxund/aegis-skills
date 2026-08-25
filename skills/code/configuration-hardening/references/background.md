# Configuration Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, config tables, and remediation recipes.

## How this class emerged

Misconfiguration is older than the web. The first multi-user operating systems
already shipped with permissive defaults — world-writable files, open network
services, well-known administrative passwords — and every generation of
administrators relearned that a default is a decision someone made for you.
Server-hardening guides and consensus benchmarks appeared in the late 1990s and
early 2000s precisely because "the vendor shipped it this way" kept turning into
incidents, and OWASP gave the category its modern name when *Security
Misconfiguration* entered the Top 10 in 2013.

The class then re-expanded with each new deployment layer:

- Application frameworks grew built-in conveniences — debug pages, interactive
  consoles, diagnostics endpoints — designed for development and dangerous when
  they reach production unchanged.
- Containers and orchestrators (Docker's mainstream arrival was 2013) moved
  defaults from `server.conf` files into images, compose files, and pod specs,
  where running as root, mounting the daemon socket, and default-allow networks
  became the path of least resistance.
- Infrastructure-as-code turned cloud consoles into reviewable text — which also
  means an open security-group rule is now greppable evidence rather than a
  click someone forgot.
- Managed platforms and reverse proxies added the newest layer: headers,
  timeouts, forwarded-header trust, all decided at the edge where the app never
  sees the choice.

Two root causes explain nearly every finding in this module: an **insecure
default accepted** (nobody flipped the switch) or a **hardening step omitted**
(the control exists but was never configured). Everything else is detail.

## Anatomy: one flag, one leak

The minimal shape needs no exploit at all — just a value that differs between
the developer's laptop and production:

```python
# settings module named by the production entrypoint
DEBUG = True
ALLOWED_HOSTS = ["*"]
```

Walkthrough of what happens on one bad request:

1. A request arrives for a URL that does not exist (`/items/?page=NOT_AN_INT`
   forces an exception instead).
2. With debug enabled, the framework answers not with a generic error page but
   with a diagnostic one: full traceback, source lines, local variables, and
   settings values.
3. Nothing "broke" — the developer asked for exactly this behavior while
   debugging last month, and the profile resolution silently kept it on.
4. Every visitor now reads internals that were meant for the author's terminal:
   file paths, library versions, query text, configuration keys.

The same anatomy recurs across the module's classes, only the switch changes:

```yaml
# management plane shipped wide open
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

A diagnostics endpoint intended for operators becomes an unauthenticated map of
environment properties; a heap-dump endpoint hands over megabytes of process
memory to anyone who asks. CORS follows the identical pattern one level up:

```javascript
// reflects any Origin and lets cookies through
app.use(cors({ origin: true, credentials: true }));
```

Here the failure is *reflection plus credentials*: the server echoes whatever
website asked and simultaneously tells browsers that cookies may ride along, so
any page on the internet can make a victim's browser read session-scoped data.

The fix pattern is always channel discipline, not cleverness: resolve which
settings profile actually boots in production, judge only that profile, and set
explicit allowlists (origins, hosts, exposure lists) instead of wildcards or
echoing client input.

## Why naive fixes fail

One subsection because the failure modes rhyme across all ten classes:

- **Fixing the dev settings too hard.** Teams delete `DEBUG = True` everywhere
  except a module nobody traced — and production boots that module via
  `DJANGO_SETTINGS_MODULE` or a container env var. If you did not resolve which
  profile wins at process start, you fixed a file, not the deployment.
- **Header-by-header patching in the wrong layer.** Adding headers inside app
  code when the reverse proxy terminates requests (or vice versa) leaves one of
  two response paths unprotected; nginx additionally drops server-level
  `add_header` directives inside any `location` block that defines its own.
- **CORS allow-by-suffix.** `origin.endsWith("example.com")` accepts
  `https://evilexample.com`; unanchored regexes do the same. Only anchored
  comparison over the parsed hostname closes it, and `"null"` origins must be
  rejected outright, not whitelisted "for local dev".
- **Renaming instead of removing.** Hiding an actuator endpoint behind a secret
  path or renaming an admin console lowers discoverability by days. Exposure
  decisions belong to authentication and binding addresses, not spelling.
- **Disabling the noisy check.** Turning off TLS verification warnings
  (`verify=False`, `rejectUnauthorized: false`) makes the warning disappear and
  keeps the man-in-the-middle. Internal traffic deserves validated encryption
  precisely because nobody watches it.
- **Treating IaC as reviewed because it is code.** Committed Terraform still
  contains `cidr_blocks = ["0.0.0.0/0"]` on database ports in plenty of repos;
  version control records mistakes, it does not prevent them.
- **Default credentials "temporarily" left.** Seed users and compose-file
  passwords survive sprints because nothing forces their rotation; a known
  vendor pair is public knowledge the day it ships.

## Common misconceptions

1. "It's just a debug flag, low severity." Debug pages routinely include
   settings values and SQL; paired with anything sensitive they become secret-
   exposure findings, and the Werkzeug-style interactive console is remote code
   execution if reachable.
2. "Actuator `/health` being open proves exposure is fine." Health and info are
   the safe defaults of modern Spring Boot; the findings are `/env`,
   `/heapdump`, `/threaddump` — the ones requiring explicit opt-in exposure.
3. "CORS errors mean the API is protected." Browsers enforce CORS; curl does
   not. CORS governs who may *read* responses cross-origin, never whether the
   endpoint can be called — confusing the two hides real authorization gaps.
4. "Missing security headers are cosmetic." Each absent header removes a
   browser-enforced control (sniffing defense, framing limits, transport
   pinning). They are cheap defense-in-depth, and their absence correlates with
   unreviewed edge configurations.
5. "Cookies without flags are fine on HTTPS-only sites." One plaintext hop, one
   misconfigured subdomain, or one proxy downgrade leaks them; `Secure`,
   `HttpOnly`, and `SameSite` exist because networks and scripts fail in ways
   TLS alone does not cover.
6. "Containers are isolated by default." Without a `USER` directive they run as
   root; without resource limits one workload starves neighbors; with the
   Docker socket mounted, container escape stops being hypothetical.
7. "Version disclosure is harmless." By itself informational — but it converts
   attacker reconnaissance from guesswork into lookup, so suppression is cheap
   hygiene worth doing anyway.

## How professionals think about it today

Modern practice reads the repository as five stacked layers (proxy → runtime →
framework switches → containers/IaC → default identities) and hunts two root
causes per layer. The taxonomy mirrors SKILL.md's ten sections:

| Layer/class | Typical gap | Defining control |
|---|---|---|
| Debug/error modes | verbose pages reaching clients | prod-profile resolution + generic error handler |
| Admin/debug surfaces | actuators, toolbars, consoles exposed | exposure lists + loopback/auth-gated management ports |
| CORS | reflection/wildcard with credentials | exact-origin allowlist, no `null`, credentials only when needed |
| Security headers | baseline missing at the edge | one canonical edge config with `always` semantics |
| Cookie flags | session cookies transportable/scriptable | `Secure`/`HttpOnly`/deliberate `SameSite`; prefixes where supported |
| TLS | legacy protocols, verification disabled | modern protocol floors; pinned internal CAs |
| Containers/IaC | root, privileged, open CIDRs | non-root users, dropped capabilities, deny-by-default networks |
| Default credentials | seed users, vendor pairs | no known pairs in any deployed environment |
| Version disclosure | fingerprinting headers | suppression directives at each server |
| Reverse proxy gaps | no size caps/timeouts, blind XFF trust | explicit limits; hop-count proxy trust |

Severity thinking follows exposure: secrets or heap dumps reachable
unauthenticated are Critical–High regardless of elegance; a single missing
low-value header is Low hygiene. Record the *effective* configuration for the
production deploy target — judging a dev profile that never boots wastes the
report's credibility.

## Read next

In `../SKILL.md`: **Mental Model** (five layers, two root causes), **What To
Check** (the ten classes in order), **Where To Look** (artifact table), **Patterns & Signatures** (ripgrep sweeps and absence checks), **Taint Tracing
Guidance** (Origin/XFF/exception flows), **Remediation** (hardened configs per
stack), **Verification & Validation**, **Severity Assessment**, **Common False
Positives** (dev-profile traps).

Sibling modules: `../secrets-data-exposure/SKILL.md` (what leaked `.env` and
heap dumps contain), `../authn-session/SKILL.md` (session-cookie semantics),
`../authz-access-control/SKILL.md` (forwarded-header trust abuse),
`../web-client/SKILL.md` (clickjacking and CSP mechanics), `../denial-of-service/SKILL.md` (timeout and size-limit math), `../cloud-iam/SKILL.md` (wildcard IAM policies).
