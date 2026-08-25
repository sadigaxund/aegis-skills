# Web Client Attacks — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no prior security background assumed. Teaches the *why*; SKILL.md keeps the
payload tables, sink matrices, and remediation recipes.

## How this class emerged

The browser was designed to mix documents from everywhere into one page while
keeping origins apart. Two failure families grew out of that tension:

- **Cross-site scripting** got its name at Microsoft in the late 1990s, when
  engineers noticed scripts "crossing" between sites that shared a host. A CERT
  advisory in early 2000 warned about malicious HTML tags embedded in web
  requests, and the class has never left the top of the risk lists since.
- **Cross-site request forgery** was formalized around 2001 as researchers
  showed that a browser silently attaches cookies to any request a page makes,
  so one site could drive another user's authenticated actions.

Later waves followed browser capability growth: clickjacking (overlay attacks
disclosed publicly in 2008) exploited framing; `postMessage` abuse arrived with
iframe-mashup architectures; client-side template injection emerged in the
mid-2010s once SPAs shipped template compilers to every visitor's browser. The
pattern is constant: each new browser feature becomes a new way for attacker
data to turn into behavior inside someone else's session.

## Anatomy

**Reflected XSS** — the server echoes input into HTML:

```html
<p>Results for: <?php echo $_GET['q']; ?></p>
```

Walkthrough: request `?q=<img src=x onerror=alert(1)>`. The browser parsing the
response cannot know which bytes were "meant" as text; `<img` opens a tag, the
event handler fires, and attacker script runs with the victim's origin — their
cookies, their DOM, their authority. The server never executed anything; the
*victim's browser* is the compromised machine.

**CSRF** — no injection needed at all. The victim's browser holds an ambient
credential (session cookie). An attacker's page auto-submits:

```html
<form action="https://bank.example/email" method="POST">
  <input name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit()</script>
```

The browser sends it with cookies attached; the server sees a valid
authenticated request the victim never intended. XSS and CSRF are complements:
XSS makes the victim's browser run attacker *code*, CSRF makes it send attacker
*requests*.

**Client-side template injection** — an SPA compiles user text as template
source instead of binding it as data; the framework executes embedded
expressions in the victim's browser, equivalent in power to stored XSS.

## Why naive fixes fail

One subsection because the same errors recur across every sub-class:

- **Blacklisting `<script>`** ignores event handlers, SVG/iframe elements,
  `javascript:` URIs, and encoding variants. HTML grammar offers dozens of
  execution contexts; you cannot enumerate them faster than browsers add them.
- **Client-side sanitization** happens where the attacker controls the code;
  filtering must occur at the final output sink.
- **POST-only assumptions** treat method choice as protection; attackers forge
  POSTs with forms just as easily as GETs with images.
- **Referer-checking** breaks on privacy settings and missing headers, and
  misfires on legitimate flows — an unreliable gate.
- **Obscurity** (hidden admin buttons, SPA routes rendered only for admins)
  leaves backing endpoints unprotected; bundles and network traces reveal them.
- **"HttpOnly stops XSS"** confuses one mitigation (cookie theft) with the class
  (code execution). Keylogging, action forgery, and DOM exfiltration survive.
- **CSP as the primary fix** inverts the model: strict CSP raises exploit cost,
  but `'unsafe-inline'`, wildcards, and legacy endpoints routinely gut it.

## Common misconceptions

1. "XSS means injecting a `<script>` tag." Event-handler attributes, SVG,
   `srcdoc` iframes, and `javascript:` URLs execute without any script tag.
2. "Modern frameworks escape everything." They escape *text interpolation*;
   every framework ships deliberate escape hatches (`dangerouslySetInnerHTML`,
   `v-html`, `{@html}`, `bypassSecurityTrust*`) whose misuse is the finding.
3. "JSON APIs can't be hit by CSRF." If the endpoint tolerates text/plain bodies
   or query parameters, a cross-site form reaches it; content-type checks are
   not origin checks.
4. "SameSite=Lax ends CSRF." Top-level GET navigations still carry cookies under
   Lax, sibling subdomains are same-site, and state-changing GET routes remain
   exposed.
5. "Encoding once, anywhere, is enough." Encoding is context-specific: an
   entity-encoded value placed into a JS string context, or JSON inserted into
   HTML, is still exploitable. Match the operation to the sink context.
6. "postMessage is safe because it replaced direct DOM access." A receiver that
   skips `event.origin` allowlisting plus payload schema checks accepts messages
   from any hostile frame embedding it.
7. "Clickjacking only matters for trivial pages." Overlay attacks target exactly
   the sensitive flows — password change, MFA disable, payment consent — where a
   single misdirected click transfers authority.

## How professionals think about it today

Practice organizes the field by *where data lands* and *who holds authority*,
mirroring SKILL.md's structure:

| Branch | Question | Core control |
|---|---|---|
| Reflected / stored / DOM-based / mXSS | Where does attacker data become markup? | context-aware output encoding at the final sink |
| Framework escape hatches | Which raw sinks exist per stack? | text-node defaults; sanitizer with default profile |
| Client-side template injection | Is user text compiled as template source? | compile-time constants only; bind data via props/interpolation |
| CSRF | Does an ambient credential authorize this request? | per-session tokens + SameSite + safe-method design |
| Clickjacking / framing | Can another page overlay or embed this UI? | X-Frame-Options + CSP frame-ancestors on sensitive pages |
| Cross-origin messaging | Does every handler validate sender origin and schema? | explicit `event.origin` allowlist; typed payload validation |
| Client storage / clobbering / redirects | What does XSS reach if it happens? | no tokens in web storage; declared globals; redirect allowlists |

Two habits distinguish professional analysis from pattern matching:

- **Context-first classification.** Before writing any probe, name the parse
  context at the echo point (element, attribute, script string, URL, CSS);
  everything else follows from that row.
- **Authority accounting.** For CSRF and framing questions, reason about where
  credentials live (cookies vs headers vs tokens) rather than about endpoints;
  ambient-authority design is the vulnerability.

Severity thinking tracks privilege: XSS reaching admin consoles rates Critical
because it hijacks sessions of the most powerful users; reflected payloads need
a lure but exploit identically once delivered.

## Read next

In `../SKILL.md`: **Mental Model — Source-Sink Model** and the **Injection
Context Table**, **What To Check**, **Where To Look** (per-stack file maps),
**Patterns & Signatures**, **Remediation — Context-Aware Output Encoding Rules**
and **CSP Guidance**, **Common False Positives** (safe syntax that merely looks
dangerous).

Sibling modules: `../configuration-hardening/SKILL.md` (cookie attribute and
security-header matrix), `../http-protocol/SKILL.md` (cache deception and
protocol-level delivery), `../file-handling/SKILL.md` (SVG upload as stored-XSS
delivery), `../oauth-sso/SKILL.md` (redirect and consent-surface handling).
