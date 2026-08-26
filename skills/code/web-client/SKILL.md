---
name: aegis-web-client
description: Detects and remediates browser-facing web vulnerabilities including reflected, stored, and DOM-based XSS, CSRF, clickjacking, unsafe postMessage handling, client-side storage misuse, DOM clobbering, client-side open redirects, and client-side template injection across React, Vue, Angular, Svelte, jQuery/vanilla JS, and major server-template stacks.
category_slug: WEB
cwe: [CWE-79, CWE-80, CWE-83, CWE-116, CWE-94, CWE-312, CWE-346, CWE-352, CWE-601, CWE-922, CWE-1021]
owasp: A03:2021 – Injection
---

## Scope & Objectives

### In Scope
- XSS in all three flavors: reflected (server echoes input), stored (input persisted then rendered to other users), DOM-based (client-side JS moves data from source to sink without a safe encoding step).
- Server-side template autoescaping bypasses (`|safe`, `mark_safe`, `{!! !!}`, `raw`, `<%-`, `@Html.Raw`, `th:utext`).
- Context-aware output-encoding review: HTML body, attributes, JS strings, URLs/hrefs, CSS.
- Mutation XSS (mXSS) triage at re-parsing sinks.
- CSP strength evaluation as a mitigating control.
- CSRF: token presence/validation across frameworks, state-changing GETs, JSON/content-type-only guards, SameSite analysis, custom-method validation gaps, login/logout CSRF.
- Clickjacking on sensitive pages via X-Frame-Options / frame-ancestors.
- Cross-origin pitfalls: postMessage handler origin/data validation; CORS-with-credentials reflection (deep config detail lives in the CONFIG module — cross-reference it, do not duplicate deeply).
- Client-side storage misuse: tokens/secrets/PII in localStorage/sessionStorage, password-field autocomplete.
- DOM clobbering gadgets and client-side open redirect via location manipulation (server-side redirects belong to the SSRF module).
- Client-side template injection: AngularJS `$compile`, Vue runtime templates, Handlebars/Mustache/lodash compile-from-string.
- Post-authentication stored dangers: admin-panel field rendering, filename rendering (SVG upload payload delivery is covered by the FILE module).
- Subresource Integrity: every `<script src>`/`<link rel=stylesheet>` pointing at third-party origins carries `integrity="sha384-..."` + `crossorigin`; a compromised CDN must not become script execution. Missing SRI on vendor assets = flag (first-party same-origin assets exempt).

### Out of Scope / Cross-references
| Topic | Owner module |
|---|---|
| Server-side open redirect chains used for SSRF, internal redirect targets | SSRF module |
| Deep cookie attribute matrix, CORS `Access-Control-Allow-*` reflection logic, cookie name inventory | CONFIG module |
| SVG upload validation, file-content sanitization, upload-path traversal | FILE module |

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **XSS**: injecting script into pages that other users' browsers then execute
- **output encoding**: rewriting user data so the browser displays it instead of executing it, matched to the surrounding context (HTML, attribute, JS string, URL)
- **DOM sink**: a browser API where data becomes code or markup (`innerHTML`, `eval`, `location=`)
- **CSP**: a page policy restricting which scripts and styles the browser may load
- **CSRF**: the victim's browser silently sending authenticated requests they never intended
- **CSRF token**: a random per-session value the server requires on state-changing requests
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function

## Mental Model

### Source-Sink Model
Every browser XSS is: attacker-controlled SOURCE -> unsanitized propagation -> dangerous SINK whose parsing CONTEXT determines which payload executes. Audit = enumerate sinks, walk back to sources, classify the context at the sink, pick the matching payload.

### Injection Context Table
The mapping below is the core audit skill. Identify where untrusted data LANDS, then the only payloads that matter are that row's payloads.

| Data lands in... | Parsing behavior | Payload class |
|---|---|---|
| HTML element content (body text) | Browser parses new tags | Element injection with event handlers (`<img src=x onerror=...>`) |
| Double-quoted HTML attribute value | Quote closes the attribute early | `" onmouseover="alert(1)" x="` breakout |
| Single-quoted attribute | Same with `'` | `' onmouseover='alert(1)' x='` |
| Unquoted attribute value | Whitespace terminates value | ` onfocus=alert(1) autofocus x=` |
| Inside a `<script>` block, inside a JS string literal | String delimiter closes literal | `";alert(1)//`, or `</script><svg onload=alert(1)>` to leave the block |
| JS template literal | `${}` interpolation executes | `${alert(1)}` |
| HTML comment | `-->` closes comment | `--><svg onload=alert(1)>` |
| URL attribute (`href`, `src`, `formaction`, `xlink:href`) | Scheme decides handler | `javascript:` URIs |
| `<style>` block or `style=` attribute | `</style>` closes block | Block escape; `expression()` is IE-only legacy (dead elsewhere) |
| Server template raw filter output | Same as element content | Standard element payloads |

### Reliable Event Handler Inventory (real, current)
| Vector | Works when |
|---|---|
| `<img src=x onerror=alert(1)>` | Element content anywhere; fires immediately |
| `<svg onload=alert(1)>` | Content context; no network request needed |
| `<details open ontoggle=alert(1)>` | Content context; no user interaction |
| `<input autofocus onfocus=alert(1)>` | Attribute breakout or content; fires on load |
| `" onmouseover="alert(1)" x="` | Attribute breakout; needs victim hover |
| `<iframe srcdoc="<script>alert(1)</script>">` | Content context; srcdoc inherits parent origin |
| `<video><source onerror=alert(1)>` | Content context |
| `javascript:alert(1)` in `href`/`formaction` | Still live on click in all modern browsers |

Dead/low-value payloads to avoid wasting time on: `expression(alert(1))` outside IE, `<meta http-equiv=refresh>` in modern sandboxes, `data:text/html` top-level navigation (blocked in current Chrome/Firefox/Safari), CSS `url(javascript:)`.

## What To Check

1. Scan all client bundles and templates for the raw-HTML sinks listed under Patterns & Signatures; for every hit, trace whether any request-derived or database-derived value reaches it.
2. Trace every reflected parameter: find its echo point in the response, classify the context (element/attribute/script/URL), and test the row-matching payload.
3. Flag every server-template raw construct (`|safe`, `mark_safe()`, `{!! !!}`, `<%==`, `<%-`, `|raw`, `th:utext`, `@Html.Raw`, `.html_safe`) whose variable originates from user input or a DB column writable by users.
4. Verify CSRF tokens exist AND are validated: presence of the hidden field alone proves nothing; replay requests without/bogus tokens.
5. Enumerate all state-changing routes; flag any reachable via GET, and any POST route missing framework CSRF protection or protected only by "must be JSON" content-type checks.
6. Read every Set-Cookie for session/auth cookies; record SameSite/Secure/HttpOnly and reason about state-changing GET exposure under Lax.
7. Fetch security headers specifically on sensitive pages (password/email change, 2FA disable, payment, API-key generation, OAuth consent): require `X-Frame-Options: DENY|SAMEORIGIN` or CSP `frame-ancestors 'none'`.
8. Review every `message` event listener for an explicit origin allowlist and schema/type validation of `event.data`; flag `postMessage(... , '*')` senders.
9. Grep localStorage/sessionStorage usage for token/secret/PII key names; check logout clears them.
10. Check password inputs for correct autocomplete hints (`current-password` login, `new-password` registration/change forms).
11. Hunt client-side open redirects: any assignment into `location.*`/`window.open` fed by query/hash params without an allowlist.
12. Hunt DOM clobbering preconditions: truthy reads of window globals and config objects that named elements can shadow.
13. Hunt client-side template compilation from strings (`$compile`, `Handlebars.compile(userStr)`, `_.template(userStr)`, Vue runtime `template:` option).
14. Evaluate CSP from code/config: flag `'unsafe-inline'`/`'unsafe-eval'` in script-src, wildcard sources, missing `object-src`/`base-uri`/`frame-ancestors`, and Report-Only-only deployment.
15. In admin panels and notification surfaces, verify every user-controlled field (username, filenames, profile fields, order notes) renders through text nodes or escaped templates, never raw HTML.
16. WebSocket surfaces found in client code (`new WebSocket(...)`): verify server-side origin checks at upgrade AND per-message authorization, not just handshake-time authentication.
17. Cross-reference boundaries: cache deception/poisoning analysis belongs to the PROTO module; full security-header audits belong to the CONFIG module — record pointers, do not duplicate deeply.

## Where To Look

| Stack | Files/directories to inspect | Notes |
|---|---|---|
| React / Next.js | `src/**/*.jsx`, `src/**/*.tsx`, `public/index.html`, `next.config.js`, `middleware.ts` | dangerouslySetInnerHTML, href interpolation, headers()/CSP config |
| Vue / Nuxt | `src/**/*.vue`, `nuxt.config.{js,ts}`, `vite.config.ts` | v-html directives; Nuxt `render.routeMeta`, head scripts |
| Angular 2+ | `src/app/**/*.ts`, `*.component.html`, `index.html`, anything importing `DomSanitizer` | Only bypassSecurityTrust* calls are high-signal |
| AngularJS 1.x (legacy) | `**/*.js` with `ng-bind-html`, `$compile`, `$sce.trustAsHtml` | Whole app is higher risk; JIT compiles templates |
| Svelte | `src/**/*.svelte` | `{@html ...}` expressions |
| jQuery / vanilla | `static/js/**`, `assets/js/**`, `dist/*.bundle.js`, inline `<script>` in templates | Member names survive minification; greps work on bundles |
| Express + EJS/Handlebars | `views/**/*.ejs`, `views/**/*.hbs`, `app.js`, `routes/**` | `<%- %>` vs `<%= %>` distinction; triple-stash |
| Jinja2 (Flask/FastAPI/Django-Jinja) | `templates/**/*.html`, any `*.py` calling `Markup(`, `Template(...).render` | `|safe` filters; `autoescape=false` |
| Django | `templates/**/*.html`, `**/views.py`, `**/models.py`, `settings.py` | mark_safe in Python code, not just templates; MIDDLEWARE list |
| Rails | `app/views/**/*.erb`, `app/controllers/application_controller.rb`, `config/initializers/content_security_policy.rb` | `protect_from_forgery` location; `raw`/`html_safe`/`<%==` |
| Laravel | `resources/views/**/*.blade.php`, `app/Http/Middleware/VerifyCsrfToken.php`, `app/Http/Kernel.php` | `{!! !!}`; `$except` array contents |
| Thymeleaf / Spring | `src/main/resources/templates/**/*.html`, `SecurityConfig.java` / `WebSecurityConfig*.java`, `application.yml` | th:utext vs th:text; `.csrf().disable()`; header config |
| Razor / ASP.NET | `**/*.cshtml`, `Program.cs`, `Startup.cs`, `Pages/**/*.cshtml.cs` | `@Html.Raw`; antiforgery global filters; cookie policy |
| Twig / Symfony | `templates/**/*.twig`, `config/packages/twig.yaml` | `autoescape: false` service option is repo-wide danger |
| Header/middleware config | `nginx.conf`, `.htaccess`, `web.config`, helmet setup, Django `MIDDLEWARE`, Spring `.headers()` | Where CSP/XFO actually get emitted |

## Patterns & Signatures

### DOM XSS Sinks (vanilla JS + libraries)
```regex
\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write(ln)?\s*\(|\.srcdoc\s*=|createContextualFragment\s*\(
```
```regex
\$\([^)]{0,120}\)\.(html|append|prepend|after|before|replaceWith|appendTo|prependTo|insertAfter|insertBefore|wrap|wrapAll|wrapInner)\s*\(
```
```regex
\b(eval|execScript)\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`]
```

### Request-Derived Sources
```regex
location\.(hash|search|href)|document\.(referrer|URL|documentURI)|window\.name|\bURLSearchParams\b|getParameterByName|\$_(GET|REQUEST|POST|COOKIE)\[|req\.(query|body|params)[.\[]|request\.(GET|POST)\[|params\[:"']
```

### SPA Framework Raw-HTML Markers
```regex
dangerouslySetInnerHTML|v-html|\{@html|x-html=|\[innerHTML\]|bypassSecurityTrust(Html|Url|Script|Style|ResourceUrl|JavaScript)|\$compile\s*\(|ng-bind-html|\{\{\{\s*[A-Za-z_$]
```

### Server Template Raw Sinks (all stacks)
```regex
\|\s*safe\b|\|raw\b|mark_safe\s*\(|\{%\s*autoescape\s+(off|false)|<%==|\{!!|@Html\.Raw\s*\(|th:utext|<%-\s|\bhtml_safe\b|\bMarkup\s*\(
```

### CSRF Protection Markers (should exist)
```regex
csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|ValidateAntiForgeryToken|protect_from_forgery|\{%\s*csrf_token\s*%\}|X-CSRF-TOKEN|XSRF-TOKEN|VerifyCsrfToken|CsrfViewMiddleware
```

### CSRF Protection Disabled/Bypassed (high signal)
```regex
csrf\s*\.\s*disable\s*\(|AbstractHttpConfigurer::disable|csrf_exempt|skip_before_action\s+:verify_authenticity_token|skip_forgery_protection|validate_on_submit|CSRF_TRUSTED_ORIGINS\s*=.*\*
```
Additionally open `app/Http/Middleware/VerifyCsrfToken.php` (Laravel) and read the `$except` array entry-by-entry.

### Clickjacking Controls
```regex
X-Frame-Options|frame-ancestors|FRAME_ANCESTORS|frameOptions|xframe_options
```
Flag: `.frameOptions().disable()` (Spring), `xframe_options_exempt` decorator (Django), deleted `X-Frame-Options` headers in Rails after_actions, nginx configs lacking `add_header`.

### postMessage Handlers
```regex
addEventListener\(\s*["']message["']|\.postMessage\s*\(
```
For each listener hit, confirm within 10 lines: `event.origin` compared against a hardcoded allowlist, plus type/schema checks of `event.data`. Absence of both = finding.

### Client Storage Misuse
```regex
localStorage\.(setItem|getItem)\s*\(|sessionStorage\.(setItem|getItem)\s*\(|document\.cookie\s*=
```
```regex
(setItem|getItem)\s*\(\s*["'][^"']*(token|jwt|secret|apikey|api_key|passwd|password|refresh|sessionid|ssn|card|dob)
```

### Password Field Autocomplete
```regex
<input[^>]*type=["']password["'][^>]*
```
Manually pair each hit with its `autocomplete=` value: expect `current-password` (login) or `new-password` (registration/change); bare `type=password` with none, or `autocomplete="on"`, is the gap.

### Location Manipulation / Client-Side Open Redirect
```regex
(window\.open|location\.assign|location\.replace)\s*\(|(location\.href|window\.location|document\.location)\s*=
```
```regex
(next|redirect|return_to|returnTo|returnUrl|rurl|callback|continue|dest|destination|goto|forward|target)\s*[=:]\s*(new URLSearchParams|getQueryParam|req\.query|\$_GET|request\.GET|params\[|location\.(hash|search))
```

### DOM Clobbering Preconditions
```regex
window\.[A-Za-z_$][\w$]*\s*(===?|\|\||&&)|getElementById\s*\(\s*["'](config|opts|options|attributes|name|id)["']|namedItem\s*\(|document\.forms\[
```
Technique to confirm statically: attacker-supplied markup like `<img id=options>` or `<form name=config><input name=url>` shadows undeclared globals/config objects read with truthiness checks (`var o = window.config || {}`). Flag any such gadget whose clobbered property flows into a sink or security decision.

### Client-Side Template Injection
```regex
\$compile\s*\(|Handlebars\.compile\s*\(|Mustache\.render\s*\(|_\.\s*template\s*\(|Vue\.compile\s*\(|template:\s*[A-Za-z_$][\w$.]{0,40}\b(req|query|param|user|input|data)\w*
```

### Sink Matrix: Client Frameworks
| Framework/library | Dangerous sink/API | Safe alternative |
|---|---|---|
| Vanilla DOM | `el.innerHTML = x`, `el.outerHTML`, `insertAdjacentHTML()`, `document.write(x)` | `el.textContent = x`, `createElement` + `textContent` |
| Vanilla DOM (nav) | `location.href = userInput`, `window.open(userInput)` | Allowlist then assign fixed path |
| jQuery (1.x–3.x) | `$(sel).html(x)`, `.append('<td>'+x)`, `.prepend`, `.after`, `.before`, `.replaceWith`, `$('<div>'+x)` selector-as-HTML | `.text(x)`, `$('<div>').text(x).appendTo(sel)` |
| jQuery < 3.5.0 | Any untrusted string through `.html()`/`.append()` (CVE-2020-11022 mXSS family) | Upgrade to >= 3.5.0 AND stop passing untrusted HTML |
| Legacy JS execution | `eval(x)`, `new Function(x)`, `setTimeout("string")`, `setInterval("string")` | Function references, `JSON.parse` |
| React | `dangerouslySetInnerHTML={{__html}}`, `href={userInput}` accepting `javascript:` | Text children `{x}`; sanitize with DOMPurify if HTML required |
| Vue 2/3 | `v-html="expr"`; runtime compiler builds (`vue.global.js` full build) compiling data-derived `template:` | `{{ expr }}` text interpolation; runtime-plus-compiler build removed |
| Angular 2+ | `[innerHTML]="..."` combined with `DomSanitizer.bypassSecurityTrust{Html,Url,Script,Style,ResourceUrl}` | Default binding (auto-sanitizes); never bypass for user data |
| AngularJS 1.x | `ng-bind-html` without `$sanitize`; `$sce.trustAsHtml(x)`; `$compile(userStr)` | `ng-bind`; `$sce` untouched |
| Svelte | `{@html expr}` | `{expr}` |
| Alpine.js | `x-html="expr"` | `x-text` |
| Ember | `{{{triple-stash}}}`, `Ember.String.htmlSafe()` | `{{double-stash}}` |

### Sink Matrix: Server Templates
| Language/Framework | Dangerous sink/API | Safe alternative |
|---|---|---|
| Jinja2 (Flask) | `{{ x \| safe }}`, `Markup(x)` in Python, `{% autoescape false %}` blocks | Plain `{{ x }}`; sanitize before any `safe` |
| Django | `mark_safe(x)` in views/models, `\|safe`, `{% autoescape off %}` | Plain `{{ x }}`; `format_html()` for composed fragments |
| Rails ERB | `<%= raw x %>`, `<%== x %>`, `x.html_safe` chained from user data | `<%= x %>` |
| Laravel Blade | `{!! $x !!}` | `{{ $x }}` |
| Thymeleaf (Spring) | `th:utext="${x}"` | `th:text="${x}"` |
| Razor (ASP.NET) | `@Html.Raw(x)`, `HtmlString(x)`, `IHtmlContent` wrappers around user data | `@x` |
| Twig (Symfony) | `{{ x \| raw }}`, `twig.yaml` `autoescape: false` | Default escaped `{{ x }}` |
| EJS (Express) | `<%- x %>` (UNescaped tag — inverted intuition vs ERB) | `<%= x %>` |
| Handlebars.js | `{{{triple}}}`, `Handlebars.SafeString(x)` | `{{double}}` |
| Mustache.js | Not exploitable directly (HTML-encodes); risk only via compile-from-string | n/a |
| Underscore/lodash | `_.template(x)` with user-derived `x` executes arbitrary JS in-browser; also `<%- %>` raw print tag | Never pass user strings as template source |

## Taint Tracing Guidance

### Step Procedure
1. Start at a sink hit from Patterns & Signatures; record file:line and sink context (element/attribute/JS/URL/CSS).
2. Walk backwards through local variables, props/state, function params until you reach either (a) a request-derived source (Sources regex), or (b) a DB/model read. For (b), grep who writes that column — user-writable columns make it STORED.
3. Note every transform on the path: `decodeURIComponent`, `atob`, `replace()` single-pass sanitizers (e.g., `.replace('<','')` removes one occurrence — bypassable with `<<img`), string concatenation, template literals, jQuery `.val()` round-trips.
4. Classify final context and select payload per Mental Model table.
5. Record reachability conditions: auth roles, admin-only pages, feature flags.

### Sanitizer Weakening Checklist (flag these configs)
| Library | Weakener pattern | Consequence |
|---|---|---|
| DOMPurify | `ADD_TAGS: ['script']`, `ADD_ATTR: ['onclick','onerror','onload','formaction']`, `ALLOW_UNKNOWN_PROTOCOLS: true`, `ALLOWED_URI_REGEXP` loosened | Full XSS despite "sanitizing" |
| DOMPurify | Custom hooks returning `node.innerHTML` mutations | mXSS reintroduction |
| Angular DomSanitizer | Any `bypassSecurityTrust*` wrapping non-static values | Disables platform sanitizer |
| Rails | `config.action_view.sanitizer_allowed_tags` extended with event-ish attrs | Attribute-based XSS |
| Custom regex sanitizers | Blacklist of `<script>` only | Trivially bypassed via img/svg/iframe/event handlers |

### Encoding-API Pitfalls During Tracing
- `encodeURI` does NOT encode `: / ? & =` — `javascript:alert(1)` survives; only `encodeURIComponent` percent-encodes values, and even that must be paired with a scheme allowlist for `href`.
- Entity-encoding a value destined for a JS string context does nothing (`&#x27;` is inert in JS but the raw `'` already broke out).
- Server-side `json.dumps` inserted into `<script>` must additionally have `</` escaped (see Remediation); plain dumps allows `</script><svg onload=...>` breakout.
- Minified production bundles keep member names (`.innerHTML`, `.postMessage`), so all signature greps remain valid against `dist/`.

## Exploitation & Reproduction

All examples target `https://app.example.com`. Replace with the audited host. Use `print(1)`/`alert(1)` interchangeably in reports; static curl verification proves DELIVERY of executable markup, which is the finding.

1. Reflect a marker to find echo context.
   ```bash
   curl -sG 'https://app.example.com/search' --data-urlencode 'q=zxqmarker7' | grep -n -C2 'zxqmarker7'
   ```
   Expected: marker echoed; surrounding bytes reveal context (element content? attribute? inside `<script>`?).
2. Test body-context execution markup.
   ```bash
   curl -sG 'https://app.example.com/search' --data-urlencode 'q=<img src=x onerror=alert(1)>' | grep -i 'onerror'
   ```
   Expected (vulnerable): raw `<img src=x onerror=alert(1)>` present unescaped. Expected (fixed): `&lt;img src=x onerror=alert(1)&gt;`.
3. Test the context-specific breakout found in step 1. Attribute context example:
   ```bash
   curl -sG 'https://app.example.com/profile?name=' --data-urlencode '" onmouseover="alert(1)" x="' | grep -o 'onmouseover="alert(1)"'
   ```
   Script-string context example:
   ```bash
   curl -sG 'https://app.example.com/report?id=' --data-urlencode '";alert(1)//' | grep -F '";alert(1)//'
   ```
   Expected: payload lands intact inside the vulnerable context with delimiters broken as intended.
4. Stored XSS chain (two accounts): authenticate, persist payload, fetch as the OTHER user.
   ```bash
   curl -s -c jar.txt -X POST 'https://app.example.com/login' -d 'user=victim&pass=...' -o /dev/null
   curl -s -b jar.txt -c jar.txt -X POST 'https://app.example.com/profile' --data-urlencode 'bio=<svg onload=alert(document.cookie)>' -o /dev/null
   # swap to second account's jar, then:
   curl -s -b jar2.txt 'https://app.example.com/u/victim' | grep -i '<svg onload'
   ```
   Expected (vulnerable): raw `<svg onload=...>` served inside the OTHER user's authenticated session — proving cross-user execution potential.
5. CSRF token-validation replay (no token):
   ```bash
   curl -i -X POST 'https://app.example.com/settings/email' \
     -H 'Cookie: sessionid=victim-session-value' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data 'email=attacker@evil.example'
   ```
   Expected (vulnerable): HTTP 200/302 success. Expected (protected): 403/400. Then resend WITH a bogus token value (`csrfmiddlewaretoken=x`): still 200 means the token is present-but-unvalidated — same finding.
6. Probe JSON/content-type-only protection:
   ```bash
   curl -i -X POST 'https://app.example.com/api/account/email' \
     -H 'Cookie: sid=victim-session-value' \
     -H 'Content-Type: text/plain' \
     --data '{"email":"attacker@evil.example","pad":"x"}'
   ```
   Expected (vulnerable): accepted because the parser tolerates text/plain bodies shaped like JSON — a cross-site form with `enctype="text/plain"` reproduces this. Also test state-changing GETs: `curl -i -H 'Cookie: sid=victim-session-value' 'https://app.example.com/user/delete/42'` returning 302/200 is a finding regardless of SameSite=Lax (top-level GET navigations carry cookies under Lax).
7. Clickjacking header check on each sensitive page:
   ```bash
   for p in settings/password settings/email settings/2fa billing/pay oauth/authorize; do
     printf '%s: ' "$p"; curl -sI "https://app.example.com/$p" | grep -icE 'x-frame-options|content-security-policy';
   done
   ```
   Expected (secure): each prints 1 with a DENY/SAMEORIGIN or `frame-ancestors 'none'` value. Expected (vulnerable): 0.
8. postMessage verification without a browser first: read the handler located by the signature grep; if neither `event.origin` allowlisting nor `event.data` type checks exist, write a local PoC page embedding the app in an iframe that calls `iframe.contentWindow.postMessage(JSON.stringify({cmd:'transfer',to:'attacker'}),'*')`. Observable outcome: state change/alert in the embedded app.
9. DOM-based XSS static confirmation: locate source->sink path with `rg -n 'location.hash' assets/app.js -A5` ending at an innerHTML sink. Confirm execution when a browser is available:
   ```bash
   chromium --headless=new --dump-dom 'https://app.example.com/page#<img src=x onerror=alert(1)>' 2>/dev/null | grep -F '<img src=x'
   ```
   Expected: injected node appears in the dumped DOM (source reached sink unencoded). Without any browser, the static dataflow proof (steps above) is the documented evidence.
10. Login-CSRF check: submit the login form cross-origin style WITHOUT any CSRF field using a fresh cookie jar; a 302 into an authenticated session seeded with attacker-chosen credentials is a login-CSRF finding. Logout-CSRF: `curl -i 'https://app.example.com/logout'` succeeding via GET with no token.

## Remediation

### Context-Aware Output Encoding Rules
| Output context | Required operation | Python (server) | PHP | Java | Ruby | JavaScript (client) | C# |
|---|---|---|---|---|---|---|---|
| HTML element content | Entity-encode `& < > " '` | `html.escape(x, quote=True)` | `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')` | `Encoder.forHtml(x)` (OWASP Java Encoder) | `ERB::Util.h(x)` | `he.encode(x)` or set `textContent` | `System.Net.WebUtility.HtmlEncode(x)` |
| HTML attribute (quoted) | Same encoding + ALWAYS quote the attribute | `html.escape(x, quote=True)` | same | `Encoder.forHtmlAttribute(x)` | `h(x)` | `he.encode(x)` | `HtmlEncode` |
| JS string inside `<script>` | JSON serialize + neutralize `</` and U+2028/U+2029 | `json.dumps(x).replace('</','<\\/')` | `json_encode($x, JSON_HEX_TAG)` | Jackson `writeValueAsString` + `<\/` replace | `x.to_json` | `JSON.stringify(x)` client-side only | `JsonSerializer.Serialize(x)` + replace |
| URL param value | Percent-encode + scheme allowlist for the base | `urllib.parse.quote(x, safe='')` | `rawurlencode($x)` | `URLEncoder.encode(x, UTF_8)` | `ERB::Util.url_encode(x)` | `encodeURIComponent(x)` | `Uri.EscapeDataString(x)` |
| href/src scheme | Allowlist `http:`, `https:`, `mailto:` only; default-deny everything else incl. protocol-relative `//evil` | manual allowlist | manual | manual | manual | `new URL(u, base)` + protocol check | `Uri` + scheme check |
| CSS values | Keep user data OUT of CSS; allowlist tokens (`px`, `%`, hex colors) if unavoidable | — | — | `Encoder.forCssUrl` | — | — | — |

Rule of thumb: escaping functions are context-specific. An entity-encoded value placed in a JS string context, or a JSON-encoded value placed in HTML, is still vulnerable.

### Before/After: Frontend Frameworks
```jsx
// VULNERABLE: userComment enters HTML parsing context
<div dangerouslySetInnerHTML={{ __html: userComment }} />

// FIXED: render as text; React escapes automatically
<div>{userComment}</div>

// FIXED: only when trusted rich HTML is a hard requirement
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userComment) }} />
```

```jsx
// VULNERABLE
<a href={userUrl}>docs</a>

// FIXED
const safeHref = (u) => {
  try {
    const p = new URL(u, window.location.origin);
    return ['http:', 'https:', 'mailto:'].includes(p.protocol) ? p.href : '#';
  } catch { return '#'; }
};
<a href={safeHref(userUrl)}>docs</a>
```

```vue
<!-- VULNERABLE -->
<div v-html="userComment"></div>
<!-- FIXED -->
<div>{{ userComment }}</div>
```

```typescript
// VULNERABLE: disables Angular's platform sanitizer
constructor(private sanitizer: DomSanitizer) {}
this.trusted = this.sanitizer.bypassSecurityTrustHtml(userComment);

// FIXED: default binding auto-sanitizes [innerHTML]
this.comment = userComment;
```

```svelte
<!-- VULNERABLE -->
{@html userComment}
<!-- FIXED -->
{userComment}
```

```javascript
// VULNERABLE
$('#bio').html(userComment);
$('#row').append('<td>' + userName + '</td>');
// FIXED
$('#bio').text(userComment);
$('<td>').text(userName).appendTo('#row');
```

### Before/After: Server Templates
```jinja
{{ comment | safe }}   {# VULNERABLE #}
{{ comment }}          {# FIXED #}
```
```python
from django.utils.safestring import mark_safe
mark_safe(user_supplied_markdown)          # VULNERABLE
format_html("<b>{}</b>", user_title)       # FIXED: argument escapes
```
```erb
<%= raw @comment %>   <%# VULNERABLE %>
<%= @comment %>       <%# FIXED %>
```
```blade
{!! $comment !!}   {{-- VULNERABLE --}}
{{ $comment }}     {{-- FIXED --}}
```
```razor
@Html.Raw(Model.Comment)   <!-- VULNERABLE -->
@Model.Comment             <!-- FIXED -->
```
```html
<span th:utext="${comment}"></span>  <!-- VULNERABLE -->
<span th:text="${comment}"></span>   <!-- FIXED -->
```
```twig
{{ comment|raw }}   {# VULNERABLE #}
{{ comment }}       {# FIXED #}
```
```ejs
<%- comment %>   <%# VULNERABLE: EJS raw tag %>
<%= comment %>   <%# FIXED: escaped tag %>
```

### CSP Guidance (mitigating control, never the primary fix)
Weak policy red flags: `script-src` containing `'unsafe-inline'` or `'unsafe-eval'`; wildcard hosts (`*`, `*.partner.example` covers attacker tenants); missing `object-src`, `base-uri`, `frame-ancestors` (defaults stay permissive); deployed ONLY as `Content-Security-Policy-Report-Only` (zero enforcement).
Strong reference policy:
```
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-r4nd0m-per-response'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; require-trusted-types-for 'script'
```
Notes: generate the nonce per response in server code; `'strict-dynamic'` may be added for script loaders; hashes are an alternative to nonces for static inline scripts; Trusted Types (where supported) kills most `innerHTML` sink classes outright.

### CSRF Token Integration Per Framework
```java
// VULNERABLE (Spring Security 5+/6)
http.csrf(csrf -> csrf.disable());
// FIXED: default-on protection; Thymeleaf th:action forms embed _csrf automatically
http.csrf(Customizer.withDefaults());
```
```python
# settings.py — Django: middleware must be present
MIDDLEWARE = [..., "django.middleware.csrf.CsrfViewMiddleware", ...]
# VULNERABLE: @csrf_exempt decorating any view handling unsafe methods
```
```html
<form method="post">{% csrf_token %}<input name="email"></form>
<!-- AJAX: read csrftoken cookie, send as X-CSRFToken header -->
```
```ruby
# FIXED: ApplicationController must contain
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end
# VULNERABLE: skip_before_action :verify_authenticity_token (audit each skip's scope)
```
```csharp
// FIXED (ASP.NET Core): enforce globally, opt out nowhere user-facing
builder.Services.AddControllersWithViews(o =>
    o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
// .cshtml views: <form method="post"> tag helper injects the token automatically
```
```blade
<form method="POST" action="/settings/email">
    @csrf
    <input name="email">
</form>
{{-- VULNERABLE: entries in app/Http/Middleware/VerifyCsrfToken.php $except --}}
```

### Cookie & Session Hardening (summary — deep matrix lives in CONFIG module)
- Auth/session cookies: `Secure`, `HttpOnly`, `SameSite=Lax` minimum; `Strict` where no inbound-link session dependency exists; `None` only with `Secure` and a documented cross-site need.
- Missing SameSite + state-changing GET routes = exploitable under any browser default; fix BOTH sides.
- Sibling-subdomain attackers are same-site (cookies flow) yet cross-origin: do not treat SameSite as subdomain-tenant isolation.

### Other Fixes
| Finding | Fix |
|---|---|
| Clickjacking | Emit `X-Frame-Options: DENY` AND CSP `frame-ancestors 'none'` globally; remove exemptions from sensitive pages |
| Tokens in localStorage | Move sessions to HttpOnly cookies or in-memory access tokens + refresh via credential-bearing call; clear storage on logout |
| PII persisted client-side | Store transient UI state only; purge keys on logout (`Object.keys(localStorage).filter(...).forEach(k=>localStorage.removeItem(k))`) |
| Password autocomplete | `autocomplete="current-password"` (login), `autocomplete="new-password"` (register/change) |
| postMessage receiver | `if (event.origin !== 'https://trusted.example') return;` + validate `event.data` shape before use; sender: explicit targetOrigin, never `'*'` |
| Client-side open redirect | Accept only same-origin relative paths: reject values starting with `/\/`, `//`, or containing a scheme; else fall back to `/` |
| DOM clobbering gadgets | Declare all referenced globals explicitly; wrap reads in `typeof x === 'object'` checks; avoid relying on named-access collections (`document.forms.x`) for security decisions |
| Client-side template injection | Compile only build-time constant templates; render user data AS DATA (interpolation/props), never as template source |
| mXSS exposure | Upgrade jQuery >= 3.5.0; sanitize at the FINAL sink with default-profile DOMPurify; avoid double innerHTML round-trips of sanitized content |

## Verification & Validation

### GIVEN/WHEN/THEN Scenarios
```text
Scenario TC-W1 Reflected XSS escaped
  GIVEN the search results template renders q via {{ q }}
  WHEN the client requests /search?q=<svg onload=alert(1)>
  THEN the response body contains "&lt;svg onload=&quot;" 
  AND the response body contains no "<svg" substring

Scenario TC-W2 Negative control (feature intact)
  GIVEN the same template
  WHEN the client searches for "Tom & Jerry <3"
  THEN the response displays "Tom &amp; Jerry &lt;3" (legit input unaffected)

Scenario TC-W3 Stored XSS neutralized
  GIVEN a user bio saved as <img src=x onerror=alert(1)>
  WHEN ANY other authenticated user fetches the profile page
  THEN the served HTML contains "&lt;img" and zero occurrences of "onerror=alert(1)"

Scenario TC-W4 CSRF enforced
  WHEN POST /settings/email is sent with a valid session cookie and NO csrf token
  THEN the server responds 4xx and the email is unchanged
  AND the identical request WITH a valid token succeeds (proves the feature works)

Scenario TC-W5 Frame protection present
  WHEN GET /settings/password response headers are inspected
  THEN X-Frame-Options: DENY (or SAMEORIGIN) OR CSP frame-ancestors 'none' is present

Scenario TC-W6 postMessage origin gate
  WHEN a message event with origin https://evil.example is dispatched to the app frame
  THEN the handler returns without mutating state or invoking sinks
```

### Regression Tests (pseudocode)
```javascript
describe('comment component XSS regression', () => {
  const PAYLOAD = '<img src=x onerror=window.__pwned=1>';
  it('renders payload inert', () => {
    render(<Comments text={PAYLOAD} />);
    expect(window.__pwned).toBeUndefined();
    expect(document.body.innerHTML).toContain('&lt;img');
    expect(document.body.innerHTML).not.toContain('onerror');
  });
});
```
```python
def test_bio_stored_escaped(client, malicious_bio):
    save_profile(bio='<svg onload=alert(1)>')
    html = client.get('/u/tester').content.decode()
    assert '&lt;svg' in html
    assert '<svg onload' not in html
```

### Manual Re-test Checklist
1. Replay every original PoC curl from Exploitation & Reproduction; confirm protective responses.
2. Re-run bogus-token variant (step 5) to confirm validation, not just presence.
3. Re-test one benign rich-content path end-to-end (feature not broken by the fix).
4. Confirm CSP nonce rotates per response and page still loads with zero console violations in devtools.
5. Confirm logout clears previously persisted localStorage items.
6. Spot-check three sensitive pages for frame headers individually (global middleware can exempt paths silently).

### Greps to Re-run Post-fix (expect zero hits outside a documented allowlist)
```bash
rg -n --no-heading -e '\|\s*safe\b' -e 'mark_safe\s*\(' -e '\{!!' -e '@Html\.Raw' -e 'th:utext' -e '<%-\s' templates/ src/ app/
rg -n --no-heading -e 'dangerouslySetInnerHTML' -e 'v-html' -e '\{@html' src/
rg -n --no-heading -e 'csrf\s*\.\s*disable\s*\(' -e 'csrf_exempt' -e 'skip_before_action\s+:verify_authenticity_token' .
rg -n --no-heading -e '(setItem|getItem)\s*\(\s*["'"'"'][^"'"'"']*(token|jwt|secret|password)' .
```
Expected observable outcome: only allowlisted, reviewed occurrences remain; each carries a code comment referencing the review decision.

## Severity Assessment

| Finding | Primary CWE | Example CVSS v3.1 vector | Typical band | Key drivers |
|---|---|---|---|---|
| Stored XSS rendered into admin console (no strict CSP) | CWE-79 | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H` | Critical | Hijacks privileged sessions; scope changed |
| Stored XSS user-to-user (comments/profiles) | CWE-79 | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` | High | Session theft, wormability raises impact |
| Reflected XSS | CWE-79 (CWE-80/83 variants by context) | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | Medium–High | Requires lure/click |
| Self-XSS (only own visible input) | CWE-79 | `AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N` | Low | Chaining with login-CSRF escalates |
| CSRF on auth-critical action (email/password/payment) | CWE-352 | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L` | High | Account takeover via email swap |
| Logout-CSRF or trivial-preference CSRF | CWE-352 | `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | Low–Medium | Impact-bounded nuisance |
| Missing frame protections on sensitive page | CWE-1021 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | Low–Medium | Overlay sophistication required |
| Secrets/tokens in localStorage | CWE-922 / CWE-312 | `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` | Low–Medium standalone; Critical amplifier with any XSS | XSS turns theft remote |
| Client-side open redirect | CWE-601 | `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` | Low–Medium | OAuth fragment-token leakage raises sharply |
| Client-side template injection (`$compile`/`_.template`/Handlebars-from-string) | CWE-94 / CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` | Critical | Equals arbitrary in-page JS |
| postMessage sink without origin validation | CWE-346 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L` | High | Attacker page must host the frame |

Rubric anchors:
- Stored + admin-context = Critical REGARDLESS of CSP presence; strict CSP lowers exploit reliability but the targeting of privileged sessions dominates.
- Self-XSS = Low unless combinable (login-CSRF injecting attacker text into victim session) — then rescore as stored-equivalent.
- CSRF severity tracks the action: payment/auth changes High; display prefs informational-to-Low.
- Any DOM-XSS sink reachable from `location` with NO interaction beyond opening a link scores at least as high as its reflected equivalent.

## Common False Positives

- `innerHTML`/`.html()` assigned static literals, i18n strings, or build-time constants with no interpolated request data — verify interpolation absence before flagging.
- Generic greps hitting SAFE syntax by design: `{{ x }}` (Jinja/Twig/Vue), `<%= x %>` (ERB/EJS), `{{ x }}` (Blade) all escape; only raw variants (`|safe`, `<%-`, `{!! !!}`, `v-html`, triple-stash) are findings.
- Angular `[innerHTML]` WITHOUT any `bypassSecurityTrust*` call in the trace — the platform sanitizer strips active content by default.
- DOMPurify-wrapped sinks with DEFAULT config — confirm no weakeners (ADD_TAGS/ADD_ATTR/ALLOW_UNKNOWN_PROTOCOLS) before flagging.
- `javascript:` appearing in constants/comments/key names rather than bound to `href`/`src`/`formaction`/navigation.
- CSRF "absence" in pure token-authenticated REST/mobile APIs with no ambient cookie credentials — CSRF requires ambient authority; confirm no cookie fallback exists.
- Dev-only `csrf().disable()` guarded by active profiles/env checks verified absent from production configuration.
- postMessage handlers with strict origin equality checks AND schema validation on `event.data`.
- SameSite=Strict/Lax present AND no state-changing GET routes — residual CSRF surface is minimal; report as hardening note, not a vulnerability.
- localStorage holding non-sensitive UI preferences (theme, locale, collapsed panels).
- Test fixtures, e2e specs, and docs containing payload strings — scope greps to shipped code.
- `autocomplete="off"` reported as REQUIRED: modern managers ignore it on username fields; the meaningful signals are `current-password`/`new-password` hints.

## References

- CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — https://cwe.mitre.org/data/definitions/79.html
- CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) — https://cwe.mitre.org/data/definitions/80.html
- CWE-83 Improper Neutralization of Script in Attributes in a Web Page — https://cwe.mitre.org/data/definitions/83.html
- CWE-94 Improper Control of Generation of Code ('Code Injection') — https://cwe.mitre.org/data/definitions/94.html
- CWE-116 Improper Encoding or Escaping of Output — https://cwe.mitre.org/data/definitions/116.html
- CWE-346 Origin Validation Error — https://cwe.mitre.org/data/definitions/346.html
- CWE-352 Cross-Site Request Forgery (CSRF) — https://cwe.mitre.org/data/definitions/352.html
- CWE-601 URL Redirection to Untrusted Site ('Open Redirect') — https://cwe.mitre.org/data/definitions/601.html
- CWE-922 Insecure Storage of Sensitive Information — https://cwe.mitre.org/data/definitions/922.html
- CWE-1021 Improper Restriction of Rendered UI Layers or Frames — https://cwe.mitre.org/data/definitions/1021.html
- OWASP Cheat Sheet: Cross Site Scripting Prevention — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet: DOM Based XSS Prevention — https://cheatsheetseries.owasp.org/cheatsheets/DOM_Based_XSS_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet: Cross-Site Request Forgery Prevention — https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet: Content Security Policy — https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- OWASP Cheat Sheet: Clickjacking Defense — https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- OWASP Cheat Sheet: HTML5 Security — https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- OWASP ASVS 4.0: V5 Validation, Sanitization and Output Encoding (esp. V5.3 Output Encoding); V14 Configuration — https://owasp.org/www-project-application-security-verification-standard/
- PortSwigger Web Security Academy: Cross-site scripting — https://portswigger.net/web-security/cross-site-scripting
- PortSwigger Web Security Academy: Client-side template injection — https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection
- MDN: Window.postMessage() — https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
