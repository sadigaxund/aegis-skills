# Web Client Attacks — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.

## Standards & cheat sheets

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) - the context-by-context output-encoding rules that Remediation summarizes.
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) - safe-sink rules for client-side JavaScript writing into the DOM.
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) - token patterns, SameSite limitations, and client-side-CSRF guidance behind What To Check items 4-6.
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) - frame-ancestors/X-Frame-Options selection logic for the frame-protection check.
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) - strict-CSP (nonce/hash) construction guidance referenced by the CSP evaluation check.

## Deep dives

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html) - formal definition and variant taxonomy (basic, attribute, DOM-based) used in severity mapping.
- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) - end-to-end treatment of the reflected/stored/DOM triad, contexts, and CSP interplay.
- [PortSwigger Web Security Academy: Client-side template injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection) - the sandbox-escape methodology behind the `$compile`/client-template findings.

## Vendor docs

- [MDN: Window.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) - normative origin/targetOrigin semantics cited by the postMessage handler review.
- [MDN: Content-Security-Policy header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) - directive reference (frame-ancestors, script-src sources, Trusted Types) backing the CSP red-flag list.
