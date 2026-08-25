# OAuth 2.0 / OIDC / SAML Federation — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, flaw tables, greps, and remediation
shapes.

## How this class emerged

Federated login is younger than it feels, and each generation of its standards
carries a scar.

Enterprise single sign-on standardized first: SAML 2.0 became an OASIS standard
in 2005 and put signed XML assertions into browsers. The XML signature machinery
proved fragile in practice — in 2012, academic work titled "On Breaking SAML:
Be Whoever You Want to Be" showed that implementations verifying a signature
*somewhere* in a document while extracting claims from *elsewhere* could be
tricked by relocating elements (XML signature wrapping). The OWASP SAML cheat
sheet still teaches schema-validation-first countermeasures from that era,
because the mistake class never fully left.

OAuth began as an ad-hoc industry delegation protocol (a 2007 community effort),
was published as OAuth 1.0 in RFC 5849 (2010), and was rebuilt as OAuth 2.0 in
RFC 6749 (October 2012). Crucially, 6749 defined *authorization*, not
authentication — but the market immediately used bearer tokens as logins.
OpenID Connect 1.0 (final February 2014) patched that gap by layering a signed
id_token over OAuth so relying parties could know WHO authenticated, not just
WHAT was allowed. Loose ends remained: tokens crossing the browser could be
intercepted, which is why PKCE (RFC 7636, September 2015) introduced a per-login
verifier/challenge pair to make stolen codes worthless.

The next decade was corrective. The OAuth Security Best Current Practice —
formally RFC 9700 (January 2025) — deprecated the implicit flow and the password
grant, mandated exact redirect_uri string matching, required PKCE for public
clients, and codified mix-up/code-injection defenses. OAuth 2.1 (in progress)
consolidates those decisions into the base spec. Meanwhile identity-claim abuse
moved to the application layer: linking local accounts by email claims without
checking `email_verified`, and researchers documented account "pre-hijacking"
patterns where an attacker seeds a federated identity at a service before the
real owner ever signs up. The audit surface today spans three eras at once —
legacy SAML deployments, misconfigured OIDC clients, and modern-but-incomplete
PKCE adoption.

## Anatomy: eight lines, three flaws

A minimal vulnerable callback handler (Python/Flask shape; every framework has
an equivalent):

```python
@app.route("/auth/callback")
def callback():
    code    = request.args["code"]                      # state never read
    tokens  = exchange_code(code)                       # back-channel POST /token
    claims  = jwt.decode(tokens["id_token"], options={"verify_signature": False})
    user    = Users.get_by_email(claims["email"]) or Users.create(claims)
    login(user)                                         # session issued here
    return redirect("/")
```

Failure walkthrough, one login:

1. **No state binding.** The handler never compares `request.args["state"]`
   against a server-stored pending value. An attacker can run their OWN login,
   harvest the callback URL containing THEIR code/state, and get a victim's
   browser to load that URL (link, image tag, iframe). The victim's session is
   silently bound to the attacker's federated identity (login CSRF); anything
   the victim uploads next lands in attacker-readable territory.
2. **Decode masquerading as verify.** `jwt.decode(..., options=
   {"verify_signature": False})` parses JSON; it proves nothing. Any string with
   valid base64 segments and chosen claims passes. Even with verification on,
   omitting `algorithms` invites alg-confusion, and omitting `issuer`/`audience`
   lets tokens minted for other apps replay here.
3. **Email-keyed linking without verification.** Accounts merge on raw email;
   nothing reads `email_verified`. An IdP where anyone registers any address
   (or issues `{"email":"victim@corp.com","email_verified":false}`) becomes an
   account-takeover oracle against this RP.

Order matters as much as presence: validations must execute BEFORE side effects
(state compare before user lookup, signature before session write), because a
check that runs after `login(user)` protects nothing on that request path.

## Why naive fixes fail

- **Generating state only in the browser** (localStorage/JS variable) does not
  bind it to a server-side session; an attacker initiating their own flow mints
  valid-looking states too. State must be CSPRNG-generated server-side (or HMAC'd
  into a signed cookie with issuance time), stored per-login, compared-and-
  DELETED first thing in the callback.
- **Prefix or wildcard redirect matching**   (`startsWith`, unanchored regex, wildcard subdomains) reopens code theft via
  percent-encoded dots, sibling paths, and subdomain takeover. RFC 9700 requires
  exact string comparison after canonicalization — with the sole native-app
  exception of loopback IP literals where the port may vary.
- **Rejecting only `alg=none`.** The classic confusion verifies RS256-intended
  tokens as HMAC using the PUBLIC key or client secret; the fix is an explicit
  allowlist (typically `["RS256"]`) plus pinned issuer/audience at decode time,
  not a blocklist of one bad header value.
- **Checking email presence instead of `email_verified == true`.** A missing
  boolean is not consent from the issuer; treating absence as verified hands
  account creation to whoever controls a mailbox-shaped claim.
- **HTTPS-only redirect URIs as the security control.** TLS protects the wire,
  not the destination; a traversal bug delivering codes to
  `/callback/../../relay?next=evil` rides perfectly valid HTTPS all the way out.
- **Clearing the RP cookie and calling it logout.** Without back-channel/front-
  channel logout wiring, the IdP session survives; the next "Sign in with…"
  click silently re-authenticates the supposedly logged-out user.

## Common misconceptions

1. "OAuth logs users in." Base OAuth authorizes API access; only OpenID Connect
   adds the id_token that says who authenticated. Using bare access tokens as
   logins is itself the vulnerability pattern.
2. "Decoding a JWT validates it." Parsing extracts claims; validation checks
   signature, algorithm allowlist, iss, aud, exp/nbf, and nonce — every row of
   SKILL.md's claim matrix, before any session issuance.
3. "state is CSRF protection for logged-in users." Its absence enables LOGIN
   CSRF: victims bound into attacker identities on otherwise-anonymous flows.
4. "Confidential clients with secrets don't need PKCE." Current best practice
   recommends PKCE for ALL clients; it also mitigates authorization-code
   injection, which client secrets alone do not stop.
5. "`email_verified` absent means true." Absent means unknown; unknown means do
   not link accounts on it.
6. "A signature validated somewhere in the document covers my assertion."
   Signature wrapping decouples exactly those two; the SP must resolve ONE
   assertion element for both signing and claims, after full schema validation.
7. "Loopback port flexibility is a bypass to report." RFC 8252 explicitly allows
   any port on `127.0.0.1`/`[::1]` redirects for native apps; divergent handling
   of `localhost` vs IP literals is the finding, not port variability itself.

## How professionals think about it today

Modern practice treats everything arriving at the callback as attacker-touchable
front-channel data, trusts only the back channel, and demands crypto + binding:
verified by signature, bound by state (request integrity), nonce (freshness),
audience (recipient). The taxonomy mirrors SKILL.md's objectives O1–O10:

| Class | Core question |
|---|---|
| Flow selection | implicit/ROPC gone; PKCE S256 on every interactive client? |
| redirect_uri validation | exact-match comparator; no wildcards/traversals/open redirectors? |
| state parameter | CSPRNG, session-bound, consumed before side effects? |
| Code handling | single-use atomic redemption; leakage channels closed? |
| id_token/JWT validation | allowlisted alg; iss/aud/exp/nonce/at_hash complete? |
| Token handling | storage exposure; refresh rotation with family revocation? |
| IdP-side policy | prompt=none scope creep; grant-type mixing; open dynamic registration? |
| SAML | XSW resistance; audience restriction; tight windows; RelayState pinned? |
| Session bridging | email gated on `email_verified`; identity keyed `(iss,sub)`; complete logout? |
| Discovery/config | internal topology leaks; JWKS cache poisoning surfaces? |

Severity anchors follow impact: takeover-grade flaws (unverified-email linking,
accepted wrapping) sit Critical; interception-dependent flaws scale down with
attacker position requirements; pure redirectors stay Medium phishing pivots.

## Read next

In `../SKILL.md`: **Scope & Objectives** (trigger list, O1–O10), **Mental Model**
(front/back channel, six axioms, mix-up note), **What To Check** (numbered
procedures per class), **Where To Look** (stack/file map plus ripgrep sweeps),
**Patterns & Signatures** (master flaw table, regex hunts, payload cheat-sheet),
**Taint Tracing Guidance** (source→sink table, callback trace procedure),
**Exploitation & Reproduction** (static-first recipes), **Remediation**
(library-correct option shapes), **Verification & Validation**, **Severity
Assessment**, **Common False Positives**.

Sibling modules: `../authn-session/SKILL.md` (session design the RP issues after
SSO), `../web-client/SKILL.md` (token storage mechanics in browsers),
`../injection/SKILL.md` (kid reaching SQL/paths), `../deserialization/SKILL.md`
(IdP payload parsing), `../ssrf-url-security/SKILL.md` (metadata/jwks fetch
validation).
