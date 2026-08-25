---
name: oauth-sso-checks
description: Deep-audit checks for OAuth 2.0, OIDC, and SAML federation covering flow misuse, redirect_uri validation, state and PKCE handling, token and assertion verification, IdP-side misconfiguration, and session-bridging flaws up to account takeover.
category_slug: SSO
cwe: [CWE-352, CWE-287, CWE-601, CWE-347]
owasp: A07:2021 – Identification and Authentication Failures
---

# OAuth 2.0 / OIDC / SAML Federation Checks

## Scope & Objectives

Run this module when the repo contains federation code or configuration. Triggers include any of:

- Client/RP libraries: `passport`/`passport-*`, `omniauth(-*)*`, `authlib`, `flask-dance`, `social-auth-core`, `django-allauth`, `python-jose`, `PyJWT` used on id_tokens, `spring-boot-starter-oauth2-client`, `spring-security-saml2-service-provider`, `Microsoft.AspNetCore.Authentication.OpenIdConnect`/`Cookies`/`JwtBearer`, `Microsoft.Identity.Web`, `next-auth`, `express-openid-connect`, `oauth4webapi`, `angular-oauth2-oidc`, `keycloak-js`, `@auth0/auth0-*`/`auth0-spa-js`, `@okta/*`.
- IdP-side artifacts: Keycloak realm-export JSON, Auth0 tenant/rules/actions config, Okta org YAML, ADFS/WIF settings, `doorkeeper`, `keycloak` services, custom `/authorize`, `/token`, `/jwks` handlers.
- SAML stacks: `passport-saml`, `samlify`, `saml2-js`, `ruby-saml`, `python3-saml`, OneLogin SDKs, Shibboleth SP (`shibboleth2.xml`, `attribute-map.xml`), pac4j, Spring SAML.

Objectives, in audit order:

- O1 Flow selection: implicit flow presence; authorization-code without PKCE on public clients; `client_credentials` scope breadth; `response_mode` confusion.
- O2 redirect_uri validation depth: exact vs prefix bugs, path traversal inside registered prefixes, first-party open redirectors, wildcard subdomains, loopback/native-app variants, unvalidated `post_logout_redirect_uri`.
- O3 state parameter: absence (login CSRF/session swap), weak or reused values, state not bound to the initiating session.
- O4 Code handling: interception mitigated by PKCE (verify verifier/challenge correctness), server-side single-use enforcement, leakage via Referer/history/fragments.
- O5 id_token/JWT verification at the RP: JWKS retrieval and kid handling, alg allowlisting, iss/aud/exp/nonce completeness, at_hash/c_hash where the flow demands them.
- O6 Token handling at the RP: storage exposure (one line, cross-ref WEB), refresh-token rotation, back-channel vs front-channel choice.
- O7 IdP side (when present): consent bypass via `prompt=none`, scope escalation via grant-type mixing, resource-indicator narrowness (RFC 8707), dynamic registration openness.
- O8 SAML: XML signature wrapping conceptually, audience restriction, NotOnOrAfter skew, RelayState as open redirector, metadata trust/cert pinning.
- O9 Session bridging: account linking by email without `email_verified`, pre-hijack patterns, IDP-initiated vs SP-initiated tenant confusion, incomplete logout.
- O10 Discovery/config exposure: `.well-known` introspection norms, internal issuer URL leakage, JWKS cache poisoning.

CWE set kept deliberately small and defensible: CWE-352 (login CSRF via missing/unbound state), CWE-287 (improper authentication umbrella: validation gaps, email-link takeover, replay), CWE-601 (redirect flaws incl. RelayState and post-logout), CWE-347 (improper signature verification: XSW, alg confusion). CWE-346 was considered and dropped as redundant with 287/601 for every finding class in this module.

Out of scope (cross-references): baseline authN design -> `authn-session.md`; injection sinks found en route (kid into SQL/path) -> `injection.md`; deserialization of IdP payloads -> `deserialization.md`; browser-storage mechanics detail -> `web-client.md`; generic outbound fetch validation -> `ssrf-url-security.md`.

## Mental Model

Two roles exist and are audited differently. The **RP/client** is application code that must treat everything arriving from the browser as attacker-touchable. The **IdP** (if its config/code is in scope) is the trust anchor whose policy mistakes become everyone's vulnerabilities.

```
Browser                    RP (client app)                     IdP
   |--- GET /authorize?...state,nonce,PKCE-challenge -------->|  front-channel
   |<-- 302 callback?code&state (fragment if implicit) ------|
   |--- GET /auth/callback?code&state ----------------------->|
   |                          [validate state FIRST]          |
   |                          |-- POST /token {code,verifier} -->|  back-channel
   |                          |<-- access_token, id_token -------|
   |                          [verify sig via JWKS, iss/aud/exp/nonce]
   |<====================== session cookie ===================|
```

Axioms that drive every check below:

1. Only back-channel responses (direct TLS RP-to-IdP) are trustworthy. Everything in the front channel - query strings, fragments, POSTed assertions - can be read, stripped, replayed, or forged by an attacker positioned anywhere in the redirect chain.
2. The redirect chain is a chain of trust. Every hop must be pinned to an exact URI. One permissive hop converts a hardened flow into an open one.
3. An identity claim is only as strong as its verification AND its binding: verified by crypto, bound by state (request integrity) and nonce (token freshness) and audience (recipient).
4. Email is not identity unless the issuer vouches it is verified (`email_verified`). Matching accounts on raw email hands account creation decisions to whoever controls a mailbox-shaped claim.
5. Order matters: validations execute before side effects. A state comparison performed after user creation protects nothing.
6. Short lifetimes are controls: codes, states, nonces, and assertion validity windows all limit replay blast radius.

Mix-up note: with multiple configured IdPs, a code delivered for IdP-A but redeemed at IdP-B breaks identity binding. Mitigations are distinct redirect URIs per provider plus issuer validation of discovery metadata; RFC 9207 adds an `iss` field to authorization responses for this purpose.

## What To Check

### Flow selection
1. Find every authorize-URL construction and IdP client registration. Flag `response_type=token`, `id_token`, `id_token token`, or `code id_token` (implicit/hybrid): implicit is deprecated for all clients per the OAuth Security BCP, and is worst for public clients where tokens land in fragments.
2. For every SPA/mobile/native/desktop client running authorization-code flow, confirm PKCE: the built authorize URL must carry `code_challenge` + `code_challenge_method=S256` and the token exchange must carry the matching `code_verifier`. Absence on a public client is a finding.
3. Verify challenge correctness: reject `code_challenge_method=plain` (downgrade-prone); recompute `BASE64URL(SHA256(verifier))` server-side rather than trusting a client-declared method; confirm verifiers come from CSPRNG with >= 43 chars.
4. Audit `client_credentials` consumers: flag requests that omit `scope` (yielding default full-role tokens), shared service identities, or scopes broader than the consumer's documented need.
5. Check `response_mode` coherence: handler parses query but AS sends fragment/form_post (lost params, dead validations), tokens requested in `query` mode (leak to logs/history), form_post callbacks accepted without CSRF token/`Origin` check.
6. Flag ROPC (`grant_type=password`) anywhere; it survives only as a documented legacy exception.

### redirect_uri validation
7. Read the actual comparator in the AS/client validator. Flag prefix checks (`startsWith`, `indexOf == 0`, regex without `$`, Django/Rails route-prefix matching) versus byte-exact comparison after canonicalization.
8. Test traversal shapes against the registered prefix mentally: `/callback/../../evil`, percent-encoded `%2F%2e%2e`, double slashes, trailing-dot/space OS quirks. If normalization happens before matching, traversal collapses - verify which order the code uses.
9. Inventory first-party redirector endpoints (`/redirect`, `/auth/relay`, `next=`/`url=`/`returnTo=` handlers). Each must allowlist a closed set of first-party paths; an arbitrary passthrough chained behind a valid `redirect_uri` is an open-redirector finding.
10. Flag wildcard registrations (`https://*.example.com/cb`) - any subdomain takeover or open subdomain becomes a code/token capture point.
11. Native apps: expect loopback IP literal redirect URIs with variable port per RFC 8252; flag validators that treat `localhost` string, `127.0.0.1`, and `[::1]` inconsistently, or custom-scheme URIs (`com.app:/cb`) validated loosely.
12. Check logout: `post_logout_redirect_uri` must be compared against a per-client registered list AND bound to a valid `id_token_hint`; unvalidated echo into `Location` is a finding.

### state parameter
13. Confirm the RP generates a fresh random state (>= 128 bits CSPRNG) at authorize time, stores it in server-side session (or signed cookie), and compares-and-deletes it in the callback BEFORE any user lookup, creation, or login.
14. Flag absent state entirely, weak generators (`Math.random()`, timestamps, short constants), reuse across logins, and acceptance of missing/mismatched state.
15. Explain the failure when reporting absence: attacker initiates their own OAuth flow, receives the callback URL containing THEIR code, and gets the victim's browser to load that URL (link, image, iframe). With no state binding, the victim is logged in under the attacker's identity (login CSRF/session swap) and may unknowingly submit data into attacker-controlled accounts.

### Code handling
16. Confirm the IdP marks codes consumed atomically on first redemption; a second exchange must return `invalid_grant`. Replay acceptance is a finding.
17. Hunt leakage channels: code/state in URLs of external assets loaded by the callback page (no `Referrer-Policy: strict-origin-when-cross-origin`), codes logged, codes stored in browser history via query mode when fragment was available.
18. If the repo embeds an IdP: verify code TTL is minutes-scale and codes are bound to client_id.

### id_token / JWT validation at the RP
19. Signature path: JWKS fetched from the configured issuer's `jwks_uri` over TLS, cached with sane TTL, kid treated as an opaque lookup key (never interpolated into SQL, file paths, or key filenames - cross-ref INJ/DESER), unknown-kid handling triggers bounded refresh, never trust of header-supplied key material or `jwks_uri`.
20. Algorithm policy: explicit allowlist (typically `["RS256"]` or the configured ES algorithm); reject `none`; reject HS256 unless the protocol design truly uses symmetric keys (classic confusion: library picks alg from token header and verifies RS256-intended tokens as HMAC using the public key or client secret).
21. Claim matrix completeness - each row must actually execute before session issuance:

| Claim | Required behavior | Flaw if missing |
|---|---|---|
| iss | exact equality with configured issuer | mix-up / foreign-token acceptance |
| aud | contains client_id; azp checked when multiple audiences | token minted for another app replayed |
| exp/nbf | enforced with small skew | expired-token resurrection |
| nonce | equals session-stored value, then deleted | replayed/stolen id_token reuse |
| iat | sanity-bounded (not decades old/future) | long-window replay |
| email_verified | gates any email-based account linking | takeover via issuer-unverified mail |

22. at_hash verified whenever an access token arrives via front channel (implicit flows - REQUIRED there); c_hash verified in hybrid flows alongside the code.

### Token handling at the RP
23. One line here, deep-dive elsewhere: access/refresh/id tokens persisted in `localStorage`/`sessionStorage` are XSS-exfiltratable -> cross-ref WEB module; prefer HttpOnly cookies or memory.
24. Refresh tokens: rotation on every use with family revocation on detected reuse; absent rotation = finding. Note whether refresh happens back-channel (good) or through browser-visible calls.

### IdP-side audit (if config/code present)
25. Consent: `prompt=none` combined with broad previously-consented scopes enables silent grants users never see re-affirming; flag clients whose scope set can expand silently.
26. Grant-type mixing: one client holding authorization-code + client_credentials (+ ROPC) with a shared scope set lets a compromise escalate privileges; require disjoint clients/scopes per grant type.
27. Resource narrowness: check whether requests pin `resource`/`audience` (RFC 8707); default "all APIs" audience tokens are over-scoped.
28. Dynamic registration endpoint open without initial access token = finding.

### SAML (when present)
29. Conceptual XSW pattern: signature is cryptographically valid but decoupled from values - original signed Assertion is relocated (into `Advice`, `SubjectConfirmationData`, or an extension node) while a new unsigned Assertion carrying attacker-chosen `Subject/NameID` sits in the position the SP parser reads. Detection in code: signature verification resolves ONE element while attribute extraction reads ANOTHER; schema validation skipped; duplicate-assertion policy absent.
30. Audience restriction: assertion `Audience`/`AudienceCondition` must equal this SP's entity ID; missing restriction permits cross-SP replay.
31. Validity windows: `NotOnOrAfter` minus `NotBefore` should be tight (minutes) with small clock skew tolerance; multi-hour windows extend stolen-assertion replay.
32. RelayState: post-login redirect target must be restricted to relative paths or registered URLs; raw echo is CWE-601.
33. Metadata trust: IdP metadata fetched unsigned over changeable URLs without cert pinning lets an infrastructure-level attacker substitute signing certs.

### Session bridging
34. Account linking: find the merge/link site. If it matches local users by claim email WITHOUT requiring `email_verified=true`, flag as account-takeover-capable (unverified-email takeover; pre-hijack variant: attacker pre-registers the victim's future email at an IdP they control, seeds the RP link, victim later signs up via SSO into the attacker-seeded identity).
35. Identity primary key: sessions/users keyed by `(issuer, subject)` pair preferred; email-keyed identities break when emails recycle.
36. Multi-tenant SSO: IDP-initiated (unsolicited) responses accepted at any ACS blur tenant boundaries; prefer SP-initiated with `InResponseTo` binding; if unsolicited is required, restrict per-tenant ACS and audience.
37. Logout completeness: IdP logout must terminate RP session via back-channel logout (server-to-server logout token) or front-channel iframes; RP-only cookie clearing leaving upstream sessions alive is a finding; same in reverse (RP logout not hitting IdP).

### Discovery/config exposure
38. `.well-known/openid-configuration` introspection is normal and NOT a finding by itself. Finding-grade: internal/staging issuer URLs, internal hostnames, IPs, or admin endpoints committed in client configs leaking infra topology (severity note, usually Low).
39. JWKS caching poisoning brief: cache keyed only by kid across issuers (multi-tenant collision), attacker-influenced `jwks_uri` from embedded metadata, or unbounded cache growth on unknown-kid storms.

## Where To Look

| Stack | Files / globs | What to extract |
|---|---|---|
| Node/Express | `**/*passport*`, `**/*strategy*.js`, `app/routes/**`, `**/callback*.{js,ts}`, `next-auth` config, `express-openid-connect` setup | strategy options (state/pkce), callback handlers, token storage |
| Ruby | `config/initializers/omniauth.rb`, `devise.rb`, `app/controllers/users/omniauth_callbacks_controller.rb` | provider blocks, `skip_jwt`, callback verification order |
| Python | `authlib` client registration, `django-allauth` settings, FastAPI/Django callback views, `python-jose`/`PyJWT` decode sites | `client_kwargs`, decode `algorithms`, linking logic |
| Java/Spring | `application.yml`: `spring.security.oauth2.client.*`, `spring.security.saml2.relyingparty.*`; `SecurityConfig.java` | registration/provider keys, saml2 assertingparty |
| .NET | `Startup.cs`/`Program.cs` `AddOpenIdConnect`, `appsettings.json` AzureAD sections | OpenIdConnectOptions members, TokenValidationParameters |
| Keycloak/Auth0/Okta | `*-realm.json`, realm exports, `auth0.*` config, okta YAML, admin-exported client JSON | redirectUris wildcards, implicit/direct-grant toggles, logout attrs |
| Generic IdP code | routes `/authorize`,`/token`,`/register`,`/jwks`,`/.well-known/*` | code single-use, dynamic registration, scope defaults |
| SAML stacks | `passport-saml` strategy opts, `samlify`/`ruby-saml` settings, `shibboleth2.xml`, ACS/SLO controllers | wantAssertionsSigned, audience, RelayState handling, clock skew |

Ripgrep sweeps (run from repo root; interpret hits manually):

```bash
rg -n --hidden -g '!node_modules' -g '!vendor' \
  -e 'response_type[=:](token|id_token|id_token%20token|code%20(id_)?token)' \
  -e 'responseType[=:]\s*["'"'"'](token|id_token)' .
rg -n -e '(redirect_uri|redirectUri|redirect_uris|post_logout_redirect_uri|postLogoutRedirectUri|SignedOutRedirectUri)' .
rg -n -e '(implicitFlowEnabled|directAccessGrantsEnabled|standardFlowEnabled|"publicClient")' .
rg -n -e '(/acs|AssertionConsumerService|assertion_consumer|RelayState|/slo|SingleLogout)' .
rg -n -e '(jwt\.decode|JWT\.decode|decodeJwt|JwtDecoder|TokenValidationParameters|verifyIdToken|IdTokenVerifier)' .
rg -n -e '(Math\.random\(\)[^\n]{0,40}state|state\s*[:=]\s*(Date\.now|Math\.random)|nonce\s*[:=]\s*Math\.random)' .
rg -n -e '(localStorage\.setItem\(["'"'"'](access_token|refresh_token|id_token))' .
```

## Patterns & Signatures

Master flaw table:

| Flaw | Where in flow | Detection marker | Fix |
|---|---|---|---|
| Implicit flow offered | `/authorize` accepts `response_type=token` | `implicitFlowEnabled: true`; client builds token-fragment URLs | Disable; migrate to code+PKCE |
| Code flow w/o PKCE (public client) | authorize builder | built URL lacks `code_challenge` | Enforce S256 PKCE |
| PKCE plain/downgrade | token exchange | `code_challenge_method=plain`; server trusts client-declared method | S256 only; recompute server-side |
| `client_credentials` overbreadth | token request | no `scope` param -> default all-role token | per-consumer least-privilege scopes |
| response_mode confusion | callback parsing | handler reads `query`, AS sends fragment/form_post; tokens in query | pin mode per flow; parse accordingly |
| Prefix redirect matching | validator | `startsWith`/unanchored regex on redirect_uri | canonicalize + byte-exact compare |
| Traversal redirect_uri | validator | `/cb/../../evil`, `%2f..%2f` survive into allowlisted prefix | normalized exact match (fn below) |
| Wildcard subdomain registration | IdP client config | `"https://*.example.com/cb"` in redirectUris | explicit host enumeration |
| Loopback inconsistency | native validators | `localhost` vs `127.0.0.1` vs `[::1]` divergent rules | RFC 8252: loopback IP literal, any port; else exact |
| First-party open redirector | `/redirect`,`next=` handlers | raw param echoed to Location | closed allowlist of first-party paths |
| post_logout_redirect_uri unvalidated | `/logout` | param -> Location w/o registry compare + id_token_hint binding | validate against per-client list |
| state absent | authorize builder | no `state=` emitted, session lacks pending-state slot | CSPRNG >=128-bit, session-bound, single-use |
| state weak/reused/unbound | builder+callback | `Math.random()`/timestamp values; compare after login side effects | consume-on-compare BEFORE user ops |
| code replay accepted | IdP token endpoint | second exchange of same code returns tokens | atomic single-use, short TTL |
| JWT alg unpinned | RP decode | `jwt.decode` w/o `algorithms`; header alg drives verify | allowlist e.g. `["RS256"]`; reject none/HS256 |
| iss/aud/nonce/exp gaps | RP validation | options disabled or absent at decode site | full claim matrix (What To Check #21) |
| at_hash/c_hash skipped | RP validation | implicit/hybrid flows without hash checks | verify per OIDC Core when flow demands |
| kid-driven unsafe JWKS lookup | JWKS cache | kid concatenated into SQL/path/filename | opaque parameterized lookup; bounded refresh |
| Tokens in localStorage | SPA persistence | `localStorage.setItem('access_token',...)` | HttpOnly cookie/memory; cross-ref WEB |
| Refresh rotation absent | RP token mgmt | refresh token reused indefinitely, no reuse-detection revocation | rotate on use; revoke family on reuse |
| prompt=none consent bypass | IdP policy | silent grant path expands scopes unreviewed | narrow granted scopes; re-prompt on expansion |
| Grant-type mixing escalation | IdP client policy | one client: auth_code + client_credentials + ROPC, shared scopes | disjoint clients/scopes per grant type |
| Dynamic registration open | IdP `/register` | unauthenticated client creation | initial access token gate |
| XSW acceptance | SAML SP | signature verified on one element, claims read from another; no schema validation | upgrade library; single-assertion schema-valid policy |
| Audience restriction missing | SAML SP | no AudienceCondition/entity-id check | enforce audience per SP |
| NotOnOrAfter skew wide | SAML SP | multi-hour validity tolerated | minutes-scale windows; synced clocks |
| RelayState open redirect | SAML ACS handler | post-login `Location = RelayState` raw | relative-path/registered targets only |
| Metadata trust absent | federation setup | unsigned metadata over mutable URL, no cert pinning | signed metadata; pin certs |
| Email-match linking w/o verified check | linking logic | `get_by_email(claims.email)` with no `email_verified` read anywhere | gate on `email_verified==true`; key on (iss,sub) |
| Tenant confusion / unsolicited SSO | multi-tenant SAML/OIDC | IDP-initiated accepted at any ACS; no InResponseTo binding | bind to SP-initiated requests; restrict ACS |
| Logout incomplete | RP/IdP config | no back-channel/front-channel logout endpoints wired | configure back-channel logout URL |

Regex hunts (ripgrep-compatible; each hit needs manual-context judgment - a match is a lead, not a verdict):

```regex
# implicit/hybrid response types in code or URLs
response_type[=:](token|id_token)(%20|\+)?(token)?
```

```regex
# authorize constructions - then MANUALLY inspect surrounding lines for code_challenge absence
(authorizationUrl|authorizeUrl|authorize_url|getAuthorizationUrl|/authorize\?|buildAuthorize)
```

```regex
# PKCE presence where it SHOULD exist; correlate hits against the authorize sites above
code_challenge(_method)?[=:]
```

```regex
# redirect configuration surfaces incl. logout and wildcards
(redirect_uri[s]?|redirectUri|post_logout_redirect_uri|postLogoutRedirectUri|SignedOutRedirectUri)["']?\s*[:=]\s*["']?(https?://[^"']*|\*\.)?
```

```regex
# SAML route handlers and assertion plumbing
(/acs\b|AssertionConsumer|assertion_consumer_service|RelayState|NotOnOrAfter|/slo|wantAssertionsSigned)
```

```regex
# jwt decode sites lacking visible algorithm pinning (verify manually for 'algorithms' arg)
(jwt\.decode\(|JWT\.decode\(|decodeJwt\(|JwtDecoder|SecurityTokenValidator|verifyIdToken\()
```

```regex
# weak state generation; strong-state hits are context, weak ones are findings
state\s*[:=]\s*(Date\.now\(|Math\.random\(|["'][A-Za-z0-9]{1,8}["'])|nonce\s*[:=]\s*Math\.random\(
```

Polyglot vulnerable/fixed signatures (comment markers use language-appropriate syntax):

```js
// VULNERABLE: no state option, no pkce - passport-oauth2 default behavior is both missing
new OAuth2Strategy({ authorizationURL, tokenURL, clientID, clientSecret,
  callbackURL: '/auth/callback' }, (accessToken, refreshToken, profile, done) => {})
// FIXED
new OAuth2Strategy({ authorizationURL, tokenURL, clientID, clientSecret,
  callbackURL: '/auth/callback',
  state: true,        // random state generated/stored/verified by the strategy
  pkce: 'S256' }, cb) // Needs-Review: pkce option exists on passport-oauth2 >= 2.x; confirm locked version
```

```python
# VULNERABLE: algorithm taken from token header or verification disabled
claims = jwt.decode(id_token, key, options={"verify_signature": False})
# FIXED: pinned algorithms plus issuer/audience enforced at decode time
claims = jwt.decode(id_token, signing_key, algorithms=["RS256"],
                    audience=CLIENT_ID, issuer=ISSUER)
```

Payload cheat-sheet (attack URL templates per flaw; use only against systems you are authorized to test):

```text
[login-CSRF via missing state] Attacker completes their OWN authorize round-trip, harvests:
  https://rp.example/auth/callback?code=ATTACKER_CODE&state=
  ...then delivers that URL to the victim (link/img). Victim's browser binds attacker identity.

[redirect_uri prefix traversal] append to a registered prefix during an authorized probe:
  &redirect_uri=https%3A%2F%2Frp.example%2Fcallback%2F..%2F..%2Fadmin%2Frelay%3Fnext%3Dhttps%3A%2F%2Fevil.example

[wildcard subdomain swap] if https://*.example.com registered:
  &redirect_uri=https%3A%2F%2Fattacker-control.example.com%2Fcb

[loopback variants for native] try port-flexibility abuse and family divergence:
  http://127.0.0.1:ANYPORT/cb   http://localhost:0/cb   http://[::1]:9999/cb

[post-logout open redirect probe]
  GET /logout?id_token_hint=<recent id_token>&post_logout_redirect_uri=https://evil.example/phish

[nonce-reuse test] complete one login capturing id_token N; start a SECOND login but submit the
  FIRST callback's id_token (or replay the first callback verbatim). If RP issues a session from
  the previously-consumed nonce/token instead of rejecting, replay window exists.

[prompt=none silent-scope probe]
  GET /authorize?client_id=X&response_type=code&scope=openid%20profile%20email&prompt=none
  A 302 with code, zero user interaction, reveals silent-grant breadth.

[XSW conceptual structure] (capability class; Burp-extension tooling such as the commonly cited
  SAML Raider exists for this category):
    <Response>
      <Signature/>                      <!-- still validates over ORIGINAL assertion -->
      <Assertion id="ORIGINAL">         <!-- relocated into Advice/SubjectConfirmationData -->
      <Assertion>                       <!-- NEW unsigned, placed where parser extracts claims -->
        <Subject><NameID>admin@corp</NameID></Subject>
        <Conditions NotBefore=t NotOnOrAfter=t+10m/>
      </Assertion>
    </Response>
  Success criterion: SP verifies a signature SOMEWHERE while consuming claims ELSEWHERE.
```

## Taint Tracing Guidance

Treat federation parameters as untrusted input with high-value sinks:

| Source (attacker-controlled) | Sink | Flaw when reached |
|---|---|---|
| `code`, `state`, `error` on callback | session issuance / user lookup before validation | login CSRF, forced login to attacker identity |
| `id_token` string + header `kid`, `alg` | JWKS lookup, verifier selection, decode options | kid SQLi/path traversal; alg confusion; none |
| claim `email`, `sub`, groups/roles | account linking query, role assignment | unverified-email ATO; privilege escalation via claim trust |
| `RelayState`, `post_logout_redirect_uri`, `next` | `Location` / redirect helpers | open redirect -> token/code phishing |
| SAML XML body at ACS | signature resolver vs claim extractor | XSW divergence |
| `jwks_uri`/metadata from embedded config | HTTP fetcher, cache key | key substitution; cross-tenant cache poisoning |

Trace procedure per callback:

1. Locate the authorize builder. Record exactly which of `state`, `nonce`, PKCE params are generated, their entropy source, and where they are persisted (server session vs signed cookie vs nothing).
2. Locate the callback handler. Walk statement order: the state compare must appear BEFORE any DB read for users, any user creation, any session write, any redirect that consumes the code. Note every early-return path that skips the compare (e.g., provider mismatch branches, error branches that still call `signIn`).
3. For each validation (state, code exchange, signature, iss/aud/exp/nonce), determine: does it exist; does it execute on ALL paths; does its failure actually abort (vs log-and-continue inside swallowed try/catch); does it run before side effects.
4. Follow the linking sink: which claim keys the local user record (`email`? `sub`? both?), and whether `email_verified` is read anywhere in the file or its imports.
5. On IdP side: follow client registration data (redirectUris, grant types) from config into the validator that enforces it - configs that are never consulted by runtime validation are findings.

## Exploitation & Reproduction

Static-first. Dynamic probes only against systems you own or have written authorization for.

1. **Missing-state login CSRF confirmation.** Static: trace authorize builder -> callback handler; verify no stored-state comparison executes before user creation/login. Dynamic (authorized): initiate two flows in separate browser profiles; take attacker's callback URL and load it in victim's profile; if victim lands logged-in as attacker's federated identity, confirmed. Record evidence as code-order screenshot plus optional HAR.
2. **redirect_uri manipulation.** Against a staging IdP: issue authorize requests varying only redirect_uri - sibling path, traversal variant, subdomain swap, scheme downgrade. Expected safe behavior: NO 302 toward the manipulated URI; failure surfaces as an AS error page or `error=invalid_request`-shaped response (some frameworks emit a `redirect_uri_mismatch`-style error). Any 30x landing off-allowlist is the finding.
3. **Code replay / single-use test.** Complete one flow, capture `code` from the callback request. Replay the token exchange twice. Second must fail `invalid_grant`. Also replay the raw callback URL after logout: no session may be created from a consumed code.
4. **Nonce/id_token replay test.** Capture a full id_token-bearing callback. Replay it verbatim against the RP. Then start a second login supplying the first nonce value. Both replays must be rejected; acceptance proves nonce binding or single-use id_token handling is absent.
5. **PKCE downgrade probe.** If the repo controls both ends (embedded IdP): send authorize with `code_challenge_method=plain`; if accepted, flag downgrade tolerance. If auditing RP only: static-verify challenge = BASE64URL(SHA256(verifier)) and method constant `S256`.
6. **Unverified-email takeover walkthrough (code-audit checklist).**
   a. Find linking/registration-on-SSO code path.
   b. Does it read `email_verified` (or provider-specific equivalent) before matching on email? Grep claim names across the linking module.
   c. Is identity keyed on `(iss, sub)` with email as display-only?
   d. Pre-hijack check: can an account exist at the RP whose federated identity points to an external IdP subject the "owner" never controlled (attacker-seeded)? Look for auto-create on first SSO without domain allowlist or admin approval.
   e. Write up with concrete claim-flow: attacker IdP issues `{"email":"victim@corp.com","email_verified":false}` -> RP matches victim -> session as victim.
7. **XSW conceptual reproduction.** Static: confirm SP library version against known-wrapping-resistant releases; check whether schema validation and single-assertion enforcement exist in ACS handler. Conceptual dynamic: craft Response per cheat-sheet structure using a self-generated cert for the relocated-but-signed original assertion; success = NameID swap accepted. Reference tooling generically: browser-extension/Burp categories performing certificate substitution and assertion relocation (e.g., the widely known SAML Raider-style extensions).
8. **Logout incompleteness verification.** Log in via SSO, then complete IdP-side logout. Re-present the RP session cookie: if authenticated content still renders, back-channel/front-channel logout is unwired. Check RP logs for received logout tokens.

## Remediation

Per-flaw fixes with library-correct configuration shapes. Where option names drift across library versions the line carries a Needs-Review marker; verify against your lockfile before prescribing.

- **Flows:** disable implicit everywhere (Keycloak client `implicitFlowEnabled: false`; ASP.NET never set `ResponseType = IdToken`/`IdTokenToken`; use `Code`). Use authorization-code + PKCE S256 for ALL clients - public and confidential alike, per current BCP.
- **PKCE generation** (Node shape; same math in every stack):

```js
const { randomBytes, createHash } = require('crypto');
const verifier  = randomBytes(32).toString('base64url');              // >= 43 chars
const challenge = createHash('sha256').update(verifier).digest('base64url');
// authorize: &code_challenge=${challenge}&code_challenge_method=S256
// token:    &code_verifier=${verifier}
```

Server side: store the CHALLENGE with the pending authorization; on exchange recompute from the submitted verifier; reject `plain`.

- **Strict redirect_uri matching.** Canonicalize once, then compare exact strings; special-case loopback ports only:

```js
function redirectAllowed(requestedRaw, allowlist) {
  const requested = new URL(requestedRaw);            // normalizes ../ traversal away
  return allowlist.some(entry => {
    const allowed = new URL(entry);
    const loopback = h => h === '127.0.0.1' || h === '[::1]' || h === 'localhost';
    if (loopback(allowed.hostname) && allowed.hostname === requested.hostname) {
      // RFC 8252: loopback IP literal -> port may vary; everything else must match
      return allowed.protocol === requested.protocol &&
             allowed.pathname.replace(/\/+$/, '') === requested.pathname.replace(/\/+$/, '');
    }
    return entry === new URL(requestedRaw).href;       // byte-exact for all non-loopback
  });
}
```

Remove wildcard registrations; enumerate hosts. For first-party redirectors: closed path allowlist, no arbitrary `next` passthrough.

- **post_logout_redirect_uri:** validate against per-client registered list AND require valid `id_token_hint`; Keycloak (18+) exposes `post.logout.redirect.uris` client attribute (Needs-Review across realm versions).

- **state:** CSPRNG value stored server-side (or HMAC'd into a signed cookie containing issuance time), consumed-and-deleted in callback before any user operation:

```python
# authorize
state = secrets.token_urlsafe(32); session["oauth_state"] = state
# callback - FIRST lines, before user lookup/creation/session write
if not state_param or state_param != session.pop("oauth_state", None):
    abort(400)
```

- **passport-oauth2 strategy options shape** (`state: true`, `pkce: 'S256'` - Needs-Review for version support):

```js
new OAuth2Strategy({
  authorizationURL: `${ISSUER}/authorize`, tokenURL: `${ISSUER}/token`,
  clientID, clientSecret, callbackURL: 'https://rp.example.com/auth/callback',
  scope: 'openid email profile', state: true, pkce: 'S256',
}, verify)
```

- **express-openid-connect middleware shape** (option names stable across recent majors):

```js
app.use(auth({
  issuerBaseURL: 'https://idp.example.com', baseURL: 'https://rp.example.com',
  clientID: process.env.CLIENT_ID, clientSecret: process.env.CLIENT_SECRET,
  secret: process.env.SESSION_COOKIE_SECRET,
  authorizationParams: { response_type: 'code', scope: 'openid profile email' },
  idpLogout: true,
  routes: { callback: '/auth/callback' },
}));
```

- **Spring client registration keys** (certain names; PKCE auto-enablement for `client-authentication-method: none` is Boot-version dependent - Needs-Review):

```yaml
spring.security.oauth2.client.registration.acme:
  client-id: spa
  client-authentication-method: none   # public client
  authorization-grant-type: authorization_code
  redirect-uri: '{baseUrl}/login/oauth2/code/{registrationId}'
  scope: openid,profile,email
spring.security.oauth2.client.provider.acme:
  issuer-uri: https://idp.example.com  # pins iss + discovery + jwks_uri together
```

SAML relying-party key names moved between Boot releases (`assertingparty.*` vs legacy nesting) - Needs-Review against your Boot version.

- **ASP.NET OpenIdConnect options shape**:

```csharp
new OpenIdConnectOptions {
  Authority = ISSUER,
  ClientId = clientId, ClientSecret = clientSecret,
  ResponseType = OpenIdConnectResponseType.Code,
  ResponseMode = OpenIdConnectResponseMode.FormPost,
  CallbackPath = "/auth/callback",
  SignedOutRedirectUri = "/logged-out",
  SaveTokens = false,
  TokenValidationParameters = { ValidIssuer = ISSUER, ValidAudience = clientId }
};
```

- **omniauth_openid_connect strategy shape** (option names vary by gem major - Needs-Review):

```ruby
provider :openid_connect, {
  name: :acme, issuer: 'https://idp.example.com', discovery: true,
  scope: [:openid, :email, :profile], response_type: :code,
  client_options: { identifier: ENV.fetch('CLIENT_ID'),
                    secret: ENV.fetch('CLIENT_SECRET'),
                    redirect_uri: 'https://rp.example.com/auth/acme/callback' },
  uid_field: 'sub'   # bind identity to issuer+subject, never raw email
}
```

Also remove `skip_jwt: true`-style verification opt-outs found in omniauth provider blocks.

- **Authlib registration shape**: pass `client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"}` and `server_metadata_url` pointing at `/.well-known/openid-configuration` so iss/jwks pinning comes from one configured root.

- **email_verified gate sample**:

```python
sub, email = claims.get("sub"), claims.get("email")
verified   = claims.get("email_verified") is True
user = Users.get_by_federated_identity(issuer=ISSUER, subject=sub)   # primary lookup
if user is None and verified:
    user = Users.get_by_email(email)                                  # linking ONLY after gate
elif user is None:
    raise LinkRefused("issuer has not verified the mail claim")
```

- **JWT validation:** decode with explicit `algorithms=["RS256"]` (or configured EC algorithm), `audience=`, `issuer=`; fetch keys only from the pinned `jwks_uri`; treat kid as opaque parameterized lookup key; cap unknown-kid refresh attempts.
- **Code single-use (IdP side):** consume codes atomically (unique-index or compare-and-swap) on first redemption; TTL minutes-scale.
- **Refresh rotation:** issue new refresh on every use; detect reuse of a rotated token and revoke the whole family.
- **Back-channel logout:** implement the OIDC Back-Channel Logout endpoint at the RP and register its URL in the IdP client config (Keycloak client attributes `backchannel.logout.url` / `backchannel.logout.session.required` - Needs-Review naming across realms); validate the logout token's `events`/`sub` and clear local session. Front-channel iframes are the fallback where back-channel is unavailable.
- **SAML SP:** upgrade to a maintained library release with wrapping resistance; enforce schema validation, single-Assertion policy, AudienceCondition equality, tight validity windows with small skew, RelayState restricted to registered/relative targets, signed metadata with pinned certs.

## Verification & Validation

Scenario checks:

- GIVEN tightened build WHEN forged callback arrives with absent/mismatched state THEN no session is created AND rejection is logged; WHEN a real browser completes SSO login THEN it succeeds (negative-control against over-tightening).
- GIVEN allowlist-only redirect validation WHEN legitimate registered URIs are used THEN flow completes unchanged; WHEN sibling-path/traversal/subdomain variants are sent THEN AS returns mismatch error and issues no redirect off-list.
- GIVEN single-use code enforcement WHEN the token endpoint receives a consumed code THEN response is `invalid_grant` AND no second token set appears anywhere.
- GIVEN alg allowlisting WHEN an HS256-confusion or `alg:none` id_token is presented THEN RP rejects before any claim use; WHEN staging-issued genuine tokens arrive THEN login works across ALL configured providers.
- GIVEN nonce binding WHEN a captured id_token-bearing callback is replayed THEN rejected.
- GIVEN unverified-email gate WHEN an IdP account presents `email_verified:false` matching an existing local user THEN no link occurs AND security event is recorded; WHEN a properly verified identity links THEN succeeds.
- GIVEN back-channel logout WHEN IdP logout completes THEN RP receives logout token, clears session, and subsequent requests are anonymous end-to-end.

Regression suite pseudocode for CI against a staging IdP:

```
suite oauth-federation-hardening:
  t1 authorize(foreign redirect_uri)        -> non-redirect error, mismatch surfaced
  t2 authorize(traversal redirect variant)  -> mismatch error, no Location to attacker host
  t3 exchange(code) twice                   -> first 200, second invalid_grant
  t4 forged callback(state=nope)            -> zero sessions created; 4xx recorded
  t5 public-client exchange w/o verifier    -> invalid_grant (PKCE enforced)
  t6 HS256-confused id_token                -> RP rejects; legit RS256 token accepted (control)
  t7 replay of prior id_token/callback      -> rejected
  t8 scripted real SSO login each provider  -> success (guards over-tightening)
  t9 full logout chain                      -> RP anonymous afterwards
```

Manual checklist: every authorize site emits state+nonce+PKCE-S256; every callback compares state first; decodes pin algorithms; linking reads email_verified; identity keyed (iss,sub); post_logout validated; refresh rotates; logout endpoints wired; IdP toggles implicit/direct-grant/dynamic-registration off unless documented.

Post-fix greps (expect empty or reviewed hits):

```bash
rg -n 'response_type[=:](token|id_token)' .
rg -n '"implicitFlowEnabled"\s*:\s*true|implicitFlowEnabled: true' .
rg -n 'code_challenge_method[=:](plain|"plain"|'"'"'plain'"'"')' .
rg -n 'algorithms\s*:\s*\[\s*["'"']none["'"']\s*\]' .
rg -n 'startsWith\([^)]*(redirect|callback|returnUrl)' .
rg -n 'grant_type[=:]["'"']password' .
rg -n 'skip_jwt:\s*true' .
```

## Severity Assessment

Anchors (CVSS v3.1; rescope if multi-tenant blast radius applies):

| Anchor | Flaw class | Vector | Score |
|---|---|---|---|
| Critical | Account takeover via email-match linking without `email_verified` gate | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| Critical | SAML XML signature wrapping accepted at ACS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| High | Missing PKCE on public client with interceptable redirect channel (http redirect_uri, hijackable scheme, referrer leakage); use AC:H when interception requires attacker-installed app/network position | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | 8.1 |
| High | Code replay accepted (leakage channel via Referer/history makes capture realistic) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | 8.2 |
| High | state absent/unbound with session-fixation impact (victim operates inside attacker identity) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` | 7.1 |
| Medium | post_logout_redirect_uri / RelayState open redirect (phishing pivot) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` | 4.3 |
| Medium | Refresh-token rotation absent (extends life of an already-stolen token) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | 4.8 |
| Low | Internal issuer URLs / topology disclosure in client configs or verbose discovery surfaces | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` | 3.1 |

Modifiers: downgrade High anchors one step when the affected client is internal-only with network controls documented; upgrade to Scope:Changed when a tenant boundary is crossed (assertion/token from tenant A valid in tenant B). kid-injection findings inherit INJ-module severity by sink type.

## Common False Positives

- First-party redirectors intentionally relaying their own paths: verify the target set is closed and first-party-only, then scope-limit the finding ("redirector accepts arbitrary path under own origin" vs "open redirect"). Do not flag blindly.
- Service-account `client_credentials`: machine-to-machine flows legitimately lack state/nonce/PKCE. Still check scope breadth and credential handling, but do not report user-flow flaws against them.
- Legacy SAML kept deliberately behind VPN: downgrade severity and document the compensating boundary in the report; do not silently drop.
- Loopback port flexibility on native clients is RFC 8252-conformant behavior, not a bypass; only divergent treatment between `localhost`, IP literals, and `[::1]` across checks is a finding.
- `response_mode=form_post` on code flow is correct design, not confusion; confusion is the mismatch between declared mode and handler parsing.
- Publishing standard `.well-known/openid-configuration` fields is spec-required behavior; only internal-infrastructure leakage within it is reportable.
- Tokens stored in HttpOnly cookies are fine; the localStorage finding belongs to actual web-storage persistence (cross-ref WEB).

## References

Specifications:

- RFC 6749, OAuth 2.0 Framework - https://datatracker.ietf.org/doc/html/rfc6749
- RFC 6750, Bearer Token Usage - https://datatracker.ietf.org/doc/html/rfc6750
- RFC 7636, PKCE - https://datatracker.ietf.org/doc/html/rfc7636
- RFC 8252, OAuth 2.0 for Native Apps - https://datatracker.ietf.org/doc/html/rfc8252
- RFC 8707, Resource Indicators - https://datatracker.ietf.org/doc/html/rfc8707
- OAuth 2.0 Security Best Current Practice (RFC 9700) - https://datatracker.ietf.org/doc/html/rfc9700
- OpenID Connect Core 1.0 - https://openid.net/specs/openid-connect-core-1_0.html
- OIDC Discovery 1.0 - https://openid.net/specs/openid-connect-discovery-1_0.html
- OIDC Back-Channel Logout 1.0 - https://openid.net/specs/openid-connect-backchannel-1_0.html
- OIDC Front-Channel Logout 1.0 - https://openid.net/specs/openid-connect-frontchannel-1_0.html

Weakness entries:

- CWE-352 Cross-Site Request Forgery - https://cwe.mitre.org/data/definitions/352.html
- CWE-287 Improper Authentication - https://cwe.mitre.org/data/definitions/287.html
- CWE-601 URL Redirection to Untrusted Site - https://cwe.mitre.org/data/definitions/601.html
- CWE-347 Improper Verification of Cryptographic Signature - https://cwe.mitre.org/data/definitions/347.html

OWASP Cheat Sheets:

- SAML Security - https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- Cross-Site Request Forgery Prevention - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Session Management - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Authentication - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

Tooling category: browser-proxy extensions of the SAML-manipulation class (commonly cited example: SAML Raider-style Burp extension) providing assertion relocation and certificate-substitution testing capability.
