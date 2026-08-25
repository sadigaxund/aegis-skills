# Authentication & Session Management — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no prior security background assumed. Teaches the *why*; SKILL.md keeps the
state-machine tables, signatures, and remediation recipes.

## How this class emerged

Authentication is older than networked computing: early 1960s time-sharing
systems introduced passwords to separate users on shared machines, and almost
immediately someone abused the mechanism itself. Three engineering responses
define the field's history:

- **Slowing offline guessing.** Unix introduced salted, deliberately slow
  password hashing in the 1970s; successive KDFs (bcrypt in 1999, scrypt in
  2009, Argon2 winning its design competition in 2015) escalated hardware cost
  because general-purpose hashes kept getting faster.
- **Keeping state over a stateless protocol.** Cookies were proposed in 1994 to
  give HTTP memory. Sessions inherited every problem of unguessable identifiers:
  fixation (planting an identifier you already know), non-expiry, and logout
  theater where only the client forgets.
- **Adding factors.** Hardware tokens date to the 1980s; TOTP was standardized
  as RFC 6238 in 2011. As password databases leaked wholesale in the 2010s,
  credential stuffing industrialized reuse of those passwords, making rate
  limiting and breached-password screening first-class requirements.
- **Delegated tokens.** JWT arrived as RFC 7519 in 2015: signed claims instead
  of server-side session records — trading revocation difficulty for
  distribution convenience, and introducing algorithm-selection bugs of its own.

Reset flows became the dominant account-takeover path once email became the
universal identity anchor: whoever controls the mailbox controls the account.

## Anatomy

A minimal flawed login handler concentrates several flaw classes at once:

```js
const u = db.users.findByEmail(req.body.email);
if (!u) return res.status(404).json({ error: "No such user" });
if (u.password === sha256(req.body.password))
  return res.status(200).json({ error: null });
return res.status(401).json({ error: "Wrong password" });
```

Walkthrough of what an auditor sees:

1. **Enumeration** — unknown users get 404 with a distinct message; known users
   get 401. The response difference is an account-existence oracle.
2. **Fast hash** — single-pass SHA-256 lets an attacker who later obtains the
   table test billions of guesses per second per GPU. No salt means identical
   passwords produce identical hashes across accounts.
3. **String comparison** — `===` on digest strings is not a constant-time
   verifier; use the KDF library's compare function.
4. **No throttle** — unlimited guesses per account and per source; nothing feeds
   lockout or backoff.
5. **No regeneration step shown** — if login never rotates the pre-auth session
   identifier, anyone who planted it owns the authenticated session (fixation).

Every stage of SKILL.md's state machine exists because one of these lines went
wrong somewhere: credential verify, attempt throttle, identity issuance,
lifetime, recovery, step-up, token trust, registration, response parity.

## Why naive fixes fail

One subsection because the recurring errors are structural:

- **Hiding usernames does not stop enumeration.** Timing differences (KDF runs
  only when the user exists) leak the same fact; uniform responses require doing
  equivalent work on both paths.
- **Client-side lockouts are decorative.** Attackers script raw HTTP; any limit
  must be enforced against server-side state keyed by account *and* source.
- **Security questions are a second password** chosen from public-record
  answers; treat them as knowledge factors only when the answers are high-
  entropy random values stored like secrets.
- **Hashing twice with SHA-256 is not a KDF.** Speed is the enemy; only memory-
  hard or tunably-slow functions make offline guessing expensive.
- **"JWT is stateless so logout is impossible"** conflates a limitation with an
  excuse: short lifetimes plus denylists/rotation recover most of the control.
- **Obscure endpoints stay vulnerable**: reset and MFA routes are discovered via
  bundles, docs, and parameter fuzzing regardless of link visibility.

## Common misconceptions

1. "HTTPS makes sessions safe." Transport protection does not stop token theft
   via logs, Referer leaks, XSS, or shared devices — nor fixation at issuance.
2. "A valid JWT signature proves the claims are true." It proves integrity since
   signing *by whatever key verified it* — algorithm confusion (`none`, RS256->
   HS256) or missing audience/issuer checks turn valid signatures into bypasses.
3. "Logout deletes the session." Deleting a client cookie changes nothing
   server-side; replay works until the store entry dies.
4. "Lockout after N attempts stops brute force." Keyed per-IP it falls to
   distributed attempts; blanket per-account it becomes a denial-of-service lever
   against victims.
5. "MFA eliminates account takeover." Push-bombing fatigue, real-time relay
   kits, SIM-swapped SMS codes, and "verify later" flow skips all reintroduce
   bypasses; enforcement point matters more than factor count.
6. "Password rotation policies improve security." Forced periodic changes push
   users toward predictable variants; modern guidance favors length, breach
   screening, and change-on-evidence-of-compromise.
7. "Email is an internal channel." Mailboxes are shared, backed up, indexed, and
   themselves recoverable by the same reset flows — reset links are credentials.

## How professionals think about it today

Practice models authentication as a guarded state machine and token lifecycle,
matching SKILL.md's stage table:

| Branch | Core question | Defining control |
|---|---|---|
| Credential verification | Slow, salted KDF + constant-time compare? | Argon2id/bcrypt(12+)/scrypt/PBKDF2-600k |
| Throttling & stuffing defense | Bounded per account AND source? | server-side counters, breached-password screening |
| Identity issuance | Fresh unpredictable identifier at login? | session regeneration / new refresh family |
| Lifetime & invalidation | Server-authoritative expiry everywhere? | store-backed timeouts; logout kills records |
| Recovery | Unguessable expiring single-use token? | CSPRNG >=128-bit, hashed storage, atomic consume |
| Step-up (MFA) | Sensitive actions re-prove identity? | server-side gate before privileged routes mount |
| Token trust | Algorithm, issuer, audience, expiry enforced? | pinned allowlist verification, key from config |
| Response parity | Do all failures look identical? | uniform status/body/timing |

Factor taxonomy (knowledge/possession/inherence), phishing-resistant upgrades
(WebAuthn/passkeys), and per-session visibility for users round out the modern
posture. Severity intuition: anything reachable before authentication completes
is fully attacker-controlled input territory — audit it like public surface,
because it is one.

## Read next

In `../SKILL.md`: **Mental Model** (the nine-stage state machine), **What To
Check** (per-flow procedures), **Where To Look** (path globs and framework
marker matrix), **Patterns & Signatures**, **Taint Tracing Guidance**,
**Remediation**, **Common False Positives** (md5-for-cache-keys and friends).

Sibling modules: `../oauth-sso/SKILL.md` (delegated identity and consent
flows), `../authz-access-control/SKILL.md` (decisions after identity is
established), `../secrets-data-exposure/SKILL.md` (committed signing keys and
seeded credentials), `../configuration-hardening/SKILL.md` (cookie attribute
matrix), `../crypto/SKILL.md` (hash/KDF depth).
