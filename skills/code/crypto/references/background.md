# Cryptographic Failures — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the grep signatures, decision tables, and per-language
fixes.

## How this class emerged

Cryptography in software went through three eras that each left debris in
modern codebases:

- **Hand-rolled era (1990s).** Developers invented ciphers from XOR loops and
  character shifts, because strong primitives were hard to obtain and export
  laws restricted them. The lesson that survived: custom constructions break,
  and "hidden" algorithms are not protection.
- **Standardization era (2000s).** AES, SHA-2, TLS, and mature libraries made
  strong primitives available everywhere. But standards specify primitives, not
  their wiring — so applications still chose wrong modes (ECB), reused
  initialization values, and hashed passwords with one fast digest call.
- **Hardening era (2010s onward).** High-profile failures moved attention from
  "is this algorithm broken?" to "is this *use* of a good algorithm safe?"
  Nonce reuse under AEAD modes was shown to destroy both secrecy and tamper
  detection at once; password hashing gained dedicated memory-hard functions;
  TLS verification kill-switches (`verify=False`) were cataloged as a defect
  class of their own; and post-quantum migration planning entered the agenda.

OWASP's Top 10 renamed this category from "Sensitive Data Exposure" to
"Cryptographic Failures" to emphasize exactly that shift: the failure is rarely
mathematics — it is configuration, parameter choice, key provenance, and
verification order inside ordinary application code.

## Anatomy: one good cipher, used wrong

Minimal generic vulnerable snippet (Python-flavored pseudocode; every stack has
an equivalent):

```python
key = b"s3cr3t-key-1234"            # hardcoded, low entropy, 16 bytes
iv  = bytes(16)                     # fixed all-zero IV, reused forever
ct = aes_cbc_encrypt(key, iv, plaintext)
store(ct)                           # no MAC/tag anywhere
```

Failure walkthrough:

1. **Key origin.** The key is a human-chosen string committed beside the code.
   Guessing space collapses to dictionary attacks; rotation is impossible
   because it ships inside the artifact.
2. **IV/nonce reuse.** CBC with a constant IV encrypts identical plaintexts to
   identical ciphertexts, leaking equality patterns; worse, an attacker who
   knows one plaintext block can manipulate ciphertext blocks to flip
   corresponding plaintext bits in the next block (bit-flipping) because there
   is no integrity check to notice.
3. **No authentication.** Decryption accepts tampered ciphertext and returns
   altered plaintext or padding errors — either way the application downstream
   trusts data nobody vouched for.
4. **Nothing "fails."** The API returns success on every operation. The damage
   surfaces only when someone compares two ciphertexts, flips bits, or decrypts
   a forged record.

Contrast the corrected shape in one breath: key from a secret manager, fresh
random nonce per message, authenticated mode (GCM/ChaCha20-Poly1305) with tag
verified before any plaintext is used.

## Why naive fixes fail

Each tempting shortcut below fails; SKILL.md's Remediation section holds the
working replacements.

- **"Just switch to AES."** The default transformation in some libraries *is*
  ECB; naming the primitive without naming mode, IV source, and tag length
  reproduces the same defects with a modern label.
- **Hashing the password harder with SHA-512.** Fast general-purpose hashes are
  built to be fast; GPU rigs measure billions of guesses per second. Only
  dedicated password KDFs (Argon2id, scrypt, bcrypt, tuned PBKDF2) impose cost.
- **Salting with username/email.** Predictable salts enable precomputed tables
  per known salt value; salts must be random per credential and stored alongside.
- **Base64/XOR "encryption" for obfuscation.** Encoding is transport, not
  secrecy; reversible without any key material once recognized.
- **Disabling certificate verification to "fix" connectivity.** The error was
  the defense working. The fix is trusting the right root CA, not trusting
  everything.
- **Seeding a PRNG with the time "for more randomness."** Seeding makes the
  stream deterministic; timestamps are guessable, so outputs become guessable.
  Security tokens need the OS CSPRNG, unseeded.
- **Comparing digests with `==`.** Ordinary equality short-circuits at the first
  differing byte, leaking position information over many trials; use the
  language's constant-time comparison.
- **Signing with `hash(secret || data)`.** Merkle-Damgård digests accept
  length-extension: knowing a valid signature lets you append data and compute
  a new valid signature without the secret. Keyed HMAC exists precisely to
  prevent this.

## Common misconceptions

1. **"Encrypted means safe."** Encryption without authentication is malleable:
   attackers can alter ciphertexts in meaningful ways. Secrecy and integrity
   are separate properties; only authenticated encryption gives both.
2. **"Strong algorithms are the hard part."** Almost every finding here uses a
   respected algorithm incorrectly — wrong mode, repeated nonce, truncated tag,
   cross-purpose key. Wiring dominates mathematics.
3. **`Math.random()` is random enough.** It is a fast statistical generator
   with no security guarantees; its outputs are predictable from a few observed
   values. Session IDs, reset tokens, OTPs require CSPRNG sources.
4. **"HTTPS everywhere means crypto is done."** TLS protects data in motion
   only. Data at rest, stored credentials, webhook verification, and token
   signing are separate surfaces with separate failure modes.
5. **"MD5/SHA-1 are fine for non-password uses."** They are broken for
   collision-dependent trust decisions (signatures, fingerprints gating
   access). For dedup/cache keys they are tolerable — context decides, which is
   why SKILL.md lists them as false positives when nothing security-relevant
   consumes the digest.
6. **"Bigger numbers mean better crypto."** A huge RSA modulus with PKCS#1 v1.5
   padding on an encryption path is weaker than correct OAEP at 2048 bits;
   parameter correctness beats size theater.
7. **"Encoding = encryption."** Base64 is visible to anyone; ROT13 is older than
   computers; embedded keys in shipped JavaScript are public constants.

## Modern taxonomy map

Matches the failure-class table in `../SKILL.md`'s Mental Model section:

| Failure class | Essence | Canonical site |
|---|---|---|
| Wrong primitive | MD5/SHA-1/DES/RC4 still wired in | digest helpers, legacy adapters |
| Wrong mode | ECB; raw CBC/CTR without MAC | `Cipher.getInstance("AES")`, `MODE_ECB` |
| Wrong uniqueness | Fixed/zero/repeating IV or nonce | IV literals, counters reset per boot |
| Wrong key | Password bytes as key; one key for enc+MAC+sign | `SecretKeySpec(pw.getBytes())` |
| Wrong randomness | `Math.random()` tokens, seeded PRNGs | token/OTP/reset generators |
| Wrong verification | `==` on digests; missing sig checks; no replay window | webhooks, token validators |
| TLS bypass | Verification disabled/overridden | HTTP clients, trust managers |
| Password storage | Fast/unsalted/under-parameterized hashing | user tables, migration paths |
| Pseudo-encryption | base64/XOR/ROT13 masquerading as crypto | config blobs, license checks |

Severity intuition: nonce reuse on attacker-visible traffic and algorithm-
acceptance bypasses (e.g., JWT `alg:none`) are Critical; disabled TLS
verification and weak token randomness are High; under-tuned password KDFs are
Medium during documented migrations.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — the six-decision-point pipeline every crypto call must answer.
2. **What To Check** — per-surface checklists: primitives, modes/IVs, AEAD
   coverage, key management, password parameters, randomness, hash
   constructions, TLS clients, JWT/JWE, encoding masquerades, webhooks.
3. **Patterns & Signatures** — P1–P14 ripgrep blocks plus the dangerous-call
   reference table.
4. **Exploitation & Reproduction** — offline proofs (ECB determinism, bit-flip
   math, keystream recovery) usable without touching production.
5. **Remediation** — the algorithm decision table and before/after diffs per stack.
6. **Common False Positives** — before flagging MD5-in-a-cache-key or bcrypt-cost
   debates, read what does not qualify.

Sibling modules owning adjacent defects:

- `../secrets-data-exposure/` — where keys live (committed .env, sprawl); here we judge usage sites.
- `../authn-session/` — auth-flow logic and HS/RS JWT confusion walkthrough.
- `../configuration-hardening/` — server-side TLS termination, HSTS headers.
