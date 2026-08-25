---
name: crypto-checks
description: Detects cryptographic failures including weak/legacy algorithms, cipher-mode and nonce misuse, broken key management, weak password hashing, insecure randomness, disabled TLS verification, JWT crypto misconfiguration, encoding masquerading as encryption, and missing webhook signature verification.
category_slug: CRYPTO
cwe: [CWE-327, CWE-326, CWE-321, CWE-323, CWE-328, CWE-329, CWE-330, CWE-331, CWE-338, CWE-340, CWE-347, CWE-295, CWE-297, CWE-354, CWE-208, CWE-759, CWE-760, CWE-916]
owasp: A02:2021 – Cryptographic Failures
---

## Scope & Objectives

Scan application source, configuration, and dependency manifests for cryptographic design and implementation flaws. Confirm or refute each candidate finding by tracing how key material, plaintexts, nonces, and verification results actually flow.

- In scope: weak/legacy primitives; ECB/CBC/CTR/GCM misuse; IV/nonce generation; key derivation and cross-purpose reuse; hardcoded keys and peppers at usage sites; password hashing parameters and comparisons; PRNG choice; hash-based MAC/signature constructions and domain separation; TLS client verification; JWT/JWE crypto parameters; base64/XOR/ROT13 pseudo-encryption; webhook signature validation and replay windows.
- Out of scope (cross-reference): credential/key storage sprawl and committed `.env` files (SECRETS); auth-flow logic and the JWT HS/RS confusion walkthrough (AUTHN); server TLS termination, HSTS, and header hardening (CONFIG); network-level infra scanning.

## Mental Model

Evaluate every cryptographic operation along one pipeline and interrogate six decision points:

```text
plaintext --> [1 primitive] --> [2 mode] --> [3 IV/nonce source] --> [4 integrity/auth] --> ciphertext
key ------> [5 origin & strength] ----------------------> [reused across purposes?]
verifier --> [6 constant-time? fresh? covers what exactly?] --> allow/deny
```

| Failure class | Canonical bug | Typical code site |
|---|---|---|
| Wrong primitive | MD5/SHA-1/DES/RC4 still wired in | digest helpers, legacy adapters |
| Wrong mode | ECB; raw CBC or CTR without MAC | `Cipher.getInstance`, `AES.new` |
| Wrong uniqueness | Fixed, zero, or repeating IV/nonce | IV constants, counters reset per boot |
| Wrong key | Password bytes as key; one key for enc+MAC+sign | `SecretKeySpec(pw.getBytes(), "AES")` |
| Wrong randomness | `Math.random()` tokens, seeded PRNGs | token/OTP/reset-code generators |
| Wrong verification | `==` on digests; missing sig check; no replay window | webhook handlers, token validators |

Escalation rule: any single answer that is "attacker-influenced" or deterministic is a finding; when answers 3 and 4 are both wrong for the same data path (e.g. GCM nonce reuse), classify as catastrophic immediately — confidentiality AND integrity are lost together.

## What To Check

### Weak & Legacy Primitives
1. Scan all digest construction sites; flag MD5 and SHA-1 wherever output feeds a security decision (tokens, signatures, password storage, cache authorization, fingerprint matching).
2. Flag DES, 3DES/TripleDES/DESede, RC2, RC4/ARC4, Blowfish, and any cipher instantiated without an explicit authenticated mode.
3. Flag ECB in every form: explicit `/ECB/` transformations, `MODE_ECB`, `AesMode.ECB`, and library defaults such as Java `"AES"` with no transformation (SunJCE default = ECB).
4. Trace RSA usage: encryption must use OAEP with SHA-256/MGF1-SHA-256; flag `PKCS1Padding`, `EncryptPKCS1v15`, `RSA_PKCS1_PADDING` on encryption paths (RSASSA-PKCS1-v1_5 *signatures* are a separate, lower-severity concern).
5. Check generated key sizes: RSA >= 2048 (prefer 3072); EC curves P-256+ (reject prime192v1/secp192r1/secp160*/secp224r1); symmetric keys >= 128 bits.
6. Hunt export-grade/legacy suite configuration: `EXPORT`, `EXP-`, `RC4`, `3DES`, `NULL`, `aNULL`, `SECLEVEL=0` in SSL configs and code-built cipher lists.

### Modes, IVs, Nonces
1. Trace every IV/nonce assignment to its origin; require CSPRNG output per message (GCM/CTR: unique-under-key 96-bit nonce; CBC: random 128-bit IV).
2. Flag hardcoded IVs, zero IVs, `IV = first 16 bytes of key`, counters restarting per process, and nonces derived from timestamps or user IDs alone.
3. For GCM: require full 128-bit tags; flag `GCMParameterSpec(96|64|32, ...)` and silent acceptance of truncated tags on decrypt.
4. For CTR/OFB/CFB: prove nonce uniqueness under the key across restarts and concurrent writers; timestamp+PID is not sufficient.
5. For CBC without a MAC: assess padding-oracle exposure (distinct errors/timings for bad padding vs bad MAC) and bit-flip susceptibility of trusted token fields.

### Authenticated Encryption Coverage
1. Require AEAD (AES-GCM, ChaCha20-Poly1305) or explicit encrypt-then-MAC at every confidentiality boundary.
2. Verify the MAC/AAD covers IV/nonce, ciphertext, algorithm/version identifiers, and binding metadata (user ID, key version) — not ciphertext alone.
3. Flag MAC-then-encrypt layouts and MACs that omit the IV.
4. Inspect decryption failure paths: uniform error responses, no plaintext fragments or padding details in exceptions/logs.

### Key Management Usage
1. Locate every key/secret/pepper literal consumed by crypto APIs (storage sprawl itself is SECRETS; here judge usage).
2. Flag keys derived from passwords via one bare hash (`sha256(pw)` as an AES key) instead of Argon2id/scrypt (passwords) or HKDF (high-entropy inputs).
3. Flag one key serving encryption + MAC + signing roles; require HKDF subkeys with distinct `info` labels.
4. Flag key material reaching logs, exception messages, `fmt.Println(key)`, `toString()` dumps, or URL query strings.
5. Check pepper handling: pepper lives outside the credential store and enters as HMAC-SHA-512 pre-hash before the password KDF — never concatenated into an unsalted fast digest.

### Password Storage Parameters
1. Identify the stored verifier format (PHC strings `$argon2id$...`, `$2b$...`, `pbkdf2$...` vs bare hex) from schema/migrations/fixtures.
2. Enforce floors: Argon2id m=19 MiB,t=2,p=1; scrypt N=2^17,r=8,p=1; bcrypt cost >= 10; PBKDF2-HMAC-SHA256 >= 600k iterations (SHA-512 >= 210k; SHA-1 legacy >= 1.3M).
3. Flag unsalted fast hashes (`md5($password)`, `sha256(password.encode())`), saltless `crypt()`, salts < 16 bytes, or salts equal to username/email.
4. Flag non-constant-time comparisons (`==`, `===`, `strcmp`, `Arrays.equals`) on digest/signature values where `hash_equals`, `crypto.timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`, `CryptographicOperations.FixedTimeEquals`, `subtle.ConstantTimeCompare`, or `secure_compare` exists.
5. Verify bcrypt >72-byte input handling (pre-hash `base64(HMAC-SHA-512(pepper,pw))` or document truncation explicitly).

### Randomness Provenance
1. Classify every token/OTP/session-ID/nonce generator against the OS CSPRNG requirement (`getRandomValues`, `randomBytes`, `secrets`, `SecureRandom`, `RandomNumberGenerator`, `random_bytes`, `SecureRandom` module, `crypto/rand`).
2. Flag `Math.random`, `mt_rand`, bare `rand()`, `random.choice/random.randint/random.random`, `new Random()`, `srand(time())`, `Time.now.to_i % n`.
3. Flag manual seeding of otherwise-correct PRNGs (`setSeed(long)`, `rng.seed(...)`, `random.seed(input)`).
4. Flag UUID v1 (timestamp+MAC, guessable) used as capability/session identifier; UUID v4 is acceptable.
5. Require >= 128 bits CSPRNG entropy per session/reset token (>= 256 for long-lived API keys).

### Hash-Based Constructions
1. Flag bare `digest(data)` compared against an expected value acting as a signature — require keyed HMAC.
2. Detect length-extension-prone layouts `hash(secret || data)` on URLs, cookies, query params (MD5/SHA-1/SHA-256 are Merkle-Damgard); require `HMAC(secret, data)`.
3. Check domain separation: one MAC key signing multiple message types without a type prefix enables token splicing; require per-purpose HKDF subkeys or `type || ':' || payload`.
4. Review fingerprint comparisons (cert pin sets, SSH host keys, artifact checksums): expect SHA-256 fingerprints; SHA-1 only for non-adversarial display.

### TLS Client Configuration
1. Flag kill-switches: `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False`, `ssl=False`, `InsecureSkipVerify:true`, `CURLOPT_SSL_VERIFYPEER=0`, `CURLOPT_SSL_VERIFYHOST=0`, `VERIFY_NONE`, `CERT_NONE`, `allow_self_signed:true`.
2. Flag trust overrides accepting everything: empty `checkServerIdentity` replacements, anonymous `X509TrustManager`s, `TrustAllCerts`/`HostnameVerifier` implementations returning true, `setDefaultSSLSocketFactory`.
3. Flag protocol pinning to TLSv1.0/1.1 client-side (`maxVersion:'TLSv1'`, `ssl_version=PROTOCOL_TLSv1`, `SslProtocols.Tls/Tls11`) and server-side (`ssl_protocols TLSv1 TLSv1.1;`, `sslEnabledProtocols="TLSv1"`).
4. Confirm private-CA deployments extend trust correctly (`NODE_EXTRA_CA_CERTS`, `verify='/etc/ssl/corp.pem'`, Go `RootCAs` pool, JVM truststore import) rather than disabling validation.

### JWT/JWE Crypto Parameters
1. Flag `'none'/null` algorithm acceptance points: `algorithms:['none']`, `allowNone:true`, hand-rolled base64-decode-and-trust claim readers.
2. Flag weak HMAC secrets: string literals <= ~24 chars, dictionary words, secrets equal to app/host names; require >= 256-bit random keys from secret management.
3. For JWE: flag `RSA1_5` key wrapping (Bleichenbacher-class risk); require `RSA-OAEP-256`, `ECDH-ES+A256KW`, or `A256GCMKW`; flag low-entropy CEKs in `dir` mode; prefer `A256GCM` content encryption.
4. Confirm verify calls pin an explicit algorithm allowlist instead of trusting the token's `alg` header (deep HS/RS confusion analysis: AUTHN).

### Encoding Masquerading as Encryption
1. Trace fields described as "encrypted" whose implementation is only `btoa`, `atob`, `base64_encode`, `base64.b64encode`, `Buffer.from(x,'base64')` with no cipher call.
2. Flag ROT13 (`str_rot13`), fixed-key XOR loops, character-shift schemes, and `xxtea`-style homebrew constructions protecting sensitive values.
3. Flag reversible obfuscation of PII/secrets shipped to clients (packed config blobs, license checks keyed by embedded constants).
4. Flag client-side "encryption" with keys embedded in bundled JS/WASM — extraction is trivial; treat as encoding, not cryptography.

### Webhook & Message Signatures
1. Enumerate inbound webhook routes; require signature presence checks (Stripe `stripe-signature`, GitHub `x-hub-signature-256`, Slack `x-slack-signature`, generic `x-signature`).
2. Verify comparison is constant-time over a recomputed HMAC — not `==` against the attacker-supplied header value, not substring/prefix matching.
3. Verify timestamp parsing enforces a replay window (typical +/- 5 minutes) plus event-ID dedupe where the provider supports it.
4. Verify HMAC input is the raw request body bytes, not a re-serialized object (key-order normalization silently breaks or fakes coverage).

### Enrichment: Key Lifecycle & Migration Posture
1. Post-quantum migration readiness: inventory long-lived signature/key-agreement usage and whether a crypto-agility/migration plan exists (NIST post-quantum migration guidance); treat absence as a roadmap question, not a standalone finding.
2. Envelope encryption pattern: prefer KMS/HSM-backed envelope encryption (data keys wrapped under a key-encryption key) over application-managed raw key material.
3. Certificate lifecycle automation: expiry inventory across deployed certificates, automated renewal wiring, and CT-log monitoring (crt.sh) for unexpected certificates issued against your domains.

## Where To Look

| Surface | Paths / manifests | Focus |
|---|---|---|
| Node/TS | `src/**`, `server/**`, `scripts/**`, `package.json` | `node:crypto`, `crypto-js`, `jsonwebtoken` call sites |
| Python | `**/*.py`, `settings.py`, `requirements.txt`, `pyproject.toml` | `hashlib`, `pycryptodome`/`Crypto`, `cryptography`, `passlib` |
| Java/Kotlin | `src/main/java/**`, `application*.yml`, `pom.xml`, `build.gradle(.kts)` | `javax.crypto`, `MessageDigest`, BouncyCastle, jjwt, nimbus-jose-jwt |
| C# | `**/*.cs`, `appsettings.json`, `web.config`, `*.csproj` | `System.Security.Cryptography`, machine.config |
| PHP | `app/**`, `config/*.php`, `composer.json` | `openssl_*`, `md5(`, `password_hash` cost params |
| Ruby | `app/models/**`, `config/initializers/**`, `Gemfile` | `Digest::`, `OpenSSL::`, Devise/mailboxer token config |
| Go | `**/*.go`, `go.mod` | `crypto/*`, `math/rand`, `tls.Config`, `x/crypto` |
| Infra/config | `nginx*.conf*`, `*.cnf`, `httpd.conf`, `server.xml`, `docker-compose*.yml`, `k8s/**`, `.env.example` | cipher strings, protocol floors, keystore paths |
| Dependencies | `crypto-js`, `js-md5`, `blueimp-md5`, `des.js`, `xxtea`, `bcrypt-nodejs`, `pyDes`, `commons-codec` (DigestUtils), `phpseclib` | how each is invoked, not mere presence |

Prioritize in order: auth/session code; payment and webhook controllers; token/URL signers; data-at-rest helpers (`CryptoUtil`, `EncryptionService`, `crypt.py`, `secrets.go`); batch jobs touching exported data.

Dependency red flag example (npm): `"crypto-js": "*"` combined with `CryptoJS.AES.encrypt(value, 'passphrase')` implies OpenSSL-style KDF with 1 iteration and unauthenticated CBC — treat as broken even though the library itself has no CVE.

## Patterns & Signatures

All patterns are ripgrep-compatible with no lookarounds. Run from repo root:
`rg -n --hidden -g '!{vendor,node_modules,dist,.git}/**' -e '<pattern>'`

[P1] Weak digests:
```regex
(?i)(MessageDigest\.getInstance\(\s*["'](MD5|SHA-?1)["']\s*\)|createHash\(\s*["'](md5|sha1)["']\s*\)|hashlib\.(md5|sha1)\s*\(|Digest::(MD5|SHA1)(\.|::)|new\s+(MD5|SHA1)CryptoServiceProvider|crypto/md5|crypto/sha1|\bmd5\s*\(|\bsha1\s*\()
```

[P2] Legacy ciphers, ECB, dangerous defaults:
```regex
(?i)(-ecb|ecb/|/ecb|MODE_ECB|AesMode\.Ecb|TripleDES|DESede|\bDES[-/]|\bRC4\b|ARC4|ARC2|Blowfish|RijndaelManaged|des\.NewCipher|rc4\.NewCipher|tripledes\.NewCipher|Cipher\.getInstance\(\s*"AES"\s*\))
```

[P3] RSA padding and undersized keys:
```regex
(RSA_PKCS1_PADDING|PKCS1Padding|EncryptPKCS1v15|OPENSSL_PKCS1_PADDING|rsa\.EncryptPKCS1v15|modulusLength\s*:\s*(512|768|1024|1536)|\.initialize\(\s*(512|768|1024|1536)\s*[,)]|rsa\.GenerateKey\([^)]*,\s*(512|1024)|(secp(112|128|160|192)r1|prime192v1|brainpoolP(160|192)r1))
```

[P4] IV/nonce misuse and predictable seeds:
```regex
(?i)(iv\s*[:=]\s*["'][A-Za-z0-9+/=]{8,}["']|new\s+IvParameterSpec\([^)]*getBytes|nonce\s*[:=]\s*["'][A-Za-z0-9+/=]{4,}["']|setSeed\s*\(|random\.seed\s*\(|new\s+Random\s*\(\s*[0-9L]+\s*\)|srand\s*\(|seedrandom)
```

[P5] GCM tag truncation (anything below 128 bits):
```regex
GCMParameterSpec\(\s*(8|12|16|24|32|48|64|96)\s*,
```

[P6] Insecure randomness for security values:
```regex
(Math\.random\s*\(\s*\)|mt_rand\s*\(|\brand\s*\(\s*\)|random\.choice\s*\(|random\.randint\s*\(|random\.random\s*\(\s*\)|uuid1\s*\(|UUID1|time\.time\s*\(\s*\)\s*[%+^]|Time\.now\.to_i\s*[%+^])
```

[P7] TLS verification disabled or overridden:
```regex
(?i)(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|verify\s*=\s*False|ssl_verify\s*=\s*false|verify_peer\s*=>\s*false|allow_self_signed\s*=>\s*true|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFY(Peer|peer|HOST|host)\s*,\s*0|VERIFY_NONE|CERT_NONE|ssl\s*=\s*False|TrustAll|trustAllCerts|X509TrustManager|checkServerIdentity\s*:|HostnameVerifier|setDefaultSSLSocketFactory)
```

[P8] Dead TLS versions / export suites pinned in config or code:
```regex
(?i)(ssl_protocols\s+[^;]*TLSv1(\.0|\.1)?[\s;]|sslEnabledProtocols\s*=\s*"[^"]*TLSv1(\.0|\.1|")|SslProtocols\.(Tls\b|Tls11\b|None\b)|ssl_version\s*=\s*ssl\.PROTOCOL_TLSv1|minVersion\s*:\s*['"]TLSv1(\.0|\.1)?['"]|MaxVersion\s*=\s*['"]TLSv1\.1['"]|SECLEVEL\s*=\s*0|CipherSuite.*(EXPORT|RC4|3DES|NULL)|SSLCipherSuite.*(EXP-|RC4|3DES|aNULL))
```

[P9] Password storage weaknesses:
```regex
(?i)(md5\s*\(\s*\$(POST|REQUEST|GET)?\[?["']?password|sha1\s*\(\s*\$(POST|REQUEST|GET)?\[?["']?password|hashlib\.(md5|sha1|sha256|sha512)\s*\(\s*password|crypt\s*\(\s*\$password\s*,|cost\s*[:=]\s*([0-9]|1[0-2])\b|rounds\s*[:=]\s*\d{1,3}\b|iterations\s*[:=]\s*[0-9]{1,6}\b|DEFAULT_COST|PASSWORD_BCRYPT\s*\)|hashpw\([^)]*gen_salt)
```
Note: P9's `iterations` clause flags any literal — adjudicate against the decision-table floors rather than treating every hit as a defect.

[P10] Non-constant-time comparisons of crypto outputs:
```regex
(?i)((hash|digest|mac|sig|signature|tag)[A-Za-z_]*\s*={2,3}\s*[A-Za-z_$[]|[A-Za-z_$[]+\s*={2,3}\s*(expected[A-Z]|calculated[A-Z]|computed[A-Z]|providedSig|signature)|strcmp\s*\(|Arrays\.equals\s*\([^)]*(hash|sig|mac))
```

[P11] JWT/JWE misconfiguration:
```regex
(?i)(algorithm\s*[:=]\s*["']none["']|algorithms\s*:\s*\[\s*["']none["']|allowNone|jwt\.decode\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*[,)]|RSA1_5|"alg"\s*:\s*"none")
```

[P12] Encoding-as-encryption and hardcoded key usage:
```regex
(?i)(str_rot13\s*\(|xor_(cipher|encrypt|decrypt)|base64_(encode|b64encode)\s*\(\s*(serialize\s*\()?\$|btoa\s*\(\s*JSON\.stringify|xxtea|(aes|hmac|secret|private|public)_?[Kk]ey\s*[:=]\s*["'][A-Za-z0-9+/]{16,}={0,2}["']|PEPPER\s*[:=]\s*["'][^"']{6,}["'])
```

[P13] Webhook signature surfaces (presence scan; then audit each handler against the checklist):
```regex
(?i)(x-hub-signature(-256)?|stripe-signature|x-slack-signature|x-signature|x-webhook-signature|svix-signature|hmac\.hexdigest|hash_hmac\s*\()
```

[P14] Key material leaking into logs/errors:
```regex
(?i)(log(ger)?\.(debug|info|warn|warning|error|fatal)\s*\([^)]*(key|secret|iv|nonce|salt|passphrase)|fmt\.Errorf\([^)]*key|console\.(log|error)\s*\([^)]*(key|secret)|throw new \w+Exception\([^)]*(key|secret)))
```

### Dangerous Call Reference

| Language/Library | Dangerous call | Why | Safe replacement |
|---|---|---|---|
| Node `crypto` | `createHash('md5'/'sha1')` | Collision-broken digests | `createHash('sha256')`; HMAC where authenticity needed |
| Node `crypto` | `createCipher/createDecipher` (password form) | EVP_BytesToKey(MD5), no salt work, no auth | `createCipheriv('aes-256-gcm')`; `scryptSync` for passphrase-derived keys |
| Node `crypto` | `createCipheriv('des-*'/'des3'/'rc4'/*-ecb)` | Broken/legacy/deterministic | `'aes-256-gcm'`, `'chacha20-poly1305'` |
| Node `https` | `{ rejectUnauthorized: false }` | Any MITM cert accepted | default agent; `NODE_EXTRA_CA_CERTS` for private CAs |
| WebCrypto | raw AES-CBC without MAC layer | Malleable ciphertext | `AES-GCM` via `subtle.encrypt` |
| crypto-js | `AES.encrypt(msg, 'passphrase')` | 1-iteration EVP KDF + CBC, no tag | node:crypto/WebCrypto AEAD |
| Python `hashlib` | `md5(pw)`, `sha1(pw)` | Fast, unsalted, broken | `argon2.PasswordHasher().hash(pw)` |
| pycryptodome | `AES.new(k, AES.MODE_ECB/MODE_CBC)` | ECB leaks equality; CBC malleable | `AES.new(k, AES.MODE_GCM, nonce=os.urandom(12))` |
| pycryptodome | `PBKDF2(pw, salt)` (default `count=1000`) | Trivially brute-forceable | `count>=600000` or `argon2.low_level.hash_secret_raw` |
| `cryptography` | `TripleDES`, `ARC4`, `modes.ECB()` | Deprecated/broken | `AESGCM(key)`, `ChaCha20Poly1305(key)` |
| Java `javax.crypto` | `Cipher.getInstance("AES")` | SunJCE default = ECB/PKCS5Padding | `Cipher.getInstance("AES/GCM/NoPadding")` |
| Java | `new SecretKeySpec(password.getBytes(), "AES")` | Low-entropy key material | `PBKDF2WithHmacSHA256` (>=600k iters) or HKDF |
| Java `MessageDigest` | `getInstance("MD5"/"SHA-1")` | Broken digests | SHA-256; `Mac.getInstance("HmacSHA256")` for auth |
| Java `SecureRandom` | `setSeed(long)` | Deterministic stream thereafter | never seed; use OS entropy |
| Java TLS | anonymous/all-trusting `X509TrustManager` | Accepts any certificate | system TrustManager or imported corporate truststore |
| C# | `MD5.Create()`, `SHA1.Create()`, `TripleDES.Create()` | Broken/legacy | `SHA256`, `AesGcm` |
| C# | `new Rfc2898DeriveBytes(pw, salt, 1000)` | Iterations far below floor | `Rfc2898DeriveBytes.Pbkdf2(pw,salt,600_000,SHA256,32)` |
| C# | `Aes` CBC without HMAC | Bit-flipping/padding oracle | `new AesGcm(key, TagByteSizes=[16])` |
| PHP | `md5($pw)`, `sha1($pw)`, unsalted `crypt($pw)` | Unsalted fast hash | `password_hash($pw, PASSWORD_DEFAULT)` (bcrypt/argon2id) |
| PHP | `openssl_encrypt($d,'aes-128-ecb',$k,...)` | Deterministic | `openssl_encrypt($d,'aes-256-gcm',$k,OPENSSL_RAW_DATA,$iv,$tag)` |
| PHP | `rand()`/`mt_rand()` for OTPs/tokens | Guessable PRNG | `random_int(min,max)` / `random_bytes(32)` |
| Ruby | `Digest::MD5/SHA1` for tokens | Broken/fast digests | `SecureRandom.urlsafe_base64(32)` |
| Ruby | `OpenSSL::Cipher.new('DES-EDE3-CBC'/'AES-128-ECB')` | Legacy/deterministic | `'aes-256-gcm'` + `cipher.random_iv` |
| Ruby Net::HTTP | `verify_mode = OpenSSL::SSL::VERIFY_NONE` | MITM accepted | `VERIFY_PEER` + `ca_file` |
| Go | `crypto/md5`, `crypto/sha1`, `des.NewCipher`, `rc4.NewCipher` | Broken/legacy | `crypto/sha256`; AES-GCM; `chacha20poly1305` |
| Go | `rsa.EncryptPKCS1v15` | Padding-oracle history | `rsa.EncryptOAEP(sha256.New(), rng, pub, msg, nil)` |
| Go | `math/rand` for tokens/secrets | Seedable/predictable | `crypto/rand.Read(buf)` |

### Command-Line Spot Checks

```bash
# Server protocol posture (staged endpoints only)
openssl s_client -connect host:443 -tls1_1 </dev/null 2>&1 | head -n 5
# Expected if vulnerable: handshake proceeds showing "Protocol : TLSv1.1"; if patched: handshake_failure alert

nmap --script ssl-enum-ciphers -p 443 host | grep -B1 -A3 -E 'TLSv1\.(0|1)'
# Expected if vulnerable: sections listing TLSv1.0/TLSv1.1, possibly EXPORT/RC4/3DES entries

echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -text | grep -E 'Signature Algorithm|Public-Key'
# Expected weak: "sha1WithRSAEncryption" or "Public-Key: (1024 bit)"

# ECB determinism proof requiring no project code
printf '41111111111111114111111111111111' | openssl enc -aes-128-ecb -K 00000000000000000000000000000000 -nosalt | xxd -p
# Expected: first and last 32 hex characters IDENTICAL (equal plaintext blocks -> equal ciphertext blocks)

openssl dgst -sha256 -hmac "$key" artifact.bin   # reference HMAC to compare against app output
```

## Taint Tracing Guidance

### Sources (attacker-influenced inputs entering cryptography)
- HTTP bodies/headers/params consumed as ciphertext, tokens, signatures, IVs, or "encrypted" blobs.
- Database columns holding user-written payloads later decrypted server-side (stored webhook bodies, retry queues).
- Uploaded file bytes feeding digest checks or archive decryption.
- Time (`Date.now()`, `time.time()`) used as nonce, PRNG seed, or signed value.
- Admin-panel-writable configuration selecting algorithms, key versions, or cipher suites.

### Sinks (operations where tainted input becomes exploitable)
- Cipher construction/init: `createCipheriv/createDecipheriv`, `Cipher.getInstance(...).init`, `AES.new`, `openssl_encrypt/decrypt`, `EVP_*Init_ex`, `aes.NewCipher`+`cipher.New*`, `AesGcm`/`AesCbc` — tainted key/IV/nonce/plaintext arguments.
- Digest composition: `createHash`, `MessageDigest.getInstance`, `hashlib.*`, `Digest::*` fed concatenated `secret||data` strings.
- Equality checks receiving attacker-supplied MAC/signature/digest strings.
- Token verifiers propagating the token's own `header.alg` into algorithm options.

### Propagation Rules
1. Resolve dynamic transformation strings at every call site: `"AES/" + mode` from config or request data must be resolved to its final literal before judging safety.
2. Treat crypto wrappers (`CryptoUtil.encrypt`, `lib/crypto.py`, `internal/kms`) as chokepoints: enumerate all callers — one unsafe caller of a safe wrapper is still a finding.
3. Track key provenance backwards from sink to origin: literal -> config/env -> KMS/HSM call; only the last origin is clean.
4. Mark IV/nonce variables and audit every write: CSPRNG at init followed by counter increments per message is still reuse if two writers exist.
5. For signature verification, confirm the hashed bytes are the raw request body variable — a re-serialized object changes byte order and silently voids (or fakes) coverage.
6. Follow cross-process state for nonce uniqueness: counters in Redis, per-pod counters, and restarted jobs each create independent sequences that collide under one key.

## Exploitation & Reproduction

Test only systems you are authorized to assess. Procedures are offline unless a running service is explicitly targeted. Record command output as evidence.

### Procedure 1 — ECB Block Leakage
1. Prove determinism standalone:
```bash
printf '41111111111111114111111111111111' | openssl enc -aes-128-ecb -K 00000000000000000000000000000000 -nosalt | xxd -p
# Expected observable: first 32 and last 32 hex chars IDENTICAL -> equal plaintext blocks visible in ciphertext
```
2. Map to the application: find an encrypted field with repeated structure (repeated account numbers, duplicated role substrings); request the same record twice with one controlled aligned-block change and diff ciphertext blocks.
```python
from Crypto.Cipher import AES
key = bytes(16)
pt = b'41111111111111114111111111111111'          # two identical 16-byte halves
ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
print(ct[:16] == ct[16:32])                        # Expected observable: True
```
3. Static-only fallback: ECB at an encryption site is itself the defect; attach the standalone demo and cite the field/handler.

### Procedure 2 — CBC Bit-Flip on a Trusted Token (worked byte math)
Layout: token = `IV || C1 || C2 || C3` where plaintext is `userid=1007&admin=0&expires=20301231` (36 bytes + PKCS#7 pad to 48).
Byte positions: block0 = offsets 0-15 (`userid=1007&adm`), block1 = offsets 16-31 (`n=0&expires=2030`). Target char `0` of `admin=0` sits at absolute offset 18, i.e. intra-block index `j = 18 - 16 = 2` of P1.
CBC relation: `P1[j] = D(C1)[j] XOR IV[j]`. Therefore `IV'[2] = IV[2] XOR ('0' XOR '1')` flips exactly that character to `1`. Delta = `0x30 ^ 0x31 = 0x01`. Collateral damage is confined to block0 via the shared IV (byte 2 of `userid` garbles), which attackers absorb by registering accounts whose layout tolerates corruption.
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
key = os.urandom(16)
pt = b'userid=1007&admin=0&expires=20301231'
iv = bytearray(os.urandom(16))
ct = AES.new(key, AES.MODE_CBC, bytes(iv)).encrypt(pad(pt, 16))
iv[2] ^= ord('0') ^ ord('1')                       # flip only intra-block byte 2
out = AES.new(key, AES.MODE_CBC, bytes(iv)).decrypt(ct)
print(out[:32])
# Expected observable: b'usdrid=1007&admin=1&expires=2030'  ('0'->'1'; side effect 'e'->'d' in userid)
```
1. Replay the tampered token against the service. Expected if unauthenticated CBC: request processed with `admin=1`.
2. Expected if fixed: rejection with an integrity/MAC error before any field parsing.

### Procedure 3 — Nonce Reuse Keystream Recovery (CTR/GCM)
Reuse under one key gives `C1 XOR C2 = P1 XOR P2`; a guessed message reveals the other. GCM additionally leaks its authentication subkey, enabling universal forgeries (Joux 2006, "Authentication Failures in NIST version of GCM").
```python
from Crypto.Cipher import AES
key, nonce = bytes(range(16)), b'\x00' * 8        # same key AND nonce twice = forbidden
c1 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(b'From: alice\nTo: bob\nAmount: $10')
c2 = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(b'From: mallory\nTo: eve\nAmount: $9999')
x = bytes(a ^ b for a, b in zip(c1, c2))
print(x)                                           # Expected observable: P1^P2 (zeros where texts match)
p2 = bytes(a ^ b for a, b in zip(x, b'From: alice\nTo: bob\nAmount: $10'))
print(p2)                                          # Expected observable: full second plaintext recovered
```
In-app variant: capture two ciphertexts sharing a nonce source (constant IV literal, counter reset across restarts) and run the same XOR offline; crib-drag known headers until printable.

### Procedure 4 — MD5 Collision Existence Proof
`fastcoll` from Marc Stevens' hashclash toolchain (github.com/cr-marcstevens/hashclash) produces MD5 collision pairs quickly.
```bash
fastcoll -o col_a.bin col_b.bin    # Expected observable: writes two ~128-byte files
md5sum col_a.bin col_b.bin         # Expected observable: IDENTICAL digests
sha256sum col_a.bin col_b.bin      # Expected observable: different digests (files truly differ)
```
If MD5 guards artifact/dedup integrity, substitute `col_b` where `col_a` was validated and observe acceptance. Fallback without tooling: argue from collision-pair concept and cite the SHAttered SHA-1 collision (shattered.io) when SHA-1 fingerprints gate trust decisions.

### Procedure 5 — Length Extension on `hash(secret || data)`
For Merkle-Damgard digests (MD5/SHA-1/SHA-256), knowing `data` and its digest lets you compute the digest of `secret||data||glue||appendix` without the secret (glue padding depends on secret length; sweep plausible lengths).
1. Forge with hash_extender (iagox86/hash_extender; adjust flags per its --help):
```bash
hash_extender --data '/download?file=q3.pdf' --append '&admin=1' \
  --signature <hex-digest-from-url> --secret-min 8 --secret-max 40 --format sha256
# Expected observable: forged signature plus extended data string including computed glue padding
```
2. Submit `url?sig=<forged>&data=<extended>`; Expected if vulnerable: privileged action executes. Expected if fixed (HMAC): signature mismatch rejection.

### Procedure 6 — TLS Verification Bypass (config diff + MITM observable)
```diff
--- a/lib/http-client.js
+++ b/lib/http-client.js
-const agent = new https.Agent({ rejectUnauthorized: true });
+const agent = new https.Agent({ rejectUnauthorized: false });
```
```bash
mitmproxy --mode reverse:https://api.prod.internal -p 8443
# Point the vulnerable client base URL at https://localhost:8443 and trigger one authenticated call
# Expected observable in mitmproxy flow view: full request including Authorization: Bearer ... (MITM succeeded)

curl --cacert corp-root.pem https://api.prod.internal/v1/ping
# Expected observable: "certificate verify failed" -> proves the REAL endpoint is fine; only the app accepted the proxy cert
```
Corroborate dead-version pinning: `openssl s_client -connect host:443 -tls1_1 </dev/null` completing the handshake confirms TLSv1.0/1.1 acceptance.

### Procedure 7 — Webhook Missing Signature / Replay Window
```bash
# Absence probe: valid-looking body, NO signature header
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.target.test/hooks/payment \
  -H 'Content-Type: application/json' --data '{"order":"x","paid":true}'
# Expected if vulnerable: 200/2XX -> unauthenticated callback processing

# Replay probe: resend a captured VALID delivery ~72h later
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://api.target.test/hooks/payment \
  -H 'X-Signature: sha256=<captured>' --data-binary @captured_body.json
# Expected if vulnerable: 200 again plus duplicated side effect (second fulfillment email/invoice)
```
Expected if fixed: 401/400 on missing or invalid signature and on timestamps outside the replay window.

### Static-Only Confirmation
When live reproduction is impossible (compiled dependencies, managed KMS), drive the project's own functions from a scratch test: invoke its decrypt/verify entry point with a tampered IV/tag/truncated signature. A returned (rather than thrown) altered plaintext — or a comparison that evaluates truthy on modified input — confirms the finding statically. Log function name, exact input bytes, and observed output in the report.

## Remediation

### Algorithm Decision Table

| Purpose | Recommended primitive | 2024-era minimum params |
|---|---|---|
| Symmetric encryption (default) | AES-256-GCM or ChaCha20-Poly1305 | unique 96-bit nonce per key (random or monotonic-counter); full 128-bit tag; AAD binds key-version/context |
| Symmetric (legacy interop only) | AES-256-CBC + HMAC-SHA-256, encrypt-then-MAC | random 128-bit IV per message; MAC over `version\|\|iv\|\|ct\|\|aad`; constant-time verify |
| Password hashing | Argon2id | m=19456 KiB (19 MiB), t=2, p=1 (raise within latency budget) |
| Password hashing alt | scrypt | N=131072 (2^17), r=8, p=1 |
| Password hashing alt | bcrypt | cost >= 10; 16-byte salt; pre-hash `base64(HMAC-SHA-512(pepper,pw))` for >72-byte inputs |
| Password hashing (FIPS-only) | PBKDF2-HMAC-SHA256 / PBKDF2-HMAC-SHA512 | >= 600,000 / >= 210,000 iterations; >= 16-byte random salt |
| Pepper layer | HMAC-SHA-512 pre-hash before KDF | key >= 256 bits held in secret manager, never beside credential rows |
| KDF (high-entropy inputs) | HKDF-SHA-256 (RFC 5869) | random >= 32-byte salt; distinct `info` label per derived purpose |
| MAC | HMAC-SHA-256 (FIPS 198-1) | key >= 256 bits; dedicated per-purpose key |
| Digital signatures | Ed25519 (RFC 8032) or ECDSA P-256 | deterministic Ed25519 preferred; ECDSA nonces from CSPRNG |
| Asymmetric encryption | RSA-OAEP (RFC 8018 tooling) | modulus >= 2048 (3072 preferred), SHA-256 + MGF1-SHA-256 |
| Random tokens/IDs | OS CSPRNG (sources below) | >= 128 bits per session/reset token; >= 256 bits for long-lived keys |
| Transport security | TLS 1.3 (minimum 1.2) | AEAD suites only; no static-RSA key exchange; disable TLSv1.0/1.1 |

Randomness sources per language: browser/WebCrypto `crypto.getRandomValues`; Node `crypto.randomBytes` / `crypto.randomUUID`; Python `secrets.token_bytes` / `secrets.token_urlsafe`; Java `new SecureRandom()` (never `setSeed`); C# `RandomNumberGenerator.GetBytes/Fill`; PHP `random_bytes` / `random_int`; Ruby `SecureRandom.bytes` / `SecureRandom.urlsafe_base64`; Go `crypto/rand.Read`.

### Before/After — Node.js
```javascript
// VULNERABLE
const key = Buffer.from('s3cr3t-key-1234567890abcdef', 'utf8'); // hardcoded low-entropy key
const iv  = Buffer.alloc(16, 0);                                // fixed zero IV
const c   = crypto.createCipheriv('aes-128-cbc', key, iv);

// FIXED
const key = await kms.getDataKey('orders-v2');                  // 32 bytes, external origin
const nonce = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
const tag = c.getAuthTag();                                     // persist nonce+tag alongside ct
```
```javascript
// VULNERABLE
const token = Math.floor(Math.random() * 1e9).toString();

// FIXED
const token = crypto.randomBytes(32).toString('base64url');     // 256-bit CSPRNG token
```

### Before/After — Python
```python
# VULNERABLE
digest = hashlib.sha256(password.encode()).hexdigest()
ok = digest == row["password_hash"]                 # fast hash + timing-leaky compare

# FIXED
from argon2 import PasswordHasher, exceptions
ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)   # OWASP floor params
try:
    ph.verify(row["password_hash"], password)
except exceptions.VerifyMismatchError:
    abort_login()
if ph.check_needs_rehash(row["password_hash"]):
    db.save_user_field(row.id, "password_hash", ph.hash(password))   # parameter upgrade path
```
```python
# VULNERABLE
ct = AES.new(key, AES.MODE_CBC, b"\x00" * 16).encrypt(pad(data, 16))

# FIXED
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = secrets.token_bytes(12)
blob = nonce + AESGCM(key).encrypt(nonce, data, associated_data=b"orders-v2")
```

### Before/After — Java
```java
// VULNERABLE
Cipher c = Cipher.getInstance("AES");               // SunJCE default = ECB/PKCS5Padding
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(password.getBytes(), "AES"));

// FIXED
byte[] nonce = new byte[12];
new SecureRandom().nextBytes(nonce);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
// key from SecretKeyFactory "PBKDF2WithHmacSHA256" >=600k iterations, or KMS-provided data key
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
```
```java
// VULNERABLE
if (hex(expectedMac).equals(hex(provided))) { grant(); }

// FIXED
if (MessageDigest.isEqual(macBytes, providedBytes)) { grant(); }    // constant-time
```

### Before/After — C#
```csharp
// VULNERABLE
using var md = MD5.Create();
var stored = Convert.ToHexString(md.ComputeHash(Encoding.UTF8.GetBytes(password)));

// FIXED
byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
bool ok = CryptographicOperations.FixedTimeEquals(hash, stored);
```
```csharp
// VULNERABLE
using var des = TripleDES.Create();                 // 64-bit blocks (Sweet32)

// FIXED
using var gcm = new AesGcm(key, 16);                // AES-256-GCM with full 16-byte tag
byte[] nonce = RandomNumberGenerator.GetBytes(12);
```

### Migration Guidance

**Passwords — re-hash on login.** Store PHC strings that self-describe their scheme; upgrade transparently after successful legacy verification:
```python
if row.legacy_scheme == "salted_sha1":
    if hmac.compare_digest(legacy_digest(row.salt, password), row.digest):
        db.save_user_field(row.id, "phc", ph.hash(password))    # transparent Argon2id upgrade
        return login_ok()
```
Track remaining legacy rows weekly; force resets for dormant accounts once the migration window closes.

**Data at rest — re-encrypt queues.** Introduce envelope headers `ENC1.<keyver>.<b64nonce>.<b64ct>.<b64tag>`; producers emit ENC1 only; consumers accept LEGACY+ENC1 during transition; background job re-encrypts oldest-first; drop the LEGACY reader after drain, then revoke old keys in KMS (retain restricted decrypt-only copies for the audit window).

**Token signers — rotate with versions.** Prefix HMAC outputs with a key version (`v2.<mac>`); verify against the matching version's key; retire v1 after expiry of all outstanding tokens.

**TLS verification restore patterns:**
```diff
- agent: new https.Agent({ rejectUnauthorized: false })
+ agent: new https.Agent({})            // defaults secure; private CA: NODE_EXTRA_CA_CERTS=/etc/ssl/corp.pem
```
```diff
- requests.post(url, verify=False)
+ requests.post(url, verify="/etc/ssl/corp-root.pem")
```
```go
- tlsCfg := &tls.Config{InsecureSkipVerify: true}
+ pool, _ := x509.SystemCertPool()
+ pool.AppendCertsFromPEM(corporatePEM)
+ tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
```
JVM: import the corporate root instead of a permissive TrustManager:
`keytool -importcert -alias corp-root -file corp-root.pem -keystore truststore.jks -storepass changeit`

## Verification & Validation

### Behavioral Tests (GIVEN/WHEN/THEN)
1. GIVEN the AEAD helper WHEN encrypting identical plaintext twice THEN nonces differ AND ciphertexts and tags differ (instrument the nonce source to throw on repeat under one key).
2. GIVEN a valid token with one flipped IV/ciphertext byte WHEN decrypted THEN verification fails (`InvalidTag` / `BadPaddingException` / HMAC mismatch) and NO altered plaintext is returned — negative test proving authenticated encryption.
3. GIVEN a webhook delivery with a valid signature but a 6-hour-old timestamp WHEN submitted THEN rejected as replay — negative test for the replay window.
4. GIVEN a JWT signed with `alg:none` (and an HS token presented where RS is pinned) WHEN verified THEN rejected — negative test for algorithm allowlists.
5. GIVEN the client calling through a proxy presenting an untrusted certificate WHEN any internal endpoint is hit THEN the handshake fails — negative test that no `InsecureSkipVerify`-equivalent remains.
6. GIVEN a legacy salted-SHA1 password row WHEN the correct password logs in THEN login succeeds AND the stored verifier now starts with `$argon2id$` AND re-login exercises only Argon2id.
7. GIVEN a hardened TLS endpoint WHEN probed with `-tls1_1` and `ssl-enum-ciphers` THEN old-version handshakes fail and only AEAD suites on TLS1.2+ appear.
8. GIVEN concurrent encryptions under load WHEN all emitted nonces are collected THEN zero duplicates across writers (catches multi-writer counter collisions).

### Regression Gate (CI grep gate pseudocode)
```bash
# .github/workflows/crypto-lint.yml run step (pseudocode)
rg --no-heading -n \
   -f .security/banned-crypto.regex \
   -g '!{vendor,node_modules,dist,.git}/**' \
   > findings.txt || true                        # rg exits 1 when there are no matches

sort -u findings.txt -o findings.txt
comm -23 findings.txt <(sort -u .security/crypto-allowlist.txt) > violations.txt
test ! -s violations.txt || { echo "banned crypto primitives:"; cat violations.txt; exit 1; }
```
Allowlist file `.security/crypto-allowlist.txt` holds exact finding lines with expiry metadata:
```text
# path:line:snippet | expires | owner | ticket
src/legacy/import_md5.py:42:hashlib.md5( | 2027-03-31 | data-migration | SEC-482
```
Every row MUST carry an expiry date and ticket; CI fails rows whose expiry has passed.

### Manual Re-test Checklist
- Re-run P1-P14 from repo root; confirm zero hits outside the allowlist.
- Confirm every encryption call site shows an explicit AEAD transformation, a CSPRNG nonce allocated per message, and a tag that is persisted then verified.
- Confirm the password verifier column contains only PHC strings meeting floor parameters (sample at least 10 rows).
- Confirm no `rejectUnauthorized:false` / `verify=False` / `VERIFY_NONE` remains anywhere, including scripts baked into production images.
- Confirm staging webhook handlers reject missing-signature and stale-timestamp deliveries.
- Confirm key material never reaches application logs (scan a staging-run log snapshot for key prefixes).

### Greps To Re-run Post-fix
```bash
rg -n "(?i)createHash\(['\"](md5|sha1)['\"]\)|hashlib\.(md5|sha1)\(" --glob '!node_modules/**'
rg -n "(?i)MODE_ECB|/ECB/|Cipher\.getInstance\(\s*\"AES\"\s*\)" --glob '!vendor/**'
rg -n "(?i)rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|VERIFY_NONE"
rg -n "Math\.random\s*\(\s*\)|mt_rand\s*\(|random\.choice\s*\(" src/
rg -n "GCMParameterSpec\(\s*(8|12|16|24|32|48|64|96)\s*,"
# Expected observable after remediation: no output, or only unexpired allowlisted rows
```

## Severity Assessment

| CWE | Name | Example finding in this module |
|---|---|---|
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | MD5 signatures; ECB data at rest; RC4 |
| CWE-328 | Use of Weak Hash | SHA-1 fingerprints gating trust decisions |
| CWE-326 | Inadequate Encryption Strength | RSA-1024 keys; short symmetric keys |
| CWE-321 | Use of Hard-coded Cryptographic Key | Embedded AES key protecting live data |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption | Fixed GCM/CTR nonce across messages |
| CWE-329 | Generation of Predictable IV with CBC Mode | Zero IV or IV = key prefix |
| CWE-330 | Use of Insufficiently Random Values | Predictable reset tokens |
| CWE-331 | Insufficient Entropy | Short/guessable HMAC secrets |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | `Math.random()` session IDs |
| CWE-340 | Generation of Predictable Numbers or Identifiers | Sequential OTPs |
| CWE-347 | Improper Verification of Cryptographic Signature | Webhook sig absent or `==`-compared |
| CWE-295 | Improper Certificate Validation | `rejectUnauthorized:false` |
| CWE-297 | Improper Validation of Certificate with Host Mismatch | Overridden hostname verification |
| CWE-354 | Improper Validation of Integrity Check Value | Truncated GCM tags accepted |
| CWE-208 | Observable Timing Discrepancy | `==` over MAC hex strings |
| CWE-759 | Use of a One-Way Hash without a Salt | Unsalted password digests |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt | Username/email as salt |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | PBKDF2 at 1000 iterations; bcrypt cost 4 |

CVSS v3.1 example vectors (base scores derived from the standard formula):
- GCM/CTR nonce reuse exposing credentials: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1 Critical.
- JWT `alg:none` accepted yielding auth bypass: same vector shape = 9.1 Critical.
- Disabled TLS verification on credential-bearing flows (MITM position required): `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 8.1 High (Critical where exposure is internet-reachable).
- `Math.random()` reset tokens: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = 8.3 High.
- Unsalted fast-hash password store (offline cracking after breach): `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` = 7.5 High.
- Below-floor KDF cost such as bcrypt cost 4: `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N` = 5.6 Medium.

Rubric anchors:
- Critical: GCM/CTR nonce reuse on attacker-visible traffic; hardcoded production key guarding remotely readable data; `alg:none` acceptance; unauthenticated-CBC trusted-token tampering with working repro.
- High: disabled TLS verification on auth flows; `Math.random()` security tokens; unsalted fast-hash password storage; absent webhook signature validation; padding-oracle-capable CBC.
- Medium: below-floor password-hash parameters; short HS256 secrets; missing webhook replay window; one-key-for-all-purposes without demonstrated cross-protocol abuse yet.
- Low: display-only SHA-1 fingerprints; base64 obfuscation of non-sensitive values; slightly stale protocol floors; adjacent gaps such as missing HSTS are scored under CONFIG.

## Common False Positives

- MD5/SHA-1 used solely for non-adversarial dedup, cache keys, ETags, or sharding — no attacker payoff; note but do not raise unless outputs gate access.
- Git object hashes, torrent infohashes, and historical artifact manifests using SHA-1 — integrity-of-record contexts; raise only when forgery has a live attack path.
- Dummy keys in test fixtures guarded by build tags or test-only modules that cannot reach production builds.
- `InsecureSkipVerify` inside localhost-only harnesses where an mTLS sidecar actually performs verification — confirm the real transport before raising.
- PBKDF2 iterations below current floor during a documented migration window with re-encrypt-on-read and a near-term expiry ticket.
- bcrypt cost 10 vs 12 debates — 10 meets the OWASP floor; do not flag.
- UUID v4 as a token source is acceptable (122 CSPRNG bits); only UUID v1 is the finding.
- Constant-time compare "missing" on public values (cache-key equality, config lookups) — timing only matters for secret-dependent comparisons.
- `Cipher.getInstance("AES/CBC/PKCS5Padding")` paired with a verified HMAC elsewhere — encrypt-then-MAC CBC is sound; check coverage before flagging.
- RSA PKCS1-v1_5 appearing in *signature* APIs (`RSASSA-PKCS1-v1_5`, JWT RS256) — legacy but not the OAEP encryption defect; score separately.
- `crypto-js` imported but unused for security values (e.g., client-side cache hashing) — verify sink before raising.
- Java `"AES/GCM/NoPadding"` with `GCMParameterSpec(128, ...)` flagged by naive tag-size regexes — 128 is the correct bit-length; P5 targets values below it.

## References

### CWE Entries
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-326: Inadequate Encryption Strength
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-323: Reusing a Nonce, Key Pair in Encryption
- CWE-328: Use of Weak Hash
- CWE-329: Generation of Predictable IV with CBC Mode
- CWE-330: Use of Insufficiently Random Values
- CWE-331: Insufficient Entropy
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
- CWE-340: Generation of Predictable Numbers or Identifiers
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-295: Improper Certificate Validation; CWE-297: Improper Validation of Certificate with Host Mismatch
- CWE-354: Improper Validation of Integrity Check Value
- CWE-208: Observable Timing Discrepancy
- CWE-759: Use of a One-Way Hash without a Salt; CWE-760: ...with a Predictable Salt
- CWE-916: Use of Password Hash With Insufficient Computational Effort

### OWASP Cheat Sheet Series (stable owasp.org URLs)
- Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- Transport Layer Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- TLS Cipher String Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
- OWASP ASVS v4 chapter V6 (Stored Cryptography) and V9 (Communications): https://owasp.org/www-project-application-security-verification-standard/

### NIST Publications (by number and name)
- FIPS 180-4, Secure Hash Standard (SHA-2 family)
- FIPS 197, Advanced Encryption Standard (AES)
- FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC)
- SP 800-38A, Recommendation for Block Cipher Modes of Operation
- SP 800-38D, Recommendation for Block Cipher Modes of Operation: GCM and GMAC
- SP 800-57 Part 1 Rev. 5, Recommendation for Key Management
- SP 800-108 Rev. 1, Recommendation for Key-Derivation Methods Using Pseudorandom Functions (HKDF-style construction guidance context)
- SP 800-132, Recommendation for Password-Based Key Derivation
- SP 800-90A Rev. 1, Recommendation for Random Number Generation Using Deterministic Random Bit Generators
- SP 800-52 Rev. 2, Guidelines for the Selection, Configuration, and Use of TLS Implementations
- SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management (memorized-secret verifier requirements)

### RFCs and Primary Research
- RFC 5869 HKDF; RFC 8018 PKCS #5 v2.1 (PBKDF2/OAEP); RFC 9106 Argon2; RFC 8032 Ed25519; RFC 7518 JSON Web Algorithms (JWA/JWE algorithm registry).
- Joux, "Authentication Failures in NIST Version of GCM" (2006) — nonce-reuse forbidden-attack analysis.
- Stevens et al., "Announcing the first SHA1 collision" (SHAttered, shattered.io); hashclash/fastcoll toolchain (github.com/cr-marcstevens/hashclash).
- hash_extender length-extension tool (github.com/iagox86/hash_extender).

### Cross-referenced Modules
- SECRETS: storage sprawl, committed credentials, `.env` hygiene.
- AUTHN: JWT HS/RS confusion deep dive, session flow logic.
- CONFIG: TLS termination posture, HSTS and security headers, cipher-suite baselines at the edge.
