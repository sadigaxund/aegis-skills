---
name: malicious-code-checks
description: Hunts deliberately malicious constructs — obfuscated payloads, exfil beacons, backdoor routes, install-time implants, and provenance-less vendored blobs — across source trees, dependencies, build scripts, and repo-local automation.
category_slug: MALCODE
cwe: [CWE-506, CWE-507]
owasp: A08:2021 – Software and Data Integrity Failures
---

# MALCODE — Deliberate Malice Detection

> **Adaptation note:** This module reuses the shared playbook skeleton with two deliberate deviations. **Exploitation & Reproduction** is a *tabletop lab exercise*: you construct a throwaway repo containing a fully disclosed, inert canary implant, then practice locating it using this module's own sweep block — dynamic detonation (firecracker/qemu sandboxes, any.run-style services) belongs to a separate dynamic-analysis category and is out of scope here; this module is static-only. **Severity Assessment** is a *trust-impact classification* (how much attacker trust a finding implies), not CVSS scoring; no base scores, vectors, or environmental metrics are computed in this module.

## Scope & Objectives

This module detects code that someone placed with intent to harm — not accidental defects. The difference drives everything below: accidental vulnerabilities look like bugs and hide in plain sight; deliberate malware looks like nothing and works to hide. Scan for concealment as aggressively as for capability.

Threat origins to model before scanning (know where malice comes from so you know which surfaces it touches):

| Origin | Mechanism | Canonical shape |
|---|---|---|
| Compromised dependency | Maintainer account or package hijacked post-publication; payload rides a semver range into every dependent tree | event-stream incident (npm, 2018): card-wallet-stealing payload added inside an unrelated helper package |
| Typosquat / confusion publish | Look-alike package name published fresh; payload runs at first install | misspelled names, swapped hyphens/underscores, scoped-name impersonation |
| Insider backdoor | Employee or contractor plants auth bypass, time bomb, or exfil in first-party code | hidden route keyed on magic header; date-gated logic |
| Build-system implant | Malicious logic in build scripts that execute at compile/package time, outside reviewed source | `build.rs` fetching payloads; MSBuild targets injection |
| Vendored prebuilt blob | Binary checked in without matching source or build recipe; behavior unverifiable by review | `.node`/`.so`/`.wasm` files with no origin |
| Hijacked maintainer release | Valid project, attacker-controlled release step injects differencing artifact | release tarball differing from tagged source |

In scope:

- Obfuscation signature hunting in all text sources (JS/TS, Python, Rust, shell, CI YAML; brief notes for Go/C#/Ruby/PHP).
- Network-indicator hunting in source: hardcoded IPs, webhook/paste-exfil endpoints, DNS-exfil shapes, TLS-verification sabotage adjacent to outbound calls.
- Behavioral red-flag combos: credential harvest paired with egress; clipboard/keyring access where unjustified; scheduled phone-homes; telemetry shipping source contents.
- Backdoor patterns in application code: hidden routes/magic params/header tokens, time bombs, dormant env-flip branches, default-credential fallbacks.
- Repo-local implants: non-sample `.git/hooks`, `.vscode/tasks.json` / `launch.json` / `.idea` command runners, CI-step `curl | sh` inserts.
- Ecosystem install/compile-time execution surfaces: npm lifecycle scripts, Python `setup.py`, Rust `build.rs` and proc-macros.
- Vendored/binary artifacts lacking provenance, including LFS pointer tricks.
- Triage verdict discipline and evidence preservation workflow.

Out of scope (cross-references, no duplication):

- Dynamic execution/detonation of suspects (sandbox selection, network simulation) → dedicated dynamic-analysis category; this module stops at quarantine hand-off.
- Dependency version/vulnerability hygiene, lockfile-drift mechanics, registry-confusion preconditions, CI workflow-injection mechanics → `skills/code/supply-chain/SKILL.md` (SUPPLY). Where this module says "review the postinstall scripts of ALL deps," SUPPLY carries the inventory command.
- TLS/certificate configuration quality itself → CRYPTO module; this module only flags verification-disabled flags sitting next to suspicious egress.
- Leaked credentials as such (a harvested key's storage hygiene) → `skills/code/secrets-data-exposure/SKILL.md`.

Objectives: produce findings with `file:line` evidence; classify each hit Benign-explained / Suspicious-needs-human / Likely-malicious-evidence; preserve any likely-malicious artifact plus hash before removal; never auto-delete.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **IOC (indicator of compromise)**: an artifact hinting at intrusion — an odd domain, an encoded blob, a scheduled call-home
- **obfuscation**: deliberate code-hiding via encoding chains, look-alike names, or minified blobs committed as "source"
- **provenance**: the traceable origin story (author, commit, vendor documentation) explaining why code exists
- **typosquat**: a look-alike package name published to catch misspellings
- **install-script implant**: malicious logic running automatically at package install or build time, outside reviewed source
- **quarantine hand-off**: preserve the artifact plus its hash for specialists instead of deleting it
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Judge malice as a triangle — capability, concealment, purpose:

1. **Capability** — does the construct do something dangerous (execute decoded data, send data out, alter auth decisions)? Dangerous-but-open is often just bad practice.
2. **Concealment** — did the author work to keep you from understanding it? Encoding chains, homoglyph identifiers, minified blobs committed as "source", dormant gates. Concealment is the intent tell; ordinary code has no reason to hide from its own maintainers.
3. **Purpose/provenance** — is there a legitimate explanation traceable to a real requirement, commit author, vendor doc? Absence of provenance converts "odd" into "unaccounted."

Any two legs present ⇒ escalate the verdict class. One leg alone is usually noise (see Common False Positives).

Trust gradient — weight findings by how much trust the location already carries. An implant deep in a transitive dependency installed everywhere outranks one in an example script nobody runs:

```
first-party reviewed source
  > direct dependencies (locked)
    > transitive dependencies (deep chains)
      > install/compile-time hooks (postinstall, setup.py, build.rs)
        > vendored binaries (no source)
          > repo-local automation (.git/hooks, IDE tasks, CI steps)   ← highest leverage, least reviewed
```

Indicator strength rules:

- Single patterns are Weak/Moderate — encoding exists legitimately; IPs appear in tests.
- Combos are Strong: decode→exec, harvest→send, schedule→beacon, clipboard-access→wallet-replace, cert-disable→egress. Hunt pairs, then confirm intent via provenance.
- Attack economics predict placement: install hooks run once per victim machine (cheap, broad); hidden routes persist server-side; time bombs sleep past review cycles; telemetry channels provide ongoing egress cover.

Verdict classes used throughout this module:

| Verdict | Evidence bar |
|---|---|
| Benign-explained | Construct matches a documented legitimate mechanism (vendor feature, fixture, framework idiom) AND provenance checks out |
| Suspicious-needs-human | Capability or concealment present without explanation; reachability unproven; needs a human with repo context |
| Likely-malicious-evidence | Capability + concealment + no legitimate provenance, or harvest/send combo reachable from installed path; preserve-and-remove territory |

## What To Check

Work the list in order; each item cites its fence IDs from Patterns & Signatures.

1. **Hunt obfuscation signatures (F01–F05).** Scan for long base64/hex/unicode literals, decode-then-exec chains (`atob`→`eval`, `base64.b64decode`→`exec`, gzip/zlib chained decodes), charcode arrays, string split/join/reverse assembly, rot13/custom ciphers, and homoglyph identifiers (Cyrillic/Greek codepoints inside otherwise-ASCII files). Treat any packed/encoded blob committed without build provenance as unexplained until decoded offline.
2. **Hunt network indicators in source (F06–F09).** Flag hardcoded raw IPs outside documented/test ranges, webhook-exfil endpoint fragments by name-category (Discord/Telegram/paste sites/request-catchers), DNS-exfil shapes (data-length labels concatenated into subdomains), non-standard ports paired with socket/connect calls, and TLS/cert verification disabled adjacent to outbound calls (cross-ref CRYPTO for config-level treatment).
3. **Score behavioral combos (F10–F14).** Escalate when harvest meets egress: env-var/credential reads plus outbound send in one file; clipboard/history/keyring/browser-store access in packages that have no UI or sync feature; process-injection/debug APIs inside utility libraries; crypto-wallet address patterns near replace/clipboard operations; timer/scheduled jobs that phone home; "telemetry" that uploads source-file contents.
4. **Hunt backdoor logic in application code (F15).** Grep for hidden routes and magic query params/header tokens granting bypass (`req.get('x-debug') === '…'`), time-bombed date gates, dormant branches resurrectable via env/config flip, default-credential fallbacks in auth paths.
5. **Audit repo-local automation (F16–F18).** List non-sample `.git/hooks` and `core.hooksPath`; inspect `.vscode/tasks.json`, `.vscode/launch.json`, `.idea` runners for shell commands; grep CI YAML for mid-pipeline `curl | sh` implants (cross-ref SUPPLY for full workflow-injection mechanics).
6. **Triage ecosystem install/compile-time execution surfaces (F19a–F19c).**
   - npm: review `preinstall`/`install`/`postinstall`/`prepare`/`prepublish(Only)` scripts of ALL dependencies including transitives — SUPPLY module carries the inventory command; on every dependency bump, diff the lockfile and read what actually changed before merging dependabot PRs. Blind merges are how event-stream-class payloads ship.
   - PyPI: `setup.py` executes at install time — audit it like production code. Check wheel-vs-sdist divergence (payload hidden in the sdist only); prefer wheels whose contents you can inspect against sdist.
   - Rust: `build.rs` runs arbitrary code at COMPILE time on every developer machine — audit it like production code. Proc-macros execute too (check `proc-macro = true` in Cargo.toml manifests of deps).
   - One-liners elsewhere — Ruby: gemspec `extensions:` fields compile native code at `gem install`; PHP: Composer `post-package-install` scripts and unpacked `.phar` blobs; both get the same question as npm hooks: why does installing this run code?
   - Go/C# briefly: Go has no install hooks but scan `go:generate` directives and cgo blocks for command exec; NuGet packages can inject `build/*.targets|*.props` MSBuild imports that execute at restore/build — flag third-party packages shipping them without documentation.
7. **Flag vendored/binary artifacts without provenance (F20–F21).** Inventory `.so/.dll/.dylib/.node/.wasm/.pyd/.exe` committed to the tree; require a matching source directory AND a build recipe AND a checksum — absence of all three is itself the finding. Inspect LFS pointers: tiny files with binary extensions whose content is an `version https://git-lfs` pointer deserve a store-side size check (pointer-swapped payload trick). Absence of checksum/provenance verification anywhere binaries enter the tree is a hygiene finding feeding Severity Assessment.
8. **Apply verdict discipline to everything above.** Suspicious ≠ malicious. Classify per the Mental Model table; preserve artifact + SHA-256 before any removal; hand dynamic detonation to the sandbox category.

## Where To Look

| Location | Hunt for | Why attackers choose it |
|---|---|---|
| Dependency manifests + lifecycle script fields (`package.json` at every depth, `setup.py`, `Cargo.toml`, gemspecs, `composer.json`) | Exec-at-install entries, unexpected new deps in patches | Runs once on every victim machine before any review of package internals |
| Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`) | Unexplained resolution changes, integrity-hash rewrites on unchanged versions | Payload swaps ride in under "just a version bump" PRs |
| Deep transitive trees (`node_modules/**`) | The installed path, not just source: minified single-letter blobs, embedded encoded strings | event-stream-class payloads live 3+ levels down where nobody looks |
| First-party rarely-touched files (`utils.*`, `helpers.*`, `compat.*`, `internal/*`) | New obfuscation or network code in low-churn files | Low reviewer attention; small helper deps are cheap compromise vehicles |
| Build scripts (`build.rs`, `Makefile`, `scripts/*`, MSBuild targets) | Command exec, network fetches, writes outside `OUT_DIR` | Executes at compile time on every contributor machine, pre-review |
| Route/controller registries | Routes registered conditionally, magic-param auth checks, debug endpoints | Persistence: server-side backdoor survives client updates |
| Env/config loaders and feature-flag plumbing | Branches gated on exact-value env flips | Dormancy: invisible during normal operation, resurrectable later |
| Auth/middleware chains | Header-token comparisons, default-credential fallbacks, time-gated grants | Single point of total bypass |
| CI definitions (`.github/workflows`, `.gitlab-ci.yml`, etc.) | Mid-pipeline downloads piped to shell, steps added between test and deploy | Secrets-rich context; runs automatically on trusted infra |
| `.git/hooks/` (non-sample) + `core.hooksPath` target dirs | Any executable hook content | Outside version control — invisible in diffs, survives branch switches |
| `.vscode/tasks.json`, `.vscode/launch.json`, `.idea/*` | Shell commands bound to build/run/watch tasks | Auto-executes when devs press build/debug; rarely audited |
| Vendored/binary assets (`vendor/`, `assets/`, `dist/` inputs, LFS pointers) | Blobs without sibling source/build recipe/checksum; pointer-size anomalies | Review-proof: behavior cannot be read, only detonated |
| Telemetry/analytics integrations | Payloads containing file contents, globs over the repo, POSTs to non-vendor endpoints | Provides perpetual legitimate-looking egress channel |

## Patterns & Signatures

All regexes are ripgrep-compatible (Rust regex engine; no lookarounds used anywhere). Weights assume a single indicator in isolation — pair hits per Mental Model before escalating.

| Indicator | Example shape | grep | Verdict weight |
|---|---|---|---|
| Long base64 blob committed as source | `const s='TWFsbHdhcmU…='` then decode | F01 | Weak alone; Moderate if decoded content unexplained |
| Hex/unicode escape soup | `'\x41\x42…'`, `'\u0041\u0042…'` | F02 | Moderate |
| Decode primitive adjacent to nothing legitimate | `atob(x)`, `Buffer.from(b,'base64')`, `marshal.loads(blob)` | F03 | Moderate alone |
| Exec/spawn sink | `eval(...)`, `Function(...)`, `execSync`, `subprocess.run` | F04 | Weak alone; **decode+sink in same file = Strong** |
| String reassembly | `s.split('').reverse().join('')`, charcode arrays | F05 | Moderate |
| Custom cipher / shift arithmetic | `c%26+13` rot13 loops | F06 | Moderate |
| Homoglyph identifiers | Cyrillic `а` inside ASCII `.js` identifier | F07 | Strong |
| Webhook/paste exfil endpoint by name-category | POST to Discord webhook / Telegram bot API / pastebin raw | F08 | Strong unless vendor-documented telemetry (see FP list) |
| DNS-exfil label shape | `<30-char-label>.<label>.attacker.tld` built from data | F09 | Weak-Moderate |
| Raw IP literal endpoint (+odd port) | `connect('203.0.113.7', 4444)` | F10 | Moderate |
| TLS verification disabled near egress | `rejectUnauthorized:false` next to fetch | F11 | Moderate (config-level → CRYPTO cross-ref) |
| Credential/env harvest naming | `process.env.AWS_SECRET_ACCESS_KEY` collected into array | F12 | Weak alone; **harvest+send same file = Critical-combo** |
| Clipboard/keyring/browser-store access | `pbpaste`, `keytar`, `Cookies` sqlite read | F13 | Moderate; unjustified context = Strong |
| Wallet string + replace/clipboard op | `bc1…` or `0x[a-f0-9]{40}` near `writeText` | F14 | Strong |
| Scheduled/timer phone-home | `setInterval(()=>fetch(u),60000)` | F15 | Moderate |
| Telemetry shipping source contents | glob repo files → POST body | F16 | Strong |
| Hidden route / magic param / header token | `req.headers.get('x-magic')==='…'` grants bypass | F17 | Strong |
| Time-bombed date gate | `Date.now() >= new Date('2027-01-01')` flips behavior | F18a | Strong when gating destructive/auth logic |
| Dormant env-flip branch | `if(env.X==='exact-value'){…backdoor…}` | F18b | Moderate; exact-match gate = Strong |
| Default-credential fallback in auth path | `password \|\| 'admin123'` | F18c | Moderate; in auth path = Strong |
| npm lifecycle script entries | `"postinstall": "node x.js"` in ANY dep manifest | F19a | Moderate; SUPPLY carries full inventory flow |
| Python install-time exec (`setup.py`) | `subprocess.*`, `os.system`, URL fetch inside setup.py | F19b | Strong |
| Rust compile-time exec (`build.rs`) / proc-macro | `Command::new` inside build.rs | F19c | Strong |
| CI mid-pipeline download-to-shell | `curl … \| sh` between test and deploy steps | F20 | Strong (mechanics → SUPPLY) |
| Provenance-less vendored binary | `foo.node` with no source/recipe/checksum | F21 | Moderate as hygiene; blob in installed path = Strong |
| LFS pointer anomaly | 90-byte `video.mp4` holding git-lfs pointer | F21 | Moderate |

Correlation technique — single-line greps cannot see "decode here, eval there." Intersect file lists instead:

```bash
# Files containing BOTH a decode primitive AND an exec/sink (same-file pairing):
comm -12 <(rg -l -f /tmp/f03.txt 2>/dev/null || rg --files) \
         <(rg -l "$(cat /tmp/f04.txt)" )
# Practical form:
comm -12 <(rg -l "(atob\s*\(|base64\.(b64)decode|marshal\.loads)") <(rg -l "\b(eval\s*\(|exec(Sync)?\s*\(|subprocess\.(run|call))")
```

### Fence library

**F01 — base64 blob length heuristic** (40+ chars of base64 alphabet; tune length down for small repos, up to cut noise):

```regex
[A-Za-z0-9+/=]{40,}
```

**F02 — hex/unicode escape soup:**

```regex
(\\x[0-9a-fA-F]{2}){12,}
```

```regex
(\\u[0-9a-fA-F]{4}){8,}
```

**F03 — decode primitives** (single-line only; use the comm technique above for cross-line chains):

```regex
(atob\s*\(|Buffer\.from\([^)]{0,80}['"]base64['"]|base64\.(b64|urlsafe_b64|standard_b64)decode|decodeURIComponent\s*\(|marshal\.loads\s*\(|zlib\.decompress\s*\(|gzip\.decompress\s*\(|gunzipSync\s*\(|inflateSync\s*\(|pako\.inflate\s*\()
```

Chained-decode ladder (gzip+zlib+base64 stacked in one expression is a classic implant shape):

```regex
(zlib\.(decompress|inflate)\s*\(\s*base64\.b64decode|inflateSync\s*\(\s*Buffer\.from\([^)]{0,60}base64|fromCharCode[\s\S]{0,80}atob)
```

**F04 — exec/spawn sinks:**

```regex
\b(eval\s*\(|Function\s*\(|exec(Sync)?\s*\(|spawn(Sync)?\s*\(|os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\(|__import__\s*\(|importlib\.import_module\s*\(|Invoke-Expression|iex\s*\()
```

**F05 — charcode arrays and string-split/reverse/join assembly:**

```regex
(String\.fromCharCode\s*\(\s*[0-9]{2,3}(\s*,\s*[0-9]{2,3}){5,}|\.split\s*\(.{1,3}\)\s*\.\s*(reverse\s*\(\s*\)\s*\.\s*)?join\s*\(|charCodeAt\s*\()
```

**F06 — rot13/custom shift ciphers:**

```regex
(rot13|%26|\bcharCodeAt\s*\([^)]{0,10}\)\s*[-+]%?\s*(13|[0-9]{1,2})\b[^;\n]{0,30}%26)
```

**F07 — homoglyph/confusable codepoints in code files** (`\p{Cyrillic}` is natively supported by ripgrep's default engine; exclude i18n/locale trees where non-Latin text is legitimate). Any hit inside an identifier is an intent signal — Cyrillic `а` (U+0430) vs Latin `a` renders identically:

```regex
[\p{Cyrillic}\p{Greek}]
```

Scope it: `rg -n '[\p{Cyrillic}\p{Greek}]' -g '*.{js,ts,py,rb,go,rs,php,java,c,h,cs,sh,json,yml,yaml,toml}' -g '!*i18n*' -g '!*locale*' -g '!*lang*'`

**F08 — webhook/paste exfil endpoint fragments** (name-category matching, run case-insensitively):

```regex
(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/(raw|api)/|hastebin|hasteb\.in|termbin|transfer\.sh/|file\.io/|webhook\.site/|requestbin|pipedream\.net|ntfy\.sh/|push\.safer\.com|anonfiles|gofile\.io/)
```

**F09 — DNS-exfil shapes:** data-length labels concatenated into subdomains before resolution. High noise; require adjacency to resolver calls:

```regex
([A-Za-z0-9+/=]{16,}\.[A-Za-z0-9-]{1,63}\.){1,3}[a-z]{2,}
```

Pair with: `(dns\.resolve|resolve4?\s*\(|getaddrinfo|dns\.lookup)`.

**F10 — IP-literal endpoints and common beacon ports:**

```regex
\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(:[0-9]{2,5})?\b
```

Filter loopback/broadcast privately (`rg -v '127\.0\.0\.1|0\.0\.0\.0|255\.255'`), then judge remaining hits against company ranges. Port-side pattern (weak, contextual): `\b(1337|31337|4444|5555|9001)\b` adjacent to socket/connect/dial calls.

**F11 — TLS/cert verification disabled near outbound calls** (cross-ref CRYPTO module for config-level findings):

```regex
(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|ssl_verify\s*=\s*(false|none)|CERT_NONE|curl[^;\n]{0,40}\s-K\b)
```

**F12 — credential/env harvest naming** (Weak alone — score only with egress in same file):

```regex
(process\.env\s*[\s\S]{0,120}(KEY|TOKEN|SECRET|PASS|CRED|AWS|GITHUB|NPM_|SLACK)|os\.environ|os\.getenv|System\.getenv|std::env::var)
```

Run case-insensitively; `[\\s\\S]` stays line-local under rg — treat multi-line collection loops via the comm technique against F08/F15/F16.

**F13 — clipboard/keyring/browser-store/history access:**

```regex
(clipboardy|copy-paste|pbpaste|xclip|wl-(copy|paste)|arboard|keytar|keyring|SecretService|\.bash_history|\.zsh_history|Cookies|Login Data|Local State|browser-history)
```

**F14 — crypto-wallet strings near replace/clipboard operations** (wallet regex alone has heavy FP weight from docs/tests):

```regex
(bc1[a-z0-9]{20,}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,33})
```

Combo pass: intersect F14 file list with F13 hits or `replace|swap|writeText|setSelection`.

**F15 — scheduled phone-home** (single-line limit noted honestly; cron-file review covers the rest):

```regex
(setInterval|setTimeout|schedule\.every|tokio::(spawn|interval)|thread::sleep)[^;\n]{0,160}(fetch\s*\(|axios|requests\.(get|post)|urlopen|TcpStream::connect|http[s]?://)
```

Also inventory crontab-like declarations: `(cron|schedule):` in YAML plus any `@app.on_schedule` style decorators present in-framework.

**F16 — telemetry/analytics uploading source contents** (glob-plus-send adjacency):

```regex
(readFileSync|fs\.readFile|Path\(['"][^)]{0,40}(package\.json|\*{1,2}/\*)|walkdir|glob\()[^;\n]{0,160}(post|upload|fetch\s*\(|axios|requests\.post)
```

**F17 — hidden routes / magic params / header-token bypasses:**

```regex
((get|header)s?\s*\(\s*["']x[-_](debug|dev|magic|secret|backdoor|canary|internal)|(query|params|body|headers)\.[A-Za-z_$]*(magic|backdoor|master|godmode)[A-Za-z_$]*\s*===?|===?\s*["'][A-Za-z0-9_-]{20,}["'])
```

Follow every hit to what the branch unlocks — bypass grant vs benign feature flag decides verdict class.

**F18a — time-bombed date gates:**

```regex
(new\s+Date\s*\(\s*["']?20(2[4-9]|3[0-9])|datetime\((20(2[4-9]|3[0-9]))|Date\.now\(\)\s*[<>]=?|time\.time\(\)\s*[<>]=?)
```

**F18b — dormant env/config-flip branches** (gate on exact sentinel values):

```regex
(if\s*\(?\s*(process\.env|os\.environ|env::var|getenv)[^;\n]{0,80}(===?|==)\s*["'][A-Za-z0-9_-]{8,}["'])
```

**F18c — default-credential fallbacks in auth paths:**

```regex
(password|passwd|pwd|secret|token|apikey|api_key)["']?\s*(===?|!=|!==)?\s*(\|\||&&|\?)\s*["'](admin|root|toor|password|123456|changeme|letmein|default|guest)["']
```

**F19a — npm lifecycle script keys in manifests** (grep over all `package.json`; SUPPLY module owns the full dep-wide dump command):

```regex
"(preinstall|install|postinstall|prepare|prepublish|prepublishOnly)"\s*:
```

**F19b — Python install-time exec shapes**, path-scoped to `setup.py`/`setup.cfg`/`pyproject.toml`:

```regex
(os\.(system|popen)|subprocess\.|urllib\.request\.urlopen|requests\.(get|post)|socket\.(socket|create_connection)|eval\s*\(|exec\s*\(|__import__)
```

**F19c — Rust compile-time exec shapes**, path-scoped to `build.rs` plus proc-macro crates:

```regex
(Command::new|process::Command|TcpStream::connect|(ureq|reqwest|minreq)::(get|post)|include_bytes!\(|fs::(write|copy|hard_link))
```

Inventory first (`find . -name build.rs -not -path './target/*'`); treat every hit like production code, not build plumbing.

**F20 — CI download-piped-to-shell** (workflow-injection mechanics live in SUPPLY; this catches the crude implant insert):

```regex
(curl[^|;&]{0,140}\|\s*(sudo\s+)?(ba|z|da)?sh|wget[^|;&]{0,140}&&|Invoke-WebRequest[^|]{0,100}\|\s*iex|iwr\s[^|]{0,100}\|\s*iex)
```

**F21 — vendored binary + LFS pointer inventory** (find, not grep):

```bash
find . -path ./.git -prune -o -type f \( -name '*.so' -o -name '*.dll' -o -name '*.dylib' -o -name '*.node' -o -name '*.wasm' -o -name '*.pyd' -o -name '*.exe' \) -print
# For each: require sibling source dir + build recipe + checksum file; else flag.
# LFS pointer anomalies: tiny files with binary extensions holding pointer text:
find . -path ./.git -prune -o -type f \( -name '*.bin' -o -name '*.dat' -o -name '*.mp4' -o -name '*.psd' \) -size -1k -print | xargs -r grep -l 'version https://git-lfs'
git lfs ls-files 2>/dev/null
```

### Paste-ready read-only sweep block

Highest-yield static pass over a whole tree. Read-only — writes nothing anywhere. Save as `tools/aegis-malcode-sweep.sh`, run at repo root. Installed trees (`node_modules`) are scanned deliberately: the installed path is prime implant territory; SUPPLY owns the deeper dep-wide lifecycle dump.

```bash
#!/usr/bin/env bash
# AEGIS MALCODE static sweep - READ ONLY. Run at repo root; writes nothing.
echo '[1/8] long encoded blobs'
rg -n --hidden -g '!.git/**' -g '!*.lock' '[A-Za-z0-9+/=]{40,}' || true
echo '[2/8] decode primitives'
rg -n "(atob\s*\(|Buffer\.from\([^)]{0,80}['\"]base64['\"]|base64\.(b64|urlsafe_b64)decode|marshal\.loads|zlib\.decompress|gunzipSync|inflateSync)" || true
echo '[3/8] exec/spawn sinks'
rg -n "\b(eval\s*\(|Function\s*\(|exec(Sync)?\s*\(|spawn(Sync)?\s*\(|os\.(system|popen)|subprocess\.(run|call|check_output|Popen)|__import__\s*\()" || true
echo '[4/8] assembly tricks + homoglyphs'
rg -n '(String\.fromCharCode|(\\x[0-9a-fA-F]{2}){12,}|(\\u[0-9a-fA-F]{4}){8,}|\.split\(.{1,3}\)\s*\.\s*(reverse\s*\(\s*\)\s*\.)?join)' || true
rg -n "[\p{Cyrillic}\p{Greek}]" -g '*.{js,ts,py,rb,go,rs,php,java,c,h,cs,sh,json,yml,yaml,toml}' -g '!*i18n*' -g '!*locale*' || true
echo '[5/8] exfil endpoints / TLS-off / raw IPs'
rg -n -i "(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/(raw|api)/|hastebin|termbin|transfer\.sh/|file\.io/|webhook\.site|requestbin|pipedream\.net|ntfy\.sh/)" || true
rg -n -i "(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CERT_NONE)" || true
rg -n "\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(:[0-9]{2,5})?\b" -g '!*.md' | rg -v "127\.0\.0\.1|0\.0\.0\.0|255\.255" || true
echo '[6/8] install/build-time exec surfaces'
find . \( -name package.json \) -not -path './.git/*' | xargs -r grep -HnE '"(pre|post)?(install|prepare|prepack)":' || true
find . \( -name setup.py -o -name build.rs -o -name '*.gemspec' \) -not -path './target/*' | xargs -r grep -HnE "(os\.(system|popen)|subprocess\.|Command::new|process::Command|urlopen|requests\.(get|post)|TcpStream::connect|Net::HTTP)" || true
echo '[7/8] repo-local implants'
ls .git/hooks 2>/dev/null | grep -v '\.sample$' || true; git config --get core.hooksPath 2>/dev/null || true
find .vscode .idea -type f 2>/dev/null || true
find . -path './.git' -prune -o -type f \( -name '*.node' -o -name '*.wasm' -o -name '*.so' -o -name '*.dll' -o -name '*.dylib' \) -print || true
echo '[8/8] backdoor-shaped logic'
rg -n -i "((get|header)s?\s*\(\s*[\"']x[-_](debug|dev|magic|secret|backdoor|canary)|(query|params|body|headers)\.[A-Za-z_$]*(magic|backdoor|master)[A-Za-z_$]*\s*===?)" || true
rg -n "(new\s+Date\s*\(\s*[\"']?20(2[4-9]|3[0-9])|Date\.now\(\)\s*[<>]=?|time\.time\(\)\s*[<>]=?)" || true
rg -n -i "(password|passwd|pwd|secret|token)[\"']?\s*(\|\||&&|\?)\s*[\"'](admin|root|toor|password|123456|changeme|letmein)[\"']" || true
rg -n "curl[^|;&]{0,140}\|\s*(sudo\s+)?(ba|z|da)?sh" || true
echo 'sweep complete - classify every hit against the verdict table before acting.'
```

## Taint Tracing Guidance

Classic dataflow taint tracks runtime user input into sinks. Invert the model for malice: **the repository content itself is attacker-controlled**, so every constant is tainted at authoring time. The open question is never sanitization — it is *reachability* and *intent*.

Work each candidate construct through five steps:

1. **Anchor** — record `file:line`, surrounding commit (author, date, PR context), and which fence fired. A construct introduced by an unrelated third party in a maintenance release outranks one by your own team.
2. **Resolve the payload offline** — decode base64/hex/zlib chains in a throwaway directory (`printf '%s' '<blob>' | base64 -d | xxd | head`). Decode only; never execute decoded content on any machine you care about. If the blob is binary or chained beyond trivial decode, stop and hand to dynamic analysis (sandbox category).
3. **Trace reachability** — does this module actually run?
   - Is it imported from an entry point? Grep import graphs: `rg -n "(require\(|from ['\"])" --glob '*.js' | rg canary-dep` equivalents per language; npm `bin:`/`main:` fields; Python console_scripts; Rust crate roots.
   - Is a hook active (lifecycle script present AND dependency installed)?
   - Is a route registered at boot, or registered conditionally behind a gate (treat env-gated registration as reachable-by-default for suspicion purposes)?
4. **Chain the combo** — for harvest-style hits, find the egress leg in the same module or its imports: intersect F12/F13 file lists with F08/F10/F15/F16. Harvest without egress may still be Suspicious (staging), but combos decide Likely-malicious.
5. **Document the evidence chain** — every verdict must be reproducible from written `file:line` references plus decoded-payload excerpts stored under your evidence directory (hash them). Verdicts without chains are opinions; do not report them as findings.

## Exploitation & Reproduction

Tabletop lab exercise on a throwaway repo you build yourself. The plant below is a fully disclosed, inert canary — its entire malicious capability is `touch /tmp/aegis-canary-hit`, chosen so "success" is observable and harmless. Never plant anything beyond this scope; never commit plants to real repos; delete the lab when done.

### Phase 0 — ground rules

- Lab lives entirely under `/tmp/malcode-lab`; nothing touches network or real credentials.
- The canary demonstrates detection, not offense. Every plant below is annotated in-file as inert training material.

### Phase 1 — construct the lab

```bash
rm -rf /tmp/malcode-lab && mkdir -p /tmp/malcode-lab/lab-app/node_modules/canary-dep /tmp/malcode-lab/lab-app/routes
cd /tmp/malcode-lab && git init -q
```

Plant 1 — fake dependency whose install hook decodes a base64'd command (inert):

```jsonc
// /tmp/malcode-lab/lab-app/node_modules/canary-dep/package.json
{
  "name": "canary-dep",
  "version": "1.0.0",
  "description": "INERT training implant - lab only, safe to delete",
  "scripts": { "postinstall": "node install-canary.js" }
}
```

```js
// /tmp/malcode-lab/lab-app/node_modules/canary-dep/install-canary.js
// INERT TRAINING CANARY - lab only. Effect: touch /tmp/aegis-canary-hit
const { execSync } = require('child_process');
const blob = 'dG91Y2ggL3RtcC9hZWdpcy1jYW5hcnktaGl0ICMgaW5lcnQgYWVnaXMgbGFiIGNhbmFyeQ==';
const cmd = Buffer.from(blob, 'base64').toString();
execSync(cmd);
```

Plant 2 — demo app with a magic-header auth bypass plus a homoglyph identifier:

```js
// /tmp/malcode-lab/lab-app/routes/admin.js
// INERT training backdoor - lab only.
const express = require('express');
const router = express.Router();
const аdminOverride = 'aegis-canary-magic-token-9f3ab2'; // leading char is CYRILLIC а
router.get('/reports', (req, res) => {
  if (req.get('x-canary-key') === аdminOverride) {
    return res.json({ role: 'admin', note: 'inert canary bypass reached' });
  }
  res.status(404).end();
});
module.exports = router;
```

```js
// /tmp/malcode-lab/lab-app/server.js
const express = require('express');
const app = express();
app.use('/api', require('./routes/admin'));
app.listen(3000);
```

Predict before scanning — which stages should fire: `[1/8]`+`[2/8]`+`[3/8]` on the decode-exec chain, `[6/8]` on the postinstall entry, `[7/8]` quiet (no binaries), `[8/8]` on the magic header, `[4/8]` homoglyph pass on the Cyrillic identifier, time-bomb stage quiet (no future dates — a deliberate negative control).

### Phase 2 — run this module's sweep against the lab

Run the paste-ready sweep block (end of Patterns & Signatures) saved as `tools/aegis-malcode-sweep.sh` at `/tmp/malcode-lab`. Note the sweep intentionally scans installed trees (`node_modules`) — the installed path is exactly where dep implants live; only `.git` and lockfiles are excluded.

Expected output (trimmed to representative lines):

```text
[1/8] long encoded blobs
lab-app/node_modules/canary-dep/install-canary.js:3:const blob = 'dG91Y2ggL3RtcC9hZWdpcy1jYW5hcnktaGl0ICMgaW5lcnQgYWVnaXMgbGFiIGNhbmFyeQ==';
[2/8] decode primitives ...
lab-app/node_modules/canary-dep/install-canary.js:4:const cmd = Buffer.from(blob, 'base64').toString();
[3/8] exec/spawn sinks
lab-app/node_modules/canary-dep/install-canary.js:5:execSync(cmd);
[4/8] assembly tricks + homoglyphs
lab-app/routes/admin.js:4:const аdminOverride = 'aegis-canary-magic-token-9f3ab2'; // leading char is CYRILLIC а
lab-app/routes/admin.js:6:  if (req.get('x-canary-key') === аdminOverride) {
[6/8] install/build exec surfaces
./lab-app/node_modules/canary-dep/package.json:5:  "scripts": { "postinstall": "node install-canary.js" }
[8/8] backdoor-shaped logic
lab-app/routes/admin.js:6:  if (req.get('x-canary-key') === аdminOverride) {
```

Every planted indicator was caught by the same static sweeps you would run on a real target. Score them per Patterns & Signatures weights: decode→exec chain in an installed dependency = Strong; postinstall entry = Moderate pending SUPPLY-flow review; magic-header bypass = Strong; homoglyph identifier = Strong. Composite verdict for the canary dep: Likely-malicious-evidence — which is correct behavior for the classifier even though the artifact is inert, proving triage runs on evidence, not impact knowledge.

### Phase 3 — tabletop narrative

Replay the event-stream shape: a popular utility gains a new transitive helper; weeks later that helper ships an update adding an obfuscated install step targeting wallet data. Walk the timeline through this module: lockfile diff discipline catches the new helper at bump-review (SUPPLY flow); had it landed, `[1/8]`–`[3/8]` flag the decode-exec chain inside the installed tree; `[6/8]` surfaces the lifecycle entry; verdict lands Likely-malicious-evidence; Remediation ladder executes (pin, preserve, rotate, rebuild). Debrief question for the table: which single control would have caught it earliest?

### Phase 4 — teardown

```bash
cd / && rm -rf /tmp/malcode-lab /tmp/aegis-canary-hit
```

Confirm removal, then record the drill (date, operator, stages fired) in your verification log — see Verification & Validation VV4.

Vetting gate for NEW dependencies before they enter the tree: OpenSSF Scorecard for maintainer/Build-provenance risk signals, Socket-style behavioral scanners for install-time and runtime anomalies, plus the SUPPLY module's lockfile-diff review. A dependency with no scorecard data AND install scripts AND recent maintainer change is a quarantine-and-review, not a routine add.

## Remediation

### Response ladder per verdict class

| Verdict | Immediate action | Follow-through |
|---|---|---|
| Benign-explained | Document the legitimate mechanism with references in the finding ticket | Add a negative-test allowlist entry (VV2) so future sweeps do not re-flag |
| Suspicious-needs-human | Open a security issue with evidence chain; pin the suspect dependency at its current known-good version if it is a dep; freeze release of affected artifacts pending human review | Assign a reviewer with repo context; deadline-bound; if unresolved, treat as Likely-malicious |
| Likely-malicious-evidence | Quarantine: create an incident branch, stop deploys of affected artifacts, preserve artifact + hash (below), remove the component from manifests/tree on a fix branch | Rotate credentials plausibly exposed on every machine where the component was installed/built (CI secrets, npm/pypi tokens, cloud keys, git creds); invalidate sessions; audit egress logs for beacon indicators from F08/F10; rebuild all artifacts from a verified-clean baseline; report to the registry/vendor; notify downstream consumers |

Evidence preservation before any removal — never auto-delete silently:

```bash
sha256sum <suspect-file> > /tmp/evidence/sha256.txt
cp --parents <suspect-file> /tmp/evidence/          # plus its package.json/manifest context
git bundle create /tmp/evidence/repo-state.bundle --all   # full-repo snapshot incl refs
tar czf /tmp/evidence/node_modules-suspect.tgz node_modules/<suspect-pkg>
```

Escalation coupling: any Critical-class finding (per Severity Assessment) triggers the credential-rotation step even if you cannot prove exploitation — assume-installed is the safe posture for harvest+exfil payloads.

### Prevention set

1. **Lockfile diff review rule** — every dependency-bump PR (including dependabot) gets its lockfile diff read by a human before merge; no rubber-stamp merges. New transitive packages are named and justified in the PR body.
2. **Install-script allowlist** — enforce an explicit allowlist of packages permitted to run install lifecycle scripts; everything else installs with scripts blocked. Adopt a policy tooling layer (e.g., LavaMoat's allow-scripts approach or registry-level policy); SUPPLY module covers the enforcement mechanics.
3. **Deny-git-hook-commits policy** — CI rejects trees shipping executable hook content outside samples and rejects non-empty `core.hooksPath` pointing inside the repo; developer machines get periodic `.git/hooks` audits since hooks live outside version control.
4. **Provenance attestation adoption** — require signed provenance attestations for release artifacts as capability matures (in-toto/SLSA/sigstore foundations; adoption path and verification commands → SUPPLY module).
5. **Vendored-binary gate** — no `.so/.dll/.node/.wasm` enters the tree without sibling source + build recipe + checksum; violations block merge.
6. **Sweep regression gate** — this module's sweep block runs in CI failing on new unexplained hits (VV3), making malice-introduction a visible diff rather than a silent ride-along.

## Verification & Validation

- **VV1 — re-run expecting clean.** After remediation, re-run the full sweep block against the fixed tree. Expect zero hits except entries present in the documented allowlist (VV2). Any residual unexplained hit means the remediation branch is not done.
- **VV2 — negative tests with documented reasons.** Legitimate heavily-encoded assets (embedded test fixtures, compiled-in data blobs) will trip F01/F02 forever unless baselined. Maintain `docs/security/malcode-baseline.txt`: one exact match line per accepted hit, sorted (`LC_ALL=C sort`), each mirrored by an entry in `docs/security/malcode-baseline.md` recording artifact path, reason, approver, review date. An undocumented allowlist entry is itself a finding.
- **VV3 — regression gate.** CI job running the sweep and failing on hits absent from the baseline:

  ```yaml
  - name: MALCODE static sweep (regression gate)
    run: |
      bash tools/aegis-malcode-sweep.sh > /tmp/hits.raw || true
      LC_ALL=C sort -u <(grep -v '^\[' /tmp/hits.raw) > /tmp/hits.sorted
      comm -13 docs/security/malcode-baseline.txt /tmp/hits.sorted | tee /tmp/new-hits.txt
      test ! -s /tmp/new-hits.txt || { echo 'New MALCODE hits need triage'; exit 1; }
  ```

  Keep the sweep script itself under review like any build tool — it executes greps, not payload logic, but a tampered sweep would blind the gate (apply VV to the sweep repo too).
- **VV4 — detector canary drill.** Quarterly (or at onboarding), rebuild the Phase-1 lab plant from Exploitation & Reproduction and confirm every predicted stage fires exactly as listed in Phase 2 expected output. A silent stage means the fence rotted (regex drift, rg version change) — repair before trusting negative results anywhere.
- **VV5 — false-positive budget check.** Sample ten Benign-explained allowlist entries per quarter and re-validate their documented reasons still hold (vendor moved endpoint? fixture deleted?). Stale allowlist entries erode the signal for everyone.

## Severity Assessment

**CVSS is not applied in this module.** Malice findings are classified by trust impact — how much attacker trust the evidence implies — using the table below. Reachability comes from Taint Tracing step 3; "installed path" means imported/executed on victim machines or developer machines at install/build time.

| Class | Trigger criteria | Typical examples | Required response |
|---|---|---|---|
| Critical | Credential-harvest plus exfil confirmed and reachable in a production dependency path; or auth-bypass backdoor reachable on a deployed service | Harvest+send combo (F12+F08) in an installed dep's boot path; hidden route granting admin on prod app | Full Likely-malicious ladder incl. mandatory credential rotation |
| High | Obfuscated network beacon in an installed/imported path; decode-exec chain behind an active lifecycle hook; compile-time exec in `build.rs` of a used crate | F03+F04 pair inside `node_modules` entry-reachable module; postinstall decoding commands | Quarantine, preserve, remove, rotate-if-installed, rebuild |
| Medium | Suspicious-unexplained constructs not proven reachable, or concealment without demonstrated capability | Long encoded blob never decoded by any code path; dormant env-flip branch with no payload attached; homoglyph identifier with benign body | Human review deadline; pin/suppress via allowlist after explanation |
| Low | Hygiene gaps that enable rather than constitute malice | Vendored binary missing checksum/provenance; non-sample git hook present but reviewed; LFS pointers unverified | Backlog ticket; fold into prevention-set adoption |

Classification notes:

- Escalate one class when the same implant pattern appears in more than one location (persistence intent).
- A Medium construct inside an install hook escalates to High automatically — hooks are executed paths by definition.
- Verdict class and severity class are orthogonal axes: verdict says *what it is*, severity says *how much trust it abused*. Report both.

## Common False Positives

Scope discipline kills most noise before triage: run source-dir scans against authored code (`src/`, `lib/`, `app/`, package roots), exclude `dist/`, `build/`, bundles, and generated trees from obfuscation fences — heavy minification there is expected, and its absence would be the anomaly.

1. **Legitimate obfuscation in commercial dependencies** — license-key validation, anti-tamper checks, DRM-ish encoding. Shape overlaps F01–F05. Resolution: vendor documentation plus consistent vendor identity across commits; classify Benign-explained with doc link.
2. **Minified dist/bundle artifacts treated as source** — single-letter variables, packed strings. Resolution: exclude dist globs from F01–F05; if a repo commits minified files as its only "source" for a component, that is itself a provenance flag (F21 territory), not a false positive.
3. **Test fixtures with fake webhooks/mock endpoints** — fixture JSON containing Discord/paste URLs for egress tests, security regression suites replaying exfil shapes. Resolution: allowlist under VV2 with test-file path recorded.
4. **Security tooling doing encoded payloads — including this playbook's own cheat-sheets** — SAST rule engines, canary drills, YARA-style signature repos all contain literal malicious shapes. Resolution: exclude security-tooling directories from sweeps; expect self-matches when sweeping this repository family and baseline them deliberately.
5. **CDN/telemetry SDKs phoning known-vendor endpoints** — analytics beacons to documented vendor domains look like F15/F16 adjacency. Resolution: check endpoint against the SDK's published documentation and pinned vendor list; unknown destination inside a known telemetry SDK is NOT a false positive — escalate.
6. **i18n/locale content tripping homoglyph scans** — legitimate Cyrillic/Greek prose in translation files. Resolution: the `-g '!*i18n*' -g '!*locale*' -g '!*lang*'` scoping in F07; hits inside string literals of UI text vs identifiers decide verdicts.
7. **Framework-generated magic params** — CSRF tokens, state params, idempotency keys compared as long literals trip parts of F17. Resolution: follow what the branch unlocks; grant-of-privilege decides, presence alone does not.

## References

- CWE-506: Embedded Malicious Code — <https://cwe.mitre.org/data/definitions/506.html>
- CWE-507: Trojan Horse — <https://cwe.mitre.org/data/definitions/507.html>
- OWASP Top 10 2021 A08: Software and Data Integrity Failures — <https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/>
- OWASP Cheat Sheet Series: Third Party JavaScript Management — <https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html>
- event-stream incident maintainer disclosure thread (canonical primary account) — <https://github.com/event-stream/event-stream/issues/116>
- Unicode Technical Report #39: Unicode Security Mechanisms (confusable/homoglyph foundations) — <https://www.unicode.org/reports/tr39/>
- SLSA: supply-chain integrity levels framework — <https://slsa.dev>
- in-toto: software supply-chain attestation framework — <https://in-toto.io>
- Sigstore: artifact signing and verification — <https://www.sigstore.dev/>
- Cargo Book: Build Scripts (audit target, not boilerplate) — <https://doc.rust-lang.org/cargo/reference/build-scripts.html>

Cross-module companions: dependency inventory, lockfile-diff mechanics, workflow injection, provenance verification → `skills/code/supply-chain/SKILL.md` (SUPPLY); TLS configuration quality → CRYPTO module; leaked-credential storage hygiene → `skills/code/secrets-data-exposure/SKILL.md`.





