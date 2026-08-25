---
name: secrets-data-exposure-checks
description: Detects hardcoded credentials, secrets leaked into VCS history and build artifacts, runtime information disclosure, PII over-exposure in APIs and logs, and cleartext sensitive data at rest.
category_slug: SECRETS
cwe: [CWE-798, CWE-259, CWE-321, CWE-200, CWE-209, CWE-532, CWE-540, CWE-615, CWE-538, CWE-359, CWE-312, CWE-313, CWE-489, CWE-522]
owasp: A02:2021 – Cryptographic Failures
---

## Scope & Objectives

- Scan the full repository surface: source, configs, tests, fixtures, docs, scripts, CI definitions, container/mobile manifests.
- Trace VCS history (`git`), build output (`dist/`, `build/`, source maps), editor/backup leftovers, debug dumps, committed data files (CSV/SQL dumps).
- Inspect runtime configuration for information-disclosure switches: debug modes, actuator/debug endpoints, GraphQL introspection, directory listings, deployed `.git`, published source maps.
- Inspect API responses and logging paths for over-exposed fields, secrets, and PII; inspect storage patterns for cleartext sensitive data.
- Objectives: produce findings with `file:line` evidence, classify each via the severity rubric, mark every uncertain item `Needs-Review`. Never exfiltrate or bulk-download live data during validation; validate minimally per Exploitation & Reproduction.

## Mental Model

Secrets leak by hopping trust boundaries. Each hop widens the audience permanently:

| Stage | Exposure surface | Typical artifact |
|---|---|---|
| Created | literal next to code | `.env`, `settings.py`, `application.yml` |
| Committed | VCS history retains every prior blob | any past revision, forks, clones |
| Built | value compiled into shippable output | `dist/*.js`, `*.js.map`, APK/IPA payloads |
| Deployed | runtime endpoints echo internals | stack traces, `/actuator/env`, `/debug/vars` |
| Observed | logs become a long-retention database | request bodies/headers in logs, crash reports |
| Exported | bulk data leaves the app boundary | CSV exports, DB dumps, backups |

Operating principles:

1. Every secret ever pushed is compromised until rotated. History rewrite alone does not un-leak it.
2. Base64/hex are encodings, not encryption. Kubernetes `kind: Secret` manifests store base64 plaintext.
3. Client-shipped equals public: any key inside a browser bundle or mobile package must be treated as disclosed.
4. Entropy triage separates machine-generated values from human words, but low-entropy real passwords exist. Entropy is a signal, never a verdict.
5. When unsure, flag `Needs-Review`. Silent drops are the primary failure mode for a scanning agent.

## What To Check

### Hardcoded Credentials In Source

- Scan all provider fingerprints listed in Patterns & Signatures across tracked files.
- Flag framework master keys as Critical-adjacent: Django `SECRET_KEY`, Rails `RAILS_MASTER_KEY` or committed `config/master.key` (misuse that defeats `credentials.yml.enc`), Laravel `APP_KEY=base64:...`, JWT HS256 signing literals.
- Grep credential-bearing variable names assigned literals: `(?i)(api[_-]?key|apikey|secret|token|passwd|password|pwd)\s*[:=]\s*['"][^'"]{8,}['"]`.
- Determine reachability: does the literal feed runtime code or only test scaffolding? Note either way in the finding.
- Check well-known config paths: `config/*.yml`, `*/settings*.py`, `application*.{yml,properties}`, `appsettings*.json`, `web.config`, `wp-config.php`, `local_settings.py`, `config/database.yml`.

### Committed Secret Files

- Flag any tracked file matching: `.env*` (non-example), `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`, `*.jks`, `*service-account*.json`, `*credentials*.json`, `client-secret*.json`, `kubeconfig`, `**/.kube/config`.
- Flag Terraform state and variables: `terraform.tfstate*` (state stores resolved resource attributes), `*.tfvars` containing `password = "..."`, backend blocks with embedded credentials.
- Inspect `docker-compose*.yml`: plaintext entries under `environment:` such as `- DB_PASSWORD=hunter2`; if `env_file:` is used, verify the target file is not itself committed.
- Verify every committed `.env.example` contains placeholders only, never real values.

### History, Artifacts, And Forgotten Copies

- Scan git history for fingerprints using the exact commands in the ready-to-run block below (`git rev-list --all | xargs ... git grep`, `git log --all -G`).
- Scan build output: `dist/`, `build/`, `.next/`, `.nuxt/`, `public/assets`, `*.min.js` — build-time-injected keys land here.
- Scan leftover copies: `*.bak`, `*.old`, `*.orig`, `*~`, `*.swp`, `*.swo`, especially siblings of config files.
- Scan debug dumps: `*.log`, `*.har`, heap dumps, committed coverage HTML, `debug/` folders.
- Compare fixtures/sample data against production-shaped values: `fixtures/`, `db/seeds.rb`, `seeders/`, `testdata/` holding real-looking emails, phone numbers, tokens.
- Grep test suites for live-service markers: `sk_live_`, real AWS account IDs, internal staging hostnames under `test/**`.
- Search comments for pasted credentials near ticket references: `(?i)(jira|ticket|issue)[- _]?\d+.*(key|token|password)`.
- Detect obfuscation-only hiding: base64/hex literals beside decoders, split-string concatenation rebuilding keys, fallbacks like `process.env.API_KEY || "sk_live_..."`.

### Runtime Information Disclosure

- Flag debug switches enabled in production configs: `DEBUG=True` (Django), `NODE_ENV=development`, `APP_DEBUG=true` (Laravel), `app.UseDeveloperExceptionPage()` (ASP.NET), Werkzeug `debug=True` (Flask), Rails `config.consider_all_requests_local = true`, PHP `display_errors=On`.
- Flag exposed management surfaces without auth: Spring Boot `/actuator/env`, `/actuator/configprops`, `/actuator/heapdump`; Go `/debug/vars` (expvar), `/debug/pprof`; legacy .NET `/elmah`.
- Flag GraphQL introspection and tracing (Apollo tracing, query-plan metrics) enabled in prod builds.
- Check client-facing error messages for SQL fragments, absolute paths (`/srv/app/...`, `C:\inetpub\...`), internal hostnames, framework versions.
- Check web server configs for directory listings: nginx `autoindex on;`, Apache `Options Indexes`.
- Check whether deploy scripts copy the whole checkout into the webroot: `GET /.git/HEAD` returning `ref:` confirms an exposed repository.
- Check minified production bundles for `//# sourceMappingURL=` where the `.map` file is also published.

### Response Over-Exposure

- Find serializers lacking field allowlists: Django `fields = '__all__'`, Rails `to_json`/`as_json` without `only:`, Sequelize/Mongoose documents passed straight to `res.json()`, JPA entities serialized directly by Jackson, Go structs marshalling exported PII fields.
- Grep sensitive column names reachable from serializers: `password_hash`, `password_digest`, `encrypted_password`, `otp_secret`, `ssn`, `date_of_birth`, `is_admin`, `api_token`, `internal_notes`.
- Identify endpoints embedding other users' objects in one response without scoping (e.g., order response carrying a different customer's full profile).
- Flag mass-readback: PATCH handlers persisting then echoing `req.body` verbatim.

### Logging And Telemetry Leakage

- Grep log sinks fed whole request objects: `console.log(req.body)`, `logger.info(req.headers)`, `print(request.json)`, `Rails.logger.debug params`, `log.info(payload)` before validation.
- Flag crash reporters capturing PII/locals: Sentry `send_default_pii=True`, breadcrumb passthroughs of Authorization headers.
- Flag analytics events carrying emails, names, or government IDs where a pseudonymous ID suffices.
- Confirm Authorization/Cookie values never reach access logs (custom morgan tokens, Apache `%{Authorization}i`).

### Data At Rest And Backups

- Flag tracked data files with real-shaped PII columns: `*.csv`, `*.xlsx`, `*.sql` whose headers include name/email/national-ID fields with populated rows.
- Automatic Critical: any CVV/cvv2/csc column stored post-authorization — PCI DSS Req 3.3.1 prohibits this outright.
- Flag unmasked PAN-like 13–19 digit sequences in exports; recommend tokenization.
- Inspect backup scripts for world-readable output: `chmod 777`, `umask 000`, dumps written under shared or web-served paths (`mysqldump ... > /var/www/html/backup.sql`).
- Note regulation-sensitive fields lacking `_encrypted` counterparts (SSN, diagnosis codes); mark `Needs-Review` — naming absence is not proof of plaintext.

## Where To Look

| Location | Paths / globs | Why |
|---|---|---|
| Env files | `.env*` (exclude `*.example`) | highest-yield commit type |
| App config | `config/`, `*/settings*.py`, `application*.{yml,properties}`, `appsettings*.json`, `web.config`, `wp-config.php` | framework keys, connection strings |
| Cloud IaC | `*.tf`, `*.tfvars`, `terraform.tfstate*`, `serverless.yml` | state resolves secrets into plaintext |
| Containers | `Dockerfile*`, `docker-compose*.yml`, `.dockerignore` | build args/env bake into layers; missing ignore ships `.env` in images |
| CI | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `.travis.yml` | inline creds, `docker login -p`, uploaded artifacts/logs |
| Mobile | `Info.plist`, `GoogleService-Info.plist`, `AndroidManifest.xml`, `res/values/strings.xml`, `build.gradle(.kts)`, `google-services.json`, `*.xcconfig` | keys shipped inside app packages |
| Build output | `dist/`, `build/`, `.next/`, `.nuxt/`, `public/**/*.min.js`, `*.js.map` | compile-time-injected secrets |
| VCS metadata | `.git/` history and reflog | permanent record of past blobs |
| Data files | `*.sql`, `*.csv`, `*.har`, `fixtures/`, `db/seeds.rb`, `seeders/` | real records reused as sample data |
| Editor debris | `*.bak`, `*.old`, `*~`, `*.swp`, `.idea/`, `.vscode/` | stale copies of secret-bearing files |
| Docs | `README*`, `docs/`, `runbooks/` | onboarding notes often embed real creds |

Mobile-specific checks:

- `strings.xml`: `<string name="api_key">...</string>` ships inside the APK.
- `build.gradle`: `buildConfigField "String", "API_KEY", "\"...\""` compiles into `BuildConfig` bytecode.
- `Info.plist`: top-level entries embedding SDK secrets; `NSAppTransportSecurity` exceptions revealing internal hosts.
- `google-services.json` / `GoogleService-Info.plist`: AIza client keys are expected here — flag only unrestricted keys (no bundle-ID/package restrictions) as `Needs-Review`.

## Patterns & Signatures

### Ready-To-Run Triage Sweep

Paste-run from repo root. Requires `git` and ripgrep. Every step tolerates zero matches.

```bash
#!/usr/bin/env bash
set -uo pipefail

echo "== [1/6] Provider key fingerprints =="
rg -n --hidden -g '!.git' -g '!node_modules' -g '!vendor' \
  -e '(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}' \
  -e 'AIza[0-9A-Za-z_\-]{35}' \
  -e '(sk|rk)_live_[0-9a-zA-Z]{16,}' \
  -e 'gh[pousr]_[A-Za-z0-9]{36}' \
  -e 'github_pat_[A-Za-z0-9_]{60,}' \
  -e 'glpat-[0-9A-Za-z\-=_]{20,22}' \
  -e 'xox[baprs]-[A-Za-z0-9\-]{10,}' \
  -e 'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}' \
  -e 'SK[0-9a-fA-F]{32}' \
  -e 'shp(at|ss|ca)_[a-fA-F0-9]{32}' \
  -e 'sq0(atp|csp)-[0-9A-Za-z_\-]{22,43}' \
  -e 'oy2[a-z0-9]{43}' \
  -e 'npm_[A-Za-z0-9]{36}' \
  -e 'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+' \
  -e 'sk-(proj-)?[A-Za-z0-9_\-]{40,}' || true

echo "== [2/6] Private key material =="
rg -n --hidden -g '!.git' -e '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----' || true

echo "== [3/6] Secret-bearing filenames =="
rg --files --hidden -g '!.git' -g '.env*' -g '!*.example' \
  -g '*.{pem,key,p12,pfx,jks,keystore,ovpn}' -g 'id_rsa*' -g 'id_ed25519*' \
  -g '*service-account*.json' -g '*credentials*.json' -g 'client-secret*.json' \
  -g '*.tfstate*' -g '*.tfvars' -g '**/.kube/config' -g 'kubeconfig' \
  -g 'config/master.key' -g 'credentials.yml.enc' || true

echo "== [4/6] Connection strings / URLs with embedded passwords =="
rg -n --hidden -g '!.git' -g '!node_modules' \
  "(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql|jdbc:[a-z0-9]+)://[^/\s:@'\"]+:[^@\s'\"]+@" || true

echo "== [5/6] Master keys / JWT literals / client-bundle traps =="
rg -n --hidden -g '!.git' \
  -e "(?i)secret_key\s*=\s*['\"][^'\"]{8,}" \
  -e 'APP_KEY=base64:' -e 'RAILS_MASTER_KEY' -e 'credentials\.yml\.enc' \
  -e '(?i)(jwt\.sign|jwt\.encode)[^;\n]{0,80}["'"'"'][A-Za-z0-9+/=]{16,}["'"'"']' \
  -e 'NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|EXPO_PUBLIC_' || true

echo "== [6/6] Git history sweep =="
git rev-list --all | xargs -n1 -I{} git grep -nIE \
  'AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|xoxb-|BEGIN [A-Z ]*PRIVATE KEY|sk_live_' \
  {} -- 2>/dev/null | sort -u | head -n 100 || true
git log --all --oneline -G'AKIA[A-Z0-9]{16}|sk_live_[0-9a-zA-Z]{16,}|BEGIN [A-Z ]*PRIVATE KEY' | head -n 50 || true

echo "== done =="
```

Note: `AKIAIOSFODNN7EXAMPLE` plus its companion secret is AWS's documented example pair; treat vendor-documented sample values as non-findings and record them in the allowlist.

### Provider Fingerprint Table

Regexes below are ripgrep-compatible; copy fenced blocks when alternation pipes would collide with Markdown tables (pipes here are escaped).

| Secret type | Fingerprint regex | Provider | Rotation difficulty |
|---|---|---|---|
| AWS access key ID | `(A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16}` | Amazon Web Services | Hard — IAM cleanup plus CloudTrail review |
| AWS secret access key | `[A-Za-z0-9/+=]{40}` contextual (near `aws_secret_access_key`) | Amazon Web Services | Hard |
| Google API key | `AIza[0-9A-Za-z_\-]{35}` | Google APIs | Easy-Medium — restrict or delete in console |
| GCP OAuth client ID | `[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com` | Google Identity | Medium — reset paired secret |
| Stripe live secret | `(sk\|rk)_live_[0-9a-zA-Z]{16,}` | Stripe | Medium — roll in dashboard; brief break |
| Stripe publishable | `pk_live_[0-9a-zA-Z]{16,}` | Stripe | Public by design; flag misuse only |
| GitHub classic token | `gh[pousr]_[A-Za-z0-9]{36}` | GitHub | Medium — revoke breaks CI/webhooks |
| GitHub fine-grained PAT | `github_pat_[A-Za-z0-9_]{60,}` | GitHub | Medium |
| GitLab PAT | `glpat-[0-9A-Za-z\-=_]{20,22}` | GitLab | Medium |
| Slack token | `xox[baprs]-[A-Za-z0-9\-]{10,}` | Slack | Easy — reinstall app with new token |
| SendGrid API key | `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}` | SendGrid | Easy — high sender-abuse risk while live |
| Twilio API Key SID | `SK[0-9a-fA-F]{32}` (32-hex auth token nearby) | Twilio | Easy |
| Shopify app token | `shp(at\|ss\|ca)_[a-fA-F0-9]{32}` | Shopify | Easy |
| Square token | `sq0(atp\|csp)-[0-9A-Za-z_\-]{22,43}` | Square | Medium |
| npm token | `npm_[A-Za-z0-9]{36}` | npm registry | Medium — publish-rights abuse |
| PyPI token | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+` | PyPI | Medium |
| NuGet API key | `oy2[a-z0-9]{43}` | NuGet | Easy |
| Mailgun key | `key-[0-9a-zA-Z]{32}` | Mailgun | Easy — spoofing risk while live |
| Azure storage conn string | `AccountKey=[A-Za-z0-9+/]{86}==` | Microsoft Azure | Hard — full storage-account access |
| OpenAI API key | `sk-(proj-)?[A-Za-z0-9_\-]{20,}` | OpenAI | Easy — billing-abuse risk |

### Core Regex Groups

```regex
# Private key material. NOTE: BEGIN PUBLIC KEY and *.pub are NOT secrets.
-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----
```

```regex
# Connection strings and scheme URLs carrying credentials
(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql|jdbc:[a-z0-9]+)://[^/\s:@'"]+:[^@\s'"]+@
(?i)(server|data source|host)=.{0,80};(password|pwd)=
```

```regex
# Framework master keys and JWT signing literals
(?i)(secret_key|django_secret_key)\s*=\s*['"][^'"]{8,}['"]
APP_KEY=base64:[A-Za-z0-9+/]{43}=
RAILS_MASTER_KEY|config/master\.key
(?i)(jwt\.sign|jwt\.encode)[^;\n]{0,100}['"][A-Za-z0-9+/=]{12,}['"]
```

```regex
# Generic high-entropy candidates — triage input ONLY, never a verdict
['"][A-Za-z0-9+/]{40,}={0,2}['"]
\b[0-9a-fA-F]{32,64}\b
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.?[A-Za-z0-9_.+/=-]*   # serialized JWT in code/logs
```

```regex
# Obfuscation-only hiding: encoding is not protection
(?i)(atob\(|base64\.b64decode|b64decode\(|Convert\.FromBase64String|Buffer\.from\()['"]?[A-Za-z0-9+/=]{24,}
\b(?:[0-9a-f]{2}){24,}\b
(?i)process\.env\.[A-Z_]+\s*\|\|\s*['"][^'"]{16,}['"]
```

```regex
# Placeholder markers — subtract these before verdicts
(?i)(change_?me|change_?this|placeholder|your[_-]?api[_-]?key|your[_-]?token|dummy|sample[-_]?(key|token)|example[-_]?(key|token)|xxxxx+|not[_-]?real|\$\{[A-Z0-9_]+\}|<insert[^>]*>|todo|fixme)
```

Entropy helper for borderline strings (run manually on a candidate):

```bash
python3 -c 'import sys,math,collections
s=sys.argv[1]; n=len(s)
h=-sum((c/n)*math.log2(c/n) for c in collections.Counter(s).values())
print(f"{h:.2f} bits/char")' "VALUE_TO_TEST"
```

Interpretation: mixed-case+digits+symbols at length >=24 scoring >=3.5 bits/char suggests machine generation; English words score roughly 2.0-3.0. A low score never proves harmlessness ("password123" is a live credential).

### Entropy Triage Decision Table

| Observed signal | Verdict | Confidence | Action |
|---|---|---|---|
| Provider fingerprint match, no placeholder marker | Likely-live secret | High | Report Critical/High; validate read-only only if authorized |
| Fingerprint match containing placeholder words or repeated-char runs (`aaaa`, `1234`) | Placeholder | High | Informational note only |
| Vendor-documented sample value (AWS `...EXAMPLE` pair, Stripe docs test keys) | Known-public sample | High | Non-finding; add to allowlist |
| Entropy >=3.5 bits/char, length >=24, credential-named variable | Suspected secret | Medium | Needs-Review |
| Low-entropy string bound to `secret`/`password`/`key` name | Weak-but-real candidate | Medium | Needs-Review; weak values still authenticate |
| Base64 blob decoding to image/font/binary magic bytes | Embedded asset | High | Non-finding |
| Test-mode keys (`sk_test_`, sandbox IDs) confined to tests | Test credential | High | Informational; confirm no prod reach |
| Anything ambiguous | Undetermined | — | Flag Needs-Review (mandatory default) |

## Taint Tracing Guidance

Model every secret as definition site -> propagation -> leak sink. A hardcoded literal is one finding class; a value that reaches a client-visible or logged sink is a second, often worse, finding.

| Language | Definition sites | Leak sinks |
|---|---|---|
| JS/TS | `process.env.X`, `import.meta.env.X`, dotenv config modules | `console.log`/loggers given objects, `res.json(config)`, `Error` message strings, Sentry breadcrumbs, compile-time bundle injection |
| Python | `os.environ[]`, `os.getenv()`, Django settings module, pydantic Settings | `logging`/`print`, `HTTPException(detail=str(e))`, sentry_sdk captures, template context containing settings |
| Java/Kotlin | `System.getenv/getProperty`, `@Value("${...}")`, `application.yml` | log4j/slf4j statements interpolating variables, `e.printStackTrace()`, error responses embedding exception text |
| C# | `Configuration["x"]`, `Environment.GetEnvironmentVariable` | `_logger.LogError(ex, ...)` full exception, ProblemDetails with exception detail enabled, `Console.WriteLine` |
| PHP | `getenv()`, `$_ENV`/`$_SERVER`, Dotenv | `var_dump`/`dd`/`error_log`, echoing `$e->getMessage()`, `display_errors` output |
| Ruby | `ENV['X']`, Rails credentials/secrets | `Rails.logger`, `raise CustomError.new(msg + ENV[...])`, `puts`/`pp`, views rendering ENV |
| Go | `os.Getenv`, viper configs | `log.Printf`, `http.Error(w, err.Error())`, `panic(err)` surfacing to output |

Client-bundle trap (check in every JS/TS/mobile repo):

- Env names prefixed `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_` are inlined into shipped bundles at build time. Any secret under these names is public regardless of repo hygiene.
- Android `buildConfigField` values become bytecode constants; iOS `.xcconfig` values land in `Info.plist` inside the IPA.
- Verify by grepping built output (`dist/`) for both variable names and resolved values, not just source.

Procedure:

1. Locate the definition (literal or env read) with `file:line`.
2. Follow assignments, imports, and config-object spreads toward sinks.
3. Sink is client artifact, response body, log line, or crash report => exposure finding.
4. Sink is server-side runtime use only => hardcoded-credential finding instead.
5. Record both ends of the flow in the finding so remediation can cut the path.

## Exploitation & Reproduction

Ground rules: act only on authorized repos/targets; use read-only calls; if a validation step is not explicitly permitted, stop at Needs-Review; redact every captured value in reports to its first 4 characters plus type; never export data beyond what proves impact.

1. Validate suspected AWS key (read-only): set `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` from the finding temporarily and run `aws sts get-caller-identity --region us-east-1`. Expected observable outcome: JSON containing `Account` and `Arn` (key live) or `InvalidClientTokenId` (dead). Record only "live key, IAM principal of type X" and redact account digits. Do NOT invoke any other AWS API without explicit authorization.
2. Confirm DB credential works: from an authorized network run `psql "$CONN" -c '\conninfo'` or `mysql -h HOST -u USER -p -e 'SELECT 1;'`. Expected: connection info line or result `1` (credential valid), or access-denied (invalid/expired). Redact host and user in notes. Unreachable network => mark unvalidated, still report the committed credential itself.
3. Show stack trace disclosure: `curl -s https://TARGET/route-that-throws` (or any 500 trigger). Expected: response contains `Traceback (most recent call last)` (Django/Flask), `at com.example.` frames (Java), or absolute source paths. Capture only keyword presence plus one redacted frame as evidence.
4. Probe Spring env endpoint: `curl -si https://TARGET/actuator/env`. Expected: `200` with a property tree (values commonly masked as `******`; the reachable endpoint alone is the finding, `/heapdump` even worse) or `401/404` (hardened).
5. Confirm exposed `.git`: `curl -s https://TARGET/.git/HEAD`. Expected: `ref: refs/heads/main` proving the object store is fetchable via `/.git/objects/`. Confirm accessibility only; do not reconstruct the repo unless separately authorized.
6. GraphQL introspection in prod: POST `{"query":"{__schema{types{name}}}"}` to the GraphQL URL. Expected: full type list returned => schema disclosure finding; error rejecting introspection => hardened.
7. Source map publication: fetch a minified prod bundle, extract trailing `//# sourceMappingURL=`, fetch the map. Expected: `sourcesContent` array present => original source disclosed. Save only field names, no file dumps.
8. Response over-exposure: authenticated request to your own profile (`GET /users/me`). Diff returned fields against UI needs. Expected: fields such as `password_hash`, `otp_secret`, `is_admin` present in a self-response demonstrates serialization leakage without touching other users' data.

## Remediation

### Secret Manager Integration

Inject secrets at runtime; never write them into files under version control.

```bash
# HashiCorp Vault
vault kv put secret/payments STRIPE_KEY='sk_live_xxxx' DB_PASS='xxxx'
# app reads at boot:
vault read -field=STRIPE_KEY secret/payments
```

```python
# FIXED: AWS Secrets Manager fetched at boot, cached in memory only
import boto3, json, functools

@functools.lru_cache
def get_secret(secret_id: str) -> dict:
    resp = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)
    return json.loads(resp["SecretString"])
```

- Kubernetes: prefer mounting secrets as files over env vars (env values leak into `/proc`, `kubectl describe`, crash dumps). Set `automountServiceAccountToken: false` when unused.
- Docker/Swarm: use `docker secrets` (tmpfs-mounted files), not `ENV` in Dockerfiles.
- systemd: `EnvironmentFile=/etc/app/env` with `chmod 600` owned by the service user.
- CI: reference the platform secret store (`${{ secrets.NAME }}` in GitHub Actions); forbid raw literals in workflow YAML.

### Pre-Commit And CI Guardrails

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

```bash
gitleaks detect --source . --redact --report-path leaks.json   # full history scan
trufflehog git file://. --only-verified                        # verifies liveness with providers where supported
detect-secrets scan --all-files > .secrets.baseline            # Yelp detect-secrets baseline workflow
```

### Rotate Vs Rewrite — History Purge Decision Rule

RULE: ROTATION IS MANDATORY FIRST. History rewrite alone is insufficient — public forges are crawled for keys within minutes of push, and clones/forks/CI caches retain blobs. Sequence:

1. Revoke/rotate every exposed credential everywhere: provider console, teammate clones, backup archives, CI caches, issue tickets.
2. Audit provider-side logs for misuse during the exposure window (CloudTrail, Stripe dashboard logs, git host audit log).
3. Only after rotation, optionally purge history to shrink future blast radius:

```bash
printf 'sk_live_OLDVALUE==>REDACTED\nAKIAOLDKEYID123456==>REDACTED\n' > replacements.txt
git filter-repo --replace-text replacements.txt --force
# then force-push and require all collaborators to re-clone
```

4. Add pre-commit + CI scanning before restoring push access (see above).

### Response Field Allowlisting (DTO Patterns)

```python
# VULNERABLE: ORM object serialized wholesale
@app.get("/users/{uid}")
def get_user(uid: int):
    return db.query(User).get(uid)          # leaks password_hash, otp_secret

# FIXED: response model allowlists fields
class UserOut(BaseModel):
    id: int
    email: EmailStr
    display_name: str

@app.get("/users/{uid}", response_model=UserOut)
def get_user(uid: int):
    return db.query(User).get(uid)
```

```java
// VULNERABLE: entity goes straight through Jackson
@GetMapping("/users/{id}")
public User user(@PathVariable Long id) { return repo.findById(id).orElseThrow(); }

// FIXED: explicit projection record
public record UserDto(Long id, String email) {}
@GetMapping("/users/{id}")
public UserDto user(@PathVariable Long id) {
    User u = repo.findById(id).orElseThrow();
    return new UserDto(u.getId(), u.getEmail());
}
```

```go
// FIXED: deny-by-default field tags
type User struct {
    ID           uint   `json:"id"`
    Email        string `json:"email"`
    PasswordHash string `json:"-"`
}
```

Rails equivalent: `user.to_json(only: [:id, :email, :display_name])` or jbuilder templates; Django REST Framework: replace `fields = "__all__"` with an explicit tuple. Belt-and-braces: add `@JsonIgnore`/`serializable_guard` on sensitive columns too.

### Log Redaction Middleware

```javascript
// Node/Express — FIXED: redact before any sink sees the data
const REDACT = ["authorization", "cookie", "set-cookie", "x-api-key"];
const redactHeaders = (h) => Object.fromEntries(
  Object.entries(h).map(([k, v]) => [k, REDACT.includes(k.toLowerCase()) ? "[REDACTED]" : v])
);
app.use((req, res, next) => {
  logger.http({ method: req.method, url: req.url, headers: redactHeaders(req.headers) });
  next();
});
```

```python
# Python logging — FIXED: global masking filter
import re, logging
SECRET_RE = re.compile(
    r"(?i)(authorization\s*[=:]\s*\S+|(api[_-]?key|token|password|secret)[\"']?\s*[:=]\s*[\"'][^\"'\s]{6,})"
)
class RedactFilter(logging.Filter):
    def filter(self, record):
        record.msg = SECRET_RE.sub("[REDACTED]", str(record.getMessage()))
        record.args = None
        return True
logging.getLogger().addFilter(RedactFilter())
```

```ruby
# Rails — params are filtered by default; widen the list, headers need custom care
Rails.application.config.filter_parameters += [:password, :token, :secret, :authorization, :cvv, :ssn]
```

Also cap third parties: Sentry `send_default_pii=False` (default) and scrub breadcrumbs of headers.

### Error Handler Hardening

```javascript
// Express — FIXED: generic client payload, details stay server-side
app.use((err, req, res, next) => {
  logger.error({ err: err.stack, path: req.path });     // internal only
  res.status(500).json({ error: "internal_server_error" });
});
```

- Django: `DEBUG = False`, custom `handler500` template, `ALLOWED_HOSTS` pinned.
- Flask/Werkzeug: never ship the dev server; run under gunicorn/uwsgi with `PROPAGATE_EXCEPTIONS = False`.
- Spring Boot: `@ControllerAdvice` returning sanitized problem JSON; expose only health/info as needed, lock `/actuator/*` behind auth and network policy.
- ASP.NET: `app.UseExceptionHandler("/Error")` in production paths; remove `UseDeveloperExceptionPage()`; keep detailed errors off (`ASPNETCORE_ENVIRONMENT != Development`).
- PHP: `display_errors=Off`, `log_errors=On` with protected log destination.

### Data At Rest Fixes

- Encrypt sensitive columns at rest (KMS-backed envelope encryption, pgcrypto, application-field encryption); keep keys in the secret manager, not beside the data.
- Purge CVV columns immediately upon discovery; document destruction per PCI DSS Req 3.3.1.
- CSV exports: mask PANs (show last 4), drop national-ID columns unless legally required, watermark and rate-limit downloads.
- Backups: `umask 077` before dump creation, encrypted offsite targets, no web-served directories.

## Verification & Validation

GIVEN/WHEN/THEN acceptance tests (include the negative tests):

- GIVEN the triage sweep WHEN run at repo root THEN fingerprint matches are zero outside the allowlisted sample-key list.
- GIVEN secrets migrated to a manager WHEN the app boots in staging THEN health check returns 200 AND `rg -n "(?i)(secret_key\s*=|AKIA[A-Z0-9]{16})" src/ config/` returns nothing. (Negative test: app must still boot from the secret store.)
- GIVEN error hardening WHEN an unauthenticated request triggers an exception THEN the body is `{"error":"internal_server_error"}` with no traceback frames, paths, or SQL text. (Negative test: page stays generic.)
- GIVEN actuator lockdown WHEN unauthenticated `GET /actuator/env` THEN response is 401 or 404, never a property tree.
- GIVEN a rebuilt client bundle WHEN grepping `dist/` for `NEXT_PUBLIC_|VITE_|REACT_APP_` names THEN no resolved secret values appear in output.
- GIVEN log redaction deployed WHEN a request with an Authorization header is processed AND logs sampled THEN stored lines contain `[REDACTED]`, never a bearer token.
- GIVEN history purge executed WHEN `git log --all -G'AKIA[A-Z0-9]{16}'` runs THEN zero commits match for every rotated prefix.
- GIVEN CVV storage discovered WHEN the column is dropped and app re-tested THEN checkout still succeeds end-to-end via the gateway token.

Regression CI pseudocode — scanning step fails on any new fingerprint match:

```yaml
# .github/workflows/secret-scan.yml (illustrative; pin real tool versions)
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }            # full history required
      - name: Scan fingerprints + history
        run: |
          gitleaks detect --source . --redact --exit-code 1 --report-path leaks.json
      - name: Diff against allowlist baseline
        run: |
          rg -n --hidden -g '!.git' \
            '(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-' \
            > findings.txt || true
          comm -23 <(sort findings.txt) <(sort allowlist.txt) | grep -q . && exit 1 || exit 0
```

Manual re-test checklist:

1. Re-run the full ready-to-run triage sweep; expect only allowlisted hits.
2. Re-run each git-history one-liner for every rotated credential prefix; expect empty.
3. Replay Exploitation probes 3-7 against hardened endpoints; expect generic errors / 401 / introspection refused / no source maps.
4. Fetch a production JS bundle; confirm no `sourceMappingURL` pointing to a published map and no secret literals.
5. Issue introspection probe against prod GraphQL; expect rejection in prod, allowed only behind internal auth.
6. Field-diff three representative API responses against their DTO definitions; expect exact-match field sets.
7. Confirm CI scan job is green on clean branches and red when a planted decoy (`AKIAIOSFODNN7EXAMPLE`) is added on a scratch branch.
8. Boot the app locally with only secret-manager access (no `.env`) to prove runtime injection works.

Greps to re-run post-fix:

```bash
rg -n --hidden -g '!.git' 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' || echo CLEAN
rg -n --hidden -g '!.git' '(?i)secret_key\s*=\s*["'"'"'][^"'"'"']{8,}' || echo CLEAN
git log --all --oneline -G'AKIA[A-Z0-9]{16}|sk_live_' || true
```

## Severity Assessment

| Finding | Primary CWE | Notes |
|---|---|---|
| Hardcoded password/API key in code or config | CWE-798 / CWE-259 / CWE-321 | 259 passwords, 321 crypto keys, 798 generic |
| Secret embedded in shipped client bundle/mobile binary | CWE-540 / CWE-200 | treat as public disclosure |
| Credential in VCS history | CWE-798 (+CWE-540) | rotation mandatory regardless of purge |
| Cleartext sensitive data stored (files/columns/dumps) | CWE-312 / CWE-313 | 313 file-or-disk specific |
| Verbose stack traces/error pages to clients | CWE-209 / CWE-489 | Active Debug Code for enabled debug modes |
| Secrets/PII written to logs | CWE-532 | centralized retention raises impact |
| Debug/actuator endpoints exposed | CWE-489 / CWE-200 | env endpoints can leak property values |
| Directory listing / deployed .git / source maps | CWE-538 / CWE-200 | file-and-directory information exposure |
| Credentials in source comments/ticket references | CWE-615 | search comments explicitly |
| PII over-exposure in responses | CWE-359 / CWE-200 | scale by volume and sensitivity class |
| Unprotected credential storage (unsalted hashes etc.) | CWE-522 | pair with crypto review |

Rubric:

| Scenario | Default severity | Adjustments |
|---|---|---|
| Live cloud provider key with broad privileges (AWS/GCP/Azure) | Critical | Downgrade only with proof of dead key |
| Live third-party paid API key (Stripe/Twilio/SendGrid) | High | Financial-abuse ceiling; Critical if unlimited spend |
| Internal DB credential, network-restricted | High | Medium if segmentation demonstrably enforced |
| JWT signing secret recoverable by clients | Critical | Token forgery = auth bypass |
| Placeholder/test-mode credentials only | Informational-Low | Verify confinement before downgrading |
| Prod stack traces / GraphQL introspection | Medium | High if trace echoes env vars or credentials |
| Secrets in centralized long-retention logs | High | Medium for short-lived local-only logs |
| Single PII field over-exposed | Medium | Bulk export capability => High |
| Children's/health/financial/government-ID class exposure | High floor | Bump one level vs ordinary contact PII |
| CVV stored post-authorization | Critical | Compliance violation independent of exploitability |

CVSS v3.1 example vectors:

- Committed live AWS admin key: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` -> 9.8 Critical.
- JWT signing secret in client bundle: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L` -> 9.7 Critical (scope changed: trust across boundary).
- Stack traces returned unauthenticated: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` -> 5.3 Medium.
- Authenticated endpoint returning other users' PII fields: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` -> 6.5 Medium.

Privacy quick-pass — classify exposed data so reports justify severity differences:

| Class | Indicators | Why severity differs | Factual compliance hook |
|---|---|---|---|
| Ordinary contact PII | name, email, phone | baseline identity risk | GDPR/CCPA personal data |
| Government IDs | SSN/NINO/passport numbers | irreversible identity theft | High-Critical; GDPR Art. 5(1)(f) integrity |
| Health | diagnoses, medications, appointment reasons | discrimination/stigma harm | GDPR Art. 9 special category; HIPAA if covered entity |
| Children | age <13 derivable, parental-consent flags | heightened protection duty | COPPA; GDPR Art. 8 |
| Financial | PAN, bank accounts, credit scores | fraud exposure | PCI-DSS scope for card data; CVV storage prohibited |
| Biometrics/precise location | fingerprints, face templates, GPS trails | unique, non-rotatable identifiers | GDPR Art. 9 biometric data |

## Common False Positives

- Public keys: `-----BEGIN PUBLIC KEY-----`, `*.pub`, certificate bodies — not secrets; verify no matching private key nearby.
- Stripe `pk_live_`/`pk_test_` publishable keys — public by design; report only misuse such as embedding server-side capabilities.
- Vendor-documented sample values (AWS `AKIAIOSFODNN7EXAMPLE` pair, docs quickstart keys copied verbatim).
- Test/sandbox keys (`sk_test_`) clearly confined to test trees — Informational after confinement check.
- Base64 data URIs (`data:image/png;base64,...`) and bundled font/asset blobs tripped by entropy heuristics.
- Lockfile integrity hashes and checksum constants (SHA256 lines in `package-lock.json`, `go.sum`).
- Obviously synthetic fixture data: `example.com` emails, `555-*` phone numbers, sequential test tokens.
- AIza keys inside `google-services.json`/`Info.plist` — expected placement; flag restriction status as Needs-Review, not as a leaked secret.
- Dev-only self-signed certificates intentionally committed for local TLS with documented throwaway status.
- kubeconfig using exec/SSO plugins with no embedded credential material.
- Minified single-letter variables coincidentally matching length/entropy heuristics.
- i18n/localization strings and license-key placeholders (`XXXXX-XXXXX`) in setup docs.
- `terraform.tfstate` entries whose values are already non-sensitive outputs — still inspect `sensitive` attributes separately.
- Proprietary license keys — not credentials but still flag Needs-Review at reduced severity (licensing exposure).

Never silently drop a candidate: downgrade with rationale or mark Needs-Review.

## References

- CWE-798: Use of Hard-coded Credentials. https://cwe.mitre.org/data/definitions/798.html
- CWE-259: Use of Hard-coded Password. https://cwe.mitre.org/data/definitions/259.html
- CWE-321: Use of Hard-coded Cryptographic Key. https://cwe.mitre.org/data/definitions/321.html
- CWE-312: Cleartext Storage of Sensitive Information. https://cwe.mitre.org/data/definitions/312.html
- CWE-313: Cleartext Storage in a File or on Disk. https://cwe.mitre.org/data/definitions/313.html
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor. https://cwe.mitre.org/data/definitions/200.html
- CWE-209: Generation of Error Message Containing Sensitive Information. https://cwe.mitre.org/data/definitions/209.html
- CWE-532: Insertion of Sensitive Information into Log File. https://cwe.mitre.org/data/definitions/532.html
- CWE-540: Inclusion of Sensitive Information in Source Code. https://cwe.mitre.org/data/definitions/540.html
- CWE-615: Inclusion of Sensitive Information in Source Code Comments. https://cwe.mitre.org/data/definitions/615.html
- CWE-538: File and Directory Information Exposure. https://cwe.mitre.org/data/definitions/538.html
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor. https://cwe.mitre.org/data/definitions/359.html
- CWE-489: Active Debug Code. https://cwe.mitre.org/data/definitions/489.html
- CWE-522: Insufficiently Protected Credentials. https://cwe.mitre.org/data/definitions/522.html
- OWASP Top 10 A02:2021 – Cryptographic Failures. https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- OWASP Cheat Sheet: Secrets Management. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP Cheat Sheet: Authentication. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Cheat Sheet: Error Handling. https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- OWASP Cheat Sheet: Logging. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Cheat Sheet: User Privacy Protection. https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html
- OWASP Cheat Sheet: Cryptographic Storage. https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Cheat Sheet: GraphQL. https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Provider key-format documentation to consult for current formats (names only): AWS General Reference "IAM identifiers"; Google "API key restrictions"; Stripe docs "API keys"; GitHub docs "Token formats" and secret-scanning patterns; Slack docs "Token types"; SendGrid docs "API Keys"; Twilio docs "API Keys"; GitLab docs "Personal access tokens"; PyPI docs "API token"; npm docs "Access tokens".
- Tools: gitleaks, trufflehog, Yelp detect-secrets, awslabs git-secrets, git-filter-repo, BFG Repo-Cleaner.
