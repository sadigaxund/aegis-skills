---
name: aegis-supply-chain
description: Audits dependency manifests, lockfiles, vendored code, and CI/CD definitions for supply-chain weaknesses such as vulnerable or unmaintained components, resolution drift, typosquat and install-script exposure, registry-confusion preconditions, and workflow injection.
category_slug: SUPPLY
cwe: [CWE-1104, CWE-494]
owasp: A06:2021 – Vulnerable and Outdated Components
---

## Scope & Objectives

- Inventory every dependency manifest/lockfile pair across all ecosystems present in the repo (npm/yarn/pnpm, pip/Pipfile/poetry/uv, Go modules, Maven/Gradle, NuGet, Composer, Bundler, Cargo).
- Assess version risk statically: EOL runtimes/majors, packages whose bad reputation you are certain of; defer everything else to network-gated official scanners listed here.
- Test lockfile hygiene: missing lockfiles, manifest/lockfile drift, vendored trees without provenance, git submodules floating on a branch instead of a commit.
- Map the typosquat/install-script surface: lifecycle scripts in dependency `package.json` files, dependencies that do not belong, dependency-confusion preconditions (missing private-registry scoping).
- Judge pinning posture: semver ranges without locks, Dockerfile `FROM :latest`, unpinned GitHub Actions refs, `curl | bash` in images and CI.
- Audit CI/CD pipeline logic: `pull_request_target` secret exposure to forks, `${{ github.event.* }}` interpolation into `run:` blocks (script injection), third-party actions without SHA pinning, self-hosted runners attached to public-repo workflows, artifact tampering paths, deploy-credential breadth, cache poisoning preconditions.
- Check build integrity: SBOM generation absent, artifacts unsigned, stale base images, unpinned package installs inside images.
- Objectives: produce findings with `file:line` evidence, classify via the severity rubric, mark every uncertain item `Needs-Review`, and clearly separate offline-static conclusions from conclusions that require the network-gated scanners.

Out of scope: runtime container escape, secrets storage hygiene itself (cross-reference `skills/code/secrets-data-exposure/SKILL.md` for leaked credentials, including creds echoed into CI logs), and application-level injection sinks (`skills/code/injection/SKILL.md` covers reachable sinks used by the severity rubric below).

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **lockfile drift**: the manifest and lockfile disagreeing, so builds resolve different dependency versions
- **install/lifecycle script**: package-defined commands that run automatically at install or build time
- **dependency confusion**: unscoped internal names letting attackers publish a fake public package that wins resolution
- **SCA (software composition analysis)**: scanning declared dependencies for versions with known vulnerabilities
- **SBOM**: a machine-generated inventory of every component shipped in the artifact
- **provenance/attestation**: signed evidence of where and how an artifact was built
- **workflow injection**: untrusted text (a PR title, for example) interpolated into CI shell commands
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

A build moves code through three layers, and every supply-chain attack injects at one boundary:

| Layer | What it is | Trust question |
|---|---|---|
| 1. Declared | manifests: `package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `*.csproj` | "Did a human intend this?" |
| 2. Resolved | lockfiles, vendor dirs, module caches, downloaded sdists/gems | "Is what arrived exactly what was declared, from who?" |
| 3. Built & shipped | CI runner executing workflows, producing signed artifacts/deployables | "Who ran code during this build, with which secrets?" |

Attack classes map onto the boundaries:

| Attack class | Boundary | Canonical example |
|---|---|---|
| Exploit stale content | inside layer 2 content | known-vulnerable dependency version, EOL runtime |
| Poison resolution | 1 → 2 | typosquat name, dependency confusion, mutable tag/submodule branch |
| Hijack the builder | 2 → 3 | malicious `postinstall`, compromised third-party action, workflow injection via PR title |
| Tamper output | after 3 | unsigned artifacts, overwritten named artifacts between jobs |

Operating principles:

- A repository's CI executes third-party-authored code on every push and every fork PR. Treat workflow inputs (`github.event.*`) as attacker-controlled strings until proven otherwise.
- Lockfiles convert "whatever the registry serves today" into "exactly these bytes". No lockfile means no reproducibility and no auditability.
- Absence of evidence (no scanner hit) is not evidence of absence when you could not run the scanner; report offline findings honestly as heuristics.

## What To Check

### Run This Inventory First

Paste and run this block from the repo root; its output drives every later section.

```bash
#!/usr/bin/env bash
set -uo pipefail

echo "== manifests & lockfiles (excluding vendored trees) =="
find . \( -name node_modules -o -name vendor -o -name third_party -o -name .git \) -prune -o -type f \
  \( -name 'package.json'    -o -name 'package-lock.json' -o -name 'yarn.lock'   -o -name 'pnpm-lock.yaml' \
     -o -name 'requirements*.txt' -o -name 'Pipfile'      -o -name 'Pipfile.lock' -o -name 'pyproject.toml' \
     -o -name 'poetry.lock'    -o -name 'uv.lock'           -o -name 'go.mod'      -o -name 'go.sum' \
     -o -name 'pom.xml'        -o -name 'build.gradle*'     -o -name 'gradle.lockfile' \
     -o -name '*.csproj'       -o -name 'packages.config'   -o -name 'packages.lock.json' \
     -o -name 'composer.json'  -o -name 'composer.lock'     -o -name 'Gemfile'     -o -name 'Gemfile.lock' \
     -o -name 'Cargo.toml'     -o -name 'Cargo.lock' \) -print

echo "== dependency counts per manifest =="
command -v jq >/dev/null && \
  find . -name package.json -not -path '*/node_modules/*' -exec sh -c \
    'printf "%s: %s prod deps\n" "$1" "$(jq -r ".dependencies // {} | length" "$1")"' _ {} \;
for f in $(find . \( -name go.mod -o -name requirements.txt -o -name Gemfile.lock \
                     -o -name composer.lock -o -name Cargo.lock \) -not -path './.git/*'); do
  printf "%s: ~%s lines\n" "$f" "$(wc -l < "$f")"
done

echo "== install scripts across EVERY nested package.json (incl. node_modules/vendored) =="
grep -rnE '"(preinstall|install|postinstall|prepublish|prepublishOnly|prepare)"[[:space:]]*:' \
  --include=package.json . | sort || true

echo "== Dockerfile FROM lines =="
find . -name .git -prune -o -type f \( -name 'Dockerfile*' -o -name '*.dockerfile' \) -print0 \
  | xargs -0 -r grep -nE '^[[:space:]]*FROM' || true

echo "== GitHub Actions uses: lines =="
find . -type f \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \) -print0 \
  | xargs -0 -r grep -nE '[[:space:]]uses:' || true
```

Interpret before continuing:

- An application manifest with no sibling lockfile is finding SC-LOCK-1.
- `postinstall` hits outside well-known tooling (`esbuild`, `sharp`, `husky` in dev deps) need per-package review.
- Every `FROM` line feeds the base-image check; every `uses:` line feeds the action-pinning check.

### Ecosystem Inventory And Scanner Matrix

| Ecosystem | Manifest | Lockfile | Official scanner command | Offline heuristic |
|---|---|---|---|---|
| JavaScript/TypeScript | `package.json` | `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | `npm audit` (also `yarn audit` / `pnpm audit`) — requires network | EOL runtimes in `engines`; packages with certain compromised reputations (below); lifecycle-script count |
| Python | `requirements.txt` / `pyproject.toml` / `Pipfile` / `setup.py` | `poetry.lock` / `uv.lock` / `Pipfile.lock`; fully pinned `requirements.txt` doubles as lock | `pip-audit`; `safety check -r requirements.txt` — requires network | EOL Pythons (`<=3.8` as of 2026); sdist installs that execute `setup.py`; unpinned ranges |
| Go | `go.mod` | `go.sum` | `govulncheck ./...` — requires network; reports symbol-level reachability | Stale module versions; missing `go.sum` entries; toolchain age |
| Java | `pom.xml` / `build.gradle(.kts)` | `gradle.lockfile` (Gradle only; Maven has no first-class lock) | `mvn org.owasp:dependency-check-maven:check` — requires network | `log4j-core` 2.x below 2.17.1 (Log4Shell family, CVE-2021-44228); Maven ranges `[1.0,2.0)`; ancient Spring majors |
| .NET | `*.csproj` / `packages.config` | `packages.lock.json` (PackageReference projects) | `dotnet list package --vulnerable` — requires network | Legacy `packages.config`; missing `nuget.config` source mapping; EOL target frameworks |
| PHP | `composer.json` | `composer.lock` | `composer audit` (Composer 2.4+) — requires network | Packages flagged abandoned; missing `platform.php` pin; plugin allow-list state |
| Ruby | `Gemfile` | `Gemfile.lock` | `bundler-audit check` — requires network to refresh advisory DB | Rails `<=6.0`; `git:` gem sources without a pinned ref |
| Rust | `Cargo.toml` | `Cargo.lock` | `cargo audit` — requires network (RustSec DB) | Weak signal offline; say so rather than guess |

### Version Risk Without Network

Reason statically only about what you are certain of; label everything else `Needs-Review`.

- Flag EOL majors outright (as of 2026): Node.js `<=18`, Python `<=3.8`, Rails `<=6.0`, Django `<=3.2`, AngularJS 1.x, OpenSSL `1.1.1`/`1.0.2`, base images `ubuntu:16.04`, `node:14*`, `python:3.7*`.
- Flag packages whose compromise or notoriety is public knowledge and that you can name confidently:
  - `event-stream` (2018 malicious takeover), `ua-parser-js` (2017 and 2021 hijacks), `colors` and `faker` (2022 maintainer sabotage releases), `xz`/`liblzma` `5.6.0`–`5.6.1` backdoor (CVE-2024-3094).
  - `lodash` `<4.17.21` (final prototype-pollution fix), `log4j-core` `2.x <2.17.1` (CVE-2021-44228 family).
- Do not invent version ranges for anything else. Write "unknown — run the listed scanner when network is authorized" instead of guessing.
- Record each flag as `manifest-path:dependency-name@declared-range → reason`.

### Lockfile Hygiene

- For every application/deployable manifest require a sibling lockfile. Libraries may omit locks deliberately; applications may not.
- Verify manifest/lockfile sync per ecosystem (concrete diffs in Exploitation & Reproduction step 1):
  - npm: `npm ci` fails on drift; offline alternative is comparing dep-name sets with `jq`.
  - Composer: `composer validate` reports an out-of-date lock without network.
  - Poetry/uv/pnpm: each has a lock-validity mode; consult `--help` rather than guessing flags.
  - Go: copy the repo, run `go mod tidy` in the temp copy, then `diff` the original `go.mod`/`go.sum` (offline once the module cache is warm).
- Vendored dependencies: inspect `vendor/`, `third_party/`, `deps/`. Accept vendoring only when provenance travels with it: Go's `vendor/modules.txt` embeds module versions and hashes; anything else should ship checksums (`SHASUMS`, lockfile entries) and a documented update procedure. Unattributable tarballs are findings.
- Git submodules: read `.gitmodules`. Submodules pin commits by nature, but any of these re-floats them:
  - a `branch =` line in `.gitmodules`,
  - CI invoking `git submodule update --remote`,
  - docs instructing `--remote` updates.
- Check CI never regenerates the lockfile at deploy time (`npm install` instead of `npm ci`, `pip install -r` on unpinned file, `composer update` instead of `composer install`) — that silently rebuilds layer 2.

### Install Scripts And Typosquat Surface

- Run the inventory block's install-script grep. For each hit, open that `package.json` and read the script body:
  - Expected: narrow build helpers (`node-gyp rebuild`, `husky install`, postinstall patches).
  - Suspicious: `curl|wget` to registries or raw hosts, base64 blobs, writes outside the project, env harvesting, spawning obfuscated node code (`node -e`), touching `~/.ssh`, `~/.npmrc`, or credential paths.
- Detect deps referenced nowhere in first-party code (heuristic, JS example):

```bash
while read -r dep; do
  rg -q "(from +[\"']${dep}|require\([\"']${dep}|import +.*[\"']${dep})" \
    --glob '!**/node_modules/**' . || echo "possibly unused: $dep"
done < <(jq -r '.dependencies // {} | keys[]' package.json)
```

- Typosquat eyeball rules over `dependencies` lists: transposed characters, missing hyphens, pluralization, `.js` suffix additions, lookalike Unicode — compare near-matches against the well-known package you expect. Tools such as `depcheck` (JS) help find stray deps; do not trust name-similarity tooling blindly, report as `Needs-Review`.
- Internal-looking names published publicly (e.g., `@acme-core/utils` appearing with a public-registry source while nothing internal matches it) indicate either squatting or confusion bait.

### Dependency-Confusion Preconditions

Check each precondition; every unchecked box is exposure:

- [ ] `.npmrc` present mapping internal scopes (`@scope:registry=...`)? Absence means installs resolve internal names from the public registry.
- [ ] Does any workflow set `NODE_AUTH_TOKEN` / run `npm publish`? Publishing rights plus unscoped internal names equals takeover-by-registration.
- [ ] Python: does CI set `PIP_INDEX_URL` to an internal index while manifests still reference public-only names? Note pip merges `extra-index-url` sources without preferring the private one — internal names must not also exist publicly.
- [ ] .NET: is there a `nuget.config`? Without Package Source Mapping, NuGet consults all configured feeds for every ID.
- [ ] Go: is `GOPRIVATE` set in CI/docs? Without it, private module paths leak to the public proxy and checksum DB, and resolution can be hijacked.
- [ ] Composer/Cargo/Bundler: check `repositories`/registry config ordering and whether internal-only names could resolve from the default public source.

### Pinning Posture

- Application repos: flag `"^x.y.z"`/`"~x.y.z"` ranges combined with no lockfile or with CI/deploy steps that ignore the lockfile — silent major bumps reach prod.
- Dockerfiles: flag `FROM repo:latest` and bare `FROM repo` (implicit latest); prefer tag pins and digests.
- GitHub Actions: flag every `uses:` referencing a mutable ref (`v4`, `main`). SHA pinning with a version comment is the standard.
- Shell bootstrapping: flag `curl ... | sh`, `wget ... | bash`, and their sudo variants anywhere in images, scripts, or workflows.

### CI/CD Pipeline Flaws

Read every file under `.github/workflows/` end-to-end:

- `pull_request_target`: runs from the BASE branch with repository secrets available. Safe uses are rare (labeling/commenting bots). Any step that checks out PR head code, builds it, tests it, or interpolates head-derived strings into commands converts fork PRs into authenticated code execution.
- Script injection: any `${{ github.event.* }}` value (title, body, branch name, issue/comment text, reviewer names, commit messages) interpolated directly into `run:` is shell injection by a fork author. Same for `env` values later passed through unquoted expansions into `eval`, `sh -c`, or dynamic `uses:`.
- Secrets scoping: list jobs receiving secrets or `GITHUB_TOKEN` with elevated permissions; verify each needs it for that event type.
- Third-party actions: any non-`actions/*` org action running on sensitive jobs must be SHA-pinned and reviewed.
- Self-hosted runners: flag `runs-on: [self-hosted]` in any repo reachable by forks/public contributors; GitHub guidance treats this as unsafe without ephemeral isolation.
- Artifacts: map upload → download chains between jobs. Mutable shared artifact names let a lower-trust job overwrite what a higher-trust job consumes downstream; treat downloaded artifacts as untrusted input.
- Deploy credentials: breadth matters more than count — a static cloud key usable account-wide in every build is Critical-adjacent; prefer short-lived OIDC tokens scoped per environment.
- Cache poisoning (concept): `actions/cache` keys derived from attacker-reachable inputs (branch names, lockfile contents in PRs) can seed poisoned caches restored into trusted builds; note preconditions rather than proving exploitation.

### Build Integrity Gaps

- SBOM: search CI for SBOM generation (syft, cyclonedx-cli, ecosystem-native). None found = provenance gap finding.
  Concrete invocation shapes: `syft packages dir:. -o cyclonedx-json > sbom.json` for a repo/filesystem scan or `syft <image>` for an image; npm projects can use `npx @cyclonedx/cyclonedx-npm` instead. Verify the flag set against `--help` — CLI surfaces churn.
- Signing: artifacts/images unsigned (no cosign usage anywhere) = integrity gap finding; mention cosign by name in remediation.
- Base image staleness: apply the EOL list from Version Risk Without Network to all `FROM` lines collected earlier.
- In-image installs: flag `apt-get install pkg...` / `apk add pkg...` without version pins in release images, and any `pip install` without constraints inside images.
- CI logs: grep workflows for `echo $SECRET`, `-v` flags on curl, `set -x` around secret-bearing steps — leaked credentials belong to `skills/code/secrets-data-exposure/SKILL.md`; record cross-reference only.
- Attestation verification: check deploy steps for sigstore/cosign signature verification and in-toto attestations (SLSA provenance levels as the build-integrity maturity vocabulary); consuming unsigned/unattested artifacts extends the signing gap above.
- New-dependency screening gate: newly added dependency names in PR diffs get edit-distance screening against popular packages before merge (a typosquat gate beyond the eyeball rules above).

## Where To Look

| Artifact | Path(s) | Why it matters |
|---|---|---|
| Manifests/lockfiles | repo-wide; include monorepo subdirs and workspace globs (`pnpm-workspace.yaml`, `go.work`, Gradle multi-project) | layer 1/2 inventory |
| Lifecycle scripts | every nested `package.json` incl. `node_modules/` and vendored trees | builder hijack surface |
| Registry config | `.npmrc`, `.yarnrc.yml`, `pip.conf`/`PIP_INDEX_URL` in CI env, `nuget.config`, `.composer/config.json`, `~/.cargo/config.toml` committed copies, `settings.xml` (Maven) | confusion preconditions |
| Submodules | `.gitmodules`, `git submodule status` output | floating refs |
| CI definitions | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, `azure-pipelines.yml` | pipeline flaws |
| Containers | all `Dockerfile*`, `docker-compose*.yml` `build:` contexts, `.dockerignore` | base pins, curl-bash, build secrets in layers |
| Vendored code | `vendor/`, `third_party/`, `deps/`, `ext/` | provenance |
| Release tooling | release scripts, `Makefile` publish targets, `.goreleaser*` | artifact integrity |

Skip-list awareness: exclude `node_modules/` from manifest discovery but INCLUDE it for the targeted install-script sweep; exclude test fixtures from findings unless they ship.

## Patterns & Signatures

Ripgrep-compatible patterns (no lookarounds):

Install/lifecycle scripts in package manifests:

```regex
"(preinstall|install|postinstall|prepublish|prepublishOnly|prepare)"\s*:
```

Floating semver ranges in a JS manifest:

```regex
"[~^][0-9]+\.[0-9]+\.[0-9]+"
```

Docker base images on latest or untagged:

```regex
FROM\s+[^@\s:]+:latest
FROM\s+[a-z0-9._/-]+\s+(AS\s|$)
```

curl/wget piped to shell:

```regex
(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh
```

GitHub Actions pinned by tag/branch instead of SHA:

```regex
uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(v[0-9]|main|master|latest)
```

GitHub Actions correctly SHA-pinned (positive control — expect hits after fix):

```regex
uses:\s*\S+@[0-9a-f]{40}
```

Workflow script-injection sinks (untrusted event data interpolated into run):

```regex
run:.*\$\{\{.*github\.event
run:\s*.*\$\{\{.*(pull_request|issue|comment|head_ref|commits)
```

Registry scoping directives:

```regex
@[A-Za-z0-9._-]+:registry=
index-url\s*=|extra-index-url\s*=
GOPRIVATE|GONOSUMDB|GOPROXY
```

Submodule floaters:

```regex
branch\s*=\s*\S+
submodule update --remote
```

Unpinned in-image package installs (review each hit for version pins):

```regex
apt-get install
apk add .*(--no-cache)?\s+[a-z]
```

Both patterns match broadly; manually verify each hit for absence of `pkg=version` / `pkg=epoch-ver-rel` pins, since ripgrep lookarounds are unavailable.

Workflow anti-patterns with labels:

```yaml
# VULNERABLE — pull_request_target exposes base-repo secrets to fork-triggered runs;
# PR title interpolated straight into a shell command line.
name: greeting
on: pull_request_target
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks for the PR, ${{ github.event.pull_request.title }}"
```

A PR titled `hi'; whoami #` turns the executed script into `echo "Thanks for the PR, hi'; whoami #"` — `whoami` runs inside your runner. Expression-style payloads have historically double-evaluated too; treat both as exploitable.

```yaml
# FIXED — pull_request grants no fork secrets; untrusted value travels through env,
# expanded quoted at shell time, never re-parsed as an expression.
name: greeting
on: pull_request
permissions:
  contents: read
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "Thanks for the PR, $PR_TITLE"
```

```dockerfile
# VULNERABLE
FROM node:latest
RUN curl -sSL https://example.com/installer.sh | sh
RUN apk add --no-cache openssl
```

```dockerfile
# FIXED — version-pinned base (optionally append @sha256:<digest>; obtain via
# docker buildx imagetools inspect node:20-bookworm-slim), checksum-gated installer,
# version-pinned packages matching that image's apk index.
FROM node:20.11.1-bookworm-slim
COPY installer.sh installer.sh.sha256 /tmp/
RUN cd /tmp && sha256sum -c installer.sh.sha256 && sh installer.sh
RUN apk add --no-cache openssl=3.1.4-r0
```

Action pinning format — resolve the current SHA yourself rather than copying examples (`git ls-remote https://github.com/actions/checkout refs/tags/v4.2.2`), then keep the tag as a comment:

```yaml
# FIXED
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

## Taint Tracing Guidance

Model CI workflows as data-flow graphs from untrusted sources to dangerous sinks:

Sources (attacker-reachable in public/fork contexts):

- `github.event.pull_request.*` (title, body, head ref, user, labels), `github.event.issue.*`, `github.event.comment.*`, commit messages and author emails.
- File contents inside PR head commits when the workflow checks out or fetches them.
- Artifacts and caches produced by earlier/lower-trust jobs.
- Outputs of third-party actions (`steps.<id>.outputs.*`) — the action's code defines their content.

Propagation patterns:

- Direct expression taint: `${{ <source> }}` textually spliced into `run:` — evaluated before shell sees it; expression payloads may double-evaluate.
- Env-indirect taint: source into `env:`, then `$VAR` unquoted, backticked, command-substituted, or passed to `eval`/`sh -c`/interpreter `-e` flags — still exploitable.
- Filesystem taint: workflow writes event-derived data to a file that a later step `eval`s, `source`s, parses into `uses:`, or feeds to a deploy tool.
- Dynamic resolution taint: `uses: ${{ inputs.action }}` or version strings computed at runtime — arbitrary third-party code selection.

Sinks ranked by impact:

1. `run:` blocks and any shell invocation within them.
2. Steps holding secrets (`secrets.*` in env of a tainted job) — injection plus exfiltration.
3. Deploy/publish steps (registry tokens, cloud keys).
4. Artifact upload consumed by a protected environment downstream.

Worked chain: fork PR title → `run: make TAG=${{ github.event.pull_request.head.ref }} deploy` → attacker-controlled ref reaches Makefile variable → Makefile `sh -c` line interpolates it → shell execution with `AWS_SECRET_ACCESS_KEY` present. Report each link you can see statically; mark unverifiable links `Needs-Review`.

## Exploitation & Reproduction

Emphasize static/local proof; network-gated steps are marked explicitly.

1. Lockfile drift demonstration (offline):
   1. Extract declared names: `jq -r '.dependencies // {} | keys[]' package.json | sort > /tmp/manifest.txt`.
   2. Extract locked names from lockfile v2+: `jq -r '.packages | to_entries[] | select(.key != "") | .value.name // (.key | sub("^node_modules/"; ""))' package-lock.json | sort -u > /tmp/locked.txt`.
   3. `comm -23 /tmp/manifest.txt /tmp/locked.txt` lists deps install would resolve fresh — silent drift. Mirror the check for other ecosystems using the sync commands under Lockfile Hygiene. Show both outputs in the finding as evidence of non-reproducible installs.
2. Workflow script-injection walkthrough (pure YAML reading):
   1. Locate a workflow with `on: pull_request_target` (or any `pull_request` type) whose `run:` contains `${{ github.event.pull_request.title }}`.
   2. Quote the exact line in the report, then show the resulting script after substitution for benign payload `hello`: `echo "Thanks for the PR, hello"` — then for payload `hi'; whoami #`: `echo "Thanks for the PR, hi'; whoami #"` demonstrating command insertion while explaining this executes on the repository's runner during a fork-triggered run.
   3. Live-fire confirmation is requires network + authorization: open a fork PR with payload title on an approved staging mirror only, observe job log output, revert immediately.
3. Unpinned-action replaceability check (offline):
   1. From inventory, list every `uses:` with tag ref.
   2. For one example, run `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>` — record that the tag currently points at some SHA and that tags are mutable upstream; the workflow would silently execute whatever that SHA becomes.
   3. Verify absence of any allowlist/SHA pinning policy file; conclude replaceability statically.
4. Typosquat/internal-name triage (mostly offline):
   1. For each suspicious dep name, search first-party usage (grep) and internal docs; zero usage plus public-registry-only availability = confusion/squat candidate.
   2. Registry metadata lookup (npm view, pip index versions) is requires network + authorization; otherwise mark `Needs-Review`.
5. Network-gated scanner sweep — requires network + authorization:
   1. Run the matrix column commands per ecosystem at repo root (`npm audit --omit=dev`, `pip-audit`, `govulncheck ./...`, `cargo audit`, `bundler-audit check`, `composer audit`, `dotnet list package --vulnerable`, `mvn org.owasp:dependency-check-maven:check`, `osv-scanner -r .`; where a CLI has evolved, run base form and consult `--help`).
   2. Attach raw scanner output; do not paraphrase severities. Cross-check Critical/High advisories against reachable sinks via `skills/code/injection/SKILL.md` before final severity.

## Remediation

### Pinning Policies Per Ecosystem

- npm/yarn/pnpm: ship `package-lock.json`/lockfile; install in CI and prod with `npm ci`; set `"save-exact": true` or use exact versions for direct deps of applications.
- Hash-locked installs where the ecosystem supports them: `pip install --require-hashes -r requirements.txt` (hashed requirements file), `cargo build --locked`, `go mod verify` — a changed transitive dep becomes a build failure instead of a silent update.
- Python: pin transitively in deployed contexts — `flask==3.0.3`, generated via `pip freeze` or lock tools (`poetry.lock`, `uv.lock`); never bare names in prod requirements.
- Go: commit `go.mod` + `go.sum`; verify with `go mod verify`.
- Gradle: enable locking:

```groovy
dependencyLocking {
    lockAllConfigurations()
}
```

- Maven: no first-class lockfile — pin explicit versions, avoid ranges like `[1.0,2.0)`, consider a BOM for coordination.
- .NET: PackageReference projects commit `packages.lock.json` and restore with `dotnet restore --locked-mode`.
- Composer/Bundler/Cargo: commit the lock; install with `composer install`, `bundle install --deployment` semantics (or frozen config), `cargo build --locked`.

GitHub Actions — SHA-pin every third-party action, keep the version as a comment:

```yaml
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

Resolve SHAs yourself (`git ls-remote <repo> refs/tags/<tag>`); Dependabot/Renovate maintain these automatically once configured.

### Automated Update Bots

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Renovate equivalent (`.renovaterc.json`):

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "rangeStrategy": "pin",
  "lockFileMaintenance": { "enabled": true }
}
```

### Private-Registry Scoping

```ini
# .npmrc — route internal scope to internal registry; everything else stays public
@acme:registry=https://npm.acme.internal/
//npm.acme.internal/:always-auth=true
save-exact=true
```

Python: set `[global] index-url = https://pypi.acme.internal/simple` in `pip.conf`/CI. Avoid `extra-index-url` for private feeds: pip unions sources without preferring the private one, so internal-named packages must also be claimed by scoping or name policy.

Go:

```bash
go env -w GOPRIVATE='scm.acme.internal/*'
```

GOPRIVATE excludes matching module paths from public proxy fetches and checksum-db queries — required both to prevent leaks and confusion.

.NET: configure NuGet Package Source Mapping in `nuget.config` so internal prefixes (`Acme.*`) resolve only from the internal feed; ensure the public source's patterns do not also match internal IDs (consult Microsoft's docs for exact pattern-matching semantics).

Composer: declare internal VCS repositories explicitly and keep plugin execution allow-listed (`composer config allow-plugins.<name> true` only for reviewed plugins).

### CI Hardening Checklist

```yaml
# Top-level least privilege in every workflow
permissions:
  contents: read
```

- Use `pull_request`, not `pull_request_target`, for anything building/testing PR code. Reserve `pull_request_target` for label/comment bots that never execute PR-derived input.
- Never interpolate `github.event.*` into `run:`; pass through `env:` and expand quoted (`"$VAR"`).
- Pin third-party actions by full SHA.
- Do not attach self-hosted runners to public repos or fork-reachable workflows; use ephemeral isolated runners if unavoidable.
- Give deploy jobs scoped short-lived credentials (OIDC) instead of account-wide static keys; attach them via protected environments:

```yaml
jobs:
  deploy:
    environment: production   # protect this environment with required reviewers in repo settings
    runs-on: ubuntu-latest
```

- Name artifacts uniquely per producing job; treat downloaded artifacts as untrusted input downstream.
- Key caches on content digests rather than attacker-influenced strings; audit restore-key fallbacks.
- Generate SBOMs into release artifacts using syft or cyclonedx-cli, and sign artifacts/images with cosign.

### GitHub organization settings audit (where the code and the credentials meet)

- Enforce 2FA for all org members; base repository permissions set to read/none — write is granted per-repo, not org-wide.
- Audit-log streaming exported to external storage; a log only the suspect can delete is not evidence.
- Automation uses fine-grained personal tokens or deploy keys scoped per repo — classic PATs with full `repo` scope are shared-house-keys.
- Third-party OAuth applications allow-list reviewed quarterly; each installed app lists exactly what it can read.

## Verification & Validation

GIVEN/WHEN/THEN:

1. GIVEN a synced manifest+lockfile WHEN `npm ci` runs THEN install succeeds byte-identically across runs; negative test: bump a version in `package.json` without updating the lock and confirm `npm ci` fails loudly (drift detection intact).
2. GIVEN routine dependency-update automation WHEN a legitimate patch-bump PR updates manifest AND lock together THEN all gates pass and merge proceeds — proving hardening does not block normal flow.
3. GIVEN the fixed greeting workflow on `pull_request` WHEN a fork PR is titled `hi'; whoami #` THEN the log shows the literal string echoed, no command output from `whoami`.
4. GIVEN all actions SHA-pinned WHEN re-running the unpinned-action regex over `.github/workflows/` THEN zero hits while the SHA-positive-control regex returns hits for each pinned step.
5. GIVEN locked-mode restores WHEN CI executes `npm ci` / `dotnet restore --locked-mode` / `composer install` THEN builds pass without network resolution drift; negative test: delete one lock entry and confirm the strict installer aborts.

Regression mechanism (honest description): there is no built-in "allowlist" that auto-blocks new dependencies. Enforce review-by-diff instead:

```
policy:
  when a PR diff touches any of:
    package.json|package-lock.json|requirements*.txt|pyproject.toml|poetry.lock|uv.lock|
    go.mod|go.sum|pom.xml|gradle.lockfile|*.csproj|packages.lock.json|
    composer.json|composer.lock|Gemfile*|Cargo.*
  then:
    - CODEOWNERS assigns @security-reviewers to the PR (path-based rule)
     - branch protection requires their approval before merge

   - commit-signing verification: branch protection (or server-side hooks) marks
     unsigned commits as untrusted for protected branches. GPG/SSH-signed commits
     with `Require signed commits` enabled means a stolen token pushing directly
     still fails the gate; absent verification = every CI secret-holder is also an
     identity-forger.
    - an advisory CI job posts the dep-name diff (comm -23 old new) for reviewer context
  enforcement lives in GitHub branch protection + CODEOWNERS; the CI job informs, it does not gate alone
```

Manual checklist post-fix:

- Every application manifest has a lockfile and CI installs strictly from it.
- No workflow interpolates event data into `run:`; spot-check two workflows end-to-end.
- All third-party actions SHA-pinned with version comments.
- Registry scoping configs present and exercised in CI logs (internal fetch succeeds, public path unaffected).

Post-fix greps (expect zero hits unless stated):

```bash
rg -n 'uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(v[0-9]|main|master|latest)' .github/workflows/
rg -n 'run:.*\$\{\{.*github\.event' .github/workflows/
rg -n 'pull_request_target' .github/workflows/
rg -n 'FROM\s+[^@\s:]+:latest' --glob 'Dockerfile*' .
rg -n '(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh' .github/workflows/ Dockerfile* scripts/
```

## Severity Assessment

| Finding | Band | Notes |
|---|---|---|
| Known-exploited/vulnerable dependency with reachable sink | Critical–High | Confirm reachability with `skills/code/injection/SKILL.md` (or govulncheck symbol output for Go) before assigning Critical |
| Vulnerable dependency, sink unreachable / unused codepath | Medium–Low | Honest downgrade; still file and track — reachability can change with one commit |
| CI secret exposure via `pull_request_target` or injection, prod credentials in scope | Critical | Fork-triggered authenticated execution + prod secrets = account takeover path |
| Same but non-prod/scoped tokens only | High–Medium | Scope by blast radius of exposed values |
| Unpinned third-party actions | Medium | Context-dependent: repo visibility, runner sensitivity, whether secrets are in the same workflow |
| Missing lockfile (application) / lock drift | Medium | Non-reproducible installs undermine every downstream control; Low for pure libraries whose consumers lock |
| Typosquat/confusion preconditions without confirmed abuse | Medium–Low | Precondition finding; raise if internal names already resolve publicly |
| EOL runtime/base image alone, no known vuln mapped | Low–Medium | Hygiene debt; escalates when paired with internet-facing deploy |

CVSS v3.1 examples (illustrative vectors — score with your organization's calculator):

- Vulnerable dependency with reachable network-facing sink: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Critical band).
- CI secret exposure to forks with prod creds: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (Critical band due to scope change).
- Unpinned action on a private repo without secrets in that workflow: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L` (Medium band).

Always report CWE-1104 (unmaintained third-party components) for EOL findings and CWE-494 (download of code without integrity check) for unpinned/curl-bash/artifact-tampering classes.

## Common False Positives

- Dev-only vulnerable dependencies: scope to production install paths before severity assignment (`npm audit --omit=dev`, extras groups in Python); still fix, downgrade severity.
- Floating ranges WITH a committed lockfile AND strict installs (`npm ci`): reproducible today; flag as hardening note, not a drift finding.
- Private registries legitimately shadowing same-named public packages with scoping configured: intended design.
- Vendored trees WITH embedded provenance (Go `vendor/modules.txt`, checksums manifest, documented update process): acceptable pattern.
- Renovate/Dependabot branches tripping "unused dependency" or name-similarity heuristics: verify against base branch state.
- Test-fixture repositories intentionally installing vulnerable packages (audit-tool fixtures, e2e repros): exclude unless they ship to prod.
- Monorepo generated lockfiles appearing out-of-sync to naive diffing when workspaces hoist deps: validate with the ecosystem's own sync command before filing.
- Internal package names coincidentally similar to public ones where your organization owns the namespace and scoping is enforced.

## References

- CWE-1104: Use of Unmaintained Third Party Components
- CWE-494: Download of Code Without Integrity Check
- OWASP Top 10 2021 A06 – Vulnerable and Outdated Components: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- OWASP Cheat Sheet Series (see its dependency-management sheet): https://cheatsheetseries.owasp.org/
- OSV database and osv-scanner: https://osv.dev , https://github.com/google/osv-scanner
- Dependabot project root: https://github.com/dependabot
- GitHub Actions security hardening guidance (docs.github.com, search "Security hardening for GitHub Actions"): https://docs.github.com/
- npm audit CLI docs: https://docs.npmjs.com/
- pip-audit: https://github.com/pypa/pip-audit
- Go vulnerability database and govulncheck: https://go.dev/security/vuln
- cargo-audit / RustSec: https://github.com/rustsec/rustsec
- bundler-audit: https://github.com/rubysec/bundler-audit
- Composer docs: https://getcomposer.org/
- .NET package management docs (learn.microsoft.com, search "dotnet list package --vulnerable", "package source mapping"): https://learn.microsoft.com/
- Renovate docs: https://docs.renovatebot.com/
- SBOM tooling: syft https://github.com/anchore/syft , CycloneDX https://cyclonedx.org/
- Artifact signing: cosign (Sigstore) https://github.com/sigstore/cosign
- Log4Shell advisory entry: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- xz backdoor advisory entry: https://nvd.nist.gov/vuln/detail/CVE-2024-3094
