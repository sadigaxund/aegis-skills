# Supply Chain — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, scanner matrix, and remediation recipes.

## How this class emerged

Software has been assembled from other people's code since before the web; what
changed is scale and anonymity. Shared-code archives became automated package
registries in the late 2000s and early 2010s, and resolution rules ("give me
version ^1.2 of anything") turned installs into open-ended network requests to
machines nobody on the team had ever vetted. The industry kept a mental model of
"dependencies I chose" long after the truth became "transitive graphs with
thousands of nodes, resolved at build time by whoever answers first."

Attackers followed the audience. The recurring shapes are now well understood:
maintainer accounts hijacked to push malicious releases; popular projects whose
original authors moved on leaving unpatched flaws behind; typosquatted names
harvesting mistyped installs; "dependency confusion," where an internal-only
package name gets registered publicly so corporate builds resolve the attacker's
copy; install-time lifecycle scripts that execute whatever code just arrived;
and CI/CD pipelines that hand repository secrets to code submitted by strangers.
The xz backdoor disclosed in March 2024 — an upstream compression library
subtly sabotaged over months of social engineering — demonstrated that even
low-level, slow-moving components are targets.

Two institutional responses define current practice. First, *lockfiles*: commit
the exact resolved graph as bytes, so every build consumes identical inputs.
Second, *provenance*: signed statements about where and how an artifact was
built (SBOMs, attestations, signing), pushed into mainstream policy after a
2021 US executive order directed federal buyers toward software supply-chain
integrity requirements. Neither is optional anymore; both appear throughout
SKILL.md's checks.

## Anatomy: one name, one install, one execution

The minimal shape needs only a manifest and a registry:

```json
{
  "name": "checkout-service",
  "dependencies": {
    "left-pad-utills": "^1.0.0"
  }
}
```

Walkthrough of one `npm install` on a fresh machine:

1. No lockfile pins the graph, so the resolver asks the public registry for
   `left-pad-utills` — a transposed-letter typosquat of a real package.
2. The attacker's package exists (they published it weeks ago), declares a
   higher compatible version, and wins resolution.
3. Its `package.json` carries `"postinstall": "node bootstrap.js"`. Package
   managers run lifecycle scripts automatically at install time — no import,
   no function call, no review.
4. `bootstrap.js` reads `.npmrc`, environment variables, and SSH keys, and
   posts them to an external host from inside a developer's laptop or a CI
   runner that holds deploy credentials.
5. Nothing "broke." The build succeeded faster than usual. The exfiltration
   left through the same egress every dependency already uses.

The same anatomy recurs across the attack classes, only the boundary changes:

```yaml
# CI executes attacker-authored text with repository secrets present
on: pull_request_target
steps:
  - run: echo "Thanks, ${{ github.event.pull_request.title }}"
```

A pull-request title is data; interpolated straight into `run:` it becomes
grammar — the shell parses it, so a title containing quotes and semicolons runs
commands inside your runner with secrets in scope. This is injection, but the
injection lives in the build layer: the source-to-sink path runs from a fork PR
to your production credentials without touching application code.

Lockfiles work because they convert "whatever the registry serves today" into
"exactly these bytes"; hash-pinned installs go further and make any changed
transitive dependency a loud build failure instead of a silent update. SHA-
pinning third-party CI actions works identically — tags are mutable pointers,
commit hashes are not.

## Why naive fixes fail

One subsection because the failure modes rhyme across all sub-types:

- **"We ran a vulnerability scanner, so we're safe."** Offline absence of scan
  results proves nothing when you could not reach the advisory database, and a
  clean scan says nothing about a compromised *latest* release published this
  morning. Scanners answer "known-vulnerable versions?"; they do not answer
  "who controls these names?"
- **Pinning direct dependencies only.** Ranges like `^1.2.3` float transitives;
  without a lockfile the attacker owns the middle of the graph. And pinning
  while CI still runs `npm install` (not `npm ci`) rebuilds resolution anyway.
- **Blocking all install scripts.** Breaks legitimate native builds and trains
  the team to bypass their own control. Triage per-script instead: narrow build
  helpers pass; curl-to-registry, base64 blobs, and credential-path writes do
  not.
- **Private registries without scoping.** Configuring an internal mirror helps
  only if internal names are scoped to it (`@scope:registry=...`, NuGet package
  source mapping, `GOPRIVATE`). pip's `extra-index-url` unions sources without
  preferring yours — confusion preconditions survive the migration intact.
- **Trusting tags in CI actions.** `uses: some/action@v4` follows whichever
  commit the tag points to forever after; only full-length SHA pinning freezes
  behavior against upstream compromise.
- **Assuming fork PRs are sandboxed.** Workflows triggered by `pull_request_target`
  run from the base branch with secrets available; the sandbox assumption dies
  the first time such a workflow checks out or interpolates head-derived input.
- **Vendoring as a synonym for safety.** Vendored trees without embedded
  provenance (`vendor/modules.txt`-style version records or checksum manifests)
  are unattributable tarballs with extra steps.

## Common misconceptions

1. "Our code is proprietary, so nobody studies our dependencies." Attackers do
   not read your code; they read the registries your resolver trusts. Dependency
   confusion targets exactly the assumption that internal names are invisible.
2. "Lockfiles are for reproducibility, not security." They are both: the lock
   is also the audit artifact — diff it and you know precisely which bytes
   changed hands between two builds.
3. "Known-vulnerable means exploitable." Reachability decides severity: a
   vulnerable function never called is hygiene debt, while one reachable from a
   request handler can be Critical. Downgrade honestly, never delete.
4. "Typosquatting only catches careless typists." Lookalike Unicode, plural/singular
   forms, dropped hyphens, and `.js` suffixes catch careful readers too; edit-distance
   screening on new dependencies exists because eyeballs fail.
5. "CI secrets are safe because workflows are reviewed." Fork-triggered workflows
   execute stranger-authored content by design; review covers the workflow file,
   not the PR title flowing through it.
6. "SBOM equals security." An inventory creates accountability and enables fast
   impact analysis, but an unsigned, unverified SBOM is a menu, not a control.
7. "Renovate/Dependabot will keep us safe." Update bots shrink the window on
   known advisories; they neither screen new names for squatting nor pin your
   actions by SHA unless configured to.

## How professionals think about it today

Modern practice models the build as three layers with trust questions at each
boundary (declared → resolved → built-and-shipped) and maps every attack class
onto one boundary. The taxonomy mirrors SKILL.md's sections:

| Attack class | Boundary crossed | Defining control |
|---|---|---|
| Exploit stale content | inside resolved bytes | SCA scanning + EOL-runtime flags |
| Poison resolution | declared → resolved | lockfiles, strict install modes, scoping configs, name screening |
| Hijack the builder | resolved → executed | script triage, action SHA-pinning, workflow-injection hygiene, isolated runners |
| Tamper output | after build | SBOM generation, artifact/image signing, attestation verification |

Severity thinking follows credential proximity: fork-triggered execution plus
production credentials is Critical regardless of payload elegance; missing
lockfiles are Medium because they undermine auditability rather than grant
access directly; EOL runtimes alone stay Low–Medium until paired with exposure.
Report offline conclusions as heuristics and mark network-gated verification
explicitly — honesty about evidence boundaries is part of the finding.

## Read next

In `../SKILL.md`: **Mental Model** (three layers, four attack classes),
**What To Check** (inventory-first procedure), **Where To Look** (artifact map),
**Patterns & Signatures** (ripgrep sweeps, workflow anti-patterns), **Taint
Tracing Guidance** (workflow sources/sinks), **Exploitation & Reproduction**
(offline drift demos), **Remediation** (pinning policies per ecosystem),
**Severity Assessment**, **Common False Positives**, **References**.

Sibling modules: `../secrets-data-exposure/SKILL.md` (credentials echoed into
CI logs), `../injection/SKILL.md` (reachable sinks deciding exploitability of
vulnerable deps), `../configuration-hardening/SKILL.md` (container base-image
posture), `../malicious-code/SKILL.md` (analyzing hostile code you did find),
`../deserialization/SKILL.md` (gadget chains reached through stale libraries).
