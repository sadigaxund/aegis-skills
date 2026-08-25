# Deliberate Malice Detection — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind deliberate-malice hunting; SKILL.md carries the fences, sweep
blocks, verdict tables, and remediation recipes.

## How this class emerged

The idea of code that betrays its user is older than networking. The term
"Trojan horse" entered computer-security vocabulary in the early 1970s —
recorded by James P. Anderson in the security-planning literature of that era,
introduced by Dan Edwards — for programs that perform a useful service while
exploiting the rights of their user in ways never intended. Through the
mainframe and PC decades the dominant shapes were insider acts: a logic bomb
gated on an employment end-date, a hidden maintenance account, a payroll
routine quietly mailing itself out. Detection meant auditing your own people's
code, and the audit trail was short.

Two shifts turned this niche problem into an industry-scale one. First,
software stopped being something you wrote and became something you *assemble*:
public package registries (npm, PyPI, RubyGems, crates.io and their peers,
maturing through the late 2000s and 2010s) replaced copying source with
resolving thousands of machine-chosen downloads at install time. Second,
resolution rules made installs open-ended network requests: `^1.2` means
"whatever best matches today," so a compromised upstream release flows into
every dependent tree automatically, with no human reading the diff.

Attackers followed the audience, and the recurring routes are now well mapped:

- **Maintainer-transition hijacks.** Popular projects outlive their authors'
  attention, and handing maintainership to an eager stranger is normal,
  healthy open-source behavior — exactly the moment a payload can enter. The
  event-stream incident (npm, 2018) is the canonical case: a very widely
  depended-upon library changed hands, gained a small obfuscated helper
  dependency weeks later, and that helper carried a payload targeting
  bitcoin-wallet users of one specific application built on it. It surfaced
  through behavioral anomaly at the far end, not any scanner.
- **Typosquat/confusion publishes.** Look-alike names catch mistyped installs;
  scoped-name impersonation and swapped separators catch careless configuration.
- **Install-time and build-time execution.** npm lifecycle scripts, Python
  `setup.py`, Ruby native-extension gemspecs, MSBuild targets/props imports,
  and Rust `build.rs` all execute attacker-controlled code on developer
  machines and CI runners before anyone reviews the package body.
- **Build-output tampering.** The xz/liblzma backdoor disclosed in March 2024
  showed the far end of the spectrum: an attacker spent years patiently earning
  maintainership of a low-level compression library, then shipped release
  tarballs whose build process injected logic interfering with OpenSSH
  authentication on affected distributions — found only because one engineer
  chased a few hundred milliseconds of unexplained SSH latency.
- **Source-level concealment.** Research published in 2021 ("Trojan Source")
  showed bidirectional text controls and invisible characters making reviewed
  source render one way while compilers parse another; homoglyph identifiers
  (a Cyrillic `а` inside an otherwise-Latin name) defeat visual diff review.

The institutional responses define current practice: lockfile diff review so
dependency changes arrive as visible bytes rather than silent resolutions;
install-script allowlists so running code at install time becomes an explicit,
reviewed decision; provenance frameworks (SLSA, in-toto, Sigstore) that sign
statements about who built what from which source; and behavioral scanners that
profile what packages *do* rather than what they claim. This module teaches the
static hunting layer underneath all of it.

## Anatomy: one helper package, one install hook

The minimal implant needs only a manifest and one script. The description below
is anatomy only — inert, no working payload:

```json
{
  "name": "string-leftpad",
  "version": "1.0.1",
  "description": "Tiny string padding helper",
  "scripts": { "postinstall": "node bootstrap.js" }
}
```

```js
// bootstrap.js — the whole implant, four lines
const cp = require('child_process');
const cmd = Buffer.from('c29tZS1zaGVsbC1jb21tYW5k', 'base64').toString();
const secrets = Object.entries(process.env)
  .filter(([k]) => /KEY|TOKEN|SECRET|PASS/.test(k))
  .map(([k, v]) => k + '=' + v).join('&');
cp.execSync(cmd + ' ' + secrets);
```

Failure walkthrough, step by step:

1. **Entry.** A routine patch bump adds `string-leftpad@^1.0.0`. No lockfile
   pins the tree — or the reviewer rubber-stamps the lock diff — so resolution
   accepts 1.0.1. The PR shows a README change; nobody expands the tarball.
2. **Trigger.** `npm install` runs `postinstall` automatically. No import, no
   function call, no test exercises it. The code executes on every developer
   laptop and CI runner — machines holding deploy tokens, cloud keys, git
   credentials.
3. **Concealment ladder.** The command travels base64-encoded, so grepping for
   shell tools finds nothing; credential names exist only inside a regex
   filter; the exfil destination rides the egress every dependency already has.
4. **Capability.** Decoded, the blob posts harvested secrets outward.
   Harvest-plus-egress in one installed file — the combo SKILL.md's Mental
   Model scores Strong however weak either half looks alone.
5. **Aftermath.** Nothing crashes; builds get marginally faster. The team
   learns of it weeks later from an incident, not a scan — no stage ever looks
   broken.

The same anatomy recurs with the boundary moved: in `setup.py` at pip-install;
in `build.rs` at compile time on every contributor machine; as a hidden route
(`req.get('x-debug')`) it skips clients entirely and persists server-side
across releases; as a non-sample `.git/hooks` script it lives outside version
control, invisible in diffs indefinitely. Constant throughout: dangerous
capability, deliberate concealment, absent provenance.

## Why naive fixes fail

One subsection because the failure modes rhyme across all sub-types:

- **"Delete it and move on."** Removing a Likely-malicious artifact without
  preserving it (copy plus hash) destroys incident evidence, and without
  credential rotation the harvested tokens stay fully alive. Removal is
  hygiene; rotation is remediation.
- **Blocking all install scripts.** Breaks legitimate native builds, teaches
  the team to bypass their own policy, and does nothing about compile-time
  surfaces (`build.rs`, proc-macros) or runtime backdoors. Triage beats bans.
- **Single-line greps as the whole answer.** A decode primitive here, an exec
  sink there, in different files: per-line signatures never connect them.
  SKILL.md's file-list intersection technique exists for exactly this.
- **Trusting human review of diffs.** Homoglyph identifiers render identically;
  time bombs sit behind future dates; dormant env-gates read like feature
  flags. Review catches what renders wrong, not what is written wrong.
- **"The registry/scanner would catch it."** Registries publish, they do not
  audit content; advisory scanners answer "known-vulnerable versions?", not
  "did this morning's release gain a postinstall?" Fresh implants are
  zero-days by definition.
- **Pinning direct dependencies only.** Floating ranges still resolve
  transitives; event-stream-class payloads rode a helper package deep in the
  graph. And excluding installed/vendored trees wholesale from sweeps is worse:
  the installed path is where hooks actually execute — dist/build exclusions
  belong to minification-noise scoping (F01–F05), not to skipping the tree.
- **Obfuscation as the sole signal.** Minified bundles are legitimate under
  `dist/`; conversely, perfectly readable code can hide
  `if (header === MAGIC) grantAdmin()`. Concealment is one triangle leg, never
  the verdict by itself.

## Common misconceptions

1. "Malware looks weird." Working implants look boring — a padding helper, a
   compat shim, a telemetry client. Capability hides inside mundane purpose.
2. "Popular packages are safe." Popularity is the attacker's targeting metric,
   not a safety property; the canonical npm incident hit at peak adoption.
3. "Open source means somebody read it." Dependents consume APIs, not
   internals; a widely used package can go years unread until its handover.
4. "Registries vet what they host." They verify identity and availability,
   not intent; publishing is instant and global by design.
5. "We only use reputable dependencies." Your exposure is the transitive graph
   resolved at build time — reputations you never evaluated, chosen by a solver.
6. "A clean static sweep proves we're clean." Negative results are only as good
   as the detector; SKILL.md's canary drill (VV4) exists because detectors rot.
7. "This is a big-company problem." The core controls (lockfile diffs, script
   allowlists, provenance checks) are cheap, and the trust gradient reaches
   every laptop identically.

## How professionals think about it today

Modern practice treats malice classification as evidence work, not pattern
matching: every finding must carry capability, concealment, and provenance
analysis, with the verdict derived rather than asserted. The taxonomy below
maps one-to-one onto SKILL.md's check order:

| Sub-type (SKILL.md check item) | Intent tell | Primary detection surface |
|---|---|---|
| Obfuscation ladders (item 1, F01–F07) | encoding depth unjustified by purpose | encoded-literal length heuristics, decode primitives, homoglyph scans |
| Network indicators (item 2, F08–F11) | egress destinations no feature needs | webhook/paste fragments, raw IPs + odd ports, DNS-label shapes, TLS-off adjacency |
| Behavioral combos (item 3, F12–F16) | harvest paired with send | same-file intersections of credential reads and egress calls |
| Application backdoors (item 4, F17–F18) | privilege grants keyed on secrets, dates, env flips | route tables, header comparisons, date gates, default-credential fallbacks |
| Repo-local automation (item 5) | executable content living outside version control | `.git/hooks`, IDE task runners, mid-pipeline curl-to-shell inserts |
| Install/build-time surfaces (item 6, F19a–c) | code executing before any review | lifecycle manifests, setup.py, build.rs/proc-macros, gemspecs, MSBuild imports |
| Vendored blobs (item 7, F20–F21) | behavior unverifiable by reading | binaries lacking source+recipe+checksum; LFS pointer anomalies |

Severity is framed as trust impact rather than exploitability scoring: a
credential-harvest combo in an installed path implies attacker access to every
machine that ran the install, outranking any elegance of payload. Two
disciplines separate professional practice from keyword hunting: *combos over
singles* (any two triangle legs escalate; isolated indicators are noise), and
*evidence chains* (`file:line` anchors, decoded-payload excerpts, hashes) that
make every verdict reproducible — unreproducible findings are how both false
accusations and missed implants happen.

## Read next

In `../SKILL.md`: **Scope & Objectives** (threat-origin table), **Prerequisites
& Vocabulary**, **Mental Model** (capability/concealment/purpose triangle,
trust gradient), **What To Check** (the eight-item hunt order), **Where To
Look** (placement-economics map), **Patterns & Signatures** (fence library
F01–F21 plus the paste-ready sweep block), **Taint Tracing Guidance** (inverted
taint: repository content treated as attacker-controlled), **Exploitation &
Reproduction** (inert canary tabletop lab), **Remediation** (verdict-class
response ladder and prevention set), **Verification & Validation** (VV1–VV5),
**Severity Assessment** (trust-impact classes), **Common False Positives**,
**References**.

Sibling modules: `../supply-chain/SKILL.md` (lockfile mechanics, workflow
injection, provenance verification — the dependency-inventory commands this
module deliberately omits), `../secrets-data-exposure/SKILL.md` (storage
hygiene for credentials implants harvest), `../crypto/SKILL.md` (TLS
configuration quality; this module only flags verification-disabled flags
beside suspicious egress).
