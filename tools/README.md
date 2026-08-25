# Deterministic Sweep Tools

## Purpose

Sweep scripts remove improvisation from the **evidence-gathering** half of a
server audit. Every run of `sweep-baseline.sh` on the same host produces the
same sections in the same order with the same commands. The agent's judgment
is spent ONLY on interpretation, which is governed by the matching check
module (`checks/server/<module>.md`). Evidence collection is mechanical;
verdicts come from module rubrics.

**Code-audit note:** only recon is scripted (`sweep-code-recon.sh`). Code
findings themselves stay grep-driven from each check module — repos differ too
much for fixed sweeps.

## Usage

```bash
./tools/run-all-sweeps.sh                 # all sweeps -> ./sweep-evidence-<ts>/
./tools/sweeps/sweep-baseline.sh          # single sweep to stdout
```

Then: for each `<name>.txt`, load the matching module file and walk its
"Patterns & Signatures" + severity tables against the captured output.
Findings are still written per `templates/finding-report.md`.

## Contract (normative for sweep authors)

1. Strictly read-only. No writes outside stdout, no service restarts, no
   installs, no firewall changes. Ever.
2. Exit code 0 even when individual commands fail — failures print
   `[cmd-failed rc=N]` and the audit continues.
3. Sections are stable IDs (`[BASE-01] ...`) — findings cite these IDs plus
   line content; agents must not invent new section names.
4. Any command that could surface secret values pipes through `redact`.
   Sweeps never print full tokens/passwords/keys.
5. Unprivileged-friendly: root-dependent sections emit `[ROOT]` notes and
   partial output instead of failing.
6. Missing tools produce `[skip: X not installed]`, not errors.

## Adding a sweep

Source `sweep-lib.sh`, call `init_sweep SLUG`, use only `hdr/run/grun/grep/
grpr/note/rootwarn/finish_sweep`, keep sections ordered to mirror their check
module, and register the script in the module's "Where To Look"/Verification
sections.
