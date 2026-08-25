# Logging & Monitoring — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind journald persistence, rsyslog/auditd coverage, file-integrity
monitoring, off-host shipping, retention, and out-of-band alerting; SKILL.md
carries the exact commands, judgement tables, and remediation blocks.

## How this class emerged

Server logging is older than server security. Syslog was written in the early
1980s as part of the Sendmail project so one machine could relay messages about
another; the protocol that spread (RFC 3164 in 2001 merely documented existing
practice) sent plaintext UDP packets to port 514 with no delivery guarantee and
no sender authentication. Everything downstream inherits that bargain: syslog
was designed for convenience on a trusted LAN, then carried unchanged onto the
internet-connected hosts of the 1990s and 2000s.

Four later waves shaped what we now audit:

- **The kernel grew a memory of its own.** The Linux audit subsystem landed in
  the mid-2000s: a small set of kernel rules records identity-file changes,
  privilege use, and clock shifts at syscall depth — things userspace daemons
  cannot witness reliably. It stayed optional tooling: `auditd` still ships
  installed-or-absent depending on distro and image builder, never guaranteed.
- **systemd centralized capture — with a conditional default.** From the early
  2010s, `journald` collected nearly every message into a binary journal. Its
  default storage mode (`auto`) persists to disk *only if* `/var/log/journal`
  existed at daemon start; otherwise everything lives in tmpfs and dies at
  reboot. Countless minimal images and slimmed containers therefore run
  "logged" systems whose history evaporates every boot.
- **Integrity monitoring became its own layer.** Tripwire emerged from Purdue
  research in the early-to-mid 1990s on a simple insight: an intruder who can
  edit logs can also edit binaries, so something must watch *file content*
  against a stored baseline. AIDE (first released around the turn of the
  millennium) carried that baseline-and-compare model into open source.
- **Shipping became mandatory doctrine.** As intrusion reports accumulated,
  one pattern repeated: attackers with root erase their own traces — truncate
  auth logs, vacuum journals, clear histories. Guidance bodies responded by
  treating local-only logging as no logging at all, and formalizing "collect
  centrally" advice such as NIST SP 800-92 (2006) and successive CIS
  benchmark sections.

The recurring lesson: every logging component defaults to *convenient*, not
*durable*. Defaults bite precisely because they are reasonable for a developer
laptop and quietly wrong for an internet-reachable server.

## Anatomy: one silent host, one invisible breach

A minimal generic weak configuration needs nothing but absence. Picture a stock
minimal cloud image serving a web app:

```
# /etc/systemd/journald.conf          # untouched: #Storage=auto applies
# ls /var/log/journal                 # -> No such file or directory
# systemctl is-active rsyslog         # -> inactive (image slimming removed it)
# dpkg -l auditd                      # -> no packages found
# command -v aide                     # -> not found
# grep -R '@@\|omfwd' /etc/rsyslog*   # -> nothing (and rsyslog isn't running anyway)
```

Walkthrough of how this fails:

1. A credential-stuffing campaign hits sshd for days. Every failed attempt is
   written only to the runtime journal (`/run/log/journal`, tmpfs).
2. The attacker guesses right during a maintenance window reboot two weeks
   later: pre-reboot history is gone, so nobody can ever establish how long
   guessing had been underway or from where.
3. Post-exploitation proceeds silently: `useradd` of a rogue account, sudoers
   edit, authorized_keys write — none recorded anywhere, because auditd does
   not exist to watch `/etc/passwd` or `/etc/shadow`.
4. The attacker replaces a CGI helper binary in the webroot with a trojaned
   version. No log line announces it; without integrity monitoring, content
   itself is unwatched.
5. Cleanup is trivial: `journalctl --vacuum-time=1s` wipes even the current
   boot's traces. Local evidence existed solely at the attacker's discretion.
6. Nobody notices until a customer reports fraud — the classic unbounded dwell
   time this module exists to bound.

No exploit chain appears above beyond one guessed password. Each step was
silent because a *layer* was missing — which is why SKILL.md scores gaps by
layer rather than by individual missing package.

## Why naive fixes fail

- **Setting `Storage=persistent` and walking away.** Persistence also needs
  the store directory created with correct ownership plus a journald restart;
  verifying with `journalctl --list-boots` after a real reboot is the only
  proof. Config text alone has fooled auditors for years.
- **Installing auditd without loading rules.** Rules files under
  `/etc/audit/rules.d/` are inert text until compiled into the running kernel
  (`augenrules --load`). File presence earns no credit; only `auditctl -l`
  output counts.
- **Enabling `-e 2` immutability on day one.** The anti-tamper lock converts
  every future rule change into a maintenance-window reboot — teams respond by
  disabling the whole subsystem. Load watches first, validate for weeks, lock
  last, and document the unlock procedure before enabling.
- **Global `execve` auditing "for completeness".** Every process launch logged
  means gigabytes per day, disks full, real events buried. Coverage comes from
  targeted watches of critical paths, not breadth.
- **`ForwardToSyslog=yes` without a consumer.** Forwarding to a nonexistent or
  stopped rsyslog drops messages on the floor; the pipeline must be proven
  end-to-end with a test `logger` message landing in files AND journal AND
  collector.
- **Counting single-`@` UDP forwarding as off-host shipping.** Fire-and-forget
  transport loses records silently under load and is spoofable besides. It
  technically leaves the box; it does not reliably arrive anywhere.
- **Building the AIDE baseline on today's host and trusting it forever.** If
  the host is already compromised, the baseline blesses the malware. And after
  every legitimate package operation the database needs review-plus-promotion,
  or each patch night floods false alerts until the channel is muted.
- **Buying headroom by deleting evidence.** `journalctl --vacuum-*` trades
  forensics for availability. Caps (`SystemMaxUse`) and rotation shrink logs
  forward; deletion destroys them backward.

## Common misconceptions

1. "`rsyslog` is absent, so nothing logs." Modern images often rely on journald
   alone — legitimate when the journal is persistent AND something ships it.
   Absence of ALL consumers is the finding, not absence of one component.
2. "Commented `#Storage=auto` means broken." `auto` is persistent whenever the
   directory exists — many cloud images pre-create it. Check the directory and
   `--list-boots` before flagging; conversely explicit `volatile` is always
   real.
3. "Rules in `/etc/audit/rules.d/` prove auditing works." Only loaded kernel
   state audits anything. Present-but-unloaded rules are the most common
   auditd false pass.
4. "`-e 2` makes audit rules tamper-proof." It locks live edits until reboot —
   raising cost, not removing power. Root who reboots edits freely. It is a
   speed bump calibrated for the cleanup phase of an intrusion, valuable but
   not magic.
5. "Logs on a second disk are off-host." Same host means same root, same wipe.
   Off-host means separate infrastructure the monitored box cannot silence.
6. "A green log dashboard means monitoring works." An agent shipping only
   container stdout or metrics while auth.log goes unread satisfies no threat
   model — glob coverage of the AUTH stream is the check, not liveness.
7. "Silence means all is well." Attackers strip telemetry first; a host that
   stops emitting is louder than one emitting errors. Absence-of-events over N
   hours is itself the alert.

## How professionals think about it today

Modern practice reads telemetry as six defensive layers; every gap maps to one,
and severity follows chains across layers. The taxonomy mirrors SKILL.md's own
sections:

| Layer | Domain | Typical gap | Defining control |
|---|---|---|---|
| Capture | journald persistence, rotation, headroom | volatile-only journal, unrotated gigabyte files | persistent store, caps, working logrotate |
| Coverage | the should-be-logged checklist | auth stream swallowed by minimal configs | positive `authpriv.*` selector verified end-to-end |
| Depth | auditd + survival knobs | package absent, rules unloaded, tiny ring | baseline watch set, rotate policy, space actions |
| Integrity | AIDE / osquery FIM | stale or absent database, blessed malware | fresh db age, webroot watches, promotion discipline |
| Survival | off-host shipping, retention | nothing forwards; UDP-only; short windows | TCP/TLS/RELP forwarding, WORM archives |
| Response | out-of-band alerting + triage | alerts land on the monitored host | paging infra on separate failure domains |

Two axioms drive scoring: local-only logs are attacker-wipeable, and unread
logs are unwritten logs. Silence-as-signal belongs to Response: freshness
checks at the collector turn a scrubbed host from invisible into an alarm.

## Read next

In `../SKILL.md`: **Scope & Objectives** (eight domains in priority order),
**Prerequisites & Vocabulary**, **Mental Model** (attack-action vs telemetry-
layer table), **What To Check** (thirteen numbered sections from journald
persistence through incident-triage quickstart), **Where To Look** (artifact
map plus paste-ready sweep), **Patterns & Signatures** (config-as-code greps),
**Taint Tracing Guidance** (exposure × gap matrix), **Exploitation &
Reproduction** (D1–D4 read-only proofs), **Remediation** (F1–F8 hardened
blocks), **Verification & Validation** (V1–V6), **Severity Assessment**
(detection-absence anchors), **Common False Positives** (managed-node logging,
cloud-agent globs).

Sibling modules: `../linux-baseline/SKILL.md` (clock sync and the entry points
whose events you are recording), `../firewall-edge/SKILL.md` (drop-log rule
design feeding the coverage checklist), `../host-secrets/SKILL.md` (secrets
that must never flow INTO these logs), `../updates-patching/SKILL.md` (whether
known flaws in the logging stack itself are fixed), `../tls-proxy/SKILL.md`
(the edge whose access lines you correlate), `../backup-dr/SKILL.md` (canary
files and alert wiring shared with ransomware resilience).
