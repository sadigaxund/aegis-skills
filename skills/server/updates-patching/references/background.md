# Updates & Patch Discipline — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind EOL posture, unattended-update automation, reboot debt, and package
minimization; SKILL.md carries the exact distro-aware commands, config shapes,
and severity anchors.

## How this class emerged

Distributions institutionalized security response early: Debian has published
coordinated security advisories against a dedicated repository since the late
1990s, and Red Hat built parallel errata streams — both establishing the pattern
every mainstream distribution still follows. A *vendor fix* is not one event but
a pipeline: advisory published → package built into a security pocket → mirror
sync → host downloads → host installs → affected process restarts → occasionally,
machine reboots. Every stage after "advisory published" requires something on the
host to work, which is why this module audits machinery rather than intentions.

Four historical realities shape the checks:

- **Enterprise version numbers lie by design.** Backporting — shipping fixed
  code inside the original version number so downstream dependencies stay
  compatible — means an old-looking package can be fully patched and a
  fresh-looking one vulnerable. Naive version comparison false-positives
  forever; changelogs are the truth.
- **Fixes do not take effect at install time.** A kernel fix sits dormant until
  reboot; glibc, systemd, and OpenSSL-linked daemons run pre-patch code until
  restarted. The gap between "packages updated" and "machines restarted" grew
  large enough to earn its own name — reboot debt — and inspired kernel
  live-patching technology (mainline since the mid-2010s) precisely because
  fleets kept deferring reboots.
- **N-day replay became the dominant breach path.** Once scanning industrialized,
  adversaries stopped needing novel research: publicly documented techniques
  replayed against unpatched hosts suffice. The 2017 self-propagating outbreaks
  that crippled organizations worldwide were built entirely on flaws vendors had
  already patched weeks earlier — disclosure happens upstream whether or not any
  given host ever hears about it.
- **End-of-life is a cliff, not a suggestion.** Past vendor support, no patches
  will ever exist; every subsequently disclosed flaw in shipped software is
  permanent. Distribution lifecycle models differ (Ubuntu LTS standard windows,
  Debian's staged stable→oldstable progression, RHEL decade-scale major-version
  maintenance, Alpine's branch-per-release cadence), so honest audits verify
  current standing rather than reciting remembered dates.

## Anatomy: automation on paper, nothing on the wire

A minimal generic weak state needs three artifacts:

```ini
# /etc/apt/apt.conf.d/20auto-upgrades          [VULNERABLE]
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
```
```
$ uname -r            # 5.4.0-150-generic   (boot-time snapshot)
$ dpkg -l 'linux-image-[0-9]*' | sort -V | tail -1
linux-image-5.4.0-169-generic                # newest on disk: fixes dormant
$ systemctl is-active rpcbind
active                                       # surface nobody justified
```

Walkthrough of how this fails:

1. **Nothing fetches or applies security fixes.** Both periodic switches off
   mean every future advisory lands in the repository while this host never
   moves; there is no notification hook either, so silence hides regressions.
2. **Even past installs are inert.** The running kernel predates nineteen builds
   of shipped packages: every kernel-side fix in between activates only at next
   boot. Dashboards fed by "updates installed" show green; the wire shows red.
3. **The exposure is reachable.** An unnecessary portmapper service from another
   computing era keeps listening because removal felt risky — attack surface is
   listening services × their unpatched flaws × who can reach them, and all
   three factors are currently maximal.
4. **The clock never stops.** Public bugs accumulate daily regardless of what
   the host does; the fix clock is simply frozen here, and the divergence grows
   silently until something exploitable overlaps something reachable.

## Why naive fixes fail

- **Enabling downloads without installs.** The RHEL-family split between
  download-only and install timers exists precisely to catch this: automation
  that stops one stage short produces logs instead of patches.
- **Trimming allowed origins.** Configuring unattended-upgrades to everything
  except the `-security` pocket misses the entire point; the security origin is
  the one line that must be present.
- **Big-bang fleet reboots.** Rebooting everything simultaneously converts a
  patch program into an outage; cohort staggering behind load balancers keeps
  availability while draining debt.
- **Automatic reboots before windows exist.** Flipping hands-off reboot onto
  stateful database nodes surprises nobody acceptably; schedule and announce
  windows first, then automate.
- **Purging before observing.** Deleting postfix while applications still shell
  out to its sendmail binary breaks mail flows discovered only in hindsight;
  disable → mask → observe a full cycle → purge last.
- **Blacklisting filesystem modules blindly.** vfat is load-bearing on EFI-booted
  hosts and squashfs underpins common container/live-media stacks; each blacklist
  line needs verification that nothing depends on it, tested on a canary first.
- **Trusting stale indexes.** Clean `apt list --upgradable` output with a
  months-old refresh stamp proves only that nobody refreshed; check freshness
  before celebrating zeros.

## Common misconceptions

1. "The version number tells me if we're vulnerable." On enterprise distros,
   backported fixes preserve original version strings across dozens of flaw
   fixes; consult changelogs before judging anything.
2. "We applied the updates, so we're protected." Installed-but-not-running fixes
   are dormant — kernels wait for reboot, daemons wait for restart; measure the
   gap, don't assume it away.
3. "Long uptime proves stability." It proves deferred remediation: every month
   of uptime extends how long known kernel fixes have been sitting unused.
4. "`is-enabled` said disabled, so it's off." Start-at-boot and running-now are
   independent states; hand-started or dependency-pulled services run happily
   while disabled.
5. "Removing unused services is too risky." Done in the reversible order — stop
   and disable, mask against every activation path, observe across a reboot
   cycle, purge last — minimization is among the safest controls available.
6. "Unattended security updates will break production." Restricting automation
   to the security pocket is deliberately conservative; the classic breakages
   come from skipping notification hooks and reboot planning, not from patching.
7. "EOL dates are negotiable vendor marketing." Past end of support, fixes
   simply cease to exist; when you cannot confirm a release's current standing,
   the honest verdict is needs-review with the exact release string.

## How professionals think about it today

Modern practice models patch discipline as two clocks — vulnerabilities
accumulate daily; fixes take effect only through a pipeline — kept synchronized
by four auditable layers. The taxonomy mirrors SKILL.md's own structure:

| Layer | Question | Typical failure signature |
|---|---|---|
| Inventory | what is installed, how stale? | nobody can say how far behind the host is |
| Automation | does anything apply fixes unprompted? | config exists but timer dead — armed on paper only |
| Restart honesty | are installed fixes effective? | kernel packages months old, uptime 400 days |
| Surface shrinkage | is unnecessary software provably off? | print/discovery/mail daemons alive on headless nodes |

Weight reachability over raw counts: one stale internet-facing daemon outranks
fifty stale internal libraries, and severity inherits from the chain
host → listener → package → advisory-stream membership → restart-gap.

## Read next

In `../SKILL.md`: **Mental Model** (two clocks, four layers, correcting
assumptions), **What To Check** (paste-ready sweep plus per-area drills),
**Where To Look** (authoritative paths per distro family), **Patterns &
Signatures** (vulnerable/fixed config pairs and state signatures), **Taint
Tracing Guidance** (listener→package→advisory chains), **Exploitation &
Reproduction** (read-only demos proving pending updates, stale kernels, absent
automation), **Remediation** (automation first, then reboot windows, then the
disable→mask→purge procedure), **Verification & Validation**, **Severity
Assessment**, **Common False Positives** (backports, pinned environments,
immutable infrastructure).

Sibling modules: `../linux-baseline/SKILL.md` (the identity and kernel knobs
that patches flow into), `../firewall-edge/SKILL.md` (reachability weighting for
every stale listener), `../service-sandboxing/SKILL.md` (containment for the
daemons you cannot yet remove), `../logging-monitoring/SKILL.md` (detecting
regressions the missing mail hook would have hidden), `../backup-dr/SKILL.md`
(the recovery half of maintenance-window planning).
