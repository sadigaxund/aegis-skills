# Firewall & Network Edge Hardening — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind listener inventories, default-deny rulesets, egress filtering,
IPv6 parity, fail2ban, and the Docker/cloud-layer interplay; SKILL.md carries
the exact commands, reference rulesets, and lockout-safe procedures.

## How this class emerged

Host firewalls on Linux grew out of packet-filtering code in the kernel: the
netfilter/iptables framework replaced its ipchains predecessor around the year
2000 and gave administrators chain-based filtering with connection tracking.
Its successor, nftables, entered mainline kernels in the mid-2010s and unified
the IPv4/IPv6 rule languages into one `inet` family — which matters directly to
this module, because dual-stack coverage is exactly what the old split made easy
to get wrong. Frontends layered on top (ufw on Debian/Ubuntu, firewalld on
RHEL-family systems) traded expressiveness for usability, each with its own idea
of where the truth lives.

Two historical facts explain most findings here:

- **Linux hosts have always booted default-open.** Chain policies default to
  ACCEPT and no firewall runs unless someone enables one. Decades of "it works
  out of the box" produced generations of servers whose entire network policy
  was *absence of policy*.
- **Convenience services bind wildcards by default.** Databases, caches, queues,
  and dev servers listen on every interface unless configured otherwise. When
  mass scanning met these defaults, the result was well-documented waves of
  unauthenticated Redis and MongoDB compromise used for data theft and
  ransom-note extortion, plus Memcached briefly becoming the largest UDP
  amplification vector ever measured — none requiring any exploit beyond
  *reachability*.

The cloud era added a twist rather than removing the problem: security groups
moved a filter in front of the host, but the host's own firewall and bindings
still decide who reaches what whenever topology shifts — a new subnet, a peered
VPC, an attached load balancer. Containers added another: Docker publishes ports
by rewriting addresses before the host's INPUT rules ever evaluate them, so a
"deny incoming" firewall coexists peacefully with an internet-reachable database
inside a container. Both behaviors are documented by their own vendors, yet both
still surprise operators routinely.

Egress — the outbound half — has been neglected through all of this. After any
foothold, an unfiltered output path is precisely what turns access into reverse
shells, callback traffic, and exfiltration.

## Anatomy: three layers, one exposed cache

A minimal generic weak configuration needs no exploit at all:

```
$ ss -tlnp | grep redis
LISTEN 0 511  0.0.0.0:6379 ... users:(("redis-server",pid=812))   # wildcard bind

$ ufw status verbose
Status: inactive        # manager installed, never enabled

$ iptables -S | grep '^-P'
-P INPUT ACCEPT         # zero rules follow
```

Walkthrough of how this fails:

1. **Binding is ground truth.** `0.0.0.0:6379` offers the service to every
   interface; only layers above the process stand between the internet and this
   socket. A loopback bind (`127.0.0.1:6379`) would be unreachable regardless
   of firewall mistakes — which is why the inventory starts at `ss`, not at
   rules.
2. **No loaded firewall exists.** Installed-but-disabled managers are theater;
   empty chains with ACCEPT policies mean nothing evaluates inbound traffic.
   An external probe would receive answers from the cache with no credentials.
3. **The classic chain follows.** Unauthenticated Redis reachable from outside
   has been abused publicly by writing attacker-controlled keys, pointing the
   server's save directory at root's crontab, and letting the scheduler execute
   the payload — a full host compromise from one open port, described in public
   write-ups from real campaigns.
4. **Docker makes it worse invisibly.** If that Redis had instead been a
   container started with `-p 6379:6379`, its port is address-translated before
   INPUT evaluation, so even a correctly deny-by-default ufw never sees the
   traffic. The operator believes the firewall protects them; it does not.

## Why naive fixes fail

- **Installing without enabling.** Package presence proves nothing; `is-active`
  and loaded rules do. Many audits find ufw or firewalld present and inert.
- **Building IPv4-only rulesets.** A `table ip` covers v4 only while every
  `[::]:port` listener stays wide open; attackers resolve AAAA records exactly
  like A records. Dual-stack needs an `inet` table or mirrored v6 rules — and
  ICMPv6 neighbor discovery must survive, or v6 dies silently after minutes.
- **Disabling Docker's iptables management as a "fix".** It breaks container
  networking bookkeeping; the supported shape is loopback-prefixed publishing
  (`127.0.0.1:5432:5432`) plus explicit FORWARD-stage restrictions.
- **Adding INPUT rules for container ports.** They never evaluate DNAT'd
  traffic; the fix belongs in the FORWARD/DOCKER-USER stage or in how the port
  is published.
- **One-jump strict egress.** Blocking all output breaks DNS resolvers, package
  mirrors, NTP, and monitoring at once. Staged rollout — log-only observation
  first, enforce later — is the workable pattern.
- **Applying restrictive rules over SSH without an escape hatch.** Without an
  out-of-band console or a scheduled automatic rollback, the first typo ends
  remote administration permanently.

## Common misconceptions

1. "The security group is closed, so the host doesn't need a firewall." SG-closed
   plus host-open is false comfort that evaporates on topology change — new
   peering, LB attach, or a v6-default-open VPC silently activate the open layer.
2. "My firewall denies everything incoming." For container-published ports, the
   packets take the nat-table detour and are accepted via forwarding chains your
   INPUT policy never inspects.
3. "Nobody uses IPv6 here, so parity is theoretical." Listeners bound to `[::]`
   are live doors on any host with a routable v6 address, and scanners treat v6
   like v4.
4. "Default ACCEPT is fine because we don't run anything sensitive." Listener
   sets change weekly; a developer's forgotten `--host 0.0.0.0` dev server turns
   yesterday's harmless default into today's breach.
5. "fail2ban fixes weak SSH authentication." Its own documentation states it
   cannot eliminate the risk of weak auth — it throttles log noise; key-only or
   equivalent is the actual control.
6. "Egress filtering will break production." Done as a big bang, yes. Log-first
   phases enumerate legitimate destinations safely before anything drops.
7. "Cloud LB health checks hitting my host are misconfigurations." Managed
   probes must reach targets by design; scope findings to genuinely public
   paths instead of flagging provider ranges blindly.

## How professionals think about it today

Modern practice treats exposure as four independent layers — cloud security
group, host firewall, listener binding, application auth — and hunts for the
hole in whichever one is missing. The taxonomy mirrors SKILL.md's own sections:

| Domain | Typical gap | Defining control |
|---|---|---|
| Exposure inventory | wildcard binds nobody justified | `ss -tlnp` classification table |
| Firewall state | installed-but-disabled managers | effective-state checks (`nft list tables`, policies) |
| Default-deny design | ACCEPT policies, unsourced allows | loopback→established→scoped allows→logged drop |
| Egress posture | output policy ACCEPT forever | staged observe→enforce→narrow rollout |
| IPv6 parity | family-ip-only tables, `[::]` doors | `table inet` or mirrored v6 rules + NDP survival |
| Rate limiting / brute force | no meters, no fail2ban jails | L4 limits + jail coverage on sshd/proxy auth |
| Admin-plane isolation | management ports from whole VPC | bastion-CIDR-scoped allow rules |
| Layer interplay | Docker DNAT bypass, double exposure | DOCKER-USER rules, SG×host×binding matrix |

Severity follows worst-case reachability of each listener, not rule counts: an
unauthenticated wildcard-bound service is Critical regardless of how tidy the
rest of the ruleset looks.

## Read next

In `../SKILL.md`: **Scope & Objectives** (eight domains), **Mental Model**
(four-layer exposure stack and key asymmetries), **What To Check** (exposure
sweep through SG reconciliation), **Where To Look** (backend-specific artifact
map), **Patterns & Signatures** (listener table, vulnerable/fixed shapes,
three-syntax reference design), **Taint Tracing Guidance** (bind-literal sources
to internet sinks), **Exploitation & Reproduction** (read-only proofs including
the Docker bypass evidence chain), **Remediation** (lockout-hazard preamble,
hardened nftables/ufw/firewalld, fail2ban jails, staged egress, DOCKER-USER),
**Verification & Validation**, **Severity Assessment**, **Common False
Positives** (kube-proxy noise, LB health checks, host-networked containers).

Sibling modules: `../linux-baseline/SKILL.md` (kernel-side knobs and sshd
identity behind this edge), `../tls-proxy/SKILL.md` (the public web service
these rules admit), `../service-sandboxing/SKILL.md` (containment once traffic
reaches a process), `../updates-patching/SKILL.md` (offender-service removal as
surface shrinkage), `../logging-monitoring/SKILL.md` (where drop-log evidence
ships), `../kubernetes-cluster/SKILL.md` (when kube-proxy owns the rules and
host-firewall auditing must step aside).
