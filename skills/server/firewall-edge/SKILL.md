---
name: aegis-firewall-edge
description: Audits host firewall state and network-edge exposure on Linux hosts — listener inventory and wildcard bindings, nftables/iptables/ufw/firewalld default-deny design, egress filtering, IPv6 parity, L4 rate limiting, admin-plane isolation, Docker NAT bypass, and cloud security-group reconciliation — with read-only evidence commands and hardened reference rulesets.
category_slug: FW
cwe: [CWE-16, CWE-284]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Audit one running Linux host's network edge (or its config-as-code). Eight domains, in priority order:

1. **Exposure inventory** — every TCP/UDP listener mapped to bound address, service, user; classified internet-reachable vs loopback-only vs link-local; wildcard (`0.0.0.0` / `[::]`) bindings that should be loopback.
2. **Firewall state** — which of nftables / iptables / ufw / firewalld is actually active (or none), default policies, rule density per chain.
3. **Default-deny design** — inbound policy drop with explicit allows; drop logging with rate limiting; correct syntax for all three management layers.
4. **Egress filtering** — outbound control for SSRF exfil, reverse shells, data theft; staged log-only rollout.
5. **IPv6 parity** — v6 filtered at least as tightly as v4; NDP/RA permitted.
6. **L4 rate limiting & brute-force protection** — connection/rate meters at the firewall plus fail2ban jails for sshd and nginx auth failures.
7. **Admin-plane isolation** — SSH, DB admin, monitoring agents reachable only from VPN/bastion CIDR; lockout-safe change procedure.
8. **Layer interplay** — Docker DNAT bypass of INPUT rules; cloud security groups vs host firewall double-exposure or false comfort.

Out of scope (cross-references): kernel sysctl knobs (SYN cookies, `tcp_syncookies`, conntrack limits) → BASE/linux-baseline; TLS termination and proxy headers → TLS; container runtime sandboxing → SANDBOX; log shipping → LOGMON.

Operating rules:

- All inspection commands are read-only; mutating commands appear only under Remediation after approval.
- Prefer **effective-state evidence** (`ss -tlnp`, `nft list ruleset`) over config files — a ruleset file on disk says nothing about what is loaded.
- Commands needing root are tagged `[ROOT]`. Without root, audit world-readable state plus the config repo and judge rendered configs using Patterns & Signatures.
- External probing (connecting to services from outside the host) requires written authorization naming the source host and target range. Where absent, rely on in-host evidence per Exploitation & Reproduction.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **default-deny**: dropping all traffic except what is explicitly allowed
- **listener binding**: the address a service accepts connections on; `0.0.0.0` means every interface
- **security group (SG)**: a cloud-level firewall in front of the host
- **Docker DNAT bypass**: published container ports forwarding around normal host firewall rules
- **egress filtering**: restricting outbound destinations so stolen access cannot call home or exfiltrate
- **IPv6 parity**: filtering IPv6 at least as strictly as IPv4
- **fail2ban jail**: automatic IP bans after repeated failed logins
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Exposure is decided by four independent layers; a hole in any one is enough:

```
internet ──▶ [1] cloud SG/NLB     filters by CIDR/port BEFORE the host
         ──▶ [2] host firewall    nftables/iptables INPUT (+ FORWARD for docker)
         ──▶ [3] listener binding which address the process accepts on
         ──▶ [4] app auth         passwords, ACLs, TLS client certs
```

Key asymmetries this module exploits:

- **Binding is ground truth for "who could reach it if all filters vanished."** A wildcard bind (`0.0.0.0:6379`) means layer 3 offers the service to the entire internet; only layers 1–2 stand in the way. Loopback binds (`127.0.0.1:6379`) are unreachable regardless of firewall mistakes. This is why wildcard bindings — not missing firewall rules — were the #1 cloud breach vector (open Redis/Memcached/MongoDB ransomware waves).
- **Docker punches through layer 2.** Published ports (`-p 6379:6379`) are DNAT'd in the nat table and forwarded via the FORWARD chain; ufw/nftables INPUT rules never see that traffic.
- **Host firewall is layer 2 of 4, not a substitute for the SG.** SG-open + host-open = double exposure; SG-closed + host-open = false comfort that evaporates when topology changes (new subnet, peered VPC, LB attach).
- **Inbound gets all the attention; egress is the neglected half.** After any foothold (SSRF, webshell), an unfiltered output path is what turns access into exfiltration, reverse shells, and lateral movement.
- **IPv6 is a second front door.** Rulesets built family-`ip` only leave `table inet`-less hosts wide open on `[::]` listeners; attackers scan v6 exactly like v4.

Classify each listener by worst-case reachability, then check whether layers 1–2 actually restrict it. Never accept "the SG blocks it" without reconciling both layers.

## What To Check

### 1. Exposure inventory (do this first)

Run the paste-ready sweep below `[ROOT]`, then build a table of every row of `ss -tlnp` and `ss -ulnp`: bound address:port → process name → owning UID → classification.

```bash
# ===== exposure sweep (read-only; run as root) =====
echo "== TCP listeners ==";  ss -tlnp
echo "== UDP listeners ==";  ss -ulnp
echo "== wildcard-bound TCP listeners (suspect) =="
ss -tlnp | awk 'NR==1 || $4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\[::\]:/ || $4 ~ /^\*:/'
echo "== firewall backend detection =="
for s in nftables ufw firewalld iptables netfilter-persistent; do
  printf '%-24s %s\n' "$s:" "$(systemctl is-active "$s" 2>/dev/null)"
done
command -v nft          >/dev/null && nft list tables
command -v iptables     >/dev/null && iptables -V
command -v ufw          >/dev/null && ufw status verbose
command -v firewall-cmd >/dev/null && firewall-cmd --state
echo "== iptables chain policies + INPUT rule count =="
iptables -S 2>/dev/null | grep '^-P'
printf 'INPUT rules: %s\n' "$(iptables -S INPUT 2>/dev/null | grep -c '^-A')"
echo "== ipv6 parity quick check =="
ip6tables -S 2>/dev/null | grep '^-P'
printf 'ip6tables INPUT rules: %s\n' "$(ip6tables -S INPUT 2>/dev/null | grep -c '^-A')"
nft list tables 2>/dev/null | grep -qE '(^| )(inet|ip6) ' || echo "no inet/ip6 nft table -> IPv6 likely unfiltered"
echo "== docker presence =="
[ -S /var/run/docker.sock ] && echo "docker socket present"
iptables -t nat -S DOCKER 2>/dev/null | head -5
```

Classification rules:

- Bound `127.0.0.1` / `[::1]` → loopback-only, safe by construction.
- Bound `169.254.*` or link-local v6 → link-local only; note but do not treat as internet-reachable.
- Bound `10.*`, `172.16-31.*`, `192.168.*`, or a private interface IP → internal-reachable; still audit who owns those ranges (VPN? whole VPC? shared office LAN?).
- Bound `0.0.0.0`, `[::]`, `*`, or the public interface IP → internet-reachable unless a layer above blocks it; each such listener needs explicit justification.

For every wildcard binding ask: *must* this be reachable beyond loopback? Web servers (80/443), public API ports, and load-balanced backends are legitimate; databases, caches, queues, admin panels, dev servers are not. Cross-check process identity from the `users:(("name",pid=N,...))` field — a "node" or "python" on 0.0.0.0 may be a forgotten dev server.

### 2. Firewall state assessment

Identify which backend actually owns the loaded rules — distros differ and multiple managers fight silently:

- `nft list tables` `[ROOT]` — empty output with active listeners means **no firewall at all** (a finding by itself).
- `iptables -V` — version suffix `(nf_tables)` = iptables-nft translation backend; `(legacy)` = legacy xtables. Rules loaded under one backend are invisible to the other; detect before trusting `iptables -S`.
- `ufw status verbose` `[ROOT]` — `Status: inactive` = finding; note the `Default:` lines.
- `firewall-cmd --state` and `firewall-cmd --list-all` `[ROOT]` — note zone, interfaces, services, and rich rules.
- Legacy detection corroboration: `update-alternatives --display iptables 2>/dev/null | grep value` (Debian/Ubuntu); `lsmod | grep -E '^ip_tables|^nf_tables'`.

Assess policies and density:

- Chain policies: `iptables -S | grep '^-P'`; nft: the `policy` keyword on each base chain line of `nft list ruleset`.
- Rule counts per chain: `iptables -S INPUT | grep -c '^-A'`. **Policy ACCEPT + zero rules on an internet-reachable host = empty firewall finding**, even if ufw/firewalld packages are installed (installed ≠ enabled).
- Drop logging presence: look for `log prefix` rules preceding `drop` verdicts in `nft list ruleset`, or `-j LOG` in `iptables -S INPUT`.

### 3. Default-deny design

Confirm the loaded (not on-disk) ruleset implements: loopback allow → established/related allow → admin-CIDR-scoped SSH → public 80/443 → rate-limited log+drop everything else, with FORWARD also default-dropping. Compare against the reference patterns in Patterns & Signatures and Remediation. Any `accept` broader than the intended scope (e.g., `tcp dport 22 accept` without source restriction) is a finding.

### 4. Egress posture

Inspect the output chain direction: `iptables -S OUTPUT` / nft output chain policy. `policy ACCEPT` with no restrictions is the norm today — record it as the baseline finding (Medium anchor) and assess what a foothold could reach: resolvers, package mirrors, the app's known external APIs, and especially the cloud metadata endpoint. Metadata reachability probe (harmless GET, authorized environments):

```bash
curl -sS --max-time 3 http://169.254.169.254/latest/meta-data/ami-id && echo   # AWS/GCP shape
curl -sS --max-time 3 -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' -o /dev/null -w '%{http_code}\n'  # Azure shape
```

An answer from inside a workload context proves metadata is reachable — the SSRF-to-instance-credential pivot target. Note whether IMDSv2/token enforcement applies (blind GET returns 401 on AWS IMDSv2-only instances).

### 5. IPv6 parity

- Does any `table inet` exist (`nft list tables`)? `inet` families cover v4+v6; a lone `table ip filter` covers v4 only.
- If legacy: compare `iptables -S INPUT | grep -c '^-A'` vs `ip6tables -S INPUT | grep -c '^-A'`.
- Re-scan the listener table for `[::]:PORT` rows — every one is an unfiltered v6 door when v6 has no firewall.
- NDP/RA requirement: any v6 firewall must permit ICMPv6 types neighbor-solicit/advert and router-advert, or v6 connectivity dies silently. Privacy extensions (temporary addresses) are irrelevant here — servers use static addresses; do not attempt to filter around them.

### 6. Rate limiting & L4 protection

Check for, at any layer:

- SSH throttling: `ufw limit ssh` style rules, nft meters (`meter ... { ip saddr ... }`), iptables `recent`/`hashlimit` matches on port 22 NEW connections.
- SYN/new-connection rate caps on public services (`limit rate` in nft rules for dport 80/443).
- ICMP rate limiting: echo-request under a `limit rate` clause; destination-unreachable/time-exceeded still permitted.
- fail2ban: `systemctl is-active fail2ban`, then `fail2ban-client status` `[ROOT]` — which jails are enabled? Is an sshd jail present? On nginx hosts, a jail watching auth failures?

Absence of all four on an internet-reachable host with password SSH = finding (compounds BASE/linux-baseline sshd checks).

### 7. Admin-plane isolation

For each management listener (sshd 22, DB admin ports, node_exporter 9100, phpMyAdmin, RabbitMQ management 15672, monitoring agents):

1. From the inventory table, note its bound address.
2. In the loaded ruleset, find the rule that admits it and check the source selector: admin CIDR / VPN range vs unrestricted.
3. Note overlay/knocking options observed (tailscale/wireguard interfaces `ip link show type wireguard`, knockd units) as context, without endorsing them as sufficient.

Any management port admitted from `0.0.0.0/0` or from the whole VPC CIDR when only a bastion subnet needs it = finding.

### 8. Docker interaction

If `/var/run/docker.sock` exists or `docker ps --format '{{.Names}}\t{{.Ports}}'` returns containers:

- List published ports and their host-side bind: `-p 127.0.0.1:5432:5432` vs `-p 5432:5432`.
- `[ROOT]` `iptables -t nat -S DOCKER | grep DNAT` — every published wildcard port appears here as a DNAT that bypasses INPUT entirely.
- Check DOCKER-USER chain exists and has restrictive rules: `iptables -S DOCKER-USER`. Default shape is empty except the trailing `RETURN` — meaning ufw INPUT rules do NOT protect container-published ports.
- Cross-check compose files / unit args: bare `"8080:8080"` port maps vs `127.0.0.1:` prefixed ones.

### 9. Cloud security-group reconciliation

The host cannot see its own SG directly. Reconcile by:

- Reading the config-as-code repo (Terraform `aws_security_group`/`google_compute_firewall`/`azurerm_network_security_group` blocks, or cloud console if access exists) for the SG rules applying to this instance's NIC/LB target group.
- Building the combined matrix: for each port — SG state × host-firewall state × binding. Findings:
  - SG open + host open + wildcard bind → double exposure, Critical if unauthenticated service.
  - SG closed + host open → false comfort; flag because topology changes (new peering, LB attach, IPv6 default-open in some VPCs) silently activate the open host layer.
  - SG open + host closed → usually correct design (SG as the edge); verify the host layer isn't closed *by accident* (empty chains nobody owns).

## Where To Look

Evidence collection: `tools/sweeps/sweep-firewall.sh` captures `[FW-nn]` sections verbatim; judge them against this module's rubrics, never against raw output alone.

Effective-state commands first; files second (files may not match what's loaded):

| Artifact | Path / Command | Notes |
|---|---|---|
| Loaded nftables ruleset | `nft list ruleset` `[ROOT]` | Ground truth for nft backend |
| nftables persistent config | `/etc/nftables.conf`; drop-ins `/etc/nftables.d/*.nft` | Loaded by `nftables.service` |
| iptables-nft/legacy live rules | `iptables -S`, `iptables -t nat -S`, `ip6tables -S` `[ROOT]` | nat table mandatory for docker audit |
| Persistent iptables | Debian: `/etc/iptables/rules.v4`, `rules.v6`; RHEL legacy: `/etc/sysconfig/iptables`, `ip6tables` | `iptables-persistent`/`netfilter-persistent.service` vs `iptables.service` |
| ufw state | `ufw status verbose` `[ROOT]` | Files: `/etc/default/ufw` (IPV6=yes?), generated rules `/etc/ufw/{before,user,after}.rules` |
| firewalld | `firewall-cmd --list-all --permanent` `[ROOT]` | Zones: `/etc/firewalld/zones/*.xml`, distro defaults `/usr/lib/firewalld/zones/` |
| fail2ban | `fail2ban-client status` `[ROOT]`; `/etc/fail2ban/jail.local`, `jail.d/*.conf` | Effective jails via client, not file text |
| Docker published ports | `docker ps --format '{{.Names}}\t{{.Ports}}'`; `iptables -t nat -S DOCKER` `[ROOT]` | Compose files: repo-wide `ports:` blocks |
| Listener/process map | `ss -tlnp`, `ss -ulnp` `[ROOT]` | Also `lsof -nP -iTCP -sTCP:LISTEN` equivalent |
| Config-as-code edge rules | Terraform `*.tf` security-group blocks; Ansible `ufw`/`iptables`/firewalld tasks; cloud-init user-data | Judge rendered output, per Patterns & Signatures |

Distro detection before trusting paths: `cat /etc/os-release`. Debian/Ubuntu favor ufw+nftables; RHEL/Fedora favor firewalld; Alpine uses plain iptables/nftables with no manager.

## Patterns & Signatures

### Listener classification table

| Listener | Risky binding | Expected binding | Why |
|---|---|---|---|
| Redis 6379 | `0.0.0.0:6379`, `[::]:6379` | `127.0.0.1:6379` | Unauthenticated by default; historic mass compromise → crontab write → RCE chain |
| Memcached 11211 | `0.0.0.0:11211`, UDP enabled | `127.0.0.1:11211`, `-U 0` | Data theft + the largest UDP amplification DDoS vector ever measured |
| PostgreSQL 5432 | `0.0.0.0:5432`, `listen_addresses='*'` | `127.0.0.1:5432` + unix socket | Credential stuffing surface; exposure is never needed for app-on-same-host |
| MySQL/MariaDB 3306 | `bind-address=0.0.0.0` | `127.0.0.1` or private CIDR | Brute-force target; historical pre-auth CVEs |
| MongoDB 27017 | `bindIp: 0.0.0.0` without auth enabled | `127.0.0.1` / VPC-internal + auth | The canonical ransomware-exposure campaign target |
| RabbitMQ mgmt 15672 / AMQP 5672 | `0.0.0.0:15672` | loopback or VPN-only | Admin panel; default `guest/guest` historically retained |
| Elasticsearch 9200 / Kibana 5601 | `network.host: 0.0.0.0` | loopback/private + auth | Full data theft; scripting-RCE history in old versions |
| Dev/admin servers (Jupyter 8888, Werkzeug 5000, Vite/webpack 3000–8080) | `0.0.0.0` or `--host=0.0.0.0` | `127.0.0.1` | Debugger consoles, file upload endpoints, no hardening at all |
| Monitoring agents (node_exporter 9100, dcgm, etc.) | `0.0.0.0:9100` | private interface or loopback+proxy | Internal metric disclosure; scraping endpoint enumeration |

### Signature: exposed wildcard listeners

```bash
# VULNERABLE — ss -tlnp shape: wildcard binds on sensitive services
LISTEN 0 511   0.0.0.0:6379   0.0.0.0:*  users:(("redis-server",pid=812,fd=7))
LISTEN 0 4096  [::]:27017    [::]:*     users:(("mongod",pid=903,fd=21))
LISTEN 0 128   *:8888        *:*        users:(("python",pid=1204,fd=4))
# FIXED — same services loopback-bound
LISTEN 0 511   127.0.0.1:6379   0.0.0.0:*  users:(("redis-server",pid=812,fd=7))
LISTEN 0 4096  127.0.0.1:27017  127.0.0.1:* users:(("mongod",pid=903,fd=21))
LISTEN 0 128   127.0.0.1:8888   0.0.0.0:*  users:(("python",pid=1204,fd=4))
```

### Signature: empty firewall on a running host

```bash
# VULNERABLE — iptables -S on an internet-reachable host: policies ACCEPT, zero rules
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
# FIXED — default-deny shape with explicit allows present (excerpt)
-P INPUT DROP
-P FORWARD DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 203.0.113.0/24 -p tcp --dport 22 -j ACCEPT
-A INPUT -j LOGDROP
```

### Signature: IPv6 gap

```bash
# VULNERABLE — v4 locked down but ip6tables empty/wide open; listeners on [::]
$ ip6tables -S INPUT
-P INPUT ACCEPT            # zero '-A' lines follow
$ nft list tables
table ip filter            # family 'ip' only -> v6 unfiltered
# FIXED
table inet filter { ... }  # single inet table governs both families
ip6tables -P INPUT DROP    # legacy path equivalent, mirrored rule set
```

### Reference inbound design (three syntaxes)

Intent for an app server: loopback allowed, established/related allowed, SSH from admin CIDR `203.0.113.0/24` only, HTTP(S) public, ICMP rate-limited, all else logged (rate-capped) and dropped. Canonical full files live in Remediation; signatures here:

```bash
# FIXED — nftables (native)
tcp dport { 80, 443 } ct state new accept
ip saddr 203.0.113.0/24 tcp dport 22 ct state new accept
icmp type echo-request limit rate 5/second accept
meta l4proto ipv6-icmp accept
jump logdrop              # chain: log under rate limit, then drop everything
```

```bash
# FIXED — ufw (same intent, command sequence)
ufw default deny incoming
ufw allow from 203.0.113.0/24 to any port 22 proto tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw logging on
ufw enable
```

```bash
# FIXED — firewalld rich rules (same intent)
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="203.0.113.0/24" service name="ssh" accept'
firewall-cmd --permanent --zone=public --remove-service=ssh
firewall-cmd --permanent --zone=public --add-service=http --add-service=https
firewall-cmd --set-log-denied=all
firewall-cmd --reload
```

## Taint Tracing Guidance

Treat "exposure" as data flow from configuration source to internet-reachable sink:

**Source patterns (where dangerous values originate):**

- Wildcard bind literals: `0.0.0.0`, `[::]`, `*`, `--host 0.0.0.0`, `listen_addresses = '*'`, `bind 0.0.0.0`, `bindIpAll: true`, `network.host: 0.0.0.0`.
- Defaults that resolve to wildcards: unset `LISTEN_HOST`, compose `ports: "8080:8080"`, Docker `-p 8080:8080`, Kubernetes `hostPort:`/`nodePort:`.
- Broad edge rules: SG `cidr_blocks = ["0.0.0.0/0"]` or `"::/0"` on non-web ports; nft/iptables accept rules lacking a source selector.
- Egress absence: output policy ACCEPT with no destination-scoped allows.

**Propagation to trace in config-as-code repos:**

1. Variable defaults: `${LISTEN_HOST:-0.0.0.0}` in entrypoints, systemd units (`Environment=`), Helm values.yaml — trace where the variable lands in the final config.
2. Template rendering: Ansible/Jinja templates that interpolate bind addresses — audit the rendered file, not the template constant.
3. Compose/K8s port maps: every `ports:`/`hostPort` entry → which host interfaces it opens, then whether host firewall/SG covers it.
4. SG inheritance: instance → NIC → SG set; LB/target-group SGs add implicit allow paths — follow the whole chain before declaring a port closed.
5. Docker DNAT: a published port taints the FORWARD path regardless of INPUT hygiene — treat `-p <pub>:<pub>` as an automatic finding unless DOCKER-USER restricts it.

**Sink classification:** internet-reachable (public interface, `::/0` SG), partner/VPC-shared, bastion-only, loopback. Severity follows the sink: a tainted path terminating at an internet sink is Critical/High per Severity Assessment; the same misconfiguration terminating at a bastion-only sink is Medium.

Repo-wide grep recipes are in Verification & Validation; run them even when live inspection is impossible.

## Exploitation & Reproduction

READ-ONLY demonstrations. Connect to services only from positions named in your authorization; otherwise rely on in-host evidence interpretation.

### 1. Unauthenticated wildcard-bound Redis

External proof (only from an authorized source position):

```bash
$ redis-cli -h 198.51.100.10 ping
PONG                          # no AUTH required -> unauthenticated reachability proven
$ redis-cli -h 198.51.100.10 CONFIG GET dir
1) "dir"
2) "/var/lib/redis"           # writable data dir confirmed -> RCE chain viable
```

When external testing is not authorized, prove the same from host state alone: the `ss -tlnp` line `0.0.0.0:6379 ... redis-server` establishes the wildcard bind; an empty/absent firewall (`iptables -S` all ACCEPT, or `nft list tables` empty) and a `0.0.0.0/0` SG rule establish that nothing stands between the internet and that bind. The combination is logically equivalent to the external probe.

Attacker-path narrative (classic chain — describe in findings; do not execute): unauth Redis reachable → attacker runs `CONFIG SET dir /var/spool/cron`, writes a cron payload as a key, triggers `SAVE` → Redis serializes the key into root's crontab file → cron executes it every minute → reverse shell as root. Every step is documented in public write-ups from real mass-compromise campaigns.

### 2. Empty firewall proof

`iptables -L -n -v [ROOT]` on a wide-open host has this exact shape — policies ACCEPT, zero rules, only counters:

```bash
# VULNERABLE
Chain INPUT (policy ACCEPT 15432 packets, 892134 bytes)
 pkts bytes target prot opt in out source destination

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target prot opt in out source destination

Chain OUTPUT (policy ACCEPT 12098 packets, 745112 bytes)
 pkts bytes target prot opt in out source destination
```

Corroborate with `ufw status verbose` showing `Status: inactive` while `systemctl is-active ufw` says inactive too — installed-but-disabled managers are common theater.

### 3. IPv6 gap proof

```bash
# VULNERABLE shape
$ iptables -S INPUT | head -3
-P INPUT DROP
-A INPUT -i lo -j ACCEPT
# ...remaining v4 allow rules (established/related, admin ssh, 80/443)...
$ ip6tables -S INPUT
-P INPUT ACCEPT               # <- entire v6 plane open
$ ss -tlnp | grep ':::'
LISTEN 0 511 [::]:6379 [::]:* users:(("redis-server",pid=812,fd=7))
```

Narrative: attacker resolves the host's AAAA record, connects over v6, and lands on exactly the service v4 filtering was built to hide. Dual-stack hosts with family-`ip`-only rulesets are fully exposed on v6 for every `[::]` listener.

### 4. Docker bypass demonstration

```bash
# Evidence chain [ROOT]
$ docker ps --format '{{.Names}}\t{{.Ports}}'
cache   0.0.0.0:6379->6379/tcp          # published wildcard
$ ufw status verbose | grep 'deny\|Default'
Default: deny (incoming)
$ iptables -t nat -S DOCKER | grep 6379
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 6379 -j DNAT --to-destination 172.17.0.2:6379
```

Interpretation: inbound :6379 traffic is DNAT'd in nat PREROUTING and accepted via FORWARD's docker chains — ufw's deny-incoming INPUT policy never evaluates it. The container is internet-reachable even though "the firewall denies everything." Attacker path: identical unauth-Redis chain as above, but invisible to the operator who believes ufw protects them.

## Remediation

> **LOCKOUT HAZARD — read before applying anything remotely.**
> Before pushing a restrictive ruleset over SSH, confirm out-of-band access exists and works: cloud serial console session opened in a browser tab, IPMI/iDRAC/iLO reachable, or hypervisor console. Then schedule automatic rollback BEFORE applying:
>
> ```bash
> echo 'nft flush ruleset && nft -f /etc/nftables.conf' | at now +5 minutes
> atq                       # confirm job queued
> # ... apply new ruleset, test from a SECOND shell ...
> atrm <jobid>              # cancel rollback only after verified access
> ```
>
> Requires `atd`: check `systemctl is-active atd`; install with the distro package manager (`apt install at` / `dnf install at`) if absent, or use a root crontab one-liner deleted afterward. When neither at nor cron is available: keep TWO live SSH sessions open, apply from one, verify from the second before closing the first, and rely on OOB console as the backstop. firewalld variant: apply runtime-only changes (omit `--permanent`) so `systemctl restart firewalld` reverts them. ufw variant: review first with `ufw --dry-run enable` (prints rules, applies nothing).

### Hardened nftables ruleset (`/etc/nftables.conf`)

```bash
# FIXED — complete reference ruleset, app server, dual stack
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain logdrop {
        limit rate 5/second burst 20 packets log prefix "nft-drop " level warn
        counter drop
    }

    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmp type echo-request limit rate 5/second accept
        meta l4proto ipv6-icmp accept
        ip saddr 203.0.113.0/24 tcp dport 22 ct state new meter ssh-brute { ip saddr limit rate over 15/minute } drop
        ip saddr 203.0.113.0/24 tcp dport 22 accept
        tcp dport { 80, 443 } ct state new limit rate 50/second burst 100 packets accept
        jump logdrop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        # docker-managed forwarding may require explicit allows here; see Docker subsection
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

Apply and persist:

```bash
echo 'nft flush ruleset && nft -f /etc/nftables.conf' | at now +5 minutes   # rollback guard
nft -f /etc/nftables.conf
nft list ruleset                                    # verify loaded
systemctl is-enabled nftables || systemctl enable nftables
systemctl cat nftables.service                      # ExecStart must be 'nft -f /etc/nftables.conf'
atrm <jobid>
```

Legacy-iptables equivalent (hosts without nft): same logic via `-P INPUT DROP`, `-A INPUT -i lo -j ACCEPT`, conntrack ESTABLISHED,RELATED accept, CIDR-scoped dport 22, `hashlimit`/`recent` for SSH throttling, and a LOGDROP chain using `-m limit --limit 5/s -j LOG --log-prefix "ipt-drop "` then `-j DROP`. Persist with `netfilter-persistent save`.

### ufw equivalent sequence

```bash
# FIXED — run from console-backed session; dry-run first
ufw --dry-run enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 203.0.113.0/24 to any port 22 proto tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw logging on
ufw enable
ufw status verbose numbered
```

Ensure `/etc/default/ufw` contains `IPV6=yes` (default) so rules apply to v6. Rollback: `ufw disable`.

### firewalld equivalent

```bash
# FIXED — runtime-only first (self-reverting via restart), then permanent
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="203.0.113.0/24" service name="ssh" accept'
firewall-cmd --zone=public --remove-service=ssh
firewall-cmd --zone=public --add-service=http --add-service=https
firewall-cmd --set-log-denied=all
# verify SSH still works from admin range, then persist:
firewall-cmd --runtime-to-permanent
firewall-cmd --reload
firewall-cmd --list-all
```

### fail2ban jails

`/etc/fail2ban/jail.local`:

```ini
# FIXED
[DEFAULT]
banaction = nftables-multiport
findtime = 10m
bantime = 1h
maxretry = 5
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24

[sshd]
enabled = true
port = 22
backend = systemd

[nginx-auth]
enabled = true
port = http,https
filter = nginx-auth
logpath = /var/log/nginx/error.log
maxretry = 5
```

Enable: `systemctl enable --now fail2ban && fail2ban-client status sshd`. The stock `nginx-auth` filter matches HTTP basic-auth failures; add a custom filter regexing nginx access log for sustained 401/403 responses if you also want credential-stuffing detection there. Recent fail2ban supports `bantime.increment = true` for escalating bans.

### Egress staged rollout

Honest warning: strict egress breaks more than it saves if done in one jump — DNS resolvers, apt mirrors, NTP, monitoring egress, and CDN-based APIs all need enumeration. Stage it:

- **Phase 0 — observe (no risk).** Keep `policy accept`, append counting/log rules for everything not yet explicitly allowed:
  ```bash
  # FIXED — nft output additions, observe-only
  oifname "lo" counter accept
  ip daddr 203.0.113.53 udp dport 53 counter accept      # resolver
  ip daddr 203.0.113.53 tcp dport 53 counter accept
  udp dport 123 counter accept                            # NTP
  tcp dport { 80, 443 } counter accept                    # mirrors/APIs, narrow later by CIDR where feasible
  counter log prefix "egress-would-drop "                 # watch this for days before Phase 1
  ```
- **Phase 1 — enforce.** Flip `policy drop` in output, keep the same accepts, route residue through a rate-limited egress logdrop chain.
- **Phase 2 — narrow.** Pin package mirrors and known API destinations to specific CIDRs/FQDN-resolved sets; drop broad 80/443 where the business allows.
- Always include: established/related accept, loopback, DNS to *specified* resolvers only, and an explicit decision on `ip daddr 169.254.169.254 drop` (block for workloads that never need metadata; cloud agents/cloud-init may — coordinate before dropping).

### Docker interaction fix

Primary control — publish on loopback only (compose):

```yaml
# VULNERABLE
ports:
  - "6379:6379"
# FIXED
ports:
  - "127.0.0.1:6379:6379"
```

Defense in depth — restrict forwarded traffic in DOCKER-USER:

```bash
# FIXED [ROOT] — block off-host reach of sensitive published ports at FORWARD stage
iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -I DOCKER-USER -i eth0 -s 127.0.0.0/8 -j RETURN
iptables -I DOCKER-USER -i eth0 -p tcp -m multiport --dports 3306,5432,6379,27017 -j DROP
netfilter-persistent save     # or iptables-save > /etc/iptables/rules.v4; DOCKER-USER survives docker restarts but NOT reboots without persistence
```

The `ufw-docker` utility (github.com/chaifeng/ufw-docker) automates the equivalent ufw-side FORWARD rules; evaluate it against hand-maintained DOCKER-USER rules. Never set `"iptables": false` in `/etc/docker/daemon.json` as a "fix" — it disables Docker's NAT bookkeeping and breaks container networking.

## Verification & Validation

Re-run the exposure sweep from What To Check after every fix; expected deltas are listed per fix.

| Fix | Verify command | Expected output |
|---|---|---|
| Loopback rebind | `ss -tlnp \| grep -E '6379\|27017\|5432'` | `127.0.0.1:` prefixes only, no `0.0.0.0:`/`[::]:` |
| nftables default-deny | `nft list ruleset \| grep policy` | `policy drop` on input and forward |
| ufw enabled | `ufw status verbose` | `Status: active`, `Default: deny (incoming)` |
| firewalld applied | `firewall-cmd --list-all` | ssh service absent, http/https present, rich rule for admin CIDR |
| IPv6 parity | `ip6tables -S INPUT \| grep '^-A' \| wc -l`; `nft list tables` | non-zero count or an `inet`/`ip6` table exists |
| fail2ban | `fail2ban-client status sshd` | jail listed with `Currently banned` field |
| Docker containment | `iptables -S DOCKER-USER`; `docker ps --format '{{.Ports}}'` | DROP rule present; loopback-prefixed publish only |

Negative tests (legit traffic must still pass — run from authorized positions):

```bash
curl -sSI --max-time 10 https://YOUR-HOST | head -1        # HTTP/1.1 200 or 301 -> web path intact
ssh -o ConnectTimeout=5 -o BatchMode=yes HOST true         # succeeds from admin IP
getent hosts archive.ubuntu.com                            # DNS resolution works under egress rules
ping -c1 -W3 HOST                                          # v6 NDP/ICMP not over-filtered (dual-stack hosts)
```

Blocked-path tests: from an external authorized source, `nc -zv -w3 HOST 6379` and `nc -zv -w3 HOST 22` must time out or refuse; repeat against the AAAA address for the v6 plane.

Regression watch-list (known breakage signatures):

- Strict egress + missing resolver allow → `Temporary failure resolving` in apt/logs, systemd timers retry-looping. Fix: allow UDP+TCP 53 to the configured resolvers first (`resolvectl status` / `/etc/resolv.conf` to find them).
- Missing ESTABLISHED,RELATED accept → downloads stall mid-transfer, long SSH sessions freeze.
- Over-broad DOCKER-USER drops → LB health checks fail, container-to-internet calls break; inspect counters `iptables -L DOCKER-USER -n -v`.
- ICMPv6 filtered entirely → v6 works briefly then dies (ND cache expiry); symptom is intermittent v6-only outages.
- fail2ban without `ignoreip` for the bastion range → operators banned during shared-NAT bursts.

Config-as-code grep recipes:

```bash
grep -RInE '"0\.0\.0\.0"|0\.0\.0\.0/0|::/0|--host[= ]0\.0\.0\.0|listen_addresses\s*=\s*.{0,3}\*' .
grep -RInE 'bind[- ]address|bindIp|network.host' --include='*.cnf' --include='*.conf' --include='*.yml' . | grep -vE '127\.0\.0\.1'
grep -RInE 'ports:\s*$' --include='docker-compose*.yml' -A2 . | grep -E '[0-9]+:[0-9]+' | grep -v '127\.0\.0\.1:'
grep -RInE 'ufw.*allow.*(22\|3389)\b' . ; grep -RInE 'cidr_blocks?\s*=?.*(0\.0\.0\.0/0)' .
grep -RIlE 'policy accept|-P INPUT ACCEPT' .   # ruleset files shipping default-accept
```

## Severity Assessment

Anchors (adjust within band for scope-changed variants; S:C pushes upward):

| Finding | Severity | CVSS v3.1 vector |
|---|---|---|
| Unauthenticated service wildcard-bound and internet-reachable (Redis/Memcached/MongoDB shape) | Critical (10.0) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| No firewall loaded / all-ACCEPT policies on internet-reachable host | High (9.3) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` |
| IPv6 fully open while IPv4 filtered (or Docker DNAT bypassing INPUT) | High (8.8) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| No egress filtering on any exposed host | Medium (5.8) | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| Default-deny present but drop-logging missing/rate-unlimited | Low (3.6) | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` |

Modifiers: authenticated-but-wildcard-bound services downgrade one band (auth is a real control); management ports open to whole-VPC instead of bastion CIDR = Medium–High by asset criticality; wildcard bind *with* working SG-closed topology stays High because topology change silently activates it.

## Common False Positives

- **Kubernetes worker/control-plane nodes** — kube-proxy programs thousands of KUBE-* iptables/nft chains and sets its own FORWARD behavior. Hand-tightening fights the controller and breaks service routing. Detect via `iptables -S | grep -c KUBE-` or the kube-proxy process; audit exposure at the NetworkPolicy/cloud-SG layer instead.
- **Cloud LB health checks** — ALB/GCP health-check ranges (e.g., VPC CIDR, GCP `100.64.0.0/10` probing ranges) must reach targets, so host-firewall "openness" to those ranges is a functional requirement. Confirm the listener behind it actually needs protection before flagging; scope findings to genuinely public paths.
- **Containers with `--network=host`** — their listeners appear in host `ss -tlnp` as ordinary processes; the fix belongs in container launch args/compose, and host-firewall rules still apply normally (no DNAT). Don't double-report both layers as separate findings when one root cause explains both.
- **Cluster interconnects** (Galera, etcd peer ports, NFS) legitimately bind private interfaces broadly; classify by interface reachability, not by port alone.

## References

- Netfilter/nftables wiki — https://wiki.nftables.org/ (ruleset syntax, meters, logging); netfilter project documentation — https://netfilter.org/documentation/
- Man pages: `nft(8)`, `iptables(8)`, `ip6tables(8)`, `ufw(8)`, `firewalld(1)`, `firewall-cmd(1)`, `fail2ban-client(1)`, `jail.conf(5)` (fail2ban jail configuration manual), `ss(8)`, `at(1)`
- Docker published-port/iptables interaction — https://docs.docker.com/network/iptables/
- ufw-docker tool — https://github.com/chaifeng/ufw-docker
- fail2ban wiki (filters, actions) — https://github.com/fail2ban/fail2ban/wiki
- CWE-16 Configuration — https://cwe.mitre.org/data/definitions/16.html
- CWE-284 Improper Access Control — https://cwe.mitre.org/data/definitions/284.html
- OWASP Top 10 A05:2021 Security Misconfiguration — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- CIS Distribution Independent Linux Benchmark (firewall section baseline naming)
