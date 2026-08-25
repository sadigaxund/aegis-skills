# Firewall & Network Edge Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's Remediation section remains the primary fix reference.

## Ruleset references (nftables / netfilter)

- [nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) - project HOWTO hub covering families (`inet` = dual-stack), hooks, and conntrack — the concepts behind the IPv6-parity check.
- [nftables quick reference in 10 minutes](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes) - syntax cheat sheet for matches, `limit rate` meters, and the exact drop-policy shapes in the remediation block.
- [netfilter project documentation](https://netfilter.org/documentation/) - canonical home for iptables-era HOWTOs and conntrack material supporting legacy-backend audits.

## Manager documentation (ufw / firewalld)

- [ufw(8) man page — Ubuntu manpages](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html) - normative semantics of `default deny`, `limit`, route rules, and the IPV6=yes toggle cited in the ufw sequence.
- [firewalld](https://firewalld.org/) - vendor doc root explaining zones and the runtime-vs-permanent split the self-reverting remediation relies on.

## Container interaction (the DNAT bypass)

- [Docker: Packet filtering and firewalls](https://docs.docker.com/network/iptables/) - vendor confirmation that published ports divert before ufw's INPUT/OUTPUT chains evaluate — the authoritative basis for the Docker-bypass finding.
- [ufw-docker](https://github.com/chaifeng/ufw-docker) - maintained utility implementing DOCKER-USER-stage rules for ufw hosts, referenced by SKILL.md's defense-in-depth fix.

## Brute-force response

- [fail2ban](https://github.com/fail2ban/fail2ban) - upstream project (jails, filters, IPv6 support since 0.10) backing the sshd/nginx jail configuration; its own README notes it complements, not replaces, strong auth.

Nothing here replaces the in-repo evidence rules: judge loaded state
(`nft list ruleset`, `iptables -S`, `ss -tlnp`) per SKILL.md first; these links
corroborate.
