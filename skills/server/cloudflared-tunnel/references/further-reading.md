# Cloudflare Tunnel Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding pillar needs authoritative backing;
SKILL.md's sweeps and interview checklist remain the primary reference.

## Tunnel mechanics

- [Cloudflare Tunnel (public applications)](https://developers.cloudflare.com/tunnel/) - outbound-only connection model, four-connections-to-two-data-centers redundancy, replica/HA guidance behind the operational-hygiene checks.
- [Cloudflare Tunnel (Zero Trust / private networks)](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) - the same daemon's private-networking role plus the note that tunnel origins need no inbound listener, grounding the "tunnel replaces port exposure" framing.

## Edge layers (dashboard-side — corroborates interview items)

- [Access policies](https://developers.cloudflare.com/cloudflare-one/policies/access/) - Allow/Block/Service Auth actions and common misconfigurations ("Include everyone") backing the Zero Trust Access interview questions.
- [WAF overview](https://developers.cloudflare.com/waf/) - managed rulesets, custom rules, rate-limiting rules feature map for the edge-controls inventory.
- [Authenticated Origin Pulls (mTLS)](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) - the anti-bypass control AND its documented limit: AOP does not apply to tunnel-routed hostnames (no inbound listener) — quote this nuance in interviews rather than assuming it closes direct-to-origin gaps.

## Origin binding discipline

- [Cloudflare IP Ranges](https://www.cloudflare.com/ips/) - the authoritative current range list for firewall allowlists and real_ip scoping; fetch-at-deploy-time and re-review cadence per Remediation 4.

Nothing here replaces evidence rules: dashboard settings stay interview items
(Confirmed/Unconfirmed), host findings cite `ss`/unit/config output per SKILL.md;
these links corroborate vendor semantics only.
