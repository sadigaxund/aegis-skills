# TLS Proxy & Edge Hardening — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's Remediation section remains the primary fix reference.

## Server documentation (primary proxies)

- [nginx documentation](https://nginx.org/en/docs/) - vendor root for every directive audited here (`ssl_protocols`, `add_header` inheritance, `proxy_set_header`, `limit_req`) plus the http_access/ssl module pages.
- [Apache mod_ssl reference](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html) - authoritative `SSLProtocol`/`SSLCipherSuite`/stapling directives behind the Apache equivalents.
- [HAProxy documentation](https://docs.haproxy.org/) - version-indexed configuration manuals covering `ssl-min-ver` bind options and crt bundle layout.
- [Caddy documentation](https://caddyserver.com/docs/) - automatic-HTTPS model, Caddyfile `header` blocks, and the localhost admin API checked in the secondary-proxy section.

## TLS profiles & certificate lifecycle

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) - the canonical per-server/version protocol+cipher profiles SKILL.md mandates copying verbatim (page now forwards to the maintained TLSRef configurator).
- [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/) - official weekly duplicate-cert/domain caps and staging-environment guidance backing the ACME-hygiene checks.
- [Certbot](https://certbot.eff.org/) - upstream docs for timers, renewal hooks, and `renew --dry-run` proof used in remediation F2/V5.

## Standards

- [RFC 6797 — HTTP Strict Transport Security](https://datatracker.ietf.org/doc/html/rfc6797) - normative max-age/includeSubDomains semantics and the bootstrap-window threat model behind the staged rollout rule.
- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) - practical browser behavior (persistence, no click-through, preload caveats) explaining the lockout hazard.
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) - the mapped weakness class for plaintext proxy-to-app hops across network segments.

Nothing here replaces the in-repo evidence rules: judge effective config
(`nginx -T`, `openssl s_client` probes) per SKILL.md first; these links
corroborate.
