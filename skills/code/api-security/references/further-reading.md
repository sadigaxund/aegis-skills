# API Security — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's framework location map remains the primary audit reference.

## Standards & cheat sheets

- [OWASP API Security Top 10 project](https://owasp.org/www-project-api-security/) - the 2023 category list this module's References section maps class-by-class.
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) - framework-by-framework allowlist patterns backing the binding findings and fixes.
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) - method/content-type/validation hygiene behind the REST-hygiene class.

## Deep dives

- [GraphQL.org: Security](https://graphql.org/learn/security/) - foundation-published guidance on depth limiting, complexity analysis, introspection, and error masking matching the GraphQL checks.
- [PortSwigger Web Security Academy: API testing](https://portswigger.net/web-security/api-testing) - recon-to-exploitation methodology including a mass-assignment walkthrough aligned with the module's procedures.

## Vendor docs

- [gRPC Authentication guide](https://grpc.io/docs/guides/auth/) - vendor semantics of channel vs call credentials underpinning the per-RPC interceptor remediation.
- [Socket.IO: Handling CORS](https://socket.io/docs/v4/handling-cors/) - vendor documentation of origin options and the WebSocket-not-covered-by-CORS caveat cited in the channel checks.

Framework semantics decide false positives (SKILL.md, Common False Positives);
these links corroborate the binder, limiter, and channel behavior a finding cites.
