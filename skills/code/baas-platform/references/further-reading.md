# BaaS & Managed Platforms — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding platform finding needs authoritative
backing; SKILL.md's footgun matrix remains the primary platform reference.

## Standards & cheat sheets

- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) - deny-by-default and least-privilege principles underlying every rules/policies finding.
- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) - the normative RLS semantics (enable, per-operation policies, USING vs WITH CHECK) beneath Supabase's model.

## Deep dives

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) - the pillar weakness this module's findings map to, with specification-vs-enforcement framing.

## Vendor docs

- [Supabase: Row Level Security guide](https://supabase.com/docs/guides/database/postgres/row-level-security) - vendor guidance on grants + policies, anon/authenticated roles, service_role bypass, and policy testing matching the flagship checks.
- [Firebase: Get started with Cloud Firestore Security Rules](https://firebase.google.com/docs/firestore/security/get-started) - vendor rule structure (match/allow, request.auth) behind the rules-file review.
- [Stripe: Webhooks](https://docs.stripe.com/webhooks) - vendor requirements for raw-body signature verification, replay tolerance, retries, and duplicate-event handling cited in webhook remediation.
- [Vercel: Deployment Protection](https://vercel.com/docs/deployment-protection) - vendor options (authentication scope, password protection, source-map gating) for the preview-exposure class.

Vendor console settings change; when a screenshot or migration cannot confirm a
control's state, report per SKILL.md as `Needs-Review` rather than assuming.
