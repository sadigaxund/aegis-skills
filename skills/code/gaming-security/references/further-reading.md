# Gaming & Multiplayer Service Security — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & frameworks

- [OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) - server-side authorization rules for money-moving actions backing every economy-integrity check.

## Deep dives

- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) - the module's primary weakness class; its AUTH-then-command demonstrative example is the raw-socket substitution test in miniature.
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) - umbrella for receipt/integrity findings (scores, saves, webhooks); note mapping-discouraged status, cite children in final reports.
- [Gabriel Gambetta: Client-Server Game Architecture](https://www.gabrielgambetta.com/client-server-game-architecture.html) - canonical plain-language explanation of authoritative servers, "don't trust the player," and why prediction needs reconciliation — the Mental Model in essay form.

## Vendor docs

- [Apple App Store Server API](https://developer.apple.com/documentation/appstoreserverapi) - the server-to-server transaction verification surface that purchase checks E23–E26 must call.
- [Google Play Developer API](https://developers.google.com/android-publisher) - Google's counterpart for purchase-status and voided-purchase management behind refund-revocation checks.

(6 URLs total; each returned HTTP 200 with matching content when fetched.
Dropped during verification: developer.valvesoftware.com Source networking
wiki (anti-bot proof-of-work page, content not retrievable) and Android Play
Integrity docs (repeated transport errors). The Gambetta series covers the
authoritative-server grounding; store verification coverage above suffices.)
