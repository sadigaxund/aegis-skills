---
name: incident-response-lifecycle
description: Dual-purpose incident-response module that audits whether an organization actually possesses IR capability and provides the phase-by-phase execution playbook that turns this skillset's audit findings into operational readiness when a real incident hits.
category_slug: IR
cwe: []
owasp: N/A – Operational (maps to NIST CSF Respond/Recover)
---

# Incident-Response Lifecycle (IR)

## Adaptation Note — Read First

This module deviates from the red-team template on purpose. It is not vulnerability hunting; it is the orchestration layer that runs WHEN a finding is exploited or an audit gap is hit in production. Section meanings are remapped as follows:

| Template section | Meaning HERE |
|---|---|
| What To Check | Readiness-audit items: does IR capability exist at all? |
| Where To Look | Where artifacts/docs/tools should live if capability exists |
| Patterns & Signatures | Playbook templates, checklists, scenario tables (the bulk) |
| Taint Tracing Guidance | Escalation/communication chains: who informs whom, when |
| Exploitation & Reproduction | Tabletop exercise procedures (simulated, explicitly non-destructive) |
| Severity Assessment | Incident-severity matrix SEV1–SEV4, NOT vulnerability CVSS |

Empty `cwe` array is intentional: this module audits process capability, not a code-level weakness class. Cross-references assume sibling modules by slug: TOK (`skills/server/api-token-security/SKILL.md`), SUPPLY (`skills/code/supply-chain/SKILL.md`), DR (`skills/server/backup-dr/SKILL.md`), LOGMON (`skills/server/logging-monitoring/SKILL.md`), DETECT (`skills/operations/blue-team-detection/SKILL.md`). The host-forensics deep-dive (DFIR) is a planned companion; until it exists in your copy, treat this module's evidence-preservation steps plus the sweep scripts under `tools/sweeps/` as authoritative for triage-time forensics.

## Scope & Objectives

Two halves, one lifecycle:

**Half A — READINESS AUDIT.** Answer one question with evidence: if an incident starts in the next hour, does anything besides improvisation happen? Audit for: written playbook, contact/on-call tree including an out-of-band channel, break-glass access procedure, notification-obligations inventory, evidence-handling capability, insurance/vendor contacts, restorable-backup proof.

**Half B — EXECUTION PLAYBOOK.** Phase-by-phase guidance for running an incident: Preparation, Detection & Analysis, Containment, Eradication, Recovery, Lessons Learned — with concrete templates, decision trees, and five scenario playbooks matching this playbook's own finding classes (leaked tokens, webshell/RCE, database exfiltration, malicious dependency, committed secrets).

Deliverables of an audit run with this module:

1. **Readiness scorecard** — each Half-A item graded PRESENT / PARTIAL / ABSENT with artifact pointers.
2. **Gap list feeding Remediation** — every ABSENT item becomes a build task with an owner.
3. **Populated templates** — intake form, first-hour checklist, escalation map, postmortem skeleton, ready to drop into the team's wiki.
4. **Tabletop record** — one exercised scenario with injects and debrief findings (Verification & Validation).
5. **Metrics baseline** — time-to-detect (TTD) and time-to-mitigate (TTM) definitions wired to DETECT alert timestamps.

Operating rules:

- Read-only during audit. Mutating actions appear only inside the EXECUTION half and only when an actual incident is declared — never to "test" production.
- No legal advice: notification obligations are framed generically (e.g., the GDPR 72-hour regulator-notification CONCEPT, contractual customer clauses). Deadlines vary by jurisdiction and contract — verify your own obligations and write them down before an incident; do not improvise them during one.
- Every action taken during a real incident is logged by the responder in the incident ticket from minute zero (chain-of-custody-lite; full custody discipline belongs to DFIR).
- This module orchestrates siblings during incidents: LOGMON supplies the logs, DETECT supplies the page and severity context, TOK/SUPPLY/DB/HSECRET supply rotation and rebuild specifics, DR supplies the restore path, `tools/run-all-sweeps.sh` supplies validation sweeps.

Out of scope: writing detection rules → DETECT; performing host forensics image analysis → DFIR companion; backup design → DR; secret storage hygiene → HSECRET; legal determination of breach status → counsel.

## Mental Model

Incident response is a loop with a memory, not a document:

```
            ┌────────────────────────────────────────────────┐
            │                                                │
            ▼                                                │
   [1 PREPARATION]────► [2 DETECTION & ANALYSIS]             │
    tooling staged       triage intake, severity,            │
    inventories fresh    preserve-evidence-FIRST             │
            │                        │                       │
            │                        ▼                       │
            │               [3 CONTAINMENT]                  │
            │                stop the bleeding,              │
            │                keep the evidence               │
            │                        │                       │
            │                        ▼                       │
            │               [4 ERADICATION]                  │
            │                root cause or it returns        │
            │                        │                       │
            │                        ▼                       │
            │               [5 RECOVERY]                     │
            │                validate → stage → watch        │
            │                        │                       │
            │                        ▼                       │
            └──────────[6 LESSONS LEARNED]                   │
              blameless postmortem                           │
              fixes feed BACK into audit modules ─────────────┘
```

Four axioms:

1. **Evidence before remediation.** The reflex to fix destroys the record of how. Order-of-volatility applies from minute zero: capture volatile state (memory, connections, sessions, process lists) before disk, disk before reboot, reboot never before snapshot (cloud) — details per scenario in Patterns & Signatures.
2. **Containment has two clocks.** Short-term containment (minutes: cut access, isolate host) trades visibility for safety; long-term containment (hours: rotate, patch, rebuild) restores hygiene without tipping off remaining footholds prematurely. Skipping straight to eradication loses both.
3. **Assume compromise propagates through credentials.** Any credential present on or reachable from a compromised system is burned. Rotation cascades follow trust edges, not convenience.
4. **An untested plan is a wish.** Capability = artifact + person + rehearsal. A playbook nobody can find during a 3 a.m. page scores the same as no playbook.

Readiness and execution share one inventory: every Half-A gap discovered in the audit is a phase-B failure waiting at a specific step. Map gaps to phases so remediation order matches incident order.

## What To Check

Audit each item; grade PRESENT / PARTIAL / ABSENT and record the artifact pointer (or its absence).

### R1. Written IR playbook exists

A named document covering all six phases, with scenario playbooks for this team's realistic incidents (the five in Patterns & Signatures minimum), versioned and dated. ABSENT if response knowledge lives only in one person's head or chat scrollback.

### R2. Contact / on-call tree documented — with out-of-band channel

Check for: current roster (names, roles, phone numbers, personal emails), 24h escalation order, vendor/cloud support ticket paths with account IDs, AND an out-of-band communication channel that survives compromise of primary tooling. If email/Slack is attacked or the identity provider is down, that channel is gone — verify a secondary exists (e.g., pre-agreed group SMS/Signal thread, phone bridge, or a separate tenant you do not administer through the same IdP). Verify the tree was reviewed within the last 6 months.

### R3. Break-glass access procedure

When SSO/MFA/IdP is down or accounts are locked by the attacker, someone must still get in. Check for: escrowed cloud-provider console credentials (offline, tested), password-manager emergency-recovery procedure documented and REHEARSED (who holds recovery kit, how re-entry works), local admin/break-glass accounts on hosts and Postgres with rotated-on-use discipline, and printed/offline copies of critical recovery material. Untested escrow = PARTIAL at best.

### R4. Legal/compliance notification-obligations inventory

A written list of who must be told when data is confirmed breached: regulators under applicable regimes (e.g., jurisdictions applying the GDPR 72-hour notification concept — verify which apply to YOU), contractual customer-notification clauses with their own clocks, cyber-insurance policy notification requirements, payment/card processors if applicable. Each entry names: trigger condition, deadline, who files, contact address. No deadlines asserted from memory during an incident.

### R5. Evidence-handling capability

Check for: answer to "where would logs come from" cross-checked against LOGMON findings (central store? retention long enough to cover detection lag? attacker-wipeable local-only logs?), at least one person able to image/preserve a host (cloud snapshot procedure written down per provider used, disk-copy command documented), and a designated evidence location with access control. Cross-ref DETECT: if the pipeline-flow verdict is BLIND for a class, evidence capability for incidents of that class is ABSENT by definition.

### R6. Insurance and vendor contacts present

Cyber-insurance policy location, broker/emergency contact, requirement to use insurer-approved forensics vendors noted if applicable. Critical vendor security contacts (cloud provider abuse/support, Cloudflare enterprise support path, managed-service contacts) reachable without login to the affected systems.

### R7. Backups restorable — proven, not assumed

Cross-ref DR module's verification results: recent restore test date, RPO/RTO numbers written down, backup access independent of compromised production credentials (break-glass R3 applies here too). "Backups exist" is not capability; "we restored <service> on <date> in <duration>" is.

### R8. Pre-staged tooling and inventories (feeds Phase 1)

Asset-inventory currency (see Preparation), sweep scripts runnable (`tools/run-all-sweeps.sh` executes clean on a representative host), severity/paging matrix adopted from DETECT, out-of-band admin path (R3) linked into the playbook itself.

### R9. External reporting channel exists

A `security.txt` at `/.well-known/security.txt` (Contact, Expires, Policy fields) and a
stated coordinated-disclosure policy somewhere linkable, so researchers report instead of
posting. Missing channel = findings arrive via public posts. Template fields: Contact:
mailto:, Expires: <date ≤12mo>, Policy: <link>.

## Where To Look

Capability leaves artifacts. Absence of artifacts where they should be is itself the finding.

| Item | Where it should live | Tell-tale absence |
|---|---|---|
| IR playbook (R1) | Team wiki/docs repo root, `docs/incident-response.md` or equivalent, version-controlled | Only mentions inside chat history or one person's notes |
| On-call tree + OOB channel (R2) | Same doc, PLUS offline copy (printed binder, password-manager secure note) | Tree only in the paging tool that may be down |
| Break-glass (R3) | Password manager "emergency" vault; sealed offline envelope; cloud provider documented recovery flow | Recovery kit never generated/tested |
| Notification obligations (R4) | Table in the IR playbook; contract-summary spreadsheet from sales/legal | Nothing; obligations rediscovered ad hoc |
| Evidence sources (R5) | LOGMON central store config; retention settings; snapshot runbooks per cloud account | Local-only rsyslog/journald (LOGMON finding), no snapshot docs |
| Insurance/vendors (R6) | Password-manager vault entries + playbook appendix | Policy PDF unfindable when asked for |
| Backup proof (R7) | DR module restore-test records, dated log of last successful restore | Restore scripts exist, no dated test output anywhere |
| Tooling/inventory (R8) | `tools/run-all-sweeps.sh` green run output; asset inventory in CMDB/repo/spreadsheet with last-reviewed date | Inventory last touched before the newest service shipped |

Also inspect: on-call/paging tool config (schedules match R2 roster), cloud IAM for break-glass accounts actually existing, git history of the playbook (a doc edited yearly is a shelf document).

## Patterns & Signatures

The execution playbook. All blocks are fill-in-ready; copy into the team wiki and populate the bracketed fields BEFORE an incident.

### Scenario × Phase Coverage Grid

Every scenario must have owners for every phase. Gaps in this grid are readiness findings.

```
| Scenario                        | Prep            | Detect/Analyze        | Contain                | Eradicate           | Recover              |
|---------------------------------|-----------------|-----------------------|------------------------|---------------------|----------------------|
| (a) leaked/compromised API token| TOK runbook link| DETECT authz anomalies| revoke-first ordering  | rotate dependents   | prefix-hunt usage    |
| (b) webshell/RCE suspected      | snapshot runbook| LOGMON process/egress | isolate serving, keep  | rebuild from IaC    | re-run sweeps        |
|                                 |                 |                       | evidence               |                     |                      |
| (c) DB breach / data exfil      | DR restore proof| Postgres log refs     | credential cascade     | assume-all-stolen   | staged return        |
| (d) malicious/vuln dependency   | SBOM/lockfiles  | SUPPLY advisories     | freeze deploys         | pin/remove/assess   | heightened watch     |
| (e) secrets committed to git    | HSECRET scan    | SECRETS sweep output  | rotate-everything-     | history rewrite     | rescan clean         |
|                                 | cadence         |                       | touched                | SECONDARY           |                      |
```

### Phase 1 — PREPARATION

What must already exist when the page arrives:

1. **Centralized logs flowing** — per LOGMON; local-only logging means Phase 2 starts blind.
2. **Sweep scripts executable** — `tools/run-all-sweeps.sh` verified runnable on representative hosts; output directory convention known.
3. **Out-of-band admin path tested** — break-glass console login performed at least once by each on-call member (R3).
4. **Asset inventory current** — every internet-facing service listed with: owner, host/cluster, cloud account, data sensitivity, dependency on other assets. Currency rule: reviewed within 30 days OR automatically derived from IaC. An inventory that predates the newest service fails.
5. **Severity/paging matrix adopted** — SEV1–SEV4 table (see Severity Assessment) wired to paging so severity assignment is a lookup, not a debate at 3 a.m.
6. **This playbook linked from every alert** — DETECT alert payloads include a pointer to intake form + first-hour checklist.

### Phase 2 — DETECTION & ANALYSIS

**Triage intake form — capture these fields for EVERY incident, no exceptions:**

```
INCIDENT INTAKE
Incident ID:        IR-YYYYMMDD-NN          Declared by: [name]   At (UTC): [ts]
What happened:      [one sentence, observed facts only, no speculation]
When first seen:    [UTC ts]   Detection source: [alert name / report / customer]
Scope guess:        [hosts/services/accounts/data believed involved — label as GUESS]
Evidence pointers:  [alert URL, log query, dashboard, screenshot location]
Customer-impacting: [yes/no/unknown]   Data-exfil-suspected: [yes/no/unknown]
Initial severity:   [SEV1-4 per matrix]   Comms thread: [channel/bridge]
Responder scribe:   [name — owns timeline below]
```

**Initial severity decision tree** (first question wins):

```
Data exfiltration SUSPECTED or confirmed?            -> SEV1
Auth bypass / RCE ACTIVE in production?              -> SEV1
Attacker-controlled persistence found?               -> SEV1
Single host compromised, contained blast radius?     -> SEV2
Credential leak with no confirmed misuse yet?        -> SEV2
Vulnerable/malicious dependency present, unexploited -> SEV3
Anomaly investigated, likely benign but unresolved   -> SEV4 (monitor)
Downgrade only after two independent confirmations; upgrade instantly and freely.
```

**Evidence preservation comes FIRST — before remediation, always:**

Order of volatility (full treatment in DFIR companion): memory/live processes → network state and sessions → disk → backups/archives. Minimum triage-time captures before touching anything:

```bash
# On affected host, before isolation changes kill sessions:
ps auxf > /tmp/ir_ps.txt; ss -tunap > /tmp/ir_sockets.txt   # [ROOT] for -p
last -F > /tmp/ir_logins.txt; w > /tmp/ir_sessions.txt
cp -r /var/log/auth.log* /tmp/ir_logs_$HOST/ 2>/dev/null    # Debian-family
journalctl --since "-48h" > /tmp/ir_journal.txt
# Cloud hosts: SNAPSHOT DISK BEFORE REBOOT/TERMINATE. Reboot destroys
# memory-resident evidence and attacker artifacts may be timestomped on disk.
```

Copy captures OFF the affected host immediately (attacker wipes). Record hash if tooling allows (`sha256sum`). Sweep scripts under `tools/sweeps/` double as structured first-pass collectors — run the relevant ones and archive stdout.

**Incident ticket structure — timeline from minute zero:**

Every responder action is appended as it happens. This is chain-of-custody-lite: who did what, when, why, with what command.

```
TIMELINE (all times UTC, append-only, never edit past entries)
[HH:MM] DETECT alert <name> fired — link. (auto/system)
[HH:MM] <name> acknowledged, declared IR-..., initial SEV2.
[HH:MM] <name> ran `ss -tunap` on web-prod-01; captured to /tmp/ir_*.txt; copied to evidence store.
[HH:MM] <name> isolated web-prod-01 from LB (removed target) — SHORT-TERM containment.
...
Decisions log (separate section): each entry = decision, rationale, decider, time.
Evidence index: artifact -> where stored -> who copied it -> when.
```

### FIRST-HOUR CHECKLIST — execute in exact order

```
 1. Declare incident: open ticket IR-YYYYMMDD-NN, fill intake form completely.
 2. Assign roles out loud: incident lead, scribe, responders. One person may hold two;
    nobody holds zero.
 3. Start the scribe timeline. From here on, every action gets logged BEFORE or AS it runs.
 4. Preserve volatile evidence on affected systems (commands above; snapshot cloud disks).
 5. Apply short-term containment per scenario table (revoke token / isolate host /
    freeze deploys). Fastest safe action first.
 6. Assign preliminary severity via decision tree; page per matrix. Upgrade freely.
 7. Open the pre-agreed OUT-OF-BAND channel (R2); post incident ID + severity there.
 8. Pull detection context from DETECT/LOGMON: what fired, what else looked like it
    (pivot queries), earliest related event = provisional start-of-incident timestamp.
 9. Send first internal exec update (template in Taint Tracing) — facts only,
    "investigating", next update at stated time.
10. Decide containment-vs-evidence tradeoff explicitly and record it in Decisions:
    what visibility will short-term containment cost, and is it accepted?
```

Steps 1–7 target completion within 15 minutes of declaration. If any step blocks (no escrow access, no channel), that block IS the readiness finding — record it even mid-incident.

### Phase 3 — CONTAINMENT

Two distinct stages; do them in order:

- **Short-term containment (minutes).** Cut attacker access and stop spread: revoke credentials, isolate hosts, disable accounts, remove from load balancer. Costs visibility — log what you cut BEFORE cutting where feasible (export sessions, capture flows).
- **Long-term containment (hours).** Apply interim hardening on clean paths while eradication is prepared: rotate dependent credentials, patch on unaffected hosts, tighten firewall rules, raise logging verbosity. Buys time without the risk of a rushed rebuild.

| Scenario | Short-term containment | Long-term containment |
|---|---|---|
| (a) token compromised | Revoke token NOW | Rotate dependents, audit grants |
| (b) webshell/RCE | Isolate host from serving | Rebuild plan, hunt siblings |
| (c) DB breach/exfil | Kill app→DB creds in use | Cascade rotation, scope theft |
| (d) bad dependency | Freeze deploys | Pin/remove, assess exposure |
| (e) secrets in git | Block repo access if account abused | Rotate everything touched |

#### Scenario (a) — Leaked or compromised API token

Order matters: REVOKE FIRST, investigate second. A live token being "watched" is an active breach.

1. **Revoke the token immediately** via provider console/API. Do not wait to confirm misuse; re-issue later is cheap, continued attacker use is not.
2. **Rotate every dependent credential** that shared trust with it: refresh tokens issued from it, session tokens bound to it, downstream service credentials it could mint.
3. **Hunt usage by prefix** per the TOK runbook: query provider logs for the key prefix/ID across all regions/accounts; list every API call with timestamp, source IP, UA, resources touched.
4. **Find the leak source**: which log/repo/ticket/client shipped the token? Cross-ref SECRETS sweep output; fix the emitter or it recurs.
5. **Scope blast radius**: what could the token read/write? Enumerate permissions, assume worst observed action plus everything unlogged.
6. **Record rotation chain** in ticket: old ID → revoked at [ts] → replaced by [ref] → dependents rotated by [names/ts].

#### Scenario (b) — Webshell / RCE suspected

1. **Snapshot before anything restarts**: cloud disk snapshot AND memory/live-state captures (order-of-volatility above). Snapshot-before-reboot is non-negotiable on cloud hosts — reboot destroys memory evidence.
2. **Isolate from serving while preserving evidence**: remove from LB/target group, block egress except your collection path, keep host powered ON. Do not power off unless actively hostile to you — a running box can be interrogated; a powered-off one only imaged.
3. **Capture**: process tree, listening sockets, cron/systemd units, webroot file lists sorted by mtime, shell history, auth logs — then copy OFF-host to evidence store.
4. **Identify entry vector**: correlate first-anomaly timestamp with LOGMON data — which request/deploy/credential preceded it? If unanswerable, that is a DETECT gap finding.
5. **Hunt siblings**: same indicators across all similar hosts (`for h in $(inventory); do sweep...`); webshells rarely travel alone.
6. **Do NOT clean in place** as endgame — cleaning a compromised host is eradication theater; proceed to rebuild (Phase 4).

#### Scenario (c) — Database breach / data exfiltration

1. **Cut the bleeding path**: rotate the application DB credentials in active use, kill suspicious sessions (`pg_terminate_backend`), revoke the specific role/grant used.
2. **Cascade rotation along trust edges**: app→DB creds, DB superuser, replication credentials, backup-tooling creds, any secret the DB host could reach (HSECRET inventory of that host). One rotation missed = re-entry path.
3. **Scope honestly — assume all data in the DB is stolen until proven otherwise.** Proving a negative is expensive; the scoping statement to executives should say exactly this and enumerate what WAS in the database (tables, PII classes, row counts) rather than claim bounds you cannot evidence.
4. **Pull Postgres evidence** before logs roll: `log_connections`/`log_disconnections`/`log_statement` output (cross-ref DB module — these were supposed to be ON), `pg_stat_activity` history if captured, WAL/archive anomalies.
5. **Determine exfil volume ceiling**: query bytes served / rows readable by the compromised role over the exposure window; record as upper bound with its assumptions stated.
6. Trigger R4 obligations review EARLY — notification clocks may start at confirmation, and confirming takes time you may not have.

#### Scenario (d) — Malicious or vulnerable dependency discovered in production

1. **Freeze deploys** (CI flag or lock branch protection): no new code reaches prod until the dependency question is settled — otherwise you cannot tell compromised builds from clean ones.
2. **Pin or remove**: pin to last-known-good version, or remove entirely per SUPPLY guidance. Record exact versions in/out.
3. **Assess runtime exposure**: is the malicious/vulnerable code path actually executed? Check call graphs, feature flags, import reachability. Exposure assessment determines whether this is hygiene (SEV3) or incident (SEV2+).
4. **Sweep for indicators**: per SUPPLY — unexpected network destinations, new install scripts, postinstall hooks in lockfile diffs across ALL services, not just the reporter's.
5. **Verify build provenance** of what is currently running: was the deployed artifact built from the lockfile you think? Container image digests vs source.
6. Unfreeze only after rebuilt/clean artifacts pass `run-all-sweeps.sh` plus targeted checks.

#### Scenario (e) — Secrets committed to git

1. **ROTATE EVERYTHING TOUCHED — this rule has no exceptions and comes FIRST.** Every secret ever present in the exposed history is burned, including ones removed long ago and ones in "private" repos. Assume clones/forks/cache exist.
2. Only after rotation completes: **history rewrite is SECONDARY** (filter-repo/BFG) plus force-push coordination, provider-side cache purge, and notification to anyone holding clones. Rewriting history does not un-leak; rotation does.
3. **Enumerate the full set**: run SECRETS-class sweeps against full history, not just HEAD (`git log -p` scanning, tooling per secrets-data-exposure module); produce the burned-secret list with owners.
4. **Check abuse**: for each burned secret, provider-side usage logs (pairs with scenario (a) hunting).
5. **Fix the emitter**: pre-commit hooks, CI secret-scanning gate so the class closes.
6. Ticket records: each secret → leaked-in commit → rotated at → verified-by-log line.

### Phase 4 — ERADICATION

**Root cause or it will return.** Removing the artifact (webshell, token, dependency) without removing the ENTRY PATH guarantees a repeat incident. Eradication ends only when you can state: initial access vector, persistence mechanisms (ALL of them), and why each is now closed.

**Rebuild-vs-clean framing.** Default recommendation: **rebuild from IaC when feasible.** Cleaning trusts your ability to find every implant; rebuilding trusts your pipeline instead. Choose clean-in-place ONLY when rebuild cost is genuinely prohibitive AND forensic confidence in full-artifact enumeration is high — write that justification into the ticket. For k8s workloads: redeploy from images built fresh from known-good source, never restart existing pods. For hosts: reprovision from config management/cloud-init, restore data only from pre-incident backups validated clean (DR).

**Credential-rotation completeness checklist pattern** — enumerate, don't brainstorm:

```
For the compromised scope, list and check off:
[ ] Creds PRESENT on affected systems (files, env, configmaps, .netrc, ssh keys)
[ ] Creds REACHABLE from them (IAM roles, cloud metadata, service accounts)
[ ] Creds SHARED/trusted (API keys minting sub-tokens, OAuth grants, sessions)
[ ] Human creds with standing access to the scope
[ ] Machine-to-machine creds on every edge of the trust graph
Source of truth: HSECRET inventories + IAM reviews — not memory.
```

### Phase 5 — RECOVERY

**Validation-before-restore-to-service gate.** Rebuilt systems earn traffic only after:

```
[ ] Relevant check modules re-run CLEAN against the rebuilt system
    (the modules whose findings enabled this incident)
[ ] tools/run-all-sweeps.sh green on rebuilt hosts/clusters
[ ] Targeted checks: TOK rotation verified provider-side; SUPPLY lockfile
    diff reviewed; DR restore integrity confirmed for restored data
[ ] Detection confirmed LIVE: would DETECT fire if the same attack replayed?
    (purple-team style validation, staging-safe)
```

Then return traffic staged: internal users → canary percentage → full. Keep rollback path warm during entire ramp.

**Heightened-monitoring window:** 14–30 days watchlist on the affected scope — DETECT rules for the incident's indicators at lowered thresholds, daily review of auth/anomaly logs, calendar reminder set at declaration time so expiry is deliberate, not forgotten. Attackers commonly test re-entry within days of eviction; the window exists because of that, not ceremony.

### Phase 6 — LESSONS LEARNED

Hold within 5 business days while memory is fresh. Blameless means: systems and contributing factors, not culprits — "the token lacked expiry" not "Alice committed the token."

**Blameless postmortem skeleton:**

```
# IR-YYYYMMDD-NN: <one-line title>
Severity: [SEVx -> final]   Duration: [detect -> mitigate -> close]
Impact: [users/data/duration/money — numbers]

TIMELINE
[detect] [declare] [contain-short] [contain-long] [eradicated] [recovered]
(each: UTC ts + one line + link)

CONTRIBUTING FACTORS (not culprits)
- detection: [why TTD was what it was]
- prevention: [which check-module gap let it in]
- response: [what slowed containment/mitigation]
- process: [ambiguity, missing tooling, stale docs]

WHAT WENT WELL (keep these)

ACTION ITEMS
| # | Action | Owner | Due date | Type |
|---|--------|-------|----------|------|
| 1 |        |       |          | prevent/detect/respond/process |

AUDIT-SKILLSET UPDATES DISCOVERED
- findings that map back to playbook modules needing fixes/additions:
  [module slug + proposed change]   <- feed these BACK into the skillset

METRICS
TTD: [first malicious event -> detection]   TTM: [declaration -> mitigation]
```

**Metrics definitions (capture every incident, baseline over time):**
- **TTD (time-to-detect):** first attacker action visible in logs → detection alert/report fired. Long TTD = DETECT/LOGMON investment needed.
- **TTM (time-to-mitigate):** incident declaration → attacker access credibly cut. Long TTM = containment authority/tooling gaps.
- Track also: time-to-evidence-preserved, action items closed past due (process health).

### Communications Guidance

**Never speculate before confirmation — externally this rule is absolute; internally label everything unconfirmed as GUESS.** One wrong public claim ("no data was affected") is unretractable and converts a security incident into a trust incident.

**Internal exec update template fields** (send on cadence even when nothing changed — "no change since HH:MM" counts):

```
EXEC UPDATE IR-... [SEVx] — <time UTC>
Status:  investigating / contained / eradicated / recovered / closed
Facts confirmed so far: [bulleted, sourced]
What we do NOT yet know: [explicit unknowns]
Actions in flight + owners
Customer/data impact: [known / under investigation]
External comms status: [none yet / drafted / sent — by whom]
Next update: [exact time]
```

**Customer-facing statement skeleton** (legal/counsel review REQUIRED before sending; obligations per R4):

```
On <date> we identified <plain-language issue class> affecting <service>.
Upon detection we <contained it — concrete actions>. Our investigation
<determined / is ongoing regarding> what information was involved.
<If notification obligations apply: who we notified and how affected
customers should protect themselves — concrete steps.>
Measures taken to prevent recurrence: <short list>.
Where to get help / updates: <channel>.
No speculation about attacker identity or cause before confirmation.
```

Cadence discipline: SEV1 internal updates hourly until contained; customer/regulator statements only after facts confirmed AND counsel review; single named spokesperson for external channels.

## Taint Tracing Guidance

Remapped: escalation and communication chains — who informs whom, triggered by what, with what latency. A finding "flows" upward like taint flows through a call graph; every sink must be named in advance.

```
DETECTION SINKS (who must hear, by severity):
SEV1: on-call -> incident lead -> executives (<15min) -> counsel/insurer
      (per R4/R6 triggers) -> board per policy
SEV2: on-call -> incident lead -> engineering manager (same day)
SEV3: ticket queue -> weekly review
SEV4: logged -> monitored

ESCALATION TRIGGERS (auto-upgrade the chain when any flips true):
- data-exfil-suspected flips to CONFIRMED  -> R4 clock review IMMEDIATELY
- second system implicated                  -> severity upgrade + exec update
- customer data classes involved            -> counsel joins chain
- >4h without containment                   -> bring secondary responder,
                                              declare SEV1 authority question
- media/customer inquiry received           -> spokesperson chain only,
                                              responders say NOTHING externally
```

Rules for the chain:

1. **One incident lead owns decisions; one scribe owns the record.** Escalation replaces leads explicitly and aloud ("lead handover at HH:MM") — never two implicit leads.
2. **Downward flow is as mandatory as upward**: executives must push back DOWN the promise of "no impact" before confirmation reaches them. The chain carries uncertainty honestly in both directions.
3. **Regulator/customer clocks are owned by a NAMED person from R4's inventory**, not "whoever gets to it". Their first action on trigger: open the deadlines table, write each applicable deadline into the ticket timeline.
4. **Out-of-band channel mirrors the primary chain** (R2): same roles reachable if Slack/email/IdP is the compromised asset. If the incident IS the identity provider, the OOB channel becomes primary — rehearse this flip in tabletops.

## Exploitation & Reproduction

Remapped: tabletop exercises — simulated incidents run against the PLAYBOOK, never production systems. Explicitly non-destructive: no packets to prod, no test credentials planted, no alerts manually triggered outside agreed windows with DETECT owners. The "exploit" being reproduced is organizational failure modes.

### Tabletop Facilitation Kit

**Facilitator role:** controls pace, plays all external parties, enforces blameless ground rules, captures gaps verbatim. Timebox: 90 minutes. Attendees: full on-call roster + one executive.

**Scenario card format** (prepare 2–3 cards per session):

```
TABLETOP CARD — <title>
Severity start: SEV?   Teams involved: [on-call, exec, counsel?]
Situation (read aloud at T0):
  "<one paragraph of observed symptoms, NO diagnosis included>
   It is <day/time>. <detection source> reported <observation>.
   On-call is <name>. Incident lead is unreachable by phone."
Hidden facts (facilitator reveals only on good probing questions):
  1. [fact that changes scoping]
  2. [complication: e.g., IdP degraded / token shared across services]
Win condition: [containment declared with correct evidence order +
  notifications triggered within stated clocks]
```

**Inject ideas list** (drop mid-exercise to stress specific phases):

- "The on-call's laptop battery dies; they are mobile-only now." (R2/OOB)
- "Slack is slow/unreachable — coordinate anyway." (OOB channel)
- "A reporter emails press@ asking about 'the outage'." (comms discipline)
- "Provider console MFA is failing org-wide." (break-glass R3)
- "Log retention turns out to be 72h and the first anomaly was 5 days ago." (LOGMON/R5)
- "The compromised API key is also used by the nightly backup job." (rotation cascade)
- "Legal asks: do we have 72 hours? For whom?" (R4 inventory)
- "Snapshot failed — disk was encrypted with a key held by the compromised account." (order-of-volatility, DR)
- "Mid-containment, CI deploys an unrelated hotfix to the isolated host." (freeze discipline)

**Debrief questions** (last 20 minutes, capture as action items):

1. Where did the playbook NOT have an answer, and who improvised?
2. What evidence would we have lost given our actual logging (cross-check LOGMON findings)?
3. Did severity assignment match the matrix, or did debate happen?
4. Which rotation cascade step would have been missed?
5. Who could not perform their role (access, knowledge, tooling)?
6. What does this exercise change in the audit modules? (feed into postmortem's AUDIT-SKILLSET section)

Run cadence: quarterly minimum, rotate scenarios so all five classes are exercised annually; every new on-call member participates within 30 days of joining.

## Remediation

Building missing Half-A capability, ordered so each step enables the next. Every item names its R-finding and produces an artifact.

**B0. Offboarding checklist (same-day) — standing insider-risk control.** Leavers with live access are a slow-motion incident; HR paperwork is not access revocation. Fill-in checklist:

```text
[ ] SSO/account disabled                        same day, effective immediately
[ ] SSH keys removed from all hosts             + authorized_keys sweep across fleet
[ ] API tokens / service accounts revoked       (TOK leak runbook applies)
[ ] Cloud IAM keys and active sessions revoked
[ ] Shared secrets this person knew ROTATED     (removing their access ≠ un-knowing a secret)
[ ] Removed from repos/org, CI, SaaS tools,
    VPN profiles, DNS/registrar, package registries
[ ] Server-side sessions killed                 (not just cookie deletion)
[ ] Device wiped/inspected on return            (cross-ref DFIR if anything odd)
Executed by: ________  date: ________  spot-checked by: ________
```

**B1. Write the playbook skeleton first (fixes R1).** Do not start with prose; start by copying this module's fill-in-ready blocks — intake form, SEV matrix, first-hour checklist, scenario grid, postmortem skeleton — into the wiki and populating brackets. A 60% playbook that exists beats a perfect one that doesn't. Version it; date it; link it from DETECT alert payloads.

**B2. Build the contact tree + OOB channel (R2).** Roster from current on-call tool config; add personal-contact column; create the out-of-band thread/bridge NOW while nothing is wrong; print it; put a copy in the password-manager emergency vault. Review calendar reminder: every 6 months.

**B3. Stand up break-glass (R3).**
1. Generate password-manager recovery kit; store offline split between two people; document re-entry steps.
2. Create escrowed cloud console credentials per provider account (dedicated break-glass user, excluded from SSO), sealed offline.
3. Verify local admin + Postgres break-glass accounts exist with documented rotation-on-use.
4. TEST all three paths this week — untested escrow is decoration.

**B4. Compile the notification-obligations inventory (R4).** Table with columns: obligation / trigger / deadline / owner / contact. Sources: counsel for applicable regulatory regimes (frame GDPR-72h-style clocks as "verify which jurisdictions apply to us"), sales/legal for customer contract clauses, insurer policy docs. Counsel reviews the finished table once; owners keep it current.

**B5. Close evidence-handling gaps (R5).** Work LOGMON findings to closure first (central shipping, retention ≥ detection lag); write the per-cloud snapshot runbook for each provider in use; designate evidence store location with access list; identify and train a second person who can image a host (bus factor).

**B6. File insurance/vendor contacts (R6).** Vault entries + playbook appendix row each: broker emergency line, insurer claims intake + approved-vendor requirement, cloud support severity paths with account IDs, Cloudflare plan's support channel, critical vendor contacts.

**B7. Prove restorability (R7).** If DR module shows no dated restore test: schedule one now for the most critical service; record date/duration/result in the DR verification log; confirm backup access works under break-glass identity, not just production credentials.

**B8. Stage tooling and wire severity paging (R8).** Verify `tools/run-all-sweeps.sh` runs clean on one representative host per class; fix or note failures. Adopt the SEV matrix into paging-tool severities. Refresh asset inventory (30-day rule) — derive from IaC where possible to make currency automatic.

Order matters: B1–B3 make response POSSIBLE, B4–B6 make it LAWFUL and funded, B7–B8 make it rehearsed. A team can only do so much at once — if forced to triage, B2/B3 (reachability) outrank everything else because every other phase depends on reaching people and systems.

## Verification & Validation

Readiness is verified the same way exploits are: by exercise, not inspection.

| Capability | Verification method | Pass criterion |
|---|---|---|
| Playbook findable (R1) | Ask on-call "show me the first-hour checklist" unprompted | Found < 2 min from memory of where it lives |
| Contact tree + OOB (R2) | Ring-the-real-phone drill: page on-call, they open OOB channel via documented path | Channel live < 10 min |
| Break-glass (R3) | Scheduled live test: escrowed console login performed, recovery-kit re-entry walked through | Both succeed; rotation-on-use executed after |
| Obligations table (R4) | Walkthrough: given scenario X, name trigger/deadline/owner without lookup aids failing | Each entry answerable |
| Evidence chain (R5) | Timed drill: alert → relevant logs located → copied off-host → hashed | Within TTD-relevant window; retention covers drill lookback |
| Backup proof (R7) | Restore test per DR module cadence | Dated success record within policy interval |
| Sweeps (R8) | `tools/run-all-sweeps.sh` on representative host | Completes; output archived; gaps ticketed |
| Full loop | Quarterly tabletop (Exploitation & Reproduction kit) + annual full-scale simulation including restore | Debrief action items created AND closed |

Validation rules:

1. **Every verification produces an artifact** (drill record, restore log, tabletop debrief). No artifact = not verified = PARTIAL in next audit.
2. **Rotate the human under test** — capability that only one employee demonstrates is single-point-of-failure, score PARTIAL regardless of outcome.
3. **Re-audit after incidents**: every real incident triggers a readiness re-run of this module — real incidents are the cheapest readiness data you will ever get.
4. Track readiness trend across quarters; regressions (tree stale, test overdue) reopen findings at their original severity.

## Severity Assessment

**This is an INCIDENT severity matrix, not vulnerability CVSS.** It answers "who gets woken and how fast do we move," assigned per the Phase-2 decision tree. Vulnerability findings from other modules keep their own scoring; this matrix governs live events only.

| SEV | Definition | Examples | Response | Comms |
|---|---|---|---|---|
| 1 | Confirmed/suspected compromise with data exposure, active attacker control, or customer impact | Data exfil suspected; auth bypass/RCE active in prod; attacker persistence found; production down security-related | Immediate page, all-hands roles filled <15 min, exec chain <15 min | Exec hourly; counsel engaged; R4 clocks reviewed |
| 2 | Compromise contained or limited blast radius, no confirmed data exposure yet | Single host compromised + isolated; credential leak, misuse unconfirmed; malicious deploys possible | Page on-call + lead same hour; containment within hours | Exec same-day summary |
| 3 | Weakness present with plausible path but no exploitation evidence | Vulnerable dependency unexploited; secrets committed, rotation complete, no abuse found; scanning/probing observed | Ticket + fix within sprint; monitor for escalation | Weekly review mention |
| 4 | Anomaly under investigation, likely benign | Unexplained log noise; single failed-auth burst from known scanner; false-positive-prone alert firing | Logged, monitored, auto-closes if quiet 14 days | None unless upgraded |

Assignment rules: first question of the decision tree wins; upgrade instantly on any trigger flip, downgrade only after two independent confirmations; when torn between two levels, take the higher — paging costs minutes, under-response costs the postmortem's entire timeline.

Readiness-audit findings themselves are NOT scored on this matrix — they use each finding's real-world enabler value: an ABSENT break-glass procedure during a live IdP outage converts directly into SEV1 delay, so grade Half-A gaps by what they would cost at 3 a.m., not by document presence.

## Common False Positives

Audit-time traps that make readiness LOOK present:

1. **Document exists ≠ capability.** A playbook last edited 18 months ago, never exercised, with departed employees in the tree, scores ABSENT-in-effect. Test: can the current on-call produce it and act on it?
2. **Backups exist ≠ restorable.** Restore scripts in repo without dated successful-run output is R7 failure. Only DR-module verification records count.
3. **Escrow exists ≠ usable escrow.** Recovery kit generated but never re-entry-tested; console creds sealed but MFA-bound to the same dead IdP. Untested = PARTIAL.
4. **On-call tool reachable ≠ comms plan.** The paging system shares fate with the IdP/Slack/email that may be the compromised asset. OOB channel must be independent.
5. **Severity debates during tabletops aren't process failures** — they're the exercise working. A team that assigns instantly but wrongly via unwritten rules is WORSE than one that debates against an explicit matrix.
6. **"We'd know because we watch the logs"** — LOGMON findings showing local-only, short-retention, or unread logs invalidate this claim. Cross-check before accepting.
7. **One incident handled well ≠ program.** A single heroic response by one engineer who has since left proves nothing about organizational capability; look for artifacts, rehearsal records, and bus factor ≥2.
8. **Tabletop success ≠ production readiness** — injects were finite and known to the facilitator. Weight debrief gaps over smooth execution.
9. **Rotation performed ≠ rotation complete.** Scenario checklists exist precisely because memory-based cascades miss dependent/shared credentials; verify against HSECRET/IAM inventories, not recollection.

## References

- NIST SP 800-61r2, *Computer Security Incident Handling Guide* — the Preparation/Detection/Containment/Eradication/Recovery/Lessons-Learned lifecycle this module follows: https://csrc.nist.gov/pubs/sp/800/61/r2/final
- NIST Cybersecurity Framework — Respond/Recover function mapping stated in frontmatter: https://www.nist.gov/cyberframework
- SANS *Incident Handler's Handbook* (SANS IR handbook) — phase checklists and handler discipline: https://www.sans.org/white-papers/incident-handlers-handbook/
- CISA #StopRansomware Guide / ransomware checklist — scenario-specific response checklist pattern (containment-before-recovery ordering): https://www.cisa.gov/stopransomware
- Sibling modules: TOK `skills/server/api-token-security/SKILL.md` (rotation runbook), SUPPLY `skills/code/supply-chain/SKILL.md` (dependency incidents), DR `skills/server/backup-dr/SKILL.md` (restore proof), LOGMON `skills/server/logging-monitoring/SKILL.md` (evidence sources), DETECT `skills/operations/blue-team-detection/SKILL.md` (alert-to-page wiring), DB `skills/server/db-server-hardening/SKILL.md` (Postgres logging), HSECRET `skills/server/host-secrets/SKILL.md` (rotation inventories), SECRETS `skills/code/secrets-data-exposure/SKILL.md` (leak hunting)
- Tooling: `tools/run-all-sweeps.sh`, `tools/sweeps/` — validation sweeps reused as triage collectors and recovery gates

