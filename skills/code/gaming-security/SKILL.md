---
name: aegis-gaming-security
description: Audit playbook module for video-game and multiplayer-service backends, hunting client-trust violations in simulation authority, movement and action validation, economy integrity, leaderboards, in-app purchases, anti-cheat telemetry, game-protocol sessions, cloud saves and LiveOps config, UGC sandboxing, and secrets shipped inside client binaries.
category_slug: GAME
cwe: [CWE-602, CWE-345, CWE-20]
owasp: A04:2021 – Insecure Design (primary) 
---

# Gaming / Multiplayer Service Security Checks

## Scope & Objectives

### Objective

Audit the server-side code of video games and multiplayer services for every place the CLIENT decides an outcome and the server accepts it (CWE-602). Produce file:line evidence, a static-first reproduction recipe, a severity weighted by economy scale, and a fix built on authoritative server recomputation, bounded validation, atomic ledger operations, receipt verification, and detection telemetry.

### In Scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Server-authority gaps | Damage/kill attribution computed by shooter client; currency counts posted by client; client-submitted match results persisted; cooldown state read from client UI | CWE-602 |
| Movement / action validation | Position packets applied without displacement bounds; no per-entity action rate caps; cooldowns and tick timing taken from client clocks | CWE-20 |
| Economy integrity | Trade double-spend races; mail/gift attachment duplication; auction bid/cancel races; shop grant before wallet debit; save rollback resurrecting spent currency; negative/overflow quantities | CWE-362-shaped flows (see LOGIC module); CWE-20 |
| Leaderboard / score | Final scores POSTed by clients; totals stored instead of derived from validated event streams; impossible values accepted | CWE-345 |
| In-app purchases | Client-side purchase callbacks granting goods; receipts validated on device or not at all; transaction-id replay; refunds never revoking grants | CWE-345 |
| Anti-cheat design (defensive) | No cheat-signal telemetry; full world state broadcast enabling ESP/wallhacks; honeypot absence | Design finding |
| Session / protocol | Unauthenticated UDP/game ports; missing sequence numbers or replay windows; unbounded message floods per connection | CWE-345 (flooding -> DOS module) |
| Save data / LiveOps | Cloud saves merged into authoritative state without schema/bounds gates; unsigned remote-config/economy tables applied live | CWE-20 |
| UGC / modding | Player scripts/maps executing with host privileges; missing resource quotas; moderation hooks absent | Design finding (injection -> INJECTION module) |
| Client-binary secrets | API keys, endpoint maps, tokens embedded in shipped desktop/mobile/console clients and patchers | CWE-345 (deep dive -> SECRETS module) |

### Out of Scope (cross-references)

- Generic race-condition theory, TOCTOU mechanics, idempotency patterns -> LOGIC module (`business-logic-races`). This module covers only game-specific shapes (trades, mail claims, auctions, crafting loops); reuse its fix vocabulary.
- Cheat-signal log schema, analytics pipeline, alert routing -> DETECT module.
- Packet/message flood volumetrics -> DOS module.
- Webview XSS inside game clients -> WEB module.
- Secret storage hygiene, scanning methodology -> SECRETS module; memory-disclosure techniques -> MEM module.
- Anti-cheat kernel drivers (EAC/BattlEye-style deployments): out of scope entirely — this module evaluates service design, not endpoint protection agents. Note their presence/absence factually, never as a compensating control for server-authority findings.

### Operating Assumptions

Read access to the repository; no running instance guaranteed. Static confirmation is sufficient evidence: a handler that persists a client-supplied outcome without recomputation IS the finding, whether or not dynamic testing is authorized. Dynamic procedures in this module are test vectors for systems you own or have written authorization to test.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **server authority**: the rule that only the server decides outcomes; client displays are suggestions
- **client prediction**: the game client guessing results locally for responsiveness; legitimate only if the server later corrects it
- **dupe (duplication glitch)**: racing claims so one grant of items or currency is created twice
- **receipt validation**: confirming an app-store purchase with the store, server-to-server, before granting goods
- **ESP/wallhack**: seeing hidden state because the server broadcast it — fixed by sending less, not by client tools
- **ledger**: append-only record of currency changes used instead of trusting client-posted counts
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

### One Rule: The Server Owns Truth

Every packet, HTTP body, socket message, protobuf field, cloud-save blob, and store webhook body arriving at the server is UNTRUSTED INPUT. Unity, Unreal, and Godot clients predict animation, movement, and hit feedback locally for responsiveness — that prediction lives entirely in attacker-controlled memory and is legitimate ONLY as a display hint. The finding exists the moment a handler lets that hint mutate authoritative state directly. Ask of every mutating endpoint: "If I replaced this client with 50 lines of raw sockets, would the operation still be legal?" If the answer depends on the client being honest, you have a CWE-602 finding.

### Trust-Boundary Map

| Game flow | Client-trust violation | Detection marker | Server-side fix |
|---|---|---|---|
| Combat resolution | Shooter client computes damage/kills and posts them | `applyDamage(req.body.damage)` reaching persistence | Server recomputes from weapon stats + buffs + validated hit event |
| Movement | Position/velocity packets applied verbatim | Displacement > v_max * dt accepted | Per-tick clamp + time-budgeted tolerance window |
| Inventory / currency | Client posts new counts (`coins`, `gems`) | Count fields bound straight from payload into UPDATE | Typed ledger operations; counts never client-writable |
| Match results | Final score/result submitted by client | Score persisted with no backing event stream | Derive score from server-recorded validated events |
| Abilities / cooldowns | Client UI state gates actions (`ui.canCast`) | Handler reads readiness flag from message | Server-side cooldown map keyed by entity + server clock |
| Trades / mail / auction | Offer consumed by two concurrent paths | await-chain between claim check and claim write | Single ACID transaction, row lock or CAS conditional write |
| Leaderboards | Posted totals land on boards | Totals endpoint accepting score from body | Aggregate from event stream; physics-max bounds; checkpoint consistency |
| Purchases | Grant fires on client-reported success | Grant code reachable without server-side receipt proof | Receipt validated against store API server-to-server; consumed-once ids |
| Cloud saves | Blob parsed and merged as-is | `state = JSON.parse(saveBlob)` then assign | Schema + bounds gate before merge; monotonic version check |
| LiveOps config | Unsigned remote config applied live | fetch-config -> apply with no signature/schema step | Signature verify + schema validate + staged rollout |
| UGC / mods | Player content executes beyond sandbox | eval/exec/loadstring over user strings; unrestricted imports | Capability-limited sandbox, CPU/memory/entity quotas |
| Netcode session | Gameplay served on unauthenticated ports | Socket accepts entities before any token check | Handshake auth token, sequence numbers, replay windows |
| State visibility | Server broadcasts all entities every tick | Full-world snapshots in protocol dumps | Interest management: send only what the recipient can perceive |

### Three Design Principles

1. Prediction is not authority. Client prediction plus SERVER reconciliation is correct netcode; blind acceptance is the vulnerability. Distinguish them by checking whether the server later corrects or validates predicted state.
2. Visibility filtering is the real anti-ESP fix. Wallhacks exist because the server sends hidden-state; prevention-on-client fails because clients are attacker-controlled eventually. Fix the send path, add detection telemetry as backstop.
3. Detection over prevention. You cannot stop a modified client from ASKING; you can make dishonest asks fail server-side and record structured signals when behavior is statistically impossible. Honeypots and outlier metrics convert an arms race into an audit trail.

## What To Check

**A. Server authority (run this sweep first — it finds the highest-severity issues).**

1. Enumerate every handler that mutates player-visible state (health, position, inventory, currency, score, cooldowns, match outcome). For each, answer: which fields come from the client, and does the server recompute the OUTCOME or merely record client-claimed VALUES? Persisting `body.damage` instead of computing `f(weapon, buffs, hit)` is a finding even if bounds-checked.
2. Check kill/assist attribution: does the shooter's client report the kill, or does the server observe hit events against its own health simulation? Client-computed damage totals feeding server health pools are Critical in competitive modes.
3. Check ability gating: search for readiness flags read from messages (`canCast`, `cooldownReady`, `abilityReady`) used as authorization. Cooldown timers must live on the server keyed by entity id and server clock.
4. Check match lifecycle: can one participant end the match, submit the result, or set the winning score? Results must derive from server-side win conditions.
5. Build the trust-boundary table for THIS codebase (fill the Mental Model template with real endpoints/files) and keep it as audit evidence.

**B. Movement and action validation.**

6. Find every position-updating path (HTTP move endpoints AND socket/UDP movement messages). Verify each applies a per-tick displacement bound: `distance(newPos, lastServerPos) <= v_max * dt * tolerance`, where dt comes from the SERVER clock.
7. Check teleport/waypoint handlers for plausibility gates (line-of-sight, range, ability ownership) and confirm server-initiated relocations (respawn, match start) are whitelisted from those gates rather than disabling the gate globally.
8. Verify per-entity action-rate caps exist beyond HTTP rate limiting: actions-per-second per character id (swing, cast, fire, craft, open), enforced before effect application, not just request throttling.
9. Verify tick-time authority: order-of-operations uses server timestamps; client timestamps are accepted only inside a bounded reorder buffer (e.g., ±150 ms); sequence numbers are monotonic; stale/duplicate sequence ids rejected.

**C. Economy integrity.**

10. For trade offer/accept flows: can an item be offered in a trade while simultaneously consumed by sale/craft/equip? Look for check-then-write gaps around escrow/lock steps.
11. Mail/gift/claim flows: is "claimed" set via a single conditional write (`UPDATE ... SET claimed = true WHERE id = ? AND claimed = false RETURNING attachments`) or a read-then-write pair a parallel request can interleave?
12. Auction house: bid placement and cancel/refund paths — do they lock the auction row (`FOR UPDATE`), or can cancel payout race a concurrent winning bid?
13. Crafting/refund loops: recompute refund math in integer minor units; look for rounding that makes output value exceed inputs across repeated cycles.
14. Shop purchase ordering: grant-then-debit (crash between = free item) vs debit-then-grant without compensation (crash = paid, no item) vs single transaction (correct).
15. Save rollback: can a client upload an old save blob to resurrect spent currency? Server must track monotonic profile version/clock and reject regressions outside support-flagged paths.
16. Currency-type confusion: premium vs earned wallets swapped anywhere (shop debit, transfer credit)? All mutations should flow through typed debit/credit functions taking wallet type explicitly.
17. Quantity sanity: reject negative, zero-with-side-effects, and overflow quantities (> max stack/int32) at the DTO layer for EVERY economy endpoint.
18. Transfer-to-self fee loops: cancel/refund handlers touching the same rows as transfer — verify escrow restore is atomic with cancellation and fees are never refunded on paths that also completed the transfer.

**D. Leaderboards and scores.**

19. Locate leaderboard write paths. Any POST of a final total from the client is a finding. Correct shape: server accumulates validated in-match events and derives the final.
20. Check bounds: score-per-event caps compared against physics-max achievable rates (kills/sec * points/kill * match duration). Values above physics-max are auto-rejected AND logged as cheat signals.
21. Check checkpoint consistency: claimed final progress (wave 40) requires stored prerequisite events (waves 1–39) for that session id.
22. Season reset: snapshot-and-clear must be atomic and idempotent per season_id; partial resets enable double-counting rewards across seasons.

**E. In-app purchases and stores.**

23. Trace the grant path: goods must be granted ONLY after the server verifies the receipt/purchase token against Apple App Store Server API or Google Play Developer API verification endpoints (server-to-server). Client callback alone granting anything = Critical.
24. Replay protection: a consumed-once table keyed by transaction id / purchase token (unique constraint), checked-and-consumed inside the same transaction as the grant.
25. Refund handling: voided/refunded/revoked webhooks (Apple App Store Server notifications, Google Play Developer Notifications) must revoke or flag granted goods; missing handler = finding.
26. Grant idempotency: webhook retries must be no-ops (idempotency key = transaction id); pending purchase states handled, not just completed ones.

**F. Anti-cheat defensive design.**

27. Confirm structured cheat-signal events exist (kind, actor, metric, cap, tick, match id) written when validations fail, suitable for DETECT-module pipelines. Absence of telemetry is itself a Low finding.
28. Honeypot values present? Hidden item ids/stats that no legitimate flow can produce or read; any appearance in payloads is manipulation evidence. Verify honeypots never leak through normal read APIs.
29. Interest management: does the server send full world state to every client, or filter by visibility/relevance? Over-sending is the root cause of ESP/wallhack classes — report as High in competitive titles.
30. Report + review pipeline fields exist on player reports (reporter, target, match, reason, replay pointer).

**G. Session and protocol.**

31. Game sockets/UDP ports require the same authentication as HTTP: token at handshake, identity bound to connection, per-message authorization. A gameplay-serving port reachable pre-auth is a Critical finding.
32. Message sequence numbers with replay windows; duplicate/stale packets dropped.
33. Per-connection message-rate caps distinct from IP rate limiting (see DOS module for volumetric sizing).

**H. Save data and LiveOps config.**

34. Cloud-save load path validates schema + field bounds BEFORE merging into authoritative state; save editors are user-facing tools, so treat saves like untrusted uploads.
35. Remote-config/LiveOps payloads (feature flags, economy tuning tables) signature-verified and schema-validated before applying; staged rollout with kill switch documented.

**I. UGC and modding boundaries.**

36. Player-created content execution (maps/scripts/mods): enumerate capabilities exposed to sandboxed content; flag network access, filesystem access, unrestricted FFI/native calls; verify CPU/memory/entity quotas; sandbox escape potential equals RCE-by-design — report Critical.
37. Moderation hooks: shared UGC passes through review/takedown states before broad visibility.
38. Webview-based UI surfaces loading remote/player HTML: hand to WEB module for XSS review.

**J. Client-binary secrets.**

39. Sweep shipped-client source/config trees (including patchers/launchers, mobile wrappers, console build configs) for embedded API keys, shared secrets, internal endpoint maps. Treat ALL client-embedded secrets as public; flag any server authz decision relying on their secrecy. Deep methodology -> SECRETS module.

## Where To Look

### Directory and file heuristics

- Handlers/routes: `server/`, `services/`, `api/`, `rpc/`, `handlers/`, `controllers/`, `gateway/`, `netcode/`, `matchmaker/`, anything registering socket message types (`on("move"`, `MsgType::`, proto `service` blocks).
- Economy: files named `wallet|currency|inventory|shop|trade|auction|mail|gift|craft|loot|reward`; SQL migrations creating those tables (read them for unique constraints — their absence IS evidence).
- Purchases: `iap|store|purchase|receipt|billing|subscription` routes plus webhook receivers (`apple|google|play|webhook`).
- Scores: `leaderboard|score|season|rank|match_result`.
- Saves/LiveOps: `save|snapshot|cloud_sync|remote_config|feature_flag|liveops|tuning`.
- UGC: `ugc|mods|custom_map|script_runtime|sandbox|plugin_host`.
- Protocol definitions: `.proto`, FlatBuffers/MessagePack schemas, `packets/` enums — these enumerate every client-writable field faster than reading handlers.

### Ripgrep sweeps

Run from repo root; default rust-regex engine (no lookarounds/backrefs). `-C 10` gives useful context. Patterns are copy-paste ready:

```bash
# A. Client-supplied outcomes flowing toward persistence
rg -in '\b(damage|heal|score|gold|coins?|gems?|xp|reward|final_?score)\b[^;\n]{0,80}\.(set|update|add|push|insert|save)\(' .
rg -in '(const|let|var)\s*\{[^}]*(damage|position|velocity|coins|gold|quantity|score)[^}]*\}\s*=\s*(req\.body|payload|msg|event\.data)' .

# B. Direct assignment smell (near-certain CWE-602)
rg -in '\.(health|hp|balance|wallet|score|position)\s*=\s*(req|body|payload|msg|data)\.' server/

# C. Movement acceptors and client-trusted cooldowns
rg -in '(move_to|teleport|waypoint|pos_update|set_position|on_move)\b' server/
rg -in '(can_cast|cooldown_ready|ability_ready|is_ready)[^;\n]{0,40}(===?|if\b)' server/

# D. Economy write shapes
rg -in 'UPDATE\s+wallets?|balance\s*=\s*balance|\$inc.*(balance|coins)' .          # then inspect ±30 lines for tx wrapping
rg -in '(claimed|redeemed|consumed)\s*=\s*(true|1|TRUE)' .                          # verify conditional-write form
rg -ni 'transaction_id' -g '*.sql' | rg -iv 'unique|primary|consumed'               # missing consumed-once constraint

# E. Purchases: validate->grant ordering and refund coverage
rg -in '(receipt|purchase_token|transaction_id|signed_payload|order_id)' server/
rg -in '(refund|void(ed)?|revoke[ds]?|did_renew)' server/                           # diff grant sites vs revoke sites

# F. Saves / LiveOps / UGC / protocol
rg -in '(load_save|cloud.?save|deserialize|from_dict|merge_state)' server/
rg -in '(remote_?config|feature_?flag|liveops|tuning_table)' .                      # check signature/schema step exists
rg -in '\b(eval|exec|compile|loadstring|importlib)\s*\([^;]*' server/ugc/ mods/
rg -in '(SOCK_DGRAM|socket\.bind|UdpSocket::bind)' server/ gateway/

# G. Secrets shipped in client trees (desktop/mobile/console/patcher)
rg -in '(api[_-]?key|client[_-]?secret|bearer|sk_live|AKIA[0-9A-Z]{16})' client/ apps/mobile/ patcher/ launcher/ 2>/dev/null
```

Interpretation notes:

- Category B hits are Confirmed-by-default findings unless a recompute call sits between intake and persistence.
- Category D wallet hits require manual ±30-line inspection: an `await` between balance read and balance write is the race shape.
- Every UDP bind hit must be answered by "what authenticates the first packet?" — if nothing does, log it as Critical.

Also read: schema/migration files for `UNIQUE` constraints on `transaction_id`, mail ids, trade escrow rows; CI/test fixtures replaying cheat payloads (their absence supports the Verification section later).

## Patterns & Signatures

Each pattern below is a vulnerable shape to recognize on sight. Fixed counterparts live in Remediation.

### Combat: client-computed damage

```typescript
// VULNERABLE — shooter's number becomes truth; bounds checks do not fix authorship
app.post("/match/:id/hit", async (req, res) => {
  const { targetId, damage, killed } = req.body;        // all three attacker-chosen
  await db.players.update(targetId, { hp: { decrement: damage } });
  if (killed) await awardKill(req.playerId, targetId);   // attribution from client
  res.sendStatus(200);
});
```

Signature: handler parameter named like an outcome (`damage`, `killed`, `headshot: true`) with no server-side formula call (`computeDamage`, `resolveHit`, weapon/buff lookups) before the write.

### Movement: position accepted verbatim

```rust
// VULNERABLE — no displacement bound, no clock authority
async fn on_move(state: &GameState, conn: &Conn, msg: MoveMsg) {
    let player = state.player(conn.entity);
    state.set_position(player.id, msg.x, msg.y, msg.z);   // msg is attacker bytes
}
```

Signature: `set_position`/`translate` called directly from message context; absence of any `max_displacement`, `v_max * dt`, or distance comparison in the same function.

### Cooldowns: UI state as authorization

```python
# VULNERABLE — client says the ability is ready
def cast_ability(msg):
    if not msg.get("ability_ready"):
        return reject("cooldown")
    apply_ability(msg["caster"], msg["ability"])          # server timer never consulted
```

### Economy: grant-then-debit shop purchase

```typescript
// VULNERABLE — crash or exception between the two awaits mints items
await inventory.add(playerId, itemId, qty);   // granted
await wallet.debit(playerId, price);          // may never run
```

### Purchases: client callback as proof

```typescript
// VULNERABLE — trusting the device's "I paid" message
app.post("/store/grant", (req, res) => {
  const { sku, orderId } = req.body;
  grant(req.user.id, sku);                    // no store-API verification anywhere
});
```

Signature: grant code path reachable without any call into Apple App Store Server API / Google Play Developer API verification logic; no `consumed_transactions` table in migrations.

### Saves: blob merged into authoritative state

```python
# VULNERABLE — save editors are user-facing tools; this is remote state injection
def load_cloud_save(user, blob):
    state = json.loads(blob)
    user.profile.update(state)                # arbitrary fields, arbitrary values
```

### Telemetry signatures worth grepping FOR (absence = finding)

```json
{"evt": "cheat_signal", "kind": "speed|damage|teleport|econ_velocity", "actor": "acct:123",
 "metric": 42.0, "cap": 0.45, "tick": 88123, "match": "m_9", "session": "s_77"}
```

If no code path emits anything shaped like this when validations fail, detection telemetry is absent (Low finding that amplifies everything else).

## Taint Tracing Guidance

**Sources (treat every one as attacker-controlled):**

- HTTP bodies hitting gameplay endpoints; WebSocket message frames; raw UDP datagram payloads (bypass every framework validator — locate them at the bind site, not the router).
- Protobuf/FlatBuffer fields by field name, since schemas are public contracts.
- Cloud-save blobs at load time; remote-config/LiveOps payloads at apply time.
- Store webhook bodies — untrusted until the signature/verification step succeeds; trace whether that step precedes parsing-and-granting or is missing.
- Values read back from caches holding client-written data (stale trust).

**Sinks (state mutations that matter):**

- Any ORM write/UPDATE touching `players`, `wallets`, `inventory`, `leaderboard`, `match_results` rows.
- Grant functions (`grantItem`, `awardCurrency`, `unlockSkin`), mail attachment insertion.
- UGC script loaders and config appliers (execution sinks).

**Procedure:**

1. Pick a sink; walk backwards to its handler entry. Identify each field read from the source.
2. Between intake and sink, classify every intermediate statement: RECOMPUTE (derives value from server state — good), BOUNDS-CHECK (limits a client value — necessary, never sufficient for outcomes), or PASSTHROUGH (finding).
3. For movement sinks specifically, reconstruct the math: does any line compute `distance(newPos, lastServerPos)` against a bound derived from SERVER time?
4. For economy sinks, draw the operation ordering diagram (read/check/write per row). Two writes to different rows separated by an `await` or network call inside no transaction = race shape -> LOGIC module for the generic fix vocabulary.
5. For receipt flows, verify order: parse -> verify-with-store-API -> consume-id-in-same-tx-as-grant -> grant. Any other order is exploitable; missing consume table means replayable.
6. Record file:line for each verdict. Static confirmation standard: passthrough found = Confirmed; recompute found = Clean; bounds-only on outcome fields = Confirmed (bounds limit magnitude, not authorship).

Static-only confirmation is fully sufficient for reporting. The dynamic procedures that follow exist for authorized environments.

## Exploitation & Reproduction

Run dynamic tests ONLY against systems you own or are contractually authorized to test. Every procedure below uses test accounts in your own environment; these are defense-verification vectors, not offensive tooling.

### Payload cheat-sheet

| Flow | Forged body | Expected on VULNERABLE server | Expected on FIXED server |
|---|---|---|---|
| Damage | `{"targetId":"p2","damage":99999,"killed":true}` | One-shot kill credited | 400/ignored; damage derived server-side |
| Score | `{"matchId":"m1","score":999999999}` | Board updated instantly | 4xx or clamped to physics-max |
| Currency | `{"coins":1000000}` posted to profile update | Balance mints | Field rejected (not writable) |
| Negative trade qty | `{"give":[],"receive":[{"item":"gem","qty":-5}]}` | Sender gains 5 gems via sign flip | 422 validation |
| Overflow qty | `{"qty":2147483647}` on stackable item | Integer overflow / infinite stack | Bound check rejects |
| Mail dupe | two identical `POST /mail/{id}/claim` in parallel | Two attachments granted | Second gets 409 / no-op via CAS |
| Receipt replay | same purchase webhook body sent twice | Double grant | First grants, second no-op |
| Old save upload | earlier `save_v3.json` blob after spending currency in v9 | Spent currency resurrected | Version regression rejected |
| Wallet swap | shop buy passing premium item priced against earned wallet | Wrong wallet debited/undebited | Typed debit enforces wallet kind |

Movement-impossibility math (use the game's real constants from config):

```text
tick_rate = 20 Hz            -> dt = 0.05 s
v_max     = 6  m/s (walk), 9 m/s (sprint)
d_max per tick = v_max * dt  -> 0.30 m walk, 0.45 m sprint
observed  = 42.0 m in one tick  => 93x sprint cap  => impossible
tolerance window W = 1 s, lag factor k = 1.5
budget(W) = v_max * W * k    -> 13.5 m per sliding second — bursts inside this are legit
```

### Procedure A — Forge a stat update (server-authority proof)

Requires: two accounts you control, one private match, an HTTP proxy on your own client.

1. Join both accounts to your match. Observe baseline HP of account B (e.g., 100).
2. Capture the stat/hit message your own client emits when attacking (proxy the WebSocket frame or HTTPS body).
3. Replay it with `damage` set to `99999` and `killed: true`, from account A's session.
4. Observable (vulnerable): B's HP drops to 0 or negative in one hit; kill feed credits A; subsequent DB read (`SELECT hp FROM players WHERE id='B'`) shows the injected value persisted.
5. Observable (fixed): 4xx response or silent ignore; HP unchanged; a `cheat_signal` event with `kind=damage` appears in logs.

### Procedure B — Movement impossibility

1. From your test session, emit one movement message teleporting the entity 42 m from its last server-known position (math above).
2. Observable (vulnerable): position accepted; world state shows displacement far beyond `v_max * dt`; no log entry.
3. Observable (fixed): rejection or clamp-to-budget; `cheat_signal kind=speed` emitted; repeated attempts escalate per policy but a single burst within tolerance does NOT punish (see Verification negatives).

### Procedure C — Concurrent mail/gift claim (dupe)

1. Send yourself one mail with a valuable attachment. Note balance before.
2. Fire two identical claims simultaneously:

```bash
curl -X POST https://your-game.example/api/mail/mail_123/claim \
     -H "Authorization: Bearer $TOKEN" & \
curl -X POST https://your-game.example/api/mail/mail_123/claim \
     -H "Authorization: Bearer $TOKEN" & wait
```

3. Observable (vulnerable): both return 200; attachment granted twice; balance incremented twice.
4. Observable (fixed): exactly one grant; loser returns 409/no-op; single row shows `claimed=true`.

### Procedure D — Leaderboard forgery

1. With a valid session and NO completed match events, post the result endpoint directly: `curl -X POST .../api/match/m1/result -H auth -d '{"score":999999999}'`.
2. Observable (vulnerable): leaderboard top entry now yours; no backing event stream exists.
3. Observable (fixed): 403/409 ("no such match session" / "result not derivable"); attempt logged as cheat signal.

### Procedure E — Purchase webhook replay

1. Complete one real sandbox purchase; capture your store's webhook to your server (or synthesize one if signatures are verified — then replay is impossible without the key, which IS the check).
2. Re-send the identical webhook body twice.
3. Observable (vulnerable if unsigned OR unverified): double grant of currency.
4. Observable (fixed): signature failure rejected pre-parse (if signature verification present); verified duplicate consumed-once → first grants, second returns idempotent success WITHOUT granting again.

### Static-only confirmation

When dynamic testing is not authorized: trace handler → persistence without recomputation (Procedure A step 4's code-level equivalent) and mark Confirmed. Procedures C/E confirmed statically by showing read-then-write pairs without transactions/CAS and grant paths lacking consumed-once constraints.

## Remediation

### Authoritative combat recompute

```typescript
// FIXED — outcome computed from server state; client supplies only intent + aim evidence
app.post("/match/:id/hit", requireMatchSession, async (req, res) => {
  const { targetId, weaponId, hitPoint } = req.body;
  const shooter = await session.player(req.user.id);
  const target  = await session.entity(targetId);
  if (!shooter.canSee(target, hitPoint))          return res.status(409).json({err:"invalid_hit"});
  if (!shooter.weaponReady(weaponId))             return res.status(409).json({err:"cooldown"});
  const dmg = computeDamage(shooter.loadout(weaponId), target.resistances(), dist(shooter, target));
  await session.applyDamage(target.id, dmg);      // health pool lives server-side only
});
```

### Movement clamp (Rust, server tick)

```rust
// FIXED — server clock authority + per-tick displacement bound with lag budget
const MAX_SPEED: f32 = 9.0;   // m/s, highest legit locomotion incl. sprint
const TOL: f32 = 1.5;         // lag tolerance multiplier
fn accept_move(p: &mut Player, want: Vec3, now: Instant) -> Result<Vec3, MoveErr> {
    let dt = (now - p.last_tick).as_secs_f32().min(1.0);       // server clock, capped window
    let budget = MAX_SPEED * dt * TOL + p.move_credit.min(MAX_SPEED); // banked slack absorbs spikes
    let d = (want - p.pos).length();
    if d > budget {
        signals::emit(CheatSignal::new("speed", p.id, d, budget));
        let dir = (want - p.pos).normalize();
        p.pos += dir * budget;                                  // clamp, don't rubber-band hard
        Ok(p.pos)
    } else {
        p.move_credit = (budget - d).min(MAX_SPEED);            // carry unused budget forward
        p.pos = want; p.last_tick = now; Ok(p.pos)
    }
}
```

Tuning honesty: over-aggressive bounds punish laggy legitimate players (rubber-banding complaints, unfair deaths). Derive `MAX_SPEED` per gamemode including vehicles/abilities; measure legit p99 displacement and set caps above it; use credit/budget accumulation rather than instant kicks; never gate SERVER-initiated relocations (respawn, match start) through player-move validation.

### Server-side cooldowns

```typescript
// FIXED — timers keyed by entity on the server clock
if (!cooldowns.ready(casterId, abilityId, serverNow())) return reject("cooldown");
cooldowns.start(casterId, abilityId, serverNow() + ABILITIES[abilityId].duration_ms);
applyAbility(casterId, abilityId);
```

### Atomic economy operations

Single-statement conditional debit (works under any concurrency):

```sql
-- FIXED — atomic check+debit; zero rows returned means insufficient funds
UPDATE wallets SET balance = balance - $1
 WHERE user_id = $2 AND wallet_type = $3 AND balance >= $1
RETURNING balance;
```

Application layer wraps ALL multi-row economy moves (debit + credit + escrow flag + mail insert) in ONE transaction; never interleave `await`s between balance read and write. Trade cancel restores escrowed items in the same transaction as cancellation; fees are non-refundable once transfer commits. Claim-style one-shot flags become CAS writes:

```sql
UPDATE mails SET claimed = TRUE WHERE id = $1 AND claimed = FALSE RETURNING attachments;
```

Generic race theory, lock ordering, and idempotency-key patterns: LOGIC module (`business-logic-races`) — apply its vocabulary here; this module adds only the game-specific flows above.

### Scores from validated event streams

Server records every scoring event during play; final score = aggregate over the session's event stream, bounded by physics-max (`max_events_per_sec * points_per_event * duration`), gated by checkpoint consistency (claimed wave N requires stored events for waves < N). Client-submitted totals are rejected at the schema layer (field not accepted). Season reset runs snapshot+clear atomically, idempotent per season_id.

### Receipt-validation middleware skeleton (Node)

```javascript
// FIXED — verify server-to-server, consume-once, grant idempotently, revoke on refund
async function purchaseWebhook(req, res) {
  if (!verifyStoreSignature(req)) return res.status(401).end();      // platform JWS/signature first
  const txn = await apple.verifyTransaction(req.body.signedPayload)  // Apple App Store Server API
              .catch(() => google.verifyPurchase(req.body));          // Google Play Developer API
  if (!txn.ok) return res.status(400).json({err:"unverified"});
  if (txn.state === "refunded") return revokeGrant(txn.originalId);   // refund path revokes goods
  const granted = await db.tx(async t => {
    const ins = await t.oneOrNone(
      `INSERT INTO consumed_transactions(txn_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING txn_id`,
      [txn.id]);                       // unique constraint = replay protection, same tx as grant
    if (!ins) return false;            // replayed webhook: idempotent no-op, still 200
    await grantGoods(t, txn.userId, txn.sku);
    return true;
  });
  res.status(200).json({granted});     // always 200 on dupes so the store stops retrying
}
```

Python services mirror the shape: parse → platform-API verify → `INSERT ... ON CONFLICT DO NOTHING` → grant, all inside one transaction. Pending purchase states must be recorded and reconciled, not ignored. Never trust client-side store callbacks alone for any grant decision.

### Visibility filtering (anti-ESP architecture)

Replace full-world snapshots with interest management: per tick, compute each connection's relevant set (spatial range + line-of-sight/occlusion + team rules) and serialize ONLY those entities. Fog-of-war games send fog-masked tiles; hidden players are simply absent from the payload, so a wallhack reads nothing. Budget note: filtering costs CPU — cache visibility sets, update at reduced cadence for static geometry. This is the root-cause fix for ESP/wallhack classes; client hardening cannot substitute because clients are attacker-controlled eventually.

### Save-validation gate

```python
# FIXED — cloud saves are untrusted input; validate schema+bounds before merge
SAVE_SCHEMA = Schema({
    "version": And(int, lambda v: v >= SAVE_VERSION_MIN),
    "pos": {"x": Range(-WORLD_W, WORLD_W), "y": Range(-WORLD_H, WORLD_H)},
    "inventory": [And({"item": valid_item_id, "qty": Range(1, MAX_STACK)})],
    Optional("quests"): {"completed": [valid_quest_id]},
}, extra=SchemaForbidden)                     # unknown fields rejected, not merged

def load_cloud_save(user, blob):
    state = SAVE_SCHEMA.validate(json.loads(blob))
    if state["version"] < user.profile.save_version:
        raise SaveRegression(user)            # rollback injection blocked; support-flagged override only
    merge_validated(user.profile, state)
```

Remote-config/LiveOps payloads get the same treatment plus a signature check against your signing key before apply, staged rollout (canary percentage), and a kill switch.

### UGC sandbox capabilities and client-secret hygiene

Player content runs capability-starved: no network, no filesystem, no native FFI; interpreter/WASM isolation in a separate process; quotas on CPU ms, memory, entity count, script size; moderation review states before broad visibility; takedown hooks. Any path where user content reaches host privileges (escaping the sandbox) is RCE-by-design — Critical.

For shipped clients: remove embedded API keys/secrets/internal endpoint maps; rotate anything already shipped; every authorization decision must rest on per-user server-side tokens, never on possession of a binary constant. Obfuscation buys time only — treat all client-embedded secrets as public from launch day. Methodology -> SECRETS module; memory-disclosure realities -> MEM module.

## Verification & Validation

### GIVEN/WHEN/THEN

1. GIVEN a handler accepting damage WHEN a forged `{"damage":99999}` arrives from a valid session THEN the request is rejected or recomputed, target HP changes by at most the formula's legal maximum, and a `cheat_signal` event is written.
2. GIVEN a legit player attacking normally WHEN normal hit messages flow THEN outcomes are identical to pre-fix behavior (no false rejections across 100 recorded legit traces).
3. GIVEN a movement message displacing 42 m in one tick WHEN submitted THEN rejected/clamped with signal; GIVEN the same player bursting within budget (13.5 m sliding second) after a 200 ms lag spike WHEN caught-up packets arrive THEN accepted — laggy-but-legit players are NOT punished.
4. GIVEN two parallel mail claims WHEN both land THEN exactly one grant; loser receives 409/no-op; attachment row shows single consumption.
5. GIVEN a shop purchase WHEN the process crashes between debit and grant (kill -9 in staging) THEN no item without payment AND no payment without item (transaction rollback proven by fault injection).
6. GIVEN a leaderboard post of 999999999 with no backing events WHEN submitted THEN rejected as non-derivable; GIVEN a real match's server-recorded events THEN final score equals event-stream aggregate.
7. GIVEN the same purchase webhook delivered twice THEN goods granted once; store receives 200 both times (retries stop).
8. GIVEN an old save blob uploaded WHEN version < stored version THEN regression rejected; GIVEN current-version legit save THEN loads and merges cleanly.
9. GIVEN hidden-state entity behind a wall WHEN client captures its own traffic stream THEN entity data absent from payload (ESP fix verified at protocol level).

### Regression fixture (CI pseudocode)

```javascript
// fixtures/cheat_regressions.test.js — replay known-bad payloads, expect rejection
const cases = [
  {name:"god_damage",   ep:"/match/m/hit",    body:{targetId:"p2",damage:99999,killed:true}, want:[400,409,422]},
  {name:"score_forge",  ep:"/match/m/result", body:{score:999999999},                        want:[400,403,409,422]},
  {name:"neg_qty",      ep:"/trade",          body:{receive:[{item:"gem",qty:-5}]},          want:[400,422]},
  {name:"overflow_qty", ep:"/shop/buy",       body:{itemId:"arrow",qty:2147483647},          want:[400,422]},
  {name:"teleport",     ep:"ws:move",         body:{x:42000,y:0,z:0},                        want:["reject","clamp"]},
];
for (const c of cases) {
  const r = await send(c.ep, c.body, testToken);
  assert.ok(c.want.includes(r.status), `${c.name} accepted with ${r.status}`);
}
assert.equal(await grantsOf(testUser), baselineGrants, "economy untouched");
```

### Manual checklist

- [ ] Trust-boundary table completed for this codebase with endpoint-level entries
- [ ] Every outcome field traced: RECOMPUTE / BOUNDS / PASSTHROUGH verdicts recorded
- [ ] All UDP/game-port binds answered with "what authenticates packet one?"
- [ ] Consumed-once constraints exist for every grant id
- [ ] Refund/void handlers exist and revoke for every grant path
- [ ] Save-load gate rejects unknown fields and version regressions
- [ ] LiveOps apply requires signature + schema validation
- [ ] UGC runtime capability list reviewed; quotas enforced
- [ ] Client trees scanned; zero embedded secrets or all flagged for rotation

### Post-fix greps

```bash
rg -in '\.(health|hp|balance|score|position)\s*=\s*(req|body|payload|msg|data)\.' server/   # expect: no hits
rg -n 'computeDamage|resolveHit' server/services/combat/                                    # expect: formula call per hit path
rg -ni 'transaction_id' -g '*.sql' | rg -i 'unique'                                         # expect: constraint present
rg -c 'cheat_signal' server/                                                                # expect: >0 emit sites per validator
```

## Severity Assessment

Weight by ECONOMY SCALE first: circulation size, premium-currency convertibility to real money, resale/RMT market presence. A numerically "High" dupe escalates to Critical when the currency is premium-convertible at scale; document escalation rationale in the report rather than letting CVSS arithmetic understate game-business impact.

| Anchor | Example vector (CVSS v3.1) | Band |
|---|---|---|
| Free currency/items mintable at scale (client-posted counts, unsigned webhook grants); account-wide stat injection usable in competitive play | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` = 9.1 when unauthenticated; authenticated variants score 8.1 but escalate to Critical under economy weighting | Critical |
| Dupes limited-per-exploit-instance; unauthenticated gameplay port serving state mutation; leaderboard top-100 forgeable; ESP enabled by full-world broadcast in competitive titles | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` = 7.6 | High |
| Cosmetic-only client-trust gaps (skin color, non-ranked stat display); telemetry absence; missing cheat-signal structure | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3 | Medium |
| Detection-telemetry gaps alone (no outlier logging, no honeypots) | No vector — process/design finding; report Low with remediation plan | Low |

Modifiers: competitive/PvP context raises any integrity finding one band over the same flaw in private PvE; monetized economies (gacha, marketplace cut) raise dupes one band; single-player or friends-only scope can lower cosmetic findings to Informational with product-team sign-off.

## Common False Positives

- Intentionally client-authoritative CO-OP/PvE designs: some co-op games deliberately simulate on the host client for cost reasons. This is a documented PRODUCT DECISION, not automatically a vulnerability — still list it, severity driven purely by business impact (private friends-only PvE: Low; public PvE feeding shared leaderboards or economy: High). Evidence = design doc or code comment declaring the decision; absence of documentation is itself part of the finding.
- Client prediction with server reconciliation is CORRECT netcode, not CWE-602. Distinguish: prediction + authoritative correction/validation later = clean; prediction values written straight through with no reconciliation = finding. Check for the corrective path before flagging movement code that "accepts" client positions.
- Lag spikes produce displacement bursts exceeding naive per-tick caps. Verify against the tolerance/budget mechanism (sliding window, credit banking) before calling legit-player behavior a bypass — and conversely, do not accept "our cap is strict" as fixed if it punishes p99 latency players (that is a correctness bug in the fix).
- Physics extrapolation jitter, mount/vehicle speeds, and ability-granted bursts legitimately exceed walk-speed constants; confirm the constant table covers all locomotion modes before reporting speed findings.
- Anti-cheat kernel drivers (EAC/BattlEye-class) are OUT OF SCOPE for this module: note their presence factually, never credit them as mitigation for server-authority flaws — they protect the client process, not your trust boundary.
- Dev/test-only endpoints (local bind, feature-flagged off, non-prod builds): confirm production exposure via config/deploy evidence before reporting; static reachability alone overstates them.
- Honeypot items appearing in internal tooling or admin seeds: honeypot hits count only where a player-reachable write path touches them; verify the read-API never exposes them either, else the trap is inert.

## References

- CWE-602: Client-Side Enforcement of Server-Side Security — https://cwe.mitre.org/data/definitions/602.html
- CWE-345: Insufficient Verification of Data Authenticity — https://cwe.mitre.org/data/definitions/345.html
- CWE-20: Improper Input Validation — https://cwe.mitre.org/data/definitions/20.html
- CWE-841: Improper Enforcement of Behavioral Workflow — https://cwe.mitre.org/data/definitions/841.html
- OWASP Top 10 2021 — A04:2021 Insecure Design — https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP Cheat Sheet Series — Input Validation Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- OWASP Cheat Sheet Series — Transaction Authorization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html
- Apple App Store Server API (transaction verification root documentation) — https://developer.apple.com/documentation/appstoreserverapi
- Google Play Developer API (purchase verification root documentation) — https://developers.google.com/android-publisher

Internal cross-references: LOGIC (`business-logic-races`) for race/idempotency fundamentals; DETECT (`blue-team-detection`) for cheat-signal pipelines; DOS (`denial-of-service`) for flood sizing; WEB (`web-client`) for webview XSS; SECRETS (`secrets-data-exposure`) and MEM (`memory-safety`) for client-secret and memory-disclosure deep dives.
