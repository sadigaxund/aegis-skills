# Gaming & Multiplayer Service Security — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, regexes, payload tables, and fix shapes.

## How this class emerged

Multiplayer games faced the client-trust problem before web applications
formalized it. Arcade and early-1990s networked titles ran simulation logic on
every participant's machine; whoever edited their copy won. The industry's
answer — the authoritative server — became doctrine as persistent online worlds
grew through the late 1990s and 2000s: clients send *inputs*, the server runs
the simulation, clients render whatever the server reports. Client-side
prediction was later layered on to hide latency, with the crucial caveat that
prediction is a display hint the server must later reconcile.

The bug class persisted anyway, because authority is expensive:

- **Latency pressure.** Recomputing every outcome server-side costs round trips.
  Teams leak authority to the client one field at a time ("the shooter knows if
  it hit") until the server is a persistence layer for client fiction.
- **Economic gravity.** Virtual currencies, gacha, and player-to-player trading
  created real-money economies inside games. Every duplication glitch became an
  arbitrage engine; races in trade/claim/auction flows turned concurrency bugs
  into money printing.
- **Mobile distribution.** App stores introduced purchase receipts, and games
  granting goods on the strength of a client-reported callback learned quickly
  that devices are attacker-controlled. Server-to-server receipt verification
  became mandatory hygiene.
- **The arms race framing error.** Anti-cheat investment historically flowed to
  client hardening — obfuscation, drivers — while the actual boundary sits at
  the server. A modified client cannot *ask* dishonestly if the server never
  accepts outcomes from it; detection telemetry then converts what remains into
  an audit trail rather than an endless prevention war.

The CWE taxonomy eventually captured the core as CWE-602 (client-side
enforcement of server-side security) and OWASP's Insecure Design category
absorbed the systemic shape: this is a design failure before it is a coding one.

## Anatomy: the client-computed kill

Minimal vulnerable shape, one endpoint:

```javascript
app.post("/match/:id/hit", async (req, res) => {
  const { targetId, damage, killed } = req.body;   // all attacker-chosen
  await db.players.update(targetId, { hp: { decrement: damage } });
  if (killed) await awardKill(req.playerId, targetId);
  res.sendStatus(200);
});
```

Failure walkthrough:

1. Legitimacy camouflage: the endpoint exists precisely because real clients
   send hit messages. Nothing about the request looks anomalous.
2. Substitution: the attacker replaces their game client with ~50 lines of raw
   socket code (or edits memory/proxies traffic) and submits
   `{"targetId": anyone, "damage": 99999, "killed": true}`.
3. Authorship transfer: the server applies the attacker's number to its health
   pool and credits the kill. Bounds-checking `damage <= 500` would not help —
   bounds limit magnitude, not authorship; the attacker sends 499 forever.
4. Cascade: competitive integrity collapses (one-shot kills), leaderboards fill
   from forged attribution, and any economy hooked to match rewards mints value.
5. Silence: no crash, no error, plausible-looking telemetry. Only recomputation
   discipline or statistical outlier detection would surface it.

A second anatomy covers economy dupes without any combat context: a mail-claim
handler that reads `claimed == false`, then sets `claimed = true` in a second,
non-atomic step lets two parallel requests both pass the read and each attach
the reward — one grant of items becomes two. Same shape auctions, trades, shop
grant/debit ordering, and refund loops.

## Why naive fixes fail

- **Bounds checks on client values**: they cap how big the lie can be, not who
  authored it. Outcome fields need server recomputation; bounds are necessary
  only for inputs the server legitimately accepts.
- **Client-side anti-cheat as the control**: packers, obfuscation, and memory
  checks raise cost on one device while the protocol still trusts clients;
  the modified-client test ("would this operation still be legal via raw
  sockets?") fails regardless of client hardening.
- **Rubber-band teleport correction**: clamping movement with a naive per-tick
  cap punishes laggy legitimate players (bursts legitimately exceed per-tick
  caps after a spike). Tolerance budgets, credit banking, and server-clock math
  exist because the strict constant fails in production.
- **"Transactions make the economy safe"**: a transaction makes multi-statement
  work atomic, but check-then-write across two awaits still interleaves between
  transactions; conditional single-statement writes (`UPDATE ... WHERE claimed =
  false`) or row locks are required.
- **Trusting store webhook signatures alone**: signature proves origin, not
  uniqueness — retries replay the same valid event. Consumed-once transaction
  tables checked inside the grant transaction are the actual replay control.
- **Signing cloud-save blobs client-side**: signatures made by the device prove
  nothing about content; save editors are user-facing tools and blobs are
  untrusted uploads needing schema/bounds gates plus monotonic version checks.
- **Banning after one anomaly**: lag spikes, mount speeds, and ability bursts
  produce false positives; over-aggressive enforcement punishes honest p99
  players and trains support to whitelist, eroding the signal.

## Common misconceptions

1. **"Our client is compiled/obfuscated, so attackers can't craft requests."**
   Protocol schemas (.proto, packet enums) are public contracts; proxying your
   own session requires no reverse engineering at all.
2. **"Client prediction is the vulnerability."** Prediction plus server
   reconciliation is correct netcode; blind acceptance without reconciliation
   is the finding. The pattern is not guilty per se.
3. **"Anti-cheat drivers cover server-authority gaps."** Endpoint agents protect
   the client process, not your trust boundary; they can never substitute for
   server recompute and are explicitly out of scope as compensating controls.
4. **"Leaderboard scores are just cosmetic."** Boards drive purchases, prestige,
   and seasonal rewards; posted totals without backing event streams poison
   every reward path downstream of rank.
5. **"Refunds are the store's problem."** Revoked-purchase notifications must
   revoke granted goods; missing handlers convert chargebacks into free items.
6. **"Full-world broadcasts are a bandwidth choice."** Sending hidden state is
   the root cause of ESP/wallhacks; visibility filtering fixes the class at the
   send path where it actually lives.
7. **"Dupes get patched fast enough."** In monetized economies a dupe live for
   days reprices the whole market; severity weights economy scale, not exploit
   elegance.

## Modern taxonomy map

Matches the In Scope table of `../SKILL.md`; use these names when reporting.

| Class | One-line essence | Typical root cause |
|---|---|---|
| Server-authority gaps | Client-posted damage/kills/scores/results persisted | Outcomes accepted instead of derived |
| Movement / action validation | Unbounded displacement; client clocks/cooldowns | No server-clock displacement budget |
| Economy integrity | Trade/mail/auction/shop races and rollback resurrection | Check-then-write pairs; no CAS |
| Leaderboard / score | Posted totals; no physics-max or checkpoint consistency | Totals stored instead of derived |
| In-app purchases | Grant on client callback; receipt replay; refunds ignored | Missing server-to-server verification |
| Anti-cheat design (defensive) | No cheat-signal telemetry; full-world broadcast; no honeypots | Detection treated as optional |
| Session / protocol | Unauthenticated gameplay ports; no sequence/replay windows | Auth assumed HTTP-only |
| Save data / LiveOps | Blob merged unvalidated; unsigned config applied | Saves trusted as first-party |
| UGC / modding | Player scripts beyond sandbox quotas | Host privileges by default |
| Client-binary secrets | API keys/tokens embedded in shipped clients | Secret-based authz decisions |

Severity intuition: free minting of premium-convertible currency, unauth'd
gameplay mutation, and sandbox escapes anchor Critical; dupes, forgeable boards,
and ESP-by-broadcast anchor High (escalating one band in competitive/PvP);
cosmetic-only trust gaps anchor Medium; telemetry absence anchors Low but
amplifies everything else.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — "the server owns truth," the trust-boundary map, three
   design principles (prediction ≠ authority, visibility filtering, detection
   over prevention).
2. **What To Check** — sweeps A–J: server authority, movement, economy,
   leaderboards, purchases, defensive design, protocol, saves/LiveOps, UGC,
   client secrets.
3. **Where To Look** — directory heuristics and the ripgrep battery including
   the direct-assignment smell.
4. **Patterns & Signatures** — vulnerable shapes per flow (combat, movement,
   cooldowns, shop, receipts, saves) and the cheat_signal telemetry shape.
5. **Taint Tracing Guidance** — RECOMPUTE/BOUNDS-CHECK/PASSTHROUGH verdicts,
   operation-ordering diagrams, receipt order verification.
6. **Exploitation & Reproduction** — payload cheat-sheet, movement-impossibility
   math, Procedures A–E for owned systems, static-only confirmation standard.
7. **Remediation** — authoritative recompute, movement clamp with tolerance
   budget, atomic economy SQL, receipt middleware skeleton, interest management.

Sibling modules that own adjacent defects (hand findings over rather than
duplicating their analysis):

- `../business-logic-races/` — generic race theory, lock ordering, idempotency
  vocabulary reused by every economy fix here.
- `../denial-of-service/` — packet/message flood volumetrics.
- `../web-client/` — XSS inside game webviews and launcher UIs.
- `../secrets-data-exposure/` — scanning methodology for client-embedded keys.
- `../memory-safety/` — memory-disclosure techniques against shipped clients.
