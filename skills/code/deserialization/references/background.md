# Deserialization & Object Injection — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the sink tables, regexes, and parser hardening flags.

## How this class emerged

Serialization exists because programs need to save and ship live objects: a
session must survive a restart, a queue message must cross process boundaries.
Native serializers solved this by writing objects out *including their type
information*, so the reader can reconstruct the exact class. That design
decision — trusting bytes to name classes — is the seed of the entire defect
class.

The security community noticed in stages:

- PHP's `unserialize()` on cookies and request fields produced "object
  injection": crafted strings instantiated arbitrary classes whose magic
  methods (constructors, destructors, string converters) ran attacker-chosen
  logic during object lifecycle events.
- Java serialization (`ObjectInputStream.readObject`, wire magic `AC ED`) became
  notorious once researchers showed that ordinary library classes could be
  chained — "gadget chains" — so that reading one innocent-looking object ends
  executing a command. Every dependency on the classpath enlarged the gadget
  pool; removing the vulnerable sink became the only reliable fix.
- Python `pickle` documented its own danger in its manual: unpickling executes
  code by design via reduction opcodes. Ruby Marshal and .NET BinaryFormatter
  followed the same pattern; BinaryFormatter was eventually deprecated and
  removed outright by its own vendor.
- XML brought a different resolution hazard: DTD *external entities* let a
  document instruct the parser to fetch files or URLs and splice them into the
  result — XXE. Hardening became a per-parser configuration chore, and one
  forgotten parser anywhere in an import path re-opened the hole.
- JavaScript contributed prototype pollution: JSON has no classes, but merging
  attacker keys like `__proto__` into plain objects mutates behavior shared by
  every object in the runtime — logic corruption without code execution.

The unifying modern lesson: the serializer is rarely the bug alone. The missing
integrity check before parsing, and the richness of classes reachable at parse
time, are what make attacker-controlled bytes exploitable.

## Anatomy: pickle's reduce opcode

Minimal generic vulnerable snippet:

```python
state = pickle.loads(base64.b64decode(request.data))
```

Failure walkthrough:

1. The endpoint accepts a base64 blob from the client and hands it to the
   deserializer with no signature check first.
2. Pickle streams contain opcodes; among them, reduction instructions naming a
   callable and its arguments. A payload of essentially
   `('os', 'system'), ('echo proof > /tmp/pwn',)` requires no exotic tooling.
3. During `loads()`, the unpickler imports `os`, resolves `system`, and calls it
   with the attacker's string — before any application-level validation runs,
   because validation happens *after* this line returns, which is too late.
4. Nothing about the surrounding code "looks wrong." The one-line call is the
   whole vulnerability; exploitability depends only on reachability of tainted
   bytes.

The identical trust shape appears everywhere: Java `readObject` honoring class
names in the stream, PHP `unserialize` invoking `__wakeup`, YAML loaders that
support language-object tags, deep-merge functions following `__proto__` keys.

## Why naive fixes fail

Each tempting mitigation below fails; SKILL.md's Remediation decision tree
shows what holds.

- **try/catch around the load**: exceptions fire after side effects began;
   catching them does not undo constructor or destructor execution.
- **Blocklists of class names**: gadget inventories grow with every dependency
   bump; you cannot enumerate what you do not control.
- **Type hints / `is_string` checks**: the blob usually *is* a string; the
   danger starts when parsing begins, not before.
- **Base64 "encoding" as protection**: transport encoding, not integrity;
   decodes trivially.
- **Signature check after parsing**: parse-time execution precedes your check
   by definition. Verify-then-parse or not at all.
- **HMAC without key hygiene**: signing helps only if the key is server-only
   and verification covers the exact serialized bytes before the load; HMACs
   also still leak content if confidentiality matters.
- **Class allowlists in old serializers**: reduces but does not eliminate risk;
   new gadgets appear inside allowlisted namespaces over time.
- **"It's internal-only traffic"**: internal services deserialize each other's
   messages; one compromised pod pivots through every native-deser hop. Scope
   may downgrade severity, never delete the finding silently.

## Common misconceptions

1. **"JSON.parse is dangerous deserialization."** Plain JSON decoding builds
   data, not executable objects — it is safe except for prototype-pollution
   merges. Flagging standard REST handlers wastes triage time.
2. **"Binary formats protect obscurity."** Attackers read binary formats just
   as readily; hex markers (`AC ED 00 05`, `\x80\x02`, `AAEAAAD/////`,
   `O:len:"Class"`) make recognition mechanical either way.
3. **"Signed means safe to parse any format."** Signatures help exactly one
   thing: integrity of those exact bytes before parsing. They neither hide
   content nor survive key leakage, and verification placed after the parse is
   decorative.
4. **"XXE needs error messages to matter."** Blind XXE exfiltrates via
   out-of-band callbacks (parameter entities fetching attacker URLs) even with
   zero reflection in responses.
5. **"Prototype pollution is client-side trivia."** Server-side Node runtimes
   pollute too; a polluted `Object.prototype` flips authorization flags,
   breaks template rendering, and enables RCE chains in some stacks.
6. **"Go's encoding/xml has the same problem."** It performs no entity
   expansion; XXE templates simply do not apply there — a false positive the
   module explicitly calls out.
7. **"We patched the known-bad library, so we're done."** Gadget chains live in
   whatever remains on the classpath; patching one library shifts the reachable
   set rather than closing the sink.

## Modern taxonomy map

Matches the three-tier risk table in `../SKILL.md`'s Mental Model section:

| Tier | Mechanism | Typical outcome | Canonical sinks |
|---|---|---|---|
| T1 | Attacker bytes drive object instantiation | RCE via gadget chains | `pickle.loads`, `ObjectInputStream.readObject`, `BinaryFormatter.Deserialize`, PHP `unserialize`, Ruby `Marshal.load` |
| T2 | External entity/reference resolution | File read, SSRF, DoS | XML parsers without entity hardening; unsafe YAML tags |
| T3 | Key/path manipulation inside plain structures | Logic bypass, pollution | Deep merges, `__proto__`/`constructor` keys, reflection-by-name |

Severity intuition: network-reachable T1 without an integrity gate starts
Critical; internal-mesh T1 and blind T2 land High/Medium-High; pollution
without a demonstrated impact path trends Medium-High pending evidence.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — the verify-before-parse insight and the three risk tiers.
2. **What To Check** — sink enumeration, origin tracing, integrity-gate
   verification, per-parser XXE flags, merge/qs pollution surfaces.
3. **Where To Look** — high-yield locations ranked (import endpoints, webhook
   XML, queue consumers, cookie decode paths).
4. **Patterns & Signatures** — serializer sink tables plus blob-format magic
   markers for confirming what a sink expects.
5. **Remediation** — decision tree ending in JSON+schema, signed-exact-bytes, or
   replacement; exact hardening flag names per XML parser.
6. **Common False Positives** — before flagging Go XML or signed cookies, read
   what does not qualify.

Sibling modules owning adjacent defects:

- `../api-security/` — mass assignment from rich request structures.
- `../ssrf-url-security/` — URL fetchers reached through XXE-style reference resolution.
- `../denial-of-service/` — decompression/entity-expansion resource math.
- `../authn-session/` — JWT/token integrity questions.
