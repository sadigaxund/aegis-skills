# API Security — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, signature greps, and remediation tables.

## How this class emerged

Machine-to-machine HTTP interfaces predate the browser-centric web: RPC systems
and SOAP services of the late 1990s and early 2000s already exposed logic where
humans could not click. REST — articulated in Roy Fielding's 2000 dissertation
and adopted widely through the decade — made APIs ordinary infrastructure, and
with them came a new failure surface: code that trusted *shape* over
*authority*, because the client was another program, not a person.

Two eras sharpened the class. First, framework ergonomics: Rails popularized
convention-heavy object binding in the mid-2000s, and in 2012 a public GitHub
incident showed a mass-assignment request flipping an organization-membership
flag through exactly such binding — the canonical demonstration that "the form
doesn't send that field" is not a security boundary when the server binds whole
objects from request bodies. Second, API-first products: GraphQL (released by
Facebook in 2015) collapsed a perimeter into thousands of client-shaped
resolvers; gRPC moved the same patterns to binary transports; mobile clients
embedded long-lived keys; and OWASP formalized the domain with its first API
Security Top 10 in 2019, refreshed in 2023.

The through-line is authority drift: every convenience that infers structure or
exposes self-description (auto-binding, introspection, reflection, docs) also
infers permissions unless someone says otherwise. Modern auditing therefore asks
not "is this endpoint protected?" but "which layer was supposed to say no, and
did it?"

## Anatomy: one extra field

The minimal shape needs only a permissive serializer:

```python
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"      # binds every column, including is_admin

# view: POST /api/register -> serializer.save()
```

Walkthrough of one registration:

1. The attacker sends the normal signup body plus one extra key:
   `{"email":"a@b.c","password":"…","is_admin":true}`.
2. Binding copies every supplied key onto the model because nothing restricts
   the writable set; unknown-but-existing columns bind silently, and there is
   no 400 for "unexpected property."
3. Persistence writes `is_admin = true`. The response may not even echo it —
   the privilege is already stored.
4. Nothing "broke." The endpoint did what its configuration said: bind all.
   The bug is that nobody drew the line between client-writable fields and
   server-owned ones.

The same anatomy recurs across the module's classes, with different carriers:

```text
GET /api/users?page=999999&limit=all   # no server-side clamp: table dump
POST /graphql {"query":"{__schema{types{name}}}"}   # introspection: schema map
Upgrade: websocket (Origin: https://evil.example) -> 101  # no origin check
grpcurl -plaintext host:50051 list     # reflection + plaintext h2c listener
```

Each is a contract the developer never wrote but the framework implied:
unbounded lists, self-describing schema, sockets that outlive handshakes,
machine interfaces that skip human-oriented middleware. Fixes are explicit
opt-ins to safety — field allowlists, server-side clamps, disabled
introspection, per-message authorization, auth interceptors — because absence
of an explicit opt-out is not a control.

## Why naive fixes fail

One subsection because the failure modes rhyme across classes:

- **Client-side validation as the allowlist.** Stripping fields in the UI or in
  frontend JS changes what browsers send; any HTTP client can replay arbitrary
  JSON at the same endpoint. Only server-side field reduction breaks the flow.
- **Validation without reduction.** Schema checks ("email looks like an email")
  still pass unknown keys through to persistence unless the binder constructs
  a fresh object from named fields or rejects extras (`forbid`/`whitelist`).
- **Rate limits keyed on spoofable inputs.** IP-only keys behind proxies read
  attacker-controlled `X-Forwarded-For` values; each new fake header mints a
  fresh bucket. Key on user-id/API-key first, IP second.
- **Disabling introspection as "hiding" the API.** Field-suggestion errors,
  batched probes, and persisted-query hashes reconstruct schemas; masking
  errors and depth/complexity limits carry the actual load protection.
- **Authenticating the connection instead of the message.** WebSocket/SSE
  handshakes establish identity once; actions arrive for hours afterward.
  Per-message authorization is a separate control, not a duplicate one.
- **Securing only the newest version.** Middleware parity gaps leave `/v1`
  running bare while `/v3` gained guards; deprecated versions are live attack
  surface until decommissioned, not documented.
- **Trusting gateway defaults for gRPC.** Plaintext h2c listeners bypass
  HTTP-layer middleware entirely; interceptors must cover every registered
  service, with exemptions (health checks) narrow and deliberate.

## Common misconceptions

1. "Our API is internal, so authz is optional." Internal consumers become
   external via SSRF, preview deployments, and pivots; object-level checks are
   the data's boundary, not the network's.
2. "The frontend only ever sends these fields." Attackers write their own
   clients; the set of fields the server accepts is defined by the binder, not
   by your forms or SDKs.
3. "GraphQL authentication at `/graphql` covers resolvers." One URL, thousands
   of reachable resolver functions; perimeter auth protects the door, resolvers
   need their own object-level predicates.
4. "429 responses prove rate limiting exists." A limiter can be present yet
   keyed on a spoofable header, scoped to the wrong route group, or absent on
   the exact expensive endpoint being hammered; check keying and coverage.
5. "Swagger/OpenAPI exposure is just documentation." A spec is a complete map
   of parameters, types, and internal hosts; unauthenticated docs hand over the
   recon phase of every later finding.
6. "gRPC is binary, so tools can't touch it." Public reflection plus grpcurl-
   style CLIs enumerate services without credentials; protobuf encoding hides
   structure from casual observers, not from the descriptor set.
7. "API keys in URLs are equivalent to headers." Query strings land in proxy
   logs, browser history, and Referer headers; transport choice is itself part
   of the secret-handling design.

## How professionals think about it today

Modern practice reads every handler as four implicit contracts — transport,
middleware, binding, serialization — and hunts mismatches between what
developers modeled and what frameworks auto-generated. The taxonomy mirrors
SKILL.md's sections:

| Class | Contract broken | Defining control |
|---|---|---|
| Mass assignment | binding | DTO/allowlist-only writes; forbid/strip extras |
| Rate limiting & pagination | middleware/transport cost model | keyed limiters + server-side clamps |
| GraphQL surface | schema/self-description | prod introspection off, depth/cost limits, masked errors |
| gRPC / protobuf | transport + interceptor parity | TLS, reflection gated, per-RPC auth on every service |
| REST hygiene | route/version/docs discipline | method allowlists, middleware parity, gated specs |
| API key management | credential lifecycle | header transport, scoping, revocation, rotation |
| WebSocket / SSE | channel lifetime vs handshake | origin-checked upgrade + per-message authz |

Severity follows authority: writing `role`/`is_admin` is Critical; unbounded
dumps scale with data sensitivity; disclosure surfaces stay Low–Medium alone
but feed everything else. Framework semantics decide false positives — Go
decoders drop unknown JSON keys, Pydantic ignores extras by default — so the
finding cites the binder's actual behavior, not folklore.

## Read next

In `../SKILL.md`: **Mental Model** (four contracts, permissive defaults), **What To Check** (per-class procedures), **Where To Look** (framework location
map), **Patterns & Signatures** (binding/rate-limit/GraphQL/gRPC greps, payload
cheat sheet), **Taint Tracing Guidance** (source/sink table per stack),
**Exploitation & Reproduction** (static-first recipes), **Remediation**
(framework-correct fixes), **Verification & Validation**, **Severity
Assessment**, **Common False Positives**.

Sibling modules: `../authz-access-control/SKILL.md` (object-level IDOR logic),
`../authn-session/SKILL.md` (credential stuffing thresholds, lockouts), `../deserialization/SKILL.md` (XML content-type payloads), `../denial-of-service/SKILL.md` (quantitative cost math), `../web-client/SKILL.md` (CSRF interplay
with method overrides), `../configuration-hardening/SKILL.md` (CORS matrix,
debug surfaces), `../secrets-data-exposure/SKILL.md` (keys echoed into logs).
