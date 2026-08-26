---
name: aegis-api-security
description: Audit playbook module for API-specific security failures covering mass assignment, missing rate limits and pagination caps, GraphQL/gRPC misconfiguration, REST hygiene gaps, API key mishandling, and WebSocket/SSE access-control defects across all mainstream web frameworks.
category_slug: API
cwe: [CWE-915, CWE-770, CWE-799, CWE-306, CWE-862, CWE-639, CWE-200, CWE-400, CWE-798, CWE-346, CWE-942]
owasp: API3:2023, API4:2023, API6:2023, API8:2023, API9:2023 primary; API1:2023, API2:2023, API5:2023 secondary (full per-class mapping in References)
---

## Scope & Objectives

### Objective

Audit the HTTP-facing surface of the target repository for API-specific design and configuration failures that let a client exceed its intended authority: write fields the server never meant to expose, consume unbounded resources, enumerate internals through schema and documentation surfaces, skip transport or channel authentication, or ride privileged channels cross-origin. For every finding produce file:line evidence, a reproduction recipe (static-first), a severity with rationale, and a framework-correct fix.

### In Scope

| Class | Typical finding | Primary CWE |
|---|---|---|
| Mass assignment / over-posting | Client sets `role`, `is_admin`, `price`, `user_id` through request-body binding to ORM entities | CWE-915 |
| Rate limiting & anti-automation | Unthrottled auth/search/export endpoints, no pagination caps, no per-key quotas | CWE-770, CWE-799 |
| GraphQL configuration | Prod introspection, exposed playground/GraphiQL, no depth/complexity limits, batching abuse, field-suggestion leakage | CWE-200, CWE-400 |
| gRPC / protobuf | Public reflection service, plaintext h2c listeners reachable externally, missing per-RPC auth interceptors | CWE-306, CWE-200 |
| REST hygiene | `_method` override shadowing, state-changing GET, deprecated versions still live, unauthenticated OpenAPI docs, debug headers, CORS wildcard with credentials, content-type confusion entry points, leaky error envelopes | CWE-200, CWE-942 |
| API key management | Keys accepted in URLs, shared keys embedded in mobile/SDK builds, god-mode unscoped keys, no revocation flow | CWE-798 |
| WebSocket / SSE channels | Missing Origin validation at upgrade, handshake-only authentication, topics without per-user ACLs | CWE-346, CWE-862 |

### Out of Scope (cross-references)

- Credential-stuffing thresholds and account lockout policy details -> AUTHN module. This module covers only the platform throttling layer.
- Object-level IDOR logic inside business flows -> AUTHZ module. Cover here only where API mechanics enable it (GraphQL resolvers, subscription topics).
- XXE payload construction via XML content-type confusion -> DESER module. Flag the accepting endpoint only.
- CSRF token design -> WEB module. Note `_method` override interplay; defer token analysis.
- Full CORS origin-reflection matrix -> CONFIG module. Record API-side wildcard+credentials observations as input.
- Secrets echoed in responses or logs -> SECRETS module. Flag key-in-URL log exposure here.
- Quantitative DoS math for nested-query bombs -> DOS module. Establish that limits are absent; do not compute blast radius.

### Operating Assumptions

Read-only access to the repository; no running instance is guaranteed. Treat dynamic reproduction as optional and permissible only against explicitly authorized environments. Static confirmation grounded in documented framework semantics is sufficient evidence for reporting.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **mass assignment**: the framework copying a whole request body into an object, letting clients set fields like `is_admin`
- **BOLA**: changing identifiers in requests to touch other users' objects (detailed in the AUTHZ module)
- **rate limit**: a cap on requests per client per time window
- **pagination cap**: maximum page size preventing million-row dumps in one call
- **introspection / playground**: GraphQL self-documentation features that hand attackers a map of your API
- **resolver**: the per-field function answering each GraphQL query; every one needs its own permission check
- **shadow API**: a live endpoint missing from documentation, so it also missed review
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function

## Mental Model

### One Endpoint, Four Implicit Contracts

An API handler composes four contracts the client sees only partially:

1. Transport: HTTP/1.1, HTTP/2, h2c, WebSocket upgrade, SSE stream.
2. Routing/middleware: which guards ran before the handler body.
3. Binding: how raw bytes became typed objects on the server.
4. Serialization: which server objects become bytes again.

Most API findings are a mismatch between what developers modeled and what a framework auto-generated in one of these layers. Mass assignment lives in binding and serialization. Throttling, origin, and channel-auth findings live in transport and middleware. Disclosure findings live in the schema surface: OpenAPI files, GraphQL introspection, protobuf reflection.

### Framework Magic Shifts Default Posture

Modern stacks optimize developer ergonomics: bind the whole request body to a model, hydrate entities from JSON, expose descriptors for tooling. Each convenience is a permissive default:

- Permissive binding enables mass assignment (CWE-915).
- Permissive schema exposure leaks internals (introspection, `/openapi.json`, gRPC reflection).
- Permissive consumption has no default cap on list size, query depth, or request rate.

Audit for an explicit opt-IN to safety (field allowlists, limiters, disabled introspection, auth interceptors), not merely the absence of an explicit opt-out. Assume permissive defaults until proven otherwise.

### Cost Asymmetry Drives the Throttling Class

Every endpoint has a server-side cost and a client-side price. Search-with-joins, export, password-reset mailers, and SMS sends multiply cost; pagination caps and throttles are the meter. A missing meter converts one request into ten thousand automated requests: enumeration, brute force, scraping, financial drain. Judge each expensive endpoint by asking one question: what stops a script calling it 10,000 times?

### GraphQL Collapses the Perimeter into Resolvers

One URL, thousands of reachable resolvers, client-shaped queries. Perimeter auth at `/graphql` protects nothing if resolvers skip object-level checks because "the schema is internal". The schema itself is a public map of your object graph; query depth is an attacker-chosen loop counter. Treat every resolver as an unauthenticated handler until middleware proves otherwise, and treat introspection, playgrounds, and field suggestions as documentation leaks.

### gRPC Moves the Same Problems Down One Layer

Protobuf replaces JSON binding; reflection replaces Swagger; interceptors replace middleware. Ask the same questions: who can call which RPC (per-method auth metadata enforced by an interceptor, or nowhere?), what does an oversized or unknown-field-filled message do to memory and storage, and is the plaintext h2c port reachable from outside the cluster?

### Channels Outlive Handshakes

WebSocket and SSE connections are long-lived and multiplex actions over messages. Handshake-time authentication without per-message authorization means any connected socket inherits the session's powers for the connection lifetime. When the Origin check at upgrade is also absent, a malicious web page in a victim's browser opens that socket cross-origin and rides the victim's cookies.

## What To Check

### Mass Assignment / Over-Posting

1. Locate every request-body ingestion point (controller action, GraphQL mutation resolver, gRPC handler). Identify the exact type being bound and whether it is an ORM/domain entity or a dedicated request DTO.
2. Flag direct binding to ORM entities: DRF `ModelSerializer` with permissive fields, Mongoose models passed straight to `create()`/`findByIdAndUpdate()`, Sequelize/Prisma `create(req.body)`, Eloquent `Model::create($request->all())`, Rails `Model.new(params)` without `permit`, Spring `@ModelAttribute` bound onto a JPA entity, ASP.NET Core `[FromBody] User user` where `User` is a `DbSet<>` entity, Go `json.NewDecoder(r.Body).Decode(&domainStruct)` into a shared model.
3. Grep serializers/schemas for allowlist absence: DRF `fields = "__all__"`, NestJS DTOs used with `ValidationPipe()` lacking `whitelist: true`, Laravel models missing `$fillable` (or `$guarded = []`), Pydantic models configured `extra="allow"`.
4. Enumerate sensitive settable candidates on every bound model: `role`, `roles`, `is_admin`, `admin`, `permissions`, `price`, `amount`, `balance`, `discount`, `status`, `verified`, `email_verified`, `user_id`, `owner_id`, `account_id`, `tenant_id`, `created_at`, `password_hash`, `credits`. For each candidate, trace whether any client-facing path binds it.
5. Inspect PATCH/PUT merge paths specifically: `Object.assign(entity, req.body)`, spread of `req.body` into update objects, Python `setattr` loops over payload keys, Ruby `merge!(params)`, EF Core `CurrentValues.SetValues(dto)` onto entities, `dict.update(payload)`.
6. Check nested/embedded writes that cascade the same flaw deeper: Rails `accepts_nested_attributes_for`, writable nested DRF serializers, Mongoose subdocument arrays hydrated from the body.
7. Verify response symmetry as corroboration: if a field is returned by GET but has no documented write path, confirm no undocumented path binds it before reporting.

### Rate Limiting & Anti-Automation

1. Reconstruct the middleware chain per route group; record which routes carry a limiter and which do not. Prioritize auth (login, register, password reset, OTP), search, export, report generation, mailer/SMS-triggering, and payment-quote endpoints lacking any limiter.
2. Confirm limiter keying: IP-only keys break behind proxies when `X-Forwarded-For` is client-controlled (`app.set('trust proxy', true)`). Prefer user-id/API-key keys with IP fallback.
3. List all collection endpoints; verify hard caps exist server-side: maximum page size clamps, bounded offsets/windows, cursor bounds, `SELECT ... LIMIT`, no `.all()`/`.find({})`/`FindAll` returning unbounded sets, export endpoints streaming entire tables in one request.
4. For metered APIs, verify per-API-key quotas exist and are enforced server-side (quota middleware, plan-tier table), not merely advertised in docs.
5. Check for captcha/proof-of-work or equivalent friction on abuse-sensitive flows: signup, voting, bulk invites, reward/gift-card redemption.
6. Note cost multipliers that make one request expensive: eager-loading everything (`include: [...all]`, `populate()`, `select_related` chains), search joining across large tables, PDF/report generation.

### GraphQL Surface

1. Find the server bootstrap (apollo-server, `@nestjs/graphql`, graphql-yoga, strawberry-graphql, graphene, gqlgen, graphql-go). Determine production values of introspection and landing-page/playground flags, not just their existence in code.
2. Verify query validation controls: depth limits, complexity/cost analysis, alias-count limits where supported, disabled field suggestions in errors.
3. Sample resolvers for object-level authorization gaps: queries/mutations accepting an `id`/`uuid` argument that fetch-and-return objects without ownership or tenant checks, especially near comments like "internal schema".
4. Test batching posture statically: does the endpoint accept an array body (`[{"query":"..."},...]`) enabling many operations per request? Is AutomaticPersistedQuery used with a registered-operation allowlist, or does it accept arbitrary hashes?
5. Inspect error formatting paths: "Did you mean" suggestions on unknown fields, stack traces or internal paths inside `errors[].extensions`.
6. Subscriptions: authenticate at subscribe AND at each event delivery; check topic/channel ACLs.

### gRPC / Protobuf

1. Find reflection registrations and determine environment gating (dev-only versus always-on).
2. Identify listener credentials: plaintext `NewServer()`/h2c versus TLS; correlate listening ports with Dockerfile `EXPOSE`, Kubernetes manifests, and load-balancer config to judge external reachability.
3. Verify auth enforcement: a unary/stream interceptor validating metadata (token, API key) applied to ALL registered services, or some services registered without it? Confirm deliberate exemptions (health checks) are narrow.
4. Assess message robustness: sane `MaxRecvMsgSize` (not `math.MaxInt64`), use of `google.protobuf.Any` with type-url-driven dispatch, unknown-field handling on persistence paths, enum validation before storage.
5. Check gateway exposure (grpc-gateway, Envoy JSON transcoding): does the HTTP path enforce the same auth as native RPC?

### REST Hygiene

1. Verb/route shadowing: `_method` form/query parameters and `X-HTTP-Method-Override` middleware; confirm overridden verbs are restricted to an allowlist and CSRF-protected where session-authenticated.
2. State changes on GET: scan route tables for GET paths containing mutating verbs (`delete`, `update`, `create`, `reset`, `send`, `confirm`, `approve`).
3. Version sprawl: multiple `/vN` prefixes mounted simultaneously; deprecated versions still receiving traffic; security middleware (authz guards, limiters) wired only onto the newest router while `/v1` runs bare.
4. Docs exposure: `/swagger`, `/swagger-ui.html`, `/api-docs`, `/openapi.json`, `/graphql` with HTML Accept, redoc pages, drf-yasg, springdoc actuator mappings; confirm each is auth-gated in production wiring. Also read the spec content for internal-only hosts/endpoints described publicly.
5. Debug/internal headers: `X-Powered-By`, `X-AspNet-Version`, Symfony `X-Debug-Token` plus reachable `/_profiler`, `Server` banners, `Access-Control-Expose-Headers` listing internals.
6. Middleware parity across route groups: compare `app.use(...)` ordering; find groups (`/internal`, `/webhooks`, legacy `/v1`) that skip auth or rate-limit middlewares the modern groups apply.
7. Content-type handling: identify XML-capable endpoints (entry points only; payload craft belongs to DESER), routes accepting `text/plain` that bypass CSRF checks keyed on content type, GET handlers parsing bodies.
8. Content negotiation: Accept-header driven serializers (DRF `renderer_classes`, ASP.NET output formatters, Rails responders) exposing richer serializations than the default JSON view (for example `?format=xml` dumping relations).
9. Error envelopes: uniform error handler? Stack traces, class names, internal hostnames leaking in error bodies; verbosity toggled by environment flags left on.
10. Shadow-API discovery: diff implemented route tables against the OpenAPI spec(s) — endpoints living in code but absent from the published spec are undocumented attack surface; record file:line evidence on both sides of each divergence.
11. Gateway-layer access-log analytics markers: confirm API access logs feed some analytics/anomaly review (per-key volume baselines, error-rate spikes); logs collected but never analyzed leave abuse patterns invisible.

### API Key Management

1. Locate key acceptance points: query-string parameters (`api_key`, `access_token`, `token`) versus headers (`Authorization`, `X-API-Key`). Flag URL transport: URLs land in proxy logs, browser history, and referrer headers.
2. Search the repo and any mobile/SDK directories for embedded static keys at SDK init sites; classify by provider prefix patterns; determine whether they are client-shippable secrets.
3. Assess scoping: does one key grant every endpoint (god key)? Look for scope/permission checks bound to key records and per-key quota enforcement.
4. Assess lifecycle: key status columns, expiry timestamps, rotation endpoints, revocation flow, issuance audit trail. Absence of any revoke path is itself a finding.
5. Public unauthenticated APIs: generous anonymous default limits with no signup friction raise abuse potential; record defaults.
6. Lifecycle depth: created-at timestamps and last-used tracking on key records enable dormant-key detection; keys with no usage telemetry make stale-credential cleanup impossible.

### WebSocket / SSE

1. Upgrade path: locate server creation (ws, socket.io, SignalR, gorilla/websocket, ActionCable, Phoenix Channels, Django Channels). Verify Origin/Host validation is enforced during upgrade (`verifyClient` in ws, `cors` option for socket.io, SignalR `AllowedOrigins`, `CheckOrigin`, `OriginValidator`).
2. Post-handshake auth: is identity established only at connection time? Are message types/actions authorized per message? Find `socket.on('action', ...)` handlers mutating data using only handshake-derived identity plus client-supplied IDs.
3. Subscription topics/rooms: check whether joining a room/channel validates per-user ACLs or accepts any client-supplied topic name (`socket.join(req.body.room)`).
4. SSE: locate `text/event-stream` endpoints; verify auth on the stream request itself and on `Last-Event-ID` replay semantics (replay must not leak other tenants' events).
5. Cross-service trust: sockets often bypass the HTTP middleware chain entirely; confirm socket handlers re-apply authorization rather than assuming "the connection is trusted".

## Where To Look

### Framework Location Map

| Stack | Binding/serializer files | Route/middleware files | Notes |
|---|---|---|---|
| Express/Fastify | handlers co-located with routes | `app.js`, `server.ts`, `routes/*.js`, Fastify `schema:` keys | Fastify JSON-schema `additionalProperties:false` changes binding posture; check each route schema |
| NestJS | `*.dto.ts`, `entities/*.entity.ts` | `main.ts` (global pipes/guards), `*.controller.ts`, `app.module.ts` | Global vs controller-level `ValidationPipe`; guard order |
| Django REST Framework | `serializers.py`, `models.py` | `urls.py`, `views.py`, `settings.py` REST_FRAMEWORK block | Default throttle classes live in settings |
| FastAPI/Flask-RESTful | Pydantic schemas `schemas.py` | `main.py`, `api/*.py`, Flask `app = Flask(...)` decorator chains | Pydantic `extra` config decides unknown-field behavior |
| Spring MVC/WebFlux | entity classes, projection DTOs, `@ControllerAdvice` | `@SpringBootApplication` main class, `WebSecurityConfigurerAdapter`/`SecurityFilterChain` beans, controllers | `springdoc.*` properties gate docs exposure |
| ASP.NET Core Web API | `Models/`, `DTOs/` | `Startup.cs`/`Program.cs`, `Controllers/*.cs` | Middleware order in pipeline; Swashbuckle `UseSwaggerUI` env gating |
| Laravel/Lumen | `app/Http/Requests/*`, `app/Models/*` ($fillable) | `routes/api.php`, `app/Http/Kernel.php` ($middleware, $middlewareGroups) | `throttle:` middleware alias presence per route group |
| Rails API mode | `app/models/*`, `app/serializers/*` | `config/routes.rb`, `config/application.rb`, Rack::Attack initializer | `ActionController::Base.allow_forgery_protection` irrelevant in API mode; strong params in controllers |
| Go chi/gin/echo | handler files binding structs | router setup in `main.go`/`cmd/*/main.go`, middleware registration | No auto-binding magic; risk is decoding into shared domain structs |
| GraphQL (apollo/yoga/strawberry/graphene) | `typeDefs`, `resolvers.*`, schema files | server bootstrap file (`apollo-server` constructor, yoga config, strawberry `extensions=[...]`) | Validation rules configured only here |
| gRPC | `*.proto`, generated stubs ignored | server setup (`grpc.NewServer(...)`, Python `grpc.server(...)`, Java `ServerBuilder`) | Interceptors and reflection registered here |

### Configuration Files With API Posture

- `settings.py`: `REST_FRAMEWORK` dict (throttles, renderers, parsers), `DEBUG`, middleware list.
- `.env`, `config/*.yaml`, `application.properties/yml`, `appsettings.json`: introspection flags, swagger enablement, rate-limit numbers, trust-proxy settings.
- `Dockerfile`, `docker-compose.yml`, `k8s/`: which ports (including plaintext gRPC) are published externally.
- Reverse proxies (`nginx.conf`, Envoy configs): platform-layer rate limiting that may satisfy throttling findings before flagging code.

### Search Order

Start from route tables to enumerate the full endpoint inventory, then walk ingestion points for binding posture, then bootstrap/config files for global flags (pipes, limiters, introspection), then per-endpoint for missing controls. This ordering prevents mistaking one protected route group for an overall protected service.

## Patterns & Signatures

All regexes run under ripgrep (`rg`) and the Rust regex crate: no lookarounds, no backreferences. Run from the repository root; triage hits manually before reporting.

### Mass Assignment Signatures

```regex
fields\s*=\s*["']__all__["']
```
DRF serializer exposing every model column, including `is_admin`, `password_hash`.

```regex
\$request->all\(\)
```
Laravel/Lumen raw request array; check every hit for flow into `create()`/`update()`/`fill()`.

```regex
->(create|update|fill|firstOrCreate|updateOrCreate)\(\$request->all\(\)\)
```
Direct Eloquent over-posting sink.

```regex
\.new\(params\[|\.create\(params\[|\.update\(params\[
```
Rails models built from unfiltered params; confirm `.permit(...)` exists upstream in the same action.

```regex
(Object\.assign|merge|extend)\(\s*[A-Za-z_$][\w$.]*\s*,\s*req\.body
```
Express/Fastify arbitrary-key merge onto a persisted object.

```regex
\.\.\.req\.body
```
Spread of client body into update payloads or constructor options.

```regex
\.(create|findByIdAndUpdate|findOneAndUpdate|updateOne|bulkWrite)\(\s*req\.body\b
```
Mongoose write sinks consuming the whole body.

```regex
ValidationPipe\(\)
```
NestJS pipe with default options: unknown properties pass through untouched.

```regex
@ModelAttribute|setAllowedFields|ignoreUnknownFields
```
Spring data-binding surface and its (rare) safety valves; flag `@ModelAttribute` bound to entity classes.

```regex
FromBody\]\s+[A-Za-z_][A-Za-z0-9_]*\s+\w+
```
ASP.NET Core body-bound parameters; diff the bound type name against `DbSet<...>` declarations to spot entity binding.

```regex
extra\s*[=:]\s*["'](allow|ignore)["']?
```
Pydantic posture: `allow` accepts and stores extras; plain `ignore` drops them (safe for writes).

```regex
setattr\s*\(\s*[a-z_]+\s*,\s*(k|key|field|attr|name)\s*,|merge!\(|SetValues\(|\.update\(payload\)|\.update\(data\)
```
Dynamic-key PATCH merge sinks across Python/Ruby/.NET/JS.

### Rate Limiting & Pagination Signatures

Inventory limiter presence first, then diff against your endpoint list:

```regex
(?i)(rate.?limit|throttle|rack.?attack|slowapi|flask_limiter|django_ratelimit|addratelimiter|ratelimiting|express-rate-limit|nestjs/throttler)
```

```regex
TooManyRequests|StatusTooManyRequests|HttpStatusCode\.TooManyRequests
```

Unbounded collection sinks:

```regex
\.all\(\)|\.find\(\s*\{\s*\}\s*\)|findAll\(\)|FindAll\(\)|SELECT\s+\*\s+FROM
```

Pagination parameters expected on list routes (their absence on a collection route is the finding):

```regex
[?&](page|per_page|pageSize|limit|offset|cursor|after|before)=
```

Proxy-trust foot-guns for IP-keyed limiters:

```regex
trust proxy|trustProxy|X-Forwarded-For
```

### GraphQL Signatures

```regex
introspection\s*:|GRAPHQL_INTROSPECTION|disableIntrospection|DisableIntrospection|introspectionEnabled
```

```regex
graphiql|playground|landingPage|LandingPage|GraphiQL
```

Depth/complexity controls (presence is good; absence near a GraphQL bootstrap is the finding):

```regex
depthLimit|max_depth|maxDepth|QueryDepthLimiter|complexity|ComplexityLimit|costAnalysis|validationRules
```

Batching/persisted-query machinery:

```regex
PersistedQuery|persistedQueries|APQ|shouldPersistedQuery|batching
```

### gRPC Signatures

```regex
reflection\.Register|enable_server_reflection|ProtoReflectionService|RegisterReflectionService
```

Plaintext listeners:

```regex
insecure\.NewCredentials|InsecureServerCredentials|WithTransportCredentials\(insecure|h2c
```

Auth interceptor presence (absence near server construction is the finding):

```regex
UnaryInterceptor|StreamInterceptor|ServerInterceptors|ServerInterceptor|AddUnaryInterceptors|AddStreamInterceptors
```

Message-size posture:

```regex
MaxRecvMsgSize|MaxReceiveMessageSize|max_receive_message_length
```

### REST Hygiene Signatures

Method override machinery:

```regex
_method|methodOverride|MethodOverride|X-HTTP-Method-Override|HttpMethodOverride
```

State changes on GET (Express-style; repeat the scan manually over Rails/Django/Flask route tables):

```regex
\.(get|GET)\(\s*["'][^"']*(delete|remove|destroy|update|edit|create|reset|send|confirm|approve)
```

Version sprawl:

```regex
/api/v[0-9]|["']/v[0-9]+/
```

Docs exposure:

```regex
swagger-ui|swagger\.json|openapi\.json|api-docs|UseSwaggerUI|drf_yasg|drf-spectacular|flask_swagger_ui|springdoc
```

Debug/internal header emission:

```regex
X-Powered-By|x-aspnet-version|x-debug-token|_profiler|exposeHeaders|Access-Control-Expose-Headers
```

CORS wildcard and origin reflection:

```regex
Access-Control-Allow-Origin["']?\s*[,:]\s*["']?\*
```

```regex
origin\s*:\s*true|callback\(null,\s*req\.headers\.origin|SetIsOriginAllowed\(|AllowCredentials\(\)|credentials\s*:\s*true
```

Content-type confusion entry points (payload craft -> DESER module):

```regex
xml-bodyparser|lxml\.etree|etree\.fromstring|fromstring\(|JAXBContext|JacksonXml|XmlSerializer|application/xml
```

Error-envelope leakage:

```regex
err\.stack|error\.stack|traceback\.format_exc|printStackTrace|DEBUG\s*=\s*True|includeErrorDetails|DetailedErrors|includeStacktrace
```

### API Key Signatures

Key accepted from URL/query (log-exposed transport):

```regex
request\.args\.get\(["'](api_key|apikey|token)["']\)|query\.Get\("api_key"\)|params\[:(api_key|token)\]|Request\.Query\[["']api_key
```

Hardcoded credential formats (well-known public prefixes):

```regex
AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-zA-Z]{16,}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z\-]{10,}
```

Scoping enforcement markers (presence is good):

```regex
scopes?\s*[=:]|hasScope|scope_required|check_scopes|permissions\.includes
```

### WebSocket / SSE Signatures

Upgrade handling and origin validation:

```regex
WebSocketServer|io\.on\(["']connection|handleUpgrade|verifyClient|CheckOrigin|AllowedOrigins|OriginValidator|allowed_origins|origins
```

Per-message action handlers needing per-message authz:

```regex
socket\.on\(|conn\.on\(|OnConnected|receive\(|async_receive
```

Room/topic joins to ACL-check:

```regex
socket\.join\(|join_room|groups\.add|AddToGroupAsync|channels\.subscribe
```

SSE surfaces:

```regex
text/event-stream|EventSource|Last-Event-ID
```

### Payload Cheat Sheet

Mass assignment bodies (POST/PUT/PATCH against registration, profile, order endpoints):

```json
{"email":"attacker@example.com","password":"Str0ng!passphrase","is_admin":true}
{"username":"a","price":0,"user_id":2,"role":"admin"}
{"nickname":"x","tenant_id":1,"balance":999999,"email_verified":true}
```

PATCH merge probe (arbitrary keys into a partial update):

```json
{"role":"admin","permissions":["*"],"status":"active"}
```

GraphQL probes:

- Introspection short form: `{"query":"{__schema{types{name}}}"}` — a JSON body containing `"types"` with a list of type names confirms introspection is enabled.
- Presence probe: `{"query":"{__typename}"}` — cheap liveness check for the GraphQL endpoint.
- Field-suggestion probe: `{"query":"{users{usrnme}}"}` — an error containing "Did you mean" leaks schema names.
- Depth-bomb shape (describe, do not ship megapayloads): a query whose selection sets nest 20-100 levels deep, each level selecting another object's connection field, e.g. `user -> friends -> friends -> friends ...`; optionally amplified with duplicate aliases at each level. Confirm absence of depth/complexity limits statically before considering any dynamic test.
- Batching probe: `[{"query":"{__typename}"},{"query":"{__typename}"}]` — two answers in one response means operation batching is enabled.

Pagination-absence probes:

```text
?page=999999&limit=all
?limit=1000000
?offset=0&count=-1
?perPage=99999999
```

A dump-one-shot endpoint returns full data (not a 400/clamp) for these.

`_method` override examples:

```text
POST /users/1/delete                      route registered for GET only
form body: _method=DELETE&_token=<csrf>   Rails/Laravel form override
header: X-HTTP-Method-Override: PUT       sent against POST /api/items/1
query:  /api/items/1?_method=DELETE       query-string variant
```

WebSocket cross-origin handshake probe:

```bash
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://evil.example" https://host/ws
```

`HTTP/1.1 101 Switching Protocols` in response to a foreign Origin means upgrade-origin validation is absent.

## Taint Tracing Guidance

Treat every client-supplied key-value pair as tainted at the transport boundary and follow it to a persistence sink. The taint of interest for mass assignment is the KEY NAME, not only the value: an attacker controls which attributes get written, not just what they contain.

### Source/Sink Table

| Language/Stack | Sources (client-controlled) | Sinks (persistence) |
|---|---|---|
| Node/Express/Fastify | `req.body`, `req.query`, `req.params`, Fastify parsed body | `Model.create()`, `findByIdAndUpdate()`, `Object.assign(entity, ...)`, Knex `update(payload)`, Prisma `create(data)` |
| NestJS | DTO parameter decorated `@Body()`, raw `request.body` in guards | repository `.save(partialEntity)`, TypeORM `preload()`/`merge()` |
| Python DRF | `request.data`, serializer input | `serializer.save()`, `Model.objects.create(**validated_data)` |
| Python Flask/FastAPI | `request.get_json()`, Pydantic model fields (`model_dump()`) | `db.session.add(obj)`, SQLAlchemy `update(values)` |
| Ruby Rails | `params` hash | `Model.new(params)`, `update(params)`, `assign_attributes`, `merge!` |
| PHP Laravel | `$request->all()`, `$request->input()` | `::create($array)`, `->fill($array)`, `->forceFill()` |
| Java Spring | form/query binding onto annotated parameters, `@RequestBody` DTOs | JPA repositories `.save(entity)`, `setData(...)` |
| C# ASP.NET | `[FromBody]` models, `TryUpdateModelAsync` | EF Core `_context.Add()`, `CurrentValues.SetValues()` |
| Go | `json.NewDecoder(r.Body).Decode(&v)`, gin `c.ShouldBindJSON(&v)` | GORM `.Create(v)`, `.Updates(map)`, sqlx insert built from struct fields |
| GraphQL | resolver `(root, args, ctx)`, nested input objects | same ORM sinks as host language |

### Procedure

1. Anchor on the source: list all body-ingestion points from Where To Look.
2. Walk forward: does the bound object reach any sink table row without a field-reduction step in between?
3. Field-reduction steps that BREAK the flow: explicit allowlists (`permit`, `fields = [...]`, `whitelist:true`, `$fillable`, projection DTOs, `pick()` helpers). Any other transformation (validation, defaults, mapping libraries) does NOT break it unless it constructs a fresh object with named fields.
4. At the sink, diff the writable attribute set against the sensitive candidate list (role/is_admin/price/user_id and friends from What To Check).
5. For GraphQL, additionally walk resolver-by-resolver: each resolver with an `id`-like argument is its own source-to-sink path; check ownership predicates inside the resolver or its data-loader.
6. For gRPC, sources are proto message fields; trace handler code paths where message fields populate entity fields directly, especially update RPCs applying partial masks.

### Flow-Breaking Constructs Reference

```js
// VULNERABLE - spread preserves attacker keys
const user = await User.create({ ...req.body });
// FIXED - explicit pick
const { email, password, nickname } = req.body;
const user = await User.create({ email, password, nickname });
```

```python
# VULNERABLE - dynamic kwargs
User.objects.create(**request.data)
# FIXED - named fields
User.objects.create(email=request.data["email"], nickname=request.data.get("nickname", ""))
```

## Exploitation & Reproduction

Confirm statically first; run dynamic steps only against environments you are explicitly authorized to test. Counts stay modest on purpose.

### Mass Assignment to Privilege Escalation

1. Identify the registration or profile-update endpoint and the entity it binds (static step).
2. Send a normal registration, adding one sensitive field:

```bash
curl -s -X POST https://host/api/register -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"Str0ng!passphrase","is_admin":true}'
```

3. Authenticate as that user and request an admin-only endpoint (e.g. `GET /api/admin/users`).
4. Expected observable for a true positive: the sensitive field was accepted silently (no 400 naming the unknown property) AND the admin endpoint returns 200 instead of 401/403. If the server rejects unknown fields with 400/422, the control holds; record that.
5. Verification without privilege claims: diff `GET /api/me` before and after a PATCH carrying `"role":"admin"`, or simply confirm acceptance of the unknown key plus code-level sink — sufficient for reporting.

### PATCH Arbitrary-Key Merge

```bash
curl -s -X PATCH https://host/api/users/me -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{"role":"admin","tenant_id":1}'
```

Expected observable: 200 OK echoing back the injected fields in the response body.

### Throttling Absence

1. Choose the auth endpoint (login is ideal).

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST https://host/api/login \
    -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"wrong"}'
done | sort | uniq -c
```

2. Expected observable for absence: twenty consecutive `200`/`401` responses and zero `429`/`403` throttles. A single `429` indicates a limiter exists; check its keying and scope next.

### Pagination Absence / Dump-One-Shot

```bash
curl -s "https://host/api/users?page=999999&limit=all" | head -c 400
curl -s "https://host/api/users" | wc -c
```

Expected observable: full data payload returned (not 400, not clamped to a max page size), and response size grows with table contents.

### GraphQL Introspection

```bash
curl -s https://host/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
```

Expected observable: JSON containing a `types` array listing schema type names (`Query`, `Mutation`, custom types). An error like "GraphQL introspection is disabled" is the negative case; record the control.

### GraphQL Playground / GraphiQL Exposure

```bash
curl -s https://host/graphql -H 'Accept: text/html' | grep -io 'graphiql\|playground'
```

Expected observable: HTML landing page markers (`GraphiQL`, `Playground`, `ApolloServerPluginLandingPage` output). Absence (JSON error instead of HTML) is the negative case.

### Field-Suggestion Leakage

```bash
curl -s https://host/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{users{usrnme}}"}'
```

Expected observable: `errors[0].message` containing "Did you mean ...?" and real field names.

### gRPC Reflection

```bash
grpcurl -plaintext host:50051 list
```

Expected observable: service list dumped without credentials. Connection refused/TLS required indicates plaintext posture findings separately.

### Method Override Shadowing

```bash
curl -s -X POST "https://host/api/items/1" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data '_method=DELETE' -b "session=$SESSION"
```

Expected observable: item deleted via a POST-only route. Confirm statically which override middlewares are mounted and whether override verbs are allowlisted and CSRF-checked.

### OpenAPI/Swagger Exposure

Probe in order: `GET /swagger-ui.html`, `/swagger/index.html`, `/swagger/v1/swagger.json`, `/api-docs`, `/openapi.json`, `/docs`, `/graphql` (HTML Accept). Expected observable: interactive docs UI HTML or raw spec JSON returned unauthenticated. Cross-check spec contents for internal hosts/endpoints.

### WebSocket Cross-Origin Upgrade

Run the handshake probe from the Payload Cheat Sheet with `Origin: https://evil.example`. Expected observable for absence: `101 Switching Protocols`. Then, if authorized, send an action message unauthenticated; success proves per-message authz is missing.

### API Key in URL Confirmation

Static: locate query-string key acceptance. Dynamic corroboration: call the endpoint with `?api_key=...`, then inspect access-log configuration (nginx `$request_uri` logging is default-on) — keys land wherever logs go.

## Remediation

### Serializer / DTO Field Allowlisting

| Framework | Risk marker | Correct pattern |
|---|---|---|
| Django REST Framework | `fields = "__all__"` | explicit `fields = ("email", "nickname")`; mark computed columns `read_only=True` |
| NestJS | `ValidationPipe()` bare | `new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` |
| Spring MVC | `@ModelAttribute` onto entity | projection DTO per use case; `@InitBinder` `setAllowedFields`; keep Jackson unknown-property failure on (`spring.jackson.deserialization.fail-on-unknown-properties=true`) |
| Rails API | `Model.new(params)` | `params.require(:user).permit(:email, :nickname)` |
| Laravel | `$request->all()` into Eloquent | strict `$fillable` on models; consume FormRequest `validated()` only; never `forceFill` from client input |
| FastAPI | Pydantic posture decision | writes: `model_config = ConfigDict(extra="forbid")` for request models; reads may stay `ignore` |
| ASP.NET Core | `[FromBody] Entity` | separate DTOs + explicit AutoMapper profiles; avoid `SetValues` from unfiltered DTOs |
| Express/Fastify | spreads of `req.body` | destructure named fields, or Fastify route schema with `additionalProperties: false` so ajv strips extras |
| Go | decode into domain structs | dedicated request structs containing only client-writable fields |

```ts
// VULNERABLE
app.useGlobalPipes(new ValidationPipe());
// FIXED
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
```

```python
# VULNERABLE (DRF)
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
# FIXED
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ("email", "nickname")
        read_only_fields = ("is_admin", "role", "user_id")
```

```ruby
# FIXED (Rails)
def user_params
  params.require(:user).permit(:email, :nickname)
end
```

```php
// FIXED (Laravel)
class User extends Model {
    protected $fillable = ['email', 'nickname'];
}
// controller consumes only validated data
$user = User::create($request->validated());
```

```csharp
// FIXED (ASP.NET Core) - bind a DTO, not the entity
public record UpdateUserDto(string Nickname); // no Role, no TenantId
```

Decision guidance for Pydantic `extra`: choose `forbid` when the endpoint is client-writable (turns over-posting into a 422), accept `ignore` where payloads are server-internal; never `allow`.

Gateway-layer option: where an API gateway fronts the services, JSON-schema request validation at the gateway (per-route body schemas that strip/reject unknown properties) is an acceptable compensating layer while code-level field allowlists are rolled out.

### Rate Limiting & Pagination Caps

Apply limiters at the platform layer AND in code (defense in depth). Token-bucket defaults that work widely: auth endpoints 5 requests/min keyed by username+IP; general API 60-120 requests/min per user or API key with short burst allowance; export/search 10 requests/min. Key by user-id/API-key first, IP second.

```js
// Express - express-rate-limit
const { rateLimit } = require("express-rate-limit");
const loginLimiter = rateLimit({ windowMs: 60_000, max: 5, standardHeaders: true });
app.use("/api/login", loginLimiter);
```

```ts
// NestJS - @nestjs/throttler
@Module({ imports: [ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }])] })
// plus @Throttle({ default: { limit: 5, ttl: 60_000 } }) on auth controllers
```

```python
# Flask - slowapi / DRF settings
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.ScopedRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"login": "5/min", "search": "30/min", "export": "10/hour"},
}
```

```ruby
# Rails - Rack::Attack
Rack::Attack.throttle("login/ip", limit: 5, period: 60) { |req| req.ip if req.path == "/api/login" }
```

```csharp
// ASP.NET Core (.NET 7+) built-in rate limiting
builder.Services.AddRateLimiter(o => o.AddFixedWindowLimiter("auth", w => {
    w.Window = TimeSpan.FromMinutes(1); w.PermitLimit = 5;
}));
```

Server-side pagination caps regardless of client hints:

```js
// FIXED - clamp before querying
const limit = Math.min(parseInt(req.query.limit ?? "20", 10), 100);
const page  = Math.max(parseInt(req.query.page ?? "1", 10), 1);
```

Add captcha/proof-of-work or equivalent friction to signup, voting, and redemption flows; enforce per-API-key quotas at the gateway or in middleware backed by a plan-tier table.

### GraphQL Hardening

- Apollo Server: `introspection: false` in production; omit landing-page plugin (`ApolloServerPluginLandingPageGraphQLPlayground`) or add `ApolloServerPluginUsageReporting`-style prod gating; disable field suggestions via `formatError`/masked errors.
- Depth/complexity: `graphql-depth-limit` inside `validationRules: [depthLimit(10)]`; cost analysis (`graphql-cost-analysis`) or Apollo `estimateComplexity`; cap aliases where the library supports it.
- graphql-yoga: depth-limit plugin via `plugins: [useDepthLimit({ maxDepth: 10 })]`, `maskedErrors` enabled by default — keep it on.
- Strawberry: `strawberry.extensions.QueryDepthLimiter(max_depth=10)` in the schema extensions list.
- Graphene: validation rules/middleware adding depth or cost limits before execution.
- Persisted queries: run AutomaticPersistedQueries against an operation registry allowlist; reject unregistered hashes from public clients.
- Batching: if operation arrays are accepted, bound array length and total complexity, or disable batching for public clients.
- Resolver authz: enforce object-level checks in resolvers/data-loaders (cross-ref AUTHZ); never rely on "the schema is internal".

```ts
// VULNERABLE
const server = new ApolloServer({ typeDefs, resolvers });
// FIXED
const server = new ApolloServer({
  typeDefs, resolvers,
  introspection: false,
  validationRules: [depthLimit(10)],
});
```

### gRPC Hardening

- Disable reflection in production builds (gate behind env/build tags); reflection hands attackers your full descriptor set.
- Terminate TLS at the service or at the load balancer; never expose plaintext h2c ports publicly. Prefer TLS credentials on the server itself:

```go
// VULNERABLE
lis, _ := net.Listen("tcp", ":50051")
s := grpc.NewServer() // plaintext
// FIXED
creds, _ := credentials.NewServerTLSFromFile("cert.pem", "key.pem")
s := grpc.NewServer(grpc.Creds(creds))
```

- Enforce per-RPC auth with interceptors covering every registered service; keep exemptions explicit and narrow (health checks only):

```go
// FIXED - unary interceptor validating metadata
func AuthInterceptor(ctx context.Context, req interface{},
    info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    md, _ := metadata.FromIncomingContext(ctx)
    if len(md.Get("authorization")) == 0 { return nil, status.Error(codes.Unauthenticated, "missing token") }
    return handler(ctx, req)
}
grpc.NewServer(grpc.UnaryInterceptor(AuthInterceptor), grpc.ChainStreamInterceptor(StreamAuth))
```

Python: build with `interceptors=[...]` (e.g. grpc-interceptor). Java: `ServerBuilder.addService(...)` paired with `ServerInterceptors.intercept(service, authInterceptor)` for every service.

- Set sane message ceilings (`MaxRecvMsgSize`, Java `maxInboundMessageSize`), validate enums, avoid `google.protobuf.Any` for security-relevant dispatch, and strip unknown fields before persistence paths that echo stored messages back.

### OpenAPI / Docs Exposure Policy

Serve API docs behind authentication or restrict to internal networks; split external and internal specs so internal endpoints never appear in the public file. Framework switches: `springdoc.api-docs.enabled=false` (or gated profile) in prod, DRF drf-spectacular/drf-yasg views wrapped in `IsAdminUser` permission classes, Swashbuckle `UseSwaggerUI()` inside `if (app.Environment.IsDevelopment())`, swagger-ui-express mounted after auth middleware. Strip `X-Powered-By`/framework banners (`app.disable("x-powered-by")`, `Program.cs` header removal), and route Symfony profiler away from production.

### WebSocket / SSE Hardening

Validate Origin against an allowlist during upgrade; authenticate per message for actions; authorize topic/room joins per user; re-check authorization on every event delivery.

```js
// VULNERABLE (ws)
const wss = new WebSocket.Server({ port: 8080 }); // no origin check
// FIXED
const wss = new WebSocket.Server({
  port: 8080,
  verifyClient: (info) => allowlist.includes(new URL(info.origin).host),
});
wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    const msg = JSON.parse(raw);
    if (!canAct(ws.user, msg.action, msg.targetId)) return; // per-message authz
  });
});
```

```js
// socket.io - origin allowlist + handshake token
new Server({ cors: { origin: ["https://app.example.com"], credentials: true } })
  .use((socket, next) => next(jwt.verify(socket.handshake.auth.token) ? undefined : new Error("unauthorized")));
```

SignalR: `AllowedOrigins("https://app.example.com")`. Django Channels: `OriginValidator` around the ASGI application plus scope-level permission checks per consumer. SSE: authenticate the stream request, and validate that `Last-Event-ID` replay stays within the requester's own tenant.

### API Key Management

Transport keys in headers only (`X-API-Key`, `Authorization: Bearer`); reject query-string key parameters. Scope every key to a permission set enforced at request time; issue separate keys per environment and per integration; implement revocation (status flag checked per request) and rotation endpoints; store hashes of keys, never plaintext. Mobile/SDK builds ship only public client identifiers — anything secret-capable belongs behind a backend-for-frontend.

## Verification & Validation

### GIVEN/WHEN/THEN Acceptance Scenarios

- GIVEN a serializer allowlist, WHEN a client POSTs `{"email":"a@b.c","password":"x","is_admin":true}`, THEN the server responds 400/422 naming the rejected property (forbid mode) or persists the object without the extra field (strip mode); a follow-up read shows no `is_admin`.
- GIVEN legitimate clients, WHEN they send exactly the documented fields, THEN requests succeed identically to before the fix (negative test: no over-blocking).
- GIVEN a rate limiter, WHEN 20 rapid login attempts arrive, THEN attempt ~6 onward receive 429 while a normal user's spaced traffic never sees 429.
- GIVEN pagination caps, WHEN `?limit=1000000` arrives, THEN the response contains at most the clamped page size and reports the cap.
- GIVEN introspection disabled in prod, WHEN `{"query":"{__schema{types{name}}}"}` is sent, THEN the endpoint returns an error and leaks zero type names; WHEN a registered client sends a persisted query hash, THEN execution still succeeds.
- GIVEN depth limits configured, WHEN a nested selection beyond the limit is executed, THEN a validation error names the depth rule before any resolver runs.
- GIVEN gRPC auth interceptor installed, WHEN an RPC is called with no authorization metadata, THEN the call fails `Unauthenticated` for every service including streams.
- GIVEN docs gating, WHEN an unauthenticated client fetches `/openapi.json` or `/swagger-ui.html`, THEN it receives 401/403/redirect.
- GIVEN WebSocket origin validation, WHEN the handshake presents `Origin: https://evil.example`, THEN the server rejects the upgrade (no 101).
- GIVEN per-message authz, WHEN a connected socket issues an action on another user's resource ID, THEN the action is refused.

### Regression Contract Test Pseudocode

```python
# CI contract test: unknown fields must never reach persistence
def test_register_rejects_unknown_fields(api_client):
    payload = {"email": "t@example.com", "password": "Str0ng!passphrase", "is_admin": True}
    r = api_client.post("/api/register", json=payload)
    assert r.status_code in (400, 422) or "is_admin" not in r.json()
    login = api_client.post("/api/login", json={"email": "t@example.com", "password": "Str0ng!passphrase"})
    me = api_client.get("/api/me", headers=auth(login))
    assert me.json().get("is_admin") is not True

def test_login_throttled():
    codes = [post_login(wrong_password=True).status_code for _ in range(20)]
    assert 429 in codes

def test_list_endpoint_capped():
    body = get_json("/api/users?limit=1000000")
    assert len(body["items"]) <= 100
```

### Manual Checklist

- Every route group has auth AND throttle middleware applied (diff middleware lists across groups).
- Every write endpoint binds a DTO/serializer with an explicit field list.
- Every list endpoint clamps page size server-side.
- GraphQL bootstrap sets introspection off, landing page off, depth/complexity limits on, suggestions masked.
- gRPC servers register reflection nowhere in prod paths, use TLS or sit behind TLS termination, and chain auth interceptors on every service.
- No state-changing GET routes; override middlewares restricted and CSRF-safe.
- Docs endpoints gated; spec files absent from static assets/public buckets.
- Keys accepted via headers only; scope checks present at request time; revocation path exists.
- WebSocket upgrades validate Origin; message handlers authorize actions; room joins check ACLs.

### Greps To Rerun Post-Fix

```bash
rg -n 'fields\s*=\s*["'"'"']__all__["'"'"']' --type py
rg -n '\$request->all\(\)' 
rg -n 'ValidationPipe\(\)'
rg -n 'introspection\s*:\s*true|GRAPHQL_INTROSPECTION'
rg -n 'reflection\.Register|enable_server_reflection|ProtoReflectionService'
rg -n 'insecure\.NewCredentials|WithTransportCredentials\(insecure|h2c'
rg -n '_method|X-HTTP-Method-Override'
rg -n '[\?&]api[_-]?key='
```

Expected post-fix state: each query returns only reviewed-and-accepted occurrences (dev-gated, allowlisted, or documented exceptions).

## Severity Assessment

### Rubric

| Finding | Baseline severity | CVSS v3.1 vector | CWE |
|---|---|---|---|
| Mass assignment writing `is_admin`/`role` (privilege escalation) | Critical | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | CWE-915 |
| Mass assignment on non-security fields (`price`, `user_id`) | High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L` | CWE-915 |
| Throttling absence alone (no lockout bypass demonstrated) | Low-Medium, context-driven | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L` | CWE-770, CWE-799 |
| Pagination absence / dump-one-shot on sensitive table | Medium-High by data class | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | CWE-770 |
| Introspection + playground + docs exposure | Low-Medium information disclosure | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | CWE-200 |
| Field-suggestion leakage / stack-trace error envelopes | Low-Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | CWE-200 |
| CORS wildcard with credentials on API | High when session-bearing | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` | CWE-942 |
| API key transported in URL | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | CWE-798 |
| Shared embedded SDK key granting account-wide access | High | assess reachability from shipped binary | CWE-798 |
| WebSocket hijack (no origin check, no per-message auth) | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L` | CWE-346, CWE-862 |
| gRPC plaintext + missing per-RPC auth on business RPCs | High if externally reachable | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | CWE-306 |
| Deprecated API version live without current fixes | Medium inventory risk | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` | CWE-200 |

### Modifiers

Raise severity one band when the vulnerable surface is internet-reachable AND unauthenticated. Lower one band when exploitation requires an internal network position (gRPC ports), an authenticated low-privilege context that already grants equivalent powers, or when compensating platform controls (gateway limiter, WAF) demonstrably cover the gap — cite the control file in the finding either way. Rate-limit findings stay Low-Medium unless chained with credential stuffing, enumeration, or financial flows, which push them to High.

## Common False Positives

- DRF `fields = "__all__"` on admin-only or read-only viewsets: verify the route's permission classes before flagging; internal-only serializers with `IsAdminUser` are acceptable.
- NestJS DTO without `whitelist` where the handler destructures named fields before persistence: binding is permissive but the sink is safe; trace the sink, not just the pipe.
- Throttling handled at the gateway: nginx `limit_req`, Envoy rate-limit filters, Cloudflare rules satisfy the control; check infra configs and note the compensating control instead of reporting absence.
- Introspection intentionally public on a genuinely public-read API: confirm no mutation surface or sensitive types exist before flagging; report as informational.
- Go/JSON strictness: Go decoders silently DROP unknown JSON keys, so decoding into a struct with only safe exported fields is not mass assignment even when the whole body is bound. Flag only if the struct exports sensitive fields (`IsAdmin`, `Role`).
- Pydantic default `extra=ignore`: unknown fields are dropped, so FastAPI endpoints are rarely over-postable unless `extra="allow"` is set or raw dicts flow to sinks.
- `_method`/override middleware in Rails/Laravel: built-in implementations restrict overrides to safe verbs and integrate CSRF protection; flag custom or unrestricted override handling, not the framework feature itself.
- Wildcard CORS without credentials: browsers refuse wildcard+credentials combos; reflected-origin WITH credentials is the real defect (cross-ref CONFIG for the matrix).
- Pagination present at the database layer via cursor defaults or ORM `LIMIT` defaults even when query params are absent: read the actual query construction.
- gRPC reflection enabled behind build tags/env gates that provably exclude production builds: cite the gate as evidence of control.
- Version sprawl where `/v1` routes proxy through the identical handler set and current middleware: shared handlers mean no patch gap; report only divergent code paths.
- Error stack traces visible only under an explicit debug flag that defaults off in prod config: verify the deployed configuration value.

## References

### OWASP API Security Top 10 (2023) Mapping

Project home: https://owasp.org/www-project-api-security/

| OWASP item | This module's coverage |
|---|---|
| API1:2023 Broken Object Level Authorization | GraphQL resolver object-level gaps; WebSocket topics/actions; IDOR-enabled sinks (primary coverage in AUTHZ module) |
| API2:2023 Broken Authentication | Platform throttling of auth endpoints; key transport/scoping (lockout specifics in AUTHN module) |
| API3:2023 Broken Object Property Level Authorization | Mass assignment / over-posting class end-to-end |
| API4:2023 Unrestricted Resource Consumption | Rate limiting, pagination caps, depth/complexity limits, message-size ceilings |
| API5:2023 Broken Function Level Authorization | Route-group middleware parity; hidden-endpoint exposure via docs/introspection |
| API6:2023 Unrestricted Access to Sensitive Business Flows | Anti-automation friction on signup/redemption/voting flows |
| API7:2023 Server Side Request Forgery | Out of scope here — covered by DESER/SSRF module |
| API8:2023 Security Misconfiguration | Introspection/playground/docs/debug headers/CORS/content-type confusion/gRPC reflection |
| API9:2023 Improper Inventory Management | Version sprawl, stale specs, deprecated versions live |
| API10:2023 Unsafe Consumption of APIs | Partially covered (key scoping toward third parties); full coverage deferred |

### CWE Entries

- CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes: https://cwe.mitre.org/data/definitions/915.html
- CWE-770 Allocation of Resources Without Limits or Throttling: https://cwe.mitre.org/data/definitions/770.html
- CWE-799 Improper Control of Interaction Frequency: https://cwe.mitre.org/data/definitions/799.html
- CWE-306 Missing Authentication for Critical Function: https://cwe.mitre.org/data/definitions/306.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-200 Exposure of Sensitive Information to an Unauthorized Actor: https://cwe.mitre.org/data/definitions/200.html
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html
- CWE-798 Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
- CWE-346 Origin Validation Error: https://cwe.mitre.org/data/definitions/346.html
- CWE-942 Permissive Cross-domain Policy with Untrusted Domains: https://cwe.mitre.org/data/definitions/942.html

### Further Reading

- OWASP Cheat Sheet Series — GraphQL: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP Cheat Sheet Series — REST Security: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Cheat Sheet Series — Denial of Service: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- OWASP Cheat Sheet Series — HTML5 (WebSocket origin guidance): https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- RFC 6455 Section 10 (WebSocket origin considerations): https://datatracker.ietf.org/doc/html/rfc6455#section-10
- GraphQL specification security notes: https://graphql.org/learn/security/
- socket.io CORS handling: https://socket.io/docs/v4/handling-cors/
- gRPC authentication guide: https://grpc.io/docs/guides/auth/

