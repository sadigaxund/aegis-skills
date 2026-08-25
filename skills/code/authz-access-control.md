---
name: authz-access-control-checks
description: Detects broken function-level and object-level authorization (BFLA/BOLA), vertical and horizontal privilege escalation, tenant-isolation failures, path/header bypasses, and unsafe delegation across mainstream web frameworks and APIs.
category_slug: AUTHZ
cwe: [CWE-284, CWE-285, CWE-639, CWE-862, CWE-863, CWE-1220]
owasp: A01:2021 – Broken Access Control
---

## Scope & Objectives

Scan for authorization failures: code decides *wrongly* who may call an action (BFLA, vertical escalation) and which object instances an action may touch (BOLA/IDOR, horizontal escalation).

In scope:

- Missing or incorrect role/permission checks on routes, handlers, resolvers, controllers.
- Object fetches keyed by request-supplied IDs without ownership/tenant predicates.
- Multi-tenant isolation gaps (tenant context from input, shared caches/queues/indexes).
- Authorization logic bugs: deny-by-absence, OR-condition typos, verb tampering.
- Path normalization and proxy-header bypasses (`X-Original-URL`, `X-Forwarded-For` trust).
- Impersonation/API-key/service-trust features without scoping or audit.

Out of scope (other modules): authentication strength, session fixation, injection, SSRF, crypto. Only audit *post-authentication decision logic* here; flag unauthenticated reachability of privileged actions as BFLA.

## Mental Model

Evaluate every route along two independent axes; a route is safe only if BOTH pass.

| Axis | Question | Failure | Primary CWE |
|---|---|---|---|
| Function (action) | May this subject invoke this endpoint at all? | BFLA / vertical escalation | CWE-862, CWE-863 |
| Object (instance) | Given yes above, may it touch THIS row/file/tenant? | BOLA / IDOR / cross-tenant leak | CWE-639 |
| Attribute | May it read/write THESE fields on the object? | Excessive data exposure, mass assignment | CWE-285 |

Decision procedure per route:

1. Identify the **subject source**: session, verified JWT sub claim, API key, mTLS identity. Anything else (query param, header like `user_id`, client-stored role) is a red flag by itself.
2. Identify required **roles/actions** from business naming (`admin`, `/users`, `/internal`, DELETE).
3. Locate where the **object is fetched** and whether the query embeds the subject (`WHERE id = ? AND tenant_id = ?`).
4. Locate the **decision point** (middleware/decorator/annotation/policy) and confirm it runs BEFORE any state change or data return.
5. Default answer when no explicit allow rule exists: **deny**. Absence of a check = finding, not "probably fine."

Two-account intuition: every endpoint must behave identically whether the caller owns the object or not — except for the owner, who alone gets data.

## What To Check

### Function-Level Authorization (BFLA)

- Enumerate every mutating route (POST/PUT/PATCH/DELETE) and every `/admin`, `/internal`, `/manage` subtree; verify each carries a guard that reads the server-side identity, not a client claim verbatim.
- Flag "security by obscurity": hidden UI buttons with no server check; SPA routes rendered only for admins while backing endpoints are open; endpoints whose only defense is an unguessable path segment.
- Check HTTP-method asymmetry: a controller guarded for GET but exposing DELETE/PATCH on the same path via a separate handler or catch-all (`app.all('/admin/x', ...)` without guard).
- Compare API versions: v1 module annotated/guarded, duplicated v2 controller forgotten. Diff guard counts per version directory.
- Test registration/update payloads for role mass assignment (`"role":"admin"`, `"isAdmin":true`) accepted into the user record.
- Inspect debug/internal surfaces: Spring Actuator, Django admin + DEBUG views, Flask debugger, Go `pprof`, ASP.NET detailed errors, GraphQL introspection + mutations in production.

### Object-Level Authorization (BOLA/IDOR)

- Trace each request parameter named `id|uuid|guid|uid|email|slug|ref` into the first DB/document lookup; require the predicate `owner_id == subject.id` or `tenant_id == subject.tenant_id` IN THE QUERY, not after it.
- Flag collection/list endpoints returning `.all()` / `find()` / `Model.objects.all()` serialized wholesale (mass listing leaks other tenants' rows).
- Nested resources: for `/org/:orgId/doc/:docId`, verify BOTH `doc.orgId == orgId` AND caller membership in `orgId`; membership check on the parent alone is insufficient.
- Export/report/download/CSV/PDF/streaming endpoints: these routinely skip guards because they bypass normal serializers. Grep for `export|download|report|dump|backup|csv|xlsx`.
- GraphQL: per-resolver object checks (not just a top-level auth directive), especially on nested fields (`invoice.customer.address`) and DataLoader/batch loaders that fetch by ID arrays.
- Sequential IDs (`AutoField`, `serial`, `IDENTITY(1,1)`, incrementing numeric JSON ids): note as exploitability amplifier; UUIDs are mitigation only, never a substitute for predicates.
- Property-level granularity: field-level BOLA — record access correct but sensitive columns (`salary`, `role`, SSN-class fields) serialized to callers lacking need-to-know; diff serializer output per caller role.
- Mass assignment crossover: client-writable privileged fields (`"role":"admin"`) are property-level authorization failure too; cross-ref the API module's mass-assignment class when spotted here.

### Vertical & Horizontal Escalation

- Roles trusted from client storage: JWT claims (`role`, `isAdmin`, `permissions`) accepted without re-deriving from the authoritative store on sensitive calls; `localStorage.getItem('role')` gating UI-only.
- Forced browsing to admin panels: static admin bundles served publicly (`express.static('admin')`), framework admin at default paths with weak/no auth.
- Version-skew escalation: legacy `/api/v1/admin/*` kept alive after v2 hardening; old microservice copies of a moved endpoint still deployed.
- Cross-tenant context: `tenant_id` taken from request body/query/subdomain instead of the authenticated principal's record; `Host`-based tenancy spoofable via direct IP access or Host header override.
- Shared infrastructure keys: cache keys lacking tenant prefix (`cache.get("invoice:"+id)`), global search indexes, queue messages consumed without tenant re-check, temp files named by raw ID in shared dirs.

### Logic, Header & Path Bypasses

- Allow vs deny style: find checks written as blocklists (`if (role === 'banned') return`) — invert them mentally; new roles inherit access silently.
- Boolean typos: `role === 'admin' || userId === id` granting admins everywhere is correct, but `role !== 'admin' || userId !== id` inside negations, or `&&`/`||` swaps, produce accidental allows. Flag any compound condition mixing role equality and identity equality.
- Path normalization: routing decisions made on raw URLs before decode → `%2f`, `//`, `/./`, trailing dots, `;jsessionid`, double encoding (`%252f`) splitting guard path from handler path.
- Verb tampering: guard attached per-method; try `HEAD/OPTIONS/TRACE` or method overrides (`X-HTTP-Method-Override: DELETE`, `_method=DELETE` form param).
- Proxy headers honored by app code: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`, `X-Forwarded-Proto` used in routing/access decisions; `X-Forwarded-For` parsed for IP allowlists (`req.headers['x-forwarded-for'].split(',')[0]`) — spoofable unless app sits behind a trusted proxy configured to strip/set it.
- Framework-specific: ASP.NET `[AllowAnonymous]` on a controller overriding global fallback; Laravel `$this->middleware()` missing in constructor; Rails `skip_before_action :authenticate_user!`.

### Delegation & Impersonation

- Support/admin impersonation ("login as customer"): verify scope limits (time-boxed, reason captured), immutable audit log entry with actor+target+reason, termination on password change, and no token minting that drops the original actor identity.
- API keys / PATs inheriting the full interactive-user permission set including admin roles; check key scopes exist and are enforced server-side.
- Service-to-service: internal endpoints trusting a forwarded username/email header set by "some gateway" (`X-User-Email`) with no signature verification; mTLS absent on internal hops assumed.
- OAuth token exchange: `scope` downgrades ignored; refresh tokens carrying original broad scopes after admin revocation.

## Where To Look

| Stack | Route table | Guard markers (present = good) | Files/dirs |
|---|---|---|---|
| Express/Fastify/NestJS | `app.use/router.stack`, Nest `@Controller` metadata, Fastify `printRoutes` | `requireAuth`, `passport.authenticate`, `addHook('preHandler')`, `@UseGuards(...)`, `@Roles(...)` | `routes/`, `controllers/`, `*.controller.ts`, `main.ts` |
| Django/DRF | `urls.py`, `router.register`, django-extensions `show_urls` | `LoginRequiredMixin`, `PermissionRequiredMixin`, `permission_classes`, DRF `get_queryset` filter | `*/urls.py`, `views.py`, `viewsets.py`, `serializers.py` |
| Flask/FastAPI | decorators `@app.route/@get/@post`, OpenAPI spec | `before_request`, `@login_required`, `Depends(current_user|require_roles)`, router-level `dependencies=[...]` | `app.py`, `api/*.py`, `deps.py` |
| Spring (Java/Kotlin) | `@RequestMapping` tree, Actuator `/mappings` (guarded!) | `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `SecurityFilterChain` matchers, `@EnableMethodSecurity` | `**/controller/**`, `SecurityConfig.*`, `application.yml` |
| ASP.NET Core | Controllers + minimal-API `Map*` chain | `[Authorize]`, `[Authorize(Policy=...)]`, `.RequireAuthorization()`, `FallbackPolicy`, `[AllowAnonymous]` (audit each) | `Controllers/`, `Program.cs`, `Startup.cs` |
| Laravel/Symfony | `php artisan route:list`, `bin/console debug:router` | `auth:` middleware, `can:` middleware, policies, `Gate::authorize`, Symfony voters + `access_control` YAML | `routes/web.php`, `routes/api.php`, `app/Policies`, `config/packages/security.yaml` |
| Rails | `rails routes` | `before_action :authenticate_user!`, Pundit `authorize @record` / `after_action :verify_authorized`, CanCanCan `load_and_authorize_resource` | `config/routes.rb`, `app/controllers/**`, `app/policies/**` |
| Go (net/http/chi/gin) | mux registrations, `chi walk` | middleware wrappers `RequireAuth/RequireRole`, `gin.Use(...)`, group-scoped `r.Group(func(r){ r.Use(guard)})` | `cmd/*/main.go`, `internal/http/**`, `middleware/` |

Also inspect: `docker-compose.yml`/k8s manifests for internal-only ports (context, not proof), OpenAPI/Swagger specs vs implemented routes (spec drift = undocumented live routes), seeders/fixtures revealing role names, frontend JS bundles for hidden admin routes (`/static/js/*.js` contains `"/admin"` strings).

## Patterns & Signatures

Route inventory (run first; diff counts against guard markers):

```bash
rg -n "@(Get|Post|Put|Patch|Delete|Request)Mapping\(" --type java --type kt
rg -n "@app\.(route|get|post|put|patch|delete)|@(get|post|put|delete)\(" --type py
rg -n "\.(get|post|put|patch|delete|all)\(\s*['\"][^'\"]+" -t ts -t js
rg -n "Route::(get|post|put|patch|delete|any|resource|apiResource)" --type php
rg -n "(map|Map)(Get|Post|Put|Delete|Patch)\(\"" --type cs
rg -n "HandleFunc|\.GET\(|\.POST\(|\.DELETE\(|\.PUT\(" --type go
```

Guard-presence markers:

```regex
@(PreAuthorize|Secured|RolesAllowed|PostAuthorize)\(
```

```regex
(LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin)
```

```regex
(@UseGuards|@Roles\(|SetMetadata\(['"](roles|permissions))
```

Missing-guard smell (Express: handler as 2nd arg, no middleware between):

```regex
\.(get|post|put|patch|delete)\(\s*['"][^'"]*['"]\s*,\s*(async\s*)?\(?[A-Za-z_$]
```

Object-fetch-without-subject heuristics:

```regex
objects\.(get|filter)\((pk|id)=
```

```regex
findById\((req|params|pathVariable)[^)]*\)
```

```regex
Model\.objects\.all\(\)
```

Client-trusted identity signals:

```regex
(decoded|payload|claims|token)\.(role|isAdmin|is_admin|admin|permissions)
```

```regex
localStorage\.(getItem\(['"]?(role|is_admin|isAdmin|user)['"]?\))
```

```regex
(req\.body|request\.body|payload)\.(role|isAdmin|is_admin|account_type)
```

Header/path bypass primitives:

```regex
(?i)x-(original-url|rewrite-url|forwarded-for|forwarded-host|http-method-override)
```

```regex
headers\[['"](x-forwarded-for|x-real-ip)['"]\]
```

```regex
(_method|X-HTTP-Method-Override|method_override)
```

Impersonation & delegation:

```regex
(impersonat(e|ion)|acting_as|act_as|as_user|become_user|sudo_mode)
```

```regex
(api[_-]?key|personal_access_token).{0,40}(scopes?|abilities?)
```

Debug/internal exposure:

```regex
(/debug/pprof|/actuator|/_profiler|/__profiler|/telescope|/horizon|DEBUG\s*=\s*True)
```

Tenant-context-from-input:

```regex
(tenant_id|org_id|organization_id)['"]?\s*[:=]\s*(req\.(query|params|body)|request\.(GET|data|json))
```

## Taint Tracing Guidance

Sources (untrusted until proven otherwise): all route params, query strings, bodies, JWT payload claims other than the verified `sub`, headers (`X-*`, even `Authorization` API keys), subdomain/Host, message-queue payloads.

Sinks (authorization-relevant): ORM/document queries (`findOne/findById/get/filter/Query.first`), raw SQL, file reads/writes/downloads, cache get/put, queue publish/consume, admin RPC calls, email/export generation containing other users' data.

Procedure:

1. For each sink fetching a singleton, list its arguments. **Flag any lookup helper whose signature lacks a user/tenant/principal parameter** — e.g., `getInvoice(id)` vs `getInvoice(id, actor)`; the omission predicts BOLA upstream of any later check.
2. Walk backward from sink to source: if the predicate chain from param → WHERE clause does not include the authenticated principal attribute, mark BOLA candidate.
3. Track role/permission values: if the value used in the decision originates from a source (JWT body, DB column writable via profile update, Redis session field set from login-time client data) rather than the canonical user store, mark escalation candidate.
4. For caches/queues, trace key construction and consumer-side filtering; a tenant tag on write but no filter on read is still vulnerable.
5. Sanitizers do NOT exist for authz — a validated integer ID is still a valid other-tenant ID. Never treat validation as authorization.

Framework shortcuts: DRF `get_queryset()` overrides (absence = base manager queryset = leak); Rails `ApplicationRecord` default scopes (none by default); SQLAlchemy `session.query(Model).get(id)` ignores any Python-level tenant notion unless filters added; JPA `EntityManager.find(Cls, id)` never tenant-filters without Hibernate `@TenantId`/`@Filter`.

## Exploitation & Reproduction

### Two-Account BOLA Test (canonical sequence)

1. Register victim and attacker accounts:
   ```bash
   curl -s -X POST https://target/api/register -H 'Content-Type: application/json' \
     -d '{"email":"victim@example.com","password":"V1ctimPass!"}'
   curl -s -X POST https://target/api/register -H 'Content-Type: application/json' \
     -d '{"email":"attacker@example.com","password":"Att4ckerPass!"}'
   ```
2. Authenticate both; store tokens:
   ```bash
   VICTIM=$(curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
     -d '{"email":"victim@example.com","password":"V1ctimPass!"}' | jq -r .token)
   ATTACKER=$(curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
     -d '{"email":"attacker@example.com","password":"Att4ckerPass!"}' | jq -r .token)
   ```
3. Victim creates an object; capture its ID:
   ```bash
   curl -s -X POST https://target/api/invoices -H "Authorization: Bearer $VICTIM" \
     -H 'Content-Type: application/json' -d '{"amount":100,"memo":"secret-payroll"}'
   # -> {"id":1042,...}   (sequential => enumerate 1030..1050 next)
   ```
4. Attacker requests the victim's object:
   ```bash
   curl -i https://target/api/invoices/1042 -H "Authorization: Bearer $ATTACKER"
   ```
5. Interpret (this triage matters):
   | Result | Meaning |
   |---|---|
   | `200` + victim's fields (`"secret-payroll"`) | Confirmed BOLA (CWE-639) |
   | `200` + empty/redacted body but different timing than random IDs | Existence oracle; partial protection |
   | `403` | Function reachable, object denied — check OTHER verbs (`curl -i -X PUT/PATCH/DELETE`) and nested paths before clearing |
   | `404` for foreign IDs, `200` for own | Correct anti-enumeration masking — verify owner still receives full record |
6. Repeat for write paths (swap IDs on PATCH/DELETE), collections (`GET /api/invoices` without `?mine=1`), exports (`GET /api/invoices/export.csv`), and nested forms (`GET /org/A/invoices/1042` where 1042 belongs to org B).
7. Static-only confirmation (no test accounts available): locate the handler for the route, show the fetch statement has no ownership predicate, and show no policy/middleware wraps the route — cite file:line for both halves.

### BFLA Admin-Endpoint Test

1. As ATTACKER (normal user), call an administrative mutation:
   ```bash
   curl -i -X POST https://target/api/users -H "Authorization: Bearer $ATTACKER" \
     -H 'Content-Type: application/json' -d '{"email":"pwn@example.com","password":"Pwn3dPass!","role":"admin"}'
   ```
2. Outcomes: `201/200` = confirmed BFLA (+ possible privilege self-grant); `403` = guarded; `401` = route also misses authentication (worse).
3. Role-injection variant at registration/update:
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://target/api/register \
     -H 'Content-Type: application/json' \
     -d '{"email":"esc@example.com","password":"Esc4late!","role":"admin","isAdmin":true}'
   # then re-login as esc@example.com and retry step 1
   ```
4. Method-swap variant against GET-guarded routes: `curl -i -X DELETE https://target/admin/users/42 -H "Authorization: Bearer $ATTACKER"`.

### Path/Header/Verb Bypass Tests

```bash
# Path confusion (use --path-as-is so curl does not normalize)
for p in '/admin/users' '/admin//users' '/admin/./users' '/admin%2fusers' '/adm%69n/users' \
         '/admin;/users' '/admin/users/' '/ADMIN/users' '/api/v1/admin/stats'; do
  curl -s -o /dev/null -w "%{http_code} $p\n" --path-as-is "https://target$p" -H "Authorization: Bearer $ATTACKER"
done
# Double-encoding round trip: %252f decodes once to %2f, again to '/'
# Proxy-header injection
curl -s -o /dev/null -w '%{http_code}\n' 'https://target/public/health' -H 'X-Original-URL: /admin/users'
curl -s -o /dev/null -w '%{http_code}\n' 'https://target/admin/stats'  -H 'X-Forwarded-For: 10.0.0.1'
# Verb tampering incl. overrides
for m in HEAD OPTIONS TRACE PATCH PUT; do curl -s -o /dev/null -w "%{http_code} $m\n" -X $m https://target/api/invoices/1042 -H "Authorization: Bearer $ATTACKER"; done
curl -s -X POST https://target/api/invoices/1042 -H "Authorization: Bearer $ATTACKER" \
  -H 'X-HTTP-Method-Override: DELETE' -d '_method=DELETE'
```

Expected observable outcome: any status other than uniform `403/404` across all variants (and identical behavior with a valid-but-unprivileged token) demonstrates a guard-bypass primitive; record which exact byte-sequence bypassed it.

## Remediation

### Centralize the Policy Layer

Move every decision into ONE choke point per stack; handlers may refine but never be the sole guard:

| Stack | Choke point |
|---|---|
| Express/Fastify | Router-level middleware registered before branch handlers (`guardRouter.use(requireAuth, attachPolicy)`) |
| NestJS | Global `APP_GUARD` JwtAuthGuard + RolesGuard; per-handler `@Roles()` metadata |
| FastAPI | `dependencies=[Depends(require_auth)]` on the router; policy dependency per operation |
| Django | Mixins on every CBV + DRF `DEFAULT_PERMISSION_CLASSES` + custom `get_queryset` base class |
| Flask | `before_request` blueprint hook + decorator on every view |
| Spring | `SecurityFilterChain` path rules + `@EnableMethodSecurity` + `@PreAuthorize` default-deny meta-annotation |
| ASP.NET Core | `FallbackPolicy = RequireAuthenticatedUser` globally; `[Authorize(Policy)]` per area |
| Laravel | Route middleware groups (`auth:sanctum`) + Policies auto-discovery; `$gate->deny` default |
| Symfony | `access_control` YAML + voters invoked via `isGranted` in a base controller/subscriber |
| Rails | `before_action :authenticate_user!` in `ApplicationController` + Pundit `verify_authorized` after_action raising on skipped checks |
| Go | Single `func Authz(next http.Handler) http.Handler` wrapper composed onto every non-public route group |

### Before / After Recipes

Express:

```javascript
// VULNERABLE
router.get('/invoices/:id', async (req, res) => {
  const inv = await Invoice.findByPk(req.params.id);
  res.json(inv);
});

// FIXED
const { requireAuth } = require('./middleware/auth');
const { authorize } = require('./policy');            // centralized decision engine
const { scopeToTenant } = require('./middleware/tenant');

router.get('/invoices/:id', requireAuth, authorize('invoice:read'),
  scopeToTenant, async (req, res) => {
    const inv = await Invoice.findOne({               // predicate lives IN the query
      where: { id: req.params.id, tenantId: req.user.tenantId }
    });
    if (!inv) return res.sendStatus(404);             // uniform mask, no existence oracle
    res.json(inv);
  });
```

Django/DRF:

```python
# VULNERABLE
class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer

# FIXED
class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated, TenantMemberRequired]

    def get_queryset(self):                            # object axis enforced centrally
        return Invoice.objects.filter(
            tenant_id=self.request.user.tenant_id,
        )
```

```python
# FIXED (classic Django CBV equivalent)
class InvoiceDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    model = Invoice
    permission_required = 'invoices.view_invoice'

    def get_queryset(self):
        return Invoice.objects.filter(tenant=self.request.user.tenant)
```

Spring:

```java
// VULNERABLE
@GetMapping("/api/v2/invoices/{id}")
public InvoiceDto get(@PathVariable long id) {
    return invoices.findById(id).map(mapper::toDto)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
}

// FIXED
@PreAuthorize("hasAuthority('invoice:read')")
@GetMapping("/api/v2/invoices/{id}")
public InvoiceDto get(@PathVariable long id, @AuthenticationPrincipal AppUser user) {
    return invoices.findByIdAndTenantId(id, user.getTenantId())
        .map(mapper::toDto)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
}
```

Laravel:

```php
// VULNERABLE
Route::get('/invoices/{invoice}', [InvoiceController::class, 'show']);

// FIXED
Route::middleware(['auth:sanctum'])
    ->get('/invoices/{invoice}', [InvoiceController::class, 'show'])
    ->middleware('can:view,invoice');                 // policy = single decision point
```

```php
// app/Policies/InvoicePolicy.php  (registered automatically by name convention)
class InvoicePolicy
{
    public function view(User $user, Invoice $invoice): bool
    {
        return $user->tenant_id === $invoice->tenant_id;
    }
}
```

Rails (Pundit):

```ruby
# VULNERABLE
def show
  @invoice = Invoice.find(params[:id])
end

# FIXED
def show
  @invoice = Invoice.find(params[:id])
  authorize @invoice                                   # raises unless policy permits
end
# with_scope in policy keeps index endpoints tenant-safe:
class ApplicationPolicy
  class Scope
    def resolve
      scope.where(tenant_id: user.tenant_id)
    end
  end
end
```

### Deny-by-Default Routing

```javascript
// Express: public surface is an EXPLICIT allowlist; everything else falls through the guard wall
app.use(['/health', '/live', '/ready', '/login', '/register'], publicRouter);
app.use(requireAuth);                       // wall: nothing below resolves without identity
app.use('/admin', requireRole('admin'));    // vertical wall for whole subtree
app.use('/api', apiRouter);                 // apiRouter assumes authenticated ctx
```

```yaml
# Spring Security: authenticate everything, permit only listed public paths
security:
  config:
    http:
      authorizeHttpRequests:
        - "/health"
        - "/login"
      others: "authenticated"
      admin-prefix: "/admin/**"
      admin-role: "ROLE_ADMIN"
    method-security: true
```

Equivalent defaults: ASP.NET `FallbackPolicy` (see below), Symfony last-resort `- { path: ^/, roles: ROLE_USER }`, Laravel `auth` on the `api` group, Rails authenticate in `ApplicationController` with `skip_before_action` audited per use.

```csharp
// ASP.NET Core: fail closed
builder.Services.AddAuthorization(o =>
{
    o.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser().Build();
});
// minimal APIs: app.MapGet("/x", h).RequireAuthorization("TenantMember");
```

### Tenant Scoping & Row-Level Security

- Enforce tenancy in ONE layer beneath all queries: repository base classes, DRF `get_queryset`, EF Core global query filters (`HasQueryFilter(i => i.TenantId == _tenant.Id)`), Hibernate `@Filter`/`@TenantId`, SQLAlchemy events, or Postgres RLS as backstop:

```sql
-- Postgres row-level security as defense-in-depth under app-level checks
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invoices
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
-- per request/connection: SET LOCAL app.tenant_id = '<uuid-from-session>';
```

- Name cache keys and queue headers with tenant scope (`t:{tenant}:invoice:{id}`); re-validate tenant on consume.
- Replace sequential integers with opaque UUIDv4 for external references (mitigation, not fix).
- Impersonation: dedicated short-TTL token type carrying `act` (actor) + target, reason string persisted to append-only audit table, auto-expiry on target password change, admin-only grant of the impersonation permission itself.

## Verification & Validation

### Automated Tests (GIVEN/WHEN/THEN)

```gherkin
Scenario: Owner retains access (negative test against over-blocking)
  GIVEN user A authenticated and owning invoice 1042
  WHEN A requests GET /api/invoices/1042
  THEN status is 200 AND body contains A's memo value

Scenario: Non-owner denied on read
  GIVEN users A and B on distinct tenants
  WHEN B requests GET /api/invoices/1042
  THEN status is 403 or 404 AND body contains no A-owned field values

Scenario: Non-owner denied on write
  WHEN B sends PATCH /api/invoices/1042 {"amount": 1}
  THEN status is 403/404 AND a follow-up GET by A shows unchanged amount

Scenario: Role matrix cell denial
  GIVEN role "viewer" exists with read-only rights
  WHEN viewer calls DELETE /api/invoices/1042
  THEN status is 403 regardless of ownership

Scenario: Unauthenticated denial
  WHEN request omits credentials entirely
  THEN status is 401 for every non-public route
```

Run the matrix for EVERY route × EVERY role × {own, foreign, nonexistent} object ID; assert status codes, not just absence of error text.

### Route-Coverage Test (deny-by-default assertion)

```javascript
// pseudocode — port enumerator per framework (Express stack walk, rails routes, artisan route:list)
const PUBLIC_ROUTES = new Set(['/health', '/live', '/ready', '/login', '/register', '/docs', '/openapi.json']);

test('every non-public route declares >=1 authz guard; no public mutations', () => {
  for (const r of enumerateRoutes(app)) {
    const isPublic = PUBLIC_ROUTES.has(r.path);
    const guards = r.middleware.filter(isAuthzGuard); // requireAuth/authorize/roles...
    expect(guards.length >= 1 || isPublic).toBe(true);           // deny-by-default
    if (isPublic) expect(r.methods.some(m => ['POST','PUT','PATCH','DELETE'].includes(m))).toBe(false);
  }
});
```

CI companion: snapshot-test the route table (`rails routes`, `artisan route:list`, Nest route dump) and fail review when count grows without a paired guard change.

### Manual Re-test Checklist

1. Re-run two-account sequence from Exploitation section; confirm `403/404` and owner `200`.
2. Re-run all path/header/verb bypass loops; confirm uniform denial.
3. Confirm admin can STILL operate (fixes frequently over-block; test each role-matrix cell positively).
4. Confirm export/download and GraphQL nested-field paths now enforce ownership.
5. Confirm impersonation writes audit rows and expires correctly.
6. Confirm cache keys are tenant-prefixed and stale pre-fix entries purged (flush affected namespaces).

### Post-Fix Greps

```bash
rg -n "skip_authorization|SkipAuthorization" app/
rg -n "objects\.(get|filter)\((pk|id)=" --type py
rg -n "findById\(" --type java --type kt | rg -v "AndTenant|ForTenant|Scoped"
rg -ni "x-(original-url|rewrite-url)" .
rg -n "x-forwarded-for" -i . | rg -v "trust proxy|trustedProxies|rate.?limit"
rg -n "@(Get|Post|Put|Delete|Patch)Mapping\(" --type java --type kt | wc -l   # compare vs @PreAuthorize count
```

## Severity Assessment

| Finding archetype | Example | Baseline CVSS v3.1 vector | Score band |
|---|---|---|---|
| Unauthenticated admin action | `POST /api/users` reachable pre-auth | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Critical (9.8) |
| Vertical escalation, authenticated write | normal user creates/disables users | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | High (8.8) |
| Cross-tenant bulk read | listing returns all tenants' records (scope-changing) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` | High (7.7) |
| Horizontal write, single object | attacker edits another tenant's invoice | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` | Medium–High (6.5) |
| Single-record cross-tenant read | one foreign record via guessed ID, high-sensitivity data | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | Medium (6.5) |
| Existence/timing oracle only | 200-empty vs 404 differentiation | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` | Low–Medium (3.1–4.3) |

Rubric modifiers: enumerable sequential IDs or absent rate limits push one band up; secrets/PHI/financial fields push up; compensating network ACLs on genuinely internal-only services push down but never to informational while the code defect persists. Admin takeover ≥9.0 always Critical; cross-tenant read defaults High even for one record when data is personal or confidential.

Primary CWE mapping: missing guard entirely → CWE-862; guard present but wrong → CWE-863; user-controlled key to another's object → CWE-639; umbrella → CWE-285; shared cache/queue granularity → CWE-1220.

## Common False Positives

- Gateway/sidecar enforcement: bare handlers behind an authorizing API gateway, service mesh `AuthorizationPolicy`, or mTLS-spiffe mesh. Verify the enforcement point exists and covers the route before dismissing; document it in the report.
- Intentionally public endpoints: pricing catalogs, status pages, docs — confirm product intent and absence of mutation methods.
- UUID capability references: unguessable IDs reduce practical exploitability, but the missing ownership predicate remains a real defect — report as lower-severity hardening gap, not a false positive of the pattern itself.
- Deliberate 404-masking: uniform `404` for foreign objects with `200` for owners is correct design, not a leak — confirm response timing/body are indistinguishable for nonexistent vs foreign IDs.
- Dev/test-only routes compiled out of production builds (verify build flags/env gates actually exclude them, e.g., `if (process.env.NODE_ENV !== 'production')`).
- Internal tools behind VPN + mTLS where identity is established at network layer — residual risk note only if the same service also binds a public interface.
- Read endpoints already filtered at the serializer to public fields — confirm no private field slips through relations/nested serializers.

## References

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
- [CWE-1220: Insufficient Resource Granularity](https://cwe.mitre.org/data/definitions/1220.html)
- [OWASP Cheat Sheet Series: Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Cheat Sheet Series: Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [OWASP Cheat Sheet Series: Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP API Security Top 10 (2023): API1 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API Security Top 10 (2023): API5 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Top 10 (2021): A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP ASVS 4.0.x — Section V4 Access Control](https://owasp.org/www-project-application-security-verification-standard/)
