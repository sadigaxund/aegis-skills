---
name: configuration-hardening-checks
description: Audit repositories for insecure defaults and hardening gaps across debug modes, exposed admin and actuator surfaces, CORS, security headers, cookie flags, TLS, containers, IaC, default credentials, and reverse proxies.
category_slug: CONFIG
cwe: [CWE-16, CWE-1188]
owasp: A05:2021 – Security Misconfiguration
---

## Scope & Objectives

Detect misconfiguration findings that arise from insecure defaults left unchanged or hardening controls never applied. This module covers ten classes:

1. **Debug/prod confusion** — debug flags, verbose error pages, stack traces and environment dumps reaching clients.
2. **Exposed admin/debug/actuator endpoints** — Spring Boot Actuator, Django debug toolbar, Laravel Telescope/_ignition, phpMyAdmin/Adminer, swagger-ui, monitoring consoles, `.git`/`.env` served from webroot, directory listings.
3. **CORS misconfiguration** — origin reflection with credentials, wildcards, `null` origin, overbroad subdomain matching, per-route divergence.
4. **Missing/weak security response headers** — CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, Referrer-Policy, Permissions-Policy.
5. **Cookie/session flags** — `Secure`, `HttpOnly`, `SameSite` per framework session store.
6. **TLS configuration** — legacy protocols, weak cipher strings, disabled certificate validation between internal services.
7. **Container/orchestration/IaC** — root containers, privileged pods, docker.sock mounts, missing pod securityContext, default-allow networks, public buckets, `0.0.0.0/0` on admin ports, wildcard IAM.
8. **Default credentials & seeds** — known passwords in compose files, seed-created admin users, vendor defaults referenced in configs/docs.
9. **Server/version disclosure** — fingerprinting headers and detailed unauthenticated status endpoints.
10. **Reverse-proxy gaps** — absent request size limits and timeouts, blind trust of `X-Forwarded-*` headers.

Out of scope (cross-references): secret *content* depth → SECRETS; session semantics → AUTHN; authorization impact of IP/header spoofing → AUTHZ; clickjacking mechanics → WEB; cryptographic strength → CRYPTO; volumetric abuse math → DOS.

Operating rules:

- Perform static review first; dynamic probes only against targets the engagement scope explicitly authorizes.
- Record the *effective* configuration for the production deploy target, not the first suspicious line you meet. Repos routinely ship `settings/base.py` plus `settings/dev.py`; resolve which profile boots before judging any flag.

## Mental Model

Read the repository as five stacked layers; a hardening gap at any layer becomes externally observable at the edge:

```
Internet
  └─ Reverse proxy (nginx / apache / ALB)          ← TLS lines, security headers, size limits, timeouts
      └─ Application runtime (Node/JVM/Python/PHP/Rails/.NET)
          ├─ Framework switches                     ← DEBUG flags, actuator exposure, CORS policy
          ├─ Middleware/filter pipeline ORDER       ← who answers errors, who echoes Origin
          └─ Outbound calls                         ← verify=False, plaintext http:// internals
Containers/IaC (Dockerfile, compose, k8s, Terraform) ← privilege, identity, network reach, secret delivery
Default identities (seed users, vendor creds, compose passwords)
```

Two root causes explain nearly every finding:

- **Insecure default accepted**: the framework ships permissive (`Flask-CORS` allows all origins out of the box; Docker runs as root without a `USER` directive; Spring Boot 1.x exposed most actuator endpoints). Nobody flipped the switch.
- **Hardening step omitted**: the control exists but was never configured (no CSP, no NetworkPolicy object anywhere, no `aws_s3_bucket_public_access_block` resource).

Decision heuristic for every switch you find: ask *"would this value plausibly differ between dev and prod?"* If yes, trace which profile wins at process start — entrypoint command, container env, `DJANGO_SETTINGS_MODULE`, `SPRING_PROFILES_ACTIVE`, `ASPNETCORE_ENVIRONMENT`, `RAILS_ENV`, `FLASK_DEBUG` — and judge only the winning value.

## What To Check

Work through the ten classes in order. For every hit record: `file:line`, the environment-resolution evidence (which profile boots), and the consequence the gap enables.

### 1. Debug and Verbose Error Modes

- Check `DEBUG = True` in Django settings and whether `ALLOWED_HOSTS = ["*"]` accompanies it. The Django debug page renders local variables, tracebacks, and settings values (SECRET_KEY is masked, most other values are not) — treat as potential secret exposure, cross-ref SECRETS.
- Check Flask/Werkzeug: `app.run(debug=True)`, `app.debug = True`, `FLASK_DEBUG=1` in deploy env files, and the interactive debugger (`use_evalex=True`), which permits console code execution if reachable.
- Check Node deployments: `NODE_ENV=development` in Dockerfiles (`ENV NODE_ENV development`), k8s Deployment env blocks, PM2 `ecosystem.config.js`, Elastic Beanstalk configs. Express' default error handler emits stack traces in development mode.
- Check Spring: `spring-boot-devtools` present as a dependency in the packaged artifact (`pom.xml`, `build.gradle`) rather than scope-managed out of prod builds; `spring.devtools.restart.enabled=true` in production properties.
- Check ASP.NET Core: unconditional `app.UseDeveloperExceptionPage()` reachable in the pipeline built for production (in `Program.cs`/`Startup.Configure`), plus `app.UseMigrationsEndPoint()`.
- Check Laravel: `APP_DEBUG=true` in the deployed `.env`; `_ignition` registers debug endpoints when debug is enabled.
- Check Rails: `config.consider_all_requests_local = true` surviving into `config/environments/production.rb` (renders full diagnostic pages regardless of who connects).
- Check generic verbose handlers: custom 500 handlers printing `e.getMessage()`/stacks to responses; Go services importing `net/http/pprof` or `expvar` on the DefaultServeMux (`/debug/pprof/`, `/debug/vars`).

### 2. Exposed Admin, Debug, and Actuator Endpoints

**Spring Boot Actuator — version semantics matter; state them per finding.**

- Boot 1.x: most endpoints are enabled by default and mapped at the context root — `/env`, `/heapdump`, `/dump` (thread dump), `/trace`, `/mappings`, `/beans`, `/configprops`. `/shutdown` is the notable opt-in exception.
- Boot 2.x and 3.x: default web exposure is **only** `health` and `info` via `management.endpoints.web.exposure.include`. Sensitive endpoints (`/actuator/env`, `/actuator/heapdump`, `/actuator/threaddump`, `/actuator/loggers`, `/actuator/scheduledtasks`, `/actuator/gateway/routes` when Spring Cloud Gateway is present) require explicit exposure. Property values shown by `/env` are masked by default in recent versions (keys remain visible); masking is governed by `management.endpoint.env.show-values`.
- Flag: `management.endpoints.web.exposure.include: "*"` or any list containing `env`/`heapdump`/`threaddump`; a management port bound on all interfaces (`management.server.address` unset) or sharing the app port.

| Config key | Insecure value | Secure value | Framework |
| --- | --- | --- | --- |
| `management.endpoints.web.exposure.include` | `"*"` or includes `env`,`heapdump`,`threaddump` | `health,info` | Spring Boot 2/3 |
| `management.server.address` | unset (binds all interfaces) | `127.0.0.1` behind ops access | Spring Boot 2/3 |
| `INSTALLED_APPS` | contains `debug_toolbar` in prod profile | absent in prod module | Django |
| `TELESCOPE_ENABLED` | `true` in prod `.env` | `false`; gate with `Telescope::gate` | Laravel Telescope |
| `autoindex` | `on` | `off` | nginx |
| `Options` | `Indexes` / `+Indexes` | `-Indexes` | Apache |
| `[auth.anonymous] enabled` | `true` | `false` | Grafana `grafana.ini` |

Also sweep for:

- **Django debug toolbar**: `debug_toolbar` in `INSTALLED_APPS` plus its URL include (commonly `__debug__/`); verify both `INTERNAL_IPS` and `DEBUG` in the *prod* profile, not just dev.
- **Laravel**: `/telescope` (Telescope dashboard), `/horizon` (Horizon). `_ignition` exposes `/_ignition/execute-solution` when `APP_DEBUG=true`; older Laravel versions had published unauthenticated remote-code-execution advisories against this endpoint class — flag statically, never probe without authorization.
- **phpMyAdmin / Adminer**: webroots such as `/phpmyadmin`, or a stray `adminer.php` anywhere under the served document root.
- **Swagger/OpenAPI open in prod**: springdoc-openapi `/swagger-ui.html` + `/v3/api-docs`; springfox `/swagger-ui/`; drf-yasg `/swagger/` and `/redoc/`; NestJS `SwaggerModule.setup('/swagger', ...)`; Flask-RESTX serving Swagger UI at the Api root and `/swagger.json`.
- **Monitoring consoles unauthenticated**: Grafana (default port `:3000`; `[auth.anonymous]` enabled in `grafana.ini`; default login `admin`/`admin` until changed), Prometheus (`:9090`, no built-in authentication), Kibana (`:5601`; check `xpack.security.enabled: false` in `elasticsearch.yml`), Jenkins (open signup or permissive authorization strategy).
- **Status endpoints**: Apache `<Location /server-status>` with `SetHandler server-status` and `ExtendedStatus On`; nginx `stub_status on` in a reachable location.
- **VCS and dotfiles served from webroot**: `/.git/HEAD` (returns `ref: refs/heads/...`), `/.svn/entries`, `/.hg/`, `/.env`, `/.DS_Store`, `web.config.bak`, editor swap files. Check whether the build context excludes them (missing `.dockerignore` entries cause exactly this).
- **Directory listing**: nginx `autoindex on;`, Apache `Options Indexes`/`+Indexes`, npm `serve-index` wired in prod, Python `http.server` as a container CMD.

### 3. CORS Misconfiguration

Evaluate every CORS policy against one question: **can an attacker-chosen Origin receive a readable response while cookies ride along?**

| Config key | Insecure value | Secure value | Framework |
| --- | --- | --- | --- |
| `CORS_ORIGIN_ALLOW_ALL` / `CORS_ALLOW_ALL_ORIGINS` | `True` (old/new spelling of same switch) | removed; use `CORS_ALLOWED_ORIGINS` list | django-cors-headers |
| `CORS_ALLOW_CREDENTIALS` | `True` combined with allow-all origins | `True` only alongside an explicit origin list | django-cors-headers |
| `CORS_URLS_REGEX` | broad like `r"/.*"` applied globally | narrow regex scoped to public APIs | django-cors-headers |
| flask-cors defaults | `CORS(app)` with no args (allows all origins) | explicit `origins=[...]` allowlist | flask-cors |
| `supports_credentials` | `True` while origins remain wildcard/reflected | `True` only with explicit origins | flask-cors |
| `origin` option | `true` (reflects request Origin verbatim) or unanchored regex/string match | array of exact scheme+host origins | express `cors` package |
| `credentials` | `true` combined with `origin: "*"` or reflection | `true` only with exact allowlist | express `cors` package |
| `CorsRegistry.addMapping(...)` | `.allowedOrigins("*").allowCredentials(true)` | exact origins via `allowedOrigins` | Spring MVC |
| `setAllowedOriginPatterns("*")` + `setAllowCredentials(true)` | pattern wildcard bypasses the wildcard+credentials guard | tight patterns or explicit origins | Spring MVC/Security |
| `@CrossOrigin(origins = "*")` | route-level loosening of a strict global policy | `origins = "https://app.example.com"` | Spring MVC |
| `AllowAnyOrigin()` + `AllowCredentials()` | chained together | `WithOrigins(...)` + `AllowCredentials()` | ASP.NET Core |

Framework behavior notes:

- ASP.NET Core refuses `AllowAnyOrigin()` combined with `AllowCredentials()` (the framework throws when the policy is evaluated); hand-rolled middleware writing raw headers does not refuse anything — search for manual `Access-Control-Allow-Origin` writes.
- Recent Spring versions throw at runtime when `allowCredentials(true)` meets `allowedOrigins("*")`; `allowedOriginPatterns("*")` is the escape hatch teams use to restore the dangerous behavior — treat it as equivalent.
- **flask-cors DANGER note**: the bare default allows all origins, and because `send_wildcard` defaults to false it *reflects* the request `Origin` header instead of emitting `*`. The default `supports_credentials=False` keeps it below account-takeover grade, but teams later add `supports_credentials=True` without tightening origins — flag both states distinctly.

Additional checks:

- **Null origin allowed**: `"null"` present in an origin allowlist (pairs with sandboxed-iframe attacks).
- **Overbroad subdomain matching**: naive checks like `origin.endsWith("example.com")` accept `https://evilexample.com`; unanchored regexes do the same. Require anchored logic over the parsed hostname (`^https://[^/]+\.example\.com$` shape, or exact-host comparison).
- **Preflight breadth**: `Access-Control-Allow-Methods: *` plus reflecting `Access-Control-Allow-Headers` from the request — acceptable only on credential-less public APIs; flag whenever credentials flow.
- **Per-route divergence**: strict global policy loosened locally — a `@CrossOrigin` annotation on one controller, `cors()` mounted on one router, a resource-level override in flask-cors. Sweep decorators/annotations for local overrides after reading the global policy.

### 4. Security Response Headers

Target this baseline on every response from the layer that actually reaches clients:

| Header | Strong baseline | Weak/absent marker |
| --- | --- | --- |
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; frame-ancestors 'self'` plus needs-based additions | absent entirely; `unsafe-inline` and/or `unsafe-eval`; no `frame-ancestors` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (guidance floor: `max-age` >= `15552000`) | absent on an HTTPS host; `max-age` below 15552000; no `includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` | absent |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` as legacy-UA fallback beside CSP `frame-ancestors` | absent (cross-ref WEB clickjacking) |
| `Referrer-Policy` | `no-referrer` or `strict-origin-when-cross-origin` | absent |
| `Permissions-Policy` | deny unused powerful features, e.g. `camera=(), microphone=(), geolocation=()` | absent |

Where each stack sets them — verify presence in the effective path:

- nginx/apache: `add_header ... always` / `Header always set` in the active server/vhost. Watch inheritance: once a child `location` block defines its own `add_header`, server-level `add_header` directives stop applying there.
- Express: `helmet()` covers most of the baseline; add explicit CSP/HSTS tuning rather than disabling modules.
- Django: `django.middleware.security.SecurityMiddleware` and `XFrameOptionsMiddleware` present in `MIDDLEWARE`, plus the `SECURE_*` settings listed in Remediation.
- Spring Security: `headers()` DSL — HSTS and `X-Content-Type-Options` and frame options have secure defaults; CSP must be added explicitly.
- ASP.NET Core: `app.UseHsts()` and `app.UseHttpsRedirection()` before routing; CSP via middleware or web.config `<customHeaders>`.

### 5. Cookie and Session Flags

For each framework, open the stated location and verify session and auth cookies carry `Secure`, `HttpOnly`, and a deliberate `SameSite` (session semantics cross-ref AUTHN):

| Framework | Config location | Keys/options to verify |
| --- | --- | --- |
| Express (`express-session`) | `app.use(session({...}))` | `cookie.secure: true`, `cookie.httpOnly: true`, `cookie.sameSite: "lax"`, `proxy: true` behind TLS-terminating proxy |
| Express (`res.cookie`) | per-response calls | third argument `{ secure: true, httpOnly: true, sameSite: "lax" }` on auth tokens |
| Django | `settings.py` | `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`, `CSRF_COOKIE_SECURE = True` |
| Rails | `config/environments/production.rb`, `config/initializers/session_store.rb` | `config.force_ssl = true` (forces HTTPS redirect and secure cookies); session store arguments include `secure: true` |
| ASP.NET Core | `services.ConfigureApplicationCookie(...)` or `CookieOptions` | `Cookie.SecurePolicy = CookieSecurePolicy.Always`, `Cookie.HttpOnly = true`, `Cookie.SameSite = SameSiteMode.Lax` |
| Tomcat (container-managed sessions) | `WEB-INF/web.xml` or global `conf/web.xml` | `<cookie-config><secure>true</secure><http-only>true</http-only></cookie-config>` inside `<session-config>` |

Flag specifically: session cookies without `Secure` on an HTTPS-only site (fires on any downgraded plaintext hop), `SameSite=None` without `Secure` (browsers reject it today — indicates stale config), and long-lived persistent remember-me cookies lacking rotation.

### 6. TLS Configuration

- Grep server configs for legacy protocol lines: nginx `ssl_protocols TLSv1 TLSv1.1 SSLv3;` variants; Apache `SSLProtocol all -SSLv3` (silently leaves TLSv1.0/1.1 enabled) or missing `-TLSv1 -TLSv1.1` exclusions.
- Weak cipher strings: `ssl_ciphers ALL`, `DEFAULT`, `HIGH:MEDIUM:!aNULL` (MEDIUM admits RC4-era suites), or any string containing `RC4`, `3DES`, `EXPORT`, `MD5`, or lacking `!aNULL:!eNULL`.
- Certificate validation disabled on internal calls (depth cross-ref CRYPTO): Python `requests(..., verify=False)` and suppressed `urllib3` warnings, Node `https.Agent({ rejectUnauthorized: false })` or `NODE_TLS_REJECT_UNAUTHORIZED=0`, Go `tls.Config{InsecureSkipVerify: true}`, Java trust-all `X509TrustManager`/`HostnameVerifier` implementations, PHP `CURLOPT_SSL_VERIFYPEER => false`, shell `curl -k`/`--insecure` in deploy scripts, git `http.sslVerify=false`.
- Plaintext internal hops: inter-service URLs using `http://` (connection strings, service-discovery entries) for services that carry session or token data where the threat model expects encrypted east-west traffic.

### 7. Containers, Orchestration, and IaC

Dockerfiles:

- Missing `USER` directive (image runs as root); `USER root` with no later demotion.
- Secrets baked into layers via `COPY .env /app/` or credential-bearing build args.
- Unpinned base images (`FROM node:latest`).

Compose / docker run flags:

- `privileged: true`; `cap_add: [SYS_ADMIN]` or broader; `security_opt: ["seccomp:unconfined", "apparmor:unconfined"]`; `pid: "host"`; `network_mode: "host"`.
- Mounting `/var/run/docker.sock` into containers (container-escape adjacency).
- Absent resource ceilings — no `mem_limit`/`cpus` (compose) or k8s `resources.limits` (resource-exhaustion adjacency, cross-ref DOS).

Kubernetes pod specs:

- Pod-level `securityContext` absent: no `runAsNonRoot: true`, no `fsGroup`, no `seccompProfile`.
- Container-level: `allowPrivilegeEscalation` unset (defaults to allowing it), `readOnlyRootFilesystem` unset, no `capabilities.drop`.
- `hostPath` volumes; unnecessary `automountServiceAccountToken: true`.
- No `NetworkPolicy` object anywhere in the repo → default-allow pod-to-pod posture; note lateral-movement adjacency.
- Detection strategy: this is a *file-presence plus field-absence* check, not a grep. Enumerate every workload manifest (`kind: Deployment|Pod|StatefulSet|DaemonSet|CronJob`), assert each contains a pod-level `securityContext:`, and report the failures.

Secrets delivery debate — practical guidance:

- Mounted files (Secret volume, read-only) beat env vars: env values leak via `/proc/<pid>/environ` to any same-container process, appear in crash dumps, and surface in inspect-class tooling; files allow per-key permissions and atomic rotation.
- Env-from-Secret is acceptable short-term under tight namespace RBAC; literal plaintext secrets committed in manifests or Terraform are always findings regardless of delivery style.

Terraform:

- Public storage: `aws_s3_bucket` with `acl = "public-read"` / `"public-read-write"`, a bucket policy with `Principal: "*"`, or simply the absence of `aws_s3_bucket_public_access_block` with all four booleans `true`.
- Open admin ports: `aws_security_group` / `aws_security_group_rule` ingress `cidr_blocks = ["0.0.0.0/0"]` (or `"::/0"`) on 22, 3389, 3306, 5432, 6379, 27017, 9200.
- `aws_db_instance` with `publicly_accessible = true`.
- IAM policy documents pairing `Effect: "Allow"` with `Action: "*"` and `Resource: "*"`; also flag service-scoped wildcards like `s3:*` over `arn:aws:s3:::*` attached to prod roles.

### 8. Default Credentials and Seeds

- Compose/env defaults: `POSTGRES_PASSWORD: postgres`, `MYSQL_ROOT_PASSWORD: root`/`mysql` (official image docs use the placeholder `my-secret-pw`), `MONGO_INITDB_ROOT_USERNAME/PASSWORD` set to doc-style `root`/`example` pairs, `RABBITMQ_DEFAULT_PASS: guest`, weak `GF_SECURITY_ADMIN_PASSWORD`, `MINIO_ROOT_USER/PASSWORD` left as `minioadmin`, Redis started without any `requirepass`.
- Seeds/migrations creating principals: Rails `db/seeds.rb` creating an admin with a known password, Django fixtures containing known password hashes, Laravel `DatabaseSeeder` admin factories, SQL migrations inserting `admin` rows, Flyway/Liquibase changelogs doing the same.
- Vendor defaults referenced in configs/docs: sample Tomcat `tomcat-users.xml` entries (e.g., `tomcat`/`tomcat` with manager roles) uncommented, Grafana `admin`/`admin`, MinIO `minioadmin`/`minioadmin`, RabbitMQ `guest`/`guest`, Solr's documented example pair `solr`/`SolrRocks`, PostgreSQL `pg_hba.conf` `trust` auth lines.
- Rule: credential attempts happen ONLY against explicitly authorized targets, using only pairs evidenced in-repo; procedure F in Exploitation & Reproduction is the sole permitted shape.

### 9. Server and Version Disclosure

Minor severity; enumerate anyway because it feeds attacker reconnaissance:

- Response headers: `Server: nginx/1.24.0`, `Apache/2.4.41 (Ubuntu)`, `Apache-Coyote/1.1` (Tomcat), `X-Powered-By: Express`, `PHP/8.2.x`, `X-AspNet-Version`, `X-AspNetMvc-Version`, Kestrel's `Server` header.
- Suppression keys: nginx `server_tokens off;`; Apache `ServerTokens Prod` + `ServerSignature Off`; php.ini `expose_php = Off`; Express `app.disable('x-powered-by')`; ASP.NET `<httpRuntime enableVersionHeader="false"/>` plus removing `X-Powered-By` via `<customHeaders>`; Kestrel `AddServerHeader = false`.
- Detailed unauthenticated internals: `/actuator/info` exposing build/scm/git metadata, `/version`, `/status.json`, Go `/debug/vars` (expvar) and `/debug/pprof/`, unauthenticated Prometheus-format `/metrics` enumerating route names and internal counts.

### 10. Reverse Proxy Gaps

- Request size limits: explicit raises like `client_max_body_size 0;` or `client_max_body_size 1000m;` in nginx (unset means the 1 m default applies silently — verify which case you have); Apache `LimitRequestBody` unset where uploads matter; Express `json({ limit: "50mb" })`.
- Timeouts (slowloris adjacency, cross-ref DOS): `client_header_timeout`/`client_body_timeout`/`send_timeout` raised far beyond their 60 s defaults; `proxy_connect_timeout`/`proxy_send_timeout`/`proxy_read_timeout` at multi-minute values pinning sockets against slow backends; inflated `keepalive_timeout`.
- Blind forwarded-header trust (auth-bypass adjacency, cross-ref AUTHZ):
  - Express `app.set('trust proxy', true)` trusts every peer's `X-Forwarded-For` claim; correct form is a hop count or CIDR list.
  - Code reading `req.headers['x-forwarded-for'].split(',')[0]` (leftmost entry is client-controlled) for rate limiting, IP allowlists, or audit identity.
  - Django `USE_X_FORWARDED_HOST = True` without proxy normalization; `SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` while the edge may not strip inbound copies of that header.
  - Rails `request.remote_ip` fed by `ActionDispatch::RemoteIp` with widened trusted-proxy configuration.
  - Spring `ForwardedHeaderFilter` enabled globally; ASP.NET `app.UseForwardedHeaders()` without `KnownProxies` restriction.

Compliance-framework mapping note (baseline lenses; no deep checklists claimed here): CIS Benchmarks publish per-technology audit baselines suited to validating the switches above; PCI DSS, HIPAA, and ISO 27001 serve as framework lenses for prioritizing findings in regulated contexts.

## Where To Look

Resolve the effective production profile first (entrypoint → env vars → settings module), then sweep these artifacts:

| Artifact | Path globs | What to extract |
| --- | --- | --- |
| Django settings | `**/settings*.py`, `**/settings/{base,dev,prod,production}.py`, `manage.py`, `wsgi.py`, `asgi.py` | which module `DJANGO_SETTINGS_MODULE` names; `DEBUG`; `ALLOWED_HOSTS`; `MIDDLEWARE` order; `SESSION_COOKIE_*`; `SECURE_*`; `CORS_*` |
| Flask/FastAPI | `**/app.py`, `**/wsgi.py`, `**/config.py`, `**/.env*`, `gunicorn*.py`, `Procfile` | `app.run(debug=...)`; `CORS(app, ...)` arguments; `FLASK_DEBUG`; uvicorn `--reload` in prod |
| Node | `**/server.js`, `**/app.js`, `**/index.js`, `package.json`, `**/.env*`, `ecosystem.config.js`, `next.config.js`, `nuxt.config.ts` | effective `NODE_ENV`; `helmet(`; `cors(`; session cookie options; `trust proxy`; `rejectUnauthorized` |
| Spring | `**/application*.{yml,yaml,properties}`, `pom.xml`, `build.gradle`, `**/WebMvc*Config*.java`, `**/SecurityConfig*.java` | actuator exposure lines; `CorsRegistry` beans; devtools dependency; `headers()` DSL |
| ASP.NET | `**/Program.cs`, `**/Startup.cs`, `**/appsettings*.json`, `**/web.config` | `UseDeveloperExceptionPage` placement; `AddCors` policies; `UseHsts`; cookie options |
| Rails | `config/environments/production.rb`, `config/application.rb`, `config/initializers/*.rb`, `Gemfile` | `force_ssl`; session store args; rack-cors config; `consider_all_requests_local` |
| PHP/Laravel | `.env*`, `bootstrap/app.php`, `config/cors.php`, `config/session.php`, `config/telescope.php`, `composer.json`, `public/.htaccess` | `APP_DEBUG`; CORS middleware stack; Telescope gate |
| Proxies/servers | `**/nginx*.conf`, `**/sites-available/*`, `**/sites-enabled/*`, `**/conf.d/*.conf`, `**/httpd*.conf`, `Caddyfile`, `haproxy.cfg` | TLS protocol/cipher lines; header directives; limits; timeouts; status endpoints; `autoindex` |
| Containers | `Dockerfile*`, `docker-compose*.yml`, `*.dockerfile`, `.dockerignore` | `USER`; `ENV NODE_ENV`; privileged flags; sock mounts; resource limits |
| Kubernetes | `**/*.yaml` with workload `kind:` values, `**/charts/**`, `values*.yaml` | securityContext presence; resources; NetworkPolicy existence; secret delivery style |
| Terraform | `**/*.tf`, `**/*.tfvars` | S3 ACL/public-access-block; SG ingress rules; RDS flags; IAM policy documents |
| CI/deploy | `.github/workflows/*`, `Jenkinsfile`, `.gitlab-ci.yml`, Helm templates/values, ansible playbooks | which profile/artifact ships to prod; debug env leaking into deploy steps |
| Docs | `README*`, `docs/deploy*`, `docs/install*` | quoted default credentials; manual topology notes revealing internal service URLs |

## Patterns & Signatures

All regexes are ripgrep-compatible (no lookarounds). Run from repo root with vendored trees excluded. Every hit is a *candidate*: confirm the environment-resolution rule from Mental Model before reporting.

### Paste-Ready Ripgrep Sweep

```bash
rg -n --hidden \
  -g '!.git/' -g '!node_modules/' -g '!vendor/' -g '!dist/' -g '!build/' \
  -e "DEBUG\s*=\s*True" \
  -e "app\.run\(.*debug\s*=\s*True" \
  -e "FLASK_DEBUG\s*=\s*1" \
  -e "APP_DEBUG\s*=\s*true" \
  -e "NODE_ENV\s*[=:].*development" \
  -e "spring-boot-devtools" \
  -e "UseDeveloperExceptionPage|UseMigrationsEndPoint" \
  -e "consider_all_requests_local\s*=\s*true" \
  -e "exposure\.include\s*[:=].*\*" \
  -e "debug_toolbar|__debug__|Telescope|_ignition" \
  -e "stub_status|server-status|autoindex\s+on|Options\s+\+?Indexes" \
  -e "CORS_(ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True" \
  -e "CORS_ALLOW_CREDENTIALS\s*=\s*True" \
  -e "supports_credentials\s*[:=]\s*True" \
  -e "origin\s*:\s*true|credentials\s*:\s*true" \
  -e "allowedOrigins\(.?\*.?\)|allowedOriginPatterns\(.?\*.?\)|AllowAnyOrigin|AllowCredentials\(\)" \
  -e "@CrossOrigin\([^\)]*\*" \
  -e "unsafe-inline|unsafe-eval" \
  -e "SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False" \
  -e "sameSite\s*[:=][\"' ]*none" \
  -e "secure\s*[:=]\s*false" \
  -e "ssl_protocols|SSLProtocol" \
  -e "TLSv1\.0|TLSv1\.1|SSLv3" \
  -e "ssl_protocols\s+TLSv1\s" \
  -e "verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true" \
  -e "NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|http\.sslVerify\s*=\s*false" \
  -e "privileged:\s*true|docker\.sock|SYS_ADMIN|security_opt:.*unconfined|pid:\s*\"?host|network_mode:\s*\"?host" \
  -e "hostPath:|automountServiceAccountToken:\s*true" \
  -e "cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]|cidr_blocks\s*=\s*\[\"::/0\"\]" \
  -e "publicly_accessible\s*=\s*true" \
  -e "acl\s*=\s*\"public-(read|read-write)\"" \
  -e "\"Action\"\s*:\s*\"\*\"|\"Resource\"\s*:\s*\"\*\"" \
  -e "POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|RABBITMQ_DEFAULT_PASS|MINIO_ROOT_|GF_SECURITY_ADMIN_PASSWORD|minioadmin|SolrRocks" \
  -e "password\s*[:=]\s*[\"'][\"']?(postgres|root|admin|changeme|example|guest|secret|toor)" \
  -e "server_tokens\s+on|ServerTokens\s+(Full|OS)|expose_php\s*=\s*On|enableVersionHeader=\"true\"" \
  -e "/debug/vars|pprof|expvar" \
  -e "client_max_body_size\s+(0|[0-9]{3,}[mM])" \
  -e "proxy_read_timeout\s+([6-9][0-9]{2}|[0-9]{4,})" \
  -e "trust proxy|USE_X_FORWARDED_HOST\s*=\s*True|SECURE_PROXY_SSL_HEADER|ForwardedHeaderFilter|UseForwardedHeaders" \
  > config_findings_raw.txt
```

The `secure\s*[:=]\s*false` and bare `ssl_protocols` lines are intentionally noisy — triage hits against the cookie-flag and TLS checklists above.

### Absence Checks (File-Presence Strategy, Not Grep)

```bash
# Workload manifests lacking any pod-level securityContext
for f in $(rg -l --glob '*.yaml' --glob '*.yml' '^kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|CronJob)$'); do
  grep -q 'securityContext:' "$f" || echo "NO-securityContext: $f"
done

# NetworkPolicy posture: no object at all means default-allow
rg -l --glob '*.yaml' --glob '*.yml' '^kind:\s*NetworkPolicy$' || echo "NO NetworkPolicy objects found"

# Dockerfiles that never demote from root
for f in $(rg --files -g 'Dockerfile*' -g '*.dockerfile'); do
  grep -qiE '^USER [a-z0-9]' "$f" || echo "no-USER-directive: $f"
done

# Terraform buckets without a public-access block anywhere in the module tree
rg --files -g '*.tf' | while read -r f; do
  if rg -q 'aws_s3_bucket\b' "$f" && ! rg -q 'aws_s3_bucket_public_access_block' "$f"; then
    echo "bucket-without-PAB: $f"
  fi
done | sort -u
```

### Debug Flags

```python
# VULNERABLE — Django settings module named by the prod entrypoint
DEBUG = True
ALLOWED_HOSTS = ["*"]

# FIXED — profile split honored, prod module wins at boot
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]
```

```yaml
# VULNERABLE — application.yml shipped to prod
management:
  endpoints:
    web:
      exposure:
        include: "*"

# FIXED — least exposure, management plane on loopback only
management:
  endpoints:
    web:
      exposure:
        include: health, info
  server:
    address: 127.0.0.1
    port: 9001
```

### CORS Signatures

```javascript
// VULNERABLE — reflects any Origin and lets cookies through
app.use(cors({ origin: true, credentials: true }));
```

```java
// VULNERABLE — pattern wildcard defeats the wildcard+credentials guard
registry.addMapping("/api/**")
        .allowedOriginPatterns("*")
        .allowCredentials(true);
```

```python
# VULNERABLE — django-cors-headers allow-everything with cookies
CORS_ALLOW_ALL_ORIGINS = True   # legacy spelling of this switch: CORS_ORIGIN_ALLOW_ALL
CORS_ALLOW_CREDENTIALS = True
```

```javascript
// VULNERABLE — suffix match accepts https://evilexample.com
const allowed = origin.endsWith("example.com");

// FIXED — parse URL and compare hostname labels
const u = new URL(origin);
const allowed = u.hostname === "app.example.com" || u.hostname.endsWith(".example.com");
```

### TLS Signatures

```nginx
# VULNERABLE
ssl_protocols TLSv1 TLSv1.1;
ssl_ciphers HIGH:MEDIUM:!aNULL;

# FIXED
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
```

```python
# VULNERABLE — internal call skips verification
resp = requests.get("http://billing.internal/api/charge", verify=False)

# FIXED — pinned internal CA bundle over HTTPS
resp = requests.get("https://billing.internal/api/charge", verify="/etc/ssl/internal-ca.pem")
```

### Container/IaC Signatures

```yaml
# VULNERABLE — docker-compose.yml
services:
  worker:
    image: internal/worker:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

```hcl
# VULNERABLE
resource "aws_security_group_rule" "ssh_open" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```

## Taint Tracing Guidance

Configuration findings are usually *state*, not taint — but three genuine source-to-sink flows exist. Trace each through the middleware/filter pipeline in order (Express `app.use` sequence; Django `MIDDLEWARE` list; ASP.NET `Configure` call order; Spring filter chain; Rack stack):

1. **Origin request header → Access-Control-Allow-Origin response header.** Locate the CORS layer; determine whether the `Origin` value flows verbatim into the response (reflection) or is matched against a static allowlist. Then check whether credentials ride along (`Access-Control-Allow-Credentials: true` plus cookie-authenticated routes). Reflection plus credentials converts any victim's browser into an exfiltration channel for session-scoped data.
2. **X-Forwarded-For / X-Forwarded-Proto / Host → security decisions.** Trace client-IP extraction into rate limiters, audit logs, and IP allowlists; trace proto/host into redirect construction and secure-cookie logic. A leftmost-XFF read lets callers mint arbitrary source IPs; an unvalidated proto hint enables downgrade paths; an unvalidated Host feeds link generation (authorization impact cross-ref AUTHZ).
3. **Exception payload → response body.** Confirm what the default error handler releases: Django's debug page includes local variables, settings values, and SQL; Express development mode emits full stacks; ASP.NET's developer exception page emits detailed runtime error data.

Ordering bugs to hunt specifically: `UseDeveloperExceptionPage()` registered unconditionally early in a production pipeline; header-setting middleware registered after response start (headers silently dropped); custom handlers answering before the real CORS policy runs.

## Exploitation & Reproduction

Static confirmation via Patterns & Signatures is sufficient evidence for most findings. Run dynamic procedures ONLY against hosts explicitly listed in the engagement scope. Record observables, never unjustifiable payloads.

### A. CORS Reflection Proof

1. Send: `curl -si "https://TARGET/api/userinfo" -H "Origin: https://evil.example"`
2. Observable (vulnerable): response carries `Access-Control-Allow-Origin: https://evil.example` — your arbitrary origin echoed back.
3. Confirm credential flow: `curl -si -X OPTIONS "https://TARGET/api/userinfo" -H "Origin: https://evil.example" -H "Access-Control-Request-Method: GET"` — look for `Access-Control-Allow-Credentials: true`.
4. Impact to state when both hold: a victim logged into TARGET who visits attacker-controlled content makes credentialed cross-origin requests whose responses the attacker's JavaScript can read — session-scoped data theft without touching credentials.

### B. Actuator Enumeration (Authorized Targets Only)

1. Map surface: `curl -s "https://TARGET/actuator"` — lists exposed endpoint hrefs.
2. Environment: `curl -s "https://TARGET/actuator/env"` — observable: property NAMES with values masked/redacted on current Boot versions; Boot 1.x may return plaintext values — apply the redaction rule from procedure E immediately.
3. Heap dump: `curl -so heap.bin "https://TARGET/actuator/heapdump"` — observable: HTTP 200 with a multi-megabyte binary body; run `strings heap.bin | grep -iE 'password|jdbc|secret'` locally to demonstrate depth, then delete per SECRETS handling rules.

### C. Verbose Error Page Trigger

1. On an authorized staging target, force a failure: `curl -s "https://TARGET/items/?page=NOT_AN_INT"`.
2. Observable markers: `Traceback (most recent call last)` (Python), `Exception Type:` with Django's yellow diagnostic page, `Werkzeug Debugger` console HTML, `An unhandled exception occurred while processing the request` (ASP.NET), Java class names with line numbers.
3. Static cross-check: debug flags from What To Check §1 prove reachability where dynamic testing is out of scope.

### D. Directory Listing Marker

1. `curl -s "https://TARGET/assets/" | grep -o "<title>[^<]*</title>"`
2. Observable: `<title>Index of /assets/</title>` (nginx autoindex and Apache mod_autoindex emit this shape) plus an entry listing.

### E. Dotfile Exposure With Mandatory Redaction

1. `.git`: `curl -s "https://TARGET/.git/HEAD"` — vulnerable if output starts with `ref: refs/heads/`.
2. `.env`: `curl -s "https://TARGET/.env"` — vulnerable if the body is lines of `KEY=value` pairs.
3. Immediate redaction rule: record key names and value lengths only; truncate every captured value after its first four characters; never paste full values into notes, tickets, or reports; treat anything confirmed fetched as compromised and route it to rotation regardless of further action (cross-ref SECRETS).

### F. Default-Credential Attempt (Explicitly Authorized Targets Only)

1. Use only pairs evidenced in-repo (compose defaults, seed files) — never external wordlists.
2. Single attempt per pair, e.g. Grafana: `curl -si "https://TARGET/login" -H "Content-Type: application/json" -d '{"user":"admin","password":"admin"}'`
3. Observable: HTTP 200 with a session cookie (`grafana_session`) or a redirect to an authenticated route.
4. Stop at first success; do not pivot; document and trigger immediate rotation.

### G. Version Disclosure Fingerprint

1. `curl -sI "https://TARGET/" | grep -iE "^(server|x-powered-by|x-aspnet)"`
2. Observable: version-bearing headers such as `Server: nginx/1.24.0` or `X-Powered-By: PHP/8.2.x`.

### H. Forwarded-Header Trust Probe (Cross-Ref AUTHZ)

1. Identify a rate-limited or IP-gated endpoint from code reading.
2. Repeat requests past the documented threshold with varying spoofs: `curl -s -o /dev/null -w "%{http_code}\n" "https://TARGET/api/login" -H "X-Forwarded-For: 10.$RANDOM.$RANDOM.$RANDOM"`
3. Observable (vulnerable): no 429/403 despite exceeding the threshold — the limiter keyed on the spoofed header.

## Remediation

Fix at the layer that actually reaches clients; prefer one canonical edge config over scattered app-level patches.

### Hardened nginx Edge

```nginx
# FIXED — baseline edge server block: headers, limits, timeouts, TLS
server {
    listen 443 ssl;
    # http2: use "listen 443 ssl http2;" on nginx < 1.25.1, else "http2 on;"
    server_name app.example.com;
    server_tokens off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    client_max_body_size 1m;
    client_body_timeout   10s;
    client_header_timeout 10s;
    keepalive_timeout     15s;
    send_timeout          10s;
    proxy_connect_timeout 5s;
    proxy_send_timeout    30s;
    proxy_read_timeout    30s;

    autoindex off;
    location ~ /\.(git|svn|hg|env) { return 404; }

    location / {
        proxy_pass http://app_upstream;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite; never trust client input
        proxy_set_header X-Forwarded-Proto https;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Content-Security-Policy   "default-src 'self'; object-src 'none'; frame-ancestors 'self'" always;
        add_header X-Content-Type-Options    nosniff always;
        add_header Referrer-Policy           no-referrer always;
        add_header Permissions-Policy        "camera=(), microphone=(), geolocation=()" always;
    }
}
```

Inheritance gotcha: server-level `add_header` directives are discarded inside any `location` that declares its own `add_header`, so the header set lives inside `location /`.

### Node/Express (helmet + bounded trust proxy)

```javascript
// FIXED — helmet defaults plus explicit CSP/HSTS, forwarded trust as hop count
const helmet = require("helmet");

app.disable("x-powered-by");
app.set("trust proxy", 1); // hops to the TLS terminator — never true

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: "no-referrer" },
}));

app.use(session({
  name: "sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000,
  },
}));
```

helmet's default HSTS max-age is already 15552000; raising to 31536000 clears the guidance floor.

### Django Production Settings Block

```python
# FIXED — exact setting names in the prod settings module
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Lax"

X_FRAME_OPTIONS = "DENY"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",      # first
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
```

Modern Django defaults several of these safely (`SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE='Lax'`, `X_FRAME_OPTIONS='DENY'`) — set them explicitly anyway so intent survives upgrades, and run `python manage.py check --deploy` in CI.

### Spring Security Headers DSL + MVC CORS

```java
// FIXED — Spring Security lambda DSL (5.8+/6.x)
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .headers(headers -> headers
            .contentSecurityPolicy(csp -> csp.policyDirectives(
                "default-src 'self'; object-src 'none'; frame-ancestors 'self'"))
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true))
            .frameOptions(frame -> frame.sameOrigin()));
    return http.build();
}
```

```java
// FIXED — explicit origins; no pattern wildcard combined with credentials
@Bean
WebMvcConfigurer corsConfigurer() {
    return registry -> registry.addMapping("/api/**")
            .allowedOrigins("https://app.example.com")
            .allowedMethods("GET", "POST")
            .allowCredentials(true);
}
```

Pair with the actuator fixed block under Patterns & Signatures (`include: health, info`, management on loopback).

### ASP.NET Core Pipeline Order

```csharp
// FIXED — developer exception page confined to non-production environments
var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureApplicationCookie(o => {
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
});
builder.Services.AddCors(o => o.AddPolicy("spa", p =>
    p.WithOrigins("https://app.example.com").AllowCredentials()));

var app = builder.Build();
if (!app.Environment.IsProduction()) {
    app.UseDeveloperExceptionPage();
}
app.UseHsts();
app.UseHttpsRedirection();
app.UseCors("spa");
```

### Hardened Kubernetes Pod Spec

```yaml
# FIXED — complete hardened Deployment pod template
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: registry.example.com/api@sha256:<digest>
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "1"
              memory: "512Mi"
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

Secrets as mounted read-only files rather than env vars:

```yaml
# FIXED — Secret delivered as read-only file mount
containers:
  - name: api
    volumeMounts:
      - name: creds
        mountPath: /var/run/secrets/db
        readOnly: true
volumes:
  - name: creds
    secret:
      secretName: db-credentials
```

### Terraform Guardrails

```hcl
# FIXED — deny all public access on every bucket
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FIXED — admin ports reachable from VPN/bastion range only
resource "aws_security_group_rule" "ssh_admin" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.8.0.0/24"]
  security_group_id = aws_security_group.admin.id
}
```

### CORS Corrected Configs Per Stack

```python
# FIXED — django-cors-headers
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
CORS_ALLOW_CREDENTIALS = True   # only because the SPA needs cookies; drop otherwise
```

```javascript
// FIXED — express cors
app.use(cors({
  origin: ["https://app.example.com"],
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
```

Principle regardless of stack: exact scheme+host allowlist; credentials only where a feature requires them; reject `Origin: null`; one global policy with no per-route loosening.

## Verification & Validation

### Scenario Tests (GIVEN/WHEN/THEN)

1. GIVEN the tightened CORS allowlist WHEN the legitimate SPA origin performs a credentialed fetch THEN the response echoes exactly that origin with `Access-Control-Allow-Credentials: true` AND preflight OPTIONS returns the permitted methods. Negative test: WHEN `Origin: https://evil.example` is sent THEN no per-origin ACAO echo occurs and no ACAC header is emitted.
2. GIVEN Secure-flagged session cookies and SSL redirect enabled WHEN a user completes login over HTTPS THEN the session persists across subsequent HTTPS navigation. Negative test: WHEN `http://` is requested THEN a redirect precedes any `Set-Cookie`, and no cookie is ever emitted on plaintext responses.
3. GIVEN the header baseline deployed WHEN fetching `/` and a forced 404 path THEN all baseline headers appear on both — validating the nginx `always` flag or app middleware ordering.
4. GIVEN actuator tightening WHEN requesting `/actuator/env` externally THEN the answer is 401/403/404; WHEN curling `127.0.0.1:9001/actuator/health` from the host THEN it returns 200.
5. GIVEN debug disabled WHEN forcing an unhandled exception in staging THEN the client receives a generic error page with a correlation ID — no traceback, framework names, settings values, or SQL text.
6. GIVEN the hardened pod spec WHEN running `kubectl exec deploy/api -- id` THEN output shows uid 10001 (non-root); WHEN writing to `/` fails while `/tmp` works THEN readOnlyRootFilesystem holds; WHEN `kubectl get networkpolicy -n prod` lists a default-deny policy THEN lateral movement is constrained.

### CI Regression Check Shape

```bash
#!/usr/bin/env bash
# pseudocode — ci/header-check.sh: fail the build when staging loses security headers
BASE="https://staging.example.com"
fail=0
check() { # check <header-name-lowercase> <required-substring-or-empty>
  local hdr="$1" want="$2" got
  got=$(curl -sI "$BASE/" | tr -d '\r' | grep -i "^${hdr}:")
  [ -z "$got" ] && { echo "MISSING: ${hdr}"; fail=1; return; }
  if [ -n "$want" ]; then
    case "$got" in *"$want"*) ;; *) echo "WEAK: ${got}"; fail=1 ;; esac
  fi
}
check strict-transport-security "max-age="
check content-security-policy "default-src"
check x-content-type-options "nosniff"
check referrer-policy ""
# first-party pages must not advertise wildcard CORS
curl -sI "$BASE/" | tr -d '\r' | grep -qi '^access-control-allow-origin: \*$' && { echo "WILDCARD ACAO"; fail=1; }
exit $fail
```

### Post-Fix Greps

```bash
rg -n "DEBUG\s*=\s*True" -g '!**/tests/**'                 # expect: hits only in never-deployed dev profiles
rg -n "exposure" -g 'application*.yml'                      # expect: health, info only
rg -n "allowedOriginPatterns\(.?\*.?\)"                     # expect: no hits
rg -n "verify\s*=\s*False|rejectUnauthorized\s*:\s*false"   # expect: hits only in test mocks
rg -n "privileged:\s*true|docker\.sock"                     # expect: no hits
```

## Severity Assessment

Score with CVSS v3.1; the vectors below are illustrative starting points — adjust for authentication state and scope before publishing.

| Finding class | Base severity | Illustrative vector | Rationale |
| --- | --- | --- | --- |
| `.env` served, `/actuator/env`/heapdump exposing working secrets | Critical–High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | secret content decides: live credentials enable full takeover (CWE-16/CWE-1188) |
| CORS reflecting arbitrary Origin with credentials | High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | victim-browser data theft via credentialed cross-origin reads (CWE-346) |
| Debug/error page without secret content | Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | internal path/stack disclosure aids further attacks (CWE-489/CWE-200) |
| Missing single low-value header | Low | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | defense-in-depth gap only |
| Server/version disclosure | Informational | not scored | reconnaissance value only |

Modifiers: internal-only network scope lowers one band; compensating NetworkPolicy or WAF coverage lowers one band with justification; exposure combined with an unauthenticated privileged surface (console, script runner) raises to Critical.

## Common False Positives

- `DEBUG = True` inside a settings module never referenced by the production entrypoint — check `DJANGO_SETTINGS_MODULE` in wsgi/manage/Dockerfile CMD first.
- `NODE_ENV=development` in a builder stage overwritten by the final image ENV or the k8s manifest — resolve the effective value per deploy target.
- flask-cors reflection on stateless token-auth APIs without cookies: reflection alone lacks credential theft impact — downgrade accordingly.
- Wide CORS on genuinely public, credential-less endpoints — hygiene note, not High.
- `verify=False` / `curl -k` in unit-test harnesses, offline fixtures, or scripts targeting placeholder domains.
- `0.0.0.0/0` on ports 80/443 for intended-public services — flag only admin/database ports.
- securityContext present in chart `values.yaml` but overridden by release-time `--set` — inspect rendered output (`helm template`) rather than source files.
- Actuator `health` and `info` exposure is the Boot 2/3 default and benign; flag only sensitive endpoints or metadata-rich `/info`.
- `X-Frame-Options` absent but CSP `frame-ancestors` present and enforced — modern equivalent covers it.
- HSTS absent on an HTTP-only internal hostname that never serves TLS — note as Low hygiene.
- Directory listing on an intentionally shared `/static/` archive — confirm intent with the owner before reporting.
- Seed users created only in CI-ephemeral databases excluded from the prod deploy path.

## References

CWE entries:

- CWE-16 Configuration — <https://cwe.mitre.org/data/definitions/16.html>
- CWE-1188 Insecure Default Initialization of Resource — <https://cwe.mitre.org/data/definitions/1188.html>
- CWE-346 Origin Validation Error — <https://cwe.mitre.org/data/definitions/346.html>
- CWE-489 Active Debug Code — <https://cwe.mitre.org/data/definitions/489.html>
- CWE-200 Exposure of Sensitive Information to an Unauthorized Actor — <https://cwe.mitre.org/data/definitions/200.html>
- CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute — <https://cwe.mitre.org/data/definitions/614.html>
- CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag — <https://cwe.mitre.org/data/definitions/1004.html>

OWASP:

- OWASP Top 10 A05:2021 Security Misconfiguration — <https://owasp.org/Top10/A05_2021-Security_Misconfiguration/>
- Cheat Sheet Series: Content Security Policy — <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
- Cheat Sheet Series: HTTP Strict Transport Security — <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html>
- Cheat Sheet Series: Transport Layer Protection — <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html>
- Cheat Sheet Series: Clickjacking Defense — <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
- Cheat Sheet Series: Session Management — <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
- Cheat Sheet Series: Cross-Site Request Forgery Prevention — <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- Cheat Sheet Series: Docker Security — <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- Cheat Sheet Series: Kubernetes Security — <https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html>
- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>

Other stable references:

- MDN CORS — <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>
- MDN Content-Security-Policy — <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy>
- Spring Boot Actuator reference — <https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html>
