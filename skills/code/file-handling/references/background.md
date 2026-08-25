# File-Handling Attacks — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the join-algebra tables, payload ladders, and per-stack
containment snippets.

## How this class emerged

File bugs predate the web. Unix inherited `..` as parent-directory notation
from its earliest filesystems, and every program that ever joined "trusted
prefix" + "user string" inherited the traversal bug with it. Web applications
industrialized the pattern: dynamic pages needed to load templates, images,
and scripts by name, so filenames flowed from URLs into filesystem APIs within
a few years of the first dynamic sites.

Each subsequent decade added a sub-family:

- **Include-driven execution (2000s).** PHP's `include $user_page` turned
  arbitrary reads into arbitrary code execution, and stream wrappers
  (`php://filter`, remote URLs) multiplied what a single parameter could do.
  Language-agnostic analogues followed: dynamic imports in Node, plugin
  loaders in Python, view resolvers in Java.
- **Upload weaponization.** As platforms accepted user content, validation
  arms races began — extension blacklists beaten by case tricks and alternate
  extensions, MIME checks beaten because declared types are client text,
  magic-byte checks beaten by polyglot files, and landing directories that
  made any surviving file executable.
- **Archive attacks.** Extraction code honored entry names containing `../`
  (Zip Slip) or planted symlinks (tar), letting a compressed file write outside
  its destination; compression ratios enabled decompression bombs as a
  resource cousin handled by the DOS module.
- **Modern storage layers.** Object stores replaced some filesystem calls but
  preserved the shape: attacker-influenced keys overwrite other tenants'
  objects when tenant prefixes come from input.

Through all of it the core defect never changed: attacker bytes reach a path,
and no layer between them and the kernel canonicalizes and re-checks.

## Anatomy: one join away from /etc/passwd

Minimal generic vulnerable snippet:

```javascript
app.get('/reports/:name', (req, res) => {
  res.sendFile(path.join(__dirname, 'reports', req.params.name));
});
```

Failure walkthrough:

1. The developer treats `name` as a leaf filename inside `reports/`.
2. The request `/reports/..%2f..%2fconfig%2fsecrets.json` decodes to
   `../../config/secrets.json`; the join produces a path escaping upward.
3. `sendFile` resolves the final path and serves whatever is there — source
   archives, credential files, anything readable by the process user.
4. No error appears; the response looks like an ordinary download. Detection
   requires reasoning about resolution order, not observing crashes.

The same single-join shape covers uploads (`move_uploaded_file($dir . $_FILES['f']['name'])`),
deletion (`unlink($dir . $_GET['name'])`), includes (`include $page`), and
archive extraction (`new File(destDir, entry.getName())`). Containment checks,
when present, fail for their own reasons: comparing before decoding, prefix
checks without trailing separators, or symlink resolution skipped entirely.

## Why naive fixes fail

Each tempting defense below fails against documented bypasses; SKILL.md's
Mental Model tables show which layer defeats which check.

- **Blacklisting `../`**: defeated by URL encoding (`%2e%2e%2f`), double
  encoding where two decodes occur, backslashes on Windows, and rebuilds like
  `....//` after naive iterative removal.
- **Filtering before framework decoding**: encoded payloads arrive at the sink
  already decoded; ordering decides everything.
- **`startsWith(base)` without separator**: base `/var/up` accepts candidate
  `/var/uploads-attacker/x`.
- **Case-sensitive comparison on Windows/macOS targets**: `BASE.TXT` slips past
  a check for `base.txt`.
- **`basename()` as sanitizer on POSIX**: `basename('..\\x')` on Linux returns
  `..\x` intact; it also destroys legitimate subpaths while missing platform
  separators.
- **Extension blacklist for uploads**: `.php` misses `.php5/.phtml/.phar`;
  `.aspx` misses `.ashx/.asmx`; case variants defeat lowercase comparisons;
  multi-extension handling varies per server.
- **Client-declared Content-Type as validation**: it is attacker text; absence
  of magic-byte verification means zero content control.
- **Checking existence then opening**: the TOCTOU window lets a symlink swap
  the target between check and use; only open-time flags or post-open
  re-resolution close it.

## Common misconceptions

1. **"path.join protects me."** Joining functions differ per language: Node's
   `join` contains absolute paths but Python's `os.path.join` lets a rooted
   argument *replace* the base entirely. Knowing your language's algebra is
   mandatory, not optional.
2. **"Browsers block traversal."** Browsers collapse dot-segments in URL paths
   before sending; payloads therefore live in query values or need raw-socket
   tools. Server-side filters see decoded values regardless.
3. **"Magic bytes prove file type."** Signatures confirm a header, not the
   body; polyglot files satisfy sniffers while carrying payloads. Re-encoding
   through an image pipeline is the robust control, not deeper sniffing.
4. **"Storing uploads outside the webroot is enough."** It removes direct
   execution but not traversal into other app files via read/download/delete
   sinks elsewhere.
5. **"Object storage keys are just strings."** Flat namespaces still collide:
   attacker-set prefixes overwrite sibling tenants' objects and poison listing
   logic when keys are built from input.
6. **"Archives are safe if we virus-scan them."** Scans test content, not entry
   names or link entries; Zip Slip and tar symlinks are structural, not
   signature, problems.
7. **"A stored filename is clean because we sanitized at upload."** Filenames
   persisted in databases are propagators: next month's export/archive feature
   concatenates them into new paths. Trace to origin every time.

## Modern taxonomy map

Matches the family list in `../SKILL.md`'s Scope & Objectives section:

| Family | Essence | Canonical sink |
|---|---|---|
| Path traversal | `../` or absolute paths escape intended root | read/write/serve/delete joins |
| LFI/RFI | Include/import steered to local or remote files | PHP include, dynamic require/import |
| Arbitrary upload | Dangerous type lands in executable context | multipart handlers, uploader classes |
| Arbitrary download/read | ID/name maps straight to disk lookup | export/invoice/attachment endpoints |
| Arbitrary deletion | Config/session/log removal chains | unlink/rmtree fed by request data |
| Archive extraction | Entry names/links escape destination | extract loops honoring entry metadata |
| Symlink/race | State swaps between containment check and open | predictable temp names, shared dirs |
| Storage-layer confusion | Tenant prefixes built from input | S3/GCS key interpolation |

Severity intuition: include-style sinks (execution) start Critical; traversal
read/write reaching credentials or web-executable zones is High; bounded
reads of low-sensitivity files trend Medium.

## Read next

Return to `../SKILL.md` by section, in this order for a first audit pass:

1. **Mental Model** — the two questions (does input reach a path; does the final
   resolved path stay inside root) plus join algebra and decode layers.
2. **What To Check** — per-family checklists including the containment-defect
   list and the upload three-leg validation demand.
3. **Where To Look** — high-yield route/controller names and ripgrep starting points.
4. **Patterns & Signatures** — dangerous-vs-safe call table, vulnerable/fixed
   snippets per language, and the payload cheat-sheet ladder.
5. **Remediation** — allowlist-first patterns and validated archive-extraction loops.
6. **Common False Positives** — before flagging basename misuse or static roots,
   read what does not qualify.

Sibling modules owning adjacent defects:

- `../web-client/` — stored XSS served from uploaded SVG/HTML payloads.
- `../denial-of-service/` — zip-bomb and decompression-amplification math.
- `../configuration-hardening/` — bucket policies, IAM, server static-root misconfig.
- `../business-logic-races/` — business-flow impact of TOCTOU windows.
