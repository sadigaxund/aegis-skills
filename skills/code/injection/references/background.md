# Injection — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, payload tables, and remediation recipes.

## How this class emerged

Dynamic web applications of the late 1990s assembled programs as text. A script
read form fields, pasted them into a query or a shell command string, and handed
the result to an interpreter. That pattern worked, so it spread everywhere before
anyone formalized why it was dangerous. The first generation of "hacker
literature" treated these bugs as isolated curiosities; the industry gradually
recognized them as one recurring design error rather than thousands of accidents.

The class then re-emerged every time a new interpreter appeared:

- OS command injection predates the web entirely — any era that glues shell
  commands together from variables has it.
- Template injection arrived when template engines gained logic (loops, calls,
  filters) in the 2000s, and became acute when products let users edit templates.
- Expression-language injection grew out of Java-era frameworks evaluating EL,
  OGNL, and SpEL strings inside request handling.
- NoSQL operator injection appeared once document stores accepted structured
  query objects built directly from JSON request bodies in the 2010s.
- Lookup-string injection (JNDI) culminated in the Log4Shell disclosure of
  December 2021, which showed a logging library treating message text as a
  directory-lookup instruction.
- The lesson generalizes: every new DSL — search syntax, spreadsheet formulas,
  filter languages — recreates the same boundary problem.

## Anatomy: one bug, many grammars

Every injection is the same event at different boundaries: attacker-controlled
bytes cross into a region the interpreter parses as *grammar*, not *data*.

```python
user = request.args.get("q")
cursor.execute("SELECT title FROM notes WHERE owner = '" + user + "'")
```

Walkthrough:

1. The developer intends the query text to be fixed grammar and `user` to be a
   data value inside a quoted literal.
2. The attacker submits `x' OR '1'='1` instead of a name.
3. The first `'` closes the string literal early; everything after is parsed as
   SQL keywords. The predicate becomes always-true and returns rows the caller
   does not own.
4. Nothing "broke" — the interpreter did exactly what the bytes said. The bug is
   that nobody separated the two channels.

The identical shape recurs at other boundaries:

```python
subprocess.run("convert " + filename + " out.png", shell=True)
# filename = "report.png; id"  -> semicolon starts a second command

render_template_string(user_bio)
# bio contains {{ 7*7 }}      -> template engine evaluates arithmetic,
#                                and worse, object traversal to code
```

Parameterized queries are not clever escaping. They work because the wire
protocol carries the statement and its values in *separate channels*: the
grammar can never be reshaped by a value, however hostile. The same channel
separation exists in argv-array process spawning (arguments never meet a shell),
XPath variable bindings, LDAP escaping per RFC 4515's grammar, and template APIs
that render user text strictly as data.

## Why naive fixes fail

One subsection because the failure modes rhyme across all sub-types:

- **Blacklists** enumerate bad strings, but interpreters accept encodings,
  comments, case changes, and nesting faster than lists grow (`SELSELECTECT`
  survives naive keyword deletion; double-encoded `%2527` defeats single-pass
  decoding). You cannot enumerate an infinite language.
- **Hand-rolled escaping** must match one dialect exactly. Multibyte charsets
  have swallowed backslashes and resurrected quotes after "safe" escaping;
  cmd.exe quotes differently from POSIX shells; HTML entities do nothing inside
  a JS string context. Context-blindness is the root error.
- **Client-side validation** happens in territory the attacker owns. Any HTTP
  client can replay a request with arbitrary values; browser-side checks are UX,
  not security.
- **Obscurity** (hidden admin routes, unguessable IDs, renamed endpoints) only
  lowers discoverability. Endpoints leak through bundles, proxies, logs, and
  word of mouth; unguessability is not authorization.
- **WAF-only defense** is detective, not preventive. Encoding layers, protocol
  quirks, and dialect-specific syntax routinely bypass signature filtering, and
  a WAF says nothing about second-order flows already stored in your database.

## Common misconceptions

1. "My ORM prevents injection." ORMs parameterize their typed helpers but ship
   raw escape hatches (`raw`, `text`, `$queryRawUnsafe`, `whereRaw`) whose
   misuse reintroduces concatenation — often on the sort/filter paths developers
   think are "just identifiers".
2. "Integers don't need quoting, so they're safe." Unquoted numeric contexts are
   injectable too; `1 OR 1=1` needs no quote at all. Safety comes from strict
   bounded casting plus binding, never from absence of quotes.
3. "Stored procedures fix SQL injection." A procedure that builds SQL from its
   parameters via string concatenation is injectable inside the database.
4. "NoSQL means no injection." Document stores accept operator objects
   (`{"$ne":1}`) and server-side JavaScript (`$where`) straight from JSON bodies;
   Redis Lua scripts concatenate just like SQL.
5. "Escaping input is the fix." Each sink needs its own output-side neutralizer.
   One global input scrubber cannot match every downstream grammar, and it
   corrupts legitimate data (O'Brien, `<3`, `C:\Users`).
6. "The WAF blocks payloads, so the code is fine." WAFs are bypassable layers;
   findings stand on code-level evidence, not on gateway confidence.
7. "Second-order injection is exotic." The database is just another propagator.
   A value stored safely today gets concatenated next month by a report job that
   trusted it because "it came from our own DB".

## How professionals think about it today

Modern practice treats injection as a *family tree under one root cause*, then
specializes controls per branch. The taxonomy mirrors SKILL.md's sections:

| Branch | Sub-types | Defining control |
|---|---|---|
| Query-language (SQL/HQL) | value contexts, identifier contexts (ORDER BY/table), LIKE patterns | driver binding + closed allowlist maps |
| NoSQL / key-value | operator injection, server-side JS (`$where`, Lua), selector widening | scalar type coercion at boundary; ban JS eval operators |
| OS command | shell-string injection, argument injection into argv wrappers | argv arrays without shell; reject option-looking tokens |
| Template (SSTI) | template-source vs template-name control; sandboxed engines | user text only ever binds as data; fixed template enums |
| Code/expression eval | eval family, format-string ownership, SpEL/OGNL/EL, JNDI lookups | delete dynamic evaluation; dispatch tables; pinned lookup targets |
| Directory/markup queries | LDAP filters, XPath predicates | RFC 4515 escaping; XPath variable resolvers |
| Line-oriented output | CRLF/header injection, log-line forging | CR/LF rejection on header-bound values; structured logging |

Two habits distinguish professional analysis from pattern matching:

- **Grammar-first reasoning.** Identify the sink's parse context before writing
  any payload; the context dictates which characters even matter.
- **Taint discipline over intuition.** Follow source -> propagator -> sink
  mechanically, treat storage as propagation, and demand the neutralizer sit
  between the last propagator and the interpreter.

Severity thinking follows reach: pre-auth injection on privileged infrastructure
is Critical regardless of exploit elegance; blind delay-only oracles rate lower
but still get fixed, because constructability proven in code does not expire.

## Read next

In `../SKILL.md`: **Mental Model** (the sink-context grammar table),
**What To Check** (per-class procedures), **Patterns & Signatures**
(dangerous/safe API matrices), **Taint Tracing Guidance**, **Remediation**
(class-by-class fixes), **Common False Positives** (safe patterns that merely
look dangerous).

Sibling modules: `../deserialization/SKILL.md` (eval-adjacent gadget chains),
`../ssrf-url-security/SKILL.md` (URL-fetch sinks reached through command and
template bugs), `../file-handling/SKILL.md` (filename normalization and
converter pipelines), `../web-client/SKILL.md` (the browser-side half of the
injection family).
