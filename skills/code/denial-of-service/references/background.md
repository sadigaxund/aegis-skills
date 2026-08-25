# Denial of Service & Resource Exhaustion — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why*; SKILL.md carries the checklists, greps, harnesses, and remediation tables.

## How this class emerged

Application-layer denial of service was not born with the cloud; it was born the
first time a program spent work proportional to something a stranger controlled.
Three strands converged into the modern class.

The first strand is algorithmic complexity itself. In 2003, Scott Crosby and Dan
Wallach presented work at USENIX Security showing that common hash-table
implementations could be driven into their worst case by crafted inputs — an
early, rigorous statement that *average-case fast* is not a security property.
The same year-period produced the first systematic treatments of regular
expression blowup. The insight was uncomfortable: a validator that "works" on
every test case can still be a remotely triggerable infinite-ish loop.

The second strand is format amplification. Compressed formats and recursive data
formats were designed assuming the producer and consumer want roughly the same
thing. XML gave the world a memorable demonstration: nested entity definitions
(the "billion laughs" shape) let a few hundred bytes of document text direct a
parser to expand billions of characters. CWE-409's own curated history records
XML-bomb issues in parsing libraries going back to 2003-era entries, and its
demonstrative example shows a DTD whose deepest entity expands to 2^32
characters — four gigabytes — from a document you could fit in a tweet. Zip
bombs generalize the trick to any container where output size is chosen by the
sender and discovered by the receiver only during extraction.

The third strand is scale economics. As applications moved to shared runtimes
(event loops, fixed thread pools, connection pools) and started spending real
money per request (SMS, transcodes, inference APIs), the gap between "small
request" and "cheap request" became an exploitable surface of its own. A flaw
that once meant one annoyed user now means a drained worker pool or an
unbounded provider bill. The response was a new engineering vocabulary — clamps,
budgets, quotas, idempotency keys — and, on the regex side, engines like RE2,
which has been used in production at Google since 2006 and guarantees that match
time is linear in input length precisely so hostile patterns cannot hurt it.

The through-line: availability failures are usually *ratio* failures. The
attacker does not send a big thing; they send a small thing that obligates a big
thing. Auditing means hunting every place the ratio is uncapped.

## Anatomy: one pattern, thirty characters

The minimal vulnerable example needs only a route with a backtracking-engine
regex validator (JavaScript shown; the same shapes apply in Python, PCRE/PHP,
.NET, Java, Ruby):

```js
// VULNERABLE: username must look like dot-separated word chunks
app.post("/signup", (req, res) => {
  if (!/^([a-z0-9_]+\.?)+$/i.test(String(req.body.username))) {
    return res.status(400).json({ error: "bad username" });
  }
  // ...create account...
});
```

Nothing looks wrong: no `.*` soup, anchored ends, plausible character classes.
The flaw is structural — a quantified group `(…)+` whose body itself contains a
quantifier with ambiguous overlap (`[a-z0-9_]+` and `\.?` can both consume the
same stretch of characters in different ways).

Failure walkthrough for one request, `username = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"`:

1. The regex engine starts matching greedily. For each `a`, there are multiple
   ways to split it between the outer repetition, the inner `[a-z0-9_]+`, and
   the optional dot — so the engine commits to one and remembers the others.
2. The trailing `!` matches none of the allowed classes, so the overall match
   fails at `$`.
3. On failure, a backtracking engine rewinds to its most recent remembered
   choice point and tries the alternative split — then fails again, rewinds
   again. The number of distinct splits grows multiplicatively with length;
   OWASP's classic `^(a+)+$` walkthrough counts 16 possible paths for a 4-letter
   probe and 65,536 for 16 letters, doubling per added character.
4. Thirty characters mean billions of retries. The worker executing the request
   spins at 100% CPU for minutes-to-hours. It never times out, logs an error, or
   crashes — it simply stops serving anyone else.
5. Repeat with a handful of concurrent requests (or hit a Node event loop, where
   ONE blocked synchronous call freezes ALL requests): the endpoint, then the
   process, then the fleet is unavailable. Total attacker cost: one POST.

The same anatomy recurs across the class with different carriers:

```text
POST /import      multipart zip, 1 MB stored -> 1 GB extracted   # memory/disk ratio
GET  /items?limit=-1                                              # clamp bypass ratio
POST /graphql     { items: [10000 elements] }                    # 10k lazy DB queries
POST /webhook     triggers paid SMS per item, replayable         # dollar ratio
```

Each is a contract nobody wrote: extraction without counting output, parameters
without ceilings, collections without cost analysis, side effects without
quotas. The fix family is always the same shape — put a *counted, enforced
clamp* between attacker-chosen input and expensive work.

## Why naive fixes fail

- **Length gate placed after the match.** `test(input) || input.length > 256`
  ordering still pays full backtracking cost before rejecting. The gate must
  precede the regex, or the fix does nothing.
- **Adding more regexes to the validator.** Chaining additional patterns adds
  new ambiguity instead of removing it; the reliable repairs are structural —
  collapse overlapping alternations into character classes, delete redundant
  outer quantifiers, or hand the job to a parser.
- **Reaching for timeouts that the engine does not have.** JavaScript offers no
  regex timeout and no atomic groups; PHP's `pcre.backtrack_limit` merely aborts
  runaway matches after burning up to the step budget AND silently turns the
  failed-limit case into a false-negative match. A cap you cannot observe is not
  a control.
- **Trusting the proxy's body-size cap.** nginx limits only traffic THROUGH the
  proxy; direct-to-origin routes skip it. Worse, a byte cap does not bound a
  quadratic loop over 100k tiny JSON items — count-based and depth-based clamps
  are separate controls.
- **Clamping without integer parsing or sign checks.** `limit = min(param, 100)`
  happily accepts `limit=-1`, which many ORMs interpret as "no limit". Negative
  and non-numeric garbage defeat naive clamps.
- **Believing archive headers.** Declared uncompressed sizes and entry counts
  come from the attacker; guards that trust them pass bombs straight through.
  Output bytes must be counted during the copy itself.
- **Moving heavy work to a queue without quotas.** Offloading transcodes or
  fanout emails protects the request path but relocates the bomb; without
  per-tenant budgets and dedup keys the worker farm dies instead.

## Common misconceptions

1. "`(a+)+$` is fine here — we use a serious language." Danger follows the
   ENGINE, not the language's reputation: Go's stdlib and Rust's `regex` crate
   are linear-time and immune to catastrophic backtracking; V8, Python `re`,
   PCRE, .NET, Java, and Ruby all backtrack and all blow up on identical shapes.
2. "It's a small upload, so it's a cheap request." Compression ratios, base64
   expansion (~4/3 size), image pixel dimensions, and archive nesting all make
   stored bytes a poor proxy for processed bytes.
3. "We rate-limit, therefore DoS is handled." Rate limiting throttles MANY
   requests; it does nothing about ONE request that hangs a worker, and
   attackers key their buckets differently than your limiter does.
4. "Our handlers are async, so nothing blocks." `async` wrappers around
   `pbkdf2Sync`, `inflateSync`, or multi-MB `JSON.parse` still pin the event
   loop; pooled helpers queue behind a libuv threadpool that defaults to four.
5. "Framework defaults will save us." Defaults vary wildly and change: some
   stacks ship no body cap at all, others cap only multipart. The audit question
   is what the DEPLOYED configuration says, never what folklore says.
6. "Pagination has a default, so it's bounded." A default only applies when the
   parameter is ABSENT; an unclamped override (`limit=99999999`) walks straight
   past it.
7. "Enabling compression is free performance." For attacker-supplied payloads,
   compression is the attacker's lever — they choose the ratio, you pay the
   decompression bill.

## How professionals think about it today

Modern practice reads every sink as source → missing-clamp → expensive
operation, and prices the worst achievable amplifier per endpoint. The taxonomy
mirrors SKILL.md's scope sections:

| Class | Amplifier | Clamp that belongs there |
|---|---|---|
| ReDoS / catastrophic backtracking | input chars : match time | length gate BEFORE match; linear rewrite; engine timeout |
| Unbounded allocation/parsing | stored bytes : allocated bytes | byte/count/depth/ratio caps at the parser boundary |
| Algorithmic complexity attacks | collection size : operations | parse-boundary item caps; O(n log n)-or-better algorithms |
| Pagination/enumeration cost | parameter value : rows serialized | default AND hard ceiling, integer-parsed, sign-checked |
| Event-loop/thread-pool blocking | one request : frozen peers | sync APIs off the request path; sized pools; server timeouts |
| Cache/log fill | distinct values : permanent entries | TTLs, cardinality caps, eviction policy, truncated error logging |
| Third-party cost amplification | request : dollars | rate limit + idempotency + async queue with quotas |

Severity follows the two structural questions: single-request vs sustained
traffic decides the ceiling, and the OBSERVED amplifier (bytes-in : bytes-out,
elements : queries, chars : milliseconds) is the strongest evidence a report can
carry. Engine semantics decide false positives — the identical pattern is a
finding in Node and a non-issue in Go.

## Read next

In `../SKILL.md`: **Scope & Objectives** (in/out of scope line), **Mental Model**
(four resource pools, two structural questions), **What To Check**
(per-class procedures), **Where To Look** (stack-by-stack config keys and
defaults), **Patterns & Signatures** (vulnerable-shape catalog, engine table,
ripgrep sweeps, offline timing harness), **Taint Tracing Guidance**
(source→sink clamp matrix), **Exploitation & Reproduction** (bounded probes,
payload cheat-sheet), **Remediation** (caps, rewrites, streaming, queues),
**Verification & Validation**, **Severity Assessment**, **Common False
Positives**.

Sibling modules: `../deserialization/SKILL.md` (XML entities/XXE parser
hardening), `../file-handling.md` via `../file-handling/SKILL.md` (tar entry
bombs, path traversal in archives), `../api-security/SKILL.md` (rate limiting,
GraphQL depth/cost budgets), `../authn-session/SKILL.md` (session-creation spam
filling stores).
