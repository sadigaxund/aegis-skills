# Memory Safety — Background Primer

Optional depth layer for `../SKILL.md`. Zero-internet reading: no links required,
no tooling assumed, no prior security background assumed. This file teaches the
*why* behind memory-safety auditing; SKILL.md carries the sink tables, audit
ladders, sanitizer procedures, and remediation recipes.

## How this class emerged

C was created at Bell Labs in the early 1970s as a systems language for Unix.
Its defining trade was deliberate: arrays decay into pointers, arithmetic on
addresses is ordinary math, and nothing at runtime checks that an index stays
inside an allocation. On hardware where every cycle and byte cost real money,
bounds checking was a luxury, and the programmers were trusted to count
correctly. The 1978 K&R book and the 1989 ANSI standard froze those semantics
into several decades of infrastructure.

The defect class was understood from the start — "run off the end of an array"
is as old as the language — but it became a *security* class when programs
began accepting bytes from strangers. In November 1988 the Morris worm spread
across the young internet partly by exploiting a stack buffer overflow in the
finger service: the daemon read input with `gets()`, a function with no length
parameter, so there was no way to bound what it wrote. One incident response
that followed was the creation of the first coordinated vulnerability-response
institution (CERT). The lesson hardened into doctrine: memory corruption is
remotely exploitable at network scale, by strangers.

In 1996, Aleph One's Phrack article "Smashing the Stack for Fun and Profit"
handed the technique to a mass audience: overwrite a stack buffer far enough to
reach the saved return address, redirect execution. The following decade was an
arms race between exploitation and mitigation. Stack canaries grew out of
late-1990s academic work ("StackGuard") into default compiler behavior;
address-space layout randomization (ASLR) and non-executable data pages (NX/DEP)
spread through mainstream operating systems during the 2000s; attackers answered
with return-to-libc and chained-gadget techniques (ROP) that reuse existing
executable code instead of injecting any. This is why SKILL.md frames every
mitigation as detect-or-raise-cost and never as a fix.

Meanwhile the taxonomy grew finer. Passing attacker-controlled text where a
`printf`-family format template belongs was publicly systematized in security
literature around 2000: `%x`/`%p` walk argument slots nobody supplied
(information leak), `%n` writes printed-character counts through pointer slots
(write primitive). Integer truncation and signedness confusion earned their own
category once researchers showed allocation-size arithmetic wrapping to
near-zero — a huge request becoming a tiny buffer. Uninitialized-memory
disclosure became front-page news in April 2014, when OpenSSL's heartbeat
handler echoed back more bytes than it had filled in its buffer — "Heartbleed,"
an out-of-bounds read leaking keys and session data from live server memory.
From the mid-2010s onward, coverage-guided fuzzing toolkits industrialized the
discovery of all these classes at scale.

The final chapter is the migration story. Managed runtimes (Java, C#, later Go)
absorbed application development during the late 1990s and 2000s but left
kernels, drivers, codecs, parsers, browsers, and embedded firmware in C/C++ —
and vendor post-mortems kept attributing large majorities of their critical
vulnerabilities to memory-safety classes. Rust, reaching version 1.0 in 2015,
demonstrated the alternative model: *ownership* gives every byte exactly one
owner; *borrowing* lets others use it only within proven lifetimes; and the
compiler rejects out-of-bounds access, use-after-free, double free, and
uninitialized reads in safe code outright — all without garbage collection.
What C catches in production (or never), Rust catches at compile time. Large
production adopters through the late 2010s and 2020s reported falling
memory-safety bug rates as safe-language share grew, and national cybersecurity
agencies began formally recommending memory-safe languages for new systems
code. Reality remains mixed-language: every `extern "C"` boundary, `-sys`
crate, and `unsafe` block re-opens the door — which is exactly where this
module audits.

## Anatomy: one length field, one fixed buffer

```c
/* greet.c — the entire vulnerable surface */
void greet(int sock) {
    char name[32];
    char out[64];
    int n = read_name(sock, name);   /* attacker chooses n */
    if (n > 0)
        memcpy(out, name, n);        /* no capacity comparison anywhere */
    send_line(sock, out);
}
```

Failure walkthrough:

1. **Source.** `read_name` returns whatever the wire declared — up to the
   protocol's maximum, say 1024. An attacker sends a 300-byte name.
2. **The check answers the wrong question.** `n > 0` validates positivity, not
   capacity. SKILL.md's central question — WHO controls the length, DOES it
   match the allocation? — fails on the second half.
3. **The write.** `memcpy` copies 300 bytes into `out[64]`; 236 bytes land in
   whatever follows the frame: neighboring locals, the stack canary,
   eventually a saved return address.
4. **Outcomes branch on luck and platform.** Crash (canary trips or the return
   goes somewhere unmapped), silent corruption (adjacent locals overwritten;
   behavior drifts subtly), or hijack (return address replaced with a crafted
   value). The heap variant of the same bug smashes adjacent allocations and
   allocator metadata instead — different geometry, same write primitive.
5. **The fix is one comparison in matching types before the copy**:
   `if ((size_t)n <= sizeof out)`. Every class in this module is a variation on
   that missing comparison (Bounds axis), on misreading what the number means
   (Type axis: bytes vs elements, truncated casts), or on whether the memory is
   still valid at all (Lifetime axis).

## Why naive fixes fail

- **Swapping `strcpy` for `strncpy`.** When the source fits exactly, `strncpy`
  silently omits the NUL terminator, so the "fixed" code walks past the buffer
  downstream via `strlen`/`printf`. The portable fix terminates always:
  `snprintf(dst, size, "%s", src)`.
- **Checking the length against the packet, not the destination.** Validation
  passes against source-side capacity while the fixed-size destination still
  overflows — SKILL.md's packet-parsing vulnerable/fixed pair demonstrates
  precisely this trap.
- **Casting away sign-compare warnings.** `(uint16_t)n` turns 70000 into 4464;
  the guard now protects the wrapped value while the copy uses the original.
  Widening to `size_t` end-to-end is the fix; silencing the warning is not.
- **Shipping hardening flags and declaring victory.** Canaries detect some
  linear stack writes after the fact; ASLR falls to any single info-leak bug;
  NX falls to gadget reuse. Hardening raises exploit cost; it does not close
  the defect, and reports must never be downgraded because a binary "ships
  hardened."
- **Freeing "earlier" to fix a use-after-free.** Moving the release above more
  error paths multiplies dangling windows and double-free branches. Lifetime
  fixes restructure ownership (capture-then-release, RAII, refcount audits);
  they do not reorder `free` hopefully.
- **Zeroing freed buffers to make UAF harmless.** Compilers elide dead stores,
  aliases persist, and reuse re-populates the memory anyway. UAF is prevented
  by making reuse impossible, not by shaping its contents.
- **Rewriting in Rust while leaving the FFI seam unvalidated.**
  `slice::from_raw_parts(ptr, len)` trusts caller-supplied `len` exactly like
  `memcpy` trusted its third argument, and a panic unwinding across
  `extern "C"` is undefined behavior. After the rewrite, the boundary *is* the
  bug class.

## Common misconceptions

1. "Managed languages ended this." Every JVM/.NET/Python/Node deployment links
   native libraries beneath safe callers; parsers, codecs, TLS stacks, and
   crypto primitives are still written in C/C++. FFI inherits everything.
2. "Heap bugs are milder than stack bugs." Different geometry, same write
   primitive; heap overflow corruption of neighbor chunks and metadata is often
   easier to aim than stack smashing.
3. "Off-by-one errors are quality nits." A single terminator byte corrupts
   adjacent state; historically, one-byte heap overflows have sufficed to flip
   allocator metadata toward control-flow impact.
4. "Use-after-free crashes reliably." Freed memory frequently retains plausible
   contents; UAF can run silently for months, corrupting only occasionally —
   ideal conditions for targeted exploitation.
5. "Uninitialized memory just makes results random." Attackers shape heap and
   stack contents beforehand, turning "random" bytes into attacker-chosen ones;
   sending whole uninitialized structs leaks whatever preceded them.
6. "Rust is immune." Safe Rust is. `unsafe` blocks, transmutes, unchecked
   `from_raw_parts`, panics crossing FFI, and legacy `mem::uninitialized`
   reintroduce every classic bug behind one keyword — hence SKILL.md's
   per-block invariant checklist.
7. "Leaks are performance nits, not security." Error-path and fd leaks
   concentrate exactly where tests never go; unbounded user-keyed caches turn
   them into remote memory-exhaustion denial of service over time.

## How professionals think about it today

Modern practice reduces every candidate finding to stress on one of three axes,
then demands evidence per axis — mirroring SKILL.md's Mental Model:

| Axis | The question | Failure classes | Where SKILL.md works it |
|---|---|---|---|
| Bounds | how many bytes touched vs allocated | stack/heap overflow, out-of-bounds read, off-by-one terminator | banned/risky sink tables, index-arithmetic checks |
| Type | how those bytes and counts are interpreted | truncation/overflow, signedness mixing, format strings, length-unit mismatches | integer rules table, format-string sweeps |
| Lifetime | how long the bytes stay valid, who owns them | use-after-free, double free, dangling views, container invalidation, uninitialized use | lifetime walk-throughs, unsafe-Rust checklist |
| Resource | does every path release what it acquires | error-path leaks, fd leaks, unbounded caches, reconnect churn, exception gaps | leak/failure-pattern signature table, soak assertions |

Four doctrines organize current practice. First, *trace the length variable,
not the buffer*: buffers are easy to spot, lengths are where bugs hide, and
every cast/arithmetic/branch on the path changes the worst case. Second,
*mitigations are not fixes* — hardening belongs in the report as context, never
as resolution. Third, *dynamic tools confirm static findings*: ASAN/MSAN/LSAN
builds and coverage-guided fuzzers catch what review misses, but a static
evidence chain (sink line, length origin, missing check, reachability) stands
on its own when compilation is impossible. Fourth, *migration is economic, not
absolute*: strangler-pattern rewrites target the highest-risk parsers first,
keep the ABI thin, and document ownership contracts at every boundary —
because the industry's endpoint is mixed-language code where safety depends on
the seams being explicit.

## Read next

In `../SKILL.md`: **Scope & Objectives** (language and defect-class inventory),
**Prerequisites & Vocabulary**, **Mental Model** (the three-axis table and
stack-vs-heap nuance), **What To Check** (inventory-first procedure, audit
question ladder, per-class checks including leak patterns), **Where To Look**
(reachability ranking, hotspots), **Patterns & Signatures** (banned/risky sink
tables, regex signatures, vulnerable/fixed pairs, integer rules), **Taint
Tracing Guidance** (sources, sinks, tracing the length variable), **Exploitation
& Reproduction** (local ASAN harnesses, reading sanitizer reports), **Remediation**
(call replacement, hardening flags, fuzzing adoption), **Verification &
Validation** (GIVEN/WHEN/THEN scenarios, CI sanitizer gates), **Severity
Assessment** (CWE mapping and rating rubric), **Common False Positives**,
**References**.

Sibling modules: `../denial-of-service/SKILL.md` (unbounded caches and resource
exhaustion — the availability half of the leak layer), `../injection/SKILL.md`
(attacker-reachable sinks deciding severity of parser bugs), 
`../secrets-data-exposure/SKILL.md` (what leaked or over-read memory exposes),
`../supply-chain/SKILL.md` (known-vulnerable vendored libraries tracked under
A06:2021 – Vulnerable and Outdated Components).
