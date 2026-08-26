---
name: aegis-memory-safety
description: Detects memory-safety defects in native code (C/C++/Objective-C and unsafe Rust/FFI boundaries) including buffer overflows and overreads, out-of-bounds index math, integer truncation and overflow in size handling, use-after-free and double-free, format-string misuse, uninitialized reads, and dangerous string-copy sinks.
category_slug: MEM
cwe: [CWE-120, CWE-416, CWE-190, CWE-134]
owasp: A06:2021 – Vulnerable and Outdated Components (native code note)
---

## Scope & Objectives

Inventory all native code in the repository, rank it by attacker reachability, then audit each parser, copy site, allocation site, and lifetime transition for memory-safety violations. Confirm or refute every candidate finding by answering one question per sink: who controls the length, and does that length match the allocation?

- In scope (languages): C (.c/.h), C++ (.cc/.cpp/.cxx/.hpp), Objective-C / Objective-C++ (.m/.mm), Rust limited to `unsafe` blocks, `unsafe fn`, `unsafe impl`, FFI (`extern "C"`) surfaces, and `-sys` binding crates; mixed-language boundaries between any of these.
- In scope (defect classes): buffer overflow (CWE-120/121/122); out-of-bounds read (CWE-125); index arithmetic from untrusted fields; integer truncation, signedness confusion, and size-calculation overflow (CWE-190); use-after-free (CWE-416); double free (CWE-415); dangling pointers including container-reallocation invalidation; NULL dereference reached from untrusted input (CWE-476); format-string flaws in the `printf` family (CWE-134); use of uninitialized or partially initialized memory (CWE-457); length-unit and ownership mistakes at FFI boundaries.
- Out of scope (cross-reference): regex/engine-level resource exhaustion patterns (DOS module, including NSRegularExpression input blowup); injection via interpreted languages (INJECTION); secrets in native binaries (SECRETS); dependency version auditing for known-vulnerable vendored libraries (track separately under A06:2021 – Vulnerable and Outdated Components).
- Objective: produce findings a maintainer can verify by reading two or three files — sink location, length origin, the missing or insufficient bound check, and worst-case attacker-controlled value — without requiring dynamic tooling.

## Prerequisites & Vocabulary

Zero-background primer: the terms this module uses, one line each. Deeper plain-language
explanations for every class live in the repository GUIDE.md glossary.

- **buffer overflow**: writing past the end of a fixed-size memory block, corrupting neighboring data
- **out-of-bounds read**: reading beyond the allocated bytes, leaking whatever sits next in memory
- **use-after-free (UAF)**: using memory after it was released; an attacker may have replaced its contents
- **integer truncation**: size math that wraps around, so a huge length suddenly looks small
- **format string flaw**: passing attacker text where a print template is expected, leaking or overwriting memory
- **bounds check**: verifying index and length match the allocation before touching memory
- **sanitizer (ASAN)**: test-build instrumentation that catches these bugs at runtime instead of silently corrupting
- **taint flow / source→sink**: path untrusted data travels from entry point to dangerous function
- **finding status**: Confirmed > Probable > Needs-Review; evidence rules in templates/finding-report.md

## Mental Model

Reduce every memory-safety bug to a failure on one of three axes. When reading any candidate line, identify which axis is under stress:

| Axis | The question | Failure classes on this axis |
|---|---|---|
| Bounds | How many bytes are read/written, versus how many were allocated? | Stack/heap overflow (120/121/122), over-read (125), off-by-one terminator |
| Type | How are those bytes (and their counts) interpreted? | Integer truncation/overflow (190), signedness confusion, format string (134), length-unit mismatch |
| Lifetime | For how long are those bytes valid, and who owns them? | Use-after-free (416), double free (415), dangling pointer/reference, uninitialized use (457), NULL deref (476) |

Stack versus heap changes technique, not severity:

- Stack buffers live in fixed-size frames adjacent to saved return addresses and canaries; overflow there historically enables control-flow hijack, and modern compilers place a canary that detects (not prevents) most linear stack smashes.
- Heap buffers sit inside allocator-managed chunks adjacent to other objects and allocator metadata; overflow corrupts neighboring allocations, and the same write primitive is often reachable.
- Treat both as Critical-class when network-reachable pre-auth; do not soften a finding because it says "heap".

Mitigations are not fixes — frame every report this way:

- Stack canaries detect some overwrites after the fact; large copies can still land past them, and they say nothing about heap writes.
- ASLR randomizes addresses; any single info-leak bug (over-read, format string, uninitialized data) hands addresses back to the attacker and defeats it.
- DEP/NX marks data pages non-executable; return-to-libc and ROP-style chains work around it using existing executable code.
- Therefore never downgrade a finding because "the binary ships hardened"; hardening raises exploit cost, it does not remove the defect. Source-level correctness is the only fix.

Carry the central audit question through the whole module: WHO controls the length, and DOES it match the allocation?

## What To Check

### Step 0: Inventory Native Code Before Auditing

Do not audit what you have not enumerated. Build the file list first:

```bash
rg --files -g '*.{c,cc,cpp,cxx,h,hpp,hh,m,mm,s,S}'
rg -n 'unsafe' --type rust -g '*.rs'
rg -l 'cmake_minimum_required|CMakeLists' ; rg --files -g 'Makefile' -g '*.mk' -g 'meson.build' -g 'BUILD.gn' -g '*.xcconfig' -g 'configure.ac'
```

Record: total native LOC, whether Rust crates exist and how many `unsafe` hits they contain, and which build system compiles them. A repository with zero native files ends this module after recording that fact.

### Rank Targets by Attacker Reachability

Audit in this order; stop going deeper when findings already demand remediation:

1. Network/message parsers: anything fed from sockets, TLS plaintext, HTTP bodies, protocol dissectors (`parse_*`, `decode_*`, `handle_*`, `*_recv`, `on_data`, `read_packet`, `process_message`).
2. File-format importers/exporters: image, audio, archive, document, font decoders — attacker-supplied files are network-equivalent input.
3. IPC and local-attack-surface handlers: Unix sockets, named pipes, D-Bus service backends.
4. Shared libraries consumed by a privileged or network-facing process.
5. Internal-only utilities last.

### Apply the Audit Question Ladder at Every Sink

For each copy, index, allocation-size, format, and free site, walk this ladder in order and record answers as evidence:

1. Where does this buffer's capacity come from — fixed array size, `sizeof` of what, malloc argument?
2. Who controls the length used here — packet field, header count, string return value, decompressor output?
3. What units is that length in — bytes, elements, UTF-8 code points, wchar_t units? Do both sides agree?
4. Is the length validated against destination capacity BEFORE the copy/index, with the comparison in matching types?
5. Does any cast sit between declaration and use (`size_t` to `int`/`uint16_t`/`unsigned short`)?
6. Do signed and unsigned values mix in any comparison on the path?
7. Can a multiplication or addition computing an allocation size overflow first?
8. Does every write leave room for the NUL terminator, and is it actually written?
9. After any `free`/`delete`/release on this path, can the same object be touched again (error paths, callbacks, logging)?
10. Is every field of every struct fully written before it is sent, hashed, or published?
11. If Rust: does each `unsafe` block satisfy its own validity contract even when the caller lies?

### Check Copies and Sinks Against the Banned/Risky Tables

Sweep with the regexes in Patterns & Signatures, then manually classify every hit using the banned-function table and the risky-with-care table. A hit is a finding only if the dangerous argument is attacker-influenced or the bound is wrong; record the justification either way.

### Check Index Arithmetic From Untrusted Fields

Hunt for array subscripts computed from parsed fields. Verify three specific traps:

- Direct index without range check: `table[pkt->type]` where `type` is a 32-bit attacker value.
- Negative index through signedness: C99 defines `%` on negative operands as negative remainder, so `(int)field % TABLE_SIZE` can still yield a negative subscript.
- Pointer arithmetic past one-past-the-end: reading `p[len]` "just to peek" is out-of-bounds unless `len < capacity`.

### Check Integer Handling on Length Paths

Apply the integer rules table (Patterns & Signatures) to every variable that flows into an allocation, copy, or loop bound. Prioritize: truncating casts, signed/unsigned comparisons, and unguarded `n * m` allocation expressions.

### Check Lifetimes (Use-After-Free / Double-Free)

Walk these recurring shapes and trace ownership across each:

- Callbacks retaining freed objects: object registers a callback, is freed on teardown, callback fires later from another thread or timer.
- Iterator/list mutation during traversal: erasing while iterating without taking `erase()`'s returned iterator; `for` loops over a linked list whose current node the body frees.
- Error paths that free then log: cleanup calls `free(conn)` and the next line logs `conn->name`.
- Refcount imbalance concepts: a getter that retains but callers don't release under some branch; over-release in an error branch causing later use or double free.
- Container reallocation invalidation (C++): pointer/reference/iterator into a `std::vector` held across `push_back`; `std::string::c_str()` stored beyond the string's next mutation.
- Double free: two error branches both freeing the same buffer, or free inside a callee plus cleanup in the caller.

### Check Format Strings

Search the `printf`/`syslog`/`err` families for non-literal format arguments, including wrappers that forward `va_list`. Any function whose first string parameter is data rather than code is a candidate (CWE-134).

### Check Uninitialized Memory

Look for the heartbleed shape and its siblings:

- A heap struct from `malloc` (not `calloc`) with fields assigned conditionally, then serialized/sent wholesale.
- A response built by writing N bytes into a buffer but sending M > N bytes because M comes from the request.
- The general form: message-declared length versus actual fill level diverge, and the send/copy uses the message's number.
- Stack arrays read up to declared size rather than filled size after a short read.

### Check String Handling

- `strlen`/`strcpy` applied to buffers parsed from binary data that may lack a terminator.
- Off-by-one terminators: loops writing `buf[i]` for `i <= len`, or `buf[len] = '\0'` where `len == capacity`.
- Truncation splitting multi-byte UTF-8 sequences when copying to fixed widths, producing invalid downstream parsing.

### Audit Every unsafe Block in Rust

For each `unsafe` occurrence, require documented evidence of all relevant items:

1. Raw pointer dereference: provenance valid, aligned, initialized for the full claimed length; aliasing rules respected for references.
2. `mem::transmute`: source and destination sizes/layout equal; prefer typed conversions; flag any transmute of `&T` to `&mut T` or lifetime extension.
3. `slice::from_raw_parts(ptr, len)` / `_mut`: ptr non-null and valid for `len * size_of::<T>()` bytes; len comes from a trusted counter, never raw FFI input unvalidated.
4. `mem::uninitialized` is instant UB for most types — always a finding; `MaybeUninit` misuse means `assume_init()` called before every byte was written.
5. `unwrap()`/`expect()` reachable from `extern "C"` entry points: a panic crossing the boundary crashes or, per older Rust references, is UB — treat any panic-reachable-from-C path as a finding.
6. `unsafe impl Send/Sync`: proof that the type really is thread-safe; these escape compile-time checking.
7. cbindgen-generated headers: confirm the C side validates lengths/types before calling, since the generated header carries no contracts.

### Bridge Checks (Objective-C/Swift)

Brief pass; memory safety in bridges concentrates on C-string handling:

- `UTF8String`/`cStringUsingEncoding:` results are owned transiently by the autorelease pool and invalidated by mutation of the source string — storing them across mutations is dangling-pointer territory.
- `getBytes:maxLength:usedLength:encoding:` — check maxLength is the DESTINATION capacity in BYTES, not element counts.
- User-supplied NSRegularExpression patterns are a resource-exhaustion risk, not memory corruption — note and cross-reference the DOS module.

### Check FFI Boundaries in Both Directions

At every language-A-calls-language-B seam, verify:

- Length units agree: bytes vs elements vs `wchar_t` units vs UTF-8 code points; `wcslen` counts wide chars, `strlen` counts bytes — mixing them corrupts copies silently.
- Ownership transfer is explicit: who frees, with WHICH allocator (`free` vs `delete` vs Rust's global allocator vs platform CRT); freeing across allocators is corruption.
- Struct layout/padding and calling convention match on both sides of the header.
- Validation done on side A is not invalidated by reinterpretation on side B.
- Rust FFI depth: a `Drop` impl or panic unwinding across an `extern "C"` boundary is undefined behavior — check for `catch_unwind` at every exported entry point; `mem::forget` on RAII guards wrapping FFI-owned resources leaks them; `Box::into_raw` ownership-transfer contracts must be documented at the receiving side.

### Check Leak & Failure-Pattern Classes (distinct from corruption)

- [ ] Allocations without matching free on ERROR paths specifically: early returns and exception paths that skip cleanup while success paths free correctly.
- [ ] File-descriptor leaks in loops and error branches (open/socket/connect per attempt, close only on the happy path).
- [ ] Growing-only containers/maps keyed by user input with no eviction — unbounded session/cache growth = slow DoS cross-ref DOS module.
- [ ] Reconnect/retry loops that allocate per attempt (new buffer per reconnect without freeing the old).
- [ ] C++ exception-safety gaps: raw `new`/`delete` pairs spanning throw-capable calls, manual lock/file/handle management instead of RAII, destructors that can throw.
- [ ] Dangling-view patterns: `std::string_view`/`std::span` outliving their backing store; reads after `std::move`.
- [ ] Container invalidation during iteration: erase-while-iterating; reallocation invalidating held references/pointers into a vector.

## Where To Look

### File Inventory Globs

```bash
rg --files -g '*.{c,cc,cpp,cxx,h,hpp,hh,m,mm}'
rg --files -g 'Cargo.toml'            # then inspect sibling crates for unsafe
rg --files -g '{CMakeLists.txt,Makefile,*.mk,meson.build,BUILD.gn,*.xcconfig,configure.ac,Package.swift}'
```

### High-Yield Directories and Names

| Location pattern | Why it matters |
|---|---|
| `src/parser*`, `*/net/*`, `*/proto*`, `*/codec*`, `*/packet*`, `*message*` | Primary attack surface |
| import/export loaders, image/media/font decoders | File-parsing exposure |
| `third_party/`, vendored dirs | Still your report; mark vendor origin and version |
| test fixtures, fuzz corpora, seed inputs | Existing malformed inputs hint at parser fragility |
| bindings directories (`*-sys`, `*-bind`, `jni`, `bridge`) | FFI seams concentrate unit/ownership bugs |

### Symbol Hotspots

```bash
rg -n '\b(parse|decode|handle|process)_\w+\s*\(' -g '*.{c,cc,cpp,m,mm}'
rg -n '\b(malloc|calloc|realloc)\s*\(' -g '*.{c,h,cpp,cc}'
rg -n '\bfree\s*\(' -g '*.{c,h}' | wc -l   # volume estimate for lifetime review
rg -n '#\[no_mangle\]|extern\s*"C"' --type rust
```

### Rust-Specific Locations

- `grep unsafe crate-by-crate`; highest risk order: `-sys` binding crates, then `build.rs` (runs arbitrary compiled code at build time), then modules exporting `#[no_mangle] extern "C"`.
- Any `static mut` shared between threads found during the unsafe sweep is also a data-access hazard worth recording.

### Build and CI Evidence

```bash
rg -n 'fsanitize|_FORTIFY_SOURCE|stack-protector' -g '!third_party/**'   # existing hardening
rg -n 'LLVMFuzzerTestOneInput|libFuzzer|afl-fuzz|cargo fuzz'             # existing fuzz targets
ls fuzz fuzz/ tests/fuzz oss-fuzz 2>/dev/null                            # common harness homes
```

## Patterns & Signatures

### Banned Functions (Sink Table)

Every use of a left-column function is at minimum a code-review finding; classify reachability before escalating.

| Function | Risk | Safe replacement |
|---|---|---|
| `gets` | Unbounded stdin read; impossible to bound; removed from C11 | `fgets(buf, sizeof buf, stdin)` and strip newline |
| `strcpy` | No bound on copy; overflows whenever source exceeds destination | `snprintf(dst, dst_size, "%s", src)` (portable); `strlcpy` only where the target libc provides it (see availability note below) |
| `strcat` | No bound; also O(n²) rescanning | `snprintf(dst, dst_size, "%s%s", dst, src)`; or explicit `strncat`-with-computed-space then verify terminator |
| `sprintf` | No bound on total output length | `snprintf` with explicit destination size; check return value `<` size |
| `vsprintf` | Same as sprintf for va_list wrappers | `vsnprintf` with size passed down |
| `scanf` family using `%s` or `%[` without width | Unbounded token write into fixed buffer | Explicit width `%63s` sized to buffer-1; or `fgets` into buffer then parse with `sscanf`; reject lines longer than capacity |
| `atoi` | No error signaling; out-of-range input has undefined behavior; accepts `"12abc"` silently | `strtol`/`strtoul` with `errno == 0`, end-pointer at end-of-string, and range re-check against the field's real limits |

### Risky With Care (Sink Table)

These are not banned; each hit requires manual proof that the bound is right in matching types.

| Function | Risk | Required care / safe replacement |
|---|---|---|
| `memcpy(dst,src,n)` | Trusts `n` completely; undefined if regions overlap | Prove `n <= dst_capacity` AND `n <= src_valid_bytes` with both operands the same unsigned type; use `memmove` when overlap is possible; consider `memcpy_s` where available |
| `strncpy(dst,src,n)` | Does NOT guarantee NUL termination when `strlen(src) >= n`; zero-pads remainder (perf cost) | After the call force `dst[n-1] = '\0'`; prefer `snprintf(dst,dst_size,"%s",src)` which always terminates |
| `snprintf` | Return value is the WOULD-BE full length on truncation; using it as an offset/length causes out-of-bounds writes later | Treat return as OK only when `rc >= 0 && rc < size`; clamp any derived offset to `size - 1` |
| `alloca(n)` with runtime n | Allocates from the current stack frame; no failure return; attacker-sized n = stack overflow that canaries may not catch | Replace with fixed maximum plus heap fallback (`malloc` with checked size); avoid VLAs likewise (optional even in C11) |
| `realloc(ptr,n)` | `ptr = realloc(ptr, n)` leaks the old block on failure AND leaves ptr dangling if you assign NULL back | Assign to temporary, check NULL, then commit |
| `strlen(p)` on parser output | Reads until it finds a NUL — walks past the allocation if none exists | Carry explicit lengths from the parser; never derive length from untrusted binary data via strlen |

strlcpy availability honesty: `strlcpy`/`strlcat` ship with the BSDs and macOS; musl historically does not provide them; glibc added them only in glibc 2.38 (2023). Microsoft's CRT instead offers the Annex K-style `_s` functions (`strcpy_s`, `strncpy_s`). C11 Annex K itself is optional and is NOT implemented by glibc or musl. Do not recommend `strlcpy` or `_s` functions without first checking the project's supported libc matrix; the `snprintf("%s")` idiom is the portable choice everywhere.

### Regex Signatures

Ripgrep-compatible patterns; run from repo root. Expect noise — each hit needs the ladder applied.

Buffer-copy sinks (banned set):

```regex
\b(gets|strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat)\s*\(
```

Unbounded scanf tokens (also inspect `%[` manually in flagged files):

```regex
\b(scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf)\s*\([^;]*%[0-9]*[hl]*(s|\[)
```

Runtime-sized stack allocation:

```regex
\balloca\s*\(
```

Format strings — non-literal format argument:

```regex
\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)
```

```regex
\bfprintf\s*\(\s*(stderr|stdout|[A-Za-z_][A-Za-z0-9_]*)\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*\)
```

```regex
\bsyslog\s*\(\s*[^,]+\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*[,)]
```

va_list passthrough wrappers (manual caller review required):

```regex
\bv(syslog|printf|fprintf|snprintf|asprintf)\s*\(
```

Allocation sizes computed by arithmetic (overflow candidates):

```regex
\b(malloc|realloc|alloca)\s*\([^)]*[*/][^)]*\)
```

```regex
\bmalloc\s*\([^)]*\+[^)]*\)
```

Truncating casts near length-like identifiers (add `-i` to widen):

```regex
\(int|short|uint16_t|int16_t|unsigned short\)\s*[A-Za-z0-9_]*(len|length|size|count|sz)
```

Signed loop counter against unsigned-looking bound:

```regex
for\s*\(\s*int\s+[A-Za-z_]\w*\s*=\s*0\s*;\s*[A-Za-z_]\w*\s*<\s*[A-Za-z_]\w*(len|length|size|count|num)
```

Uninitialized-memory indicators (C stack allocas plus Rust):

```regex
\b(alloca\s*\(|mem::uninitialized|MaybeUninit::uninit|assume_init\(\))
```

Rust unsafe inventory:

```regex
unsafe\s*(fn|impl|\{)|#\[no_mangle\]|extern\s*"C"
```

```regex
\b(mem::transmute|transmute_copy|from_raw_parts_mut?|mem::forget)\b
```

Objective-C bridge C-string handling:

```regex
UTF8String|cStringUsingEncoding|getCString|getBytes:
```

### Vulnerable / Fixed Pair: Integer Truncation in Packet Parse

```c
// VULNERABLE: 16-bit length field trusted against a 256-byte stack buffer.
void handle_packet(const uint8_t *pkt, size_t pkt_len) {
    if (pkt_len < 4) return;
    uint16_t msg_len;
    memcpy(&msg_len, pkt + 2, sizeof msg_len);   // attacker controls all 16 bits
    if ((size_t)msg_len > pkt_len) return;       // check vs PACKET length...
    char body[256];                              // ...but never vs BODY capacity
    memcpy(body, pkt + 4, msg_len);              // msg_len up to 65535 -> overflow
}
```

```c
// FIXED: widen immediately, enforce destination capacity, same type comparison.
void handle_packet(const uint8_t *pkt, size_t pkt_len) {
    if (pkt_len < 4) return;
    uint16_t raw;
    memcpy(&raw, pkt + 2, sizeof raw);
    size_t msg_len = raw;                        // no truncation possible now
    char body[256];
    if (msg_len < 1u || msg_len > sizeof body) return;   // capacity check
    if (msg_len > pkt_len - 4u) return;                  // source has the bytes?
    memcpy(body, pkt + 4, msg_len);
    body[msg_len - 1u] = '\0';                   // safe: msg_len <= sizeof body
}
```

### Vulnerable / Fixed Pair: Error-Path Use-After-Free

```c
// VULNERABLE: object freed, then its fields logged.
static void drop_stale(struct conn_table *t, uint64_t id) {
    struct conn *c = table_find(t, id);
    if (!c || c->state != CONN_STALE) return;
    conn_free(t, c);
    log_info("dropped conn %llu peer=%s", id, c->peer_name);  // UAF read
}
```

```c
// FIXED: capture what logging needs BEFORE releasing ownership.
static void drop_stale(struct conn_table *t, uint64_t id) {
    struct conn *c = table_find(t, id);
    if (!c || c->state != CONN_STALE) return;
    char peer[sizeof ((struct conn *)0)->peer_name];
    snprintf(peer, sizeof peer, "%s", c->peer_name);
    conn_free(t, c);
    log_info("dropped conn %llu peer=%s", id, peer);
}
```

### Vulnerable / Fixed Pair: Container Reallocation

```cpp
// VULNERABLE: reference held across push_back; vector may reallocate.
std::vector<Item> items;
Item &first = items[0];
items.push_back(next_item());   // growth invalidates 'first'
audit(first);                   // dangling reference
```

```cpp
// FIXED: index-based access, or reserve() up front.
std::vector<Item> items;
items.push_back(initial_item());
items.reserve(items.size() + 1);        // no reallocation on next push_back
items.push_back(next_item());
audit(items[0]);                        // always valid
```

### Vulnerable / Fixed Pair: Rust FFI Slice Construction

```rust
// VULNERABLE: trusts caller-supplied len; panics can unwind across FFI.
#[no_mangle]
pub unsafe extern "C" fn checksum(ptr: *const u8, len: usize) -> u32 {
    let s = std::slice::from_raw_parts(ptr, len);
    s.iter().map(|&b| b as u32).sum()
}
```

```rust
// FIXED: non-unsafe signature, validated construction, panic contained.
#[no_mangle]
pub extern "C" fn checksum(ptr: *const u8, len: usize) -> u32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ptr.is_null() { return 0; }
        let s = unsafe { std::slice::from_raw_parts(ptr, len) }; // contract documented:
        // caller guarantees ptr valid for len bytes for this call's duration
        s.iter().map(|&b| b as u32).sum()
    }))
    .unwrap_or(0)
}
```

### Format-String Shape (minimal)

```c
// VULNERABLE: data used as format.
void log_event(const char *tag) { printf(tag); printf("\n"); }
```

```c
// FIXED: literal format, data as argument.
void log_event(const char *tag) { printf("%s\n", tag); }
```

### Integer Safety Rules Table

| Rule | Why | Enforcement / how to check |
|---|---|---|
| Never store lengths/sizes/counts in `int`, `short`, or bitfields | Truncation silently reintroduces huge values | Use `size_t` end-to-end; compile `-Wconversion` and audit every cast it reports |
| Check multiplication BEFORE allocating | `malloc(n*m)` wraps: 65536*65536 = 0 in 32-bit math -> tiny alloc, giant loop | GCC/Clang: `__builtin_mul_overflow(n, m, &total)` returning bool; MSVC: `ULongMult`/`ULongAdd` from `intsafe.h`; Rust: `n.checked_mul(m).ok_or(...)?`; C#: `checked { }` block |
| Make both comparison operands the same signedness explicitly | Negative signed value converts to huge unsigned and passes `> 0` checks | Compile `-Wsign-compare` (in `-Wextra`); cast the SMALLER-range side up, never the wider one down |
| Validate `off + len <= total` as `off <= total && len <= total - off` | The direct form can itself overflow past the check | Standard subtraction idiom; apply in every parser bounds branch |
| Loop counters going DOWN must not be unsigned tested against `>= 0` | `for (size_t i = n; i >= 0; i--)` never terminates | Prefer upward `size_t` loops; for downward use `while (i-- > 0)` idiom |
| `sizeof` the object, not the type | Type drift during refactors desynchronizes bounds | Write `memcpy(buf, src, sizeof *buf)`; flag literal byte counts next to declarations |

Realistic overflow-in-size-calculation pair:

```c
// VULNERABLE: 32-bit product wraps before malloc sees it.
uint32_t n = hdr.count, m = hdr.elem_size;      // both attacker-controlled
uint8_t *buf = malloc(n * m);                    // 65536 * 65536 wraps to 0
for (uint32_t i = 0; i < n; i++)
    memcpy(buf + (size_t)i * m, row(i), m);      // massive heap overflow
```

```c
// FIXED: overflow-checked product, zero-size rejected.
uint32_t n = hdr.count, m = hdr.elem_size;
if (n == 0 || m == 0) return ERR_EMPTY;
size_t total;
if (__builtin_mul_overflow((size_t)n, (size_t)m, &total)) return ERR_RANGE;  // GCC/Clang
uint8_t *buf = malloc(total);
if (!buf) return ERR_NOMEM;
```

### Leak & Failure-Pattern Signature Table

| Pattern | Language | Signature/example | Failure mode |
|---|---|---|---|
| Error-path leak | C | early `return -1` between `malloc` and `free` | slow exhaustion |
| FD leak in loop/retry | C/Python | `open`/`connect` per attempt, close on happy path only | fd-table exhaustion |
| Unbounded user-keyed cache | all | `sessions[key] = ...` with no eviction/TTL | memory DoS over time |
| Per-reconnect allocation | C++/Go | new buffer each retry, old never freed | growth under flaky network |
| Exception-unsafe cleanup | C++ | raw `new`/`delete` across calls that can throw | leak or double-free paths |
| Dangling view | C++ | `std::string_view` returned from function over local string | UAF read |
| Use-after-move | C++/Rust | object read after `std::move`/moved value used | logic/UAF hybrid |
| Erase during iteration | C++ | `for (...) v.erase(it)` without `it = v.erase(it)` | iterator UB |
| Panic across FFI | Rust | `extern "C"` fn can panic (unwrap/index) unwinds into C | UB / abort |
| forget/guard leak | Rust | `mem::forget(guard)` where guard wraps FFI resource | resource leak |

Signature greps (proxies — proximity of new/free is NOT statically grep-detectable; treat hits as leads for reading):

```regex
(fopen|socket|connect)\(fopen|fdopen
\.push_back\(|\.append\(unsafe
extern\s+"C"|\[no_mangle\]|mem::forget|Box::into_raw|catch_unwind
string_view|std::span|\.erase\(
```

Read each hit's enclosing function for the error-path question: does every branch after acquisition reach the release call?

```cpp
// VULNERABLE — early return skips cleanup
char *buf = malloc(len);
if (!read_header(sock, hdr)) { return -1; }   // buf leaked; fd stays open
process(buf); free(buf);

// FIXED — RAII owns it; every path cleans up
auto buf = std::make_unique<char[]>(len);
if (!read_header(sock, hdr)) { return -1; }   // unique_ptr frees on unwind/return
process(buf.get());
```

```rust
// VULNERABLE — panic here unwinds into C caller (UB)
#[no_mangle]
pub extern "C" fn parse(ptr: *const u8, len: usize) -> i32 {
    let data = unsafe { std::slice::from_raw_parts(ptr, len) };
    data[0] as i32                       // panics when len == 0
}

// FIXED — boundary catches; contract documented
#[no_mangle]
pub extern "C" fn parse(ptr: *const u8, len: usize) -> i32 {
    let r = std::panic::catch_unwind(|| {
        let data = unsafe { std::slice::from_raw_parts(ptr, len) };
        if data.is_empty() { return -1; }
        data[0] as i32
    });
    r.unwrap_or(-2)                      // never unwind into C
}
```

## Taint Tracing Guidance

You have no dataflow engine; do this manually but systematically, and grade confidence per finding.

### Define Sources First

Mark every point where attacker bytes enter: `recv`/`recvfrom`/`read` on sockets, TLS plaintext callbacks (`SSL_read`, BIO chains), HTTP body/chunk parsers, message-queue callbacks, `fread`/`getline`/`mmap` of uploaded files, decompressor outputs (post-decompression lengths LIE relative to allocation), IPC reads, and for local-surface audits `argv`/`envp`.

### Define Sinks by Class

| Class | Sink positions to mark |
|---|---|
| Bounds | 3rd arg of copy family (`memcpy`/`memmove`/`memset`/`strcpy`-likes), array subscripts, loop bounds |
| Allocation | size argument of `malloc`/`calloc`/`realloc`/`alloca`/`new[]` |
| Format | first string argument of `printf`/`syslog`/`err` families and their `v*` wrappers |
| Lifetime | `free`/`delete`/release calls, and any pointer returned by a function owning a stack buffer |

### Trace the Length Variable, Not the Buffer

Buffers are easy to spot; lengths are where bugs hide. For each candidate sink:

1. Name the length variable reaching the sink.
2. Walk backwards line-by-line: every assignment, cast, arithmetic op, and branch it passes through.
3. At each validation branch ask: validated against WHICH capacity, in WHICH types? A check against packet length does not cover a fixed destination buffer (see the truncation pair above).
4. Derive the worst-case value an attacker can place there given the protocol's declared field widths.
5. Record evidence as `file:line -> file:line -> sink`, plus the derived worst-case number.

Grade each finding: CONFIRMED (all steps evidenced statically) / LIKELY (one step inferred) / NEEDS-RUNTIME-PROOF. Only CONFIRMED and LIKELY go in the report with severity; NEEDS-RUNTIME-PROOF items go to a watchlist with the missing link named.

### Cross-Language Boundaries Extend Taint

Taint survives FFI. When C hands Rust a `(ptr, len)` or Java via JNI hands a byte array pointer, the receiving side inherits the sending side's taint. Document a one-line contract at each boundary: units, ownership, lifetime expectations, and which side validates.

### Wrapper and Macro Traps

Projects wrap dangerous calls (`xmemcpy`, `SAFE_COPY`, custom `log()` around `vsnprintf`). Expand every wrapper before classifying its callers — a safe wrapper makes all callers safe only if IT validates; otherwise the taint passes through untouched. Grep wrapper definitions once, classify once, then treat callers accordingly.

## Exploitation & Reproduction

Static confirmation is the deliverable. Dynamic proof is optional, LOCAL-ONLY, and exists to remove doubt about a CONFIRMED finding. Never run crafted input against systems you do not own; never ship remote-exploitation tooling in the report.

### Rule of Engagement

1. Report findings primarily as static evidence: sink line, length origin, missing bound, worst-case value, reachability path.
2. Compile local harnesses yourself from scratch — never reuse untrusted PoC code from the internet inside the target repo or build.
3. Run everything in a throwaway directory outside the repository tree; ASAN builds are for your harness, not for the project's production binaries unless the project already ships sanitizer targets.

### Procedure: Prove a Stack Overflow Locally (ASAN)

Minimal vulnerable program:

```c
// vuln.c
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char small[8];
    const char *src = argc > 1 ? argv[1] : "AAAAAAAAAAAAAAAA";
    strcpy(small, src);              // VULNERABLE: no bound
    printf("%s\n", small);
    return 0;
}
```

Compile and run locally:

```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o vuln vuln.c
./vuln
```

Reading the report you will see:

```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc... 
WRITE of size 1 at 0x7ffc... thread T0
    #0 ... in main vuln.c:6
Address 0x7ffc... is located in stack of thread T0 at offset 40 in frame
    #0 ... in main vuln.c:4
  This frame has 1 object(s):
    [32, 40) 'small' <== Memory access at offset 40 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow /path/vuln.c:6 in main
```

Line-by-line meaning: header names the bug CLASS and faulting address; `WRITE of size N` says direction and granularity (READ here would mean over-read); frame `#0 ... vuln.c:6` pinpoints YOUR sink line; `located in stack ... at offset X in frame` names the victim variable; `[32, 40) 'small'` shows the object's real byte range so you can compute overflow distance; `SUMMARY` is what CI grep should alert on.

Fixed counterpart — rerun to show clean exit:

```c
// fixed.c
#include <stdio.h>
int main(int argc, char **argv) {
    char small[8];
    const char *src = argc > 1 ? argv[1] : "AAAAAAAAAAAAAAAA";
    int n = snprintf(small, sizeof small, "%s", src);   // FIXED: always terminates
    if (n < 0 || (size_t)n >= sizeof small) puts("[truncated]");
    else printf("%s\n", small);
    return 0;
}
```

### Procedure: Demonstrate Integer Truncation (CWE-190)

```c
// trunc.c — attacker length truncated before allocation, original used for write
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t n = strtoul(argv[1], 0, 10);
    uint16_t short_n = (uint16_t)n;          // VULNERABLE: wraps mod 65536
    char *buf = malloc(short_n);
    memset(buf, 'A', n);                     // writes ORIGINAL n bytes
    free(buf);
    return 0;
}
```

```bash
gcc -g -O0 -fsanitize=address -o trunc trunc.c && ./trunc 70000
# 70000 % 65536 == 4464 -> tiny alloc, 70000-byte memset -> heap-buffer-overflow WRITE
```

Expected report header: `heap-buffer-overflow ... WRITE of size 70000` with the allocation stack showing `malloc` called from `trunc.c:8`. The fix mirrors the packet pair above: keep `n` as `size_t` throughout and validate against capacity before any cast.

### Procedure: Interpret a Use-After-Free Report

```c
// uaf.c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    char *p = malloc(16);
    strcpy(p, "session-token");
    free(p);
    printf("%s\n", p);                       // VULNERABLE: read after free
    return 0;
}
```

The ASAN output contains THREE stacks — teach reviewers this anatomy:

```
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602...
READ of size 1 ... thread T0
    #0 ... in main uaf.c:8                  <- USE site (your finding's sink)
freed by thread T0 here:
    #0 free   #1 main uaf.c:7               <- FREE site (fix ownership here)
previously allocated by thread T0 here:
    #0 malloc #1 main uaf.c:6               <- ALLOCATION site (lifetime began)
```

Map: use-stack names the line to change; free-stack tells you which error path released too early; allocation-stack identifies the object type/owner. A `double-free` attempt produces an `attempting double-free` header with two free-stacks — same mapping. Null-pointer crashes appear as `SEGV on unknown address 0x000000000000` with READ/WRITE — that is CWE-476 territory, usually DoS-only.

### Procedure: Show Format-String Read Primitive Locally (%p)

```c
// fmt.c
#include <stdio.h>
int main(int argc, char **argv) {
    printf(argc > 1 ? argv[1] : "hi");       // VULNERABLE: data as format
    putchar('\n');
    return 0;
}
```

```bash
gcc -g -O0 -o fmt fmt.c && ./fmt "%p %p %p %p"
# prints register/stack garbage such as: 0x7ffd... 0x55... 0x0 0x20
```

Each `%p` consumes one vararg slot that was never provided, dumping process memory values to output — that IS the information leak (CWE-134). The `%n` conversion is the write primitive concept: `%n` stores the count of characters printed so far into a pointer argument, so an attacker-supplied format turns the same bug into controlled memory writes; do NOT demo `%n` beyond noting the mechanism, and never aim format-string tests at services you do not own. Log-forging adjacency: `%s`-heavy formats plus attacker text also forge log lines — cross-reference logging review.

### Static-Only Confirmation Template

When compiling a harness is not possible, a CONFIRMED finding still stands if the report states all five:

1. Sink line (file:line) and why it is a sink.
2. Length/value origin line with the attacker-controlled field identified.
3. The specific missing/insufficient check line (or proof none exists on any path).
4. Reachability: entry point -> call chain to the sink.
5. Worst-case numeric derivation from protocol field widths (e.g., "16-bit field admits 65535 vs 256-byte buffer").

## Remediation

### Replace Dangerous Calls

Use the banned/risky tables in Patterns & Signatures as the replacement authority. Order fixes by severity rating, and pair every fix with a regression test per Verification & Validation.

### Compiler and Linker Hardening (mitigations, ship them anyway)

| Toolchain | Flags | Notes |
|---|---|---|
| GCC / Clang | `-fstack-protector-strong` | Canary on functions with local arrays/addresses taken |
| GCC / Clang | `-D_FORTIFY_SOURCE=2` | Requires an optimizing build (`-O1`+); adds runtime-checked bounds to many libc calls |
| GCC / Clang | `-fPIE` compile + `-pie` link; `-Wl,-z,relro,-z,now` | ASLR-capable executable with full RELRO |
| GCC / Clang | `-Wall -Wextra -Wconversion -Wsign-compare -Wformat=2 -Werror=format-security` | Catches truncation, signedness, and non-literal formats at build time |
| GCC / Clang (test builds) | `-fsanitize=address,undefined -fno-omit-frame-pointer -g` | ASAN+UBSAN for CI runs, not release |
| MSVC | `/GS /SDL` | Stack canaries plus SDL-era extra checks |
| MSVC | `/DYNAMICBASE /NXCOMPAT /guard:cf` | ASLR, DEP, Control Flow Guard |

State plainly in remediation notes: these flags raise exploit cost; they do not close any defect found by this module.

### Modern API and Type Adoption

- C++: migrate parser buffers to `std::string`/`std::vector` (length travels WITH the data) and pass views as `std::span` (C++20) so capacity is part of the type; when stuck pre-C++20, pass explicit length parameters and never return pointers to internals.
- C portable copies: the `snprintf(dst, dst_size, "%s", src)` idiom works everywhere. Availability honesty for alternatives: `strlcpy` — BSDs/macOS yes, glibc only since 2.38, musl no; Annex K `_s` functions — implemented mainly by Microsoft's CRT, optional in C11 and absent from glibc/musl. Check the project's supported libc matrix before recommending either.
- Rust rewrite boundary strategy: rewrite the highest-risk parser as a safe-Rust crate, keep its `extern "C"` ABI thin, validate every `(ptr, len)` at entry, contain panics with `catch_unwind`, and leave C callers unchanged — strangler-pattern migration rather than a big-bang port.
- Prefer `calloc` over `malloc(n*m)` where a zeroed region is acceptable: `calloc` checks multiplication overflow internally on modern libcs.

### Introduce Fuzzing Where Absent

Presence check first:

```bash
rg --files -g '*fuzz*' ; rg -n 'LLVMFuzzerTestOneInput|cargo fuzz|AFL_|afl-fuzz' 
```

If nothing exists, propose (do not implement) a harness of this shape wired into the project's own test build:

```text
// fuzz/parse_fuzz.c — harness shape pseudocode
#include <stdint.h>
#include <stddef.h>
int parse_frame(const uint8_t *data, size_t len);   // existing target entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_frame(data, size);      // one attacker-shaped buffer, one call
    return 0;
}
// Build under libFuzzer or AFL++ per project toolchain; feed crashers back as unit tests.
```

### Leak & Lifetime Hardening

- Smart-pointer ownership defaults (C++): `unique_ptr` for sole owners, `shared_ptr` only when lifetime is genuinely shared, `weak_ptr` for back-references that would otherwise create cycles; raw `new`/`delete` become review flags.
- Sanitizer gates in CI: build with `-fsanitize=address,leak` for test suites (LSAN reports leaks at exit) and run `valgrind --leak-check=full` on the nightly integration suite; a leak finding fails the build like any other test.
- Container-growth budgets: every user-keyed cache/map gets an explicit max-entries + eviction policy (LRU or TTL); assert the bound in code rather than trusting operators to notice growth.
- Rust FFI convention: every `#[no_mangle]` export carries a doc comment stating the OWNERSHIP CONTRACT (who frees what, panic policy `catch_unwind` present) — undocumented-boundary = review flag.

## Verification & Validation

### GIVEN/WHEN/THEN Scenarios

Oversized input rejected cleanly:

```gherkin
GIVEN a parser whose declared maximum body is 256 bytes
WHEN a frame arrives declaring a 300-byte body
THEN the parser rejects it with a protocol error
AND no write occurs beyond any buffer boundary (ASAN-clean run)
AND subsequent valid traffic on the same session parses normally
```

Normal traffic unaffected (negative/regression guard):

```gherkin
GIVEN the same parser and a recorded golden capture of valid frames
WHEN all frames replay through the fixed code
THEN outputs match the pre-fix baseline byte-for-byte
```

Truncation path:

```gherkin
GIVEN a length field of 70000 arriving at code that previously cast to uint16_t
WHEN the frame is processed
THEN the value is either rejected (> declared max) or handled in widened size_t math
AND the value 4464 (the wrap residue) never appears in any allocation decision
```

Error-path lifetime:

```gherkin
GIVEN session teardown while one request is mid-flight
WHEN teardown frees the connection object
THEN the in-flight request completes-or-rejects WITHOUT touching freed memory (ASAN-clean)
AND the log line for the drop contains the peer name captured before free
```

Format-string hardening:

```gherkin
GIVEN an event tag containing "%n%p%s"
WHEN the tag is logged
THEN the output contains the tag verbatim
AND the process does not crash and no memory words appear in output
```

### Regression Test Pseudocode (boundary lengths)

```c
/* test_parse_boundaries.c — shape; adapt names to project test framework */
static void test_parse_boundaries(void) {
    static const size_t lens[] = {0u, 1u, MAX_BODY - 1u, MAX_BODY,
                                  MAX_BODY + 1u, 0xFFFFu};
    uint8_t frame[0xFFFF];
    memset(frame, 'x', sizeof frame);
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; ++i) {
        set_declared_len(frame, lens[i]);
        enum pstatus st = parse_frame(frame, sizeof frame);
        ASSERT(st == PS_OK || st == PS_REJECTED);   /* never UB, never crash */
    }
}
```

### Manual Post-Fix Checklist

- [ ] Every flagged sink now compares attacker length against destination capacity in matching types, before the copy/index.
- [ ] No length variable changes width between validation and use.
- [ ] All allocation-size arithmetic is overflow-checked or provably bounded by constants.
- [ ] Every freed object is unreachable afterwards on ALL paths (success, error, callback, logging).
- [ ] Every `snprintf` return used as an offset is clamped to the buffer bound.
- [ ] Error paths release what success paths release (walk each early return after an acquire).
- [ ] Leak gates green: LSAN build of the test suite exits clean; nightly valgrind run has no new "definitely lost" records.
- [ ] Soak assertion: after N=10k iterations of the worst-case flow, RSS and open-fd count (`ls /proc/self/fd | wc -l`) are within a stated tolerance — a bounded-memory regression test.
- [ ] Negative control: triggering the error path on purpose does NOT grow fd/RSS counters between before/after samples.
- [ ] Each Rust `unsafe` block carries a written invariant comment matching the checklist items.
- [ ] Hardening flags added to release build config; sanitizer flags added to CI-only config.

### Post-Fix Greps

Run from repo root excluding vendored code (`-g '!third_party/**'`); every command below should return zero hits unless an allowlisted justification exists in the file itself:

```bash
rg -n '\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(' -g '!third_party/**'
rg -n '\bscanf\s*\([^;]*%s' -g '!third_party/**'
rg -n '\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)' -g '!third_party/**'
rg -n '\balloca\s*\(' -g '!third_party/**'
```

Maintain an allowlist file listing each surviving hit with owner and reason; unexplained hits reopen the finding.

### Sanitizer Builds in CI

Example CMake invocation for a nightly job:

```bash
cmake -S . -B build-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
```

Policy: any sanitizer report in CI blocks release until triaged. MSVC equivalent exists via `/fsanitize=address` (VS 2019 16.9+). For Rust crates, address-sanitizer builds require a nightly compiler via `RUSTFLAGS="-Zsanitizer=address"` — state that constraint honestly in the CI ticket rather than assuming stable-toolchain support.

## Severity Assessment

### CWE Mapping and CVSS v3.1 Vectors

Rate the IMPACT the defect enables, not the root-cause class; integer overflow (CWE-190) inherits the severity of what it unlocks.

| Finding | CWE | Example CVSS v3.1 vector | Default rating |
|---|---|---|---|
| Network pre-auth stack/heap corruption (overflow or UAF) with control-flow potential | CWE-120 / CWE-121 / CWE-122 / CWE-416 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Critical (9.8) |
| Network pre-auth out-of-bounds READ leaking memory (heartbleed shape) | CWE-125 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | High (7.5) |
| Format string, read-only leak (`%p`/`%s` walk) | CWE-134 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | High (7.5) |
| Format string reachable write (`%n`) or UAF/double-free network-reachable | CWE-134 / CWE-415 / CWE-416 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Critical (9.8) |
| Same corruption behind authentication | above classes | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` shape | Medium–High per privilege tier |
| Local-only info leak (uninitialized data disclosure) | CWE-457 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | Medium (5.5) |
| DoS-only NULL dereference from untrusted input | CWE-476 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` | Low–Medium context (~4.3) |

Stack vs heap nuance for reporting precision: use CWE-121 when the corrupted object is a local/array in a function frame, CWE-122 when it is heap-allocated via `malloc`/`new`; CWE-120 is the generic family acceptable when the site is ambiguous.

### Rating Rubric

Apply in order; first match wins:

1. Network-reachable, pre-authentication memory corruption (overflow, UAF, double free) with any code-execution or control-flow potential → Critical.
2. Network-reachable pure information leak (over-read, uninitialized send, format-string read) → High.
3. Memory corruption requiring authentication or local access → High if privileged process, Medium otherwise.
4. Information leak requiring local access → Medium.
5. DoS-only (NULL deref, assertion abort) from network input → Medium; downgrade toward Low where process isolation/restart makes availability loss transient and the component is non-core.
6. Adjust within one band for exploitability reducers (canaries, ASLR, NX lower RELIABILITY, never existence); document the adjustment rationale in the finding.

## Common False Positives

- `strncpy` hits where `n` is provably `<=` destination size AND the code forces termination afterwards — verify both halves before dismissing.
- `memcpy` with a literal length equal to a same-named fixed buffer's `sizeof` — check they refer to the SAME object, not identically named fields of different structs.
- `snprintf` flagged because its return feeds an offset — only a finding if the return is used UNclamped on a later bounded write.
- Regex hits inside C++ files that are actually `std::string` operations or comments — confirm the types involved are raw arrays/pointers.
- Rust `unsafe` blocks whose invariants are genuinely upheld and documented — record as reviewed-safe rather than findings, so future edits know the contract was checked once.
- Unsigned downward loops written as `while (i-- > 0)` — correct idiom despite looking suspicious.
- Test fixtures, fuzz corpora generators, and demo binaries excluded from production builds — verify build flags actually exclude them before marking anything.
- Vendored third-party hits — still report, but tag vendor/version and note upstream tracking instead of demanding an immediate local patch.

## References

- CWE-120: Buffer Copy without Checking Size of Input ("Classic Buffer Overflow") — https://cwe.mitre.org/data/definitions/120.html
- CWE-121: Stack-based Buffer Overflow — https://cwe.mitre.org/data/definitions/121.html
- CWE-122: Heap-based Buffer Overflow — https://cwe.mitre.org/data/definitions/122.html
- CWE-125: Out-of-bounds Read — https://cwe.mitre.org/data/definitions/125.html
- CWE-134: Use of Externally-Controlled Format String — https://cwe.mitre.org/data/definitions/134.html
- CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html
- CWE-415: Double Free — https://cwe.mitre.org/data/definitions/415.html
- CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html
- CWE-457: Use of Uninitialized Variable — https://cwe.mitre.org/data/definitions/457.html
- CWE-476: NULL Pointer Dereference — https://cwe.mitre.org/data/definitions/476.html
- OWASP Buffer Overflow Attack — https://owasp.org/www-community/attacks/Buffer_overflow_attack
- OWASP Format String Attack — https://owasp.org/www-community/attacks/Format_string_attack
- OWASP Cheat Sheet Series: C-Based Toolchain Hardening Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html
- SEI CERT C Coding Standard (Carnegie Mellon University Software Engineering Institute) — browse the rule index at wiki.sei.cmu.edu; its memory-management (MEM) and string-handling (STR) rules map directly to this module's tables
- OWASP Top 10 2021 category A06:2021 – Vulnerable and Outdated Components — https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
