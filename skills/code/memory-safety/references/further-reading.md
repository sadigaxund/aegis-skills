# Memory Safety — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding finding class needs authoritative
backing; SKILL.md's sink tables and audit ladder remain the primary tools.

## Formal definitions (one per defect class)

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html) - the classic-overflow family behind the banned-function table (`gets`/`strcpy`/`sprintf` sinks).
- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html) - formal definition of over-reads, including the heartbleed-shaped leak class.
- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html) - read/write primitives of `%p`/`%n`, matching the format-string checks.
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html) - truncation/wraparound in size math; basis for the integer rules table.
- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html) - lifetime-class definition with consequence taxonomy (corrupt, leak, execute).
- [CWE-457: Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html) - uninitialized-read class including attacker pre-initialization of stack contents.

## Attack explainers

- [OWASP: Buffer Overflow Attack](https://owasp.org/www-community/attacks/Buffer_overflow_attack) - worked `gets()` walkthrough showing frame overwrite and control-flow hijack mechanics.
- [OWASP: Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack) - parameter table (`%x`/`%s`/`%n`) explaining leak-vs-write outcomes for CWE-134.

## Hardening & safe-language migration

- [OWASP Cheat Sheet Series: C-Based Toolchain Hardening](https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html) - compiler/linker flag guidance backing the hardening table (canaries, FORTIFY_SOURCE, PIE/RELRO).
- [The Rustonomicon](https://doc.rust-lang.org/nomicon/) - authoritative unsafe-Rust reference: ownership contracts, uninitialized memory, FFI duties audited by the unsafe-block checklist.

## Dynamic verification tooling

- [google/sanitizers](https://github.com/google/sanitizers) - documentation home of AddressSanitizer/LeakSanitizer/MemorySanitizer used in SKILL.md's harness procedures (repo now archived; sanitizer code lives in LLVM).
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html) - coverage-guided fuzzing entry-point contract (`LLVMFuzzerTestOneInput`) behind the proposed fuzz-harness shape.

Offline discipline still applies: conclusions from these references supplement,
never replace, the static evidence chains SKILL.md requires per finding.
