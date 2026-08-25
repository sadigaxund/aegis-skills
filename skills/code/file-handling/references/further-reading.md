# File-Handling Attacks — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & cheat sheets

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) - extension/MIME/signature validation chain and storage-location rules backing the upload checklist.
- [OWASP Community: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) - encoding variants and OS-specific separator behavior mirrored in the payload ladder.

## Deep dives

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) - base traversal weakness with canonicalization-first mitigation guidance matching the containment snippets.
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) - execution-consequence framing and random-name/storage-outside-webroot mitigations behind upload findings.
- [PortSwigger Web Security Academy: Path traversal](https://portswigger.net/web-security/file-path-traversal) - obstacle-bypass catalog (encoding, nested sequences, null bytes) aligned with the L0-L10 ladder.
- [PortSwigger Web Security Academy: File upload vulnerabilities](https://portswigger.net/web-security/file-upload) - web-shell impact, validation-flaw exploitation, and race-condition upload context for authorized labs.

## Vendor docs

- [Python pathlib documentation](https://docs.python.org/3/library/pathlib.html) - vendor confirmation of join/resolve semantics the fixes rely on: absolute segments replace the base, `resolve()` collapses `..` and symlinks, `relative_to()` raises outside the root.

(7 URLs total; each returned HTTP 200 with matching content when fetched.
Sibling-module cross-references live in background.md's "Read next" section.)
