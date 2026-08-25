# Target Profile Template

> **Usage:** Filled by the orchestrator during Phase 1 (Recon). Save as
> `security-audit/<run-id>/TARGET-PROFILE.md`. Everything downstream (check
> prioritization, skip decisions) must be justifiable from this file. Be factual;
> record commands you ran and globs that returned results.

---

```markdown
# Target Profile — {{target}} ({{run-id}})

## Identity

| Field | Value |
|---|---|
| Path / URL | |
| Version / commit | |
| Repo layout | {{monorepo? packages? apps vs libs}} |
| Size estimate | {{files, LOC by language}} |

## Languages & Runtimes

| Language | Version(s) | Evidence (manifest/lockfile path) | Share of code |
|---|---|---|---|

## Frameworks & Key Libraries

| Component | Version | Role (web/api/job/cli) | Notes (EOL? unusual?) |
|---|---|---|---|

## Entry Points Inventory

### HTTP routes
{{Table: method, route pattern, handler file:line, auth required?, input sources}}
{{Grep hints used: e.g. `@(app|router)\.(get|post...)`, `@api_view`, `@RequestMapping`, `func Handle`, `#[get]}}

### Non-HTTP entry points
{{CLIs, cron jobs, queue consumers, websocket handlers, gRPC, plugins, file parsers,
webhook receivers — with file:line}}

## Trust Boundaries & Data Sources

- {{Where untrusted data enters: request params/body/headers/files, env vars, DB rows
  written by other components, third-party webhooks, message queues}}
- Auth mechanisms observed: {{sessions/JWT/OAuth/API keys/mTLS/basic}}
- Session/token storage: {{cookie flags, localStorage, DB}}

## Data Stores & External Integrations

| Type | Tech | Where used (file:line) | Notes |
|---|---|---|---|
| SQL | | | |
| NoSQL | | | |
| Cache | | | |
| Object storage | | | |
| Outbound HTTP | | | {{URLs/domains called}} |

## Build, Deploy & Infra Artifacts Found

{{Dockerfile(s), compose, k8s manifests, terraform, CI files (.github/workflows,
.gitlab-ci.yml), serverless configs — paths + one-line description each}}

## Sensitive Data Observed (paths only, values REDACTED)

{{File types likely containing PII/secrets: config files, .env samples, fixtures,
seed scripts, logging of user fields}}

## Check Applicability Matrix (orchestrator decision input)

| Slug | Applicable? | Priority | Reason |
|---|---|---|---|
| INJ | yes | high | {{e.g., 3 SQL-touching repos found}} |
| MEM | no | - | {{no C/C++/Rust code present}} |

## Open Questions for the Requester

- {{Anything ambiguous: which env is in scope, is staging reachable, are tests in scope}}
```
