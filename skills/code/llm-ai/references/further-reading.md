# LLM / AI Feature Security — Further Reading

All URLs below were fetched and confirmed live during this session. Grouped for
on-demand loading; each line states why it earns its place alongside SKILL.md.
Load a group only when the corresponding SKILL.md section is being applied;
nothing here is needed for the static audit itself.

## Standards & frameworks

- [OWASP Gen AI Security Project](https://genai.owasp.org/) - home of the Top 10 for LLM Applications whose categories SKILL.md references by name; also covers agentic security and red-teaming taxonomy.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) - govern/identify/measure/manage framing for AI risk, including the generative-AI profile referenced in Scope & Objectives.
- [MITRE ATLAS](https://atlas.mitre.org/) - adversary-technique knowledge base for AI systems; use to name attack chains beyond the module's application-level classes.

## Deep dives

- [CWE-74: Injection](https://cwe.mitre.org/data/definitions/74.html) - the umbrella weakness behind stage-2 sinks (command/SQL/code children); note mapping-discouraged status, cite children in final reports.
- [Simon Willison: prompt injection archive](https://simonwillison.net/tags/prompt-injection/) - continuously updated case studies of direct/indirect injection and exfiltration chains; primary source for the "lethal trifecta" framing used in Exploitation & Reproduction.

## Vendor docs

- [Anthropic documentation](https://docs.anthropic.com/) - tool-use, structured outputs, and guardrail guidance for Claude integrations matching the Python fix patterns.
- [OpenAI API documentation](https://platform.openai.com/docs/) - function calling, safety best practices, and data controls for OpenAI-integrated call sites found by rows 1–3 markers.
- [Model Context Protocol](https://modelcontextprotocol.io/) - the tool-integration standard whose third-party servers/descriptions are audited as untrusted input in supply-chain check 8.

(8 URLs total; each returned HTTP 200 with matching content when fetched.
Dropped during verification: portswigger.net/web-security/prompt-injection,
which returns HTTP 404 — no PortSwigger page covers this topic; the Willison
archive fills the deep-dive role instead.)
