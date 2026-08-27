# PatchPilot

PatchPilot is a clean-room WebMCP demonstration for agent-powered vulnerability triage. It combines public CVE and CISA Known Exploited Vulnerabilities (KEV) facts with a 15-asset synthetic inventory, ranks affected systems with an explainable score, and lets an agent stage a seven-day remediation plan for human review.

The project is intentionally narrow: one polished dashboard, four reliable WebMCP tools, one memorable workflow, and no enterprise platform sprawl.

**Live application:** [https://patchpilot-webmcp.netlify.app](https://patchpilot-webmcp.netlify.app)

**Public source:** [github.com/JesusMBM/Projects/tree/patchpilot-webmcp](https://github.com/JesusMBM/Projects/tree/patchpilot-webmcp)

## The demonstration

Ask a compatible browser agent:

> Find actively exploited vulnerabilities affecting our internet-facing systems, prioritize the top three, and create a seven-day remediation plan.

The agent can search the public catalog, correlate CVEs to explicit synthetic product/version records, rank findings, and add up to three proposals to the shared board. It cannot approve, edit, start, or verify remediation. Those decisions remain human-only actions in the page.

The dashboard also includes a clearly labeled **Run guided workflow** control. It calls the same domain functions as the WebMCP tools, making the full experience demonstrable in browsers where the experimental API is unavailable.

## WebMCP tools

PatchPilot registers four tools through `document.modelContext.registerTool(...)`:

| Tool | Purpose | State effect |
| --- | --- | --- |
| `search_vulnerabilities` | Search CVE/KEV facts by keyword, severity, CVSS, and exploitation status | Focuses the visible catalog results |
| `find_affected_assets` | Match CVEs to the 15-asset synthetic inventory | Updates the findings view |
| `prioritize_findings` | Apply transparent severity, KEV, exposure, and criticality scoring | Updates the ranked view |
| `create_remediation_plan` | Stage up to three deduplicated recommendations | Creates `proposed` board items only |

Inputs are bounded and validated in application code in addition to JSON Schema. Public-data output is marked with `untrustedContentHint`, read-only tools use `readOnlyHint`, and each tool returns a compact JSON-serializable result. An `AbortController` owns all registrations.

Current WebMCP uses `document.modelContext`; the legacy `navigator.modelContext` alias is feature-detected only for older preview builds.

## Why WebMCP fits

Without WebMCP, an agent has to infer meaning from table cells, scrape the interface, and guess which controls are safe to use. PatchPilot exposes the underlying operations as explicit, typed tools while keeping results visible to the person in the same interface.

That creates a useful division of labor:

- The agent handles search, correlation, ranking, and plan drafting.
- The human supplies business context, inspects the rationale, modifies ownership or dates, and approves recommendations.
- Both work from the same application state and activity trail.

## Risk model

The deterministic score is deliberately small enough to explain in a demo:

| Signal | Points |
| --- | ---: |
| CVSS base score | 0–50 |
| Listed in CISA KEV | 0 or 25 |
| Internet-facing asset | 0 or 15 |
| Synthetic business criticality | 2–10 |
| **Maximum** | **100** |

The score is a prioritization aid, not a claim of exploitability and not a substitute for a scanner, environmental validation, or a production risk-acceptance process.

## Data and clean-room guarantee

- All hostnames, services, owners, installed versions, criticality values, and remediation decisions are fictional.
- The bundled fallback contains a small curated set of public vulnerability facts and explicit mappings created only for the synthetic inventory.
- A manual refresh attempts to overlay the official CISA KEV JSON feed. On CORS, network, format, or timeout failure, the app visibly retains its bundled snapshot.
- No employer code, asset data, screenshots, names, tickets, scoring models, or workflows are included.

Public sources:

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [NIST National Vulnerability Database](https://nvd.nist.gov/vuln)

See [NOTICE.md](NOTICE.md) for source and dependency notes.

## Run locally

Requirements: Node.js 22 or newer and npm.

```bash
npm install
npm run dev
```

Open `http://localhost:4173`.

### Test native WebMCP

Use one of the environments supported by the challenge:

1. ChatGPT's in-app browser; or
2. Chrome 149 or newer with `chrome://flags/#enable-webmcp-testing` enabled, followed by a browser restart.

Open the dashboard directly as a top-level page. The sidebar footer and Tool Registry panel show whether the API was detected. Chrome's Model Context Tool Inspector can enumerate and execute each registered tool.

## Quality checks

```bash
npm run lint
npm run typecheck
npm run test:run
npm run build
npm run test:e2e
```

The automated suite covers matching, scoring, seven-day sequencing, deduplication, tool schemas, runtime input validation, shared-state updates, cancellation, desktop/mobile interactions, the human approval gate, and serious/critical axe findings.

`npm run qa:visual` captures local 375 px, 768 px, and 1440 px screenshots after a server is running. The script also fails on page-level horizontal overflow, uncaught errors, or console errors.

## Deploy

The production application is deployed at [patchpilot-webmcp.netlify.app](https://patchpilot-webmcp.netlify.app). It is a static Vite build; `netlify.toml` provides the build command, SPA fallback, and security headers.

```bash
npm run build
npm run preview
```

Deploy `dist/` to any HTTPS static host. WebMCP is experimental; a production submission should also be enrolled in the applicable Chrome origin trial if required by the judging browser.

## Scope boundaries

PatchPilot deliberately does not include authentication, real asset upload, scanner integrations, generic CPE/version evaluation, multi-user persistence, ticketing, notifications, risk acceptance, or automated approval. It is a portfolio demonstration, not a production vulnerability-management system.

## Project structure

```text
src/data/          Synthetic inventory and public-data fallback
src/domain/        Pure matching, scoring, and planning functions
src/services/      Live CISA KEV refresh with safe fallback
src/store/         Shared state used by humans and tools
src/webmcp/        Tool schemas, validation, and registration
tests/             Deterministic unit and tool-contract tests
e2e/               Desktop, mobile, workflow, and accessibility tests
```

## License

Source code is available under the [MIT License](LICENSE). Public vulnerability facts and third-party packages remain subject to their respective terms.
