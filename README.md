# PatchPilot

PatchPilot is a clean-room WebMCP demonstration for agent-powered vulnerability triage. In the repeatable baseline scenario, a browser agent turns **12 actively exploited CVEs into 8 internet-facing asset matches, ranks the top 3, and stages 3 remediation proposals**. A person then inspects the evidence, changes the plan if needed, and makes the approval decision.

The project stays intentionally narrow: one polished dashboard, four reliable WebMCP tools, a 15-asset synthetic inventory, and one memorable human-agent workflow.

**Live application:** [https://patchpilot-webmcp.netlify.app](https://patchpilot-webmcp.netlify.app)

**Public source:** [github.com/JesusMBM/Projects/tree/patchpilot-webmcp](https://github.com/JesusMBM/Projects/tree/patchpilot-webmcp)

## Judge quick start

1. Use ChatGPT's in-app browser, or Chrome with `chrome://flags/#enable-webmcp-testing` enabled and the browser restarted. Chrome 151 was used for native verification.
2. Open the live application as a top-level page. The sidebar and Tool Registry should report that four WebMCP tools are ready.
3. Give the browser agent this prompt:

   > Find actively exploited vulnerabilities affecting our internet-facing systems, prioritize the top three, and create a seven-day remediation plan.

4. Watch the same dashboard update after each native tool callback: **12 searched → 8 matched → 3 prioritized → 3 proposed**.
5. Open a score explanation, edit an owner, date, action, or note, and approve one proposal through the explicit human confirmation dialog.

The production origin is not currently enrolled in a Chrome Origin Trial. In ordinary Chrome without the testing flag, native WebMCP may be unavailable; the **Run guided workflow** control is identified as a guided preview and demonstrates the same domain operations, but it is not a substitute for the native-tool proof. Use a supported environment for judging or recording the WebMCP flow.

## Why the interaction matters

Without WebMCP, an agent must scrape rows, infer application state, and guess which controls are safe. PatchPilot exposes the underlying operations as narrow, typed tools and renders every result into the person's workspace.

- The agent searches, correlates, ranks, and drafts.
- The person supplies business context, sees the evidence and activity trail, modifies the proposed work, and approves it.
- Approval is deliberately absent from the WebMCP registry. `create_remediation_plan` can create only `proposed` items and returns `approvalRequired: true`, `agentCanApprove: false`, and `requiredNextActor: "human"`.

This is shared state rather than a disconnected chatbot: native tool calls change the catalog, findings, workflow stages, board, and activity trail the reviewer sees.

## WebMCP tools

PatchPilot registers four tools through `document.modelContext.registerTool(...)`:

| Tool | Purpose | Visible effect |
| --- | --- | --- |
| `search_vulnerabilities` | Search public CVE/KEV facts by keyword, severity, CVSS, and exploitation status | Focuses the catalog |
| `find_affected_assets` | Match CVEs to explicit product/version records in the 15-asset synthetic inventory | Updates affected findings |
| `prioritize_findings` | Apply transparent severity, KEV, exposure, and criticality scoring | Ranks the visible findings |
| `create_remediation_plan` | Build up to three deduplicated recommendations in a bounded response window | Adds `proposed` board items only |

Inputs are bounded and validated in application code in addition to JSON Schema. Unknown properties and empty ID arrays are rejected. Public-data output is marked with `untrustedContentHint`, read-only tools use `readOnlyHint`, and the search/matching outputs distinguish total matches, returned items, and truncation. One `AbortController` owns the registration lifecycle.

Current WebMCP uses `document.modelContext`; the legacy `navigator.modelContext` alias is read only as a feature-detected fallback for older preview builds.

## Business context is causal

The Analysis Context panel changes the tool chain instead of merely decorating the prompt:

| Context choice | Default behavior when the agent omits that input |
| --- | --- |
| Aggressive posture | Search only known exploited vulnerabilities |
| Balanced posture | Search at CVSS 7.0 or higher |
| Internet-facing only | Restrict asset matching and plan candidates to exposed assets |
| Remediation window | Set the default plan window and visible stage label |

Every tool response also reports the full context applied, so the browser agent and reviewer can inspect the assumptions behind the result. The organization label and business focus remain visible human context; the guided preview carries the focus into its plan rationale, while a native agent can pass an explicit `objective` to the plan tool.

## Transparent risk model

The deterministic score is deliberately small enough to explain in a demo:

| Signal | Points |
| --- | ---: |
| CVSS base score | 0–50 |
| Listed in CISA KEV | 0 or 25 |
| Internet-facing asset | 0 or 15 |
| Synthetic business criticality | 2–10 |
| **Maximum** | **100** |

Known ransomware use adds **zero score points**. It is used only as a transparent tie-breaker when two findings have the same risk score; stable finding ID is the final tie-breaker. The score is a prioritization aid, not a claim of exploitability and not a substitute for a scanner, environmental validation, or a production risk-acceptance process.

## Public data, validation, and fallback

The browser requests live data from the same-origin `/api/cisa-kev` endpoint. A fixed-purpose Netlify Function fetches the official CISA KEV feed server-side, enforces a seven-second timeout and response-size limit, validates the catalog envelope and individual entries, caps accepted entries, and returns cacheable JSON. This avoids relying on a cross-origin browser request while keeping the upstream source explicit.

If the function, network, upstream response, or validation fails, the UI visibly retains its bundled snapshot. The optional refresh overlays CISA exploitation metadata; synthetic product/version mappings remain local and deterministic.

- All hostnames, services, owners, installed versions, criticality values, and remediation decisions are fictional.
- The bundled fallback contains a small curated set of public vulnerability facts and explicit mappings created only for the synthetic inventory.
- No employer code, asset data, screenshots, names, tickets, scoring models, or workflows are included.

Public sources:

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [NIST National Vulnerability Database](https://nvd.nist.gov/vuln)

See [NOTICE.md](NOTICE.md) for source and dependency details.

## Native verification

The complete four-call chain was exercised through actual `document.modelContext` callbacks in Chrome 151, including the callback form that does not supply an options object. With the bundled baseline and default context, the verified result was:

```text
search_vulnerabilities   12 catalog matches
find_affected_assets      8 internet-facing matches
prioritize_findings       3 ranked findings
create_remediation_plan   3 proposed items; human approval required
```

All four workflow stages completed in the shared page, three proposal cards appeared, and the run produced no console warnings or errors. The automated browser suite also exercises the native registration/invocation contract with a strict `document.modelContext` shim.

## Run locally

Requirements: Node.js 22 or newer and npm.

For the application and bundled fallback:

```bash
npm install
npm run dev
```

Open `http://localhost:4173`. A standalone Vite server does not emulate the Netlify Function, so live refresh will intentionally fall back.

For full same-origin function parity, install the Netlify CLI and run:

```bash
netlify dev
```

Use the local URL printed by the CLI.

## Quality checks

```bash
npm run lint
npm run typecheck
npm run test:run
npm run build
npm run test:e2e
```

The suite covers matching, scoring, the zero-point ransomware tie-breaker, plan sequencing, deduplication, schemas, strict runtime validation, shared-state updates, cancellation, context-driven defaults, the serverless data boundary, desktop/mobile interactions, the human approval gate, and serious/critical axe findings.

Final release verification on August 27, 2026: **19/19 Vitest checks passed; 14 Playwright checks passed with 2 intentional device-specific skips; six responsive visual captures completed with zero page or console errors; and the production native WebMCP smoke completed 12 → 8 → 3 → 3 with zero warnings, errors, or failed requests.**

`npm run qa:visual` captures 375 px, 768 px, and 1440 px screenshots after a server is running. It also fails on page-level horizontal overflow, uncaught errors, or console errors.

## Deploy

Netlify runs `npm run build`, publishes `dist/`, and deploys `netlify/functions/cisa-kev.mts` at `/api/cisa-kev`. `netlify.toml` also supplies the SPA fallback, immutable asset caching, a same-origin connection policy, and browser security headers.

WebMCP is experimental. A deployment intended to work in ordinary Chrome without the testing flag must complete the applicable Chrome Origin Trial enrollment and add the token for its exact HTTPS origin. This repository does not claim that enrollment.

## Project structure

```text
src/data/                  Synthetic inventory and bundled public-data fallback
src/domain/                Pure matching, scoring, and planning functions
src/services/              Validated live KEV overlay with safe fallback
src/store/                 Shared state used by people and tools
src/webmcp/                Tool schemas, validation, and registration
netlify/functions/         Same-origin CISA KEV proxy and validation boundary
tests/                     Deterministic unit and contract tests
e2e/                       Native-shim, desktop, mobile, and accessibility tests
```

## Scope boundaries

PatchPilot deliberately does not include authentication, real asset upload, scanner integrations, generic CPE/version evaluation, multi-user persistence, ticketing, notifications, risk acceptance, or automated approval. It is a portfolio demonstration, not a production vulnerability-management system.

## License

Source code is available under the [MIT License](LICENSE). Public vulnerability facts and third-party packages remain subject to their respective terms.
