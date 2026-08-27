# WebMCP Challenge submission draft

**Live application:** [https://patchpilot-webmcp.netlify.app](https://patchpilot-webmcp.netlify.app)

**Public source:** [github.com/JesusMBM/Projects/tree/patchpilot-webmcp](https://github.com/JesusMBM/Projects/tree/patchpilot-webmcp)

## Short description

PatchPilot is an agent-powered vulnerability-triage workspace. A browser agent searches public CVE and CISA KEV data, correlates vulnerabilities with a synthetic asset inventory, explains a business-aware priority score, and stages a seven-day remediation plan on a shared board. A human reviews, edits, and approves every recommendation.

## Why this is a strong WebMCP use case

Vulnerability triage crosses structured public data, technical asset context, business criticality, and accountable remediation decisions. Today, an agent looking at a dashboard must scrape rows and guess which UI controls are safe. PatchPilot exposes four narrow, typed WebMCP tools that call the same application logic as the visible interface.

The result is a genuine human-agent collaboration loop: the agent performs the repetitive investigation and drafting work; the human supplies context, sees each result appear in the page, examines the score signals, modifies the proposed owner or due date, and makes the approval decision. Approval is deliberately not exposed as a tool.

## What was built

- One responsive triage dashboard.
- A 15-asset fictional inventory with service ownership, exposure, installed product/version, and business criticality.
- A bundled public CVE/KEV snapshot plus live CISA KEV refresh and visible fallback behavior.
- Four tools registered with `document.modelContext.registerTool`.
- Explainable severity + exploitation + exposure + criticality scoring.
- A shared seven-day remediation board and activity trail.
- Human-only recommendation editing and approval.
- Desktop/mobile interaction tests, tool-contract tests, and automated accessibility checks.

## WebMCP implementation

PatchPilot statically registers:

1. `search_vulnerabilities`
2. `find_affected_assets`
3. `prioritize_findings`
4. `create_remediation_plan`

Each tool has a concise description, JSON Schema, strict runtime validation, security annotations, bounded output, cancellation handling, and a visible state update before resolution. Registrations use `document.modelContext` and are owned by one `AbortController`. The app feature-detects the experimental API and keeps the full human workflow usable when it is unavailable.

## Suggested 2:35 demo script

### 0:00–0:20 — Problem and trust boundary

Show the dashboard, the clean-room badge, and synthetic inventory. Explain that vulnerability teams spend time joining exploitation evidence with business context, but remediation decisions still need accountable human judgment.

### 0:20–0:40 — Tool registry

Open Tool Registry. Show all four registered WebMCP tools and the annotations. Point out that there is no approval tool.

### 0:40–1:25 — Agent workflow

Give the agent this prompt:

> Find actively exploited vulnerabilities affecting our internet-facing systems, prioritize the top three, and create a seven-day remediation plan.

As the agent calls each tool, show the catalog scope, affected findings, ranked top three, activity trail, and completed workflow stages changing in the page.

### 1:25–2:10 — Shared board and human judgment

Open one finding to show the transparent 100-point score and public NVD link. Modify one proposed owner or date, save it, then approve a recommendation. Emphasize that the agent drafted the plan but could not make the approval decision.

### 2:10–2:35 — Reliability and impact

Show the live/snapshot data indicator and briefly mention graceful fallback. Close with the outcome: structured tools let an agent do the repetitive correlation work reliably while a person keeps business context, accountability, and control.

## Submission checklist

- [x] Public HTTPS deployment is live and tested in desktop and mobile Chrome.
- [x] Public source branch includes source, setup/testing instructions, `LICENSE`, and visible `document.modelContext.registerTool` usage.
- [ ] Public YouTube demo has audio and is under 3:00 (target 2:35).
- [ ] Devpost description includes problem, user benefit, collaboration, and WebMCP implementation.
- [ ] Video and screenshots contain only this clean-room interface.
- [ ] Release is frozen at least one day before the deadline.
