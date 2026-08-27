# WebMCP Challenge submission draft

**Project:** PatchPilot — Agent-Powered Vulnerability Triage

**Tagline:** From 12 exploited CVEs to 3 accountable remediation decisions.

**Live application:** [https://patchpilot-webmcp.netlify.app](https://patchpilot-webmcp.netlify.app)

**Public source:** [github.com/JesusMBM/Projects/tree/patchpilot-webmcp](https://github.com/JesusMBM/Projects/tree/patchpilot-webmcp)

## Short description

PatchPilot is a shared vulnerability-triage workspace built for browser agents and human reviewers. Four native WebMCP tools search public CVE/CISA KEV facts, correlate them with a 15-asset synthetic inventory, rank affected systems with an explainable business-aware score, and stage a bounded remediation plan. The results appear in the same dashboard a person uses to inspect evidence, change ownership or dates, and approve recommendations. Approval is deliberately not a WebMCP tool.

## The problem

Vulnerability teams do more than sort CVSS scores. They join exploitation evidence, installed software, external exposure, service ownership, business criticality, and remediation deadlines. That work is repetitive enough for an agent, but the final decision carries operational accountability and should remain visible and human-controlled.

A conventional browser agent must scrape a table and infer what every button means. PatchPilot gives the agent explicit, bounded operations while letting the reviewer see every state change, score signal, proposal, and activity event.

## What PatchPilot demonstrates

With the bundled clean-room baseline and default context, the native tool chain produces a repeatable outcome:

```text
12 actively exploited CVEs
             ↓ search_vulnerabilities
 8 internet-facing asset matches
             ↓ find_affected_assets
 3 highest-priority findings
             ↓ prioritize_findings
 3 proposed remediation items
             ↓ human review and confirmation
 1 accountable approval
```

The **12 → 8 → 3 → 3** chain was exercised through actual `document.modelContext` callbacks in Chrome 151. All four stages updated visibly, three proposal cards appeared, and no console warnings or errors were produced.

## Why WebMCP is essential

PatchPilot registers these tools with `document.modelContext.registerTool(...)`:

1. `search_vulnerabilities`
2. `find_affected_assets`
3. `prioritize_findings`
4. `create_remediation_plan`

The tools call the same deterministic domain functions as the visible application and update shared state before resolving. Schemas are backed by strict runtime validation, bounded output, explicit total/returned/truncated counts, cancellation handling, and security annotations.

The boundary is intentional: `create_remediation_plan` can add only `proposed` items. Its result explicitly states that approval is required, the agent cannot approve, and the next actor must be human. There is no `approve_remediation` tool. A reviewer must use the page's confirmation dialog.

## Context changes the result

The reviewer can set the organization's risk posture, exposure scope, response window, and business focus before the agent runs. The first three are causal tool defaults:

- Aggressive posture defaults to CISA KEV-only search.
- Balanced posture defaults to CVSS 7.0 or higher.
- Exposure scope controls asset matching and plan candidates.
- The selected response window controls scheduling; direct tool input remains bounded to 1–30 days.

Tool responses return the complete context they applied, keeping the assumptions inspectable by both agent and reviewer. The guided preview carries the stated business focus into its plan rationale, while a native agent can pass that focus explicitly as the plan `objective`.

## Explainable prioritization

The score is intentionally simple: up to 50 points for CVSS, 25 for CISA KEV, 15 for internet exposure, and 10 for synthetic business criticality. Known ransomware use contributes **zero points** and is disclosed only as a tie-breaker between equal scores; stable finding ID is the final tie-breaker. PatchPilot presents the model as triage assistance, not as a scanner or exploitability verdict.

## Reliable public-data boundary

The browser calls a same-origin `/api/cisa-kev` endpoint. A fixed-purpose Netlify Function retrieves the official feed, applies a timeout and body-size limit, validates the catalog envelope and entries, caps the accepted record count, and serves cacheable JSON. If the function, upstream service, network, or validation fails, the dashboard visibly retains a bundled public-data snapshot. All inventory and remediation records are synthetic.

## Judge quick verification

1. Use ChatGPT's in-app browser, or enable `chrome://flags/#enable-webmcp-testing` in Chrome and restart it. Chrome 151 is the verified native environment.
2. Open the live URL as a top-level page and confirm that Tool Registry reports four ready tools.
3. Ask: “Find actively exploited vulnerabilities affecting our internet-facing systems, prioritize the top three, and create a seven-day remediation plan.”
4. Confirm the visible **12 → 8 → 3 → 3** completion trace, activity events, and three proposed cards.
5. Inspect a risk explanation, edit one proposal, and approve it through the human confirmation dialog.

The current Netlify origin does not include a Chrome Origin Trial token. Ordinary Chrome without the testing flag may report WebMCP unavailable and expose the guided preview instead. The native WebMCP proof should be judged or recorded in one of the supported environments above.

## Exact 2:25 demo script

Record the native agent flow. Do not substitute the guided preview for the four WebMCP calls.

### 0:00–0:12 — Hook

Show the dashboard and say:

> Twelve actively exploited CVEs. Eight touch reachable systems. Which three get fixed this week—and who gets to decide?

### 0:12–0:20 — Give the browser agent its objective

Paste or say:

> Find actively exploited vulnerabilities affecting our internet-facing systems, prioritize the top three, and create a seven-day remediation plan.

Keep the dashboard and agent invocation visible; the first native tool call should begin before 0:20.

### 0:20–0:58 — Show the four native calls

As the agent invokes each registered tool, track the visible stages and say only what changed:

> Search found 12 exploited CVEs. Explicit product and version matching found 8 exposed assets. The scoring model selected the top 3. The planning tool staged 3 proposals—nothing was approved.

End on the completed trace and shared board.

### 0:58–1:12 — Prove the trust boundary

Open Tool Registry, point to the four registered tools, and say:

> Search, match, rank, and draft are exposed. Approval is deliberately absent. The final tool says the required next actor is human.

### 1:12–1:38 — Explain one decision

Open the first finding. Show its CVSS, KEV, exposure, and criticality signals, plus the NVD link. Say:

> The score is deterministic and inspectable. Ransomware evidence adds no hidden points; it only breaks an exact tie.

### 1:38–2:02 — Make the human decision

Edit the owner or due date, add a short note, save, then click approve. Pause on the confirmation dialog before confirming. Say:

> The agent drafted the work. A reviewer can change it, sees exactly what approval means, and owns the decision.

Confirm and show the activity trail recording the human action.

### 2:02–2:15 — Establish reliability and clean-room scope

Show the data-source label without triggering a risky live refresh during the recording. Say:

> Live CISA data crosses a validated same-origin function. If it fails, the bundled public snapshot stays usable. Every asset and remediation record here is synthetic.

### 2:15–2:25 — Close on the outcome

Return to the completed board and say:

> PatchPilot lets an agent do the repetitive investigation through structured tools while a person keeps context, accountability, and control.

## Three-screenshot submission plan

1. **“Triage at a glance”** — 1440 px desktop view before the run. Include the PatchPilot identity, clean-room/data-source badges, context summary, headline metrics, and agent panel. Caption: “A clean-room vulnerability workspace shared by a browser agent and human reviewer.”
2. **“Native WebMCP: 12 → 8 → 3 → 3”** — Capture the completed four-stage trace, visible findings, and newest WebMCP activity events immediately after the native run. Caption: “Four typed tools search, match, rank, and draft into the same visible application state.”
3. **“Human accountability by design”** — Capture the three-item proposal board with one approval confirmation dialog open and the edited fields visible behind it. Caption: “The agent can propose; a person reviews, changes, and explicitly approves.”

Use consistent 1440 × 900 framing, 100% browser zoom, no personal tabs or bookmarks, and only clean-room data. Lead the gallery with screenshot 2 if the submission site uses the first image as its card.

## Technical highlights

- React 19, TypeScript, and Vite for the single-page workspace.
- Four statically registered WebMCP tools with shared-state updates.
- Pure deterministic search, version matching, scoring, and scheduling functions.
- Same-origin Netlify Function for validated CISA KEV retrieval and caching.
- Bundled fallback data and a 15-asset fictional inventory.
- Confirmation-based human approval with no approval tool registered.
- Unit, tool-contract, serverless boundary, desktop/mobile, native-shim, visual, and accessibility checks.

## Scope and clean-room statement

PatchPilot was built from scratch with public vulnerability facts and synthetic assets. It contains no employer code, internal asset information, remediation decisions, screenshots, names, tickets, scoring logic, or workflows. It intentionally omits authentication, real scanner ingestion, generic CPE resolution, persistence, ticketing, notifications, and automated approval.

## Submission checklist

- [x] Public HTTPS URL exists.
- [x] Public source branch includes setup instructions, WebMCP implementation, license, and clean-room notice.
- [x] Deploy the final release and repeat the native **12 → 8 → 3 → 3** smoke test on the live URL (Chrome 151; zero console warnings/errors, page errors, or failed requests).
- [ ] Decide whether to enroll the exact production origin in the applicable Chrome Origin Trial; otherwise document and record the supported flagged-Chrome path.
- [ ] Capture the three final screenshots using the plan above.
- [ ] Record the native-agent demo with audio in 2:25 or less.
- [ ] Upload the public YouTube video and verify playback, audio, captions, and visibility.
- [ ] Paste the final description, links, screenshots, and video into Devpost and preview the entry.
- [ ] Confirm every submission artifact contains only the clean-room interface and synthetic data.
- [ ] Freeze the verified release before the deadline.
