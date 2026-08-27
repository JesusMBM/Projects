# Data and dependency notice

PatchPilot is an original clean-room demonstration. The MIT License applies to the source code in this repository, not to third-party names, vulnerability records, upstream services, or software packages.

## Public vulnerability facts

The bundled fallback contains short, independently written summaries of selected CVE facts and links each entry to its NVD record. CISA KEV status, dates, required actions, and known-ransomware-use indicators may be overlaid from the official CISA JSON feed when a reviewer requests a live refresh.

- CISA KEV catalog and feed: review the [CISA website policies](https://www.cisa.gov/about/website-policies) and catalog documentation.
- NVD/CVE facts: review the [NVD data policies](https://nvd.nist.gov/general/faq) and individual linked vulnerability records.

Vendor and product names identify affected public products and do not imply affiliation or endorsement. The app contains no vendor logos.

## Live-data path

The browser does not request the CISA domain directly. It calls the same-origin `/api/cisa-kev` endpoint, implemented as a fixed-purpose Netlify Function. The function:

- accepts `GET` only;
- retrieves the published CISA KEV JSON feed with a seven-second timeout;
- rejects oversized bodies and malformed catalog envelopes;
- validates required fields on each CVE entry and discards malformed entries;
- caps processing at 5,000 entries;
- returns a `502` response when no valid catalog can be established; and
- allows successful responses to be cached for 15 minutes, with stale-while-revalidate support.

The client validates the received entries again before merging public KEV metadata with the bundled records. If the function, network, upstream service, parsing, or validation fails, PatchPilot displays the failure and continues with its bundled snapshot. The live response is not written to a project database, and synthetic product/version mappings are never sent to CISA.

## Synthetic inventory and decisions

All asset identifiers, hostnames, owners, services, versions, counts, criticality values, organization context, and remediation records were created for this demo. Any resemblance to a real environment is coincidental.

No employer code, internal asset information, remediation decisions, screenshots, names, tickets, scoring logic, or operational workflows were used. The bundled data and deterministic matching rules were created specifically for this clean-room project.

## Model and decision boundary

The displayed risk score combines public CVSS and KEV facts with synthetic exposure and criticality. Known ransomware use contributes zero score points and is used only as a tie-breaker between equal scores. Scores and recommendations are demonstration aids, not scanner results, exploitability determinations, compliance evidence, or production risk decisions.

The WebMCP registry exposes search, asset matching, prioritization, and proposal creation. It does not expose approval. A generated board item remains `proposed` until a person acts through the page's confirmation dialog.

## Third-party packages

Runtime and development packages are installed from npm and retain their own licenses. Notable packages include React, Vite, Lucide, Vitest, Playwright, axe-core, TypeScript, ESLint, `@netlify/functions`, and `webmcp-types`. See `package-lock.json` for the exact dependency graph.

## Browser availability

WebMCP is experimental. The production origin does not currently claim Chrome Origin Trial enrollment. Native tools require a supported agent environment, such as ChatGPT's in-app browser or Chrome with the WebMCP testing flag enabled and the browser restarted. The guided preview keeps the human workflow demonstrable when the experimental API is unavailable, but it is labeled separately from native WebMCP execution.
