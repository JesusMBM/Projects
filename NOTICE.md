# Data and dependency notice

PatchPilot is an original clean-room demonstration. The MIT License applies to the source code in this repository, not to third-party names, vulnerability records, or software packages.

## Public vulnerability facts

The fallback dataset contains short, independently written summaries of selected CVE facts and links each entry to its NVD record. CISA KEV status, dates, required actions, and ransomware-use indicators may be refreshed from the official CISA JSON feed at runtime.

- CISA KEV catalog and feed: review the [CISA website policies](https://www.cisa.gov/about/website-policies) and catalog documentation.
- NVD/CVE facts: review the [NVD data policies](https://nvd.nist.gov/general/faq) and individual linked vulnerability records.

Vendor and product names identify the affected public products and do not imply affiliation or endorsement. The app contains no vendor logos.

## Synthetic inventory

All asset identifiers, hostnames, owners, services, versions, counts, criticality values, and remediation records were created for this demo. Any resemblance to a real environment is coincidental.

## Third-party packages

Runtime and development packages are installed from npm and retain their own licenses. Notable packages include React, Vite, Lucide, Vitest, Playwright, axe-core, TypeScript, ESLint, and `webmcp-types`. See `package-lock.json` for the exact dependency graph.
