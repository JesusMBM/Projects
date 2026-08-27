import type {
  AffectedAssetsInput,
  Asset,
  Finding,
  PlanInput,
  PrioritizeInput,
  RemediationItem,
  SearchInput,
  SearchResult,
  Vulnerability,
} from './types';

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

export function searchVulnerabilities(
  vulnerabilities: Vulnerability[],
  input: SearchInput = {},
): SearchResult {
  const query = input.query?.trim().toLocaleLowerCase() ?? '';
  const limit = clamp(Math.floor(input.limit ?? 20), 1, 50);

  const matches = vulnerabilities.filter((vulnerability) => {
    if (input.knownExploitedOnly && !vulnerability.knownExploited) return false;
    if (input.severity && vulnerability.severity !== input.severity) return false;
    if (input.minCvss !== undefined && (vulnerability.cvss ?? 0) < input.minCvss) return false;
    if (!query) return true;

    return [
      vulnerability.cveId,
      vulnerability.vendor,
      vulnerability.product,
      vulnerability.title,
      vulnerability.description,
    ].some((value) => value.toLocaleLowerCase().includes(query));
  });

  return { vulnerabilities: matches.slice(0, limit), total: matches.length };
}

export function riskScore(vulnerability: Vulnerability, asset: Asset) {
  const severityPoints = Math.round((vulnerability.cvss ?? 0) * 5);
  const exploitationPoints = vulnerability.knownExploited ? 25 : 0;
  const exposurePoints = asset.internetFacing ? 15 : 0;
  const businessPoints = asset.criticality * 2;
  const score = clamp(severityPoints + exploitationPoints + exposurePoints + businessPoints, 0, 100);

  const signals = [
    `${vulnerability.cvss?.toFixed(1) ?? 'N/A'} CVSS`,
    vulnerability.knownExploited ? 'CISA KEV' : 'No KEV evidence',
    asset.internetFacing ? 'Internet-facing' : 'Internal exposure',
    `Criticality ${asset.criticality}/5`,
  ];

  const tier: Finding['tier'] = score >= 90 ? 'urgent' : score >= 75 ? 'high' : score >= 55 ? 'guarded' : 'routine';
  return { score, signals, tier };
}

export function findAffectedAssets(
  vulnerabilities: Vulnerability[],
  assets: Asset[],
  input: AffectedAssetsInput = {},
): Finding[] {
  const cveFilter = input.cveIds?.length
    ? new Set(input.cveIds.map((cveId) => cveId.toLocaleUpperCase()).slice(0, 50))
    : null;
  const findings: Finding[] = [];

  for (const vulnerability of vulnerabilities) {
    if (cveFilter && !cveFilter.has(vulnerability.cveId)) continue;

    for (const asset of assets) {
      if (input.internetFacingOnly && !asset.internetFacing) continue;

      for (const software of asset.software) {
        const rule = vulnerability.affectedProducts.find(
          (candidate) => candidate.productId === software.productId && candidate.versions.includes(software.version),
        );
        if (!rule) continue;

        const scored = riskScore(vulnerability, asset);
        findings.push({
          id: `${vulnerability.cveId}:${asset.id}`,
          vulnerability,
          asset,
          software,
          fixVersion: rule.fixVersion,
          score: scored.score,
          tier: scored.tier,
          scoreSignals: scored.signals,
        });
      }
    }
  }

  return findings;
}

export function prioritizeFindings(findings: Finding[], input: PrioritizeInput = {}): Finding[] {
  const cveFilter = input.cveIds?.length
    ? new Set(input.cveIds.map((cveId) => cveId.toLocaleUpperCase()).slice(0, 50))
    : null;
  const limit = clamp(Math.floor(input.limit ?? 50), 1, 50);

  return findings
    .filter((finding) => (!input.internetFacingOnly || finding.asset.internetFacing))
    .filter((finding) => !cveFilter || cveFilter.has(finding.vulnerability.cveId))
    .sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      if (left.vulnerability.knownRansomware !== right.vulnerability.knownRansomware) {
        return left.vulnerability.knownRansomware ? -1 : 1;
      }
      return left.id.localeCompare(right.id);
    })
    .slice(0, limit);
}

function addDays(date: Date, days: number) {
  const copy = new Date(date);
  copy.setDate(copy.getDate() + days);
  return copy.toISOString().slice(0, 10);
}

export function createRemediationPlan(
  prioritizedFindings: Finding[],
  existing: RemediationItem[],
  input: PlanInput = {},
  now = new Date(),
): RemediationItem[] {
  const count = clamp(Math.floor(input.count ?? 3), 1, 3);
  const windowDays = clamp(Math.floor(input.windowDays ?? 7), 1, 30);
  const findingFilter = input.findingIds?.length
    ? new Set(input.findingIds.slice(0, 10))
    : null;
  const existingFindingIds = new Set(existing.map((item) => item.findingId));
  const candidates = prioritizedFindings
    .filter((finding) => !findingFilter || findingFilter.has(finding.id))
    .filter((finding) => !existingFindingIds.has(finding.id))
    .slice(0, count);

  const targetDays = candidates.map((_, index) => {
    if (candidates.length === 1) return windowDays;
    return Math.max(1, Math.round(1 + (index * (windowDays - 1)) / (candidates.length - 1)));
  });

  return candidates.map((finding, index) => ({
    id: `REM-${finding.vulnerability.cveId.replace('CVE-', '')}-${finding.asset.id}`,
    findingId: finding.id,
    cveId: finding.vulnerability.cveId,
    assetId: finding.asset.id,
    hostname: finding.asset.hostname,
    service: finding.asset.service,
    owner: finding.asset.owner,
    status: 'proposed',
    dueDate: addDays(now, targetDays[index]),
    targetDay: targetDays[index],
    action: `Upgrade ${finding.software.name} ${finding.software.version} to ${finding.fixVersion}.`,
    validation: `Confirm the fixed version on ${finding.asset.hostname}, re-scan, and review service telemetry.`,
    rationale: `${finding.score}/100 risk: ${finding.scoreSignals.join(' · ')}. ${input.objective?.trim() || `Prioritized for the active ${windowDays}-day response window.`}`,
    notes: '',
    score: finding.score,
    createdAt: now.toISOString(),
    approvedAt: null,
  }));
}

export function severityFromCvss(cvss: number | null): Vulnerability['severity'] {
  if (cvss === null) return 'unknown';
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  return 'low';
}
