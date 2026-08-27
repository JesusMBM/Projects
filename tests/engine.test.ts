import { describe, expect, it } from 'vitest';
import { inventory } from '../src/data/inventory';
import { vulnerabilitySnapshot } from '../src/data/vulnerabilities';
import {
  createRemediationPlan,
  findAffectedAssets,
  prioritizeFindings,
  riskScore,
  searchVulnerabilities,
} from '../src/domain/engine';

describe('PatchPilot triage engine', () => {
  it('uses exactly fifteen synthetic assets', () => {
    expect(inventory).toHaveLength(15);
    expect(inventory.every((asset) => asset.id.startsWith('AST-'))).toBe(true);
  });

  it('searches KEV and CVSS constraints deterministically', () => {
    const result = searchVulnerabilities(vulnerabilitySnapshot, {
      query: 'screenconnect',
      knownExploitedOnly: true,
      minCvss: 9,
    });
    expect(result.total).toBe(1);
    expect(result.vulnerabilities[0].cveId).toBe('CVE-2024-1709');
  });

  it('matches only explicit synthetic product/version pairs', () => {
    const findings = findAffectedAssets(vulnerabilitySnapshot, inventory, {
      cveIds: ['CVE-2024-3400'],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].asset.hostname).toBe('perimeter-fw-01');
    expect(findings[0].fixVersion).toContain('10.2.9-h1');
  });

  it('makes the transparent score add to 100 for the highest-risk edge finding', () => {
    const vulnerability = vulnerabilitySnapshot.find((item) => item.cveId === 'CVE-2024-3400')!;
    const asset = inventory.find((item) => item.id === 'AST-001')!;
    const result = riskScore(vulnerability, asset);
    expect(result.score).toBe(100);
    expect(result.signals).toEqual(['10.0 CVSS', 'CISA KEV', 'Internet-facing', 'Criticality 5/5']);
  });

  it('ranks exploited internet-facing findings and creates only proposed work', () => {
    const affected = findAffectedAssets(vulnerabilitySnapshot, inventory, { internetFacingOnly: true });
    const prioritized = prioritizeFindings(affected, { limit: 3 });
    const plan = createRemediationPlan(
      prioritized,
      [],
      { count: 3, windowDays: 7 },
      new Date('2026-08-27T12:00:00.000Z'),
    );

    expect(prioritized).toHaveLength(3);
    expect(prioritized[0].score).toBeGreaterThanOrEqual(prioritized[1].score);
    expect(plan).toHaveLength(3);
    expect(plan.every((item) => item.status === 'proposed' && item.approvedAt === null)).toBe(true);
    expect(plan.map((item) => item.targetDay)).toEqual([1, 4, 7]);
    expect(plan.at(-1)?.dueDate).toBe('2026-09-03');
  });

  it('deduplicates existing board recommendations', () => {
    const prioritized = prioritizeFindings(
      findAffectedAssets(vulnerabilitySnapshot, inventory, { internetFacingOnly: true }),
      { limit: 3 },
    );
    const existing = createRemediationPlan(prioritized, [], { count: 3 }, new Date('2026-08-27T12:00:00Z'));
    const duplicateAttempt = createRemediationPlan(prioritized, existing, { count: 3 }, new Date('2026-08-27T12:00:00Z'));
    expect(duplicateAttempt).toEqual([]);
  });
});
