import { publicDataSources } from '../data/vulnerabilities';
import { severityFromCvss } from '../domain/engine';
import type { Vulnerability } from '../domain/types';

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown' | string;
}

interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  vulnerabilities: KevEntry[];
}

function boundedString(value: unknown, maxLength: number) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

function isKevEntry(value: unknown): value is KevEntry {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const entry = value as Record<string, unknown>;
  return typeof entry.cveID === 'string'
    && /^CVE-\d{4}-\d{4,7}$/.test(entry.cveID)
    && boundedString(entry.vendorProject, 160)
    && boundedString(entry.product, 160)
    && boundedString(entry.vulnerabilityName, 300)
    && boundedString(entry.dateAdded, 40)
    && boundedString(entry.shortDescription, 2_000)
    && boundedString(entry.requiredAction, 2_000)
    && boundedString(entry.dueDate, 40)
    && boundedString(entry.knownRansomwareCampaignUse, 40);
}

export interface KevRefreshResult {
  vulnerabilities: Vulnerability[];
  catalogVersion: string;
  dateReleased: string;
}

function toLiveOnlyVulnerability(entry: KevEntry): Vulnerability {
  return {
    cveId: entry.cveID,
    vendor: entry.vendorProject,
    product: entry.product,
    title: entry.vulnerabilityName,
    description: entry.shortDescription,
    cvss: null,
    severity: severityFromCvss(null),
    knownExploited: true,
    knownRansomware: entry.knownRansomwareCampaignUse === 'Known',
    dateAdded: entry.dateAdded,
    cisaDueDate: entry.dueDate,
    published: entry.dateAdded,
    requiredAction: entry.requiredAction,
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${entry.cveID}`,
    affectedProducts: [],
  };
}

export async function refreshKevCatalog(
  snapshot: Vulnerability[],
  parentSignal?: AbortSignal,
): Promise<KevRefreshResult> {
  const timeout = AbortSignal.timeout(5_000);
  const signal = parentSignal ? AbortSignal.any([parentSignal, timeout]) : timeout;
  const response = await fetch(publicDataSources.cisaKevFeed, {
    signal,
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) throw new Error(`CISA KEV returned HTTP ${response.status}`);
  const catalog = (await response.json()) as Partial<KevCatalog>;
  if (!Array.isArray(catalog.vulnerabilities) || !catalog.catalogVersion || !catalog.dateReleased) {
    throw new Error('CISA KEV response did not match the expected catalog format');
  }

  const validEntries = catalog.vulnerabilities.slice(0, 5_000).filter(isKevEntry);
  if (validEntries.length === 0) throw new Error('CISA KEV response contained no valid entries');

  const liveByCve = new Map(validEntries.map((entry) => [entry.cveID, entry]));
  const merged = snapshot.map((vulnerability) => {
    const live = liveByCve.get(vulnerability.cveId);
    if (!live) return { ...vulnerability, knownExploited: false };
    liveByCve.delete(vulnerability.cveId);
    return {
      ...vulnerability,
      knownExploited: true,
      knownRansomware: live.knownRansomwareCampaignUse === 'Known',
      dateAdded: live.dateAdded,
      cisaDueDate: live.dueDate,
      requiredAction: live.requiredAction,
    };
  });

  const liveOnly = [...liveByCve.values()].map(toLiveOnlyVulnerability);
  return {
    vulnerabilities: [...merged, ...liveOnly],
    catalogVersion: catalog.catalogVersion,
    dateReleased: catalog.dateReleased,
  };
}
