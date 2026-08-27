import type { Config, Context } from '@netlify/functions';

const CISA_KEV_FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const MAX_BODY_CHARACTERS = 5_000_000;
const MAX_ENTRIES = 5_000;

function boundedString(value: unknown, maxLength: number) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

function isKevEntry(value: unknown) {
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

function jsonResponse(body: unknown, status: number, cacheControl: string) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Cache-Control': cacheControl,
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export default async (request: Request, _context: Context) => {
  if (request.method !== 'GET') {
    return jsonResponse({ error: 'Method not allowed' }, 405, 'no-store');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7_000);

  try {
    const upstream = await fetch(CISA_KEV_FEED, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!upstream.ok) {
      return jsonResponse({ error: `CISA KEV returned HTTP ${upstream.status}` }, 502, 'no-store');
    }

    const rawBody = await upstream.text();
    if (rawBody.length > MAX_BODY_CHARACTERS) {
      return jsonResponse({ error: 'CISA KEV response exceeded the allowed size' }, 502, 'no-store');
    }
    const catalog = JSON.parse(rawBody) as {
      title?: unknown;
      catalogVersion?: unknown;
      dateReleased?: unknown;
      vulnerabilities?: unknown;
    };
    if (
      typeof catalog.catalogVersion !== 'string'
      || typeof catalog.dateReleased !== 'string'
      || !Array.isArray(catalog.vulnerabilities)
    ) {
      return jsonResponse({ error: 'CISA KEV response did not match the expected catalog format' }, 502, 'no-store');
    }

    const vulnerabilities = catalog.vulnerabilities.slice(0, MAX_ENTRIES).filter(isKevEntry);
    if (vulnerabilities.length === 0) {
      return jsonResponse({ error: 'CISA KEV response contained no valid entries' }, 502, 'no-store');
    }

    return jsonResponse({
      title: boundedString(catalog.title, 300) ? catalog.title : 'CISA Known Exploited Vulnerabilities Catalog',
      catalogVersion: catalog.catalogVersion,
      dateReleased: catalog.dateReleased,
      vulnerabilities,
    }, 200, 'public, s-maxage=900, stale-while-revalidate=86400');
  } catch (error) {
    const message = error instanceof Error && error.name === 'AbortError'
      ? 'CISA KEV request timed out'
      : 'CISA KEV request failed';
    return jsonResponse({ error: message }, 502, 'no-store');
  } finally {
    clearTimeout(timeout);
  }
};

export const config: Config = {
  path: '/api/cisa-kev',
};
