import type { Context } from '@netlify/functions';
import { afterEach, describe, expect, it, vi } from 'vitest';
import cisaKevHandler, { config } from '../netlify/functions/cisa-kev.mts';

const validKevEntry = {
  cveID: 'CVE-2024-3400',
  vendorProject: 'Palo Alto Networks',
  product: 'PAN-OS',
  vulnerabilityName: 'PAN-OS Command Injection Vulnerability',
  dateAdded: '2024-04-12',
  shortDescription: 'A command injection vulnerability affecting PAN-OS.',
  requiredAction: 'Apply mitigations per vendor instructions.',
  dueDate: '2024-04-19',
  knownRansomwareCampaignUse: 'Unknown',
};

const invoke = (method = 'GET') => cisaKevHandler(
  new Request('https://patchpilot.example/api/cisa-kev', { method }),
  {} as Context,
);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('CISA KEV Netlify function', () => {
  it('uses a stable same-origin endpoint', () => {
    expect(config.path).toBe('/api/cisa-kev');
  });

  it('returns validated entries with edge-cache and content-safety headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      title: 'CISA Known Exploited Vulnerabilities Catalog',
      catalogVersion: '2026.08.27-test',
      dateReleased: '2026-08-27T12:00:00.000Z',
      vulnerabilities: [
        validKevEntry,
        { ...validKevEntry, cveID: 'not-a-cve' },
      ],
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const response = await invoke();
    const body = await response.json() as {
      catalogVersion: string;
      vulnerabilities: typeof validKevEntry[];
    };

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, s-maxage=900, stale-while-revalidate=86400');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(body.catalogVersion).toBe('2026.08.27-test');
    expect(body.vulnerabilities).toEqual([validKevEntry]);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      expect.objectContaining({
        headers: { Accept: 'application/json' },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('rejects non-GET requests without contacting CISA', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const response = await invoke('POST');

    expect(response.status).toBe(405);
    expect(response.headers.get('cache-control')).toBe('no-store');
    await expect(response.json()).resolves.toEqual({ error: 'Method not allowed' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('converts an upstream failure into a non-cacheable 502 response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('unavailable', { status: 503 })));

    const response = await invoke();

    expect(response.status).toBe(502);
    expect(response.headers.get('cache-control')).toBe('no-store');
    await expect(response.json()).resolves.toEqual({ error: 'CISA KEV returned HTTP 503' });
  });
});
