import type { Severity } from '../domain/types';
import { patchPilotStore } from '../store/patchPilotStore';

type ToolInput = Record<string, unknown>;

function isRecord(value: unknown): value is ToolInput {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, name: string, maxLength: number) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new Error(`${name} must be a string`);
  const trimmed = value.trim();
  if (trimmed.length > maxLength) throw new Error(`${name} must be ${maxLength} characters or fewer`);
  return trimmed;
}

function boundedInteger(value: unknown, name: string, min: number, max: number) {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value as number;
}

function boundedNumber(value: unknown, name: string, min: number, max: number) {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    throw new Error(`${name} must be a number from ${min} to ${max}`);
  }
  return value;
}

function optionalBoolean(value: unknown, name: string) {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new Error(`${name} must be true or false`);
  return value;
}

function idArray(value: unknown, name: string, pattern: RegExp, max = 50) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > max || !value.every((item) => typeof item === 'string' && pattern.test(item))) {
    throw new Error(`${name} must be an array of no more than ${max} valid IDs`);
  }
  return [...new Set(value as string[])];
}

function safeExecute(handler: (input: ToolInput) => unknown | Promise<unknown>) {
  return async (input: ToolInput, { signal }: WebMCP.ToolExecuteCallbackOptions) => {
    if (signal.aborted) return { ok: false, error: 'Tool execution was cancelled' };
    try {
      if (!isRecord(input)) throw new Error('Tool input must be a JSON object');
      return await handler(input);
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : 'Tool execution failed' };
    }
  };
}

export function buildPatchPilotTools(): WebMCP.ModelContextTool[] {
  return [
    {
      name: 'search_vulnerabilities',
      title: 'Search vulnerabilities',
      description: 'Search the loaded public CVE and CISA KEV catalog by CVE ID, vendor, product, severity, exploitation status, or minimum CVSS. Updates the visible catalog results.',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Optional CVE ID, vendor, product, or keyword.', maxLength: 100 },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'unknown'], description: 'Optional severity filter.' },
          knownExploitedOnly: { type: 'boolean', description: 'When true, include only CISA KEV entries.' },
          minCvss: { type: 'number', minimum: 0, maximum: 10, description: 'Optional minimum CVSS base score.' },
          limit: { type: 'integer', minimum: 1, maximum: 12, description: 'Maximum results to return.' },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: safeExecute((input) => {
        const severity = boundedString(input.severity, 'severity', 12) as Severity | undefined;
        if (severity && !['critical', 'high', 'medium', 'low', 'unknown'].includes(severity)) {
          throw new Error('severity must be critical, high, medium, low, or unknown');
        }
        const result = patchPilotStore.search({
          query: boundedString(input.query, 'query', 100),
          severity,
          knownExploitedOnly: optionalBoolean(input.knownExploitedOnly, 'knownExploitedOnly'),
          minCvss: boundedNumber(input.minCvss, 'minCvss', 0, 10),
          limit: boundedInteger(input.limit, 'limit', 1, 12),
        });
        return {
          ok: true,
          count: result.total,
          vulnerabilities: result.vulnerabilities.slice(0, 12).map((item) => ({
            cveId: item.cveId,
            product: `${item.vendor} ${item.product}`,
            cvss: item.cvss,
            knownExploited: item.knownExploited,
          })),
        };
      }),
    },
    {
      name: 'find_affected_assets',
      title: 'Find affected assets',
      description: 'Cross-reference CVE IDs with the 15-asset synthetic inventory using deterministic product and version mappings. Updates the visible findings table.',
      inputSchema: {
        type: 'object',
        properties: {
          cveIds: { type: 'array', items: { type: 'string', pattern: '^CVE-[0-9]{4}-[0-9]{4,7}$' }, maxItems: 50, description: 'Optional CVE IDs to correlate.' },
          internetFacingOnly: { type: 'boolean', description: 'When true, include only internet-facing assets.' },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: safeExecute((input) => {
        const findings = patchPilotStore.findAffected({
          cveIds: idArray(input.cveIds, 'cveIds', /^CVE-\d{4}-\d{4,7}$/),
          internetFacingOnly: optionalBoolean(input.internetFacingOnly, 'internetFacingOnly'),
        });
        return {
          ok: true,
          count: findings.length,
          findings: findings.slice(0, 12).map((finding) => ({
            findingId: finding.id,
            cveId: finding.vulnerability.cveId,
            asset: finding.asset.hostname,
            service: finding.asset.service,
          })),
        };
      }),
    },
    {
      name: 'prioritize_findings',
      title: 'Prioritize findings',
      description: 'Rank affected synthetic assets with an explainable 100-point score using CVSS, CISA KEV status, internet exposure, and business criticality. Updates the visible ranking.',
      inputSchema: {
        type: 'object',
        properties: {
          findingIds: { type: 'array', items: { type: 'string', pattern: '^CVE-[0-9]{4}-[0-9]{4,7}:AST-[0-9]{3}$' }, maxItems: 50, description: 'Optional finding IDs from asset correlation.' },
          limit: { type: 'integer', minimum: 1, maximum: 10, description: 'Number of ranked findings to return.' },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      execute: safeExecute((input) => {
        const findingIds = idArray(input.findingIds, 'findingIds', /^CVE-\d{4}-\d{4,7}:AST-\d{3}$/);
        if (findingIds?.some((id) => !patchPilotStore.getState().findings.some((finding) => finding.id === id))) {
          throw new Error('findingIds contains an ID that is not present in the current findings view');
        }
        const findings = patchPilotStore.prioritize({
          findingIds,
          limit: boundedInteger(input.limit, 'limit', 1, 10) ?? 3,
        });
        return {
          ok: true,
          count: findings.length,
          findings: findings.map((finding, index) => ({
            rank: index + 1,
            findingId: finding.id,
            cveId: finding.vulnerability.cveId,
            asset: finding.asset.hostname,
            score: finding.score,
            reason: finding.scoreSignals.join(', '),
          })),
        };
      }),
    },
    {
      name: 'create_remediation_plan',
      title: 'Create remediation plan',
      description: 'Create up to three deduplicated remediation recommendations within a defined window and add them to the shared board as proposed. Human review in the page is required for approval.',
      inputSchema: {
        type: 'object',
        properties: {
          findingIds: { type: 'array', items: { type: 'string', pattern: '^CVE-[0-9]{4}-[0-9]{4,7}:AST-[0-9]{3}$' }, maxItems: 3, description: 'Optional prioritized finding IDs.' },
          count: { type: 'integer', minimum: 1, maximum: 3, description: 'Number of proposals to stage.' },
          windowDays: { type: 'integer', minimum: 1, maximum: 30, description: 'Maximum remediation window in days.' },
          objective: { type: 'string', maxLength: 160, description: 'Optional business objective for the plan.' },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: false, untrustedContentHint: true },
      execute: safeExecute((input) => {
        const findingIds = idArray(input.findingIds, 'findingIds', /^CVE-\d{4}-\d{4,7}:AST-\d{3}$/, 3);
        if (findingIds?.some((id) => !patchPilotStore.getState().findings.some((finding) => finding.id === id))) {
          throw new Error('findingIds contains an ID that is not present in the current prioritized view');
        }
        const created = patchPilotStore.createPlan({
          findingIds,
          count: boundedInteger(input.count, 'count', 1, 3) ?? 3,
          windowDays: boundedInteger(input.windowDays, 'windowDays', 1, 30),
          objective: boundedString(input.objective, 'objective', 160),
        });
        return {
          ok: true,
          created: created.length,
          approvalRequired: true,
          proposals: created.map((item) => ({
            remediationId: item.id,
            cveId: item.cveId,
            asset: item.hostname,
            owner: item.owner,
            dueDate: item.dueDate,
            status: item.status,
          })),
        };
      }),
    },
  ];
}

type ModelContextLike = Pick<WebMCP.ModelContext, 'registerTool'>;

function resolveModelContext(): ModelContextLike | undefined {
  const current = document.modelContext;
  const legacy = (navigator as Navigator & { modelContext?: ModelContextLike }).modelContext;
  return current ?? legacy;
}

export async function registerPatchPilotTools() {
  const modelContext = resolveModelContext();
  if (!modelContext) {
    patchPilotStore.setWebMcpStatus('unavailable');
    return () => undefined;
  }

  const controller = new AbortController();
  try {
    await Promise.all(
      buildPatchPilotTools().map((tool) => modelContext.registerTool(tool, { signal: controller.signal })),
    );
    patchPilotStore.setWebMcpStatus('ready');
  } catch (error) {
    controller.abort();
    patchPilotStore.setWebMcpStatus('error');
    console.error('PatchPilot WebMCP registration failed', error);
  }
  return () => controller.abort();
}
